"""
aggregator/ai_agent.py
AI Remediation Agent — one API call per finding (1:1 guarantee).
Never batches findings. Falls back to native remediation on error.
"""
import json
import logging
import re
from urllib.parse import quote
from typing import Any, Dict, Optional

import requests

log = logging.getLogger("ai_agent")

DEFAULT_MODELS = {
    "anthropic": "claude-opus-4-6",
    "openai": "gpt-4o-mini",
    "gemini": "gemini-1.5-pro",
}
SUPPORTED_PROVIDERS = tuple(DEFAULT_MODELS.keys())
GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta"

REMEDIATION_SYSTEM = """You are a senior application security engineer providing remediation guidance.
Given ONE security finding, return ONLY a valid JSON object — no markdown, no preamble.

Required JSON structure:
{
  "remediation_steps": [
    "Step 1: ...",
    "Step 2: ...",
    "Step 3: ..."
  ],
  "explanation": "Brief technical explanation of why this is a security issue",
  "cwe_reference": "CWE-XXX or empty string",
  "owasp_reference": "OWASP A0X or empty string",
  "estimated_effort": "low | medium | high",
  "references": ["url1", "url2"]
}

Rules:
- remediation_steps must be numbered, concrete, and specific to the exact file/line provided
- Each step must be a separate, actionable instruction — never combine steps
- Do not skip steps or generalise
- Reference the specific file path and line number in step 1
- Minimum 3 steps, maximum 10 steps
- Return ONLY the JSON object, nothing else
"""

CVSS_SYSTEM = """You are a CVSS v3.1 scoring expert.
Given ONE security finding, estimate CVSS and return EXACTLY one line in this exact format:
CVSS:3.1/<vector> | SCORE:<score> | SEVERITY:<CRITICAL|HIGH|MEDIUM|LOW|INFO>

Rules:
- No markdown and no extra text
- score must be 0.0 to 10.0 with one decimal
- severity must match score bands:
  9.0-10.0 CRITICAL, 7.0-8.9 HIGH, 4.0-6.9 MEDIUM, 0.1-3.9 LOW, 0.0 INFO
- Always produce a valid CVSS vector string after CVSS:3.1/
"""

CVE_POC_SYSTEM = """You are a senior application security engineer.
Given a finding with one or more CVE IDs, return ONLY JSON:
{
  "poc_status": "ready | not_enough_data",
  "poc_title": "short title",
  "verification_steps": ["step1", "step2", "step3"],
  "safety_notes": ["note1", "note2"],
  "references": ["url1", "url2"]
}

Rules:
- Steps must be for controlled validation in test/staging only
- Do not include destructive or production-targeting instructions
- Minimum 3 verification_steps when poc_status is "ready"
"""


class AIRemediationAgent:
    def __init__(self, api_key: str, provider: str = "anthropic", model: str = ""):
        self.api_key = api_key
        self.provider = (provider or "anthropic").strip().lower()
        self.model = (model or "").strip() or DEFAULT_MODELS.get(self.provider, "")
        if self.provider not in SUPPORTED_PROVIDERS:
            supported = ", ".join(SUPPORTED_PROVIDERS)
            raise ValueError(f"Unknown provider: {self.provider}. Supported providers: {supported}")
        if not self.model:
            raise ValueError(f"No model configured for provider: {self.provider}")
        self._client = None

    def _get_client(self):
        if self._client is None:
            if self.provider == "anthropic":
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            elif self.provider == "openai":
                import openai
                self._client = openai.OpenAI(api_key=self.api_key)
        return self._client

    def remediate(self, finding: dict) -> dict:
        """
        One-to-one: one call per finding.
        Never batches — guarantees no step is skipped or merged.
        """
        prompt = self._build_prompt(finding)
        try:
            result = self._call_json_api(REMEDIATION_SYSTEM, prompt, max_tokens=1024)
            result["remediation_status"] = "ai_generated"
            result["provider"] = self.provider
            result["model"] = self.model
            return result
        except Exception as e:
            log.error("AI remediation failed for finding %s: %s", finding.get("rule_id"), e)
            return self._fallback(finding, str(e))

    def estimate_cvss_with_verification(self, finding: dict) -> dict:
        """
        Estimate CVSS string using two independent LLM calls.
        Verification is strict string equality (non-LLM compare).
        """
        prompt = self._build_cvss_prompt(finding)
        try:
            first = self._call_text_api(CVSS_SYSTEM, prompt, max_tokens=160).strip()
            second = self._call_text_api(CVSS_SYSTEM, prompt, max_tokens=160).strip()

            if first != second:
                return {
                    "status": "unable_to_estimate",
                    "source": "llm_double_check",
                    "reason": "cvss_string_mismatch",
                    "cvss_string_1": first,
                    "cvss_string_2": second,
                    "provider": self.provider,
                    "model": self.model,
                }

            parsed = self._parse_cvss_string(first)
            if not parsed:
                return {
                    "status": "unable_to_estimate",
                    "source": "llm_double_check",
                    "reason": "invalid_cvss_format",
                    "cvss_string_1": first,
                    "cvss_string_2": second,
                    "provider": self.provider,
                    "model": self.model,
                }

            parsed.update(
                {
                    "status": "verified",
                    "source": "llm_double_check",
                    "cvss_string_1": first,
                    "cvss_string_2": second,
                    "provider": self.provider,
                    "model": self.model,
                }
            )
            return parsed
        except Exception as e:
            log.error("CVSS estimation failed for finding %s: %s", finding.get("rule_id"), e)
            return {
                "status": "unable_to_estimate",
                "source": "llm_double_check",
                "reason": "api_error",
                "error": str(e),
            }

    def generate_cve_poc(self, finding: dict, cves: list) -> dict:
        """
        Generate CVE validation PoC steps for controlled test environments.
        """
        prompt = self._build_cve_poc_prompt(finding, cves)
        try:
            result = self._call_json_api(CVE_POC_SYSTEM, prompt, max_tokens=900)
            result["status"] = "ai_generated"
            result["provider"] = self.provider
            result["model"] = self.model
            return result
        except Exception as e:
            log.error("CVE PoC generation failed for finding %s: %s", finding.get("rule_id"), e)
            return {
                "status": "ai_error_fallback",
                "poc_status": "not_enough_data",
                "poc_title": "PoC unavailable",
                "verification_steps": [
                    "Validate this CVE in an isolated staging environment only.",
                    "Use the scanner output and package/version details to reproduce safely.",
                    "Re-run the same scanner after remediation to confirm closure.",
                ],
                "safety_notes": [
                    "Do not run validation against production systems.",
                    "Use least-privileged credentials for any test activity.",
                ],
                "references": finding.get("references", [])[:3],
                "error": str(e),
            }

    def _build_prompt(self, finding: dict) -> str:
        return (
            f"Tool: {finding.get('tool', 'unknown')}\n"
            f"Category: {finding.get('category', '')}\n"
            f"Rule ID: {finding.get('rule_id', '')}\n"
            f"Severity: {finding.get('severity', '')}\n"
            f"CWE: {finding.get('cwe', '')}\n"
            f"File: {finding.get('file', '')}\n"
            f"Line: {finding.get('line', 'N/A')}\n"
            f"Title: {finding.get('title', '')}\n"
            f"Description: {finding.get('description', '')}\n"
            f"Code snippet: {(finding.get('code_snippet') or '')[:400]}\n"
            f"Native remediation hint: {(finding.get('native_remediation') or '')[:200]}\n"
        )

    def _build_cvss_prompt(self, finding: dict) -> str:
        refs = finding.get("references", [])[:5]
        return (
            f"Tool: {finding.get('tool', 'unknown')}\n"
            f"Category: {finding.get('category', '')}\n"
            f"Rule ID: {finding.get('rule_id', '')}\n"
            f"Title: {finding.get('title', '')}\n"
            f"Description: {finding.get('description', '')}\n"
            f"File: {finding.get('file', '')}\n"
            f"Line: {finding.get('line', 'N/A')}\n"
            f"Code snippet: {(finding.get('code_snippet') or '')[:500]}\n"
            f"References: {refs}\n"
        )

    def _build_cve_poc_prompt(self, finding: dict, cves: list) -> str:
        refs = finding.get("references", [])[:5]
        return (
            f"Detected CVEs: {', '.join(cves)}\n"
            f"Tool: {finding.get('tool', 'unknown')}\n"
            f"Category: {finding.get('category', '')}\n"
            f"Rule ID: {finding.get('rule_id', '')}\n"
            f"Title: {finding.get('title', '')}\n"
            f"Description: {finding.get('description', '')}\n"
            f"File/Target: {finding.get('file', '')}\n"
            f"Code snippet: {(finding.get('code_snippet') or '')[:500]}\n"
            f"Native remediation: {(finding.get('native_remediation') or '')[:300]}\n"
            f"References: {refs}\n"
        )

    def _call_json_api(self, system_prompt: str, prompt: str, max_tokens: int = 1024) -> dict:
        text = self._invoke(system_prompt, prompt, max_tokens=max_tokens, as_json=True)
        return json.loads(self._strip_code_fences(text))

    def _call_text_api(self, system_prompt: str, prompt: str, max_tokens: int = 256) -> str:
        return self._strip_code_fences(
            self._invoke(system_prompt, prompt, max_tokens=max_tokens, as_json=False)
        ).strip()

    def _invoke(self, system_prompt: str, prompt: str, max_tokens: int, as_json: bool) -> str:
        client = self._get_client()
        if self.provider == "anthropic":
            resp = client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
            )
            text = resp.content[0].text
        elif self.provider == "openai":
            kwargs = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": 0,
            }
            if as_json:
                kwargs["response_format"] = {"type": "json_object"}
            resp = client.chat.completions.create(**kwargs)
            text = resp.choices[0].message.content
        elif self.provider == "gemini":
            text = self._invoke_gemini(system_prompt, prompt, max_tokens=max_tokens, as_json=as_json)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")
        return text or ""

    def _invoke_gemini(self, system_prompt: str, prompt: str, max_tokens: int, as_json: bool) -> str:
        generation_config: Dict[str, Any] = {
            "temperature": 0,
            "maxOutputTokens": max_tokens,
        }
        if as_json:
            generation_config["responseMimeType"] = "application/json"

        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": generation_config,
        }
        model = quote(self.model, safe="")
        url = f"{GEMINI_API_BASE}/models/{model}:generateContent"
        resp = requests.post(url, params={"key": self.api_key}, json=payload, timeout=60)
        if resp.status_code >= 400:
            body = (resp.text or "").strip().replace("\n", " ")
            raise RuntimeError(f"Gemini API error {resp.status_code}: {body[:400]}")

        data = resp.json()
        candidates = data.get("candidates") or []
        if not candidates:
            feedback = data.get("promptFeedback", {})
            block_reason = feedback.get("blockReason", "no_candidates")
            raise RuntimeError(f"Gemini response has no candidates: {block_reason}")

        parts = candidates[0].get("content", {}).get("parts", [])
        text_chunks = [p.get("text", "") for p in parts if isinstance(p, dict)]
        text = "".join(text_chunks).strip()
        if not text:
            raise RuntimeError("Gemini response did not include text output")
        return text

    def _strip_code_fences(self, text: str) -> str:
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return text.strip()

    def _parse_cvss_string(self, cvss_line: str) -> Optional[Dict[str, Any]]:
        pat = (
            r"^CVSS:(?P<version>3\.1)/(?P<vector>[A-Za-z0-9:./_-]+)\s*\|\s*"
            r"SCORE:(?P<score>\d{1,2}(?:\.\d)?)\s*\|\s*"
            r"SEVERITY:(?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFO)$"
        )
        match = re.match(pat, cvss_line.strip())
        if not match:
            return None
        score = float(match.group("score"))
        if score < 0.0 or score > 10.0:
            return None
        return {
            "version": match.group("version"),
            "vector": f"CVSS:{match.group('version')}/{match.group('vector')}",
            "score": score,
            "severity": match.group("severity"),
            "cvss_string_verified": cvss_line.strip(),
        }

    def _fallback(self, finding: dict, error: str) -> dict:
        """
        Fallback when AI call fails — use native tool remediation.
        Finding is never left without guidance.
        """
        native = finding.get("native_remediation", "")
        steps = []
        if native:
            # Split native remediation into numbered steps if possible
            parts = [p.strip() for p in native.split(". ") if p.strip()]
            steps = [f"Step {i+1}: {p}" for i, p in enumerate(parts)]
        if not steps:
            steps = [
                f"Step 1: Review the finding in {finding.get('file', 'the reported file')} at line {finding.get('line', 'N/A')}.",
                f"Step 2: Consult the {finding.get('tool', 'tool')} documentation for {finding.get('rule_id', 'this rule')}.",
                "Step 3: Apply the fix and re-run the security scan to verify resolution.",
            ]
        return {
            "remediation_status": "ai_error_fallback",
            "remediation_steps": steps,
            "explanation": native or "See tool documentation for details.",
            "cwe_reference": finding.get("cwe", ""),
            "owasp_reference": "",
            "estimated_effort": "medium",
            "references": finding.get("references", []),
            "error": error,
        }
