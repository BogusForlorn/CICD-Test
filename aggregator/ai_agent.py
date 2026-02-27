"""
aggregator/ai_agent.py
AI Remediation Agent — one API call per finding (1:1 guarantee).
Never batches findings. Falls back to native remediation on error.
"""
import json
import logging
import os
import time
from typing import Any, Dict

log = logging.getLogger("ai_agent")

ANTHROPIC_SYSTEM = """You are a senior application security engineer providing remediation guidance.
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

OPENAI_SYSTEM = ANTHROPIC_SYSTEM  # Same prompt works for both


class AIRemediationAgent:
    def __init__(self, api_key: str, provider: str = "anthropic", model: str = "claude-opus-4-6"):
        self.api_key = api_key
        self.provider = provider
        self.model = model
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
            result = self._call_api(prompt)
            result["remediation_status"] = "ai_generated"
            result["provider"] = self.provider
            result["model"] = self.model
            return result
        except Exception as e:
            log.error("AI remediation failed for finding %s: %s", finding.get("rule_id"), e)
            return self._fallback(finding, str(e))

    def _build_prompt(self, finding: dict) -> str:
        return (
            f"Tool: {finding.get('tool', 'unknown')}
"
            f"Category: {finding.get('category', '')}
"
            f"Rule ID: {finding.get('rule_id', '')}
"
            f"Severity: {finding.get('severity', '')}
"
            f"CWE: {finding.get('cwe', '')}
"
            f"File: {finding.get('file', '')}
"
            f"Line: {finding.get('line', 'N/A')}
"
            f"Title: {finding.get('title', '')}
"
            f"Description: {finding.get('description', '')}
"
            f"Code snippet: {(finding.get('code_snippet') or '')[:400]}
"
            f"Native remediation hint: {(finding.get('native_remediation') or '')[:200]}
"
        )

    def _call_api(self, prompt: str) -> dict:
        client = self._get_client()
        if self.provider == "anthropic":
            resp = client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=ANTHROPIC_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            text = resp.content[0].text.strip()
        elif self.provider == "openai":
            resp = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": OPENAI_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=1024,
                response_format={"type": "json_object"},
            )
            text = resp.choices[0].message.content.strip()
        else:
            raise ValueError(f"Unknown provider: {self.provider}")

        # Strip any accidental markdown fences
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]

        return json.loads(text)

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
