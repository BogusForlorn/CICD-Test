"""
scanner/scanners/semgrep_scanner.py
SAST scanner using Semgrep — covers Python, Java, JS/TS, Go, Ruby, PHP, C/C++.
Replaces Bandit (Python) and SpotBugs (Java) — Semgrep has dedicated rule packs.
"""
import json
import logging
import os
import subprocess
from typing import List, Dict, Any

log = logging.getLogger("semgrep_scanner")


class SemgrepScanner:
    TOOL = "semgrep"
    CATEGORY = "SAST"

    # Language-to-config mapping for targeted scanning
    LANG_CONFIGS = {
        "has_python":     ["p/python", "p/bandit"],
        "has_java":       ["p/java", "p/owasp-top-ten"],
        "has_javascript": ["p/javascript", "p/typescript", "p/nodejs"],
        "has_go":         ["p/golang"],
        "has_php":        ["p/php"],
        "has_ruby":       ["p/ruby"],
    }

    def __init__(self, workspace: str, results_dir: str, config: dict, content: dict):
        self.workspace = workspace
        self.results_dir = results_dir
        self.config = config
        self.content = content
        self.output_file = os.path.join(results_dir, "semgrep.json")

    def run(self) -> List[Dict[str, Any]]:
        configs = self._build_configs()
        if not configs:
            log.warning("No Semgrep configs applicable — running with auto")
            configs = ["auto"]

        # Build semgrep command
        cmd = ["semgrep", "scan", "--json", f"--output={self.output_file}"]
        for cfg in configs:
            cmd += ["--config", cfg]
        cmd += [
            "--no-rewrite-rule-ids",
            "--metrics=off",
            "--quiet",
            self.workspace,
        ]

        log.info("Semgrep command: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.workspace)

        # Semgrep exits 1 when findings exist — that is normal
        if result.returncode not in (0, 1):
            log.error("Semgrep error (rc=%d): %s", result.returncode, result.stderr[:500])

        return self._parse()

    def _build_configs(self) -> List[str]:
        configs = set(self.config.get("configs", []))
        # Always include core packs
        configs.update(["p/owasp-top-ten", "p/cwe-top-25"])
        # Add language-specific packs based on detected content
        for lang_key, lang_configs in self.LANG_CONFIGS.items():
            if self.content.get(lang_key):
                configs.update(lang_configs)
        return list(configs)

    def _parse(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.output_file):
            log.warning("Semgrep output file not found")
            return []
        with open(self.output_file) as f:
            data = json.load(f)

        findings = []
        for result in data.get("results", []):
            meta = result.get("extra", {})
            severity = self._map_severity(meta.get("severity", "WARNING"))
            findings.append({
                "tool": self.TOOL,
                "category": self.CATEGORY,
                "rule_id": result.get("check_id", "unknown"),
                "severity": severity,
                "title": meta.get("message", result.get("check_id", ""))[:200],
                "description": meta.get("message", ""),
                "file": result.get("path", ""),
                "line": result.get("start", {}).get("line"),
                "line_end": result.get("end", {}).get("line"),
                "code_snippet": meta.get("lines", "")[:500],
                "cwe": self._extract_cwe(meta),
                "owasp": meta.get("metadata", {}).get("owasp", ""),
                "native_remediation": meta.get("metadata", {}).get("fix", ""),
                "references": meta.get("metadata", {}).get("references", []),
                "raw": result,
            })
        return findings

    def _map_severity(self, semgrep_sev: str) -> str:
        return {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "LOW",
            "CRITICAL": "CRITICAL",
        }.get(semgrep_sev.upper(), "MEDIUM")

    def _extract_cwe(self, meta: dict) -> str:
        cwe = meta.get("metadata", {}).get("cwe", "")
        if isinstance(cwe, list):
            return cwe[0] if cwe else ""
        return str(cwe)
