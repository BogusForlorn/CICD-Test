"""
scanner/scanners/zap_scanner.py
OWASP ZAP DAST scanner — runs against a staging deployment.
Only triggered when PR has 'deployable' label.
"""
import json
import logging
import os
import subprocess
import time
from typing import List, Dict, Any

log = logging.getLogger("zap_scanner")


class ZAPScanner:
    TOOL = "zap"
    CATEGORY = "DAST"

    def __init__(self, workspace: str, results_dir: str, config: dict):
        self.workspace = workspace
        self.results_dir = results_dir
        self.config = config
        self.output_file = os.path.join(results_dir, "zap.json")
        self.target_url = (
            config.get("target_url")
            or os.environ.get("STAGING_URL")
            or os.environ.get("ZAP_TARGET_URL", "")
        )

    def run(self) -> List[Dict[str, Any]]:
        if not self.target_url:
            log.warning("ZAP skipped — no target URL (set STAGING_URL env var)")
            return []

        # Start ephemeral staging environment
        self._start_staging()
        # Wait for app to be ready
        self._wait_for_app(self.target_url)

        timeout = self.config.get("scan_timeout_minutes", 30)
        cmd = [
            "zap-full-scan.py" if self.config.get("active_scan", True) else "zap-baseline.py",
            "-t", self.target_url,
            "-J", self.output_file,
            "-I",          # Don't fail on warnings
            "-m", str(timeout),
            "-a",          # Include alpha passive rules
        ]

        log.info("ZAP command: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout * 60 + 120)
        if result.returncode not in (0, 1, 2):
            log.error("ZAP error (rc=%d): %s", result.returncode, result.stderr[:300])

        self._stop_staging()
        return self._parse()

    def _start_staging(self):
        compose_file = os.path.join(self.workspace, "docker-compose.test.yml")
        if os.path.exists(compose_file):
            log.info("Starting staging environment via docker-compose")
            subprocess.run(
                ["docker-compose", "-f", compose_file, "up", "-d"],
                capture_output=True
            )
            time.sleep(15)  # Allow services to start

    def _stop_staging(self):
        compose_file = os.path.join(self.workspace, "docker-compose.test.yml")
        if os.path.exists(compose_file):
            subprocess.run(
                ["docker-compose", "-f", compose_file, "down", "--volumes"],
                capture_output=True
            )

    def _wait_for_app(self, url: str, max_wait: int = 60):
        import urllib.request
        for i in range(max_wait):
            try:
                urllib.request.urlopen(url, timeout=3)
                log.info("Staging app ready at %s", url)
                return
            except Exception:
                time.sleep(1)
        log.warning("Staging app may not be ready after %ds", max_wait)

    def _parse(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.output_file):
            return []
        with open(self.output_file) as f:
            data = json.load(f)

        findings = []
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                risk = alert.get("riskdesc", "").split(" ")[0].upper()
                severity = self._map_risk(risk)
                for instance in alert.get("instances", [{}]):
                    findings.append({
                        "tool": self.TOOL,
                        "category": self.CATEGORY,
                        "rule_id": f"ZAP-{alert.get('pluginid', '')}",
                        "severity": severity,
                        "title": alert.get("alert", ""),
                        "description": alert.get("desc", "").replace("<p>", "").replace("</p>", ""),
                        "file": instance.get("uri", ""),
                        "line": None,
                        "code_snippet": (
                            f"URI: {instance.get('uri', '')}\n"
                            f"Method: {instance.get('method', '')}\n"
                            f"Evidence: {instance.get('evidence', '')}"
                        ),
                        "native_remediation": alert.get("solution", "").replace("<p>", "").replace("</p>", ""),
                        "references": [alert.get("reference", "")],
                        "raw": alert,
                    })
        return findings

    def _map_risk(self, risk: str) -> str:
        return {
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "INFORMATIONAL": "INFO",
        }.get(risk, "MEDIUM")
