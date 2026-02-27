"""
scanner/aggregator_client.py
HTTP client to submit scan results to the aggregator service.
"""
import json
import logging
import requests

log = logging.getLogger("aggregator_client")


class AggregatorClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def submit(self, scan_data: dict):
        url = f"{self.base_url}/aggregate"
        try:
            resp = requests.post(url, json=scan_data, timeout=300)
            resp.raise_for_status()
            log.info("Scan data submitted to aggregator successfully")
            return resp.json()
        except Exception as e:
            log.error("Failed to submit to aggregator: %s", e)
            raise
