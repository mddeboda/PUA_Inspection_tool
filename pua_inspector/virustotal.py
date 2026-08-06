from __future__ import annotations

from datetime import datetime, timezone

import requests

from pua_inspector.models import VirusTotalResult


class VirusTotalClient:
    base_url = "https://www.virustotal.com/api/v3/files"

    def __init__(self, api_key: str, timeout_seconds: int = 15):
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self._cache: dict[str, VirusTotalResult] = {}

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def lookup_hash(self, sha256: str) -> VirusTotalResult:
        if sha256 in self._cache:
            return self._cache[sha256]
        if not self.configured:
            return VirusTotalResult(sha256=sha256, error="VirusTotal API key is not configured")

        url = f"{self.base_url}/{sha256}"
        try:
            # API call: VirusTotal v3 /files/{sha256} - retrieve the file reputation report.
            response = requests.get(
                url,
                headers={"x-apikey": self.api_key},
                timeout=self.timeout_seconds,
            )
            if response.status_code == 404:
                result = VirusTotalResult(
                    sha256=sha256,
                    detection_ratio="Unknown to VirusTotal",
                    report_url=f"https://www.virustotal.com/gui/file/{sha256}",
                )
            else:
                response.raise_for_status()
                attributes = response.json()["data"]["attributes"]
                stats = attributes.get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
                total = sum(int(value) for value in stats.values())
                analysis_timestamp = attributes.get("last_analysis_date")
                analysis_date = ""
                if analysis_timestamp:
                    analysis_date = datetime.fromtimestamp(
                        analysis_timestamp, timezone.utc
                    ).isoformat(timespec="seconds")
                result = VirusTotalResult(
                    sha256=sha256,
                    detection_ratio=f"{malicious}/{total}",
                    reputation=attributes.get("reputation"),
                    last_analysis_date=analysis_date,
                    report_url=f"https://www.virustotal.com/gui/file/{sha256}",
                )
        except (requests.RequestException, KeyError, TypeError, ValueError) as error:
            result = VirusTotalResult(sha256=sha256, error=str(error))
        self._cache[sha256] = result
        return result

