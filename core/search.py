"""
VulnForge — Search Engine
Multi-source vulnerability and exploit search: ExploitDB, NVD, Metasploit
"""

import os
import re
import subprocess
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger("vulnforge.search")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_BASE = "https://www.exploit-db.com"

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# NVD API key — loaded once at module import time
_NVD_API_KEY: str | None = os.environ.get("NVD_API_KEY")
if _NVD_API_KEY:
    logger.info("NVD API key loaded")
else:
    logger.warning("NVD_API_KEY not set — rate limiting applies")

# Unified result schema:
# {
#   source, id, title, date, url,
#   cvss_score, cve_id, severity,
#   exploit_type, platform, rank
# }


class ExploitSearchEngine:
    def __init__(self):
        self._msf_path = None

    # ── ExploitDB ─────────────────────────────────────────────────────────────

    def search_exploitdb(
        self,
        keyword: str = None,
        exploit_type: str = None,
        platform: str = None,
        cve: str = None,
    ) -> list[dict]:
        logger.info("ExploitDB scraper disabled — use CVE ID search instead")
        return []

        params = []
        if keyword:
            params.append(f"search={requests.utils.quote(keyword)}")
        if exploit_type and exploit_type.lower() != "all":
            params.append(f"type={exploit_type}")
        if platform and platform.lower() != "all":
            params.append(f"platform={platform}")
        if cve:
            params.append(f"cve={cve.replace('CVE-', '').replace('cve-', '')}")

        url = f"{EXPLOITDB_BASE}/search?{'&'.join(params)}"
        logger.info("ExploitDB search: %s", url)

        try:
            resp = requests.get(url, headers=_HEADERS, timeout=10)
            if resp.status_code != 200:
                logger.warning("ExploitDB returned HTTP %s — skipping", resp.status_code)
                return []

            soup = BeautifulSoup(resp.text, "html.parser")
            table = soup.find("table", class_="exploit_list")
            if not table:
                return []

            results = []
            for row in table.find("tbody").find_all("tr"):
                cells = row.find_all("td")
                if len(cells) < 5:
                    continue
                eid = cells[0].text.strip()
                date = cells[1].text.strip()
                title = cells[2].text.strip()
                link_tag = cells[2].find("a")
                eurl = (EXPLOITDB_BASE + link_tag["href"]) if link_tag else None
                etype = cells[3].text.strip()
                plat = cells[4].text.strip()

                cve_id = None
                cve_match = re.search(r"CVE-\d{4}-\d+", title, re.IGNORECASE)
                if cve_match:
                    cve_id = cve_match.group(0).upper()
                elif cve:
                    cve_id = cve.upper() if cve.upper().startswith("CVE-") else f"CVE-{cve.upper()}"

                results.append(
                    {
                        "source": "ExploitDB",
                        "id": eid,
                        "title": title,
                        "date": date,
                        "url": eurl,
                        "cvss_score": None,
                        "cve_id": cve_id,
                        "severity": None,
                        "exploit_type": etype,
                        "platform": plat,
                        "rank": None,
                    }
                )
        except Exception as exc:
            logger.warning("ExploitDB scrape failed: %s", exc)
            return []

        logger.info("ExploitDB: %d results", len(results))
        return results

    # ── NVD ───────────────────────────────────────────────────────────────────

    def search_nvd(self, keyword: str = None, cve: str = None) -> list[dict]:
        params: dict = {}
        if keyword:
            params["keywordSearch"] = keyword
        if cve:
            params["cveId"] = cve.upper() if cve.upper().startswith("CVE-") else f"CVE-{cve.upper()}"
        params["resultsPerPage"] = 20

        logger.info("NVD search params: %s", params)

        # Build request headers — include API key if available, otherwise rate-limit
        nvd_headers = dict(_HEADERS)
        if _NVD_API_KEY:
            nvd_headers["apiKey"] = _NVD_API_KEY
        else:
            time.sleep(0.6)  # NVD unauthenticated rate-limit courtesy delay

        try:
            resp = requests.get(NVD_API_URL, params=params, headers=nvd_headers, timeout=20)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.warning("NVD request failed: %s", exc)
            return []

        results = []
        for item in data.get("vulnerabilities", []):
            cve_item = item.get("cve", {})
            cve_id = cve_item.get("id", "Unknown")
            published = cve_item.get("published", "")[:10]

            description = "No description available"
            for desc in cve_item.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", description)
                    break

            cvss_score = None
            severity = None
            metrics = cve_item.get("metrics", {})
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(metric_key, [])
                if entries:
                    cvss_data = entries[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity")
                    break

            title = description[:120] + "…" if len(description) > 120 else description

            results.append(
                {
                    "source": "NVD",
                    "id": cve_id,
                    "title": title,
                    "date": published,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "cvss_score": cvss_score,
                    "cve_id": cve_id,
                    "severity": severity,
                    "exploit_type": None,
                    "platform": None,
                    "rank": None,
                }
            )

        logger.info("NVD: %d results", len(results))
        return results

    # ── Metasploit ────────────────────────────────────────────────────────────

    def _find_msf(self) -> bool:
        if self._msf_path:
            return True
        for path in ("/usr/share/metasploit-framework", "/opt/metasploit-framework"):
            if os.path.exists(path):
                self._msf_path = path
                return True
        # Also check if msfconsole is on PATH
        try:
            subprocess.run(
                ["msfconsole", "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            self._msf_path = "PATH"
            return True
        except Exception:
            return False

    def search_metasploit(
        self, keyword: str = None, exploit_type: str = None, cve: str = None
    ) -> list[dict]:
        if not self._find_msf():
            logger.info("Metasploit not found — skipping")
            return []

        query_parts = []
        if keyword:
            query_parts.append(keyword)
        if exploit_type and exploit_type.lower() not in ("all", ""):
            query_parts.append(f"type:{exploit_type.lower()}")
        if cve:
            query_parts.append(f"cve:{cve.replace('CVE-', '').replace('cve-', '')}")

        if not query_parts:
            return []

        rc_content = f"search {' '.join(query_parts)}\nexit\n"
        rc_path = "/tmp/vulnforge_msf.rc"
        try:
            with open(rc_path, "w") as fh:
                fh.write(rc_content)

            proc = subprocess.run(
                ["msfconsole", "-q", "-r", rc_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
            output = proc.stdout.decode("utf-8", errors="ignore")
        except Exception as exc:
            logger.warning("Metasploit search error: %s", exc)
            return []
        finally:
            if os.path.exists(rc_path):
                os.remove(rc_path)

        results = []
        for line in output.splitlines():
            line = line.strip()
            if not line or "Matching Modules" in line or line.startswith("="):
                continue
            match = re.match(r"^\s*(\S+/\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$", line)
            if not match:
                continue
            path, date, rank, _check, title = match.groups()
            module_type = path.split("/")[0]

            cve_id = None
            cve_match = re.search(r"CVE-\d{4}-\d+", title, re.IGNORECASE)
            if cve_match:
                cve_id = cve_match.group(0).upper()
            elif cve:
                cve_id = cve.upper() if cve.upper().startswith("CVE-") else f"CVE-{cve.upper()}"

            results.append(
                {
                    "source": "Metasploit",
                    "id": path,
                    "title": title.strip(),
                    "date": date if date != "0001-01-01" else None,
                    "url": f"https://www.rapid7.com/db/?q={requests.utils.quote(path)}",
                    "cvss_score": None,
                    "cve_id": cve_id,
                    "severity": None,
                    "exploit_type": module_type,
                    "platform": None,
                    "rank": rank,
                }
            )

        logger.info("Metasploit: %d results", len(results))
        return results

    # ── Multi-source parallel search ──────────────────────────────────────────

    def search(
        self,
        keyword: str = None,
        cve: str = None,
        exploit_type: str = None,
        platform: str = None,
        sources: list[str] = None,
    ) -> tuple[list[dict], dict]:
        """
        Run enabled sources in parallel.
        Returns (results, source_counts).
        sources defaults to all three.
        """
        if sources is None:
            sources = ["exploitdb", "nvd", "metasploit"]

        tasks: dict = {}
        with ThreadPoolExecutor(max_workers=3) as pool:
            if "exploitdb" in sources:
                tasks["ExploitDB"] = pool.submit(
                    self.search_exploitdb, keyword, exploit_type, platform, cve
                )
            if "nvd" in sources:
                tasks["NVD"] = pool.submit(self.search_nvd, keyword, cve)
            if "metasploit" in sources:
                tasks["Metasploit"] = pool.submit(
                    self.search_metasploit, keyword, exploit_type, cve
                )

            all_results: list[dict] = []
            source_counts: dict = {}
            for name, future in tasks.items():
                try:
                    res = future.result()
                    source_counts[name] = len(res)
                    all_results.extend(res)
                except Exception as exc:
                    logger.error("Source %s failed: %s", name, exc)
                    source_counts[name] = 0

        return all_results, source_counts
