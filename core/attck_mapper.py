"""
VulnForge — ATT&CK Mapper
CVE → CWE → CAPEC → ATT&CK technique mapping.

Primary path:  CVSS vector / vulnerability class inference
Secondary path: NVD CWE tag → CAPEC → ATT&CK

Returns a mapping dict with: technique_id, technique_name, tactic, confidence
Never returns None — always falls back to UNKNOWN.
"""

import logging
import re

import requests

logger = logging.getLogger("vulnforge.attck")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── Static mapping tables ──────────────────────────────────────────────────────

# CWE → (technique_id, technique_name, tactic)
_CWE_TO_ATTCK: dict[str, tuple[str, str, str]] = {
    # Injection / code execution
    "CWE-78":  ("T1059", "Command and Scripting Interpreter", "Execution"),
    "CWE-94":  ("T1059", "Command and Scripting Interpreter", "Execution"),
    "CWE-77":  ("T1059", "Command and Scripting Interpreter", "Execution"),
    "CWE-74":  ("T1059", "Command and Scripting Interpreter", "Execution"),
    # SQL injection
    "CWE-89":  ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    # Path traversal / LFI
    "CWE-22":  ("T1083", "File and Directory Discovery", "Discovery"),
    "CWE-23":  ("T1083", "File and Directory Discovery", "Discovery"),
    # XSS
    "CWE-79":  ("T1189", "Drive-by Compromise", "Initial Access"),
    # Remote code execution via deserialization
    "CWE-502": ("T1059", "Command and Scripting Interpreter", "Execution"),
    # Buffer overflows → privilege escalation
    "CWE-119": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    "CWE-120": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    "CWE-121": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    "CWE-122": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    "CWE-787": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    # Use-after-free → privilege escalation
    "CWE-416": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    # Authentication bypass
    "CWE-287": ("T1078", "Valid Accounts", "Defense Evasion"),
    "CWE-306": ("T1078", "Valid Accounts", "Defense Evasion"),
    "CWE-294": ("T1078", "Valid Accounts", "Defense Evasion"),
    # SSRF
    "CWE-918": ("T1090", "Proxy", "Command and Control"),
    # XXE
    "CWE-611": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    # CSRF
    "CWE-352": ("T1185", "Browser Session Hijacking", "Collection"),
    # Credentials in cleartext
    "CWE-312": ("T1552", "Unsecured Credentials", "Credential Access"),
    "CWE-319": ("T1557", "Adversary-in-the-Middle", "Credential Access"),
    # Directory listing
    "CWE-548": ("T1083", "File and Directory Discovery", "Discovery"),
    # Open redirect
    "CWE-601": ("T1189", "Drive-by Compromise", "Initial Access"),
    # Privilege escalation (generic)
    "CWE-269": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    # Public-facing application (generic)
    "CWE-200": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
}

# Keyword patterns in title/description → technique
_KEYWORD_MAP: list[tuple[re.Pattern, tuple[str, str, str]]] = [
    (re.compile(r"\brce\b|remote\s+code\s+exec", re.I),
        ("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (re.compile(r"sql\s*inj", re.I),
        ("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (re.compile(r"command\s+inj|os\s+command", re.I),
        ("T1059", "Command and Scripting Interpreter", "Execution")),
    (re.compile(r"xss|cross.site\s+script", re.I),
        ("T1189", "Drive-by Compromise", "Initial Access")),
    (re.compile(r"lfi|local\s+file\s+inclus|path\s+travers|directory\s+travers", re.I),
        ("T1083", "File and Directory Discovery", "Discovery")),
    (re.compile(r"priv.+escal|privilege\s+escal|local\s+priv", re.I),
        ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation")),
    (re.compile(r"auth\s+bypass|authentication\s+bypass", re.I),
        ("T1078", "Valid Accounts", "Defense Evasion")),
    (re.compile(r"ssrf|server.side\s+request", re.I),
        ("T1090", "Proxy", "Command and Control")),
    (re.compile(r"deseri", re.I),
        ("T1059", "Command and Scripting Interpreter", "Execution")),
    (re.compile(r"buffer\s+over|heap\s+over|stack\s+over|use.after.free", re.I),
        ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation")),
    (re.compile(r"credential|password\s+leak|clear.?text", re.I),
        ("T1552", "Unsecured Credentials", "Credential Access")),
    (re.compile(r"backdoor|web.?shell", re.I),
        ("T1505", "Server Software Component", "Persistence")),
    (re.compile(r"dos\b|denial.of.serv|resource\s+exhaust", re.I),
        ("T1499", "Endpoint Denial of Service", "Impact")),
]

_UNKNOWN: dict = {
    "technique_id": "UNKNOWN",
    "technique_name": "Unknown",
    "tactic": "Unknown",
    "confidence": "low",
}


def _from_keywords(text: str) -> dict | None:
    """Try to map based on title/description keywords."""
    for pattern, (tid, tname, tactic) in _KEYWORD_MAP:
        if pattern.search(text):
            return {
                "technique_id": tid,
                "technique_name": tname,
                "tactic": tactic,
                "confidence": "medium",
            }
    return None


def _from_cwes(cwes: list[str]) -> dict | None:
    """Map CWE list to ATT&CK technique."""
    for cwe in cwes:
        normalized = cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
        if normalized in _CWE_TO_ATTCK:
            tid, tname, tactic = _CWE_TO_ATTCK[normalized]
            return {
                "technique_id": tid,
                "technique_name": tname,
                "tactic": tactic,
                "confidence": "high",
            }
    return None


def _fetch_nvd_cwes(cve_id: str) -> list[str]:
    """Fetch CWE IDs for a CVE from NVD."""
    try:
        import time
        time.sleep(0.6)
        resp = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id.upper()},
            headers={"User-Agent": "VulnForge/1.0"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        cwes = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    val = desc.get("value", "")
                    if val.startswith("CWE-"):
                        cwes.append(val)
        return cwes
    except Exception as exc:
        logger.debug("NVD CWE fetch failed for %s: %s", cve_id, exc)
        return []


def map_cve(cve_id: str = None, title: str = "", description: str = "") -> dict:
    """
    Map a CVE (or title/description text) to an ATT&CK technique.
    Always returns a dict — never raises.
    """
    text = f"{title} {description}".strip()

    # 1. If we have a CVE, try NVD CWE lookup (most accurate)
    if cve_id and re.match(r"^CVE-\d{4}-\d+$", cve_id.upper(), re.IGNORECASE):
        cwes = _fetch_nvd_cwes(cve_id.upper())
        result = _from_cwes(cwes)
        if result:
            return result

    # 2. Keyword matching on title/description
    if text:
        result = _from_keywords(text)
        if result:
            return result

    # 3. Fallback
    return dict(_UNKNOWN)
