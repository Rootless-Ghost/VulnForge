"""
VulnForge — Exporter
LogNorm NDJSON export, HuntForge seed push, AtomicLoop trigger.
All external calls are offline-safe with a 3-second timeout.
"""

import json
import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger("vulnforge.exporter")

HUNTFORGE_URL  = "http://localhost:5007/api/hunt"
ATOMICLOOP_URL = "http://localhost:5011/api/run"
_TIMEOUT = 3


# ── LogNorm NDJSON ─────────────────────────────────────────────────────────────

def _severity_from_score(score) -> str:
    if score is None:
        return "UNKNOWN"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    return "LOW"


def to_lognorm(result: dict, attck: dict) -> dict:
    """Convert a single unified result + ATT&CK mapping to ECS-lite NDJSON record."""
    cvss = result.get("cvss_score")
    severity = result.get("severity") or _severity_from_score(cvss)

    return {
        "event.kind": "vulnerability",
        "event.category": "vulnerability",
        "cve.id": result.get("cve_id") or "",
        "vulnerability.score.base": cvss,
        "vulnerability.severity": severity.upper() if severity else "UNKNOWN",
        "threat.technique.id": attck.get("technique_id", "UNKNOWN"),
        "threat.technique.name": attck.get("technique_name", "Unknown"),
        "threat.tactic.name": attck.get("tactic", "Unknown"),
        "source.tool": "VulnForge",
        "exploit.title": result.get("title", ""),
        "exploit.url": result.get("url", ""),
        "exploit.source": result.get("source", ""),
        "exploit.id": result.get("id", ""),
        "@timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def export_lognorm(results: list[dict], attck_map: dict[str, dict]) -> str:
    """
    Produce NDJSON string for all results.
    attck_map: {result_index_str → attck_dict}
    """
    lines = []
    for i, result in enumerate(results):
        attck = attck_map.get(str(i), {
            "technique_id": "UNKNOWN",
            "technique_name": "Unknown",
            "tactic": "Unknown",
        })
        record = to_lognorm(result, attck)
        lines.append(json.dumps(record))
    return "\n".join(lines)


# ── HuntForge seed push ────────────────────────────────────────────────────────

def send_to_huntforge(result: dict, attck: dict) -> tuple[bool, str]:
    """
    POST a hunt seed to HuntForge.
    Returns (success, message).
    """
    tid = attck.get("technique_id", "UNKNOWN")
    if tid == "UNKNOWN":
        return False, "No ATT&CK technique mapped — skipping HuntForge push."

    payload = {
        "technique_id": tid,
        "source": "VulnForge",
        "cve": result.get("cve_id") or "",
        "description": f"{attck.get('technique_name', '')} — {result.get('title', '')}",
        "auto_generated": True,
    }

    try:
        resp = requests.post(HUNTFORGE_URL, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
        return True, f"HuntForge accepted: {resp.status_code}"
    except requests.exceptions.ConnectionError:
        msg = "HuntForge is offline (connection refused). Seed not sent."
        logger.warning(msg)
        return False, msg
    except requests.exceptions.Timeout:
        msg = "HuntForge timed out. Seed not sent."
        logger.warning(msg)
        return False, msg
    except Exception as exc:
        msg = f"HuntForge error: {exc}"
        logger.warning(msg)
        return False, msg


def send_bulk_huntforge(results: list[dict], attck_map: dict[str, dict]) -> tuple[int, int, list[str]]:
    """
    Send multiple results to HuntForge.
    Returns (sent_count, failed_count, warning_messages).
    """
    sent = 0
    failed = 0
    warnings = []
    for i, result in enumerate(results):
        attck = attck_map.get(str(i), {"technique_id": "UNKNOWN"})
        ok, msg = send_to_huntforge(result, attck)
        if ok:
            sent += 1
        else:
            failed += 1
            if msg not in warnings:
                warnings.append(msg)
    return sent, failed, warnings


# ── AtomicLoop trigger ─────────────────────────────────────────────────────────

def send_to_atomicloop(result: dict, attck: dict) -> tuple[bool, str]:
    """
    POST a technique trigger to AtomicLoop.
    Returns (success, message).
    """
    tid = attck.get("technique_id", "UNKNOWN")
    if tid == "UNKNOWN":
        return False, "No ATT&CK technique mapped — skipping AtomicLoop trigger."

    payload = {
        "technique_id": tid,
        "source": "VulnForge",
        "auto": False,
    }

    try:
        resp = requests.post(ATOMICLOOP_URL, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
        return True, f"AtomicLoop accepted: {resp.status_code}"
    except requests.exceptions.ConnectionError:
        msg = "AtomicLoop is offline (connection refused). Trigger not sent."
        logger.warning(msg)
        return False, msg
    except requests.exceptions.Timeout:
        msg = "AtomicLoop timed out. Trigger not sent."
        logger.warning(msg)
        return False, msg
    except Exception:
        msg = "AtomicLoop encountered an internal error. Trigger not sent."
        logger.exception("AtomicLoop unexpected error while sending trigger.")
        return False, msg


def send_bulk_atomicloop(results: list[dict], attck_map: dict[str, dict]) -> tuple[int, int, list[str]]:
    """
    Send multiple technique triggers to AtomicLoop.
    Returns (sent_count, failed_count, warning_messages).
    De-duplicates by technique_id to avoid hammering the same technique.
    """
    seen_tids: set[str] = set()
    sent = 0
    failed = 0
    warnings = []
    for i, result in enumerate(results):
        attck = attck_map.get(str(i), {"technique_id": "UNKNOWN"})
        tid = attck.get("technique_id", "UNKNOWN")
        if tid in seen_tids:
            continue
        seen_tids.add(tid)
        ok, msg = send_to_atomicloop(result, attck)
        if ok:
            sent += 1
        else:
            failed += 1
            if msg not in warnings:
                warnings.append(msg)
    return sent, failed, warnings
