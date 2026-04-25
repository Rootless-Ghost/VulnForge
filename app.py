"""
VulnForge — Vulnerability & Exploit Intelligence Tool
Part of the Nebula Forge Detection Suite v2

Port: 5012
Usage: python app.py
"""

import io
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, send_file

load_dotenv()

from core.search import ExploitSearchEngine
from core.attck_mapper import map_cve
from core.exporter import (
    export_lognorm,
    send_bulk_huntforge,
    send_bulk_atomicloop,
)

# ── Jinja2 template filters ────────────────────────────────────────────────────

def _cvss_class(score) -> str:
    """Return a CSS class name based on CVSS score."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "info"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    return "low"


def _tactic_class(tactic: str) -> str:
    """Return a CSS slug from a tactic name."""
    return tactic.lower().replace(" ", "-").replace("_", "-") if tactic else "unknown"

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("vulnforge")

# ── Flask app ──────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "vulnforge-dev-secret")

# Register filters
app.jinja_env.filters["cvss_class"]   = _cvss_class
app.jinja_env.filters["tactic_class"] = _tactic_class

engine = ExploitSearchEngine()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_search_form(form) -> dict:
    return {
        "keyword":  form.get("keyword", "").strip() or None,
        "cve":      form.get("cve", "").strip() or None,
        "exploit_type": form.get("exploit_type", "all").strip(),
        "platform": form.get("platform", "all").strip(),
        "sources":  form.getlist("sources") or ["exploitdb", "nvd", "metasploit"],
    }


def _build_attck_map(results: list[dict]) -> dict[str, dict]:
    """Build index-keyed ATT&CK mapping for a result list."""
    def _map(args):
        i, r = args
        return str(i), map_cve(cve_id=r.get("cve_id"), title=r.get("title", ""), description="")

    with ThreadPoolExecutor(max_workers=5) as pool:
        pairs = pool.map(_map, enumerate(results))
    return dict(pairs)


def _session_key(form) -> str:
    """Stable key for storing results in the session."""
    return json.dumps({
        k: form.get(k) for k in ("keyword", "cve", "exploit_type", "platform")
    }, sort_keys=True)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return render_template("index.html")


@app.post("/search")
def search():
    params = _parse_search_form(request.form)

    if not params["keyword"] and not params["cve"]:
        return render_template(
            "index.html",
            error="Please enter a keyword or CVE ID.",
        )

    try:
        results, source_counts = engine.search(
            keyword=params["keyword"],
            cve=params["cve"],
            exploit_type=params["exploit_type"],
            platform=params["platform"],
            sources=params["sources"],
        )
    except Exception as exc:
        logger.exception("Search error: %s", exc)
        return render_template("results.html", error=str(exc), results=[], attck_map={})

    attck_map = _build_attck_map(results)

    return render_template(
        "results.html",
        results=results,
        attck_map=attck_map,
        source_counts=source_counts,
        params=params,
        total=len(results),
    )


@app.post("/api/search")
def api_search():
    data = request.get_json(force=True, silent=True) or {}
    keyword     = data.get("keyword")
    cve         = data.get("cve")
    exploit_type = data.get("exploit_type", "all")
    platform    = data.get("platform", "all")
    sources     = data.get("sources", ["exploitdb", "nvd", "metasploit"])

    if not keyword and not cve:
        return jsonify({"error": "keyword or cve required"}), 400

    try:
        results, source_counts = engine.search(
            keyword=keyword,
            cve=cve,
            exploit_type=exploit_type,
            platform=platform,
            sources=sources,
        )
    except Exception as exc:
        logger.exception("API search error: %s", exc)
        return jsonify({"error": str(exc)}), 500

    attck_map = _build_attck_map(results)

    return jsonify({
        "total": len(results),
        "source_counts": source_counts,
        "results": results,
        "attck_map": attck_map,
    })


@app.post("/export/lognorm")
def export_lognorm_route():
    data = request.get_json(force=True, silent=True) or {}
    results  = data.get("results", [])
    attck_map = data.get("attck_map", {})

    if not results:
        return jsonify({"error": "No results to export"}), 400

    try:
        ndjson = export_lognorm(results, attck_map)
    except Exception as exc:
        logger.exception("LogNorm export error: %s", exc)
        return jsonify({"error": str(exc)}), 500

    buf = io.BytesIO(ndjson.encode("utf-8"))
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/x-ndjson",
        as_attachment=True,
        download_name="vulnforge_lognorm.ndjson",
    )


@app.post("/export/huntforge")
def export_huntforge_route():
    data = request.get_json(force=True, silent=True) or {}
    results  = data.get("results", [])
    attck_map = data.get("attck_map", {})

    if not results:
        return jsonify({"error": "No results to send"}), 400

    sent, failed, warnings = send_bulk_huntforge(results, attck_map)
    return jsonify({
        "sent": sent,
        "failed": failed,
        "warnings": warnings,
    })


@app.post("/export/atomicloop")
def export_atomicloop_route():
    data = request.get_json(force=True, silent=True) or {}
    results  = data.get("results", [])
    attck_map = data.get("attck_map", {})

    if not results:
        return jsonify({"error": "No results to send"}), 400

    sent, failed, warnings = send_bulk_atomicloop(results, attck_map)
    return jsonify({
        "sent": sent,
        "failed": failed,
        "warnings": warnings,
    })


@app.get("/health")
@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "tool": "VulnForge", "port": 5012})


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("VulnForge starting on 0.0.0.0:5012")
    app.run(host="0.0.0.0", port=5012, debug=False)
