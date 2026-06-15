# AI Agent — Port 8080
# Aggregates system status, runs RCA via Ollama, serves dashboard

import os, sys, time, threading, re
from datetime import datetime, timezone
from collections import deque

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(__file__))
from config import (
    HOST, AI_AGENT_PORT, METADATA_SERVER_URL,
    STORAGE_NODE_PORTS, THREAT_AGENT_PORT,
    OLLAMA_URL, OLLAMA_MODEL, AI_BOUNDARY_RULES,
    LOGS_DIR, get_logger,
)

log = get_logger("ai_agent", "ai_agent.log")
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

START_TIME        = time.time()
rca_log           = deque(maxlen=50)
node_status_cache = {}


def _call_ollama(prompt):
    if AI_BOUNDARY_RULES["deny_pii_in_prompts"]:
        prompt = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "[IP]", prompt)
    payload = {
        "model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
        "options": {"temperature": AI_BOUNDARY_RULES["temperature"],
                    "num_predict": AI_BOUNDARY_RULES["max_tokens"]},
        "think": False,
    }
    if AI_BOUNDARY_RULES["audit_all_ai_calls"]:
        log.info(f"AI_CALL | model={OLLAMA_MODEL} | chars={len(prompt)}")
    try:
        r = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=600)
        r.raise_for_status()
        text = r.json().get("response", "").strip()
        # Remove thinking blocks from qwen3
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
        return text
    except requests.ConnectionError:
        return "Ollama is not running. Start it with: ollama serve"
    except Exception as e:
        log.error(f"AI_CALL | error | {e}")
        return f"AI unavailable: {e}"


def _fetch_nodes():
    while True:
        out = {}
        for port in STORAGE_NODE_PORTS:
            try:
                r = requests.get(f"http://{HOST}:{port}/health", timeout=3)
                if r.status_code == 200:
                    d = r.json()
                    out[str(port)] = {
                        "status":       "online",
                        "uptime":       d.get("uptime", 0),
                        "bytes_stored": d.get("bytes_stored", 0),
                        "port":         port,
                    }
                else:
                    out[str(port)] = {"status": "offline", "port": port}
            except Exception:
                out[str(port)] = {"status": "offline", "port": port}
        global node_status_cache
        node_status_cache = out
        time.sleep(8)


def _run_rca(trigger=None):
    log_path = os.path.join(LOGS_DIR, "sdfs.log")
    lines = []
    if os.path.exists(log_path):
        try:
            with open(log_path, errors="replace") as f:
                lines = [l.strip() for l in f.readlines()[-30:] if l.strip()]
        except Exception:
            pass

    threats_ctx = ""
    try:
        r = requests.get(f"http://{HOST}:{THREAT_AGENT_PORT}/threats/recent", timeout=3)
        if r.status_code == 200:
            items = r.json().get("threats", [])[:5]
            threats_ctx = "\n".join(
                f"- [{t.get('severity')}] {t.get('type')}: {t.get('description')}"
                for t in items
            )
    except Exception:
        pass

    nodes_str = ", ".join(
        f"Node {p}: {'UP' if v.get('status') == 'online' else 'DOWN'}"
        for p, v in node_status_cache.items()
    ) or "No node data yet"

    prompt = (
        "You are a cybersecurity analyst for a Secure Distributed File System.\n"
        "Analyse the system state below and give a 3-4 sentence Root Cause Analysis.\n"
        "End with 1-2 concrete recommended actions.\n\n"
        f"Nodes: {nodes_str}\n"
        f"Event: {trigger or 'Routine periodic check'}\n"
        f"Recent logs:\n" + ("\n".join(lines[-15:]) or "None") + "\n"
        f"Active threats:\n{threats_ctx or 'None'}\n"
    )

    result = _call_ollama(prompt)
    sev = "INFO"
    up  = result.upper()
    if any(w in up for w in ["CRITICAL", "BREACH", "ATTACK", "COMPROMISED"]):
        sev = "CRITICAL"
    elif any(w in up for w in ["WARNING", "ANOMALY", "SUSPICIOUS", "MEDIUM"]):
        sev = "WARNING"

    rca_log.appendleft({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity":  sev,
        "trigger":   trigger or "periodic",
        "analysis":  result,
        "model":     OLLAMA_MODEL,
    })
    log.info(f"RCA | severity={sev} | trigger={trigger or 'periodic'}")


def _periodic_rca():
    time.sleep(60)   # wait 60s before first RCA so model loads
    while True:
        try:
            _run_rca()
        except Exception as e:
            log.error(f"RCA | error | {e}")
        time.sleep(120)  # run every 2 minutes


def _fmt_uptime(s):
    h, r = divmod(int(s), 3600)
    m, s = divmod(r, 60)
    if h:
        return f"{h}h {m}m {s}s"
    return f"{m}m {s}s" if m else f"{s}s"


@app.route("/health")
def health():
    return jsonify({"status": "ok", "uptime": round(time.time() - START_TIME, 1)})


@app.route("/status")
def status():
    uptime = round(time.time() - START_TIME, 1)
    meta   = {}
    try:
        r = requests.get(f"{METADATA_SERVER_URL}/stats", timeout=3)
        if r.status_code == 200:
            meta = r.json()
    except Exception:
        pass
    return jsonify({
        "uptime_seconds": uptime,
        "uptime_human":   _fmt_uptime(uptime),
        "nodes":          node_status_cache,
        "nodes_online":   sum(1 for v in node_status_cache.values() if v.get("status") == "online"),
        "nodes_total":    len(STORAGE_NODE_PORTS),
        "metadata":       meta,
        "rca_count":      len(rca_log),
        "ollama_model":   OLLAMA_MODEL,
        "timestamp":      datetime.now(timezone.utc).isoformat(),
    })


@app.route("/rca")
def get_rca():
    limit = min(int(request.args.get("limit", 10)), 50)
    return jsonify({"rca_entries": list(rca_log)[:limit], "total": len(rca_log)})


@app.route("/rca/trigger", methods=["POST"])
def trigger_rca():
    data  = request.get_json(silent=True) or {}
    event = data.get("event", "manual")
    threading.Thread(target=_run_rca, args=(event,), daemon=True).start()
    return jsonify({"status": "triggered", "event": event})


@app.route("/nodes")
def nodes():
    return jsonify(node_status_cache)


if __name__ == "__main__":
    log.info(f"AI Agent starting | port={AI_AGENT_PORT} | model={OLLAMA_MODEL}")
    threading.Thread(target=_fetch_nodes,  daemon=True).start()
    threading.Thread(target=_periodic_rca, daemon=True).start()
    app.run(host=HOST, port=AI_AGENT_PORT, debug=False, threaded=True)