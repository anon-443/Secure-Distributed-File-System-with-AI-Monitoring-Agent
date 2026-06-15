# Threat Agent (SOC) — Port 9005
# Tails logs, detects attacks, manages GRC score, blocks attacker IPs

import os, sys, time, re, threading
from datetime import datetime, timezone
from collections import deque, defaultdict

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(__file__))
from config import (
    HOST, THREAT_AGENT_PORT, AI_AGENT_PORT, METADATA_SERVER_URL,
    LOGS_DIR, GRC_INITIAL_SCORE, GRC_WEIGHTS, GRC_PENALTIES,
    TRUSTED_IPS, get_logger,
)

log = get_logger("threat_agent", "threat_agent.log")
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

START_TIME = time.time()

threats        = deque(maxlen=200)
grc_score      = float(GRC_INITIAL_SCORE)
blocked_ips    = set()
events_by_type = defaultdict(int)
framework_scores = {k: float(GRC_INITIAL_SCORE) for k in GRC_WEIGHTS}

# Deduplication — each (attack_type, source_ip) recorded only once per session
_seen = set()

# Attack patterns matched against log lines
PATTERNS = [
    {
        "name": "brute_force",
        "re":   re.compile(r"THREAT.*brute_force|failed_login.*attempt=", re.I),
        "sev":  "HIGH",      "penalty": "brute_force",
        "nist": "IA-5",      "iso": "A.9.4.2",
        "fw":   ["NIST_SP_800_207", "ISO_27001", "OWASP_TOP10"],
        "desc": "Brute force login attack detected",
    },
    {
        "name": "ransomware",
        "re":   re.compile(r"THREAT.*ransomware|RANSOMWARE|mass_encrypt", re.I),
        "sev":  "CRITICAL",  "penalty": "ransomware",
        "nist": "IR-4",      "iso": "A.16.1.5",
        "fw":   ["NIST_SP_800_207", "ISO_27001"],
        "desc": "Ransomware / mass encryption attempt",
    },
    {
        "name": "exfiltration",
        "re":   re.compile(r"THREAT.*exfiltration|EXFIL|data_exfil", re.I),
        "sev":  "HIGH",      "penalty": "exfiltration",
        "nist": "SI-3",      "iso": "A.13.2.1",
        "fw":   ["NIST_SP_800_207", "ISO_27001", "OWASP_TOP10"],
        "desc": "Data exfiltration attempt detected",
    },
    {
        "name": "ddos",
        "re":   re.compile(r"THREAT.*ddos|DDoS|rate_limit_exceeded|flood", re.I),
        "sev":  "HIGH",      "penalty": "ddos",
        "nist": "SC-5",      "iso": "A.17.1.1",
        "fw":   ["NIST_SP_800_207", "NIST_AI_RMF"],
        "desc": "DDoS / flood attack detected",
    },
    {
        "name": "jwt_invalid",
        "re":   re.compile(r"SECURITY.*jwt_invalid|invalid_token|jwt_expired", re.I),
        "sev":  "MEDIUM",    "penalty": "jwt_invalid",
        "nist": "IA-2",      "iso": "A.9.2.1",
        "fw":   ["OWASP_TOP10", "NIST_SP_800_207"],
        "desc": "Invalid or forged JWT token detected",
    },
]

# Log lines that are system noise — skip these
_SKIP = re.compile(
    r"IP_BLOCKED|block_enforced|heartbeat|LOG_TAIL|GRC \||RESET \|"
    r"|REPLICATED|registered|login_ok|commit|STORE \||RETRIEVE \||AI_CALL",
    re.I,
)


def _recalc():
    global grc_score
    grc_score = round(
        max(0.0, min(100.0,
            sum(framework_scores[fw] * GRC_WEIGHTS[fw] for fw in GRC_WEIGHTS)
        )), 1
    )


def _apply_penalty(penalty_key, frameworks):
    p = GRC_PENALTIES.get(penalty_key, 2)
    for fw in frameworks:
        if fw in framework_scores:
            framework_scores[fw] = max(0.0, framework_scores[fw] - p)
    _recalc()
    log.warning(f"GRC | score={grc_score} | event={penalty_key} | penalty={p}")


def _recover():
    while True:
        time.sleep(60)
        now = time.time()
        recent_high = any(
            t["severity"] in ("HIGH", "CRITICAL") and
            (now - _parse_ts(t["timestamp"])) < 120
            for t in list(threats)[:5]
        )
        if not recent_high:
            for fw in framework_scores:
                framework_scores[fw] = min(GRC_INITIAL_SCORE, framework_scores[fw] + 0.5)
            _recalc()
            log.info(f"GRC | recovery | score={grc_score}")


def _parse_ts(s):
    try:
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return 0.0


def _tail():
    path = os.path.join(LOGS_DIR, "sdfs.log")
    # Skip all lines that existed before this session — prevents old attacks re-triggering
    seen = 0
    if os.path.exists(path):
        try:
            with open(path, errors="replace") as f:
                seen = sum(1 for _ in f)
            log.info(f"LOG_TAIL | startup | skipping {seen} existing lines")
        except Exception:
            pass

    while True:
        try:
            if not os.path.exists(path):
                time.sleep(2)
                continue
            with open(path, errors="replace") as f:
                lines = f.readlines()
            for line in lines[seen:]:
                _check(line.strip())
            seen = len(lines)
        except Exception as e:
            log.error(f"LOG_TAIL | error | {e}")
        time.sleep(1)


def _check(line):
    if not line or _SKIP.search(line):
        return
    for p in PATTERNS:
        if p["re"].search(line):
            m  = re.search(r"(?:sim_ip|ip)=([^\s|]+)", line)
            ip = m.group(1) if m else "unknown"
            _record(p, ip)
            break


def _record(pattern, src_ip):
    key = (pattern["name"], src_ip)
    if key in _seen:
        return
    _seen.add(key)
    events_by_type[pattern["name"]] += 1

    entry = {
        "id":           len(threats) + 1,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "type":         pattern["name"],
        "severity":     pattern["sev"],
        "description":  pattern["desc"],
        "source_ip":    src_ip,
        "nist_control": pattern["nist"],
        "iso_control":  pattern["iso"],
        "status":       "active",
    }
    threats.appendleft(entry)
    _apply_penalty(pattern["penalty"], pattern["fw"])

    # Block non-trusted IPs on HIGH/CRITICAL
    if pattern["sev"] in ("HIGH", "CRITICAL") and src_ip not in TRUSTED_IPS and src_ip != "unknown":
        _block(src_ip)

    # Trigger AI RCA on CRITICAL events
    if pattern["sev"] == "CRITICAL":
        threading.Thread(
            target=_trigger_rca, args=(f"{pattern['name']} from {src_ip}",), daemon=True
        ).start()


def _block(ip):
    if ip in blocked_ips or ip in TRUSTED_IPS:
        return
    blocked_ips.add(ip)
    try:
        requests.post(f"{METADATA_SERVER_URL}/blocklist/add", json={"ip": ip}, timeout=3)
        log.warning(f"BLOCK | ip={ip}")
    except Exception:
        pass


def _trigger_rca(event):
    try:
        requests.post(
            f"http://{HOST}:{AI_AGENT_PORT}/rca/trigger",
            json={"event": event}, timeout=5,
        )
    except Exception:
        pass


# Routes

@app.route("/health")
def health():
    return jsonify({"status": "ok", "uptime": round(time.time() - START_TIME, 1)})


@app.route("/grc")
def grc():
    label = ("CRITICAL"  if grc_score < 50 else
             "HIGH RISK" if grc_score < 70 else
             "MODERATE"  if grc_score < 85 else "GOOD")
    return jsonify({
        "overall_score": grc_score,
        "label":         label,
        "frameworks": {
            "NIST_SP_800_207": {
                "name":     "NIST SP 800-207 (Zero Trust)",
                "score":    round(framework_scores["NIST_SP_800_207"], 1),
                "weight":   GRC_WEIGHTS["NIST_SP_800_207"],
                "controls": ["AC-3", "IA-2", "IA-5", "SC-7"],
            },
            "NIST_AI_RMF": {
                "name":     "NIST AI RMF 1.0",
                "score":    round(framework_scores["NIST_AI_RMF"], 1),
                "weight":   GRC_WEIGHTS["NIST_AI_RMF"],
                "controls": ["GOVERN-1.1", "MAP-3.5", "MEASURE-2.1"],
            },
            "ISO_27001": {
                "name":     "ISO/IEC 27001:2022",
                "score":    round(framework_scores["ISO_27001"], 1),
                "weight":   GRC_WEIGHTS["ISO_27001"],
                "controls": ["A.9", "A.10", "A.12", "A.16"],
            },
            "OWASP_TOP10": {
                "name":     "OWASP Top 10 2021",
                "score":    round(framework_scores["OWASP_TOP10"], 1),
                "weight":   GRC_WEIGHTS["OWASP_TOP10"],
                "controls": ["A01", "A02", "A07"],
            },
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/threats")
def get_threats():
    limit       = min(int(request.args.get("limit", 20)), 200)
    safe_blocked = [ip for ip in blocked_ips if ip not in TRUSTED_IPS]
    return jsonify({
        "threats":     list(threats)[:limit],
        "total":       len(threats),
        "grc_score":   grc_score,
        "blocked_ips": safe_blocked,
    })


@app.route("/threats/recent")
def recent_threats():
    return jsonify({"threats": list(threats)[:10], "grc_score": grc_score})


@app.route("/threats/summary")
def threat_summary():
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for t in threats:
        s = t.get("severity", "LOW")
        by_sev[s] = by_sev.get(s, 0) + 1
    safe_blocked = [ip for ip in blocked_ips if ip not in TRUSTED_IPS]
    return jsonify({
        "total_threats":     len(threats),
        "by_severity":       by_sev,
        "by_type":           dict(events_by_type),
        "blocked_ips_count": len(safe_blocked),
        "grc_score":         grc_score,
        "framework_scores":  {k: round(v, 1) for k, v in framework_scores.items()},
    })


@app.route("/blocklist")
def get_blocklist():
    safe = [ip for ip in blocked_ips if ip not in TRUSTED_IPS]
    return jsonify({"blocked_ips": safe, "count": len(safe)})


@app.route("/inject_threat", methods=["POST"])
def inject_threat():
    data   = request.get_json(silent=True) or {}
    t_type = data.get("type", "unknown")
    sev    = data.get("severity", "HIGH")
    desc   = data.get("description", "Simulated attack")
    src_ip = data.get("source_ip", "attacker_sim")

    MAP = {
        "brute_force":  ("IA-5", "A.9.4.2",  ["NIST_SP_800_207","ISO_27001","OWASP_TOP10"]),
        "ransomware":   ("IR-4", "A.16.1.5", ["NIST_SP_800_207","ISO_27001"]),
        "exfiltration": ("SI-3", "A.13.2.1", ["NIST_SP_800_207","ISO_27001","OWASP_TOP10"]),
        "ddos":         ("SC-5", "A.17.1.1", ["NIST_SP_800_207","NIST_AI_RMF"]),
        "jwt_invalid":  ("IA-2", "A.9.2.1",  ["OWASP_TOP10","NIST_SP_800_207"]),
    }
    nist, iso, fws = MAP.get(t_type, ("AC-1", "A.5.1", []))
    pattern = {"name": t_type, "sev": sev, "penalty": t_type,
               "nist": nist, "iso": iso, "fw": fws, "desc": desc}
    _record(pattern, src_ip)
    log.warning(f"THREAT | {t_type} | sev={sev} | sim_ip={src_ip} | {desc}")
    return jsonify({"status": "recorded", "grc_score": grc_score})


@app.route("/reset", methods=["POST"])
def reset():
    global grc_score
    for fw in framework_scores:
        framework_scores[fw] = float(GRC_INITIAL_SCORE)
    grc_score = float(GRC_INITIAL_SCORE)
    threats.clear()
    events_by_type.clear()
    blocked_ips.clear()
    _seen.clear()
    log.info(f"RESET | all state cleared | grc={GRC_INITIAL_SCORE}")
    return jsonify({"status": "reset", "grc_score": grc_score})


if __name__ == "__main__":
    log.info(f"Threat Agent starting | port={THREAT_AGENT_PORT} | grc={GRC_INITIAL_SCORE}")
    threading.Thread(target=_tail,    daemon=True).start()
    threading.Thread(target=_recover, daemon=True).start()
    app.run(host=HOST, port=THREAT_AGENT_PORT, debug=False, threaded=True)
