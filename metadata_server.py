# Metadata Server — Port 9000
# Handles auth, JWT, file/chunk registry, node registry, blocklist
# File registry is persisted to disk so files survive dashboard reload

import os, sys, time, hashlib, uuid, json
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt

sys.path.insert(0, os.path.dirname(__file__))
from config import (
    HOST, METADATA_SERVER_PORT, STORAGE_NODE_PORTS,
    JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_MINS,
    USERS, REPLICATION_FACTOR, CHUNK_SIZE,
    BRUTE_FORCE_THRESHOLD, TRUSTED_IPS, BASE_DIR, get_logger,
)

log = get_logger("metadata_server", "metadata.log")
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Persist registry to disk so files survive process restarts
REGISTRY_FILE = os.path.join(BASE_DIR, "file_registry.json")

node_registry = {p: {"status": "unknown", "last_seen": None, "bytes_stored": 0}
                 for p in STORAGE_NODE_PORTS}
failed_logins = {}
blocked_ips   = set()
START_TIME    = time.time()


def _load_registry():
    if os.path.exists(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE) as f:
                data = json.load(f)
            return data.get("files", {}), data.get("chunks", {})
        except Exception:
            pass
    return {}, {}


def _save_registry():
    try:
        with open(REGISTRY_FILE, "w") as f:
            json.dump({"files": file_registry, "chunks": chunk_registry}, f, indent=2)
    except Exception as e:
        log.error(f"REGISTRY | save_failed | {e}")


file_registry, chunk_registry = _load_registry()
log.info(f"REGISTRY | loaded | files={len(file_registry)} chunks={len(chunk_registry)}")


def _make_token(username, role):
    payload = {
        "sub": username, "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MINS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _verify_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        log.warning("JWT expired")
        return None
    except jwt.InvalidTokenError as e:
        log.warning(f"JWT invalid: {e}")
        return None


def require_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            log.warning(f"SECURITY | no_token | ip={request.remote_addr}")
            return jsonify({"error": "Missing token"}), 401
        claims = _verify_token(auth[7:])
        if claims is None:
            log.warning(f"SECURITY | jwt_invalid | ip={request.remote_addr}")
            return jsonify({"error": "Invalid or expired token"}), 401
        request.jwt_claims = claims
        return f(*args, **kwargs)
    return decorated


@app.route("/health")
def health():
    return jsonify({"status": "ok", "uptime": round(time.time() - START_TIME, 1)})


@app.route("/login", methods=["POST"])
def login():
    ip   = request.remote_addr
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # Block non-trusted IPs only
    if ip not in TRUSTED_IPS and ip in blocked_ips:
        return jsonify({"error": "IP blocked due to too many failed attempts"}), 403

    user    = USERS.get(username)
    pw_hash = hashlib.sha256(password.encode()).hexdigest()

    if not user or user["password_hash"] != pw_hash:
        if ip not in TRUSTED_IPS:
            failed_logins[ip] = failed_logins.get(ip, 0) + 1
            count = failed_logins[ip]
            log.warning(f"THREAT | brute_force | failed_login | ip={ip} | user={username} | attempt={count}")
            if count >= BRUTE_FORCE_THRESHOLD:
                blocked_ips.add(ip)
                log.error(f"THREAT | brute_force | IP_BLOCKED | ip={ip}")
        else:
            # Localhost: log the attempt with simulated IP so threat agent can detect it
            # without blocking real local services
            log.warning(f"THREAT | brute_force | failed_login | sim_ip=attacker_sim | user={username}")
        return jsonify({"error": "Invalid username or password"}), 401

    failed_logins.pop(ip, None)
    token = _make_token(username, user["role"])
    log.info(f"AUTH | login_ok | user={username} | role={user['role']}")
    return jsonify({"token": token, "username": username, "role": user["role"]})


@app.route("/upload/init", methods=["POST"])
@require_jwt
def upload_init():
    data       = request.get_json(silent=True) or {}
    filename   = data.get("filename") or f"file_{uuid.uuid4().hex[:8]}"
    file_size  = int(data.get("file_size", 0))
    num_chunks = max(1, int(data.get("num_chunks", 1)))
    owner      = request.jwt_claims["sub"]

    file_id = uuid.uuid4().hex
    online  = [p for p in STORAGE_NODE_PORTS
               if node_registry.get(p, {}).get("status") in ("online", "unknown")]
    if not online:
        online = list(STORAGE_NODE_PORTS)

    chunk_plan = []
    for i in range(num_chunks):
        cid     = f"{file_id}_chunk{i}"
        primary = online[i % len(online)]
        replica = online[(i + 1) % len(online)]
        nodes   = list({primary, replica})[:REPLICATION_FACTOR]
        chunk_registry[cid] = {"nodes": nodes, "hash": None}
        chunk_plan.append({"chunk_id": cid, "index": i, "nodes": nodes})

    file_registry[file_id] = {
        "filename":   filename,
        "owner":      owner,
        "size":       file_size,
        "chunks":     [c["chunk_id"] for c in chunk_plan],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status":     "uploading",
    }
    _save_registry()
    log.info(f"UPLOAD | init | file={filename} | owner={owner} | chunks={num_chunks}")
    return jsonify({"file_id": file_id, "chunk_plan": chunk_plan})


@app.route("/upload/commit", methods=["POST"])
@require_jwt
def upload_commit():
    data    = request.get_json(silent=True) or {}
    file_id = data.get("file_id", "")
    if file_id not in file_registry:
        return jsonify({"error": "Unknown file_id"}), 404
    for cid, h in data.get("chunk_hashes", {}).items():
        if cid in chunk_registry:
            chunk_registry[cid]["hash"] = h
    file_registry[file_id]["status"] = "complete"
    _save_registry()
    log.info(f"UPLOAD | commit | file_id={file_id}")
    return jsonify({"status": "committed", "file_id": file_id})


@app.route("/download/init")
@require_jwt
def download_init():
    file_id = request.args.get("file_id", "")
    if file_id not in file_registry:
        return jsonify({"error": "File not found"}), 404
    meta = file_registry[file_id]
    plan = [{"chunk_id": cid, "nodes": chunk_registry.get(cid, {}).get("nodes", [])}
            for cid in meta["chunks"]]
    log.info(f"DOWNLOAD | init | file={meta['filename']} | user={request.jwt_claims['sub']}")
    return jsonify({"file_id": file_id, "filename": meta["filename"], "chunk_plan": plan})


@app.route("/files")
@require_jwt
def list_files():
    user = request.jwt_claims["sub"]
    role = request.jwt_claims.get("role", "user")
    out  = []
    for fid, meta in file_registry.items():
        if role == "admin" or meta["owner"] == user:
            out.append({"file_id": fid, **meta})
    # Newest first
    out.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jsonify(out)


@app.route("/node/register", methods=["POST"])
def node_register():
    data = request.get_json(silent=True) or {}
    port = int(data.get("port", 0))
    if port not in STORAGE_NODE_PORTS:
        return jsonify({"error": "Unknown port"}), 400
    node_registry[port] = {
        "status": "online", "last_seen": time.time(),
        "bytes_stored": data.get("bytes_stored", 0), "port": port,
    }
    log.info(f"NODE | registered | port={port}")
    return jsonify({"status": "ok"})


@app.route("/node/heartbeat", methods=["POST"])
def node_heartbeat():
    data = request.get_json(silent=True) or {}
    port = int(data.get("port", 0))
    if port in node_registry:
        node_registry[port]["last_seen"]    = time.time()
        node_registry[port]["status"]       = "online"
        node_registry[port]["bytes_stored"] = data.get("bytes_stored", 0)
    return jsonify({"status": "ok"})


@app.route("/nodes")
def list_nodes():
    now = time.time()
    out = {}
    for port, info in node_registry.items():
        last = info.get("last_seen")
        if last and (now - last) > 15:
            info["status"] = "offline"
        out[str(port)] = info
    return jsonify(out)


@app.route("/blocklist")
def get_blocklist():
    safe = [ip for ip in blocked_ips if ip not in TRUSTED_IPS]
    return jsonify({"blocked_ips": safe})


@app.route("/blocklist/add", methods=["POST"])
def add_to_blocklist():
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "")
    if ip and ip not in TRUSTED_IPS:
        blocked_ips.add(ip)
        log.warning(f"THREAT | block_enforced | ip={ip}")
    return jsonify({"status": "ok"})


@app.route("/reset", methods=["POST"])
def reset_registry():
    global file_registry, chunk_registry, failed_logins, blocked_ips
    file_registry  = {}
    chunk_registry = {}
    failed_logins  = {}
    blocked_ips    = set()
    _save_registry()
    log.info("REGISTRY | reset | all cleared")
    return jsonify({"status": "reset"})


@app.route("/stats")
def stats():
    return jsonify({
        "files":        len(file_registry),
        "chunks":       len(chunk_registry),
        "nodes_online": sum(1 for n in node_registry.values() if n.get("status") == "online"),
        "uptime":       round(time.time() - START_TIME, 1),
        "blocked_ips":  len(blocked_ips),
    })


if __name__ == "__main__":
    log.info(f"Metadata Server starting on {HOST}:{METADATA_SERVER_PORT}")
    app.run(host=HOST, port=METADATA_SERVER_PORT, debug=False, threaded=True)
