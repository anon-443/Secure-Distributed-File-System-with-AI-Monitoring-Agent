# Storage Node — Ports 9001 / 9002 / 9003
# Usage: python storage_node.py <port>
# Stores AES-256-GCM encrypted chunks, validates JWT on every request

import os, sys, time, hashlib, threading, io, secrets
import requests
from functools import wraps
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import jwt

sys.path.insert(0, os.path.dirname(__file__))
from config import (
    HOST, STORAGE_NODE_PORTS, METADATA_SERVER_URL,
    JWT_SECRET, JWT_ALGORITHM,
    SHARED_ENCRYPTION_KEY, AES_NONCE_SIZE, get_logger,
)

if len(sys.argv) < 2:
    print("Usage: python storage_node.py <port>")
    sys.exit(1)

PORT = int(sys.argv[1])
if PORT not in STORAGE_NODE_PORTS:
    print(f"Invalid port. Allowed: {STORAGE_NODE_PORTS}")
    sys.exit(1)

STORAGE_DIR = os.path.join(os.path.dirname(__file__), f"node_storage_{PORT}")
os.makedirs(STORAGE_DIR, exist_ok=True)

log    = get_logger(f"node_{PORT}", f"storage_{PORT}.log")
app    = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
aesgcm = AESGCM(SHARED_ENCRYPTION_KEY)
START  = time.time()


def _verify_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        log.warning(f"SECURITY | jwt_expired | node={PORT}")
        return None
    except jwt.InvalidTokenError:
        log.warning(f"SECURITY | jwt_invalid | node={PORT}")
        return None


def require_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        if _verify_token(auth[7:]) is None:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated


def _encrypt(data):
    nonce = secrets.token_bytes(AES_NONCE_SIZE)
    return nonce + aesgcm.encrypt(nonce, data, None)


def _decrypt(blob):
    return aesgcm.decrypt(blob[:AES_NONCE_SIZE], blob[AES_NONCE_SIZE:], None)


def _bytes_stored():
    total = 0
    for fname in os.listdir(STORAGE_DIR):
        try:
            total += os.path.getsize(os.path.join(STORAGE_DIR, fname))
        except OSError:
            pass
    return total


def _chunk_path(chunk_id):
    safe = chunk_id.replace("/", "_").replace("..", "_")
    return os.path.join(STORAGE_DIR, f"{safe}.enc")


def _heartbeat():
    while True:
        try:
            requests.post(
                f"{METADATA_SERVER_URL}/node/heartbeat",
                json={"port": PORT, "bytes_stored": _bytes_stored()},
                timeout=3,
            )
        except Exception:
            pass
        time.sleep(5)


@app.route("/health")
def health():
    return jsonify({
        "status":       "online",
        "port":         PORT,
        "bytes_stored": _bytes_stored(),
        "uptime":       round(time.time() - START, 1),
    })


@app.route("/chunk/store", methods=["POST"])
@require_jwt
def store_chunk():
    chunk_id = request.headers.get("X-Chunk-ID", "")
    raw      = request.get_data()
    if not chunk_id or not raw:
        return jsonify({"error": "Missing chunk_id or body"}), 400

    with open(_chunk_path(chunk_id), "wb") as f:
        f.write(_encrypt(raw))

    sha256 = hashlib.sha256(raw).hexdigest()
    log.info(f"STORE | chunk={chunk_id[:16]} | size={len(raw)}B | node={PORT}")

    auth = request.headers.get("Authorization", "")
    threading.Thread(target=_replicate, args=(chunk_id, raw, auth), daemon=True).start()
    return jsonify({"status": "stored", "chunk_id": chunk_id, "sha256": sha256})


@app.route("/chunk/retrieve")
@require_jwt
def retrieve_chunk():
    chunk_id = request.args.get("chunk_id", "")
    path     = _chunk_path(chunk_id)
    if not os.path.exists(path):
        return jsonify({"error": "Chunk not found"}), 404
    with open(path, "rb") as f:
        blob = f.read()
    try:
        plain = _decrypt(blob)
    except Exception as e:
        log.error(f"DECRYPT | failed | chunk={chunk_id} | {e}")
        return jsonify({"error": "Decryption failed"}), 500
    log.info(f"RETRIEVE | chunk={chunk_id[:16]} | node={PORT}")
    return send_file(io.BytesIO(plain), mimetype="application/octet-stream")


@app.route("/chunk/replicate", methods=["POST"])
@require_jwt
def replicate_chunk():
    chunk_id = request.headers.get("X-Chunk-ID", "")
    raw      = request.get_data()
    if not chunk_id or not raw:
        return jsonify({"error": "Bad request"}), 400
    path = _chunk_path(chunk_id)
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(_encrypt(raw))
        log.info(f"REPLICATED | chunk={chunk_id[:16]} | node={PORT}")
    return jsonify({"status": "ok"})


@app.route("/chunks")
@require_jwt
def list_chunks():
    ids = [f.replace(".enc", "") for f in os.listdir(STORAGE_DIR) if f.endswith(".enc")]
    return jsonify({"node": PORT, "count": len(ids)})


def _replicate(chunk_id, data, auth_header):
    peers  = [p for p in STORAGE_NODE_PORTS if p != PORT]
    if not peers:
        return
    target = peers[hash(chunk_id) % len(peers)]
    try:
        requests.post(
            f"http://{HOST}:{target}/chunk/replicate",
            data=data,
            headers={"Authorization": auth_header, "X-Chunk-ID": chunk_id},
            timeout=5,
        )
    except Exception:
        pass


if __name__ == "__main__":
    log.info(f"Storage Node {PORT} starting | dir={STORAGE_DIR}")
    try:
        requests.post(
            f"{METADATA_SERVER_URL}/node/register",
            json={"port": PORT, "bytes_stored": _bytes_stored()},
            timeout=3,
        )
    except Exception:
        pass
    threading.Thread(target=_heartbeat, daemon=True).start()
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
