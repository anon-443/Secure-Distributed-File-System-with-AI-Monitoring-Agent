# Legitimate client simulation — generates healthy authenticated traffic
# Usage: python client.py

import os, sys, time, requests, hashlib, random, string

sys.path.insert(0, os.path.dirname(__file__))
from config import HOST, METADATA_SERVER_PORT, STORAGE_NODE_PORTS, CHUNK_SIZE, get_logger

log  = get_logger("client", "client.log")
BASE = f"http://{HOST}:{METADATA_SERVER_PORT}"

# Updated credentials to match config.py
CREDENTIALS = [
    ("adeen",   "Admin@2024"),
    ("manahil", "User@2024"),
    ("client1", "Client@001"),
    ("client2", "Client@002"),
]


def login(username, password):
    try:
        r = requests.post(f"{BASE}/login",
                          json={"username": username, "password": password}, timeout=5)
        if r.status_code == 200:
            log.info(f"AUTH | login_ok | user={username}")
            return r.json()["token"]
        log.warning(f"AUTH | login_fail | user={username} | {r.status_code}")
    except Exception as e:
        log.error(f"AUTH | error | {e}")
    return None


def upload_file(token, filename, data):
    headers    = {"Authorization": f"Bearer {token}"}
    chunks     = [data[i:i+CHUNK_SIZE] for i in range(0, max(len(data), 1), CHUNK_SIZE)]
    num_chunks = len(chunks)

    try:
        r = requests.post(f"{BASE}/upload/init",
                          json={"filename": filename, "file_size": len(data), "num_chunks": num_chunks},
                          headers=headers, timeout=5)
        if r.status_code != 200:
            log.error(f"UPLOAD | init_fail | {r.status_code}")
            return None
        plan    = r.json()
        file_id = plan["file_id"]
    except Exception as e:
        log.error(f"UPLOAD | init_error | {e}")
        return None

    hashes = {}
    for cp in plan["chunk_plan"]:
        cid  = cp["chunk_id"]
        idx  = cp["index"]
        port = cp["nodes"][0]
        cd   = chunks[idx] if idx < len(chunks) else b""
        try:
            sr = requests.post(
                f"http://{HOST}:{port}/chunk/store", data=cd,
                headers={**headers, "X-Chunk-ID": cid, "Content-Type": "application/octet-stream"},
                timeout=10,
            )
            if sr.status_code == 200:
                hashes[cid] = hashlib.sha256(cd).hexdigest()
        except Exception as e:
            log.warning(f"UPLOAD | chunk_error | {e}")

    try:
        r = requests.post(f"{BASE}/upload/commit",
                          json={"file_id": file_id, "chunk_hashes": hashes},
                          headers=headers, timeout=5)
        if r.status_code == 200:
            log.info(f"UPLOAD | ok | file={filename} | size={len(data)}")
            return file_id
    except Exception as e:
        log.error(f"UPLOAD | commit_error | {e}")
    return None


def download_file(token, file_id):
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(f"{BASE}/download/init", params={"file_id": file_id},
                         headers=headers, timeout=5)
        if r.status_code != 200:
            return None
        plan = r.json()
    except Exception:
        return None

    data = b""
    for cp in plan["chunk_plan"]:
        port = cp["nodes"][0]
        try:
            sr = requests.get(
                f"http://{HOST}:{port}/chunk/retrieve",
                params={"chunk_id": cp["chunk_id"]},
                headers=headers, timeout=10,
            )
            if sr.status_code == 200:
                data += sr.content
        except Exception:
            pass
    log.info(f"DOWNLOAD | ok | file_id={file_id} | bytes={len(data)}")
    return data


def _random_content(size_kb):
    return (''.join(random.choices(string.ascii_letters + string.digits, k=size_kb * 1024))).encode()


if __name__ == "__main__":
    print("=" * 50)
    print("  SDFS Client Simulation — healthy traffic")
    print("=" * 50)

    uploaded = []
    iteration = 0
    while True:
        iteration += 1
        user, pw = random.choice(CREDENTIALS)
        token = login(user, pw)
        if not token:
            print(f"  [!] Login failed for {user}. Is metadata_server running?")
            time.sleep(5)
            continue

        size_kb = random.choice([10, 50, 100, 256])
        fname   = f"{user}_file{iteration}_{random.randint(100,999)}.bin"
        content = _random_content(size_kb)
        fid     = upload_file(token, fname, content)
        if fid:
            uploaded.append((fid, token))
            print(f"  [+] Uploaded {fname} ({size_kb} KB) as {user}")
        else:
            print(f"  [!] Upload failed")

        if uploaded and random.random() < 0.3:
            fid2, tok2 = random.choice(uploaded)
            result = download_file(tok2, fid2)
            if result:
                print(f"  [↓] Downloaded {len(result)} bytes")

        print(f"  Iteration {iteration} done. Sleeping 5s...\n")
        time.sleep(5)
