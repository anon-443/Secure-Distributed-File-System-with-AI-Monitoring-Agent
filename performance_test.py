# Performance benchmark — AES-256-GCM upload/download speeds
# Saves performance_report.csv to same folder as this script
# Usage: python performance_test.py

import os, sys, time, csv, hashlib, statistics, requests

sys.path.insert(0, os.path.dirname(__file__))
from config import HOST, METADATA_SERVER_PORT, STORAGE_NODE_PORTS, CHUNK_SIZE, get_logger

log = get_logger("perf_test", "perf_test.log")
BASE = f"http://{HOST}:{METADATA_SERVER_PORT}"

# FIX Bug 4: save CSV in same directory as this script, not a dashboard/ subfolder
CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "performance_report.csv")

SIZES_KB     = [10, 50, 100, 256, 512, 1024]
RUNS_PER_SIZE = 3


def _login():
    r = requests.post(f"{BASE}/login",
                      json={"username": "adeen", "password": "Admin@2024"}, timeout=5)
    if r.status_code != 200:
        print(f"[!] Login failed. Is metadata_server running? {r.text}")
        sys.exit(1)
    return r.json()["token"]


def _upload(token, data, label):
    headers    = {"Authorization": f"Bearer {token}"}
    chunks     = [data[i:i+CHUNK_SIZE] for i in range(0, max(len(data), 1), CHUNK_SIZE)]
    num_chunks = len(chunks)

    r = requests.post(f"{BASE}/upload/init",
                      json={"filename": label, "file_size": len(data), "num_chunks": num_chunks},
                      headers=headers, timeout=5)
    r.raise_for_status()
    plan    = r.json()
    file_id = plan["file_id"]

    t0     = time.perf_counter()
    hashes = {}
    for cp in plan["chunk_plan"]:
        cid  = cp["chunk_id"]
        idx  = cp["index"]
        port = cp["nodes"][0]
        cd   = chunks[idx] if idx < len(chunks) else b""
        resp = requests.post(
            f"http://{HOST}:{port}/chunk/store", data=cd,
            headers={**headers, "X-Chunk-ID": cid, "Content-Type": "application/octet-stream"},
            timeout=15,
        )
        resp.raise_for_status()
        hashes[cid] = hashlib.sha256(cd).hexdigest()
    elapsed = time.perf_counter() - t0

    requests.post(f"{BASE}/upload/commit",
                  json={"file_id": file_id, "chunk_hashes": hashes},
                  headers=headers, timeout=5)
    return file_id, elapsed


def _download(token, file_id):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{BASE}/download/init", params={"file_id": file_id},
                     headers=headers, timeout=5)
    r.raise_for_status()
    plan = r.json()

    t0    = time.perf_counter()
    total = 0
    for cp in plan["chunk_plan"]:
        port = cp["nodes"][0]
        resp = requests.get(
            f"http://{HOST}:{port}/chunk/retrieve",
            params={"chunk_id": cp["chunk_id"]},
            headers=headers, timeout=15,
        )
        resp.raise_for_status()
        total += len(resp.content)
    return time.perf_counter() - t0, total


if __name__ == "__main__":
    print("=" * 55)
    print("  SDFS Performance Benchmark — AES-256-GCM")
    print(f"  Sizes: {SIZES_KB} KB  |  Runs/size: {RUNS_PER_SIZE}")
    print("=" * 55)

    token   = _login()
    results = []

    for size_kb in SIZES_KB:
        up_times, dn_times = [], []

        for run_i in range(1, RUNS_PER_SIZE + 1):
            label = f"bench_{size_kb}kb_r{run_i}.bin"
            data  = os.urandom(size_kb * 1024)
            print(f"\n  [{size_kb} KB  run {run_i}/{RUNS_PER_SIZE}]", end="  ", flush=True)
            try:
                fid, up_t = _upload(token, data, label)
                up_times.append(up_t)
                print(f"UP {up_t:.3f}s ({(size_kb/1024)/up_t:.2f} MB/s)", end="  ", flush=True)

                dn_t, dn_bytes = _download(token, fid)
                dn_times.append(dn_t)
                print(f"DOWN {dn_t:.3f}s ({(dn_bytes/1024/1024)/dn_t:.2f} MB/s)", flush=True)
            except Exception as e:
                print(f"ERROR: {e}")
                continue

        if up_times and dn_times:
            avg_up = statistics.mean(up_times)
            avg_dn = statistics.mean(dn_times)
            results.append({
                "file_size_kb":   size_kb,
                "runs":           len(up_times),
                "avg_upload_s":   round(avg_up, 4),
                "avg_download_s": round(avg_dn, 4),
                "upload_mbps":    round((size_kb / 1024) / avg_up, 3),
                "download_mbps":  round((size_kb / 1024) / avg_dn, 3),
                "encryption":     "AES-256-GCM",
                "chunk_size_kb":  CHUNK_SIZE // 1024,
            })
            print(f"  AVG: UP {avg_up:.3f}s  DOWN {avg_dn:.3f}s")

    if results:
        with open(CSV_PATH, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
            w.writeheader()
            w.writerows(results)
        print(f"\n  [OK] Report saved -> {CSV_PATH}")
    else:
        print("\n  [!] No results. Ensure all services are running.")

    print("=" * 55)