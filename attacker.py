# Attack Simulator — for academic demonstration only
# Usage: python attacker.py [--attack brute_force|ransomware|exfiltration|ddos|all]

import os, sys, time, requests, threading, argparse

sys.path.insert(0, os.path.dirname(__file__))
from config import HOST, METADATA_SERVER_PORT, STORAGE_NODE_PORTS, THREAT_AGENT_PORT, get_logger

log = get_logger("attacker", "attacker.log")

META_URL   = f"http://{HOST}:{METADATA_SERVER_PORT}"
THREAT_URL = f"http://{HOST}:{THREAT_AGENT_PORT}"

# Each attack type uses a distinct simulated attacker IP
ATTACKER_IPS = {
    "brute_force":  "10.0.0.101",
    "ransomware":   "10.0.0.102",
    "exfiltration": "10.0.0.103",
    "ddos":         "10.0.0.104",
}


def _inject(t_type, severity, description):
    ip = ATTACKER_IPS.get(t_type, "10.0.0.100")
    try:
        requests.post(f"{THREAT_URL}/inject_threat", json={
            "type":        t_type,
            "severity":    severity,
            "description": description,
            "source_ip":   ip,
        }, timeout=5)
    except Exception as e:
        log.warning(f"INJECT | failed | {e}")


def attack_brute_force():
    ip = ATTACKER_IPS["brute_force"]
    print("\n[ATTACK] Brute Force Login")
    print(f"         Attacker IP: {ip}")
    wordlist = [
        "password", "123456", "admin", "root", "letmein",
        "qwerty", "pass", "secret", "test", "abc123", "monkey",
    ]
    for i, pw in enumerate(wordlist, 1):
        try:
            r = requests.post(f"{META_URL}/login",
                              json={"username": "adeen", "password": pw}, timeout=4)
            log.warning(f"THREAT | brute_force | failed_login | sim_ip={ip} | attempt={i} | status={r.status_code}")
            print(f"  [{i:02d}] pw='{pw[:4]}***' -> {r.status_code}")
        except Exception as e:
            print(f"  [{i:02d}] Error: {e}")
        time.sleep(0.4)

    _inject("brute_force", "HIGH", f"Brute force: {len(wordlist)} login attempts from {ip}")
    print("  [!] Brute force complete. GRC score dropped.\n")


def attack_ransomware():
    ip = ATTACKER_IPS["ransomware"]
    print("\n[ATTACK] Ransomware Simulation")
    print(f"         Attacker IP: {ip}")
    log.error(f"THREAT | ransomware | RANSOMWARE | mass_encrypt | sim_ip={ip}")

    for port in STORAGE_NODE_PORTS:
        for i in range(4):
            chunk_id = f"ransom_{port}_{i}"
            garbage  = b"\xFF\xFE" * 512 + b"RANSOM" * 20
            try:
                requests.post(
                    f"http://{HOST}:{port}/chunk/store",
                    data=garbage,
                    headers={"Authorization": "Bearer INVALID_TOKEN",
                             "X-Chunk-ID": chunk_id,
                             "Content-Type": "application/octet-stream"},
                    timeout=3,
                )
                log.warning(f"THREAT | ransomware | write_attempt | sim_ip={ip} | node={port} | chunk={chunk_id}")
                print(f"  [!] Write attempt -> node:{port} chunk:{chunk_id}")
            except Exception:
                pass
            time.sleep(0.2)

    _inject("ransomware", "CRITICAL", f"Mass encryption attempt from {ip} on all nodes")
    print("  [!] Ransomware complete. CRITICAL threat registered.\n")


def attack_exfiltration():
    ip = ATTACKER_IPS["exfiltration"]
    print("\n[ATTACK] Data Exfiltration")
    print(f"         Attacker IP: {ip}")
    log.warning(f"THREAT | exfiltration | EXFIL | data_exfil | sim_ip={ip}")

    for port in STORAGE_NODE_PORTS:
        try:
            r = requests.get(
                f"http://{HOST}:{port}/chunks",
                headers={"Authorization": "Bearer FAKE_TOKEN"}, timeout=3,
            )
            log.warning(f"THREAT | exfiltration | chunk_enum | sim_ip={ip} | node={port} | status={r.status_code}")
            print(f"  [!] Chunk enumeration -> node:{port} -> {r.status_code}")
        except Exception:
            pass

        for i in range(4):
            fake = f"exfil_{port}_{i}"
            try:
                requests.get(
                    f"http://{HOST}:{port}/chunk/retrieve",
                    params={"chunk_id": fake},
                    headers={"Authorization": "Bearer FAKE_TOKEN"}, timeout=2,
                )
                log.warning(f"THREAT | exfiltration | EXFIL | retrieve | sim_ip={ip} | chunk={fake}")
            except Exception:
                pass
            time.sleep(0.1)

    _inject("exfiltration", "HIGH", f"Bulk chunk retrieval attempt from {ip}")
    print("  [!] Exfiltration complete.\n")


def attack_ddos():
    ip = ATTACKER_IPS["ddos"]
    duration = 8
    num_threads = 6
    print(f"\n[ATTACK] DDoS Flood ({num_threads} threads, {duration}s)")
    print(f"         Attacker IP: {ip}")

    stop  = threading.Event()
    count = [0]
    lock  = threading.Lock()

    def _flood():
        while not stop.is_set():
            try:
                requests.get(f"{META_URL}/health", timeout=1)
                with lock:
                    count[0] += 1
            except Exception:
                pass
            time.sleep(0.05)

    workers = [threading.Thread(target=_flood, daemon=True) for _ in range(num_threads)]
    for w in workers:
        w.start()

    deadline = time.time() + duration
    interval = 0
    while time.time() < deadline:
        time.sleep(2)
        interval += 1
        rps = count[0] / max(1, interval * 2)
        log.warning(f"THREAT | ddos | DDoS | rate_limit_exceeded | flood | sim_ip={ip} | rps={rps:.0f} | total={count[0]}")
        print(f"  [!] DDoS ongoing — {count[0]} requests ({rps:.0f} req/s)")

    stop.set()
    for w in workers:
        w.join(timeout=2)

    _inject("ddos", "HIGH", f"DDoS flood: {count[0]} requests in {duration}s from {ip}")
    print(f"  [!] DDoS complete — {count[0]} total requests.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SDFS Attack Simulator")
    parser.add_argument("--attack",
                        choices=["brute_force","ransomware","exfiltration","ddos","all"],
                        default="all")
    args = parser.parse_args()

    print("=" * 55)
    print("  SDFS Attack Simulator — Academic Demo")
    print("=" * 55)

    attacks = {
        "brute_force":  attack_brute_force,
        "ransomware":   attack_ransomware,
        "exfiltration": attack_exfiltration,
        "ddos":         attack_ddos,
    }

    if args.attack == "all":
        for fn in attacks.values():
            fn()
            time.sleep(1)
    else:
        attacks[args.attack]()

    print("[DONE] Check dashboard — GRC score dropped, threats listed.")
