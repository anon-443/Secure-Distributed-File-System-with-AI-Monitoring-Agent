# Cleanup — wipe logs and stored chunks for a fresh demo session
# Usage:
#   python backend/cleanup.py              -- wipe logs + chunks
#   python backend/cleanup.py --keep-files -- wipe logs only

import os, sys, glob, argparse

try:
    import requests as _req
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
REGISTRY = os.path.join(BASE_DIR, "file_registry.json")
STORAGE_DIRS = [os.path.join(BASE_DIR, f"node_storage_{p}") for p in [9001, 9002, 9003]]


def wipe_logs():
    files = glob.glob(os.path.join(LOGS_DIR, "*.log*")) if os.path.exists(LOGS_DIR) else []
    for f in files:
        try:
            os.remove(f)
            print(f"  Deleted: {os.path.basename(f)}")
        except Exception as e:
            print(f"  Error: {f} — {e}")
    if not files:
        print("  Logs already empty.")


def wipe_storage():
    if os.path.exists(REGISTRY):
        os.remove(REGISTRY)
        print(f"  Deleted: file_registry.json")
    for d in STORAGE_DIRS:
        if not os.path.exists(d):
            continue
        enc = glob.glob(os.path.join(d, "*.enc"))
        for f in enc:
            try:
                os.remove(f)
            except Exception:
                pass
        print(f"  Cleared {len(enc)} chunk(s) from {os.path.basename(d)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep-files", action="store_true",
                        help="Wipe logs only, keep stored file chunks")
    args = parser.parse_args()

    print("\n== SDFS Cleanup ==")
    print("Wiping logs...")
    wipe_logs()
    if not args.keep_files:
        print("Wiping stored chunks and file registry...")
        wipe_storage()

    # Reset live server memory so dashboard shows empty immediately
    if _REQUESTS:
        print("Resetting server memory...")
        for url, name in [
            ("http://localhost:9000/reset", "Metadata Server"),
            ("http://localhost:9005/reset", "Threat Agent"),
        ]:
            try:
                r = _req.post(url, timeout=3)
                if r.status_code == 200:
                    print(f"  {name} memory cleared.")
                else:
                    print(f"  {name}: reset failed (not critical).")
            except Exception:
                print(f"  {name} not running — start it fresh.")

    print("\nDone. System ready for a fresh session.\n")
