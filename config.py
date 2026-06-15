import os, sys, hashlib, logging
from logging.handlers import RotatingFileHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

# Network
HOST                 = "localhost"
METADATA_SERVER_PORT = 9000
STORAGE_NODE_PORTS   = [9001, 9002, 9003]
AI_AGENT_PORT        = 8080
THREAT_AGENT_PORT    = 9005
METADATA_SERVER_URL  = f"http://{HOST}:{METADATA_SERVER_PORT}"

# Ollama
OLLAMA_URL   = "http://localhost:11434"
OLLAMA_MODEL = "qwen3:4b"
AI_BOUNDARY_RULES = {
    "max_tokens": 512, "temperature": 0.2,
    "deny_pii_in_prompts": True, "audit_all_ai_calls": True,
}

# FIX: fixed JWT secret — all services must share the same key
# Override via env var SDFS_JWT_SECRET if needed
JWT_SECRET     = os.environ.get("SDFS_JWT_SECRET") or "SDFS_UniProject_JWT_2024_FixedKey_AdMn"
JWT_ALGORITHM  = "HS256"
JWT_EXPIRY_MINS = 120

# FIX: fixed AES-256 key — all storage nodes must share the same key
# Override via env var SDFS_AES_KEY (64 hex chars) if needed
_FIXED_AES = "a3f5c8e2b7d94061fe583a2c7b1d4e9fa3c5b2d7e4f1a6c8b9d2e5f7a4c1b3d6"
_aes = os.environ.get("SDFS_AES_KEY", _FIXED_AES)
try:
    SHARED_ENCRYPTION_KEY = bytes.fromhex(_aes)
except ValueError:
    SHARED_ENCRYPTION_KEY = bytes.fromhex(_FIXED_AES)

AES_NONCE_SIZE     = 12
CHUNK_SIZE         = 64 * 1024
REPLICATION_FACTOR = 2

# Users — SHA-256 hashed passwords
def _h(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

USERS = {
    "adeen":   {"password_hash": _h("Admin@2024"),  "role": "admin"},
    "manahil": {"password_hash": _h("User@2024"),   "role": "user"},
    "client1": {"password_hash": _h("Client@001"),  "role": "user"},
    "client2": {"password_hash": _h("Client@002"),  "role": "user"},
}

# GRC
BRUTE_FORCE_THRESHOLD = 5
GRC_INITIAL_SCORE     = 95.0
GRC_WEIGHTS = {
    "NIST_SP_800_207": 0.35,
    "NIST_AI_RMF":     0.25,
    "ISO_27001":       0.25,
    "OWASP_TOP10":     0.15,
}
GRC_PENALTIES = {
    "brute_force":  8,
    "ransomware":   15,
    "exfiltration": 12,
    "ddos":         10,
    "jwt_invalid":  3,
}

# IPs never blocked
TRUSTED_IPS = {"127.0.0.1", "::1", "localhost"}

# Logging
_FMT     = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"

def get_logger(name, log_file=None):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(_FMT, datefmt=_DATEFMT)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    sh.setLevel(logging.INFO)
    logger.addHandler(sh)
    ufh = RotatingFileHandler(
        os.path.join(LOGS_DIR, "sdfs.log"), maxBytes=5*1024*1024, backupCount=3)
    ufh.setFormatter(fmt)
    logger.addHandler(ufh)
    if log_file:
        sfh = RotatingFileHandler(
            os.path.join(LOGS_DIR, log_file), maxBytes=5*1024*1024, backupCount=2)
        sfh.setFormatter(fmt)
        logger.addHandler(sfh)
    logger.propagate = False
    return logger