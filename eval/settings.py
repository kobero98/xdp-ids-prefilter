"""Testbed settings loaded from <repo>/config.env (environment overrides)."""
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PATH_KEYS = ("HSCOLLIDER", "DATA_DIR", "BUILD_DIR", "SLAVE_PCAP_REPLAY", "SLAVE_PCAP_DIR")


def _load():
    cfg = {}
    with open(os.path.join(REPO_ROOT, "config.env")) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    for k in cfg:
        cfg[k] = os.environ.get(k, cfg[k])
    for k in _PATH_KEYS:
        if k in cfg:
            cfg[k] = repo_path(cfg[k])
    return cfg


def repo_path(p):
    """Resolve a path relative to the repository root (absolute paths unchanged)."""
    p = os.path.expanduser(str(p))
    return p if os.path.isabs(p) else os.path.join(REPO_ROOT, p)


CFG = _load()
DUT_IFACE = CFG["DUT_IFACE"]
DUT_RX_RING = int(CFG.get("DUT_RX_RING", 8192))
SLAVE_MGMT_IP = CFG["SLAVE_MGMT_IP"]
SLAVE_PORT = int(CFG["SLAVE_PORT"])
SLAVE_IFACE = CFG["SLAVE_IFACE"]
SURICATA_BIN = CFG["SURICATA_BIN"]
BUILD_DIR = CFG["BUILD_DIR"]
DATA_DIR = CFG["DATA_DIR"]
