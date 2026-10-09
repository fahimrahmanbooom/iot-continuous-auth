"""Run the unchanged verification server with N emulated devices registered.

Used only by run_load_test.py. Emulated device keys are derived from a fixed
seed, and all logs go to a separate directory so that load-test traffic never
mixes with device data.
"""

import hashlib
import os
import socket
import ssl
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server"))

import config  # noqa: E402
import verification_server as vs  # noqa: E402

SEED = b"emulated-device-load-test"


def emulated_key(device_id):
    return hashlib.sha256(SEED + device_id.encode()).hexdigest()


def main():
    count = int(sys.argv[1])
    port = int(sys.argv[2])
    log_dir = Path(sys.argv[3])
    log_dir.mkdir(parents=True, exist_ok=True)
    for k in range(count):
        device_id = f"emu-{k:04d}"
        config.DEVICE_KEYS[device_id] = emulated_key(device_id)
    vs.LOG_DIR = str(log_dir)
    vs.AUTH_LOG = str(log_dir / "auth_events.csv")
    vs.DECISION_LOG = str(log_dir / "decisions.csv")
    vs.ENVELOPE_CAPTURE = ""
    vs.ensure_log_dir()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(config.TLS_CERT, config.TLS_KEY)
    socket.setdefaulttimeout(15)
    vs.app.run(host="127.0.0.1", port=port, ssl_context=context, debug=False)


if __name__ == "__main__":
    main()
