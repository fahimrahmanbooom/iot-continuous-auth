"""
verification_server.py
HTTPS Verification Server for Continuous Authentication Framework.

Receives telemetry from ESP32 devices over TLS, evaluates authentication
state, issues cryptographic challenges, and logs all telemetry and
authentication events to CSV for analysis.

Endpoints:
    POST /api/telemetry           - Receive device telemetry
    POST /api/challenge_response  - Receive challenge responses
    GET  /api/status/<device_id>  - Query device auth state

Author : Fahim Rahman
Date   : December 2025
License: MIT
"""

import os
import csv
import json
import hmac
import hashlib
import ipaddress
import time
import socket
import ssl
from datetime import datetime, timezone

from flask import Flask, request, jsonify

from config import (
    SERVER_HOST, SERVER_PORT,
    TLS_CERT, TLS_KEY,
    DEVICE_KEYS,
    DEVELOPMENT_DEVICE_KEY,
    LOG_DIR,
    AUTH_LOG,
    DECISION_LOG,
    ENVELOPE_CAPTURE,
    WINDOW_SIZE,
    SUSPICION_THRESHOLD,
    CHALLENGE_THRESHOLD,
)
from auth_engine import AuthEngine, AuthState

# ─── Application Setup ───────────────────────────────────────────────────────

app = Flask(__name__)
engine = AuthEngine()

# CSV column headers matching the experimental datasets
TELEMETRY_COLUMNS = [
    "log_ts_utc", "server_ts", "device_id", "seq", "ts_ms",
    "uptime_ms", "wifi_connected", "internet_state", "rssi_dbm",
    "bssid", "channel", "dns1", "dns2", "heap_free", "min_free_heap",
    "latency_ms", "reset_reason", "free_heap", "loop_jitter_ms",
    "uptime_s", "wifi_bssid_hash", "wifi_rssi",
]

AUTH_COLUMNS = [
    "timestamp", "device_id", "state", "prev_state", "score",
    "avg_score", "trigger", "challenge_nonce",
]

DECISION_COLUMNS = [
    "log_ts_utc", "server_ts", "remote_addr", "device_id", "seq",
    "uptime_ms", "internet_state", "rssi_dbm", "wifi_bssid_hash", "channel",
    "dns1", "dns2", "heap_free", "latency_ms", "reset_reason", "score",
    "avg_score", "prev_state", "state", "status", "challenge_issued",
    "challenge_nonce",
]

REQUIRED_TELEMETRY_FIELDS = {
    "device_id": str,
    "seq": int,
    "ts_ms": int,
    "uptime_ms": int,
    "wifi_connected": int,
    "internet_state": int,
    "rssi_dbm": int,
    "channel": int,
    "dns1": str,
    "dns2": str,
    "heap_free": int,
    "latency_ms": int,
    "wifi_bssid_hash": str,
}


def ensure_log_dir():
    """Create the log directory and initialize CSV headers."""
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(AUTH_LOG):
        with open(AUTH_LOG, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(AUTH_COLUMNS)


def get_telemetry_log(device_id: str) -> str:
    """Return the path to the per-device telemetry log file."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    filename = f"telemetry_{device_id}_{ts}.csv"
    return os.path.join(LOG_DIR, filename)


def log_telemetry(telemetry: dict):
    """Append a telemetry record to the per-device CSV log."""
    device_id = telemetry.get("device_id", "unknown")
    logfile = get_telemetry_log(device_id)

    file_exists = os.path.exists(logfile)
    with open(logfile, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(TELEMETRY_COLUMNS)

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        server_ts = int(time.time())

        row = [
            now_utc,
            server_ts,
            device_id,
            telemetry.get("seq", ""),
            telemetry.get("ts_ms", ""),
            telemetry.get("uptime_ms", ""),
            telemetry.get("wifi_connected", ""),
            telemetry.get("internet_state", ""),
            telemetry.get("rssi_dbm", ""),
            telemetry.get("bssid", ""),
            telemetry.get("channel", ""),
            telemetry.get("dns1", ""),
            telemetry.get("dns2", ""),
            telemetry.get("heap_free", ""),
            telemetry.get("min_free_heap", ""),
            telemetry.get("latency_ms", ""),
            telemetry.get("reset_reason", ""),
            telemetry.get("free_heap", ""),
            telemetry.get("loop_jitter_ms", ""),
            telemetry.get("uptime_s", ""),
            telemetry.get("wifi_bssid_hash", ""),
            telemetry.get("wifi_rssi", ""),
        ]
        writer.writerow(row)


def log_auth_event(device_id: str, state: str, prev_state: str,
                   score: float, avg_score: float, trigger: str,
                   nonce: str = ""):
    """Append an authentication event to the auth log."""
    with open(AUTH_LOG, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            device_id,
            state,
            prev_state,
            round(score, 4),
            round(avg_score, 4),
            trigger,
            nonce,
        ])


def log_decision(payload: dict, result: dict, prev_state: str,
                 remote_addr: str):
    """Append the decision for one accepted telemetry message."""
    new_file = not os.path.exists(DECISION_LOG)
    with open(DECISION_LOG, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(DECISION_COLUMNS)
        writer.writerow([
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            round(time.time(), 3),
            remote_addr,
            payload.get("device_id", ""),
            payload.get("seq", ""),
            payload.get("uptime_ms", ""),
            payload.get("internet_state", ""),
            payload.get("rssi_dbm", ""),
            payload.get("wifi_bssid_hash", ""),
            payload.get("channel", ""),
            payload.get("dns1", ""),
            payload.get("dns2", ""),
            payload.get("heap_free", ""),
            payload.get("latency_ms", ""),
            payload.get("reset_reason", ""),
            result["score"],
            result["avg_score"],
            prev_state,
            result["state"],
            result["status"],
            int(bool(result.get("challenge"))),
            result.get("challenge", {}).get("nonce", ""),
        ])


def capture_envelope(envelope: dict):
    """Store an accepted signed envelope when capture is enabled."""
    if not ENVELOPE_CAPTURE:
        return
    with open(ENVELOPE_CAPTURE, "a", encoding="utf-8") as f:
        f.write(json.dumps(envelope, separators=(",", ":"),
                           sort_keys=True) + "\n")


def verify_hmac(payload_str: str, received_hmac: str,
                device_id: str) -> bool:
    """Verify the HMAC-SHA256 signature on the telemetry payload."""
    key = DEVICE_KEYS.get(device_id)
    if not key:
        return False
    expected = hmac.new(
        key.encode("utf-8"),
        payload_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, received_hmac)


def canonical_payload(payload: dict) -> str:
    """Serialize telemetry exactly as the firmware signs it."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def valid_envelope(envelope: object) -> bool:
    """Return True for the expected signed telemetry envelope shape."""
    if not isinstance(envelope, dict):
        return False
    payload = envelope.get("payload")
    signature = envelope.get("hmac")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return False
    device_id = payload.get("device_id")
    if not isinstance(device_id, str) or device_id not in DEVICE_KEYS:
        return False
    if len(signature) != 64:
        return False
    try:
        int(signature, 16)
    except ValueError:
        return False
    return True


def valid_telemetry_payload(payload: object) -> bool:
    """Validate required scoring fields before logging or state evaluation."""
    if not isinstance(payload, dict):
        return False
    for field, expected_type in REQUIRED_TELEMETRY_FIELDS.items():
        value = payload.get(field)
        if expected_type is int:
            if isinstance(value, bool) or not isinstance(value, int):
                return False
        elif not isinstance(value, expected_type):
            return False

    if payload["device_id"] not in DEVICE_KEYS:
        return False
    if payload["seq"] < 0 or payload["ts_ms"] < 0 or payload["uptime_ms"] < 0:
        return False
    if payload["wifi_connected"] not in {0, 1}:
        return False
    if payload["internet_state"] not in {0, 1, 2}:
        return False
    if not -127 <= payload["rssi_dbm"] <= 0:
        return False
    if not 0 <= payload["channel"] <= 14:
        return False
    if payload["heap_free"] < 0 or not 0 <= payload["latency_ms"] <= 120000:
        return False
    if not payload["wifi_bssid_hash"] or len(payload["wifi_bssid_hash"]) > 128:
        return False
    try:
        ipaddress.ip_address(payload["dns1"])
        ipaddress.ip_address(payload["dns2"])
    except ValueError:
        return False
    return True


# ─── API Endpoints ───────────────────────────────────────────────────────────

@app.route("/api/telemetry", methods=["POST"])
def receive_telemetry():
    """
    Receive telemetry from an IoT device.

    Expected JSON envelope:
    {
        "payload": { ... telemetry fields ... },
        "hmac": "<hex string>"
    }
    """
    try:
        envelope = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    if not valid_envelope(envelope):
        return jsonify({"error": "invalid_envelope"}), 400

    payload = envelope["payload"]
    received_sig = envelope["hmac"]
    device_id = payload["device_id"]

    # Verify HMAC integrity
    payload_str = canonical_payload(payload)
    if not verify_hmac(payload_str, received_sig, device_id):
        return jsonify({"error": "invalid_hmac"}), 401

    if not valid_telemetry_payload(payload):
        return jsonify({"error": "invalid_telemetry"}), 400

    # Log raw telemetry to CSV
    log_telemetry(payload)

    # Get previous state for logging
    ctx = engine.get_or_create_device(device_id)
    prev_state = ctx.state.value

    # Evaluate through authentication engine
    result = engine.evaluate_telemetry(payload)
    new_state = result["state"]
    log_decision(payload, result, prev_state, request.remote_addr or "")
    capture_envelope(envelope)

    # Log authentication state changes
    if new_state != prev_state:
        log_auth_event(
            device_id, new_state, prev_state,
            result["score"], result["avg_score"],
            "telemetry_evaluation",
            result.get("challenge", {}).get("nonce", "")
        )

    # Build response
    response = {
        "status": "ok",
        "state": new_state,
        "score": result["avg_score"],
    }

    # Include challenge if one was issued
    if "challenge" in result and result["challenge"]:
        response["challenge"] = {
            "nonce": result["challenge"]["nonce"],
        }
        print(f"[Server] Challenge issued to {device_id} "
              f"(score={result['avg_score']:.3f})")

    return jsonify(response), 200


@app.route("/api/challenge_response", methods=["POST"])
def receive_challenge_response():
    """
    Receive a challenge response from a device.

    Expected JSON:
    {
        "device_id": "...",
        "nonce": "...",
        "ts": 12345,
        "hmac": "<hex string>"
    }
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "invalid_request"}), 400

    device_id = data.get("device_id", "")
    nonce = data.get("nonce", "")
    ts = data.get("ts", 0)
    sig = data.get("hmac", "")

    if (device_id not in DEVICE_KEYS or not isinstance(nonce, str) or
            not isinstance(ts, int) or not isinstance(sig, str)):
        return jsonify({"error": "invalid_request"}), 400

    ctx = engine.devices.get(device_id)
    prev_state = ctx.state.value if ctx else "unknown"

    success = engine.verify_challenge_response(device_id, nonce, ts, sig)

    new_state = engine.devices[device_id].state.value if device_id in engine.devices else "unknown"

    log_auth_event(
        device_id, new_state, prev_state,
        0, 0,
        "challenge_success" if success else "challenge_failure",
        nonce
    )

    if success:
        print(f"[Server] Challenge PASSED for {device_id} -> authenticated")
        return jsonify({"status": "authenticated"}), 200
    else:
        print(f"[Server] Challenge FAILED for {device_id} -> {new_state}")
        response = {"status": new_state}
        ctx = engine.devices.get(device_id)
        if ctx and ctx.state == AuthState.CHALLENGED and ctx.pending_nonce:
            response["challenge"] = {"nonce": ctx.pending_nonce}
        return jsonify(response), 403


@app.route("/api/status/<device_id>", methods=["GET"])
def device_status(device_id):
    """Query the current authentication state of a device."""
    ctx = engine.devices.get(device_id)
    if not ctx:
        return jsonify({"error": "unknown_device"}), 404

    return jsonify({
        "device_id": device_id,
        "state": ctx.state.value,
        "score_window": [round(s, 4) for s in ctx.score_window],
        "suspect_count": ctx.suspect_count,
        "challenge_failures": ctx.challenge_failures,
        "baseline_rssi": round(ctx.baseline_rssi, 1) if ctx.baseline_rssi else None,
        "baseline_latency": round(ctx.baseline_latency, 1) if ctx.baseline_latency else None,
    }), 200


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    if any(
        key == DEVELOPMENT_DEVICE_KEY or len(key.encode("utf-8")) < 32
        for key in DEVICE_KEYS.values()
    ):
        raise RuntimeError(
            "Refusing to start with a public or short HMAC key. Set "
            "IOT_AUTH_ESP32_LAB_01_KEY to a unique secret of at least 32 bytes."
        )
    ensure_log_dir()

    print("=" * 60)
    print("  Continuous Authentication - Verification Server")
    print("=" * 60)
    print(f"  Host          : {SERVER_HOST}:{SERVER_PORT}")
    print(f"  TLS Cert      : {TLS_CERT}")
    print(f"  Window Size   : {WINDOW_SIZE}")
    print(f"  Theta_s       : {SUSPICION_THRESHOLD}")
    print(f"  Theta_c       : {CHALLENGE_THRESHOLD}")
    print(f"  Log Directory : {LOG_DIR}")
    print("=" * 60)

    # Configure TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(TLS_CERT, TLS_KEY)

    # The development server performs the TLS handshake while accepting a
    # connection. Without a timeout, a client that resets mid-handshake (for
    # example, a device rebooting) blocks every later connection.
    socket.setdefaulttimeout(15)

    app.run(
        host=SERVER_HOST,
        port=SERVER_PORT,
        ssl_context=context,
        debug=False,
    )


if __name__ == "__main__":
    main()
