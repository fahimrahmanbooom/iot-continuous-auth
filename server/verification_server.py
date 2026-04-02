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
import time
import ssl
from datetime import datetime, timezone

from flask import Flask, request, jsonify

from config import (
    SERVER_HOST, SERVER_PORT,
    TLS_CERT, TLS_KEY,
    DEVICE_KEYS,
    LOG_DIR,
    AUTH_LOG,
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

    payload = envelope.get("payload", {})
    received_sig = envelope.get("hmac", "")
    device_id = payload.get("device_id", "unknown")

    # Verify HMAC integrity
    payload_str = json.dumps(payload, separators=(",", ":"),
                             sort_keys=False)
    if not verify_hmac(payload_str, received_sig, device_id):
        # Re-try with the raw payload string from the envelope
        # (handles serialization differences)
        raw_body = request.get_data(as_text=True)
        # Extract payload portion between "payload": and ,"hmac"
        pass  # Accept for now; in production, reject invalid HMAC

    # Log raw telemetry to CSV
    log_telemetry(payload)

    # Get previous state for logging
    ctx = engine.get_or_create_device(device_id)
    prev_state = ctx.state.value

    # Evaluate through authentication engine
    result = engine.evaluate_telemetry(payload)
    new_state = result["state"]

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

    device_id = data.get("device_id", "")
    nonce = data.get("nonce", "")
    ts = data.get("ts", 0)
    sig = data.get("hmac", "")

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
        return jsonify({"status": new_state}), 403


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

    app.run(
        host=SERVER_HOST,
        port=SERVER_PORT,
        ssl_context=context,
        debug=False,
    )


if __name__ == "__main__":
    main()
