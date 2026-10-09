"""Physical reboot and replay events against the running verification server.

reboot:  pulses the ESP32-C6 reset line through the USB serial adapter (RTS),
         which restarts the board exactly like its reset button.
replay:  re-sends a telemetry envelope that the board signed earlier (taken
         from the server's capture file) to the live server, as an on-path
         attacker would. With --forge, the attacker also answers the returned
         challenge with a forged HMAC.

Every event is appended to datasets/physical_events.csv with a UTC timestamp.
"""

import argparse
import csv
import json
import secrets
import ssl
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import serial

ROOT = Path(__file__).resolve().parents[2]
EVENTS = ROOT / "datasets" / "physical_events.csv"
CAPTURE = ROOT / "datasets" / "captured_envelopes.jsonl"
CA = ROOT / "certs" / "ca.crt"


def log_event(kind, detail):
    new = not EVENTS.exists()
    with EVENTS.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if new:
            writer.writerow(["utc", "server_ts", "event", "detail"])
        now = time.time()
        writer.writerow([
            datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="milliseconds"),
            round(now, 3), kind, json.dumps(detail, sort_keys=True),
        ])


def post(url, body):
    context = ssl.create_default_context(cafile=str(CA))
    # The self-signed lab CA has no keyUsage extension; keep chain and host
    # verification but drop the strict RFC 5280 profile check (Python >= 3.13).
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, context=context, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"{}")


def reboot(port):
    dev = serial.Serial()
    dev.port = port
    dev.dtr = False
    dev.rts = False
    dev.open()
    dev.rts = True          # hold EN low (chip in reset)
    time.sleep(0.2)
    dev.rts = False         # release EN; DTR stays low so the app boots
    dev.close()
    log_event("reboot", {"method": "usb_rts_reset", "port": port})


def replay(server, age_s, forge):
    lines = CAPTURE.read_text(encoding="utf-8").splitlines()
    envelopes = [json.loads(line) for line in lines if line.strip()]
    # Messages are captured in arrival order at roughly six-second intervals;
    # pick the one received about `age_s` seconds before the newest.
    back = max(2, int(round(age_s / 6.0)))
    target = envelopes[-back] if len(envelopes) >= back else envelopes[0]
    status, body = post(f"{server}/api/telemetry", target)
    detail = {"replayed_seq": target["payload"]["seq"],
              "replayed_uptime_ms": target["payload"]["uptime_ms"],
              "http_status": status, "response": body}
    if forge and body.get("challenge"):
        nonce = body["challenge"]["nonce"]
        f_status, f_body = post(f"{server}/api/challenge_response", {
            "device_id": target["payload"]["device_id"], "nonce": nonce,
            "ts": int(time.time() * 1000) % 2**31, "hmac": secrets.token_hex(32)})
        detail.update({"forged_response_status": f_status,
                       "forged_response_body": f_body})
    log_event("replay_forged" if forge else "replay", detail)
    print(json.dumps(detail, indent=1))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("event", choices=["reboot", "replay"])
    parser.add_argument("--port", default="/dev/cu.usbmodem14201")
    parser.add_argument("--server", default="https://172.20.10.2:5443")
    parser.add_argument("--age", type=float, default=120.0,
                        help="replay a message signed at least this many seconds earlier")
    parser.add_argument("--forge", action="store_true")
    args = parser.parse_args()
    if args.event == "reboot":
        reboot(args.port)
    else:
        replay(args.server, args.age, args.forge)


if __name__ == "__main__":
    main()
