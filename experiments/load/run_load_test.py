"""Server load test with EMULATED devices (software clients, not hardware).

Each emulated device sends HMAC-signed telemetry, built from the recorded
ESP32-C6 trace with its own device identifier and sequence numbers, to the
verification server over a new TLS connection per message, as the firmware
does. The server runs as a separate process; its CPU time and resident memory
are sampled with ps.

Results: datasets/generated/load_test.csv
"""

import csv
import hashlib
import hmac
import json
import shutil
import ssl
import statistics
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments"))
sys.path.insert(0, str(ROOT / "experiments" / "load"))

import run_trace_injection as trace_experiment  # noqa: E402
from emulated_server import emulated_key  # noqa: E402

PORT = 5444
CA = ROOT / "certs" / "ca.crt"
LOGS = ROOT / "datasets" / "generated" / "load_test_logs"
DEVICE_COUNTS = (10, 50, 100, 200)
INTERVAL_S = 5.0          # firmware default telemetry interval
DURATION_S = 60.0


def context():
    ctx = ssl.create_default_context(cafile=str(CA))
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    ctx.check_hostname = False   # certificate names the LAN address, test uses loopback
    return ctx


def proc_stats(pid):
    out = subprocess.run(["ps", "-o", "rss=,time=", "-p", str(pid)],
                         capture_output=True, text=True).stdout.split()
    rss_kb = int(out[0])
    parts = [float(x) for x in out[1].replace("-", ":").split(":")]
    cpu_s = sum(v * 60 ** i for i, v in enumerate(reversed(parts)))
    return rss_kb, cpu_s


def device_loop(device_id, trace, stop, results, ctx):
    key = emulated_key(device_id).encode()
    seq = 0
    offset = int(device_id[-4:]) % len(trace)
    next_t = time.time() + (int(device_id[-4:]) % 50) * INTERVAL_S / 50
    while not stop.is_set():
        delay = next_t - time.time()
        if delay > 0:
            time.sleep(delay)
        if stop.is_set():
            break
        payload = dict(trace[(offset + seq) % len(trace)])
        payload["device_id"] = device_id
        payload["seq"] = seq
        payload["uptime_ms"] = 10000 + int(seq * INTERVAL_S * 1000)
        canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        body = json.dumps({"payload": payload,
                           "hmac": hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()})
        start = time.perf_counter()
        try:
            req = urllib.request.Request(f"https://127.0.0.1:{PORT}/api/telemetry",
                                         data=body.encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                ok = resp.status == 200
                resp.read()
        except Exception:
            ok = False
        results.append((time.perf_counter() - start, ok))
        seq += 1
        next_t += INTERVAL_S


def run_level(count, trace):
    if LOGS.exists():
        shutil.rmtree(LOGS)
    server = subprocess.Popen([sys.executable, str(ROOT / "experiments" / "load" / "emulated_server.py"),
                               str(count), str(PORT), str(LOGS)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ctx = context()
    for _ in range(100):
        try:
            urllib.request.urlopen(f"https://127.0.0.1:{PORT}/api/status/none", context=ctx, timeout=2)
        except urllib.error.HTTPError:
            break
        except Exception:
            time.sleep(0.2)
    rss0, cpu0 = proc_stats(server.pid)
    stop = threading.Event()
    results = []
    threads = [threading.Thread(target=device_loop,
                                args=(f"emu-{k:04d}", trace, stop, results, ctx), daemon=True)
               for k in range(count)]
    t0 = time.time()
    for t in threads:
        t.start()
    peak_rss = rss0
    while time.time() - t0 < DURATION_S:
        time.sleep(2)
        peak_rss = max(peak_rss, proc_stats(server.pid)[0])
    stop.set()
    for t in threads:
        t.join(timeout=20)
    elapsed = time.time() - t0
    rss1, cpu1 = proc_stats(server.pid)
    server.terminate()
    server.wait(timeout=10)
    lat = sorted(r[0] * 1000 for r in results if r[1])
    errors = sum(1 for r in results if not r[1])
    decisions = sum(1 for _ in (LOGS / "decisions.csv").open()) - 1 if (LOGS / "decisions.csv").exists() else 0
    return {
        "emulated_devices": count,
        "offered_rate_msg_s": round(count / INTERVAL_S, 1),
        "duration_s": round(elapsed, 1),
        "messages_ok": len(lat),
        "errors": errors,
        "throughput_msg_s": round(len(lat) / elapsed, 1),
        "decisions_logged": decisions,
        "latency_p50_ms": round(statistics.median(lat), 1) if lat else "",
        "latency_p95_ms": round(lat[int(0.95 * (len(lat) - 1))], 1) if lat else "",
        "latency_max_ms": round(lat[-1], 1) if lat else "",
        "server_cpu_pct": round(100 * (cpu1 - cpu0) / elapsed, 1),
        "server_rss_start_mb": round(rss0 / 1024, 1),
        "server_rss_peak_mb": round(peak_rss / 1024, 1),
    }


def main():
    trace = trace_experiment.load_trace()
    rows = []
    for count in DEVICE_COUNTS:
        row = run_level(count, trace)
        print(row, flush=True)
        rows.append(row)
    if LOGS.exists():
        shutil.rmtree(LOGS)
    out = ROOT / "datasets" / "generated" / "load_test.csv"
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"load test: {out}")


if __name__ == "__main__":
    main()
