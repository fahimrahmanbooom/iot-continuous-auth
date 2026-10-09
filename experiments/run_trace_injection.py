"""Reproduce the trace-driven fault-injection evaluation used in the paper.

The script replays recorded ESP32 telemetry and changes only the fields named
by each scenario. It writes sample-level decisions and an aggregate summary.
No result values are hard-coded.
"""

import csv
import hashlib
import hmac
import statistics
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server"
sys.path.insert(0, str(SERVER))

from auth_engine import AuthEngine, AuthState  # noqa: E402
from config import DEVICE_KEYS  # noqa: E402


INTEGER_FIELDS = {
    "seq", "ts_ms", "uptime_ms", "wifi_connected", "internet_state",
    "rssi_dbm", "channel", "heap_free", "min_free_heap", "latency_ms",
    "reset_reason", "free_heap", "loop_jitter_ms", "uptime_s", "wifi_rssi",
}
SCENARIOS = (
    "nominal",
    "wan_dns_fault",
    "ap_reassociation",
    "device_reboot",
    "sequence_replay",
)
TRIALS = 20
WARMUP_SAMPLES = 8
FAULT_SAMPLES = 10
RECOVERY_SAMPLES = 5


def load_trace():
    rows = []
    seen = set()
    path = ROOT / "datasets" / "baseline.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            seq = int(row["seq"])
            if seq in seen:
                continue
            seen.add(seq)
            item = dict(row)
            for field in INTEGER_FIELDS:
                item[field] = int(item[field])
            rows.append(item)
    if len(rows) < WARMUP_SAMPLES + FAULT_SAMPLES + RECOVERY_SAMPLES + TRIALS:
        raise RuntimeError("The recorded baseline trace is too short for the trial design")
    return rows


def inject(scenario, source, previous):
    sample = dict(source)
    if scenario == "wan_dns_fault":
        sample["internet_state"] = 0
        sample["dns1"] = "0.0.0.0"
        sample["dns2"] = "0.0.0.0"
        sample["latency_ms"] = previous["latency_ms"] + 1200
    elif scenario == "ap_reassociation":
        sample["wifi_bssid_hash"] = "fault-ap-hash"
        sample["channel"] = 11 if previous["channel"] != 11 else 1
        sample["rssi_dbm"] = -90
    elif scenario == "device_reboot":
        sample["seq"] = 0
        sample["uptime_ms"] = 1000
        sample["uptime_s"] = 1
    elif scenario == "sequence_replay":
        sample["seq"] = previous["seq"]
        sample["uptime_ms"] = previous["uptime_ms"]
        sample["uptime_s"] = previous["uptime_s"]
    return sample


def answer_challenge(engine, result):
    device_id = result["device_id"]
    nonce = result["challenge"]["nonce"]
    ts = 123456
    message = f"{device_id}|{nonce}|{ts}"
    signature = hmac.new(
        DEVICE_KEYS[device_id].encode(), message.encode(), hashlib.sha256
    ).hexdigest()
    return engine.verify_challenge_response(device_id, nonce, ts, signature)


def write_row(rows, scenario, trial, phase, sample_index, source_index,
              result, injected, response_ok=""):
    rows.append({
        "scenario": scenario,
        "trial": trial,
        "phase": phase,
        "sample_index": sample_index,
        "source_index": source_index,
        "injected": int(injected),
        "score": result["score"],
        "avg_score": result["avg_score"],
        "state": result["state"],
        "status": result["status"],
        "challenge_issued": int(bool(result.get("challenge"))),
        "challenge_response_ok": response_ok,
    })


def run_trial(trace, scenario, trial):
    engine = AuthEngine()
    rows = []
    start = trial - 1
    cursor = 0

    for offset in range(WARMUP_SAMPLES):
        source_index = start + offset
        sample = dict(trace[source_index])
        result = engine.evaluate_telemetry(sample)
        write_row(rows, scenario, trial, "warmup", cursor, source_index,
                  result, False)
        cursor += 1

    detected_at = None
    response_ok = False
    if scenario == "nominal":
        phase_samples = FAULT_SAMPLES
    else:
        phase_samples = FAULT_SAMPLES

    for offset in range(phase_samples):
        source_index = start + WARMUP_SAMPLES + offset
        source = trace[source_index]
        previous = trace[source_index - 1]
        sample = inject(scenario, source, previous)
        result = engine.evaluate_telemetry(sample)
        if result["state"] == AuthState.CHALLENGED.value:
            detected_at = offset + 1
            if scenario != "nominal":
                response_ok = answer_challenge(engine, result)
        write_row(rows, scenario, trial,
                  "nominal" if scenario == "nominal" else "fault",
                  cursor, source_index, result, scenario != "nominal",
                  int(response_ok) if detected_at else "")
        cursor += 1
        if detected_at is not None:
            break

    recovery_authenticated = True
    if scenario != "nominal" and detected_at is not None:
        for offset in range(RECOVERY_SAMPLES):
            source_index = start + WARMUP_SAMPLES + FAULT_SAMPLES + offset
            sample = dict(trace[source_index])
            result = engine.evaluate_telemetry(sample)
            write_row(rows, scenario, trial, "recovery", cursor, source_index,
                      result, False)
            cursor += 1
        recovery_authenticated = (
            result["state"] == AuthState.AUTHENTICATED.value
        )

    return rows, {
        "detected": detected_at is not None,
        "detection_samples": detected_at,
        "challenge_response_ok": response_ok,
        "recovery_authenticated": recovery_authenticated,
    }


def main():
    trace = load_trace()
    sample_rows = []
    summaries = []

    for scenario in SCENARIOS:
        trial_results = []
        for trial in range(1, TRIALS + 1):
            rows, result = run_trial(trace, scenario, trial)
            sample_rows.extend(rows)
            trial_results.append(result)

        detection_samples = [
            item["detection_samples"] for item in trial_results
            if item["detection_samples"] is not None
        ]
        summaries.append({
            "scenario": scenario,
            "trials": TRIALS,
            "challenges": sum(item["detected"] for item in trial_results),
            "challenge_rate_pct": round(
                100 * sum(item["detected"] for item in trial_results) / TRIALS,
                1,
            ),
            "median_detection_samples": (
                statistics.median(detection_samples)
                if detection_samples else ""
            ),
            "valid_responses_accepted": sum(
                item["challenge_response_ok"] for item in trial_results
            ),
            "recovered_authenticated": sum(
                item["recovery_authenticated"] for item in trial_results
            ),
        })

    output_dir = ROOT / "datasets" / "generated"
    output_dir.mkdir(parents=True, exist_ok=True)
    samples_path = output_dir / "trace_injection_results.csv"
    summary_path = output_dir / "trace_injection_summary.csv"

    with samples_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=sample_rows[0].keys())
        writer.writeheader()
        writer.writerows(sample_rows)

    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=summaries[0].keys())
        writer.writeheader()
        writer.writerows(summaries)

    print(f"Recorded telemetry samples: {len(trace)}")
    print(f"Sample-level results: {samples_path}")
    print(f"Summary: {summary_path}")
    for row in summaries:
        print(row)


if __name__ == "__main__":
    main()
