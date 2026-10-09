"""Simulated scenarios that could not be staged with the available hardware.

All scenarios are SIMULATIONS: they replay recorded telemetry through the
unchanged authentication engine and modify only the fields named below. Two
recorded baselines are used:

  trace     the 46-sample ESP32-C6 trace of 30 December 2025 (home Wi-Fi)
  hotspot   the nominal period of the physical session of 9 October 2026
            (smartphone hotspot), from the sample after its unplanned
            BSSID change onward

Scenarios
  two_ap_*   roaming between two access points of one network (simulated)
  wan_*      upstream (WAN) outage with and without DHCP/DNS loss (simulated)
  rssi_*     added RSSI noise and board offsets (simulated sensitivity)

Outputs are written to datasets/generated/simulation_*.csv.
"""

import csv
import random
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "experiments"))

import auth_engine  # noqa: E402
from auth_engine import AuthEngine, AuthState  # noqa: E402
import run_trace_injection as trace_experiment  # noqa: E402

OUT = ROOT / "datasets" / "generated"
PHYSICAL = ROOT / "datasets" / "physical" / "2026-10-09"
WARMUP = 8
RECOVERY = 10
MAX_POSITIONS = 20
SEED = 20261009
INT_FIELDS = trace_experiment.INTEGER_FIELDS


def load_hotspot():
    """Nominal hotspot messages after the unplanned BSSID change."""
    events = list(csv.DictReader((PHYSICAL / "physical_events.csv").open()))
    first_event = min(float(e["server_ts"]) for e in events if e["event"] == "reboot")
    rows = []
    for row in csv.DictReader((PHYSICAL / "telemetry.csv").open()):
        if float(row["server_ts"]) >= first_event:
            break
        item = {k: v for k, v in row.items() if k not in ("log_ts_utc", "server_ts")}
        for field in INT_FIELDS:
            if item.get(field, "") != "":
                item[field] = int(item[field])
        rows.append(item)
    change = next(k for k in range(1, len(rows))
                  if rows[k]["wifi_bssid_hash"] != rows[k - 1]["wifi_bssid_hash"])
    return rows[change + 1:]


def run(trace, start, event_len, mutate, recovery=RECOVERY):
    """Warm-up, mutated event segment, unmodified recovery. Challenges are
    answered with the registered key, as a legitimate device would."""
    engine = AuthEngine()
    challenges_event = challenges_recovery = 0
    first = None
    k = 0
    for offset in range(WARMUP):
        engine.evaluate_telemetry(dict(trace[start + offset]))
    for offset in range(event_len + recovery):
        source = dict(trace[start + WARMUP + offset])
        in_event = offset < event_len
        sample = mutate(source, offset) if in_event else source
        result = engine.evaluate_telemetry(sample)
        if result.get("challenge") and result["status"] != "challenge_pending":
            if in_event:
                challenges_event += 1
                if first is None:
                    first = offset + 1
            else:
                challenges_recovery += 1
            trace_experiment.answer_challenge(engine, result)
        k += 1
    return {
        "challenges_event": challenges_event,
        "challenges_recovery": challenges_recovery,
        "first": first,
        "final_state": result["state"],
    }


def positions(trace, event_len, recovery=RECOVERY):
    last = len(trace) - (WARMUP + event_len + recovery)
    return list(range(0, min(MAX_POSITIONS, last + 1)))


# ─── Two-access-point roaming (simulated) ────────────────────────────────

def other_channel(ch):
    return next(c for c in (1, 6, 11) if c != ch)


def two_ap(delta_db, new_subnet=False, ping_pong=0):
    """Roam to AP2 of the same SSID. RSSI changes by delta_db, the first
    message after reassociation carries a 1000 ms reconnection latency, and
    with new_subnet the DHCP lease (resolvers) changes too. With ping_pong=n
    the device alternates between AP1 and AP2 every n samples."""
    def mutate(sample, offset):
        on_ap2 = True if not ping_pong else (offset // ping_pong) % 2 == 0
        if not on_ap2:
            return sample
        sample["wifi_bssid_hash"] = "sim-ap2"
        sample["channel"] = other_channel(sample["channel"])
        sample["rssi_dbm"] = max(-127, min(0, sample["rssi_dbm"] + delta_db))
        if offset == 0 or (ping_pong and offset % ping_pong == 0):
            sample["latency_ms"] = sample["latency_ms"] + 1000
        if new_subnet:
            sample["dns1"] = "10.20.0.1"
            sample["dns2"] = "10.20.0.2"
        return sample
    return mutate


def wan_outage(dhcp_loss):
    def mutate(sample, offset):
        sample["internet_state"] = 0
        if dhcp_loss:
            sample["dns1"] = "0.0.0.0"
            sample["dns2"] = "0.0.0.0"
        return sample
    return mutate


SCENARIOS = [
    ("two_ap_stronger_same_subnet", two_ap(+6), 15),
    ("two_ap_equal_same_subnet", two_ap(0), 15),
    ("two_ap_weaker_same_subnet", two_ap(-6), 15),
    ("two_ap_stronger_new_subnet", two_ap(+6, new_subnet=True), 15),
    ("two_ap_ping_pong_every_3", two_ap(0, ping_pong=3), 15),
    ("wan_outage_short_lease_kept", wan_outage(False), 5),
    ("wan_outage_long_lease_kept", wan_outage(False), 15),
    ("wan_outage_short_dhcp_loss", wan_outage(True), 5),
    ("wan_outage_long_dhcp_loss", wan_outage(True), 15),
]


def scenario_table(baselines):
    rows = []
    for name, mutate, length in SCENARIOS:
        for reenroll in (True, False):
            for base_name, trace in baselines.items():
                saved = auth_engine.REENROLL_AFTER_VERIFICATION
                auth_engine.REENROLL_AFTER_VERIFICATION = reenroll
                try:
                    results = [run(trace, p, length, mutate) for p in positions(trace, length)]
                finally:
                    auth_engine.REENROLL_AFTER_VERIFICATION = saved
                firsts = [r["first"] for r in results if r["first"] is not None]
                rows.append({
                    "scenario": name,
                    "reenrollment": "enabled" if reenroll else "disabled",
                    "baseline": base_name,
                    "event_samples": length,
                    "trials": len(results),
                    "trials_challenged": sum(r["challenges_event"] > 0 for r in results),
                    "challenges_during_event": sum(r["challenges_event"] for r in results),
                    "max_per_trial": max(r["challenges_event"] for r in results),
                    "median_first_challenge": statistics.median(firsts) if firsts else "",
                    "challenges_after_recovery": sum(r["challenges_recovery"] for r in results),
                    "ended_authenticated": sum(r["final_state"] == AuthState.AUTHENTICATED.value
                                               for r in results),
                })
    return rows


# ─── RSSI noise and board offset (simulated sensitivity) ──────────────────

NOISE_SD = (0, 2, 4, 6, 8, 10)
OFFSETS = (-10, 0, 10)
DRAWS = 25
NOMINAL_LEN = 15


def rssi_table(baselines):
    rows = []
    rng = random.Random(SEED)
    for base_name, trace in baselines.items():
        pos = positions(trace, NOMINAL_LEN, recovery=0)
        for offset_db in OFFSETS:
            for sd in NOISE_SD:
                challenged = total = 0
                ap_detected = ap_total = 0
                for _ in range(DRAWS):
                    noise = [rng.gauss(0, sd) for _ in trace]
                    noisy = []
                    for k, row in enumerate(trace):
                        item = dict(row)
                        item["rssi_dbm"] = max(-127, min(0, round(row["rssi_dbm"] + offset_db + noise[k])))
                        noisy.append(item)
                    for p in pos:
                        r = run(noisy, p, NOMINAL_LEN, lambda s, o: s, recovery=0)
                        total += 1
                        challenged += int(r["challenges_event"] > 0)
                        a = run(noisy, p, NOMINAL_LEN, two_ap(-30), recovery=0)
                        ap_total += 1
                        ap_detected += int(a["challenges_event"] > 0)
                rows.append({
                    "baseline": base_name,
                    "rssi_offset_db": offset_db,
                    "rssi_noise_sd_db": sd,
                    "nominal_trials": total,
                    "nominal_trials_challenged": challenged,
                    "nominal_challenge_rate_pct": round(100 * challenged / total, 1),
                    "ap_change_trials": ap_total,
                    "ap_change_detected_pct": round(100 * ap_detected / ap_total, 1),
                })
    return rows


def write(name, rows):
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"{name}:")
    for row in rows:
        print("  ", row)


def main():
    baselines = {"trace": trace_experiment.load_trace(), "hotspot": load_hotspot()}
    for name, trace in baselines.items():
        print(f"baseline {name}: {len(trace)} samples")
    write("simulation_two_ap_and_wan.csv", scenario_table(baselines))
    write("simulation_rssi_variation.csv", rssi_table(baselines))


if __name__ == "__main__":
    main()
