"""Summarize the physical ESP32-C6 session and draw its timeline figure.

Inputs (written by the live server and physical_events.py) are copied into
datasets/physical/<date>/ so the analysis can be rerun from the archive.
"""

import csv
import json
import shutil
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
LIVE = ROOT / "datasets"
ARCHIVE = LIVE / "physical" / (sys.argv[1] if len(sys.argv) > 1 else "2026-10-09")
FIGURE = ROOT / "figures" / "physical_validation.png"


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def archive():
    ARCHIVE.mkdir(parents=True, exist_ok=True)
    for name in ("decisions.csv", "auth_events.csv", "physical_events.csv",
                 "device_serial.log"):
        if (LIVE / name).exists():
            shutil.copy2(LIVE / name, ARCHIVE / name)
    # Published copies omit neighbouring network names (from the firmware's
    # connection diagnostics) and the raw access-point MAC address.
    log = ARCHIVE / "device_serial.log"
    if log.exists():
        lines = log.read_text(encoding="utf-8").splitlines()
        keep = [l for l in lines if not any(k in l for k in ("] ch=", "Visible networks", "scan result"))]
        log.write_text("\n".join(keep) + "\n", encoding="utf-8")
    for path in LIVE.glob("telemetry_esp32-lab-01_2026*.csv"):
        with path.open(newline="", encoding="utf-8") as src:
            table = list(csv.DictReader(src))
        fields = [f for f in table[0] if f != "bssid"]
        with (ARCHIVE / "telemetry.csv").open("w", newline="", encoding="utf-8") as dst:
            writer = csv.DictWriter(dst, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(table)


def auth_ts(row):
    stamp = datetime.strptime(row["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
    return stamp.replace(tzinfo=timezone.utc).timestamp()


def main():
    archive()
    rows = read_csv(ARCHIVE / "decisions.csv")
    for row in rows:
        row["t"] = float(row["server_ts"])
    all_events = read_csv(ARCHIVE / "physical_events.csv") if (
        ARCHIVE / "physical_events.csv").exists() else []
    # The event session ends at the logged collection end; the later nominal
    # run is analyzed separately (nominal_run2_decisions.csv).
    end = next((float(e["server_ts"]) for e in all_events
                if e["event"] == "collection_end"), None)
    if end is not None:
        rows = [r for r in rows if r["t"] <= end]
        all_events = [e for e in all_events if float(e["server_ts"]) <= end]
    tests = ("reboot", "replay", "replay_forged")
    events = [e for e in all_events if e["event"] in tests]
    markers = [float(e["server_ts"]) for e in all_events]
    auth = read_csv(ARCHIVE / "auth_events.csv")
    t0 = rows[0]["t"]
    first_event = float(events[0]["server_ts"]) if events else rows[-1]["t"] + 1

    device = [r for r in rows if r["remote_addr"] != "172.20.10.2"]
    nominal = [r for r in device if r["t"] < first_event]
    rssi = [int(r["rssi_dbm"]) for r in nominal]
    lat = [int(r["latency_ms"]) for r in nominal]
    heap = [int(r["heap_free"]) for r in nominal]
    gaps = [b["t"] - a["t"] for a, b in zip(nominal, nominal[1:])]
    summary = {
        "nominal": {
            "samples": len(nominal),
            "duration_min": round((nominal[-1]["t"] - nominal[0]["t"]) / 60, 1),
            "median_interval_s": round(statistics.median(gaps), 2),
            "max_gap_s": round(max(gaps), 1),
            "challenges": sum(int(r["challenge_issued"]) for r in nominal),
            "suspect_samples": sum(r["state"] == "suspect" for r in nominal),
            "rssi_mean": round(statistics.mean(rssi), 1),
            "rssi_median": statistics.median(rssi),
            "rssi_min": min(rssi), "rssi_max": max(rssi),
            "latency_median": statistics.median(lat),
            "latency_max": max(lat),
            "latency_first": lat[0],
            "heap_min": min(heap), "heap_max": max(heap),
            "score_min": min(float(r["score"]) for r in nominal),
            "avg_score_min": min(float(r["avg_score"]) for r in nominal),
            "bssid_hashes": sorted({r["wifi_bssid_hash"] for r in nominal}),
            "channels": sorted({r["channel"] for r in nominal}),
            "dns": sorted({(r["dns1"], r["dns2"]) for r in nominal}),
        },
        "events": [],
        "server_restarts": [e["utc"] for e in all_events if e["event"] == "server_restart"],
    }

    for k, event in enumerate(events):
        # Replays are logged after the server has answered them, so the
        # window opens shortly before the logged time.
        logged = float(event["server_ts"])
        start = logged - 2.0 if event["event"].startswith("replay") else logged
        end = min([m - (2.0 if e["event"].startswith("replay") else 0.0)
                   for m, e in zip(markers, all_events) if m > logged] +
                  [rows[-1]["t"] + 1])
        detail = json.loads(event["detail"])
        window = [r for r in rows if start <= r["t"] < end]
        device_window = [r for r in window if r["remote_addr"] != "172.20.10.2"]
        challenge_rows = [r for r in window if r["challenge_issued"] == "1"]
        first = challenge_rows[0] if challenge_rows else None
        successes = [a for a in auth if a["trigger"] == "challenge_success"
                     and start - 1 <= auth_ts(a) < end]
        failures = [a for a in auth if a["trigger"] == "challenge_failure"
                    and start - 1 <= auth_ts(a) < end]
        recovered = successes[0] if successes else None
        # Decisions issued while a challenge was pending (device telemetry
        # arriving before its response was verified).
        new_challenges = [r for r in challenge_rows if r["status"] != "challenge_pending"]
        summary["events"].append({
            "event": event["event"],
            "utc": event["utc"],
            "minute": round((start - t0) / 60, 2),
            "detail": detail,
            "challenge_status": first["status"] if first else None,
            "challenge_source": first["remote_addr"] if first else None,
            "challenge_seq": first["seq"] if first else None,
            "seconds_to_challenge": round(first["t"] - start, 2) if first else None,
            "challenges_issued": len(new_challenges),
            "forged_or_failed_responses": len(failures),
            "recovered": recovered is not None,
            "seconds_to_recovery": round(auth_ts(recovered) - start, 1) if recovered else None,
            "device_messages_before_recovery": sum(
                1 for r in device_window
                if recovered is None or r["t"] <= auth_ts(recovered) + 1),
            "final_state": window[-1]["state"] if window else None,
            "reset_to_challenge_s": (round(first["t"] - logged, 1)
                                     if first and event["event"] == "reboot" else None),
            "challenge_to_valid_response_s": (
                max(0.0, round(auth_ts(recovered) - int(first["t"]), 1))
                if first and recovered else None),
        })

    restarts = [float(e["server_ts"]) for e in all_events if e["event"] == "server_restart"]
    finals = [float(e["server_ts"]) for e in all_events
              if e["event"] == "server_restart" and "final code" in e["detail"]]
    final_start = finals[0] if finals else (restarts[-1] if restarts else t0)
    for ev in summary["events"]:
        # An event after which the server processed no device message before
        # the next marker was not observed (server unavailable).
        ev["observed"] = ev["challenges_issued"] > 0 or ev["recovered"]
    for ev in summary["events"]:
        ev["phase"] = "final" if ev["minute"] * 60 + t0 > final_start else "corrective"
    final = [e for e in summary["events"] if e["phase"] == "final" and e["observed"]]
    summary["unobserved_events"] = [
        {"utc": e["utc"], "event": e["event"]} for e in summary["events"] if not e["observed"]]
    agg = {}
    for kind in tests:
        group = [e for e in final if e["event"] == kind]
        if not group:
            continue
        rec = [e["seconds_to_recovery"] for e in group if e["seconds_to_recovery"] is not None]
        agg[kind] = {
            "events": len(group),
            "challenged": sum(e["challenges_issued"] >= 1 for e in group),
            "statuses": sorted({e["challenge_status"] for e in group}),
            "recovered": sum(e["recovered"] for e in group),
            "median_seconds_to_recovery": statistics.median(rec) if rec else None,
            "max_seconds_to_recovery": max(rec) if rec else None,
            "challenges_issued_total": sum(e["challenges_issued"] for e in group),
            "failed_responses": sum(e["forged_or_failed_responses"] for e in group),
            "median_reset_to_challenge_s": (statistics.median(
                [e["reset_to_challenge_s"] for e in group if e["reset_to_challenge_s"] is not None])
                if kind == "reboot" else None),
            "max_reset_to_challenge_s": (max(
                [e["reset_to_challenge_s"] for e in group if e["reset_to_challenge_s"] is not None])
                if kind == "reboot" else None),
            "max_challenge_to_valid_response_s": max(
                e["challenge_to_valid_response_s"] for e in group),
            "median_challenge_to_valid_response_s": statistics.median(
                e["challenge_to_valid_response_s"] for e in group),
        }
    corrective_rows = [r for r in rows if first_event <= r["t"] < final_start]
    final_rows = [r for r in rows if r["t"] >= final_start]
    summary["final_phase"] = {
        "start_utc": datetime.fromtimestamp(final_start, timezone.utc).isoformat(),
        "device_messages": sum(r["remote_addr"] != "172.20.10.2" for r in final_rows),
        "duration_min": round((final_rows[-1]["t"] - final_start) / 60, 1) if final_rows else 0,
        "challenges_total": sum(r["challenge_issued"] == "1" and r["status"] != "challenge_pending"
                                for r in final_rows),
        "by_event": agg,
    }
    summary["corrective_phase"] = {
        "device_messages": sum(r["remote_addr"] != "172.20.10.2" for r in corrective_rows),
        "challenges_total": sum(r["challenge_issued"] == "1" and r["status"] != "challenge_pending"
                                for r in corrective_rows),
        "status_counts": {k: sum(r["status"] == k and r["challenge_issued"] == "1" for r in corrective_rows)
                          for k in ("critical_reboot", "critical_replay", "ok")},
    }
    summary["phase_bounds_min"] = {
        "nominal_end": round((first_event - t0) / 60, 2),
        "final_start": round((final_start - t0) / 60, 2),
        "end": round((rows[-1]["t"] - t0) / 60, 2),
    }

    (ARCHIVE / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))

    # ─── Figure ──────────────────────────────────────────────────────────
    # Break the lines where no message arrived for more than 30 s.
    def broken(values):
        xs, ys = [], []
        for k, (r, v) in enumerate(zip(device, values)):
            if k and r["t"] - device[k - 1]["t"] > 30:
                xs.append(float("nan"))
                ys.append(float("nan"))
            xs.append((r["t"] - t0) / 60)
            ys.append(v)
        return xs, ys
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 5.2), sharex=True,
                                   gridspec_kw={"height_ratios": [2.2, 1]})
    ax1.plot(*broken([float(r["avg_score"]) for r in device]), color="#1f77b4",
             lw=1.4, label="Smoothed score W(t)")
    ax1.plot(*broken([float(r["score"]) for r in device]), color="#1f77b4",
             lw=0.6, alpha=0.35, label="Instantaneous score S(t)")
    b = summary["phase_bounds_min"]
    for ax in (ax1, ax2):
        ax.axvspan(b["nominal_end"], b["final_start"], color="#bbbbbb", alpha=0.25, lw=0)
    for x, text in ((b["nominal_end"] / 2, "Nominal operation"),
                    ((b["nominal_end"] + b["final_start"]) / 2, "Corrective rounds"),
                    ((b["final_start"] + b["end"]) / 2, "Final event phase")):
        ax1.text(x, 1.025, text, ha="center", va="bottom", fontsize=8,
                 transform=ax1.get_xaxis_transform() if False else ax1.transData)
    ax1.axhline(0.75, color="#ff7f0e", ls="--", lw=1)
    ax1.axhline(0.45, color="#d62728", ls=":", lw=1)
    colors = {"reboot": "#7b61ff", "replay": "#e4572e", "replay_forged": "#a01a58"}
    seen = set()
    for event in summary["events"]:
        c = colors.get(event["event"], "grey")
        lab = {"reboot": "Hardware reboot", "replay": "Replayed message",
               "replay_forged": "Replay with forged response"}[event["event"]]
        if not event["observed"]:
            lab = "Reboot not observed (no connectivity)"
            for ax in (ax1, ax2):
                ax.axvline(event["minute"], color="#999999", lw=0.9, ls="--",
                           label=lab if (ax is ax1 and lab not in seen) else None)
            seen.add(lab)
            continue
        for ax in (ax1, ax2):
            ax.axvline(event["minute"], color=c, lw=1.1, alpha=0.8,
                       label=lab if (ax is ax1 and lab not in seen) else None)
        seen.add(lab)
    ch = [r for r in rows if r["challenge_issued"] == "1" and r["status"] != "challenge_pending"]
    ax1.scatter([(r["t"] - t0) / 60 for r in ch], [float(r["avg_score"]) for r in ch],
                color="#7b2cbf", zorder=5, s=22, label="Challenge issued")
    ax1.set_ylabel("Score")
    ax1.set_ylim(0.3, 1.08)
    ax1.legend(loc="lower left", fontsize=7, ncol=3, frameon=False)
    ax2.plot(*broken([int(r["rssi_dbm"]) for r in device]), color="#2ca02c", lw=1)
    ax2.set_ylabel("RSSI (dBm)")
    ax2.set_xlabel("Elapsed time (min)")
    fig.text(0.01, 0.005, "Dashed line: suspicion threshold 0.75; dotted line: "
             "challenge threshold 0.45", fontsize=7, color="#555")
    fig.tight_layout()
    FIGURE.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURE, dpi=300)
    print(f"figure: {FIGURE}")


if __name__ == "__main__":
    main()
