"""Reproduce the window and threshold sensitivity analysis in the paper."""

import csv
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

import auth_engine  # noqa: E402
import run_trace_injection as trace_experiment  # noqa: E402


WINDOW_SIZES = (3, 5, 7)
SUSPICION_THRESHOLDS = (0.70, 0.75, 0.80)


def main():
    trace = trace_experiment.load_trace()
    original_window = auth_engine.WINDOW_SIZE
    original_threshold = auth_engine.SUSPICION_THRESHOLD
    rows = []
    try:
        for window_size in WINDOW_SIZES:
            for threshold in SUSPICION_THRESHOLDS:
                auth_engine.WINDOW_SIZE = window_size
                auth_engine.SUSPICION_THRESHOLD = threshold
                for scenario in trace_experiment.SCENARIOS:
                    results = [
                        trace_experiment.run_trial(trace, scenario, trial)[1]
                        for trial in range(1, trace_experiment.TRIALS + 1)
                    ]
                    delays = [
                        result["detection_samples"] for result in results
                        if result["detection_samples"] is not None
                    ]
                    challenges = sum(result["detected"] for result in results)
                    rows.append({
                        "window_size": window_size,
                        "suspicion_threshold": threshold,
                        "scenario": scenario,
                        "trials": trace_experiment.TRIALS,
                        "challenges": challenges,
                        "challenge_rate_pct": round(
                            100 * challenges / trace_experiment.TRIALS, 1
                        ),
                        "median_detection_samples": (
                            statistics.median(delays) if delays else ""
                        ),
                    })
    finally:
        auth_engine.WINDOW_SIZE = original_window
        auth_engine.SUSPICION_THRESHOLD = original_threshold

    output = ROOT / "datasets" / "generated" / "parameter_sensitivity.csv"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"Sensitivity results: {output}")
    print(f"Configurations: {len(WINDOW_SIZES) * len(SUSPICION_THRESHOLDS)}")
    print(f"Scenario runs: {sum(row['trials'] for row in rows)}")


if __name__ == "__main__":
    main()
