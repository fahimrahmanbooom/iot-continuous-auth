"""Benign-disruption, weight-perturbation, and baseline-comparison analyses.

All analyses replay the same recorded ESP32-C6 trace and trial positions as
run_trace_injection.py. Three outputs are produced:

1. benign_events.csv: persistent, non-adversarial changes (roaming to a second
   access point of the same network, DHCP resolver renewal, and a planned
   reboot) with post-verification re-enrollment enabled and disabled.
2. weight_perturbation.csv: decision outcomes when every feature weight is
   independently scaled and the vector is renormalized.
3. baseline_comparison.csv: the proposed rule against simpler decision rules
   on the same nominal, fault, and benign trials.

No result values are hard-coded.
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

OUTPUT = ROOT / "datasets" / "generated"
TRIALS = trace_experiment.TRIALS
WARMUP = trace_experiment.WARMUP_SAMPLES
POST_EVENT_SAMPLES = 15
PERTURBATION_DRAWS = 500
PERTURBATION_SCALES = (0.25, 0.50)
SEED = 20261009

BENIGN_EVENTS = (
    "roaming_same_network",
    "dhcp_secondary_resolver",
    "dhcp_both_resolvers",
    "planned_reboot",
)


def benign(event, source, offset, reboot_origin):
    """Apply a persistent benign change to post-event sample `offset`."""
    sample = dict(source)
    if event == "roaming_same_network":
        sample["wifi_bssid_hash"] = "second-ap-same-ssid"
        sample["channel"] = 11 if source["channel"] != 11 else 1
        sample["rssi_dbm"] = source["rssi_dbm"] - 6
    elif event == "dhcp_secondary_resolver":
        sample["dns2"] = "8.8.8.8"
    elif event == "dhcp_both_resolvers":
        sample["dns1"] = "192.168.1.1"
        sample["dns2"] = "8.8.8.8"
    elif event == "planned_reboot":
        # Sequence restarts at zero and uptime restarts from boot; both then
        # advance at the recorded cadence.
        elapsed = source["uptime_ms"] - reboot_origin["uptime_ms"]
        sample["seq"] = offset
        sample["uptime_ms"] = 1000 + elapsed
        sample["uptime_s"] = sample["uptime_ms"] // 1000
    return sample


def run_benign_trial(trace, event, trial, engine_factory=AuthEngine):
    engine = engine_factory()
    start = trial - 1
    for offset in range(WARMUP):
        engine.evaluate_telemetry(dict(trace[start + offset]))

    origin = trace[start + WARMUP]
    challenges = 0
    challenged_samples = 0
    first = None
    states = []
    for offset in range(POST_EVENT_SAMPLES):
        source = trace[start + WARMUP + offset]
        result = engine.evaluate_telemetry(
            benign(event, source, offset, origin))
        states.append(result["state"])
        if result["status"] != "challenge_pending" and result.get("challenge"):
            challenges += 1
            if first is None:
                first = offset + 1
            trace_experiment.answer_challenge(engine, result)
        if result["state"] == AuthState.CHALLENGED.value:
            challenged_samples += 1
    return {
        "challenges": challenges,
        "first_challenge": first,
        "challenged_samples": challenged_samples,
        "final_state": states[-1],
    }


def benign_summary(trace, engine_factory=AuthEngine):
    rows = []
    for event in BENIGN_EVENTS:
        results = [run_benign_trial(trace, event, t, engine_factory)
                   for t in range(1, TRIALS + 1)]
        firsts = [r["first_challenge"] for r in results
                  if r["first_challenge"] is not None]
        rows.append({
            "event": event,
            "trials": TRIALS,
            "trials_with_challenge": sum(r["challenges"] > 0 for r in results),
            "total_challenges": sum(r["challenges"] for r in results),
            "max_challenges_per_trial": max(r["challenges"] for r in results),
            "median_first_challenge": (statistics.median(firsts)
                                       if firsts else ""),
            "final_authenticated": sum(
                r["final_state"] == AuthState.AUTHENTICATED.value
                for r in results),
        })
    return rows


def primary_outcomes(trace, engine_factory=AuthEngine):
    """Challenge counts and median delays for the 100 primary trials."""
    out = {}
    original = trace_experiment.AuthEngine
    trace_experiment.AuthEngine = engine_factory
    try:
        for scenario in trace_experiment.SCENARIOS:
            results = [trace_experiment.run_trial(trace, scenario, t)[1]
                       for t in range(1, TRIALS + 1)]
            delays = [r["detection_samples"] for r in results
                      if r["detection_samples"] is not None]
            out[scenario] = {
                "challenges": sum(r["detected"] for r in results),
                "median_delay": statistics.median(delays) if delays else "",
            }
    finally:
        trace_experiment.AuthEngine = original
    return out


# ─── Comparison rules ───────────────────────────────────────────────────────

class OneTimeAuthentication(AuthEngine):
    """Admission only: telemetry is accepted but never re-evaluated."""

    def evaluate_telemetry(self, telemetry):
        ctx = self.get_or_create_device(telemetry.get("device_id", "unknown"))
        return self._result(ctx, 1.0, 1.0, {}, "ok")


class PerFeatureLimit(AuthEngine):
    """Challenge whenever any single feature reaches zero or continuity breaks.

    Uses the same baselines and tolerances as the proposed engine but no
    weighting, window, or suspect state.
    """

    def evaluate_telemetry(self, telemetry):
        ctx = self.get_or_create_device(telemetry.get("device_id", "unknown"))
        if ctx.state == AuthState.CHALLENGED or ctx.state == AuthState.REJECTED:
            return super().evaluate_telemetry(telemetry)
        features = self._compute_features(ctx, telemetry)
        result = super().evaluate_telemetry(telemetry)
        if (not result.get("challenge") and features and
                min(features.values()) == 0.0):
            result["challenge"] = self._issue_challenge(ctx, telemetry)
            result["state"] = ctx.state.value
            result["status"] = "per_feature_limit"
        return result


class NoCriticalOverride(AuthEngine):
    """Proposed score without the reboot/replay smoothing bypass."""

    def _continuity_event(self, ctx, telemetry):
        return None


def with_settings(factory, **settings):
    """Return an engine factory that applies module settings while running."""
    def build():
        return factory()
    build.settings = settings
    return build


def run_with_settings(settings, func, *args):
    saved = {k: getattr(auth_engine, k) for k in settings}
    try:
        for key, value in settings.items():
            setattr(auth_engine, key, value)
        return func(*args)
    finally:
        for key, value in saved.items():
            setattr(auth_engine, key, value)


def comparison(trace):
    variants = [
        ("Proposed (weighted score, 5-sample window, override, re-enrollment)",
         AuthEngine, {}),
        ("Proposed without post-verification re-enrollment",
         AuthEngine, {"REENROLL_AFTER_VERIFICATION": False}),
        ("One-time authentication (no runtime reassessment)",
         OneTimeAuthentication, {}),
        ("Per-feature limits (any feature at zero challenges)",
         PerFeatureLimit, {}),
        ("Equal weights (1/9 each)",
         AuthEngine, {"FEATURE_WEIGHTS": {
             k: 1 / 9 for k in auth_engine.FEATURE_WEIGHTS}}),
        ("No smoothing (window of one sample)",
         AuthEngine, {"WINDOW_SIZE": 1}),
        ("No reboot/replay override",
         NoCriticalOverride, {}),
    ]
    rows = []
    for name, factory, settings in variants:
        primary = run_with_settings(settings, primary_outcomes, trace, factory)
        benign_rows = run_with_settings(settings, benign_summary, trace,
                                        factory)
        row = {"rule": name}
        row["nominal_false_challenges"] = primary["nominal"]["challenges"]
        for scenario in trace_experiment.SCENARIOS[1:]:
            row[f"{scenario}_detected"] = primary[scenario]["challenges"]
            row[f"{scenario}_median_delay"] = primary[scenario]["median_delay"]
        for b in benign_rows:
            row[f"{b['event']}_challenges"] = b["total_challenges"]
        row["benign_challenges_total"] = sum(
            b["total_challenges"] for b in benign_rows)
        rows.append(row)
    return rows


def perturbation(trace):
    rng = random.Random(SEED)
    base = dict(auth_engine.FEATURE_WEIGHTS)
    rows = []
    for scale in PERTURBATION_SCALES:
        preserved = 0
        nominal_fc = []
        detection = []
        sustained_delays = []
        for _ in range(PERTURBATION_DRAWS):
            raw = {k: v * rng.uniform(1 - scale, 1 + scale)
                   for k, v in base.items()}
            total = sum(raw.values())
            weights = {k: v / total for k, v in raw.items()}
            primary = run_with_settings({"FEATURE_WEIGHTS": weights},
                                        primary_outcomes, trace)
            fc = primary["nominal"]["challenges"]
            det = sum(primary[s]["challenges"]
                      for s in trace_experiment.SCENARIOS[1:])
            nominal_fc.append(fc)
            detection.append(det)
            for s in ("wan_dns_fault", "ap_reassociation"):
                if primary[s]["median_delay"] != "":
                    sustained_delays.append(primary[s]["median_delay"])
            preserved += int(fc == 0 and det == 4 * TRIALS)
        rows.append({
            "scale": f"+/-{int(scale * 100)}%",
            "draws": PERTURBATION_DRAWS,
            "outcome_preserved": preserved,
            "outcome_preserved_pct": round(100 * preserved / PERTURBATION_DRAWS, 1),
            "max_nominal_false_challenges": max(nominal_fc),
            "min_fault_detections_of_80": min(detection),
            "sustained_delay_min": min(sustained_delays),
            "sustained_delay_max": max(sustained_delays),
        })
    return rows


def write(name, rows):
    path = OUTPUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"{name}:")
    for row in rows:
        print("  ", row)


def main():
    trace = trace_experiment.load_trace()
    enabled = benign_summary(trace)
    disabled = run_with_settings({"REENROLL_AFTER_VERIFICATION": False},
                                 benign_summary, trace)
    rows = []
    for on, off in zip(enabled, disabled):
        rows.append({"reenrollment": "enabled", **on})
        rows.append({"reenrollment": "disabled", **off})
    write("benign_events.csv", rows)
    write("weight_perturbation.csv", perturbation(trace))
    write("baseline_comparison.csv", comparison(trace))


if __name__ == "__main__":
    main()
