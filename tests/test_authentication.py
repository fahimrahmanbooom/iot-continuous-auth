"""Regression tests for telemetry integrity and authentication transitions."""

import csv
import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server"
sys.path.insert(0, str(SERVER))

from auth_engine import AuthEngine, AuthState  # noqa: E402
from config import DEVICE_KEYS, FEATURE_WEIGHTS  # noqa: E402
import verification_server  # noqa: E402


INTEGER_FIELDS = {
    "seq", "ts_ms", "uptime_ms", "wifi_connected", "internet_state",
    "rssi_dbm", "channel", "heap_free", "min_free_heap", "latency_ms",
    "reset_reason", "free_heap", "loop_jitter_ms", "uptime_s", "wifi_rssi",
}


def load_trace():
    rows = []
    seen = set()
    with (ROOT / "datasets" / "baseline.csv").open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            seq = int(row["seq"])
            if seq in seen:
                continue
            seen.add(seq)
            item = dict(row)
            for field in INTEGER_FIELDS:
                item[field] = int(item[field])
            rows.append(item)
    return rows


def valid_challenge_response(engine, result):
    device_id = result["device_id"]
    nonce = result["challenge"]["nonce"]
    ts = 123456
    message = f"{device_id}|{nonce}|{ts}"
    signature = hmac.new(
        DEVICE_KEYS[device_id].encode(), message.encode(), hashlib.sha256
    ).hexdigest()
    return engine.verify_challenge_response(device_id, nonce, ts, signature)


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.trace = load_trace()

    def test_feature_weights_sum_to_one(self):
        self.assertAlmostEqual(sum(FEATURE_WEIGHTS.values()), 1.0)

    def test_recorded_baseline_does_not_trigger_challenge(self):
        engine = AuthEngine()
        for sample in self.trace:
            result = engine.evaluate_telemetry(sample)
            self.assertNotEqual(result["state"], AuthState.CHALLENGED.value)
            self.assertNotEqual(result["state"], AuthState.REJECTED.value)

    def test_access_point_change_triggers_and_recovers(self):
        engine = AuthEngine()
        for sample in self.trace[:10]:
            engine.evaluate_telemetry(sample)

        challenged = None
        for source in self.trace[10:22]:
            sample = dict(source)
            sample["wifi_bssid_hash"] = "fault-ap-hash"
            sample["channel"] = 11
            sample["rssi_dbm"] = -90
            challenged = engine.evaluate_telemetry(sample)
            if challenged["state"] == AuthState.CHALLENGED.value:
                break

        self.assertIsNotNone(challenged)
        self.assertEqual(challenged["state"], AuthState.CHALLENGED.value)
        self.assertTrue(valid_challenge_response(engine, challenged))
        self.assertEqual(
            engine.devices["esp32-lab-01"].state,
            AuthState.AUTHENTICATED,
        )

    def test_reboot_discontinuity_triggers_immediate_challenge(self):
        engine = AuthEngine()
        for sample in self.trace[:10]:
            engine.evaluate_telemetry(sample)

        reboot = dict(self.trace[10])
        reboot["seq"] = 0
        reboot["uptime_ms"] = 1000
        reboot["uptime_s"] = 1
        result = engine.evaluate_telemetry(reboot)
        self.assertEqual(result["status"], "critical_reboot")
        self.assertEqual(result["state"], AuthState.CHALLENGED.value)

    def test_invalid_hmac_is_rejected_before_processing(self):
        payload = dict(self.trace[0])
        client = verification_server.app.test_client()
        verification_server.engine = AuthEngine()
        with patch.object(verification_server, "log_telemetry") as log_telemetry:
            response = client.post(
                "/api/telemetry",
                json={"payload": payload, "hmac": "0" * 64},
            )
        self.assertEqual(response.status_code, 401)
        log_telemetry.assert_not_called()
        self.assertFalse(verification_server.engine.devices)

    def test_valid_hmac_with_missing_scoring_field_is_rejected(self):
        payload = dict(self.trace[0])
        del payload["uptime_ms"]
        serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        signature = hmac.new(
            DEVICE_KEYS[payload["device_id"]].encode(),
            serialized.encode(),
            hashlib.sha256,
        ).hexdigest()
        client = verification_server.app.test_client()
        verification_server.engine = AuthEngine()
        with patch.object(verification_server, "log_telemetry") as log_telemetry:
            response = client.post(
                "/api/telemetry",
                json={"payload": payload, "hmac": signature},
            )
        self.assertEqual(response.status_code, 400)
        log_telemetry.assert_not_called()
        self.assertFalse(verification_server.engine.devices)

    def test_three_invalid_challenge_responses_reject_device(self):
        engine = AuthEngine()
        engine.evaluate_telemetry(self.trace[0])
        ctx = engine.devices["esp32-lab-01"]
        for attempt in range(3):
            challenge = engine._issue_challenge(ctx)
            accepted = engine.verify_challenge_response(
                ctx.device_id,
                challenge["nonce"],
                123456,
                "0" * 64,
            )
            self.assertFalse(accepted)
            if attempt < 2:
                self.assertEqual(ctx.state, AuthState.CHALLENGED)
        self.assertEqual(ctx.state, AuthState.REJECTED)

    def test_invalid_response_cannot_be_bypassed_by_healthy_telemetry(self):
        engine = AuthEngine()
        engine.evaluate_telemetry(self.trace[0])
        ctx = engine.devices["esp32-lab-01"]
        challenge = engine._issue_challenge(ctx)
        accepted = engine.verify_challenge_response(
            ctx.device_id,
            challenge["nonce"],
            123456,
            "0" * 64,
        )
        self.assertFalse(accepted)
        result = engine.evaluate_telemetry(self.trace[1])
        self.assertEqual(result["state"], AuthState.CHALLENGED.value)
        self.assertEqual(result["status"], "challenge_pending")

    def test_timeout_reissues_challenge_without_telemetry_bypass(self):
        engine = AuthEngine()
        engine.evaluate_telemetry(self.trace[0])
        ctx = engine.devices["esp32-lab-01"]
        first = engine._issue_challenge(ctx)
        ctx.challenge_deadline = 0.0
        result = engine.evaluate_telemetry(self.trace[1])
        self.assertEqual(result["state"], AuthState.CHALLENGED.value)
        self.assertEqual(result["status"], "challenge_timeout_rechallenged")
        self.assertNotEqual(result["challenge"]["nonce"], first["nonce"])
        self.assertEqual(ctx.challenge_failures, 1)

    def test_valid_hmac_is_accepted(self):
        payload = dict(self.trace[0])
        serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        signature = hmac.new(
            DEVICE_KEYS[payload["device_id"]].encode(),
            serialized.encode(),
            hashlib.sha256,
        ).hexdigest()
        client = verification_server.app.test_client()
        verification_server.engine = AuthEngine()
        with patch.object(verification_server, "log_telemetry"), \
                patch.object(verification_server, "log_auth_event"), \
                patch.object(verification_server, "log_decision"):
            response = client.post(
                "/api/telemetry",
                json={"payload": payload, "hmac": signature},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["state"], "authenticated")

    def _roam_until_challenged(self, engine, first, last):
        challenged = None
        for source in self.trace[first:last]:
            sample = dict(source)
            sample["wifi_bssid_hash"] = "second-ap-hash"
            sample["channel"] = 11
            sample["rssi_dbm"] -= 6
            challenged = engine.evaluate_telemetry(sample)
            if challenged["state"] == AuthState.CHALLENGED.value:
                return challenged, source
        return challenged, None

    def test_verified_roaming_is_reenrolled_without_repeat_challenges(self):
        engine = AuthEngine()
        for sample in self.trace[:10]:
            engine.evaluate_telemetry(sample)
        challenged, _ = self._roam_until_challenged(engine, 10, 22)
        self.assertEqual(challenged["state"], AuthState.CHALLENGED.value)
        self.assertTrue(valid_challenge_response(engine, challenged))

        index = self.trace.index(
            next(s for s in self.trace if s["seq"] == engine.devices[
                "esp32-lab-01"].prev_seq)) + 1
        for source in self.trace[index:index + 15]:
            sample = dict(source)
            sample["wifi_bssid_hash"] = "second-ap-hash"
            sample["channel"] = 11
            sample["rssi_dbm"] -= 6
            result = engine.evaluate_telemetry(sample)
            self.assertNotIn("challenge", result)
        self.assertEqual(
            engine.devices["esp32-lab-01"].baseline_bssid, "second-ap-hash")

    def test_return_to_previous_context_keeps_previous_baseline(self):
        engine = AuthEngine()
        for sample in self.trace[:10]:
            engine.evaluate_telemetry(sample)
        original_bssid = engine.devices["esp32-lab-01"].baseline_bssid
        challenged, source = self._roam_until_challenged(engine, 10, 22)
        self.assertTrue(valid_challenge_response(engine, challenged))
        following = self.trace[self.trace.index(source) + 1]
        result = engine.evaluate_telemetry(dict(following))
        self.assertEqual(result["state"], AuthState.AUTHENTICATED.value)
        self.assertEqual(
            engine.devices["esp32-lab-01"].baseline_bssid, original_bssid)

    def test_unverified_context_is_not_reenrolled(self):
        engine = AuthEngine()
        for sample in self.trace[:10]:
            engine.evaluate_telemetry(sample)
        original_bssid = engine.devices["esp32-lab-01"].baseline_bssid
        challenged, _ = self._roam_until_challenged(engine, 10, 22)
        ctx = engine.devices["esp32-lab-01"]
        self.assertFalse(engine.verify_challenge_response(
            ctx.device_id, challenged["challenge"]["nonce"], 123456, "0" * 64))
        self.assertIsNone(ctx.candidate_context)
        self.assertEqual(ctx.baseline_bssid, original_bssid)

    def test_replay_of_older_message_is_classified_as_replay(self):
        engine = AuthEngine()
        for sample in self.trace[:12]:
            engine.evaluate_telemetry(sample)
        result = engine.evaluate_telemetry(dict(self.trace[3]))
        self.assertEqual(result["status"], "critical_replay")
        self.assertEqual(result["state"], AuthState.CHALLENGED.value)

    def test_replay_from_before_a_reboot_is_classified_as_replay(self):
        engine = AuthEngine()
        for sample in self.trace[:12]:
            engine.evaluate_telemetry(sample)
        reboot = dict(self.trace[12])
        reboot["seq"], reboot["uptime_ms"] = 0, 1000
        challenged = engine.evaluate_telemetry(reboot)
        self.assertTrue(valid_challenge_response(engine, challenged))
        after = dict(self.trace[13])
        after["seq"], after["uptime_ms"] = 1, 7000
        engine.evaluate_telemetry(after)
        # The pre-reboot message has a higher sequence number than the
        # current one but has already been accepted.
        result = engine.evaluate_telemetry(dict(self.trace[5]))
        self.assertEqual(result["status"], "critical_replay")
        # The legitimate device answers, and its next genuine message must not
        # be mistaken for a reboot because of the replayed counters.
        self.assertTrue(valid_challenge_response(engine, result))
        following = dict(self.trace[14])
        following["seq"], following["uptime_ms"] = 2, 13000
        result = engine.evaluate_telemetry(following)
        self.assertNotIn("challenge", result)
        self.assertEqual(result["status"], "ok")

    def test_counters_resynchronize_after_unobserved_reboot(self):
        # The device reboots while the network is down and reconnects with a
        # restarted sequence number that is still below the last one seen,
        # but with an uptime that already exceeds it.
        engine = AuthEngine()
        for k, source in enumerate(self.trace[:12]):
            sample = dict(source)
            sample["seq"], sample["uptime_ms"] = 30 + k, 100000 + 6000 * k
            engine.evaluate_telemetry(sample)
        first = dict(self.trace[12])
        first["seq"], first["uptime_ms"] = 28, 425000
        challenged = engine.evaluate_telemetry(first)
        self.assertEqual(challenged["state"], AuthState.CHALLENGED.value)
        self.assertTrue(valid_challenge_response(engine, challenged))
        for k, source in enumerate(self.trace[13:20]):
            sample = dict(source)
            sample["seq"], sample["uptime_ms"] = 29 + k, 431000 + 6000 * k
            result = engine.evaluate_telemetry(sample)
            self.assertNotIn("challenge", result)


if __name__ == "__main__":
    unittest.main()
