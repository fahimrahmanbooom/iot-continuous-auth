"""
auth_engine.py
Continuous Authentication Engine - core decision logic.

Implements the multi-state authentication model described in the paper:
  Authenticated -> Suspect -> Challenged -> Rejected

Authentication score S(t) is computed per Equation (1):
    S(t) = sum( w_i * f_i(t) )  for i = 1..N

Smoothed over a sliding window per Equation (3):
    S_bar(t) = (1/W) * sum( S(t-k) )  for k = 0..W-1

State transitions:
    - S_bar >= theta_s            -> Authenticated
    - theta_c <= S_bar < theta_s -> Suspect
    - S_bar < theta_c             -> Challenge issued
    - Sequence replay or reboot   -> Challenge issued
    - Repeated challenge failure  -> Rejected

Author : Fahim Rahman
Date   : December 2025
License: MIT
"""

import time
import hmac
import hashlib
import secrets
from collections import deque
from enum import Enum
from typing import Dict, Optional

from config import (
    WINDOW_SIZE,
    SUSPICION_THRESHOLD,
    CHALLENGE_THRESHOLD,
    SUSPECT_PATIENCE,
    CHALLENGE_TIMEOUT_SEC,
    MAX_CHALLENGE_FAILURES,
    FEATURE_WEIGHTS,
    RSSI_TOLERANCE,
    LATENCY_TOLERANCE,
    HEAP_TOLERANCE,
    MAX_SEQ_GAP,
    DEVICE_KEYS,
    REENROLL_AFTER_VERIFICATION,
)

# Number of recent (sequence, uptime) pairs retained per device.
SEEN_MESSAGE_CACHE = 1024


class AuthState(Enum):
    """Authentication states as defined in the paper (Section 3.5)."""
    AUTHENTICATED = "authenticated"
    SUSPECT       = "suspect"
    CHALLENGED    = "challenged"
    REJECTED      = "rejected"


class DeviceContext:
    """Tracks per-device authentication context and baseline."""

    def __init__(self, device_id: str):
        self.device_id = device_id
        self.state = AuthState.AUTHENTICATED
        self.score_window: deque = deque(maxlen=WINDOW_SIZE)
        self.suspect_count = 0
        self.challenge_failures = 0

        # Baseline values (learned from first accepted telemetry)
        self.baseline_rssi: Optional[float] = None
        self.baseline_latency: Optional[float] = None
        self.baseline_heap: Optional[int] = None
        self.baseline_bssid: Optional[str] = None
        self.baseline_channel: Optional[int] = None
        self.baseline_dns1: Optional[str] = None
        self.baseline_dns2: Optional[str] = None

        # Previous telemetry for continuity checks, and recently accepted
        # (sequence, uptime) pairs used to separate replay from reboot.
        self.prev_seq: Optional[int] = None
        self.prev_uptime: Optional[int] = None
        self.seen_messages: deque = deque(maxlen=SEEN_MESSAGE_CACHE)

        # Pending challenge
        self.pending_nonce: Optional[str] = None
        self.challenge_deadline: float = 0.0

        # Network context reported when the pending challenge was issued,
        # and a verified candidate context awaiting one confirming sample.
        self.challenge_context: Optional[tuple] = None
        self.candidate_context: Optional[tuple] = None
        # (sequence, uptime) of the latest genuine message that received the
        # pending nonce; continuity is resynchronized to it after a valid
        # response.
        self.challenge_counters: Optional[tuple] = None

        # Most recent scores are retained while a challenge is pending.
        self.last_score = 0.0
        self.last_avg_score = 0.0
        self.last_features: Dict[str, float] = {}

        # Timestamps
        self.last_telemetry_ts: float = 0.0
        self.state_changed_ts: float = time.time()


class AuthEngine:
    """
    Core continuous authentication engine.

    Evaluates incoming telemetry against device baselines using
    weighted feature scoring and sliding-window averaging.
    """

    def __init__(self):
        self.devices: Dict[str, DeviceContext] = {}

    def get_or_create_device(self, device_id: str) -> DeviceContext:
        if device_id not in self.devices:
            self.devices[device_id] = DeviceContext(device_id)
        return self.devices[device_id]

    def evaluate_telemetry(self, telemetry: dict) -> dict:
        """
        Main entry point.  Accepts a telemetry dict, evaluates it,
        and returns the authentication decision.

        Returns dict with:
            state, score, avg_score, features, challenge (optional)
        """
        device_id = telemetry.get("device_id", "unknown")
        ctx = self.get_or_create_device(device_id)

        # If device is rejected, do not process further
        if ctx.state == AuthState.REJECTED:
            return self._result(ctx, 0.0, 0.0, {}, "rejected")

        # Check for expired challenges
        if ctx.state == AuthState.CHALLENGED:
            # This message receives the pending nonce; if it is a genuine
            # (not previously accepted) message, its counters are the ones to
            # resynchronize to once the device proves key possession.
            counters = (telemetry.get("seq"), telemetry.get("uptime_ms"))
            if counters not in ctx.seen_messages:
                ctx.challenge_counters = counters
                ctx.seen_messages.append(counters)
            if time.time() > ctx.challenge_deadline:
                ctx.challenge_failures += 1
                if ctx.challenge_failures >= MAX_CHALLENGE_FAILURES:
                    ctx.state = AuthState.REJECTED
                    ctx.pending_nonce = None
                    ctx.challenge_deadline = 0.0
                    return self._result(ctx, 0.0, 0.0, {},
                                        "challenge_timeout_rejected")
                else:
                    challenge = self._issue_challenge(ctx)
                    return self._result(
                        ctx, 0.0, 0.0, {},
                        "challenge_timeout_rechallenged",
                        challenge=challenge,
                    )
            else:
                return self._result(
                    ctx,
                    ctx.last_score,
                    ctx.last_avg_score,
                    ctx.last_features,
                    "challenge_pending",
                    challenge={
                        "nonce": ctx.pending_nonce,
                        "deadline": ctx.challenge_deadline,
                    },
                )

        continuity_event = self._continuity_event(ctx, telemetry)
        counters = (telemetry.get("seq"), telemetry.get("uptime_ms"))
        duplicate = counters in ctx.seen_messages
        ctx.seen_messages.append(counters)

        # A network context that was reported when a challenge was issued,
        # and in which the device then proved key possession, becomes the
        # baseline once the next sample confirms the same context.
        if ctx.candidate_context is not None:
            if self._network_context(telemetry) == ctx.candidate_context:
                self._adopt_context(ctx, telemetry)
            ctx.candidate_context = None

        # Compute individual feature scores
        features = self._compute_features(ctx, telemetry)

        # Weighted sum -> instantaneous score S(t)   [Equation 1]
        score = sum(
            FEATURE_WEIGHTS.get(name, 0.0) * value
            for name, value in features.items()
        )

        # Sliding window average S_bar(t)            [Equation 3]
        ctx.score_window.append(score)
        avg_score = sum(ctx.score_window) / len(ctx.score_window)
        ctx.last_score = score
        ctx.last_avg_score = avg_score
        ctx.last_features = features

        # Store previous values for continuity checks. A replayed message does
        # not describe the device's current counters, so it must not replace
        # them; otherwise the next genuine message would look like a reboot.
        if continuity_event != "replay":
            ctx.prev_seq = telemetry.get("seq")
            ctx.prev_uptime = telemetry.get("uptime_ms")
        ctx.last_telemetry_ts = time.time()

        # Sequence replay and reboot are short-lived discontinuities. They
        # bypass smoothing so that a single critical event is not averaged
        # away by otherwise healthy telemetry.
        challenge = None
        status = "ok"
        if continuity_event in {"replay", "reboot"}:
            challenge = self._issue_challenge(ctx, telemetry)
            status = f"critical_{continuity_event}"
            if duplicate:
                # Counters of an already-accepted message are never adopted.
                ctx.challenge_counters = None
        elif avg_score >= SUSPICION_THRESHOLD:
            # Normal - authenticated
            if ctx.state != AuthState.AUTHENTICATED:
                ctx.state = AuthState.AUTHENTICATED
                ctx.suspect_count = 0
                ctx.challenge_failures = 0
                ctx.state_changed_ts = time.time()
        elif avg_score >= CHALLENGE_THRESHOLD:
            # Suspect zone
            if ctx.state == AuthState.AUTHENTICATED:
                ctx.state = AuthState.SUSPECT
                ctx.suspect_count = 1
                ctx.state_changed_ts = time.time()
            elif ctx.state == AuthState.SUSPECT:
                ctx.suspect_count += 1
                if ctx.suspect_count >= SUSPECT_PATIENCE:
                    challenge = self._issue_challenge(ctx, telemetry)
        else:
            # Below challenge threshold - immediate challenge
            if ctx.state != AuthState.CHALLENGED:
                challenge = self._issue_challenge(ctx, telemetry)

        # Update baseline only when device remains authenticated AND
        # the instantaneous score is healthy (prevents anomalous values
        # from corrupting the baseline during transient dips)
        if (ctx.state == AuthState.AUTHENTICATED and
                score >= SUSPICION_THRESHOLD):
            self._update_baseline(ctx, telemetry)

        return self._result(ctx, score, avg_score, features, status,
                            challenge=challenge)

    def verify_challenge_response(self, device_id: str,
                                  nonce: str, ts: int,
                                  received_hmac: str) -> bool:
        """
        Verify a challenge response from the device.
        Returns True if the response is valid and timely.
        """
        ctx = self.devices.get(device_id)
        if not ctx or ctx.state != AuthState.CHALLENGED:
            return False

        if ctx.pending_nonce != nonce:
            return False

        if time.time() > ctx.challenge_deadline:
            ctx.challenge_failures += 1
            if ctx.challenge_failures >= MAX_CHALLENGE_FAILURES:
                ctx.state = AuthState.REJECTED
                ctx.pending_nonce = None
                ctx.challenge_deadline = 0.0
            else:
                self._issue_challenge(ctx)
            return False

        # Compute expected HMAC
        key = DEVICE_KEYS.get(device_id, "")
        message = f"{device_id}|{nonce}|{ts}"
        expected = hmac.new(
            key.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if hmac.compare_digest(expected, received_hmac):
            # Success - restore authenticated state
            ctx.state = AuthState.AUTHENTICATED
            ctx.suspect_count = 0
            ctx.challenge_failures = 0
            ctx.pending_nonce = None
            ctx.challenge_deadline = 0.0
            ctx.state_changed_ts = time.time()
            # The device proved key possession in the context it reported
            # when challenged; offer that context for re-enrollment.
            if (REENROLL_AFTER_VERIFICATION and
                    ctx.challenge_context is not None and
                    ctx.challenge_context != self._baseline_context(ctx)):
                ctx.candidate_context = ctx.challenge_context
            ctx.challenge_context = None
            # Resynchronize continuity to the genuine message that received
            # the nonce (e.g. after a reboot that was not observed because
            # the network was down).
            if ctx.challenge_counters is not None:
                ctx.prev_seq, ctx.prev_uptime = ctx.challenge_counters
                ctx.challenge_counters = None
            # Partial window reset to accelerate trust recovery
            if len(ctx.score_window) > 2:
                recent = list(ctx.score_window)[-2:]
                ctx.score_window.clear()
                for s in recent:
                    ctx.score_window.append(max(s, SUSPICION_THRESHOLD))
            return True
        else:
            ctx.challenge_failures += 1
            if ctx.challenge_failures >= MAX_CHALLENGE_FAILURES:
                ctx.state = AuthState.REJECTED
                ctx.pending_nonce = None
                ctx.challenge_deadline = 0.0
            # Before the failure limit, retain the pending nonce and the
            # Challenged state so that ordinary telemetry cannot restore trust.
            return False

    # ─── Private helpers ─────────────────────────────────────────────────

    def _continuity_event(self, ctx: DeviceContext,
                          telemetry: dict) -> Optional[str]:
        """Classify sequence and uptime discontinuities before state updates."""
        if ctx.prev_seq is None or ctx.prev_uptime is None:
            return None

        seq = telemetry.get("seq", 0)
        uptime = telemetry.get("uptime_ms", 0)
        # An exact repeat of an accepted message is a replay even when its
        # sequence number exceeds the current one (e.g. a message captured
        # before a reboot and replayed after it).
        if (seq, uptime) in ctx.seen_messages:
            return "replay"
        if seq <= ctx.prev_seq:
            if uptime < ctx.prev_uptime:
                return "reboot"
            return "replay"
        return None

    @staticmethod
    def _network_context(telemetry: dict) -> Optional[tuple]:
        """Discrete network context, or None when the network is unusable."""
        if telemetry.get("internet_state") != 2:
            return None
        return (
            telemetry.get("wifi_bssid_hash", ""),
            telemetry.get("channel", 0),
            telemetry.get("dns1", ""),
            telemetry.get("dns2", ""),
        )

    @staticmethod
    def _baseline_context(ctx: DeviceContext) -> tuple:
        return (ctx.baseline_bssid, ctx.baseline_channel,
                ctx.baseline_dns1, ctx.baseline_dns2)

    @staticmethod
    def _adopt_context(ctx: DeviceContext, telemetry: dict) -> None:
        """Re-enroll the network context confirmed after verification."""
        ctx.baseline_bssid = telemetry.get("wifi_bssid_hash", "")
        ctx.baseline_channel = telemetry.get("channel", 0)
        ctx.baseline_dns1 = telemetry.get("dns1", "")
        ctx.baseline_dns2 = telemetry.get("dns2", "")
        ctx.baseline_rssi = telemetry.get("rssi_dbm", ctx.baseline_rssi)
        ctx.baseline_latency = telemetry.get("latency_ms",
                                             ctx.baseline_latency)

    def _compute_features(self, ctx: DeviceContext,
                          telemetry: dict) -> Dict[str, float]:
        """
        Compute normalized feature values f_i(t) in [0, 1].
        1.0 = normal/expected, 0.0 = maximum anomaly.
        """
        features = {}

        # 1) Internet state (binary: 2=reachable -> 1.0, else 0.0)
        inet = telemetry.get("internet_state", 0)
        features["internet_state"] = 1.0 if inet == 2 else 0.0

        # 2) RSSI stability
        rssi = telemetry.get("rssi_dbm", -100)
        if ctx.baseline_rssi is not None:
            delta = abs(rssi - ctx.baseline_rssi)
            features["rssi_stability"] = max(0.0,
                1.0 - (delta / RSSI_TOLERANCE))
        else:
            features["rssi_stability"] = 1.0

        # 3) BSSID consistency (hash match)
        bssid_h = telemetry.get("wifi_bssid_hash", "")
        if ctx.baseline_bssid is not None:
            features["bssid_consistency"] = (
                1.0 if bssid_h == ctx.baseline_bssid else 0.0
            )
        else:
            features["bssid_consistency"] = 1.0

        # 4) Channel consistency
        ch = telemetry.get("channel", 0)
        if ctx.baseline_channel is not None:
            features["channel_consistency"] = (
                1.0 if ch == ctx.baseline_channel else 0.0
            )
        else:
            features["channel_consistency"] = 1.0

        # 5) DNS consistency
        dns1 = telemetry.get("dns1", "")
        dns2 = telemetry.get("dns2", "")
        if ctx.baseline_dns1 is not None:
            dns_match = (dns1 == ctx.baseline_dns1 and
                         dns2 == ctx.baseline_dns2)
            features["dns_consistency"] = 1.0 if dns_match else 0.0
        else:
            features["dns_consistency"] = 1.0

        # 6) Heap stability
        heap = telemetry.get("heap_free", 0)
        if ctx.baseline_heap is not None:
            delta = abs(heap - ctx.baseline_heap)
            features["heap_stability"] = max(0.0,
                1.0 - (delta / HEAP_TOLERANCE))
        else:
            features["heap_stability"] = 1.0

        # 7) Latency stability
        lat = telemetry.get("latency_ms", 0)
        if ctx.baseline_latency is not None:
            delta = abs(lat - ctx.baseline_latency)
            features["latency_stability"] = max(0.0,
                1.0 - (delta / LATENCY_TOLERANCE))
        else:
            features["latency_stability"] = 1.0

        # 8) Sequence continuity
        seq = telemetry.get("seq", 0)
        if ctx.prev_seq is not None:
            gap = seq - ctx.prev_seq
            if gap == 1:
                features["sequence_continuity"] = 1.0
            elif 0 < gap <= MAX_SEQ_GAP:
                features["sequence_continuity"] = 0.5
            else:
                features["sequence_continuity"] = 0.0
        else:
            features["sequence_continuity"] = 1.0

        # 9) Uptime continuity (detect resets)
        uptime = telemetry.get("uptime_ms", 0)
        if ctx.prev_uptime is not None:
            if uptime >= ctx.prev_uptime:
                features["uptime_continuity"] = 1.0
            else:
                # Uptime decreased -> device reset
                features["uptime_continuity"] = 0.0
        else:
            features["uptime_continuity"] = 1.0

        return features

    def _update_baseline(self, ctx: DeviceContext,
                         telemetry: dict) -> None:
        """
        Initialize or adapt baseline values.
        Only updates when device is in Authenticated state.
        """
        if ctx.baseline_rssi is None:
            # First telemetry - initialize baseline
            ctx.baseline_rssi = telemetry.get("rssi_dbm", -50)
            ctx.baseline_latency = telemetry.get("latency_ms", 500)
            ctx.baseline_heap = telemetry.get("heap_free", 300000)
            ctx.baseline_bssid = telemetry.get("wifi_bssid_hash", "")
            ctx.baseline_channel = telemetry.get("channel", 0)
            ctx.baseline_dns1 = telemetry.get("dns1", "")
            ctx.baseline_dns2 = telemetry.get("dns2", "")
        elif ctx.state == AuthState.AUTHENTICATED:
            # Exponential moving average for continuous features
            alpha = 0.1
            rssi = telemetry.get("rssi_dbm", ctx.baseline_rssi)
            ctx.baseline_rssi = (1 - alpha) * ctx.baseline_rssi + alpha * rssi

            lat = telemetry.get("latency_ms", ctx.baseline_latency)
            ctx.baseline_latency = ((1 - alpha) * ctx.baseline_latency +
                                    alpha * lat)

            heap = telemetry.get("heap_free", ctx.baseline_heap)
            ctx.baseline_heap = int(
                (1 - alpha) * ctx.baseline_heap + alpha * heap)

            # Discrete features update directly when authenticated
            ctx.baseline_bssid = telemetry.get("wifi_bssid_hash",
                                               ctx.baseline_bssid)
            ctx.baseline_channel = telemetry.get("channel",
                                                 ctx.baseline_channel)
            ctx.baseline_dns1 = telemetry.get("dns1", ctx.baseline_dns1)
            ctx.baseline_dns2 = telemetry.get("dns2", ctx.baseline_dns2)

    def _issue_challenge(self, ctx: DeviceContext,
                         telemetry: Optional[dict] = None) -> dict:
        """Generate a cryptographic challenge nonce."""
        if telemetry is not None:
            ctx.challenge_context = self._network_context(telemetry)
            ctx.challenge_counters = (telemetry.get("seq"),
                                      telemetry.get("uptime_ms"))
        nonce = secrets.token_hex(16)
        ctx.state = AuthState.CHALLENGED
        ctx.pending_nonce = nonce
        ctx.challenge_deadline = time.time() + CHALLENGE_TIMEOUT_SEC
        ctx.state_changed_ts = time.time()

        return {"nonce": nonce, "deadline": ctx.challenge_deadline}

    def _result(self, ctx: DeviceContext,
                score: float, avg_score: float,
                features: dict, status: str,
                challenge: dict = None) -> dict:
        result = {
            "device_id": ctx.device_id,
            "state": ctx.state.value,
            "score": round(score, 4),
            "avg_score": round(avg_score, 4),
            "features": {k: round(v, 4) for k, v in features.items()},
            "status": status,
            "timestamp": time.time(),
        }
        if challenge:
            result["challenge"] = challenge
        return result
