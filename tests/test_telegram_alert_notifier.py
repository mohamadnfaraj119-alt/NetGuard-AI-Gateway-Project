#!/usr/bin/env python3

import io
import logging
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from scripts import telegram_alert_notifier as notifier


def event(
    classification="PORT_SCAN",
    confidence=0.70,
    risk_score=40.0,
    src_ip="192.168.50.95",
    time_value="2026-07-22 15:13:02",
):
    return {
        "time": time_value,
        "src_ip": src_ip,
        "attack_type": classification,
        "confidence": confidence,
        "risk_score": risk_score,
        "reasons": ["connections_30s=152 >= 120 with elevated risk"],
    }


class TelegramAlertNotifierTests(unittest.TestCase):
    def test_eligibility_policy(self):
        self.assertTrue(notifier.is_alert_eligible(event("PORT_SCAN", 0.65, 12)))
        self.assertTrue(notifier.is_alert_eligible(event("DOS_LIKE_BURST", 0.60, 8)))
        self.assertTrue(
            notifier.is_alert_eligible(
                event("SSH_BRUTE_FORCE_OR_LOGIN_PATTERN", 0.65, 12)
            )
        )
        self.assertTrue(notifier.is_alert_eligible(event("DNS_ANOMALY", 0.65, 30)))
        self.assertFalse(notifier.is_alert_eligible(event("LOW_SIGNAL_REVIEW", 0.90, 99)))
        self.assertFalse(notifier.is_alert_eligible(event("FAILED_CONNECTION_PATTERN", 0.60, 12)))

    def test_fingerprint_deduplication(self):
        state = notifier.empty_state()
        item = event()
        now = datetime(2026, 7, 22, 15, 13, 30)

        self.assertEqual(notifier.should_send_event(item, state, now), (True, "eligible"))
        notifier.mark_sent(item, state, now)
        self.assertEqual(notifier.should_send_event(item, state, now), (False, "already sent"))

    def test_cooldown_blocks_repeated_source_classification(self):
        state = notifier.empty_state()
        now = datetime(2026, 7, 22, 15, 13, 30)
        first = event(risk_score=40.0, time_value="2026-07-22 15:13:02")
        repeated = event(risk_score=45.0, time_value="2026-07-22 15:15:02")

        notifier.mark_sent(first, state, now)

        self.assertEqual(
            notifier.should_send_event(repeated, state, now + timedelta(minutes=2)),
            (False, "cooldown active"),
        )

    def test_cooldown_allows_material_risk_increase(self):
        state = notifier.empty_state()
        now = datetime(2026, 7, 22, 15, 13, 30)
        first = event(risk_score=40.0, time_value="2026-07-22 15:13:02")
        repeated = event(risk_score=50.0, time_value="2026-07-22 15:15:02")

        notifier.mark_sent(first, state, now)

        self.assertEqual(
            notifier.should_send_event(repeated, state, now + timedelta(minutes=2)),
            (True, "eligible"),
        )

    def test_missing_credentials_return_clear_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                notifier, "read_live_classified_events", return_value=[event()]
            ), mock.patch.object(notifier, "send_telegram_message") as send_mock, mock.patch.object(
                notifier.LOG, "error"
            ):
                result = notifier.process_once(dry_run=False, state_path=Path(tmpdir) / "state.json")

        self.assertEqual(result, 2)
        send_mock.assert_not_called()

    def test_missing_risk_file_returns_no_events(self):
        with mock.patch.object(notifier, "REPORTS_DIR", Path("/tmp/netguard-missing-risk-dir")):
            self.assertEqual(notifier.read_live_classified_events("2099-01-01"), [])

    def test_dry_run_does_not_call_telegram_or_write_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                notifier, "read_live_classified_events", return_value=[event()]
            ), mock.patch.object(notifier, "send_telegram_message") as send_mock, redirect_stdout(
                io.StringIO()
            ) as stdout:
                result = notifier.process_once(dry_run=True, state_path=state_path)

        self.assertEqual(result, 0)
        self.assertIn("[DRY-RUN] Would send Telegram alert", stdout.getvalue())
        self.assertFalse(state_path.exists())
        send_mock.assert_not_called()

    def test_token_never_appears_in_sanitized_errors(self):
        token = "123456:super-secret-token"
        with mock.patch.dict(os.environ, {notifier.BOT_TOKEN_ENV: token}, clear=True):
            self.assertNotIn(token, notifier.sanitized_error(RuntimeError(f"bad {token}")))

    def test_token_never_appears_in_logs(self):
        token = "123456:super-secret-token"
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        notifier.LOG.addHandler(handler)
        try:
            with mock.patch.dict(os.environ, {notifier.BOT_TOKEN_ENV: token}, clear=True):
                notifier.LOG.error("send failed: %s", notifier.sanitized_error(RuntimeError(token)))
        finally:
            notifier.LOG.removeHandler(handler)

        self.assertNotIn(token, stream.getvalue())


if __name__ == "__main__":
    unittest.main()
