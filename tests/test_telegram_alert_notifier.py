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
    flag_port_scan="1",
    unique_dst_ports_30s="101",
    unique_dst_ports_1m="102",
    connections_30s="120",
):
    return {
        "time": time_value,
        "src_ip": src_ip,
        "attack_type": classification,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": "high",
        "flag_port_scan": flag_port_scan,
        "unique_dst_ports_30s": unique_dst_ports_30s,
        "unique_dst_ports_1m": unique_dst_ports_1m,
        "connections_30s": connections_30s,
        "reasons": ["connections_30s=152 >= 120 with elevated risk"],
    }


class TelegramAlertNotifierTests(unittest.TestCase):
    def test_eligibility_policy(self):
        self.assertTrue(notifier.is_alert_eligible(event("PORT_SCAN", 0.65, 12)))
        self.assertFalse(notifier.is_alert_eligible(event("DOS_LIKE_BURST", 0.60, 8)))
        self.assertFalse(
            notifier.is_alert_eligible(
                event("SSH_BRUTE_FORCE_OR_LOGIN_PATTERN", 0.65, 12)
            )
        )
        self.assertFalse(notifier.is_alert_eligible(event("DNS_ANOMALY", 0.65, 30)))
        self.assertFalse(notifier.is_alert_eligible(event("LOW_SIGNAL_REVIEW", 0.90, 99)))
        self.assertFalse(notifier.is_alert_eligible(event("FAILED_CONNECTION_PATTERN", 0.60, 12)))

    def test_portscan_with_flag_zero_is_review_only(self):
        decision = notifier.telegram_alert_decision(event(flag_port_scan="0"))

        self.assertFalse(decision.actionable)
        self.assertTrue(decision.review_only)
        self.assertEqual(decision.classification, "PORT_SCAN")

    def test_cdn_web_fanout_with_three_to_six_ports_is_review_only(self):
        decision = notifier.telegram_alert_decision(
            event(flag_port_scan="0", unique_dst_ports_30s="6", unique_dst_ports_1m="6")
        )

        self.assertFalse(decision.actionable)
        self.assertIn("flag_port_scan", decision.reason)

    def test_validated_portscan_with_flag_and_101_ports_is_actionable(self):
        decision = notifier.telegram_alert_decision(event(flag_port_scan="1", unique_dst_ports_30s="101"))

        self.assertTrue(decision.actionable)
        self.assertFalse(decision.review_only)
        self.assertIn("validated", decision.reason)

    def test_unique_dst_ports_1m_independently_satisfies_threshold(self):
        decision = notifier.telegram_alert_decision(
            event(flag_port_scan="1", unique_dst_ports_30s="6", unique_dst_ports_1m="20")
        )

        self.assertTrue(decision.actionable)

    def test_unique_port_values_below_threshold_are_review_only(self):
        decision = notifier.telegram_alert_decision(
            event(flag_port_scan="1", unique_dst_ports_30s="6", unique_dst_ports_1m="19")
        )

        self.assertFalse(decision.actionable)
        self.assertIn("below validated threshold", decision.reason)

    def test_missing_evidence_fails_closed(self):
        decision = notifier.telegram_alert_decision({"attack_type": "PORT_SCAN"})

        self.assertFalse(decision.actionable)
        self.assertTrue(decision.review_only)

    def test_malformed_nan_and_negative_values_fail_closed(self):
        for value in ("bad", "NaN", "-1"):
            with self.subTest(value=value):
                decision = notifier.telegram_alert_decision(
                    event(flag_port_scan="1", unique_dst_ports_30s=value, unique_dst_ports_1m="")
                )
                self.assertFalse(decision.actionable)

    def test_every_unvalidated_classification_is_review_only(self):
        for classification in notifier.REVIEW_ONLY_CLASSIFICATIONS:
            with self.subTest(classification=classification):
                decision = notifier.telegram_alert_decision(event(classification=classification))
                self.assertFalse(decision.actionable)
                self.assertTrue(decision.review_only)

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

    def test_review_only_rows_never_call_telegram_sender(self):
        review_event = event(flag_port_scan="0", unique_dst_ports_30s="101")
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            with mock.patch.dict(
                os.environ,
                {notifier.BOT_TOKEN_ENV: "token", notifier.CHAT_ID_ENV: "chat"},
                clear=True,
            ), mock.patch.object(
                notifier, "read_live_classified_events", return_value=[review_event]
            ), mock.patch.object(notifier, "send_telegram_message") as send_mock:
                result = notifier.process_once(dry_run=False, state_path=state_path)

        self.assertEqual(result, 0)
        send_mock.assert_not_called()

    def test_review_only_rows_do_not_consume_cooldown(self):
        state = notifier.empty_state()
        now = datetime(2026, 7, 22, 15, 13, 30)
        review_event = event(flag_port_scan="0", unique_dst_ports_30s="101")
        decision = notifier.telegram_alert_decision(review_event)
        notifier.mark_reviewed(review_event, decision, state, now)
        actionable = event(time_value="2026-07-22 15:13:45", unique_dst_ports_30s="101")

        self.assertEqual(notifier.should_send_event(actionable, state, now), (True, "eligible"))
        self.assertEqual(state["cooldowns"], {})

    def test_validated_actionable_duplicates_still_use_cooldown_and_dedupe(self):
        state = notifier.empty_state()
        now = datetime(2026, 7, 22, 15, 13, 30)
        first = event(risk_score=40.0, time_value="2026-07-22 15:13:02")
        duplicate = dict(first)
        repeated = event(risk_score=45.0, time_value="2026-07-22 15:14:02")

        self.assertEqual(notifier.should_send_event(first, state, now), (True, "eligible"))
        notifier.mark_sent(first, state, now)
        self.assertEqual(notifier.should_send_event(duplicate, state, now), (False, "already sent"))
        self.assertEqual(
            notifier.should_send_event(repeated, state, now + timedelta(minutes=1)),
            (False, "cooldown active"),
        )

    def test_review_only_rows_advance_checkpoint_cursor(self):
        review_event = event(flag_port_scan="0", unique_dst_ports_30s="101")
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            with mock.patch.dict(
                os.environ,
                {notifier.BOT_TOKEN_ENV: "token", notifier.CHAT_ID_ENV: "chat"},
                clear=True,
            ), mock.patch.object(
                notifier, "read_live_classified_events", return_value=[review_event]
            ), mock.patch.object(notifier, "send_telegram_message"):
                result = notifier.process_once(dry_run=False, state_path=state_path)

            state = notifier.load_state(state_path)

        self.assertEqual(result, 0)
        self.assertIn(notifier.stable_fingerprint(review_event), state["reviewed_fingerprints"])
        self.assertEqual(state["sent_fingerprints"], {})
        self.assertEqual(state["cooldowns"], {})

    def test_first_normal_run_with_new_review_only_event_logs_and_reviews_it(self):
        review_event = event(flag_port_scan="0", unique_dst_ports_30s="101")
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            with mock.patch.dict(
                os.environ,
                {notifier.BOT_TOKEN_ENV: "token", notifier.CHAT_ID_ENV: "chat"},
                clear=True,
            ), mock.patch.object(
                notifier, "read_live_classified_events", return_value=[review_event]
            ), mock.patch.object(notifier, "send_telegram_message") as send_mock, mock.patch.object(
                notifier, "save_state", wraps=notifier.save_state
            ) as save_mock, self.assertLogs(notifier.LOG, level="INFO") as logs:
                result = notifier.process_once(dry_run=False, state_path=state_path)

            state = notifier.load_state(state_path)

        self.assertEqual(result, 0)
        self.assertIn(notifier.stable_fingerprint(review_event), state["reviewed_fingerprints"])
        self.assertEqual(save_mock.call_count, 1)
        send_mock.assert_not_called()
        self.assertTrue(any("Telegram review-only event" in message for message in logs.output))

    def test_second_identical_review_only_run_skips_mark_and_save_and_info(self):
        review_event = event(flag_port_scan="0", unique_dst_ports_30s="101")
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state = notifier.empty_state()
            decision = notifier.telegram_alert_decision(review_event)
            notifier.mark_reviewed(review_event, decision, state)
            notifier.save_state(state, state_path)
            with mock.patch.dict(
                os.environ,
                {notifier.BOT_TOKEN_ENV: "token", notifier.CHAT_ID_ENV: "chat"},
                clear=True,
            ), mock.patch.object(
                notifier, "read_live_classified_events", return_value=[review_event]
            ), mock.patch.object(notifier, "send_telegram_message") as send_mock, mock.patch.object(
                notifier, "mark_reviewed"
            ) as mark_mock, mock.patch.object(notifier, "save_state") as save_mock, self.assertLogs(
                notifier.LOG, level="DEBUG"
            ) as logs:
                result = notifier.process_once(dry_run=False, state_path=state_path)

        self.assertEqual(result, 0)
        mark_mock.assert_not_called()
        save_mock.assert_not_called()
        send_mock.assert_not_called()
        self.assertTrue(any("Skipping already-reviewed" in message for message in logs.output))
        self.assertFalse(any("Telegram review-only event" in message for message in logs.output))

    def test_multiple_new_review_only_events_save_state_once_per_cycle(self):
        events = [
            event(flag_port_scan="0", time_value="2026-07-22 15:13:02"),
            event(flag_port_scan="0", time_value="2026-07-22 15:14:02"),
            event(classification="DNS_ANOMALY", time_value="2026-07-22 15:15:02"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            with mock.patch.dict(
                os.environ,
                {notifier.BOT_TOKEN_ENV: "token", notifier.CHAT_ID_ENV: "chat"},
                clear=True,
            ), mock.patch.object(
                notifier, "read_live_classified_events", return_value=events
            ), mock.patch.object(notifier, "save_state", wraps=notifier.save_state) as save_mock:
                result = notifier.process_once(dry_run=False, state_path=state_path)

            state = notifier.load_state(state_path)

        self.assertEqual(result, 0)
        self.assertEqual(save_mock.call_count, 1)
        self.assertEqual(len(state["reviewed_fingerprints"]), 3)

    def test_changed_stable_fingerprint_is_new_review_event(self):
        first = event(flag_port_scan="0", time_value="2026-07-22 15:13:02")
        changed = event(flag_port_scan="0", time_value="2026-07-22 15:13:32")
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state = notifier.empty_state()
            notifier.mark_reviewed(first, notifier.telegram_alert_decision(first), state)
            notifier.save_state(state, state_path)
            with mock.patch.dict(
                os.environ,
                {notifier.BOT_TOKEN_ENV: "token", notifier.CHAT_ID_ENV: "chat"},
                clear=True,
            ), mock.patch.object(
                notifier, "read_live_classified_events", return_value=[changed]
            ), mock.patch.object(notifier, "mark_reviewed", wraps=notifier.mark_reviewed) as mark_mock:
                result = notifier.process_once(dry_run=False, state_path=state_path)

            state = notifier.load_state(state_path)

        self.assertEqual(result, 0)
        self.assertEqual(mark_mock.call_count, 1)
        self.assertIn(notifier.stable_fingerprint(first), state["reviewed_fingerprints"])
        self.assertIn(notifier.stable_fingerprint(changed), state["reviewed_fingerprints"])

    def test_review_deduplication_does_not_modify_cooldowns_or_sent_fingerprints(self):
        review_event = event(flag_port_scan="0", unique_dst_ports_30s="101")
        state = notifier.empty_state()
        notifier.mark_reviewed(review_event, notifier.telegram_alert_decision(review_event), state)

        self.assertTrue(notifier.is_already_reviewed(review_event, state))
        self.assertEqual(state["sent_fingerprints"], {})
        self.assertEqual(state["cooldowns"], {})

    def test_already_reviewed_event_does_not_suppress_later_actionable_portscan(self):
        review_event = event(flag_port_scan="0", time_value="2026-07-22 15:13:02")
        actionable = event(flag_port_scan="1", time_value="2026-07-22 15:13:30")
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state = notifier.empty_state()
            notifier.mark_reviewed(review_event, notifier.telegram_alert_decision(review_event), state)
            notifier.save_state(state, state_path)
            with mock.patch.dict(
                os.environ,
                {notifier.BOT_TOKEN_ENV: "token", notifier.CHAT_ID_ENV: "chat"},
                clear=True,
            ), mock.patch.object(
                notifier, "read_live_classified_events", return_value=[review_event, actionable]
            ), mock.patch.object(notifier, "send_telegram_message", return_value=True) as send_mock:
                result = notifier.process_once(dry_run=False, state_path=state_path)

            state = notifier.load_state(state_path)

        self.assertEqual(result, 0)
        send_mock.assert_called_once()
        self.assertIn(notifier.stable_fingerprint(actionable), state["sent_fingerprints"])
        self.assertIn(notifier.cooldown_key(actionable), state["cooldowns"])

    def test_dry_run_prints_already_reviewed_event_without_write_or_network(self):
        review_event = event(flag_port_scan="0", unique_dst_ports_30s="101")
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state = notifier.empty_state()
            notifier.mark_reviewed(review_event, notifier.telegram_alert_decision(review_event), state)
            notifier.save_state(state, state_path)
            before = state_path.read_text(encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                notifier, "read_live_classified_events", return_value=[review_event]
            ), mock.patch.object(notifier, "send_telegram_message") as send_mock, mock.patch.object(
                notifier, "mark_reviewed"
            ) as mark_mock, mock.patch.object(notifier, "save_state") as save_mock, redirect_stdout(
                io.StringIO()
            ) as stdout:
                result = notifier.process_once(dry_run=True, state_path=state_path)
            after = state_path.read_text(encoding="utf-8")

        self.assertEqual(result, 0)
        self.assertIn("[DRY-RUN] Review-only Telegram decision", stdout.getvalue())
        self.assertEqual(before, after)
        mark_mock.assert_not_called()
        save_mock.assert_not_called()
        send_mock.assert_not_called()

    def test_prime_current_performs_no_telegram_request_and_requires_no_credentials(self):
        actionable = event()
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                notifier, "read_live_classified_events", return_value=[actionable]
            ), mock.patch.object(notifier, "send_telegram_message") as send_mock, redirect_stdout(
                io.StringIO()
            ) as stdout:
                result = notifier.prime_current(state_path=state_path)

        self.assertEqual(result, 0)
        self.assertIn("[RESULT] prime_current actionable_baselined=1", stdout.getvalue())
        send_mock.assert_not_called()

    def test_prime_current_places_actionable_events_in_baseline_only(self):
        actionable = event()
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            with mock.patch.object(notifier, "read_live_classified_events", return_value=[actionable]), redirect_stdout(
                io.StringIO()
            ):
                result = notifier.prime_current(state_path=state_path)
            state = notifier.load_state(state_path)

        self.assertEqual(result, 0)
        self.assertIn(notifier.stable_fingerprint(actionable), state["baseline_fingerprints"])
        self.assertEqual(state["sent_fingerprints"], {})
        self.assertEqual(state["cooldowns"], {})

    def test_prime_current_checkpoints_review_only_events(self):
        review_event = event(flag_port_scan="0")
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            with mock.patch.object(notifier, "read_live_classified_events", return_value=[review_event]), redirect_stdout(
                io.StringIO()
            ):
                result = notifier.prime_current(state_path=state_path)
            state = notifier.load_state(state_path)

        self.assertEqual(result, 0)
        self.assertIn(notifier.stable_fingerprint(review_event), state["reviewed_fingerprints"])
        self.assertEqual(state["baseline_fingerprints"], {})
        self.assertEqual(state["sent_fingerprints"], {})
        self.assertEqual(state["cooldowns"], {})

    def test_prime_current_saves_once_for_multiple_primed_events(self):
        events = [
            event(time_value="2026-07-22 15:13:02"),
            event(time_value="2026-07-22 15:14:02"),
            event(flag_port_scan="0", time_value="2026-07-22 15:15:02"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            with mock.patch.object(
                notifier, "read_live_classified_events", return_value=events
            ), mock.patch.object(notifier, "save_state", wraps=notifier.save_state) as save_mock, redirect_stdout(
                io.StringIO()
            ):
                result = notifier.prime_current(state_path=state_path)
            state = notifier.load_state(state_path)

        self.assertEqual(result, 0)
        self.assertEqual(save_mock.call_count, 1)
        self.assertEqual(len(state["baseline_fingerprints"]), 2)
        self.assertEqual(len(state["reviewed_fingerprints"]), 1)

    def test_second_identical_prime_current_is_idempotent_and_no_write(self):
        events = [
            event(time_value="2026-07-22 15:13:02"),
            event(flag_port_scan="0", time_value="2026-07-22 15:14:02"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            with mock.patch.object(notifier, "read_live_classified_events", return_value=events), redirect_stdout(
                io.StringIO()
            ):
                self.assertEqual(notifier.prime_current(state_path=state_path), 0)
            before = state_path.read_text(encoding="utf-8")
            with mock.patch.object(
                notifier, "read_live_classified_events", return_value=events
            ), mock.patch.object(notifier, "save_state") as save_mock, redirect_stdout(
                io.StringIO()
            ) as stdout:
                result = notifier.prime_current(state_path=state_path)
            after = state_path.read_text(encoding="utf-8")

        self.assertEqual(result, 0)
        self.assertIn("actionable_baselined=0", stdout.getvalue())
        self.assertIn("review_checkpointed=0", stdout.getvalue())
        self.assertIn("unchanged=2", stdout.getvalue())
        self.assertEqual(before, after)
        save_mock.assert_not_called()

    def test_exact_primed_actionable_event_is_skipped_by_should_send_event(self):
        actionable = event()
        state = notifier.empty_state()
        notifier.mark_baselined(actionable, notifier.telegram_alert_decision(actionable), state)

        self.assertEqual(
            notifier.should_send_event(actionable, state),
            (False, "primed historical baseline event"),
        )
        self.assertEqual(state["sent_fingerprints"], {})
        self.assertEqual(state["cooldowns"], {})

    def test_future_changed_actionable_fingerprint_remains_eligible_after_prime(self):
        historical = event(time_value="2026-07-22 15:13:02")
        future = event(time_value="2026-07-22 15:20:02")
        state = notifier.empty_state()
        notifier.mark_baselined(historical, notifier.telegram_alert_decision(historical), state)

        self.assertEqual(notifier.should_send_event(future, state), (True, "eligible"))

    def test_baseline_suppression_happens_before_cooldown(self):
        actionable = event(risk_score=40.0)
        state = notifier.empty_state()
        notifier.mark_baselined(actionable, notifier.telegram_alert_decision(actionable), state)
        state["cooldowns"][notifier.cooldown_key(actionable)] = {
            "last_sent_at": datetime.now().isoformat(timespec="seconds"),
            "risk_score": 40.0,
        }

        self.assertEqual(
            notifier.should_send_event(actionable, state),
            (False, "primed historical baseline event"),
        )

    def test_old_state_files_without_baseline_fingerprints_load_correctly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state_path.write_text(
                '{"sent_fingerprints": {}, "cooldowns": {}, "reviewed_fingerprints": {}}\n',
                encoding="utf-8",
            )
            state = notifier.load_state(state_path)

        self.assertEqual(state["baseline_fingerprints"], {})

    def test_dry_run_honors_baseline_without_state_write_or_network(self):
        actionable = event()
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state = notifier.empty_state()
            notifier.mark_baselined(actionable, notifier.telegram_alert_decision(actionable), state)
            notifier.save_state(state, state_path)
            before = state_path.read_text(encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                notifier, "read_live_classified_events", return_value=[actionable]
            ), mock.patch.object(notifier, "send_telegram_message") as send_mock, mock.patch.object(
                notifier, "save_state"
            ) as save_mock, redirect_stdout(io.StringIO()) as stdout:
                result = notifier.process_once(dry_run=True, state_path=state_path)
            after = state_path.read_text(encoding="utf-8")

        self.assertEqual(result, 0)
        self.assertIn("[RESULT] dry_run eligible_alerts=0", stdout.getvalue())
        self.assertEqual(before, after)
        save_mock.assert_not_called()
        send_mock.assert_not_called()

    def test_actionable_message_contains_validated_portscan_evidence(self):
        message = notifier.build_message(
            event(unique_dst_ports_30s="101", unique_dst_ports_1m="102", connections_30s="120")
        )

        self.assertIn("Classification: PORT_SCAN", message)
        self.assertIn("Unique dst ports 30s: 101", message)
        self.assertIn("Unique dst ports 1m: 102", message)
        self.assertIn("Connections 30s: 120", message)
        self.assertIn("Risk level: high", message)

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

    def test_dry_run_prints_review_only_decision_without_network_request(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                notifier, "read_live_classified_events", return_value=[event(flag_port_scan="0")]
            ), mock.patch.object(notifier, "send_telegram_message") as send_mock, redirect_stdout(
                io.StringIO()
            ) as stdout:
                result = notifier.process_once(dry_run=True, state_path=state_path)

        self.assertEqual(result, 0)
        self.assertIn("[DRY-RUN] Review-only Telegram decision", stdout.getvalue())
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
