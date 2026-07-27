#!/usr/bin/env python3
"""
Optional Telegram notifier for high-confidence live NetGuard-AI events.

This script is read-only for detection evidence. It reuses the existing attack
classification layer over today's risk report and only writes local alert state.
"""

import argparse
import csv
import hashlib
import html
import json
import logging
import os
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from urllib import parse, request
from urllib.error import HTTPError, URLError


BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "data" / "reports"
STATE_FILE = BASE_DIR / "logs" / "telegram_alert_state.json"
DEFAULT_INTERVAL_SECONDS = 30
TELEGRAM_TIMEOUT_SECONDS = 8
COOLDOWN_SECONDS = 10 * 60
MATERIAL_RISK_INCREASE = 10.0
BOT_TOKEN_ENV = "NETGUARD_TELEGRAM_BOT_TOKEN"
CHAT_ID_ENV = "NETGUARD_TELEGRAM_CHAT_ID"
VALIDATED_ACTIONABLE_CLASS = "PORT_SCAN"
REVIEW_ONLY_CLASSIFICATIONS = {
    "SSH_BRUTE_FORCE_OR_LOGIN_PATTERN",
    "FAILED_CONNECTION_PATTERN",
    "DNS_ANOMALY",
    "DOS_LIKE_BURST",
    "BOT_LIKE_BEHAVIOR",
    "UNKNOWN_SUSPICIOUS",
    "LOW_SIGNAL_REVIEW",
}

if str(BASE_DIR / "scripts") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "scripts"))

import attack_classifier  # noqa: E402


LOG = logging.getLogger("netguard.telegram_alerts")


@dataclass(frozen=True)
class AlertDecision:
    actionable: bool
    review_only: bool
    reason: str
    classification: str
    validated_evidence: dict[str, object]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send optional Telegram alerts for high-confidence live suspicious events."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Check once and send eligible unsent alerts.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print alerts that would be sent without contacting Telegram or updating state.",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Send one harmless Telegram test notification.",
    )
    parser.add_argument(
        "--prime-current",
        action="store_true",
        help="Checkpoint current live events without sending Telegram messages.",
    )
    parser.add_argument(
        "--interval",
        type=positive_interval,
        default=DEFAULT_INTERVAL_SECONDS,
        help="Polling interval in seconds for continuous mode. Default: 30.",
    )
    return parser.parse_args()


def positive_interval(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--interval must be a positive integer") from exc
    if seconds < 1:
        raise argparse.ArgumentTypeError("--interval must be a positive integer")
    return seconds


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def today_string() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def event_classification(event: dict[str, object]) -> str:
    return str(event.get("classification") or event.get("attack_type") or "").strip()


def event_src_ip(event: dict[str, object]) -> str:
    return str(event.get("src_ip") or "n/a").strip() or "n/a"


def event_time(event: dict[str, object]) -> str:
    return str(event.get("time") or event.get("datetime") or event.get("timestamp") or "n/a").strip()


def event_float(event: dict[str, object], key: str) -> float:
    try:
        return float(event.get(key) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def event_text(event: dict[str, object], key: str) -> str:
    value = event.get(key)
    return str(value).strip() if value is not None else ""


def event_truthy(event: dict[str, object], key: str) -> bool:
    return event_text(event, key).lower() in {"1", "true", "yes", "y"}


def event_valid_nonnegative_float(event: dict[str, object], key: str) -> float | None:
    value = event.get(key)
    if value is None or str(value).strip() == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number < 0 or number in {float("inf"), float("-inf")}:
        return None
    return number


def read_live_classified_events(day: str | None = None) -> list[dict[str, object]]:
    current_day = day or today_string()
    risk_file = REPORTS_DIR / f"risk_{current_day}.csv"
    if not risk_file.exists():
        LOG.info("No live risk report found for %s; no Telegram alerts to process.", current_day)
        return []

    try:
        rows = []
        suspicious_rows = []
        with risk_file.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                rows.append(row)
                if attack_classifier.is_suspicious_row(row):
                    suspicious_rows.append(row)
    except Exception as exc:
        LOG.error("Could not read live risk report for %s: %s", current_day, sanitized_error(exc))
        return []

    try:
        suspicious_rows_by_src = Counter(attack_classifier.row_value(row, "src_ip") for row in suspicious_rows)
        suspicious_rows_by_src.pop("", None)
        events = []
        for row in suspicious_rows:
            event = attack_classifier.classify_row(row, suspicious_rows_by_src, set())
            enriched = dict(row)
            enriched.update(event)
            enriched["date"] = current_day
            events.append(enriched)
        return sorted(events, key=attack_classifier.event_sort_key, reverse=True)
    except Exception as exc:
        LOG.error("Could not classify live risk report for %s: %s", current_day, sanitized_error(exc))
        return []


def telegram_alert_decision(event: dict[str, object]) -> AlertDecision:
    classification = event_classification(event)
    evidence: dict[str, object] = {
        "flag_port_scan": event_text(event, "flag_port_scan"),
        "unique_dst_ports_30s": event.get("unique_dst_ports_30s"),
        "unique_dst_ports_1m": event.get("unique_dst_ports_1m"),
    }

    if not classification:
        return AlertDecision(False, True, "missing classification", classification, evidence)
    if classification in REVIEW_ONLY_CLASSIFICATIONS:
        return AlertDecision(False, True, f"{classification} is review-only", classification, evidence)
    if classification != VALIDATED_ACTIONABLE_CLASS:
        return AlertDecision(False, True, f"{classification} is not a validated actionable class", classification, evidence)
    if not event_truthy(event, "flag_port_scan"):
        return AlertDecision(False, True, "flag_port_scan is not set", classification, evidence)

    ports_30s = event_valid_nonnegative_float(event, "unique_dst_ports_30s")
    ports_1m = event_valid_nonnegative_float(event, "unique_dst_ports_1m")
    if ports_30s is None and ports_1m is None:
        return AlertDecision(False, True, "validated unique-port evidence is missing or invalid", classification, evidence)
    if (ports_30s is not None and ports_30s >= 20) or (ports_1m is not None and ports_1m >= 20):
        evidence["validated_port_threshold"] = "unique_dst_ports_30s>=20 or unique_dst_ports_1m>=20"
        return AlertDecision(True, False, "validated PORT_SCAN evidence", classification, evidence)
    return AlertDecision(False, True, "unique destination port evidence is below validated threshold", classification, evidence)


def is_alert_eligible(event: dict[str, object]) -> bool:
    return telegram_alert_decision(event).actionable


def stable_fingerprint(event: dict[str, object]) -> str:
    parts = [
        event_time(event),
        event_src_ip(event),
        event_classification(event),
        f"{event_float(event, 'confidence'):.4f}",
        f"{event_float(event, 'risk_score'):.4f}",
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def cooldown_key(event: dict[str, object]) -> str:
    return f"{event_src_ip(event)}|{event_classification(event)}"


def empty_state() -> dict[str, object]:
    return {
        "sent_fingerprints": {},
        "cooldowns": {},
        "reviewed_fingerprints": {},
        "baseline_fingerprints": {},
    }


def load_state(path: Path = STATE_FILE) -> dict[str, object]:
    if not path.exists():
        return empty_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        LOG.error("Could not read Telegram alert state; starting with empty state: %s", sanitized_error(exc))
        return empty_state()

    if not isinstance(data, dict):
        return empty_state()
    data.setdefault("sent_fingerprints", {})
    data.setdefault("cooldowns", {})
    data.setdefault("reviewed_fingerprints", {})
    data.setdefault("baseline_fingerprints", {})
    if not isinstance(data["sent_fingerprints"], dict):
        data["sent_fingerprints"] = {}
    if not isinstance(data["cooldowns"], dict):
        data["cooldowns"] = {}
    if not isinstance(data["reviewed_fingerprints"], dict):
        data["reviewed_fingerprints"] = {}
    if not isinstance(data["baseline_fingerprints"], dict):
        data["baseline_fingerprints"] = {}
    return data


def save_state(state: dict[str, object], path: Path = STATE_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(path)


def parse_iso_datetime(value: object) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def risk_materially_increased(event: dict[str, object], cooldown: dict[str, object]) -> bool:
    previous_risk = event_float(cooldown, "risk_score")
    return event_float(event, "risk_score") >= previous_risk + MATERIAL_RISK_INCREASE


def is_already_reviewed(event: dict[str, object], state: dict[str, object]) -> bool:
    reviewed_fingerprints = state.get("reviewed_fingerprints", {})
    return isinstance(reviewed_fingerprints, dict) and stable_fingerprint(event) in reviewed_fingerprints


def is_baselined(event: dict[str, object], state: dict[str, object]) -> bool:
    baseline_fingerprints = state.get("baseline_fingerprints", {})
    return isinstance(baseline_fingerprints, dict) and stable_fingerprint(event) in baseline_fingerprints


def should_send_event(
    event: dict[str, object],
    state: dict[str, object],
    now: datetime | None = None,
) -> tuple[bool, str]:
    decision = telegram_alert_decision(event)
    if not decision.actionable:
        return False, f"review-only: {decision.reason}"

    fingerprint = stable_fingerprint(event)
    sent_fingerprints = state.get("sent_fingerprints", {})
    if isinstance(sent_fingerprints, dict) and fingerprint in sent_fingerprints:
        return False, "already sent"

    if is_baselined(event, state):
        return False, "primed historical baseline event"

    current_time = now or datetime.now()
    cooldowns = state.get("cooldowns", {})
    cooldown = cooldowns.get(cooldown_key(event), {}) if isinstance(cooldowns, dict) else {}
    if isinstance(cooldown, dict):
        last_sent_at = parse_iso_datetime(cooldown.get("last_sent_at"))
        if last_sent_at and current_time - last_sent_at < timedelta(seconds=COOLDOWN_SECONDS):
            if not risk_materially_increased(event, cooldown):
                return False, "cooldown active"

    return True, "eligible"


def mark_reviewed(event: dict[str, object], decision: AlertDecision, state: dict[str, object], now: datetime | None = None) -> None:
    current_time = now or datetime.now()
    reviewed_fingerprints = state.setdefault("reviewed_fingerprints", {})
    if isinstance(reviewed_fingerprints, dict):
        reviewed_fingerprints[stable_fingerprint(event)] = {
            "reviewed_at": current_time.isoformat(timespec="seconds"),
            "src_ip": event_src_ip(event),
            "classification": decision.classification,
            "reason": decision.reason,
        }


def mark_baselined(event: dict[str, object], decision: AlertDecision, state: dict[str, object], now: datetime | None = None) -> None:
    current_time = now or datetime.now()
    baseline_fingerprints = state.setdefault("baseline_fingerprints", {})
    if isinstance(baseline_fingerprints, dict):
        baseline_fingerprints[stable_fingerprint(event)] = {
            "primed_at": current_time.isoformat(timespec="seconds"),
            "src_ip": event_src_ip(event),
            "classification": decision.classification,
            "event_time": event_time(event),
            "reason": decision.reason,
        }


def mark_sent(event: dict[str, object], state: dict[str, object], now: datetime | None = None) -> None:
    current_time = now or datetime.now()
    sent_fingerprints = state.setdefault("sent_fingerprints", {})
    cooldowns = state.setdefault("cooldowns", {})
    fingerprint = stable_fingerprint(event)

    if isinstance(sent_fingerprints, dict):
        sent_fingerprints[fingerprint] = {
            "sent_at": current_time.isoformat(timespec="seconds"),
            "src_ip": event_src_ip(event),
            "classification": event_classification(event),
            "risk_score": event_float(event, "risk_score"),
        }
    if isinstance(cooldowns, dict):
        cooldowns[cooldown_key(event)] = {
            "last_sent_at": current_time.isoformat(timespec="seconds"),
            "risk_score": event_float(event, "risk_score"),
        }


def build_message(event: dict[str, object]) -> str:
    reasons = event.get("reasons") or []
    if isinstance(reasons, list):
        reason = "; ".join(str(item) for item in reasons if str(item).strip())
    else:
        reason = str(reasons)
    reason = reason or "n/a"
    return "\n".join(
        [
            "🚨 NetGuard-AI Suspicious Event",
            "",
            f"Classification: {html.escape(event_classification(event))}",
            f"Source: {html.escape(event_src_ip(event))}",
            f"Time: {html.escape(event_time(event))}",
            f"Confidence: {event_float(event, 'confidence'):.2f}",
            f"Risk score: {event_float(event, 'risk_score'):.2f}",
            f"Risk level: {html.escape(event_text(event, 'risk_level') or 'n/a')}",
            f"Unique dst ports 30s: {html.escape(event_text(event, 'unique_dst_ports_30s') or 'n/a')}",
            f"Unique dst ports 1m: {html.escape(event_text(event, 'unique_dst_ports_1m') or 'n/a')}",
            f"Connections 30s: {html.escape(event_text(event, 'connections_30s') or 'n/a')}",
            f"Reason: {html.escape(reason)}",
            "",
            "Status: Validated PORT_SCAN alert tier for analyst review, not a confirmed attack.",
        ]
    )


def credentials_from_env() -> tuple[str | None, str | None]:
    token = os.environ.get(BOT_TOKEN_ENV)
    chat_id = os.environ.get(CHAT_ID_ENV)
    return token if token and token.strip() else None, chat_id if chat_id and chat_id.strip() else None


def missing_credentials_message() -> str:
    return (
        "Missing Telegram credentials. Set NETGUARD_TELEGRAM_BOT_TOKEN and "
        "NETGUARD_TELEGRAM_CHAT_ID in the environment."
    )


def sanitized_error(exc: BaseException) -> str:
    token = os.environ.get(BOT_TOKEN_ENV)
    text = str(exc)
    if token:
        text = text.replace(token, "[REDACTED]")
        text = text.replace(parse.quote(token, safe=""), "[REDACTED]")
    return text


def send_telegram_message(token: str, chat_id: str, message: str) -> bool:
    url = f"https://api.telegram.org/bot{parse.quote(token, safe='')}/sendMessage"
    payload = parse.urlencode(
        {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        }
    ).encode("utf-8")

    req = request.Request(url, data=payload, method="POST")
    try:
        with request.urlopen(req, timeout=TELEGRAM_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                LOG.error("Telegram sendMessage returned HTTP %s", response.status)
                return False
            return True
    except HTTPError as exc:
        LOG.error("Telegram sendMessage failed with HTTP %s: %s", exc.code, sanitized_error(exc))
    except (URLError, TimeoutError, OSError) as exc:
        LOG.error("Telegram sendMessage failed: %s", sanitized_error(exc))
    return False


def process_once(dry_run: bool = False, state_path: Path = STATE_FILE) -> int:
    state = load_state(state_path)
    events = read_live_classified_events()
    eligible_count = 0
    sent_count = 0
    review_state_dirty = False

    token, chat_id = credentials_from_env()
    if not dry_run and (not token or not chat_id):
        LOG.error(missing_credentials_message())
        return 2

    for event in sorted(events, key=lambda item: str(item.get("time", ""))):
        decision = telegram_alert_decision(event)
        if decision.review_only:
            if dry_run:
                print(
                    "[DRY-RUN] Review-only Telegram decision: "
                    f"classification={decision.classification or 'n/a'} "
                    f"src_ip={event_src_ip(event)} reason={decision.reason}"
                )
            else:
                if is_already_reviewed(event, state):
                    LOG.debug(
                        "Skipping already-reviewed Telegram event fingerprint=%s classification=%s src_ip=%s",
                        stable_fingerprint(event),
                        decision.classification or "n/a",
                        event_src_ip(event),
                    )
                    continue
                LOG.info(
                    "Telegram review-only event fingerprint=%s reason=%s classification=%s src_ip=%s",
                    stable_fingerprint(event),
                    decision.reason,
                    decision.classification or "n/a",
                    event_src_ip(event),
                )
                mark_reviewed(event, decision, state)
                review_state_dirty = True
            continue

        should_send, reason = should_send_event(event, state)
        if not should_send:
            LOG.debug(
                "Skipping Telegram alert fingerprint=%s reason=%s classification=%s src_ip=%s",
                stable_fingerprint(event),
                reason,
                event_classification(event),
                event_src_ip(event),
            )
            continue

        eligible_count += 1
        message = build_message(event)
        if dry_run:
            print(
                "[DRY-RUN] Actionable Telegram decision: "
                f"classification={decision.classification} src_ip={event_src_ip(event)} reason={decision.reason}"
            )
            print("[DRY-RUN] Would send Telegram alert:")
            print(message)
            print(f"Fingerprint: {stable_fingerprint(event)}")
            print()
            continue

        if send_telegram_message(str(token), str(chat_id), message):
            mark_sent(event, state)
            sent_count += 1
            try:
                save_state(state, state_path)
                review_state_dirty = False
            except OSError as exc:
                LOG.error("Telegram alert sent but state could not be saved: %s", sanitized_error(exc))
                review_state_dirty = True

    if dry_run:
        print(f"[RESULT] dry_run eligible_alerts={eligible_count}")
    else:
        if review_state_dirty:
            try:
                save_state(state, state_path)
            except OSError as exc:
                LOG.error("Telegram review-only state could not be saved: %s", sanitized_error(exc))
        LOG.info("Telegram alert check complete: eligible=%s sent=%s", eligible_count, sent_count)
    return 0


def prime_current(state_path: Path = STATE_FILE) -> int:
    state = load_state(state_path)
    events = read_live_classified_events()
    actionable_baselined = 0
    review_checkpointed = 0
    unchanged = 0
    state_dirty = False

    for event in sorted(events, key=lambda item: str(item.get("time", ""))):
        decision = telegram_alert_decision(event)
        if decision.review_only:
            if is_already_reviewed(event, state):
                unchanged += 1
                continue
            mark_reviewed(event, decision, state)
            review_checkpointed += 1
            state_dirty = True
            continue

        if decision.actionable:
            if is_baselined(event, state):
                unchanged += 1
                continue
            mark_baselined(event, decision, state)
            actionable_baselined += 1
            state_dirty = True
            continue

        unchanged += 1

    if state_dirty:
        try:
            save_state(state, state_path)
        except OSError as exc:
            LOG.error("Telegram prime-current state could not be saved: %s", sanitized_error(exc))
            return 1

    print(
        "[RESULT] prime_current "
        f"actionable_baselined={actionable_baselined} "
        f"review_checkpointed={review_checkpointed} "
        f"unchanged={unchanged}"
    )
    return 0


def send_test_message() -> int:
    token, chat_id = credentials_from_env()
    if not token or not chat_id:
        LOG.error(missing_credentials_message())
        return 2

    message = "\n".join(
        [
            "NetGuard-AI Telegram alert test",
            "",
            "Status: Test notification only. No suspicious event is being reported.",
        ]
    )
    return 0 if send_telegram_message(token, chat_id, message) else 1


def run_forever(interval: int) -> int:
    token, chat_id = credentials_from_env()
    if not token or not chat_id:
        LOG.error(missing_credentials_message())
        return 2

    LOG.info("Starting Telegram alert notifier with interval=%ss", interval)
    while True:
        process_once(dry_run=False)
        time.sleep(interval)


def main() -> int:
    args = parse_args()
    configure_logging()

    if args.test:
        return send_test_message()
    if args.prime_current:
        return prime_current()
    if args.once or args.dry_run:
        return process_once(dry_run=args.dry_run)
    return run_forever(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
