#!/usr/bin/env python3

import unittest
from collections import Counter
import sys
import types

from scripts import attack_classifier
from scripts import telegram_alert_notifier

sys.modules.setdefault(
    "numpy",
    types.SimpleNamespace(
        ndarray=object,
        zeros_like=lambda values: values,
    ),
)
sys.modules.setdefault(
    "pandas",
    types.SimpleNamespace(
        Series=dict,
        DataFrame=object,
    ),
)
from scripts import risk_engine  # noqa: E402


def row(
    unique_ips=1,
    unique_ports=1,
    unique_ports_1m=1,
    flag_port_scan=0,
    connections=1,
    failed=0.0,
    risk=25.0,
):
    return {
        "datetime": "2026-07-28 12:00:00",
        "src_ip": "192.168.50.95",
        "connections_30s": str(connections),
        "unique_dst_ports_30s": str(unique_ports),
        "unique_dst_ports_1m": str(unique_ports_1m),
        "unique_dst_ips_30s": str(unique_ips),
        "failed_conn_rate_30s": str(failed),
        "dns_rate_30s": "0",
        "burst_score_30s": "0",
        "bytes_per_sec_30s": "0",
        "flag_port_scan": str(flag_port_scan),
        "flag_brute_force": "0",
        "flag_burst": "0",
        "flag_dns_flood": "0",
        "anomaly_score": "0",
        "risk_score": str(risk),
        "dst_port": "443",
        "service": "-",
        "proto": "tcp",
    }


def classify(item):
    return attack_classifier.classify_row(item, Counter({item["src_ip"]: 1}), set())["attack_type"]


class AttackClassifierHotfixTests(unittest.TestCase):
    def test_ip_fanout_with_three_ports_and_no_flag_is_not_port_scan(self):
        item = row(unique_ips=54, unique_ports=3, flag_port_scan=0, connections=81)

        self.assertNotEqual(classify(item), "PORT_SCAN")

    def test_ip_fanout_with_five_ports_and_no_flag_is_not_port_scan(self):
        item = row(unique_ips=17, unique_ports=5, flag_port_scan=0, connections=81)

        self.assertNotEqual(classify(item), "PORT_SCAN")

    def test_flag_port_scan_with_20_ports_30s_is_port_scan(self):
        item = row(unique_ports=20, unique_ports_1m=1, flag_port_scan=1, connections=20)

        self.assertEqual(classify(item), "PORT_SCAN")

    def test_flag_port_scan_with_20_ports_1m_is_port_scan(self):
        item = row(unique_ports=5, unique_ports_1m=20, flag_port_scan=1, connections=20)

        self.assertEqual(classify(item), "PORT_SCAN")

    def test_five_port_review_explanation_does_not_use_validated_scan_phrase(self):
        item = {
            "unique_dst_ports_30s": 5,
            "unique_dst_ports_1m": 5,
            "port_entropy_30s": 0.8,
            "flag_port_scan": 0,
        }

        explanation = risk_engine._build_explanation(item, [("scan", 1.0)], "HIGH")

        self.assertNotIn("مسح منافذ محتمل", explanation)
        self.assertIn("تنوع منافذ أعلى من المعتاد للمراجعة", explanation)

    def test_validated_telegram_decision_behavior_remains_unchanged(self):
        decision = telegram_alert_notifier.telegram_alert_decision(
            {
                "attack_type": "PORT_SCAN",
                "src_ip": "192.168.50.95",
                "time": "2026-07-28 12:00:00",
                "confidence": 0.7,
                "risk_score": 40,
                "flag_port_scan": "1",
                "unique_dst_ports_30s": "101",
                "unique_dst_ports_1m": "102",
            }
        )

        self.assertTrue(decision.actionable)


if __name__ == "__main__":
    unittest.main()
