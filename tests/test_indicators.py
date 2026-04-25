from __future__ import annotations

from datetime import datetime, timedelta
import unittest

from src.indicators import get_indicators


def iso_minutes_ago(minutes: int) -> str:
    return (datetime.now().astimezone() - timedelta(minutes=minutes)).isoformat(timespec="seconds")


def _get_indicator_types(report: dict) -> list[str]:
    indicators = get_indicators(report)
    indicator_types = []
    for item in indicators["indicators"]:
        indicator_types.append(item["indicator_type"])
    return indicator_types


def _empty_report(**overrides: object) -> dict:
    report = {
        "log_events": {
            "failed_logins": [],
            "sudo_events": [],
        },
        "top_processes": {},
        "network_monitoring": {},
        "scheduled_jobs": {},
    }
    report.update(overrides)
    return report


class TestIndicatorsPositive(unittest.TestCase):
    def test_repeated_failed_logins_triggers(self) -> None:
        failed_logins_data = []
        for i in range(6):
            failed_logins_data.append(
                {
                    "timestamp": iso_minutes_ago(2),
                    "username": "root",
                    "source_ip": "127.0.0.1",
                }
            )

        report = _empty_report(
            log_events={
                "failed_logins": failed_logins_data,
                "sudo_events": [],
            }
        )

        indicator_types = _get_indicator_types(report)
        self.assertIn("repeated_failed_logins", indicator_types)

    def test_recent_sudo_activity_triggers(self) -> None:
        report = _empty_report(
            log_events={
                "failed_logins": [],
                "sudo_events": [
                    {
                        "timestamp": iso_minutes_ago(3),
                        "command": "/usr/bin/whoami",
                    }
                ],
            }
        )

        indicator_types = _get_indicator_types(report)
        self.assertIn("recent_sudo_activity", indicator_types)

    def test_high_cpu_process_triggers(self) -> None:
        report = _empty_report(
            top_processes={
                "top_cpu_processes": [
                    {
                        "pid": 1234,
                        "name": "yes",
                        "username": "hungnguyen",
                        "cpu_percent": 85.0,
                    }
                ]
            }
        )

        indicator_types = _get_indicator_types(report)
        self.assertIn("high_cpu_process", indicator_types)

    def test_unusual_listening_port_triggers(self) -> None:
        report = _empty_report(
            network_monitoring={
                "listening_ports": [
                    {
                        "protocol": "tcp",
                        "local_address": "0.0.0.0",
                        "local_port": 9099,
                        "process_name": "python3",
                        "pid": 4321,
                    }
                ]
            }
        )

        indicator_types = _get_indicator_types(report)
        self.assertIn("unusual_listening_port", indicator_types)

    def test_suspicious_cron_entry_triggers(self) -> None:
        report = _empty_report(
            scheduled_jobs={
                "entries": [
                    {
                        "source": "crontab -l (hungnguyen)",
                        "entry": "* * * * * /tmp/cron_test.sh",
                    }
                ]
            }
        )

        indicator_types = _get_indicator_types(report)
        self.assertIn("suspicious_cron_entry", indicator_types)


class TestIndicatorsNegative(unittest.TestCase):
    def test_four_failed_logins_does_not_trigger(self) -> None:
        failed_logins_data = []
        for i in range(4):
            failed_logins_data.append(
                {
                    "timestamp": iso_minutes_ago(2),
                    "username": "root",
                    "source_ip": "192.168.1.1",
                }
            )

        report = _empty_report(
            log_events={
                "failed_logins": failed_logins_data,
                "sudo_events": [],
            }
        )

        indicator_types = _get_indicator_types(report)
        self.assertNotIn("repeated_failed_logins", indicator_types)

    def test_old_failed_logins_does_not_trigger(self) -> None:
        failed_logins_data = []
        for i in range(6):
            failed_logins_data.append(
                {
                    "timestamp": iso_minutes_ago(30),
                    "username": "root",
                    "source_ip": "10.0.0.1",
                }
            )

        report = _empty_report(
            log_events={
                "failed_logins": failed_logins_data,
                "sudo_events": [],
            }
        )

        indicator_types = _get_indicator_types(report)
        self.assertNotIn("repeated_failed_logins", indicator_types)


    def test_old_sudo_events_does_not_trigger(self) -> None:
        report = _empty_report(
            log_events={
                "failed_logins": [],
                "sudo_events": [
                    {
                        "timestamp": iso_minutes_ago(60),
                        "command": "/usr/bin/whoami",
                    }
                ],
            }
        )

        indicator_types = _get_indicator_types(report)
        self.assertNotIn("recent_sudo_activity", indicator_types)


    def test_low_cpu_process_does_not_trigger(self) -> None:
        report = _empty_report(
            top_processes={
                "top_cpu_processes": [
                    {
                        "pid": 1234,
                        "name": "bash",
                        "username": "hungnguyen",
                        "cpu_percent": 10.0,
                    }
                ]
            }
        )

        indicator_types = _get_indicator_types(report)
        self.assertNotIn("high_cpu_process", indicator_types)


    def test_localhost_port_does_not_trigger(self) -> None:
        report = _empty_report(
            network_monitoring={
                "listening_ports": [
                    {
                        "protocol": "tcp",
                        "local_address": "127.0.0.1",
                        "local_port": 9099,
                        "process_name": "python3",
                        "pid": 4321,
                    }
                ]
            }
        )

        indicator_types = _get_indicator_types(report)
        self.assertNotIn("unusual_listening_port", indicator_types)


    def test_allowlisted_port_does_not_trigger(self) -> None:
        report = _empty_report(
            network_monitoring={
                "listening_ports": [
                    {
                        "protocol": "tcp",
                        "local_address": "0.0.0.0",
                        "local_port": 22,
                        "process_name": "sshd",
                        "pid": 1427,
                    }
                ]
            }
        )

        indicator_types = _get_indicator_types(report)
        self.assertNotIn("unusual_listening_port", indicator_types)


    def test_normal_cron_entry_does_not_trigger(self) -> None:
        report = _empty_report(
            scheduled_jobs={
                "entries": [
                    {
                        "source": "/etc/crontab",
                        "entry": "25 6 * * * root test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }",
                    }
                ]
            }
        )

        indicator_types = _get_indicator_types(report)
        self.assertNotIn("suspicious_cron_entry", indicator_types)


    def test_empty_report_triggers_nothing(self) -> None:
        report = _empty_report()

        indicators = get_indicators(report)
        self.assertEqual(indicators["indicator_count"], 0)
        self.assertEqual(len(indicators["indicators"]), 0)


if __name__ == "__main__":
    unittest.main()
