from __future__ import annotations

from datetime import datetime, timedelta
import unittest

from src.indicators import get_indicators


def iso_minutes_ago(minutes: int) -> str:
    return (datetime.now().astimezone() - timedelta(minutes=minutes)).isoformat(timespec="seconds")


class TestIndicators(unittest.TestCase):
    def test_repeated_failed_logins_indicator_triggers(self) -> None:
        failed_logins_data = []
        for i in range(6):
            failed_logins_data.append(
                {
                    "timestamp": iso_minutes_ago(2),
                    "username": "root",
                    "source_ip": "127.0.0.1",
                }
            )

        report = {
            "log_events": {
                "failed_logins": failed_logins_data,
                "sudo_events": [],
            },
            "top_processes": {},
            "network_monitoring": {},
            "scheduled_jobs": {},
        }

        indicators = get_indicators(report)
        indicator_types = []
        for item in indicators["indicators"]:
            indicator_types.append(item["indicator_type"])

        self.assertIn("repeated_failed_logins", indicator_types)

    def test_recent_sudo_activity_indicator_triggers(self) -> None:
        report = {
            "log_events": {
                "failed_logins": [],
                "sudo_events": [
                    {
                        "timestamp": iso_minutes_ago(3),
                        "command": "/usr/bin/whoami",
                    }
                ],
            },
            "top_processes": {},
            "network_monitoring": {},
            "scheduled_jobs": {},
        }

        indicators = get_indicators(report)
        indicator_types = []
        for item in indicators["indicators"]:
            indicator_types.append(item["indicator_type"])
        self.assertIn("recent_sudo_activity", indicator_types)

    def test_high_cpu_process_indicator_triggers(self) -> None:
        report = {
            "log_events": {
                "failed_logins": [],
                "sudo_events": [],
            },
            "top_processes": {
                "top_cpu_processes": [
                    {
                        "pid": 1234,
                        "name": "yes",
                        "username": "hungnguyen",
                        "cpu_percent": 85.0,
                    }
                ]
            },
            "network_monitoring": {},
            "scheduled_jobs": {},
        }

        indicators = get_indicators(report)

        indicator_types = []
        for item in indicators["indicators"]:
            indicator_types.append(item["indicator_type"])
        self.assertIn("high_cpu_process", indicator_types)

    def test_unusual_listening_port_indicator_triggers(self) -> None:
        report = {
            "log_events": {
                "failed_logins": [],
                "sudo_events": [],
            },
            "top_processes": {},
            "network_monitoring": {
                "listening_ports": [
                    {
                        "protocol": "tcp",
                        "local_address": "0.0.0.0",
                        "local_port": 9099,
                        "process_name": "python3",
                        "pid": 4321,
                    }
                ]
            },
            "scheduled_jobs": {},
        }

        indicators = get_indicators(report)

        indicator_types = []
        for item in indicators["indicators"]:
            indicator_types.append(item["indicator_type"])
        self.assertIn("unusual_listening_port", indicator_types)

    def test_suspicious_cron_entry_indicator_triggers(self) -> None:
        report = {
            "log_events": {
                "failed_logins": [],
                "sudo_events": [],
            },
            "top_processes": {},
            "network_monitoring": {},
            "scheduled_jobs": {
                "entries": [
                    {
                        "source": "crontab -l (hungnguyen)",
                        "entry": "* * * * * /tmp/cron_test.sh",
                    }
                ]
            },
        }

        indicators = get_indicators(report)
        indicator_types = []
        for item in indicators["indicators"]:
            indicator_types.append(item["indicator_type"])
        self.assertIn("suspicious_cron_entry", indicator_types)


if __name__ == "__main__":
    unittest.main()
