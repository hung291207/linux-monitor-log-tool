from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.log_parser import (
    _extract_failed_login_event,
    _extract_ssh_event,
    _extract_sudo_event,
    _parse_log_line,
    parse_auth_log,
)


class TestLogParser(unittest.TestCase):
    def test_parse_log_line_extracts_service_without_pid(self) -> None:
        line = ("2026-04-24T01:26:34.863236+03:00 ubuntu-vm sshd[8547]: Accepted password for hungnguyen from 127.0.0.1 port 51476 ssh2")

        parsed = _parse_log_line(line)

        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["host"], "ubuntu-vm")
        self.assertEqual(parsed["service"], "sshd")
        self.assertIn("Accepted password", parsed["message"])
        self.assertTrue(parsed["timestamp_iso"])

    def test_extract_failed_password_event(self) -> None:
        line = ("2026-04-24T01:30:00+03:00 ubuntu-vm sshd[9999]: Failed password for invalid user admin from 192.168.1.50 port 44444 ssh2")

        parsed = _parse_log_line(line)
        assert parsed is not None

        event = _extract_failed_login_event(parsed)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["event_type"], "failed_password")
        self.assertEqual(event["username"], "admin")
        self.assertEqual(event["source_ip"], "192.168.1.50")

    def test_extract_authentication_failure_event(self) -> None:
        line = ("2026-04-24T01:23:56+03:00 ubuntu-vm su: pam_unix(su:auth): authentication failure; logname=hungnguyen uid=1000 euid=0 tty=/dev/pts/5 ruser=hungnguyen rhost= user=root")

        parsed = _parse_log_line(line)
        assert parsed is not None

        event = _extract_failed_login_event(parsed)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["event_type"], "authentication_failure")
        self.assertEqual(event["username"], "root")

    def test_extract_sudo_event(self) -> None:
        line = ("2026-04-24T01:26:43+03:00 ubuntu-vm sudo: hungnguyen : TTY=pts/5 ; PWD=/home/hungnguyen ; USER=root ; COMMAND=/usr/bin/grep Accepted /var/log/auth.log")

        parsed = _parse_log_line(line)
        assert parsed is not None

        event = _extract_sudo_event(parsed)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["event_type"], "sudo_command")
        self.assertEqual(event["username"], "hungnguyen")
        self.assertIn("/usr/bin/grep", str(event["command"]))

    def test_extract_accepted_ssh_event(self) -> None:
        line = ("2026-04-24T01:43:13+03:00 ubuntu-vm sshd[8997]: Accepted password for hungnguyen from 127.0.0.1 port 38888 ssh2")

        parsed = _parse_log_line(line)
        assert parsed is not None

        event = _extract_ssh_event(parsed)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["event_type"], "ssh_login")
        self.assertEqual(event["username"], "hungnguyen")
        self.assertEqual(event["source_ip"], "127.0.0.1")

    def test_parse_auth_log_counts_events_from_temp_file(self) -> None:
        content = "\n".join([
            "2026-04-24T01:23:56+03:00 ubuntu-vm su: pam_unix(su:auth): authentication failure; logname=hungnguyen uid=1000 euid=0 tty=/dev/pts/5 ruser=hungnguyen rhost= user=root",
            "2026-04-24T01:26:43+03:00 ubuntu-vm sudo: hungnguyen : TTY=pts/5 ; PWD=/home/hungnguyen ; USER=root ; COMMAND=/usr/bin/whoami",
            "2026-04-24T01:43:13+03:00 ubuntu-vm sshd[8997]: Accepted password for hungnguyen from 127.0.0.1 port 38888 ssh2",
        ])

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"
            log_path.write_text(content, encoding="utf-8")

            result = parse_auth_log(log_path=log_path)

        self.assertEqual(result["failed_login_count"], 1)
        self.assertEqual(result["sudo_event_count"], 1)
        self.assertEqual(result["ssh_event_count"], 1)


if __name__ == "__main__":
    unittest.main()
