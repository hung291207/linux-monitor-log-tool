from __future__ import annotations

from datetime import datetime
from pathlib import Path
import re


AUTH_LOG_PATH = Path("/var/log/auth.log")

LOG_LINE_PATTERN = re.compile(
    r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}T\S+))\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[^\s:\[]+)(?:\[\d+\])?:\s"
    r"(?P<message>.*)$"
)

FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) from (?P<source_ip>\S+)"
)

AUTH_FAILURE_PATTERN = re.compile(
    r"authentication failure;.*?(?:rhost=(?P<source_ip>\S*))?.*?user=(?P<username>\S*)"
)

SUDO_PATTERN = re.compile(
    r"sudo:\s+(?P<username>\S+)\s*:\s.*COMMAND=(?P<command>.+)$"
)

SSH_ACCEPTED_PATTERN = re.compile(
    r"Accepted \S+ for (?P<username>\S+) from (?P<source_ip>\S+)"
)

SSH_INVALID_USER_PATTERN = re.compile(
    r"Invalid user (?P<username>\S+) from (?P<source_ip>\S+)"
)


def _parse_timestamp_to_iso(timestamp: str) -> str | None:
    if "T" in timestamp and "-" in timestamp:
        try:
            return datetime.fromisoformat(timestamp).isoformat(timespec="seconds")
        except ValueError:
            return None

    current_year = datetime.now().year

    try:
        parsed = datetime.strptime(
            f"{current_year} {timestamp}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None

    local_tz = datetime.now().astimezone().tzinfo
    parsed = parsed.replace(tzinfo=local_tz)
    return parsed.isoformat(timespec="seconds")


def _parse_log_line(line: str) -> dict[str, str] | None:
    match = LOG_LINE_PATTERN.match(line)
    if not match:
        return None

    parsed = match.groupdict()
    parsed["timestamp_iso"] = _parse_timestamp_to_iso(parsed["timestamp"]) or ""
    return parsed


def _build_base_event(parsed_line: dict[str, str], event_type: str) -> dict[str, str | None]:
    return {
        "event_type": event_type,
        "timestamp": parsed_line["timestamp_iso"] or None,
        "host": parsed_line["host"],
        "service": parsed_line["service"],
        "raw_message": parsed_line["message"],
    }


def _extract_failed_login_event(parsed_line: dict[str, str]) -> dict[str, str | None] | None:
    message = parsed_line["message"]

    failed_password_match = FAILED_PASSWORD_PATTERN.search(message)
    if failed_password_match:
        event = _build_base_event(parsed_line, "failed_password")
        event["username"] = failed_password_match.group("username")
        event["source_ip"] = failed_password_match.group("source_ip")
        return event

    auth_failure_match = AUTH_FAILURE_PATTERN.search(message)
    if auth_failure_match:
        event = _build_base_event(parsed_line, "authentication_failure")
        event["username"] = auth_failure_match.group("username") or None
        event["source_ip"] = auth_failure_match.group("source_ip") or None
        return event

    return None


def _extract_sudo_event(parsed_line: dict[str, str]) -> dict[str, str | None] | None:
    if parsed_line["service"] != "sudo":
        return None

    message = parsed_line["message"]
    sudo_match = SUDO_PATTERN.search(f"sudo: {message}")

    event = _build_base_event(parsed_line, "sudo_command")
    if sudo_match:
        event["username"] = sudo_match.group("username")
        event["command"] = sudo_match.group("command")
        return event

    return None



def _extract_ssh_event(parsed_line: dict[str, str]) -> dict[str, str | None] | None:
    if parsed_line["service"] != "sshd":
        return None

    message = parsed_line["message"]

    accepted_match = SSH_ACCEPTED_PATTERN.search(message)
    if accepted_match:
        event = _build_base_event(parsed_line, "ssh_login")
        event["username"] = accepted_match.group("username")
        event["source_ip"] = accepted_match.group("source_ip")
        return event

    invalid_user_match = SSH_INVALID_USER_PATTERN.search(message)
    if invalid_user_match:
        event = _build_base_event(parsed_line, "ssh_invalid_user")
        event["username"] = invalid_user_match.group("username")
        event["source_ip"] = invalid_user_match.group("source_ip")
        return event

    event = _build_base_event(parsed_line, "ssh_activity")
    event["username"] = None
    event["source_ip"] = None
    return event


def parse_auth_log(log_path: Path = AUTH_LOG_PATH) -> dict[str, object]:
    if not log_path.exists():
        return {
            "source": str(log_path),
            "error": "Log file not found",
            "failed_logins": [],
            "sudo_events": [],
            "ssh_events": [],
        }

    try:
        content = log_path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return {
            "source": str(log_path),
            "error": "Permission denied",
            "failed_logins": [],
            "sudo_events": [],
            "ssh_events": [],
        }

    failed_logins: list[dict[str, str | None]] = []
    sudo_events: list[dict[str, str | None]] = []
    ssh_events: list[dict[str, str | None]] = []

    for line in content.splitlines():
        parsed_line = _parse_log_line(line)
        if not parsed_line:
            continue

        failed_event = _extract_failed_login_event(parsed_line)
        if failed_event:
            failed_logins.append(failed_event)

        sudo_event = _extract_sudo_event(parsed_line)
        if sudo_event:
            sudo_events.append(sudo_event)

        failed_ssh_event = failed_event is not None and parsed_line["service"] == "sshd"
        if not failed_ssh_event:
            ssh_event = _extract_ssh_event(parsed_line)
            if ssh_event:
                ssh_events.append(ssh_event)

    return {
        "source": str(log_path),
        "failed_login_count": len(failed_logins),
        "sudo_event_count": len(sudo_events),
        "ssh_event_count": len(ssh_events),
        "failed_logins": failed_logins,
        "sudo_events": sudo_events,
        "ssh_events": ssh_events,
    }