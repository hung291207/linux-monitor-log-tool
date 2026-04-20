from __future__ import annotations

from datetime import datetime, timedelta


FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_MINUTES = 10
RECENT_SUDO_WINDOW_MINUTES = 15
HIGH_CPU_THRESHOLD_PERCENT = 50.0

COMMON_EXTERNAL_TCP_PORTS = {
    20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 631,
    993, 995, 3306, 5432, 8000, 8080, 8443,
}

SUSPICIOUS_CRON_PATTERNS = (
    "curl ",
    "wget ",
    "nc ",
    "netcat ",
    "/tmp/",
    "bash -c",
    "sh -c",
    "python -c",
    "python3 -c",
)


def _as_dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    return {}


def _as_list(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    return []


def _parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _get_recent_events(events: list[object], window_minutes: int) -> list[dict[str, object]]:
    cutoff = datetime.now().astimezone() - timedelta(minutes=window_minutes)
    recent_events: list[dict[str, object]] = []

    for event in events:
        event_dict = _as_dict(event)
        timestamp = _parse_iso_timestamp(str(event_dict.get("timestamp") or ""))
        if timestamp is not None and timestamp >= cutoff:
            recent_events.append(event_dict)

    return recent_events


def _unique_non_empty(values: list[object], limit: int = 5) -> list[str]:
    seen: list[str] = []

    for value in values:
        text = str(value).strip()
        if not text or text == "None":
            continue
        if text not in seen:
            seen.append(text)
        if len(seen) >= limit:
            break

    return seen


def _check_failed_logins(report: dict[str, object]) -> list[dict[str, object]]:
    log_events = _as_dict(report.get("log_events"))
    failed_logins = _as_list(log_events.get("failed_logins"))
    recent_failed = _get_recent_events(failed_logins, FAILED_LOGIN_WINDOW_MINUTES)

    if len(recent_failed) < FAILED_LOGIN_THRESHOLD:
        return []

    usernames_raw = []
    for event in recent_failed:
        usernames_raw.append(event.get("username"))
    usernames = _unique_non_empty(usernames_raw)

    source_ips_raw = []
    for event in recent_failed:
        source_ips_raw.append(event.get("source_ip"))
    source_ips = _unique_non_empty(source_ips_raw)

    return [
        {
            "indicator_type": "repeated_failed_logins",
            "severity": "medium",
            "title": "Repeated failed login attempts",
            "summary": (
                f"{len(recent_failed)} failed authentication events were observed "
                f"in the last {FAILED_LOGIN_WINDOW_MINUTES} minutes."
            ),
            "details": {
                "threshold": FAILED_LOGIN_THRESHOLD,
                "window_minutes": FAILED_LOGIN_WINDOW_MINUTES,
                "recent_event_count": len(recent_failed),
                "sample_usernames": usernames,
                "sample_source_ips": source_ips,
            },
        }
    ]


def _check_recent_sudo(report: dict[str, object]) -> list[dict[str, object]]:
    log_events = _as_dict(report.get("log_events"))
    sudo_events = _as_list(log_events.get("sudo_events"))
    recent_sudo = _get_recent_events(sudo_events, RECENT_SUDO_WINDOW_MINUTES)

    if not recent_sudo:
        return []

    commands_raw = []
    for event in recent_sudo:
        commands_raw.append(event.get("command"))
    commands = _unique_non_empty(commands_raw, limit=3)

    return [
        {
            "indicator_type": "recent_sudo_activity",
            "severity": "low",
            "title": "Recent sudo activity",
            "summary": (
                f"{len(recent_sudo)} sudo event(s) were observed "
                f"in the last {RECENT_SUDO_WINDOW_MINUTES} minutes."
            ),
            "details": {
                "window_minutes": RECENT_SUDO_WINDOW_MINUTES,
                "recent_event_count": len(recent_sudo),
                "sample_commands": commands,
            },
        }
    ]


def _check_high_cpu_processes(report: dict[str, object]) -> list[dict[str, object]]:
    process_monitoring = _as_dict(report.get("top_processes"))
    top_cpu_processes = _as_list(process_monitoring.get("top_cpu_processes"))

    flagged_processes: list[dict[str, object]] = []

    for process in top_cpu_processes:
        process_dict = _as_dict(process)
        cpu_percent = process_dict.get("cpu_percent")

        try:
            cpu_value = float(cpu_percent)
        except (TypeError, ValueError):
            continue

        if cpu_value >= HIGH_CPU_THRESHOLD_PERCENT:
            flagged_processes.append(
                {
                    "pid": process_dict.get("pid"),
                    "name": process_dict.get("name"),
                    "username": process_dict.get("username"),
                    "cpu_percent": cpu_value,
                }
            )

    if not flagged_processes:
        return []

    return [
        {
            "indicator_type": "high_cpu_process",
            "severity": "medium",
            "title": "High CPU process usage",
            "summary": (
                f"{len(flagged_processes)} process(es) exceeded "
                f"{HIGH_CPU_THRESHOLD_PERCENT}% CPU in the current snapshot."
            ),
            "details": {
                "threshold_percent": HIGH_CPU_THRESHOLD_PERCENT,
                "flagged_processes": flagged_processes,
            },
        }
    ]


def _is_external_bind(address: str | None) -> bool:
    if not address:
        return False

    if address.startswith("127."):
        return False

    if address in {"::1", "localhost"}:
        return False

    return True



def _check_unusual_ports(report: dict[str, object]) -> list[dict[str, object]]:
    network_monitoring = _as_dict(report.get("network_monitoring"))
    listening_ports = _as_list(network_monitoring.get("listening_ports"))

    flagged_ports: list[dict[str, object]] = []

    for entry in listening_ports:
        port_entry = _as_dict(entry)

        protocol = str(port_entry.get("protocol") or "")
        local_address = str(port_entry.get("local_address") or "")
        local_port = port_entry.get("local_port")

        if protocol != "tcp":
            continue

        if not _is_external_bind(local_address):
            continue

        try:
            port_number = int(local_port)
        except (TypeError, ValueError):
            continue

        if port_number in COMMON_EXTERNAL_TCP_PORTS:
            continue

        flagged_ports.append(
            {
                "local_address": local_address,
                "local_port": port_number,
                "process_name": port_entry.get("process_name"),
                "pid": port_entry.get("pid"),
            }
        )

    if not flagged_ports:
        return []

    return [
        {
            "indicator_type": "unusual_listening_port",
            "severity": "medium",
            "title": "Unusual externally exposed TCP port",
            "summary": (
                f"{len(flagged_ports)} externally bound TCP port(s) were flagged "
                "because they are not in the common-port review set."
            ),
            "details": {
                "common_port_allowlist": sorted(COMMON_EXTERNAL_TCP_PORTS),
                "flagged_ports": flagged_ports,
            },
        }
    ]


def _check_suspicious_cron_entries(report: dict[str, object]) -> list[dict[str, object]]:
    cron_review = _as_dict(report.get("scheduled_jobs"))
    entries = _as_list(cron_review.get("entries"))

    suspicious_entries: list[dict[str, object]] = []

    for entry in entries:
        entry_dict = _as_dict(entry)
        raw_entry = str(entry_dict.get("entry") or "")
        lowered = raw_entry.lower()

        if raw_entry.startswith("["):
            continue

        matched_patterns = []
        for pattern in SUSPICIOUS_CRON_PATTERNS:
            if pattern in lowered:
                matched_patterns.append(pattern)
        if not matched_patterns:
            continue

        suspicious_entries.append(
            {
                "source": entry_dict.get("source"),
                "entry": raw_entry,
                "matched_patterns": matched_patterns,
            }
        )

    if not suspicious_entries:
        return []

    return [
        {
            "indicator_type": "suspicious_cron_entry",
            "severity": "low",
            "title": "Cron entry flagged for review",
            "summary": (
                f"{len(suspicious_entries)} cron entry(ies) matched review patterns "
                "such as script execution from /tmp or command-download behavior."
            ),
            "details": {
                "matched_patterns_review_set": list(SUSPICIOUS_CRON_PATTERNS),
                "flagged_entries": suspicious_entries[:5],
            },
        }
    ]


def get_indicators(report: dict[str, object]) -> dict[str, object]:
    indicators: list[dict[str, object]] = []

    indicators.extend(_check_failed_logins(report))
    indicators.extend(_check_recent_sudo(report))
    indicators.extend(_check_high_cpu_processes(report))
    indicators.extend(_check_unusual_ports(report))
    indicators.extend(_check_suspicious_cron_entries(report))

    return {
        "indicator_count": len(indicators),
        "indicators": indicators,
    }