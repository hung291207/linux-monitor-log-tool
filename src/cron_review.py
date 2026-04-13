from __future__ import annotations

import getpass
import subprocess
from pathlib import Path


def _parse_cron_lines(content: str, source: str) -> list[dict[str, str]]:
    entries = []

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if "=" in stripped.split()[0]:
            continue

        entries.append(
            {
                "source": source,
                "entry": stripped,
            }
        )

    return entries


def _read_system_crontab() -> list[dict[str, str]]:
    crontab_path = Path("/etc/crontab")

    if not crontab_path.exists():
        return []

    try:
        content = crontab_path.read_text()
    except PermissionError:
        return [
            {
                "source": "/etc/crontab",
                "entry": "[permission denied]"
            }
        ]

    return _parse_cron_lines(content, "/etc/crontab")


def _read_cron_d() -> list[dict[str, str]]:
    cron_d = Path("/etc/cron.d")

    if not cron_d.is_dir():
        return []

    entries = []

    for filepath in sorted(cron_d.iterdir()):
        if filepath.name.startswith("."):
            continue

        try:
            content = filepath.read_text()
        except PermissionError:
            entries.append(
                {
                    "source": str(filepath),
                    "entry": "[permission denied]",
                }
            )
            continue

        entries.extend(_parse_cron_lines(content, str(filepath)))

    return entries


def _read_user_crontab() -> list[dict[str, str]]:
    username = getpass.getuser()

    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    except FileNotFoundError:
        return []

    if result.returncode != 0:
        return []

    return _parse_cron_lines(result.stdout, f"crontab -l ({username})")


def _read_spool_crontabs() -> list[dict[str, str]]:
    spool_dir = Path("/var/spool/cron/crontabs")

    if not spool_dir.is_dir():
        return []

    entries = []

    try:
        for filepath in sorted(spool_dir.iterdir()):
            try:
                content = filepath.read_text()
            except PermissionError:
                entries.append(
                    {
                        "source": f"/var/spool/cron/crontabs/{filepath.name}",
                        "entry": "[permission denied]",
                    }
                )
                continue

            entries.extend(
                _parse_cron_lines(content, f"/var/spool/cron/crontabs/{filepath.name}")
            )
    except PermissionError:
        entries.append(
            {
                "source": "/var/spool/cron/crontabs/",
                "entry": "[permission denied - cannot list directory]",
            }
        )

    return entries


def get_scheduled_jobs() -> dict[str, object]:
    system_crontab = _read_system_crontab()
    cron_d = _read_cron_d()
    user_crontab = _read_user_crontab()
    spool_crontabs = _read_spool_crontabs()

    all_entries = system_crontab + cron_d + user_crontab + spool_crontabs

    return {
        "total_entries": len(all_entries),
        "sources_checked": ["/etc/crontab", "/etc/cron.d/", f"crontab -l ({getpass.getuser()})", "/var/spool/cron/crontabs/"],
        "entries": all_entries,
    }
