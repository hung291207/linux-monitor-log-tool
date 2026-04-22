from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import getpass
import socket
import platform
import time

import psutil


def _format_uptime(uptime_seconds: int) -> str:
    days, remainder = divmod(uptime_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    if days > 0:
        return f"{days:02} days, {hours:02}:{minutes:02}:{seconds:02}"
    
    return f"{hours:02}:{minutes:02}:{seconds:02}"


def _get_os_pretty_name() -> str:
    os_release_path = Path("/etc/os-release")

    if os_release_path.exists():
        with os_release_path.open("r") as f:
            for line in f.read().splitlines():
                if line.startswith("PRETTY_NAME="):
                    return line.split("=")[1].strip().strip('"')

    return platform.system()


def get_system_info() -> dict[str, str]:
    current_time = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    boot_time = psutil.boot_time()
    uptime_seconds = max(0, int(time.time() - boot_time))

    system_info = {
        "hostname": socket.gethostname(),
        "current_user": getpass.getuser(),
        "timestamp": current_time,
        "uptime": _format_uptime(uptime_seconds),
        "os": _get_os_pretty_name(),
        "kernel": platform.release(),
    }

    return system_info