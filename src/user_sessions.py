from __future__ import annotations

from datetime import datetime, timezone

import psutil


def _format_login_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).astimezone().isoformat(timespec="seconds")


def get_user_sessions() -> dict[str, object]:
    sessions = []

    for user in psutil.users():
        sessions.append(
            {
                "username": user.name,
                "terminal": user.terminal,
                "host": user.host,
                "login_time": _format_login_time(user.started),
            }
        )
    
    return {
        "session_count": len(sessions),
        "sessions": sessions,
    }