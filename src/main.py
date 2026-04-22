from __future__ import annotations

import json

from src.system_info import get_system_info
from src.process_monitor import get_top_processes
from src.resource_usage import get_resource_usage
from src.network_monitor import get_listening_ports
from src.user_sessions import get_user_sessions
from src.cron_review import get_scheduled_jobs
from src.log_parser import parse_auth_log
from src.indicators import get_indicators
from src.report_writer import save_json_report


def main() -> None:
    report = {
        "system_info": get_system_info(),
        "resource_usage": get_resource_usage(),
        "top_processes": get_top_processes(),
        "network_monitoring": {
            "listening_ports": get_listening_ports(),
        },
        "user_sessions": get_user_sessions(),
        "scheduled_jobs": get_scheduled_jobs(),
        "log_events": parse_auth_log(),
    }
    
    indicators = get_indicators(report)
    report["indicators"] = indicators
    report_path = save_json_report(report)

    max_display = 3
    log_events = report.get("log_events", {})
    for key in ("failed_logins", "sudo_events", "ssh_events"):
        if key in log_events:
            log_events[key] = log_events[key][-max_display:]

    report_json = json.dumps(report, indent=2)
    print(report_json)
    print(f"Report saved to {report_path}")

if __name__ == "__main__":
    main()