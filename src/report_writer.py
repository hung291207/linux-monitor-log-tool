from __future__ import annotations

from datetime import datetime
from pathlib import Path
import json


REPORTS_DIR = Path("reports")


def _build_report_filename(prefix: str = "report", extension: str = "json") -> str:
    timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{timestamp}.{extension}"


def save_json_report(report: dict[str, object], reports_dir: Path = REPORTS_DIR) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)

    output_path = reports_dir / _build_report_filename(prefix="system_report", extension="json")

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return output_path