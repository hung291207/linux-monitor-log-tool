from __future__ import annotations

import psutil


def _bytes_to_gb(num_bytes: int) -> float:
    return round(num_bytes / (1024 ** 3), 2)


def get_resource_usage() -> dict[str, dict[str, float | int]]:
    cpu_percent = psutil.cpu_percent(interval=1)
    virtual_mem = psutil.virtual_memory()
    disk_usage = psutil.disk_usage('/')
    return {
        "cpu": {
            "usage_percent": cpu_percent,
        },
        "memory": {
            "total_gb": _bytes_to_gb(virtual_mem.total),
            "used_gb": _bytes_to_gb(virtual_mem.used),
            "available_gb": _bytes_to_gb(virtual_mem.available),
            "free_gb": _bytes_to_gb(virtual_mem.free),
            "usage_percent": virtual_mem.percent,
        },
        "disk": {
            "mount_point": "/",
            "total_gb": _bytes_to_gb(disk_usage.total),
            "used_gb": _bytes_to_gb(disk_usage.used),
            "free_gb": _bytes_to_gb(disk_usage.free),
            "usage_percent": disk_usage.percent,
        }
    }