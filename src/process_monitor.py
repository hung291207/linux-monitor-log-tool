from __future__ import annotations

import time

import psutil

def _safe_process_snapshot(proc: psutil.Process) -> dict[str, str | int | float] | None:
    try:
        return {
            "pid": proc.pid,
            "name": proc.name(),
            "username": proc.username(),
            "cpu_percent": proc.cpu_percent(0.0),
            "memory_percent": round(proc.memory_percent(), 2),
            "status": proc.status(),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def get_top_processes(top_n: int = 5) -> dict[str, list[dict[str, str | int | float]]]:
    processes = []
    cpu_sample_interval = 1
    
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(0.0)
            processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    time.sleep(cpu_sample_interval)
    
    process_snapshots = []
    for proc in processes:
        snapshot = _safe_process_snapshot(proc)
        if snapshot is not None:
            process_snapshots.append(snapshot)
    
    top_cpu = sorted(process_snapshots, key=lambda p: p["cpu_percent"], reverse=True)[:top_n]
    top_memory = sorted(process_snapshots, key=lambda p: p["memory_percent"], reverse=True)[:top_n]
    
    return {
        "top_cpu_processes": top_cpu,
        "top_memory_processes": top_memory,
    }
