from __future__ import annotations

import re
import subprocess


def _split_address_and_port(local_address: str) -> tuple[str, str]:
    if local_address.startswith("["):
        match = re.match(r"\[([^\]]+)\]:(\d+)", local_address)
        if match:
            return match.group(1), match.group(2)
        return local_address, ""

    if ":" in local_address:
        address, port = local_address.rsplit(":", 1)
        return address, port

    return local_address, ""


def _extract_process_info(process_field: str) -> dict[str, str | int | None]:
    if not process_field:
        return {"pid": None, "process_name": None}

    name_match = re.search(r'"([^"]+)"', process_field)
    pid_match = re.search(r"pid=(\d+)", process_field)
    
    process_name = name_match.group(1) if name_match else None
    pid = int(pid_match.group(1)) if pid_match else None

    return {
        "pid": pid,
        "process_name": process_name,
    }


def get_listening_ports() -> list[dict[str, str | int | None]]:
    command = ["ss", "-tulnp"]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        return [
            {
                "error": f"Failed to run ss command: {e}"
            }
        ]

    lines = result.stdout.strip().splitlines()
    if len(lines) < 2:
        return []
    
    listening_ports = []
    for line in lines[1:]:
        parts = line.split(maxsplit=6)
        if len(parts) < 6:
            continue

        protocol = parts[0]
        state = parts[1]
        local_field = parts[4]
        process_field = parts[6] if len(parts) == 7 else ""
        
        local_address, local_port = _split_address_and_port(local_field)
        process_info = _extract_process_info(process_field)
        
        listening_ports.append({
            "protocol": protocol,
            "state": state,
            "local_address": local_address,
            "local_port": int(local_port) if local_port.isdigit() else None,
            "pid": process_info["pid"],
            "process_name": process_info["process_name"],
        })

    return listening_ports