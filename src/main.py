import json

from src.system_info import get_system_info
from src.process_monitor import get_top_processes
from src.resource_usage import get_resource_usage
from src.network_monitor import get_listening_ports

def main() -> None:
    report = {
        "system_info": get_system_info(),
        "resource_usage": get_resource_usage(),
        "top_processes": get_top_processes(),
        "listening_ports": get_listening_ports(),
    }
    
    report_json = json.dumps(report, indent=2)
    print(report_json)
    
if __name__ == "__main__":
    main()