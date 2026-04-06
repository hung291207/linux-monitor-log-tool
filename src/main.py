import json

from src.system_info import get_system_info

def main() -> None:
    report = {
        "system_info": get_system_info(),
    }
    
    report_json = json.dumps(report, indent=2)
    print(report_json)
    
if __name__ == "__main__":
    main()