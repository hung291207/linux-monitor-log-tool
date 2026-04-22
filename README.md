# Linux System Monitoring and Log Analysis Tool

A Python-based Linux host monitoring tool that collects system data, reviews processes and network exposure, parses authentication logs, and flags suspicious activity using rule-based security indicators.

## What It Does

The tool performs a single-pass audit of a Linux host and generates a structured JSON report covering:

| Category                      | Data                                                                           |
| ----------------------------- | ------------------------------------------------------------------------------ |
| **System info**         | Hostname, current user, timestamp, uptime, OS/kernel version                   |
| **Resource usage**      | CPU, memory, and disk usage percentages and totals                             |
| **Process monitoring**  | Top 5 processes by CPU and memory consumption                                  |
| **Network visibility**  | Listening TCP/UDP ports with associated process names and PIDs                 |
| **User sessions**       | Currently logged-in users, terminals, and login times                          |
| **Scheduled jobs**      | Cron entries from `/etc/crontab`, `/etc/cron.d/`, user crontabs, and spool |
| **Log events**          | Failed logins, sudo commands, and SSH activity from `/var/log/auth.log`      |
| **Security indicators** | Rule-based flags for suspicious patterns found in the collected data           |

## Security Indicators

The tool analyzes the collected data and flags the following:

| Indicator               | Trigger                                                                   | Severity | Security Relevance                |
| ----------------------- | ------------------------------------------------------------------------- | -------- | --------------------------------- |
| Repeated failed logins  | 5+ failures in 10 minutes                                                 | Medium   | Brute-force / credential stuffing |
| Recent sudo activity    | Any sudo commands in the last 15 minutes                                  | Low      | Privilege escalation awareness    |
| High CPU processes      | Any process exceeding 50% CPU                                             | Medium   | Cryptomining / resource abuse     |
| Unusual listening ports | Externally-bound TCP ports not in common allowlist                        | Medium   | Backdoors / unauthorized services |
| Suspicious cron entries | Entries matching patterns like `curl`, `wget`, `/tmp/`, `bash -c` | Low      | Persistence mechanisms            |

## Requirements

- **OS:** Linux (tested on Ubuntu 24.04 LTS)
- **Python:** 3.10+ (tested on 3.12.3)
- **System tools:** `ss`
- **Log access:** Readable `/var/log/auth.log` — may require `sudo` depending on system permissions

## Setup

```bash
# Clone the repository
git clone https://github.com/hung291207/linux-monitor-log-tool.git
cd linux-monitor-log-tool

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

> **Important:** Always run the tool from the **project root directory** (`linux-monitor-log-tool/`). This ensures reports are saved to the `reports/` folder and all module imports resolve correctly.

```bash
# Basic run (may have limited port/log visibility)
python -m src.main

# Run with sudo for full visibility
sudo venv/bin/python -m src.main
```

### Output

The tool produces two outputs:

1. **Terminal** — JSON summary printed to stdout (log events truncated to last 3 per category for readability)
2. **Saved report** — Full JSON report saved to `reports/system_report_YYYYMMDD_HHMMSS.json` (contains all log events, not truncated)

### Running Tests

```bash
python -m unittest discover -s tests -v
```

## Testing the Indicators

To verify that all 5 security indicators trigger correctly, you can simulate the conditions on a test system.

### 1. Repeated Failed Logins

Attempt 6 failed `su` logins (the threshold is 5 failed logins within 10 minutes):

```bash
for i in $(seq 1 6); do echo "wrong" | su root 2>/dev/null; done
```

### 2. Recent Sudo Activity

Run any sudo command (detected within a 15-minute window), for example:

```bash
sudo whoami
```

### 3. High CPU Process

Start a process that consumes >50% CPU:

```bash
yes > /dev/null &
```

### 4. Unusual Listening Port

Open a TCP socket on a non-standard port bound to all interfaces:

```bash
python3 -c "import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',9099)); s.listen(1); time.sleep(300)" &
```

### 5. Suspicious Cron Entry

Add a cron entry that matches the detection patterns (`curl`, `bash -c`):

```bash
echo '*/5 * * * * curl http://example.com/sample.php | bash -c "echo test"' | crontab -
```

### Run and Verify

```bash
sudo venv/bin/python -m src.main
```

The indicators section of the output should show `"indicator_count": 5`.

### Cleanup

```bash
kill %1 %2          # stop the CPU stress and port listener
crontab -r          # remove the test cron entry
```

## Sample Output (All 5 Indicators)

```json
{
  "indicator_count": 5,
  "indicators": [
    {
      "indicator_type": "repeated_failed_logins",
      "severity": "medium",
      "title": "Repeated failed login attempts",
      "summary": "17 failed authentication events were observed in the last 10 minutes."
    },
    {
      "indicator_type": "recent_sudo_activity",
      "severity": "low",
      "title": "Recent sudo activity",
      "summary": "9 sudo event(s) were observed in the last 15 minutes."
    },
    {
      "indicator_type": "high_cpu_process",
      "severity": "medium",
      "title": "High CPU process usage",
      "summary": "1 process(es) exceeded 50.0% CPU in the current snapshot."
    },
    {
      "indicator_type": "unusual_listening_port",
      "severity": "medium",
      "title": "Unusual externally exposed TCP port",
      "summary": "15 externally bound TCP port(s) were flagged because they are not in the common-port review set."
    },
    {
      "indicator_type": "suspicious_cron_entry",
      "severity": "low",
      "title": "Cron entry flagged for review",
      "summary": "1 cron entry(ies) matched review patterns such as script execution from /tmp or command-download behavior."
    }
  ]
}
```

## Project Structure

```text
linux-monitor-log-tool/
├── README.md
├── requirements.txt
├── .gitignore
├── src/
│   ├── main.py                # entry point — assembles report and runs indicators
│   ├── system_info.py         # hostname, user, uptime, OS, kernel
│   ├── resource_usage.py      # CPU, memory, disk usage
│   ├── process_monitor.py     # top processes by CPU and memory
│   ├── network_monitor.py     # listening ports via ss
│   ├── user_sessions.py       # logged-in users via psutil
│   ├── cron_review.py         # scheduled job review from all cron sources
│   ├── log_parser.py          # auth.log parsing — failed logins, sudo, SSH
│   ├── indicators.py          # rule-based security indicator analysis
│   └── report_writer.py       # JSON report file generation
├── reports/                   # saved JSON reports (gitignored)
├── tests/
│   ├── test_log_parser.py     # 6 tests — line parsing, event extraction, integration
│   └── test_indicators.py     # 5 tests — one per indicator type
└── docs/
```

## Limitations

- Only parses `/var/log/auth.log` — does not cover `journalctl` or other log sources
- Syslog timestamps lack a year field
- Process and port visibility may be limited without `sudo`
- Indicator thresholds are static (not configurable via CLI or config file)
- No real-time monitoring — produces a point-in-time snapshot

## Dependencies

| Package                                    | Version | Purpose                                      |
| ------------------------------------------ | ------- | -------------------------------------------- |
| [psutil](https://github.com/giampaolo/psutil) | 7.2.2   | Cross-platform system and process monitoring |

All other functionality uses Python standard library modules: `json`, `re`, `subprocess`, `socket`, `platform`, `getpass`, `pathlib`, `datetime`.
