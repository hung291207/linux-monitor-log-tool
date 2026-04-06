# Linux System Monitoring and Log Analysis Tool

A Python-based Linux host monitoring tool that collects core system information, reviews processes and network exposure, parses selected authentication-related logs, and generates simple rule-based indicators for defensive review.

## Project Goal

This project is designed to demonstrate:

- Python scripting
- Linux familiarity
- process and filesystem understanding
- basic log analysis
- security-oriented reasoning
- clean technical reporting

## Scope

Version 1 aims to collect:

- hostname, current user, timestamp, uptime, OS/kernel version
- CPU, memory, and disk usage
- running processes and top resource-consuming processes
- listening ports
- logged-in users
- selected log events such as failed login attempts, sudo usage, and SSH-related activity
- simple rule-based indicators flagged for review
- terminal output and saved JSON/text reports

## Limitations

This project is **not**:

- a SIEM
- an EDR
- an enterprise monitoring platform
- a malware analysis or forensics tool

It uses simple local host-based checks and basic log parsing for learning and portfolio purposes.

## Planned Structure

```text
linux-monitor-log-tool/
├── README.md
├── requirements.txt
├── .gitignore
├── docs/
├── src/
├── reports/
└── tests/
```
