# Python Security Log Analyzer (SOC Mini Project)

A lightweight security log analyzer that parses Linux SSH logs and simple Windows Security event logs, then detects suspicious activity such as brute-force login attempts using a time-window + threshold heuristic.

## Skills Demonstrated
- Threat detection (brute-force heuristic)
- Security monitoring mindset
- Log parsing and analysis
- Python automation & reporting
- Documentation (SOC-style output)

## Features
- Parse:
  - Linux `auth.log` SSH lines (Failed/Accepted)
  - Windows mock events (4625 failed logon, 4624 success)
- Detect:
  - Brute-force attempts (N failed logins within X minutes from same IP)
- Report:
  - JSON report (machine readable)
  - Markdown report (human readable)

## How to Run
### 1) Linux sample
```bash
python src/log_analyzer.py -i sample_logs/auth.log --window-min 5 --fail-threshold 5
