# Python Security Log Analyzer (SOC Mini Project)

A lightweight Python tool that parses authentication logs and flags suspicious behavior (e.g., brute-force attempts) using a time-window + threshold heuristic.  
Designed as a portfolio project for SOC / security analyst roles.

## Skills Demonstrated
- Threat detection (brute-force heuristic)
- Security monitoring mindset
- Log parsing & analysis
- Python automation + report generation
- Clear documentation (SOC-style reporting)

## Supported Log Formats
- **Linux SSH auth logs** (Failed/Accepted password patterns)
- **Windows Security (mock)** events:
  - `4625` failed logon
  - `4624` successful logon

## How It Works
- Groups failed authentication attempts by IP
- Uses a sliding time window (e.g., 5 minutes)
- Triggers an alert when failures exceed a threshold (e.g., 5 failures)

## Run (Examples)

### Linux sample
```bash
python src/log_analyzer.py -i sample_logs/auth.log --window-min 5 --fail-threshold 5
