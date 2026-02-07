#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
from collections import defaultdict, Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple

LINUX_FAIL_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Failed password.* from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
LINUX_SUCCESS_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

WIN_EVENT_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*EventID=(?P<eid>\d+).*IpAddress=(?P<ip>\d+\.\d+\.\d+\.\d+)"
)
WIN_USER_RE = re.compile(r"AccountName=(?P<user>[\w\-\.\$]+)")

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

@dataclass
class Event:
    timestamp: datetime
    ip: str
    event_type: str  # "fail" or "success" or "other"
    username: Optional[str] = None
    raw: str = ""

def parse_line(line: str, default_year: int) -> Optional[Event]:
    line = line.strip()
    if not line:
        return None

    m = LINUX_FAIL_RE.match(line)
    if m:
        month = MONTHS.get(m.group("month"), 1)
        day = int(m.group("day"))
        t = m.group("time")
        ts = datetime(default_year, month, day, int(t[0:2]), int(t[3:5]), int(t[6:8]))
        return Event(timestamp=ts, ip=m.group("ip"), event_type="fail", raw=line)

    m = LINUX_SUCCESS_RE.match(line)
    if m:
        month = MONTHS.get(m.group("month"), 1)
        day = int(m.group("day"))
        t = m.group("time")
        ts = datetime(default_year, month, day, int(t[0:2]), int(t[3:5]), int(t[6:8]))
        return Event(timestamp=ts, ip=m.group("ip"), event_type="success", username=m.group("user"), raw=line)

    m = WIN_EVENT_RE.match(line)
    if m:
        ts = datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S")
        eid = m.group("eid")
        ip = m.group("ip")
        user_m = WIN_USER_RE.search(line)
        user = user_m.group("user") if user_m else None
        if eid == "4625":
            return Event(timestamp=ts, ip=ip, event_type="fail", username=user, raw=line)
        if eid == "4624":
            return Event(timestamp=ts, ip=ip, event_type="success", username=user, raw=line)
        return Event(timestamp=ts, ip=ip, event_type="other", username=user, raw=line)

    return None

def load_events(path: str, default_year: int) -> List[Event]:
    events: List[Event] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ev = parse_line(line, default_year=default_year)
            if ev:
                events.append(ev)
    events.sort(key=lambda e: e.timestamp)
    return events

def detect_bruteforce(events: List[Event], window_minutes: int, fail_threshold: int) -> List[Dict]:
    window = timedelta(minutes=window_minutes)
    fails_by_ip: Dict[str, List[datetime]] = defaultdict(list)

    for e in events:
        if e.event_type == "fail":
            fails_by_ip[e.ip].append(e.timestamp)

    alerts = []
    for ip, times in fails_by_ip.items():
        start = 0
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            count = end - start + 1
            if count >= fail_threshold:
                alerts.append({
                    "type": "bruteforce_suspected",
                    "ip": ip,
                    "failures_in_window": count,
                    "window_minutes": window_minutes,
                    "first_seen": times[start].isoformat(sep=" "),
                    "last_seen": times[end].isoformat(sep=" "),
                })
                break
    return alerts

def top_talkers(events: List[Event], n: int = 5) -> List[Tuple[str, int]]:
    counts = Counter([e.ip for e in events if e.event_type in ("fail", "success")])
    return counts.most_common(n)

def summarize(events: List[Event]) -> Dict:
    total = len(events)
    fails = sum(1 for e in events if e.event_type == "fail")
    success = sum(1 for e in events if e.event_type == "success")
    users = Counter([e.username for e in events if e.username])
    return {
        "total_events_parsed": total,
        "failed_logins": fails,
        "successful_logins": success,
        "top_usernames_seen": users.most_common(5),
    }

def write_report_json(report: Dict, out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

def write_report_md(report: Dict, out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    lines = []
    lines.append("# Security Log Analysis Report\n\n")
    s = report["summary"]
    lines.append("## Summary\n")
    lines.append(f"- Total events parsed: **{s['total_events_parsed']}**\n")
    lines.append(f"- Failed logins: **{s['failed_logins']}**\n")
    lines.append(f"- Successful logins: **{s['successful_logins']}**\n\n")

    lines.append("## Top Talkers (IPs)\n")
    for ip, c in report["top_talkers"]:
        lines.append(f"- `{ip}` — {c} events\n")

    lines.append("\n## Alerts\n")
    if not report["alerts"]:
        lines.append("- No alerts triggered.\n")
    else:
        for a in report["alerts"]:
            lines.append(f"### {a['type']}\n")
            lines.append(f"- IP: `{a['ip']}`\n")
            lines.append(f"- Failures in {a['window_minutes']} min: **{a['failures_in_window']}**\n")
            lines.append(f"- First seen: {a['first_seen']}\n")
            lines.append(f"- Last seen: {a['last_seen']}\n\n")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("".join(lines))

def main() -> int:
    p = argparse.ArgumentParser(description="Python Security Log Analyzer")
    p.add_argument("--input", "-i", required=True, help="Path to a log file")
    p.add_argument("--outdir", "-o", default="output", help="Output directory (default: output)")
    p.add_argument("--year", type=int, default=datetime.now().year, help="Default year for Linux logs")
    p.add_argument("--window-min", type=int, default=5, help="Brute-force window in minutes")
    p.add_argument("--fail-threshold", type=int, default=5, help="Failed login threshold within window")
    p.add_argument("--top", type=int, default=5, help="Top N IPs to show")
    args = p.parse_args()

    events = load_events(args.input, default_year=args.year)

    report = {
        "input_file": args.input,
        "generated_at": datetime.now().isoformat(sep=" "),
        "summary": summarize(events),
        "top_talkers": top_talkers(events, n=args.top),
        "alerts": detect_bruteforce(events, window_minutes=args.window_min, fail_threshold=args.fail_threshold),
    }

    base = os.path.splitext(os.path.basename(args.input))[0]
    json_path = os.path.join(args.outdir, f"{base}_report.json")
    md_path = os.path.join(args.outdir, f"{base}_report.md")

    write_report_json(report, json_path)
    write_report_md(report, md_path)

    print(f"[+] Parsed {report['summary']['total_events_parsed']} events")
    print(f"[+] Wrote: {json_path}")
    print(f"[+] Wrote: {md_path}")

    if report["alerts"]:
        print("\n[!] Alerts:")
        for a in report["alerts"]:
            print(f"  - {a['type']} from {a['ip']} ({a['failures_in_window']} fails/{a['window_minutes']}min)")
    else:
        print("\n[+] No alerts triggered.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
