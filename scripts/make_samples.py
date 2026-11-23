"""Generate the synthetic sample logs in samples/.

All IPs are from documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
or private ranges (10.0.0.0/8). No real hosts or people.

Run: python scripts/make_samples.py
"""
import json
import os
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def linux():
    t0 = datetime(2026, 11, 23, 8, 58, 10)
    lines = []
    pid = [800]

    def add(dt, msg, proc="sshd"):
        pid[0] += 1
        lines.append(f"{dt:%b %d %H:%M:%S} web01 {proc}[{pid[0]}]: {msg}")

    add(t0, "Accepted publickey for alice from 192.0.2.10 port 50122 ssh2: ED25519 SHA256:q1w2e3r4t5y6u7i8o9p0")
    add(t0 + timedelta(seconds=1), "pam_unix(sshd:session): session opened for user alice(uid=1001) by (uid=0)")
    add(t0 + timedelta(seconds=30), "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", "CRON")
    # 1) Brute force: 8 password guesses for root from 203.0.113.45 in under 2 minutes
    t = datetime(2026, 11, 23, 9, 0, 1)
    for i in range(8):
        dt = t + timedelta(seconds=13 * i)
        add(dt, "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.45  user=root")
        add(dt, f"Failed password for root from 203.0.113.45 port {41200 + i} ssh2")
    add(t + timedelta(seconds=110), "Connection closed by authenticating user root 203.0.113.45 port 41207 [preauth]")
    # 2) Password spraying from 198.51.100.23, then 3) a successful login for 'deploy'
    t = datetime(2026, 11, 23, 9, 3, 0)
    for i, (user, invalid) in enumerate([("admin", True), ("oracle", True), ("ubuntu", False),
                                         ("test", True), ("postgres", False), ("deploy", False)]):
        dt = t + timedelta(seconds=30 * i)
        if invalid:
            add(dt, f"Invalid user {user} from 198.51.100.23 port {52000 + i}")
        add(dt, f"Failed password for {'invalid user ' if invalid else ''}{user} from 198.51.100.23 port {52000 + i} ssh2")
    add(datetime(2026, 11, 23, 9, 6, 10), "Accepted password for deploy from 198.51.100.23 port 52011 ssh2")
    add(datetime(2026, 11, 23, 9, 6, 11), "pam_unix(sshd:session): session opened for user deploy(uid=1003) by (uid=0)")
    # Normal: one typo then a good login (must NOT alert)
    add(datetime(2026, 11, 23, 9, 10, 0), "Failed password for bob from 192.0.2.10 port 50300 ssh2")
    add(datetime(2026, 11, 23, 9, 10, 20), "Accepted password for bob from 192.0.2.10 port 50301 ssh2")
    # Slow guessing below the threshold window (must NOT alert)
    for i in range(3):
        add(datetime(2026, 11, 23, 9, 20, 0) + timedelta(minutes=8 * i),
            f"Failed password for root from 203.0.113.99 port {60000 + i} ssh2")
    add(datetime(2026, 11, 23, 9, 45, 0), "Received disconnect from 192.0.2.10 port 50122:11: disconnected by user")
    return "\n".join(lines) + "\n"


def windows():
    recs = []

    def ev(dt, eid, user, ip="-", logon=None, ws="-", caller=None, host="DC01.corp.example"):
        r = {"TimeCreated": dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}0Z", "Id": eid,
             "MachineName": host, "TargetUserName": user, "TargetDomainName": "CORP"}
        if eid in (4624, 4625):
            r.update(IpAddress=ip, LogonType=logon, WorkstationName=ws)
        if eid == 4740:
            r["CallerComputerName"] = caller
        recs.append(r)

    base = datetime(2026, 11, 23, 10, 0, 0)
    ev(base, 4624, "jdoe", "10.0.0.15", 3, "WS-031")
    ev(base + timedelta(minutes=1), 4624, "priya", "10.0.0.21", 2, "WS-044")
    # RDP brute force against Administrator from 203.0.113.77, then a successful logon
    for i in range(7):
        ev(base + timedelta(minutes=2, seconds=20 * i, microseconds=511234), 4625, "Administrator", "203.0.113.77", 10, "KALI")
    ev(base + timedelta(minutes=4, seconds=50), 4624, "Administrator", "203.0.113.77", 10, "KALI")
    # Internal password spray from 10.0.0.52 (WS-114): 4 accounts x 3 tries, 3 of them lock out
    t = base + timedelta(minutes=20)
    for i, user in enumerate(["jsmith", "akumar", "svc_backup", "mlopez"]):
        for j in range(3):
            ev(t + timedelta(minutes=2 * i, seconds=15 * j), 4625, user, "10.0.0.52", 3, "WS-114")
        if user != "mlopez":
            ev(t + timedelta(minutes=2 * i, seconds=31), 4740, user, caller="WS-114")
    # Normal noise
    ev(base + timedelta(minutes=40), 4625, "priya", "10.0.0.21", 2, "WS-044")
    ev(base + timedelta(minutes=40, seconds=12), 4624, "priya", "10.0.0.21", 2, "WS-044")
    recs.append({"TimeCreated": "2026-11-23T10:41:00.0000000Z", "Id": 4672, "MachineName": "DC01.corp.example",
                 "SubjectUserName": "priya"})
    return json.dumps(recs, indent=1) + "\n"


if __name__ == "__main__":
    os.makedirs(os.path.join(ROOT, "samples"), exist_ok=True)
    with open(os.path.join(ROOT, "samples", "linux_auth.log"), "w") as fh:
        fh.write(linux())
    with open(os.path.join(ROOT, "samples", "windows_security.json"), "w") as fh:
        fh.write(windows())
    print("wrote samples/linux_auth.log and samples/windows_security.json")
