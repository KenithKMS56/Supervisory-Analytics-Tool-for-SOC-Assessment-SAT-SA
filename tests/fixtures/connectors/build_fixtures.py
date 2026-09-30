"""Builds the sample product exports under tests/fixtures/connectors/ (deterministic).

    python tests/fixtures/connectors/build_fixtures.py

These are hand-built samples, not captures from live systems: the column and field names
follow each product's export/API schema (Splunk ES notable + incident_review, ServiceNow
sn_si_incident + sys_audit, TheHive 5 listAlert + listCase), the values are invented. Each
sample carries a few deliberate patterns so that an end-to-end run has something to find:

  splunk      one analyst bulk-closes 36 notables in half an hour with the same short comment
  servicenow  four incidents left open for weeks; three critical ones closed without Contain
  thehive     one analyst closes 34 alerts within an hour; four cases left open for weeks
"""

import csv
import hashlib
import json
import random
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
IST = timezone(timedelta(hours=5, minutes=30))


def _write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


# ------------------------------------------------------------------ Splunk ES

SPLUNK_RULES = [
    ("Access - Brute Force Access Behavior Detected - Rule", "access", "high"),
    ("Access - Excessive Failed Logins - Rule", "access", "medium"),
    ("Endpoint - Host With Multiple Infections - Rule", "endpoint", "high"),
    ("Endpoint - Anomalous New Service - Rule", "endpoint", "medium"),
    ("Network - Unusual Volume of Network Activity - Rule", "network", "low"),
    ("Threat - Threat Activity Detected - Rule", "threat", "critical"),
]
SPLUNK_HOSTS = [f"PLC-GW-{i:02d}" for i in range(1, 7)] + [f"SCADA-HMI-{i:02d}" for i in range(1, 5)]
SPLUNK_ANALYSTS = ["asharma", "kpatel", "rverma"]
SPLUNK_DISPOSITIONS = [
    ("disposition:1", "True Positive - Suspicious Activity"),
    ("disposition:2", "Benign Positive - Suspicious But Expected"),
    ("disposition:3", "False Positive - Incorrect Analytic Logic"),
    ("disposition:4", "False Positive - Inaccurate Data"),
]
SPLUNK_COMMENTS = [
    "Reviewed authentication logs for {host}; source is the jump server, activity matches change window.",
    "Correlated with EDR telemetry on {host}, confirmed malicious binary and isolated the endpoint.",
    "Checked firewall sessions for {host}, traffic belongs to the scheduled historian backup job.",
    "Validated with the plant operations team, account lockouts on {host} caused by an expired service password.",
    "Searched threat intel for the indicator seen on {host}, no matches; detection logic needs tuning.",
]
URGENCY = {("low", 0): "low", ("medium", 0): "medium", ("high", 0): "high", ("critical", 0): "critical",
           ("low", 1): "medium", ("medium", 1): "high", ("high", 1): "critical", ("critical", 1): "critical"}


def _splunk_time(dt: datetime) -> str:
    return dt.astimezone(IST).strftime("%Y-%m-%dT%H:%M:%S.000%z")


def build_splunk(out: Path) -> None:
    rng = random.Random(2601)
    notables, reviews = [], []

    def add(created: datetime, *, status: str, owner: str, closed: datetime | None, comment: str,
            disposition: tuple[str, str] | None, investigated: bool, rule=None, host=None) -> None:
        n = len(notables) + 1
        guid = hashlib.md5(f"notable-{n}".encode()).hexdigest().upper()
        event_id = f"{guid[:8]}-{guid[8:12]}-{guid[12:16]}-{guid[16:20]}-{guid[20:]}@@notable@@{guid[:32].lower()}"
        rule_name, domain, severity = rule or rng.choice(SPLUNK_RULES)
        host = host or rng.choice(SPLUNK_HOSTS)
        label = {"1": "New", "2": "In Progress", "5": "Closed"}[status]
        group = {"1": "New", "2": "Open", "5": "Closed"}[status]
        last_review = closed or (created + timedelta(minutes=40) if status == "2" else None)
        notables.append({
            "_time": _splunk_time(created),
            "event_id": event_id,
            "rule_name": rule_name,
            "security_domain": domain,
            "severity": severity,
            "urgency": URGENCY[(severity, 1 if host.startswith("SCADA") else 0)],
            "status": status,
            "status_label": label,
            "status_group": group,
            "owner": owner,
            "dest": host,
            "src": f"10.20.{rng.randint(1, 40)}.{rng.randint(2, 250)}",
            "user": rng.choice(["svc_historian", "op_shift1", "eng_maint", "unknown"]),
            "review_time": f"{last_review.timestamp():.3f}" if last_review else "",
            "reviewer": owner if last_review else "",
            "comment": comment.format(host=host) if last_review else "",
            "disposition": disposition[0] if disposition else "",
            "disposition_label": disposition[1] if disposition else "",
        })
        if status in ("2", "5") and investigated:
            reviews.append({"time": f"{(created + timedelta(minutes=40)).timestamp():.3f}", "rule_id": event_id,
                            "rule_name": rule_name, "status": "2", "owner": owner, "urgency": notables[-1]["urgency"],
                            "comment": "Picking this up.", "user": owner, "disposition": ""})
        if status == "5" and closed:
            reviews.append({"time": f"{closed.timestamp():.3f}", "rule_id": event_id, "rule_name": rule_name,
                            "status": "5", "owner": owner, "urgency": notables[-1]["urgency"],
                            "comment": comment.format(host=host), "user": owner,
                            "disposition": disposition[0] if disposition else ""})

    # Ordinary work: about four notables a week over six months, investigated and closed in hours.
    day = datetime(2026, 1, 5, tzinfo=IST)
    while day < datetime(2026, 6, 27, tzinfo=IST):
        for _ in range(rng.choice([0, 1, 1, 1, 2])):
            created = day + timedelta(hours=rng.randint(0, 23), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
            roll = rng.random()
            if roll < 0.08:
                add(created, status="1", owner="unassigned", closed=None, comment="", disposition=None, investigated=False)
            elif roll < 0.14:
                add(created, status="2", owner=rng.choice(SPLUNK_ANALYSTS), closed=None, comment="Picking this up.",
                    disposition=None, investigated=True)
            elif roll < 0.22:
                add(created, status="5", owner="soar_automation", closed=created + timedelta(minutes=2),
                    comment="Auto-closed by playbook: known scanner source.", disposition=SPLUNK_DISPOSITIONS[1],
                    investigated=False)
            else:
                add(created, status="5", owner=rng.choice(SPLUNK_ANALYSTS),
                    closed=created + timedelta(hours=rng.randint(1, 9), minutes=rng.randint(0, 59)),
                    comment=rng.choice(SPLUNK_COMMENTS), disposition=rng.choice(SPLUNK_DISPOSITIONS), investigated=True)
        day += timedelta(days=1)

    # The pattern: 36 low-urgency notables from 10-13 March, all closed by one analyst between
    # 02:31 and 02:58 IST on 14 March with the same short comment and no investigation step.
    for i in range(36):
        created = datetime(2026, 3, 10, 6, 0, tzinfo=IST) + timedelta(hours=2 * i, minutes=7 * (i % 5))
        closed = datetime(2026, 3, 14, 2, 31, 5, tzinfo=IST) + timedelta(seconds=45 * i)
        add(created, status="5", owner="rverma", closed=closed, comment="Closed - no action",
            disposition=SPLUNK_DISPOSITIONS[3], investigated=False, rule=SPLUNK_RULES[4], host=SPLUNK_HOSTS[i % 6])

    notables.sort(key=lambda r: r["_time"])
    reviews.sort(key=lambda r: float(r["time"]))
    _write_csv(out / "notable_events.csv", list(notables[0]), notables)
    _write_csv(out / "incident_review.csv", list(reviews[0]), reviews)


# ------------------------------------------------------------------ ServiceNow SIR

SN_STATE = {"Draft": "10", "Analysis": "16", "Contain": "18", "Eradicate": "19", "Recover": "20", "Review": "100", "Closed": "3"}
SN_PEOPLE = ["Priya Sharma", "Arjun Mehta", "Neha Iyer"]


def _sn_time(dt: datetime) -> str:
    return dt.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")


def build_servicenow(out: Path) -> None:
    rng = random.Random(2602)
    incidents, audit = [], []

    def add(opened: datetime, priority: str, path: list[str], closed_after_days: int | None) -> None:
        n = len(incidents) + 1
        number = f"SIR{10000 + n:07d}"
        sys_id = hashlib.md5(number.encode()).hexdigest()
        owner = rng.choice(SN_PEOPLE)
        closed = opened + timedelta(days=closed_after_days, hours=rng.randint(1, 6)) if closed_after_days is not None else None
        incidents.append({
            "number": number,
            "sys_id": sys_id,
            "short_description": rng.choice([
                "Suspicious outbound connection from engineering workstation",
                "Malware detected on historian server",
                "Repeated authentication failures on remote access gateway",
                "Unauthorised configuration change on substation RTU",
            ]),
            "priority": priority,
            "state": path[-1],
            "assigned_to": owner,
            "assignment_group": "SOC Tier 2",
            "opened_at": _sn_time(opened),
            "sys_created_on": _sn_time(opened),
            "closed_at": _sn_time(closed) if closed else "",
            "close_code": "Solved (Permanently)" if closed else "",
            "close_notes": f"Contact {owner.split()[0].lower()}@cse-power.example for the RCA document." if closed else "",
            "cmdb_ci": rng.choice(["HIST-SRV-01", "RTU-SUB-07", "VPN-GW-02", "ENG-WS-14"]),
            "category": "Malicious code activity",
        })
        span = (closed or opened + timedelta(days=2)) - opened
        previous = "Draft"
        for step, state in enumerate(path[1:], start=1):
            audit.append({
                "documentkey": sys_id, "tablename": "sn_si_incident", "fieldname": "state",
                "oldvalue": SN_STATE[previous], "newvalue": SN_STATE[state],
                "sys_created_on": _sn_time(opened + span * step / len(path)), "user": owner.lower().replace(" ", "."),
                "reason": "",
            })
            previous = state
        # Unrelated audit rows that the mapping must ignore.
        audit.append({"documentkey": sys_id, "tablename": "sn_si_incident", "fieldname": "assigned_to",
                      "oldvalue": "", "newvalue": owner, "sys_created_on": _sn_time(opened + timedelta(minutes=5)),
                      "user": "system", "reason": ""})

    full = ["Draft", "Analysis", "Contain", "Eradicate", "Recover", "Review", "Closed"]
    no_contain = ["Draft", "Analysis", "Review", "Closed"]
    add(datetime(2026, 1, 12, 9, 30, tzinfo=IST), "1 - Critical", full, 3)
    add(datetime(2026, 1, 27, 14, 5, tzinfo=IST), "2 - High", full, 5)
    add(datetime(2026, 2, 9, 11, 45, tzinfo=IST), "1 - Critical", no_contain, 1)
    add(datetime(2026, 2, 20, 16, 20, tzinfo=IST), "3 - Moderate", full, 6)
    add(datetime(2026, 3, 6, 8, 10, tzinfo=IST), "1 - Critical", no_contain, 1)
    add(datetime(2026, 3, 19, 10, 0, tzinfo=IST), "2 - High", full, 4)
    add(datetime(2026, 4, 2, 13, 40, tzinfo=IST), "1 - Critical", no_contain, 2)
    add(datetime(2026, 4, 14, 9, 15, tzinfo=IST), "2 - High", ["Draft", "Analysis"], None)
    add(datetime(2026, 4, 28, 17, 50, tzinfo=IST), "2 - High", ["Draft", "Analysis"], None)
    add(datetime(2026, 5, 11, 12, 25, tzinfo=IST), "3 - Moderate", ["Draft", "Analysis", "Contain"], None)
    add(datetime(2026, 5, 22, 15, 5, tzinfo=IST), "2 - High", ["Draft"], None)
    add(datetime(2026, 6, 3, 10, 30, tzinfo=IST), "3 - Moderate", full, 7)
    add(datetime(2026, 6, 16, 11, 0, tzinfo=IST), "2 - High", full, 6)
    add(datetime(2026, 6, 24, 9, 45, tzinfo=IST), "4 - Low", ["Draft", "Analysis"], None)
    # A change on another table, exported in the same sys_audit list.
    audit.append({"documentkey": hashlib.md5(b"INC0042").hexdigest(), "tablename": "incident", "fieldname": "state",
                  "oldvalue": "1", "newvalue": "2", "sys_created_on": "2026-03-01 10:00:00", "user": "itil.user", "reason": ""})

    audit.sort(key=lambda r: r["sys_created_on"])
    _write_csv(out / "sn_si_incident.csv", list(incidents[0]), incidents)
    _write_csv(out / "sys_audit.csv", list(audit[0]), audit)


# ------------------------------------------------------------------ TheHive 5

HIVE_TITLES = [
    ("Wazuh: Multiple authentication failures", "siem", 2),
    ("Wazuh: Rootkit detection on host", "siem", 3),
    ("Suricata: ET MALWARE CnC beacon", "ids", 4),
    ("Suricata: Modbus write from unauthorised source", "ids", 3),
    ("MISP: Indicator match on proxy logs", "misp", 2),
]
HIVE_ANALYSTS = ["l.dsouza@cse-water.example", "m.khan@cse-water.example", "s.rao@cse-water.example"]


def _ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def build_thehive(out: Path) -> None:
    rng = random.Random(2603)
    alerts, cases = [], []

    def case(start: datetime, severity: int, closed_after_days: int | None, status: str) -> str:
        n = len(cases) + 1
        cid = f"~{40960 + 4096 * n}"
        end = start + timedelta(days=closed_after_days, hours=3) if closed_after_days is not None else None
        cases.append({
            "_id": cid, "_type": "Case", "_createdBy": rng.choice(HIVE_ANALYSTS), "_createdAt": _ms(start),
            "_updatedAt": _ms(end or start + timedelta(hours=2)), "number": n,
            "title": f"Investigation #{n}", "description": "Imported from alert.", "severity": severity,
            "severityLabel": ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][severity], "startDate": _ms(start),
            "endDate": _ms(end) if end else None, "tags": ["ics"], "flag": False, "tlp": 2, "pap": 2,
            "status": status, "stage": "Closed" if end else "InProgress",
            "summary": "Contained and remediated." if end else None, "assignee": rng.choice(HIVE_ANALYSTS),
        })
        return cid

    def alert(created: datetime, *, stage: str, status: str, assignee: str | None, closed: datetime | None,
              in_progress: datetime | None, case_id: str | None = None, title=None) -> None:
        n = len(alerts) + 1
        name, kind, severity = title or rng.choice(HIVE_TITLES)
        alerts.append({
            "_id": f"~{8192 + 4096 * n}", "_type": "Alert", "_createdBy": "wazuh-feeder@cse-water.example",
            "_createdAt": _ms(created + timedelta(seconds=20)), "_updatedAt": _ms(closed or in_progress or created),
            "type": kind, "source": name.split(":")[0].lower(), "sourceRef": f"{kind}-{n:06d}", "title": name,
            "description": "Generated by the detection pipeline.", "severity": severity,
            "severityLabel": ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"][severity], "date": _ms(created),
            "tags": ["ics", kind], "tlp": 2, "pap": 2, "follow": True, "observableCount": rng.randint(1, 4),
            "status": status, "stage": stage, "assignee": assignee, "caseId": case_id,
            "inProgressDate": _ms(in_progress) if in_progress else None,
            "closedDate": _ms(closed) if closed and stage == "Closed" else None,
            "importedDate": _ms(closed) if closed and stage == "Imported" else None,
        })

    # Cases: four closed, four left open since April/May.
    case_ids = [
        case(datetime(2026, 1, 20, 10, tzinfo=UTC), 3, 4, "TruePositive"),
        case(datetime(2026, 2, 11, 9, tzinfo=UTC), 2, 2, "FalsePositive"),
        case(datetime(2026, 3, 3, 14, tzinfo=UTC), 4, 6, "TruePositive"),
        case(datetime(2026, 3, 25, 8, tzinfo=UTC), 2, 3, "Indeterminate"),
        case(datetime(2026, 4, 9, 11, tzinfo=UTC), 3, None, "InProgress"),
        case(datetime(2026, 4, 27, 16, tzinfo=UTC), 3, None, "InProgress"),
        case(datetime(2026, 5, 13, 13, tzinfo=UTC), 2, None, "InProgress"),
        case(datetime(2026, 5, 29, 10, tzinfo=UTC), 4, None, "InProgress"),
    ]

    # Ordinary work over six months.
    day = datetime(2026, 1, 6, tzinfo=UTC)
    imported = 0
    while day < datetime(2026, 6, 26, tzinfo=UTC):
        if rng.random() < 0.34:
            created = day + timedelta(hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
            roll = rng.random()
            analyst = rng.choice(HIVE_ANALYSTS)
            started = created + timedelta(minutes=rng.randint(5, 90))
            if roll < 0.1:
                alert(created, stage="New", status="New", assignee=None, closed=None, in_progress=None)
            elif roll < 0.3 and imported < len(case_ids):
                alert(created, stage="Imported", status="Imported", assignee=analyst,
                      closed=started + timedelta(minutes=30), in_progress=started, case_id=case_ids[imported])
                imported += 1
            else:
                alert(created, stage="Closed", status=rng.choice(["Ignored", "Duplicate", "FalsePositive"]),
                      assignee=analyst, closed=started + timedelta(hours=rng.randint(1, 6)), in_progress=started)
        day += timedelta(days=1)

    # The pattern: 34 alerts from 18-20 May closed by one analyst between 22:02 and 22:52 UTC on 20 May.
    for i in range(34):
        created = datetime(2026, 5, 18, 5, 0, tzinfo=UTC) + timedelta(hours=1, minutes=50) * i
        closed = datetime(2026, 5, 20, 22, 2, 0, tzinfo=UTC) + timedelta(seconds=88 * i)
        alert(created, stage="Closed", status="Ignored", assignee=HIVE_ANALYSTS[1], closed=closed,
              in_progress=None, title=HIVE_TITLES[0])

    alerts.sort(key=lambda a: a["date"])
    out.mkdir(parents=True, exist_ok=True)
    (out / "thehive_alerts.json").write_text(json.dumps(alerts, indent=1) + "\n", encoding="utf-8")
    (out / "thehive_cases.json").write_text(json.dumps(cases, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    build_splunk(HERE / "splunk")
    build_servicenow(HERE / "servicenow")
    build_thehive(HERE / "thehive")
    for path in sorted(HERE.rglob("*.*")):
        if path.suffix in (".csv", ".json"):
            print(f"{path.relative_to(HERE)}  {path.stat().st_size} bytes")
