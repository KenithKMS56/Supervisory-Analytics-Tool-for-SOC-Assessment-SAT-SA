"""Independent synthetic scenario generator, written from the documented rule catalogue only.

Purpose: the original generator (`satsa.synth.generator`, `defects`, `stress`) was written by the
same people who wrote the rules and built each defect around a rule's code. This generator is a
second, separately written source of test data. It builds every defect from the **prose** in
README.md ("Regulatory Detection Catalog") and docs/analytics_methodology.md Section 3, uses the
default thresholds as those documents state them (`DOC_THRESHOLDS` below), and writes the
canonical CSV submission itself. It imports nothing from `satsa.synth` and nothing from
`satsa.rules` (`tests/test_validate_independent.py` checks the imports).

What differs from the original generator, on purpose:

* 15 entities `ORG-A` .. `ORG-O` (not 10 `CSE-xx`), every sector at every size band, so each
  entity's peer cohort is its size band (4 peers); April-September 2026, not January-June.
* Per-entity alert volume drawn from a lognormal distribution (350-3,500), analyst count 4-22,
  analyst names `op-<letter><nn>`, its own severity, disposition, automation and night-time mix.
* Defects are assigned to entities at random per seed, and their size is random: a defect is
  built between 1.08x and 1.9x its documented threshold, so some sit close to it.
* **Decoys**: for most rules, a condition built just *under* the documented threshold (or one
  the prose says does not count, e.g. a repeated-comment group smaller than 10) is placed on an
  entity without that rule's defect. A finding on a decoy is a false positive.
* A **systemic** group: three entities sharing one third-party SOC provider all carry the same
  defect (README: "3 or more entities sharing the same third-party SOC provider"), plus a decoy
  pair of two entities sharing another provider and one defect.

Ground truth is written at injection time, with the size actually built (`measured`). Where the
prose leaves something open, the choice made here is noted next to the code; where the prose and
the code disagree, the run will show it, which is the point of an independent generator.

Column names follow the canonical schema (`satsa.models.canonical`), because
docs/data_requirements.md does not describe every table and names some columns differently
(recorded in docs/CHANGES_quality_pass.md); that module is a schema, not injection code.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

GENERATOR_VERSION = "independent/1"

# Default thresholds as README.md and docs/analytics_methodology.md Section 3 state them.
DOC_THRESHOLDS: dict[str, dict[str, float]] = {
    "EG01": {"fast_share": 0.15, "min_fast_count": 5},
    "EG02": {"max_uninvestigated_share": 0.15, "min_count": 5, "short_comment_chars": 25},
    "EG03": {},  # zero tolerance
    "EG04": {"max_comment_hash_share": 0.25, "min_hash_group_size": 10},
    "EG05": {"min_unaddressed_pairs": 2, "min_repeat_count": 8, "max_chance_pairs": 0.5},
    "EG06": {"min_bulk_closures_per_minute": 8},
    "EG07": {"min_closures_per_analyst_hour": 30},
    "EG08": {"min_unacknowledged_escalations": 3},
    "EG09": {"min_stale_cases": 3, "stale_case_days": 14},
    "EG10": {"mttr_gap_ratio": 0.60},
    "EG11": {"min_alert_volume": 200},
    "EG12": {"min_skipped_cases": 2},
    "NS01": {"min_asset_criticality": 3, "min_silent_days": 3},
    "NS02": {"min_peer_share": 0.6},
    "NS03": {"max_robust_z": 3.5, "min_alert_volume": 100},
    "NS04": {"min_tp_without_case": 3},
    "NS05": {"max_dormant_share": 0.40, "min_dormant_rules": 5},
    "NS06": {"min_ghost_assets": 2},
    "NS07": {},  # zero tolerance
    "NS08": {"review_period_months": 6},
}
RULES = sorted(DOC_THRESHOLDS)

PERIOD_START = datetime(2026, 4, 1)
PERIOD_END = datetime(2026, 9, 30, 23, 59, 0)
MONTHS = [(2026, m) for m in range(4, 10)]
SECTORS = ["power", "banking", "telecom", "transport", "oil_and_gas"]
SIZE_BANDS = ["small", "medium", "large"]
COMMON_CATEGORIES = [
    "Malware", "Phishing", "Brute Force", "Data Exfiltration", "Lateral Movement",
    "Command and Control", "Privilege Escalation", "Policy Violation", "Reconnaissance",
    "Insider Misuse",
]
RARE_CATEGORIES = ["OT Protocol Abuse", "SWIFT Fraud", "SS7 Abuse"]
ASSET_TYPES = ["plc", "historian", "atm_switch", "core_router", "vpn_gateway", "mail_relay", "hr_laptop"]
SEVERITIES = ["low", "medium", "high", "critical"]
NIGHT_HOURS = [20, 21, 22, 23, 0, 1, 2, 3, 4, 5, 6, 7]
DAY_HOURS = list(range(8, 20))
# Median human close time per severity, minutes (lognormal, sigma 0.5, floor 20).
CLOSE_MEDIAN = {"critical": 75.0, "high": 140.0, "medium": 420.0, "low": 900.0}
SLA_MINUTES = {"critical": (15, 480), "high": (30, 960), "medium": (120, 2880), "low": (480, 5760)}
SYSTEMIC_RULES = ["EG08", "EG12", "NS07"]
# Rules whose defects and decoys are sized as a multiple of a documented share threshold; their
# ground truth records that multiple as `design_factor` (1.08-1.9 for defects, 0.4-0.8 for decoys).
SHARE_RULES = {"EG01", "EG02", "EG04", "NS05"}

TABLE_COLUMNS: dict[str, list[str]] = {
    "entity": ["entity_id", "name", "sector", "size_band", "soc_model", "soc_provider", "timezone", "declared_shift_hours"],
    "asset": ["entity_id", "asset_id", "asset_type", "criticality", "monitored_flag", "owner_unit"],
    "log_source_daily": ["entity_id", "asset_id", "source_type", "date", "event_count"],
    "detection_rule": ["entity_id", "rule_id", "category", "mitre_tactic", "mitre_technique", "enabled", "last_fired"],
    "alert": ["entity_id", "alert_id", "rule_id", "category", "severity_orig", "severity_final", "asset_id",
              "created_at", "acknowledged_at", "first_touch_at", "closed_at", "closed_by", "closed_by_type",
              "playbook_id", "disposition", "status"],
    "case": ["entity_id", "case_id", "severity", "status", "owner", "opened_at", "closed_at"],
    "case_alert_link": ["entity_id", "case_id", "alert_id"],
    "workflow_event": ["entity_id", "ref_type", "ref_id", "ts", "actor", "action", "from_status", "to_status", "note_len"],
    "escalation": ["entity_id", "esc_id", "ref_id", "escalated_at", "from_role", "to_role", "acknowledged_at", "outcome"],
    "closure": ["entity_id", "ref_id", "reason_code", "disposition", "comment_norm_hash", "comment_len", "comment_shingles"],
    "remediation": ["entity_id", "ticket_id", "linked_asset_id", "linked_rule_id", "type", "created_at", "closed_at"],
    "external_report": ["entity_id", "incident_id", "reported_to", "reported_at"],
    "declared_kpi": ["entity_id", "period", "metric", "severity", "value"],
    "sla_policy": ["entity_id", "severity", "ack_minutes", "resolve_minutes"],
}


def _ts(dt: datetime | None) -> str:
    return "" if dt is None else dt.strftime("%Y-%m-%dT%H:%M:%S")


def robust_z(value: float, peers: list[float], floor: float) -> float:
    """(value - median) / max(1.4826 * MAD, floor), as docs/analytics_methodology.md describes."""
    if not peers:
        return 0.0
    s = sorted(peers)
    n = len(s)
    med = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2
    dev = sorted(abs(p - med) for p in s)
    mad = dev[n // 2] if n % 2 else (dev[n // 2 - 1] + dev[n // 2]) / 2
    return (value - med) / max(1.4826 * mad, floor)


def poisson_sf(k: int, lam: float) -> float:
    """P(X >= k) for X ~ Poisson(lam)."""
    if k <= 0:
        return 1.0
    term = math.exp(-lam)
    cdf = term
    for i in range(1, k):
        term *= lam / i
        cdf += term
    return max(0.0, 1.0 - cdf)


def eg05_repeat_threshold(n_alerts: int, n_pairs_space: int) -> int:
    """k = max(min_repeat_count, k_chance), k_chance capped at 2x min_repeat_count (prose of EG05)."""
    p = DOC_THRESHOLDS["EG05"]
    base = int(p["min_repeat_count"])
    lam = n_alerts / max(n_pairs_space, 1)
    k_chance = 1
    while n_pairs_space * poisson_sf(k_chance, lam) >= p["max_chance_pairs"] and k_chance < 2 * base:
        k_chance += 1
    return max(base, min(k_chance, 2 * base))


@dataclass
class EntityData:
    eid: str
    letter: str
    rows: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))
    analysts: list[str] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    rules: list[dict[str, Any]] = field(default_factory=list)
    alert_seq: int = 0
    case_seq: int = 0
    esc_seq: int = 0

    def next_alert_id(self) -> str:
        self.alert_seq += 1
        return f"EV-{self.letter}{self.alert_seq:06d}"

    def next_case_id(self) -> str:
        self.case_seq += 1
        return f"INC-{self.letter}-{self.case_seq:05d}"

    def next_esc_id(self) -> str:
        self.esc_seq += 1
        return f"ESC-{self.letter}-{self.esc_seq:05d}"


class IndependentScenarioGenerator:
    """Builds one independent scenario for `seed`; `save(dir)` writes CSVs and ground truth."""

    def __init__(self, seed: int):
        self.seed = seed
        self.rng = random.Random(f"independent-{seed}")
        self.entities: dict[str, EntityData] = {}
        self.specs: dict[str, dict[str, Any]] = {}
        self.defects: list[dict[str, Any]] = []
        self.decoys: list[dict[str, Any]] = []
        self.systemic_expected: list[dict[str, Any]] = []
        self.systemic_decoys: list[dict[str, Any]] = []
        self._factor: float | None = None

    # ------------------------------------------------------------------ plan

    def _plan(self) -> None:
        rng = self.rng
        letters = [chr(ord("A") + i) for i in range(15)]
        for i, letter in enumerate(letters):
            eid = f"ORG-{letter}"
            self.specs[eid] = {
                "letter": letter, "sector": SECTORS[i % 5], "size_band": SIZE_BANDS[i // 5],
                "soc_model": "inhouse", "soc_provider": "internal", "rules": [], "decoy_rules": [],
                "rare_category": None,
            }
        ids = list(self.specs)
        # One rare category per size band at most: a peer share of at most 1 in 4 (below 60%).
        for band in SIZE_BANDS:
            members = [e for e in ids if self.specs[e]["size_band"] == band]
            for cat in rng.sample(RARE_CATEGORIES, 2):
                self.specs[rng.choice(members)]["rare_category"] = cat

        shuffled = ids[:]
        rng.shuffle(shuffled)
        clean, defect_entities = shuffled[:3], shuffled[3:]
        self.clean = sorted(clean)
        # Rules that cannot share an entity with EG11 (built with no true positives at all).
        needs_tp = {"EG03", "NS04", "EG12", "NS07"}

        def can_take(eid: str, rule: str) -> bool:
            have = self.specs[eid]["rules"]
            if rule in have:
                return False
            if rule == "EG11" and needs_tp & set(have):
                return False
            return not (rule in needs_tp and "EG11" in have)

        # Systemic group first: three entities, one third-party provider, one shared defect.
        sys_rule = rng.choice(SYSTEMIC_RULES)
        group = rng.sample(defect_entities, 3)
        for eid in group:
            self.specs[eid].update(soc_model="mssp", soc_provider="MSSP-Orion")
            self.specs[eid]["rules"].append(sys_rule)
        self.systemic_expected.append({"provider": "MSSP-Orion", "rule_id": sys_rule, "entities": sorted(group)})
        # Decoy pair: two entities share another provider and one defect (fewer than 3).
        rest = [e for e in defect_entities if e not in group]
        pair_rule = rng.choice([r for r in SYSTEMIC_RULES if r != sys_rule])
        pair = rng.sample(rest, 2)
        for eid in pair:
            self.specs[eid].update(soc_model="mssp", soc_provider="MSSP-Vega")
            self.specs[eid]["rules"].append(pair_rule)
        self.systemic_decoys.append({"provider": "MSSP-Vega", "rule_id": pair_rule, "entities": sorted(pair)})

        # Every rule at least once.
        order = RULES[:]
        rng.shuffle(order)
        cursor = 0
        for rule in order:
            if any(rule in self.specs[e]["rules"] for e in defect_entities):
                continue
            for step in range(len(defect_entities)):
                eid = defect_entities[(cursor + step) % len(defect_entities)]
                if can_take(eid, rule):
                    self.specs[eid]["rules"].append(rule)
                    cursor = (cursor + step + 1) % len(defect_entities)
                    break
        # Decoys: most rules get one, on an entity without that rule's defect.
        decoy_rules = [r for r in RULES if r not in ("EG03", "EG11", "NS02")]  # see _inject_decoy
        for rule in decoy_rules:
            if rng.random() < 0.25:
                continue
            candidates = [e for e in ids if rule not in self.specs[e]["rules"] and not self.specs[e]["decoy_rules"]]
            candidates = [e for e in candidates if not (rule in needs_tp and "EG11" in self.specs[e]["rules"])]
            if rule in ("NS03", "NS08"):
                candidates = [e for e in candidates if not ({"NS03", "NS08"} & set(self.specs[e]["rules"]))]
            if candidates:
                self.specs[rng.choice(candidates)]["decoy_rules"].append(rule)

    # ------------------------------------------------------------------ baseline

    def _baseline(self, eid: str) -> EntityData:
        rng = self.rng
        spec = self.specs[eid]
        letter = spec["letter"]
        e = EntityData(eid=eid, letter=letter)
        e.rows["entity"].append({
            "entity_id": eid, "name": f"Independent Org {letter}", "sector": spec["sector"],
            "size_band": spec["size_band"], "soc_model": spec["soc_model"],
            "soc_provider": spec["soc_provider"], "timezone": "UTC", "declared_shift_hours": "24x7",
        })
        e.analysts = [f"op-{letter.lower()}{k:02d}" for k in range(rng.randint(4, 22))]

        # Assets and their daily telemetry (never zero in the baseline).
        days = (PERIOD_END.date() - PERIOD_START.date()).days + 1
        for k in range(rng.randint(25, 55)):
            crit = rng.choices([1, 2, 3, 4], weights=[0.3, 0.3, 0.25, 0.15])[0]
            asset = {"entity_id": eid, "asset_id": f"AS-{letter}{k:03d}", "asset_type": rng.choice(ASSET_TYPES),
                     "criticality": crit, "monitored_flag": "true", "owner_unit": rng.choice(["ops", "it", "ot", "fin"])}
            e.assets.append(asset)
            e.rows["asset"].append(asset)
            mean = rng.lognormvariate(math.log(600), 0.6)
            for d in range(days):
                day = PERIOD_START.date() + timedelta(days=d)
                e.rows["log_source_daily"].append({
                    "entity_id": eid, "asset_id": asset["asset_id"], "source_type": rng.choice(["edr", "fw", "syslog"]),
                    "date": day.isoformat(), "event_count": max(1, int(rng.gauss(mean, mean * 0.25))),
                })

        # Detection rules: every enabled rule fires at least once; a few are disabled.
        categories = COMMON_CATEGORIES + ([spec["rare_category"]] if spec["rare_category"] else [])
        n_rules = rng.randint(18, 34)
        for k in range(n_rules):
            cat = categories[k] if k < len(categories) else rng.choice(categories)
            e.rules.append({"entity_id": eid, "rule_id": f"DR-{letter}-{k:03d}", "category": cat,
                            "mitre_tactic": f"TA{rng.randint(1, 40):04d}", "mitre_technique": f"T{rng.randint(1000, 1600)}",
                            "enabled": "true", "last_fired": ""})
        for k in range(n_rules, n_rules + rng.randint(2, 5)):
            e.rows["detection_rule"].append({"entity_id": eid, "rule_id": f"DR-{letter}-{k:03d}", "category": rng.choice(categories),
                                             "mitre_tactic": "", "mitre_technique": "", "enabled": "false", "last_fired": ""})
        e.rows["detection_rule"].extend(e.rules)

        # Alert mix for this entity.
        n_alerts = max(350, min(3500, int(rng.lognormvariate(math.log(1100), 0.45))))
        p_crit, p_high, p_med = rng.uniform(0.03, 0.06), rng.uniform(0.10, 0.16), rng.uniform(0.25, 0.33)
        if "EG11" in spec["rules"]:
            # Two ways to meet EG11's prose: no true positive at all, or a false-positive/benign
            # rate far above the peers' with a few true positives left (only the peer robust-z
            # test catches that one). Drawn from a separate stream so other draws are unchanged.
            side = random.Random(f"independent-{self.seed}-EG11-{eid}")
            spec["eg11_variant"] = side.choice(["no_true_positives", "skewed_fp_rate"])
            p_tp = 0.0 if spec["eg11_variant"] == "no_true_positives" else side.uniform(0.01, 0.025)
        else:
            p_tp = rng.uniform(0.10, 0.16)
        p_auto = rng.uniform(0.10, 0.30)
        if "NS03" in spec["rules"]:
            night = rng.uniform(0.0, 0.06)
        elif "NS03" in spec["decoy_rules"]:
            night = rng.uniform(0.25, 0.28)
        else:
            night = rng.uniform(0.30, 0.45)
        spec["night_target"] = night
        all_days = [PERIOD_START + timedelta(days=d) for d in range(days)]
        weights = [1.0] * len(all_days)
        if "NS08" in spec["rules"]:
            gap = rng.choice(MONTHS[1:5])
            spec["missing_month"] = f"{gap[0]}-{gap[1]:02d}"
            weights = [0.0 if (d.year, d.month) == gap else 1.0 for d in all_days]
        elif "NS08" in spec["decoy_rules"]:
            thin = rng.choice(MONTHS[1:5])
            spec["thin_month"] = f"{thin[0]}-{thin[1]:02d}"
            weights = [0.15 if (d.year, d.month) == thin else 1.0 for d in all_days]

        for k in range(n_alerts):
            rule = e.rules[k] if k < len(e.rules) else rng.choice(e.rules)
            r = rng.random()
            sev = "critical" if r < p_crit else "high" if r < p_crit + p_high else "medium" if r < p_crit + p_high + p_med else "low"
            day = rng.choices(all_days, weights=weights)[0]
            hour = rng.choice(NIGHT_HOURS) if rng.random() < night else rng.choice(DAY_HOURS)
            created = day.replace(hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59))
            if created > PERIOD_END - timedelta(days=1):
                created -= timedelta(days=1)
            disp = "true_positive" if rng.random() < p_tp else ("false_positive" if rng.random() < 0.6 else "benign")
            human = rng.random() >= p_auto
            self._add_alert(e, created=created, severity=sev, disposition=disp, human=human, rule=rule,
                            asset=rng.choice(e.assets))

        # Cases (and escalations, reports) for high and critical true positives.
        for alert in list(e.rows["alert"]):
            if alert["disposition"] != "true_positive" or alert["severity_final"] not in ("high", "critical"):
                continue
            critical = alert["severity_final"] == "critical"
            self._add_case_for(e, alert, contain=True, report=critical, escalate=critical or rng.random() < 0.15)

        for sev in SEVERITIES:
            ack, resolve = SLA_MINUTES[sev]
            e.rows["sla_policy"].append({"entity_id": eid, "severity": sev, "ack_minutes": ack, "resolve_minutes": resolve})
        # A few genuine tuning tickets.
        for k in range(rng.randint(3, 8)):
            a = rng.choice(e.rows["alert"])
            e.rows["remediation"].append({
                "entity_id": eid, "ticket_id": f"CHG-{letter}-{k:04d}", "linked_asset_id": a["asset_id"],
                "linked_rule_id": a["rule_id"], "type": rng.choice(["tuning", "patch"]),
                "created_at": _ts(PERIOD_START + timedelta(days=rng.randint(5, 150))), "closed_at": "",
            })
        return e

    def _add_alert(self, e: EntityData, *, created: datetime, severity: str, disposition: str, human: bool,
                   rule: dict[str, Any], asset: dict[str, Any], minutes: float | None = None,
                   analyst: str | None = None, investigate: bool = True, comment_len: int | None = None,
                   comment_hash: str | None = None) -> dict[str, Any]:
        rng = self.rng
        aid = e.next_alert_id()
        if minutes is None:
            minutes = max(20.0, rng.lognormvariate(math.log(CLOSE_MEDIAN[severity]), 0.5)) if human else rng.uniform(1, 6)
        closed = created + timedelta(minutes=minutes)
        if closed > PERIOD_END:
            closed = PERIOD_END
            created = min(created, closed - timedelta(minutes=minutes))
        ack = created + timedelta(minutes=min(15.0, minutes / 3) * rng.uniform(0.2, 1.0))
        touch = ack + (closed - ack) * rng.uniform(0.1, 0.5)
        actor = analyst or (rng.choice(e.analysts) if human else "soar-bot")
        alert = {
            "entity_id": e.eid, "alert_id": aid, "rule_id": rule["rule_id"], "category": rule["category"],
            "severity_orig": severity, "severity_final": severity, "asset_id": asset["asset_id"],
            "created_at": created, "acknowledged_at": ack, "first_touch_at": touch if human else None,
            "closed_at": closed, "closed_by": actor, "closed_by_type": "human" if human else "automation",
            "playbook_id": "" if human else f"PB-{rng.randint(1, 9)}", "disposition": disposition, "status": "closed",
        }
        e.rows["alert"].append(alert)
        if human:
            e.rows["workflow_event"].append(self._wf(e, "alert", aid, ack, actor, "triage", "new", "triage", 0))
            if investigate:
                e.rows["workflow_event"].append(self._wf(e, "alert", aid, touch, actor, "investigate", "triage", "investigating", rng.randint(80, 600)))
        e.rows["workflow_event"].append(self._wf(e, "alert", aid, closed, actor, "close", "investigating", "closed", rng.randint(0, 120)))
        e.rows["closure"].append({
            "entity_id": e.eid, "ref_id": aid,
            "reason_code": {"true_positive": "confirmed", "false_positive": "fp_tuning", "benign": "expected_activity"}[disposition],
            "disposition": disposition,
            "comment_norm_hash": comment_hash or hashlib.sha256(f"{self.seed}:{aid}".encode()).hexdigest()[:16],
            "comment_len": comment_len if comment_len is not None else rng.randint(40, 400), "comment_shingles": "",
        })
        return alert

    @staticmethod
    def _wf(e: EntityData, ref_type: str, ref_id: str, ts: datetime, actor: str, action: str,
            frm: str, to: str, note: int) -> dict[str, Any]:
        return {"entity_id": e.eid, "ref_type": ref_type, "ref_id": ref_id, "ts": ts, "actor": actor,
                "action": action, "from_status": frm, "to_status": to, "note_len": note}

    def _add_case_for(self, e: EntityData, alert: dict[str, Any], *, contain: bool, report: bool,
                      escalate: bool, link: bool = True, status: str = "closed") -> str:
        rng = self.rng
        cid = e.next_case_id()
        opened = alert["created_at"] + timedelta(minutes=rng.uniform(2, 30))
        closed = opened + timedelta(hours=rng.uniform(2, 72)) if status == "closed" else None
        if closed and closed > PERIOD_END:
            closed = PERIOD_END
        owner = rng.choice(e.analysts)
        e.rows["case"].append({"entity_id": e.eid, "case_id": cid, "severity": alert["severity_final"],
                               "status": status, "owner": owner, "opened_at": opened, "closed_at": closed})
        if link:
            e.rows["case_alert_link"].append({"entity_id": e.eid, "case_id": cid, "alert_id": alert["alert_id"]})
        end = closed or PERIOD_END
        steps = [("triage", "new", "triage"), ("investigate", "triage", "investigating")]
        if contain:
            steps.append(("contain", "investigating", "contained"))
        if status == "closed":
            steps.append(("close", "contained" if contain else "investigating", "closed"))
        for i, (action, frm, to) in enumerate(steps):
            ts = opened + (end - opened) * ((i + 1) / (len(steps) + 1))
            e.rows["workflow_event"].append(self._wf(e, "case", cid, ts, owner, action, frm, to, rng.randint(50, 900)))
        if report:
            e.rows["external_report"].append({"entity_id": e.eid, "incident_id": cid,
                                               "reported_to": rng.choice(["NCIIPC", "CERT-In"]),
                                               "reported_at": opened + timedelta(hours=rng.uniform(2, 20))})
        if escalate:
            esc_at = alert["created_at"] + timedelta(minutes=rng.uniform(5, 40))
            e.rows["escalation"].append({"entity_id": e.eid, "esc_id": e.next_esc_id(), "ref_id": alert["alert_id"],
                                         "escalated_at": esc_at, "from_role": "tier1", "to_role": "tier2",
                                         "acknowledged_at": esc_at + timedelta(minutes=rng.uniform(5, 90)),
                                         "outcome": "accepted"})
        return cid

    # ------------------------------------------------------------------ helpers for injections

    def _human_closed(self, e: EntityData, severities: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
        return [a for a in e.rows["alert"] if a["closed_by_type"] == "human" and a["closed_at"] is not None
                and (severities is None or a["severity_final"] in severities)]

    def _closure(self, e: EntityData, alert_id: str) -> dict[str, Any]:
        return next(c for c in e.rows["closure"] if c["ref_id"] == alert_id)

    def _quiet_time(self, rng: random.Random, e: EntityData | None = None) -> datetime:
        """A day-time moment inside the period, away from its edges and outside a month the
        entity is built without (NS08)."""
        missing = self.specs[e.eid].get("missing_month") if e else None
        while True:
            day = PERIOD_START + timedelta(days=rng.randint(10, 170))
            if day.strftime("%Y-%m") != missing:
                return day.replace(hour=rng.randint(9, 17), minute=rng.randint(0, 59))

    def _new_tp_alert(self, e: EntityData, severity: str) -> dict[str, Any]:
        rng = self.rng
        return self._add_alert(e, created=self._quiet_time(rng, e), severity=severity, disposition="true_positive",
                               human=True, rule=rng.choice(e.rules), asset=rng.choice(e.assets))

    @staticmethod
    def _sized(share: float, population: int, min_count: int, decoy: bool) -> int:
        """How many records to change. A defect clears both the share and the minimum count; a
        decoy stays under the share or, when the population is small, under the minimum count."""
        if not decoy:
            return max(min_count, math.ceil(share * population))
        n = math.floor(share * population)
        return n if n >= min_count else min_count - 1

    def _record(self, target: list[dict[str, Any]], eid: str, rule: str, kind: str, affected: list[str],
                measured: dict[str, Any], description: str) -> None:
        share = float(measured.get("share", 0.0) or 0.0)
        factor = self._factor
        if rule in SHARE_RULES and factor is not None and "design_factor" not in measured:
            measured = {**measured, "design_factor": round(factor, 3)}
        target.append({"entity_id": eid, "rule_id": rule, "defect_type": kind, "affected_ids": affected[:50],
                       "share": round(share, 4), "measured": measured, "description": description})

    # ------------------------------------------------------------------ injections (prose -> data)

    def _inject(self, e: EntityData, rule: str, decoy: bool) -> None:
        rng = self.rng
        sink = self.decoys if decoy else self.defects
        t = DOC_THRESHOLDS[rule]
        up = rng.uniform(1.08, 1.9)      # how far over the threshold a defect is built
        down = rng.uniform(0.40, 0.80)   # how far under it a decoy is built
        self._factor = down if decoy else up  # recorded with share-based injections (_record)
        eid = e.eid

        if rule == "EG01":
            # Human High/Critical closures far faster than any peer's typical close, with <= 1
            # workflow event. Baseline human closures take at least 20 minutes.
            pool = self._human_closed(e, ("high", "critical"))
            share = t["fast_share"] * (down if decoy else up)
            n = self._sized(share, len(pool), int(t["min_fast_count"]), decoy)
            picked = rng.sample(pool, min(n, len(pool)))
            for a in picked:
                a["closed_at"] = a["created_at"] + timedelta(minutes=rng.uniform(1, 3))
                a["acknowledged_at"] = a["created_at"] + timedelta(seconds=20)
                a["first_touch_at"] = None
                e.rows["workflow_event"] = [w for w in e.rows["workflow_event"]
                                            if not (w["ref_type"] == "alert" and w["ref_id"] == a["alert_id"] and w["action"] != "close")]
                for w in e.rows["workflow_event"]:
                    if w["ref_type"] == "alert" and w["ref_id"] == a["alert_id"]:
                        w["ts"] = a["closed_at"]
            self._record(sink, eid, rule, "fast_closures", [a["alert_id"] for a in picked],
                         {"share": len(picked) / max(len(pool), 1), "count": len(picked), "population": len(pool)},
                         "Human High/Critical alerts closed within 1-3 minutes with only the close event.")

        elif rule == "EG02":
            pool = [a for a in self._human_closed(e) if a["first_touch_at"] is not None]
            share = t["max_uninvestigated_share"] * (down if decoy else up)
            n = self._sized(share, len(pool), int(t["min_count"]), decoy)
            picked = rng.sample(pool, min(n, len(pool)))
            picked_ids = {a["alert_id"] for a in picked}
            e.rows["workflow_event"] = [w for w in e.rows["workflow_event"]
                                        if not (w["ref_type"] == "alert" and w["ref_id"] in picked_ids and w["action"] == "investigate")]
            for a in picked:
                self._closure(e, a["alert_id"])["comment_len"] = rng.randint(2, int(t["short_comment_chars"]) - 1)
            self._record(sink, eid, rule, "closed_without_investigation", sorted(picked_ids),
                         {"share": len(picked) / max(len(self._human_closed(e)), 1), "count": len(picked)},
                         "Human closures with no investigate event and a closure comment under 25 characters.")

        elif rule == "EG03":
            k = rng.randint(1, 3)
            new = [self._new_tp_alert(e, "critical") for _ in range(k)]
            for a in new:  # handled everywhere else (case, containment, report), never escalated
                self._add_case_for(e, a, contain=True, report=True, escalate=False)
            self._record(sink, eid, rule, "critical_tp_not_escalated", [a["alert_id"] for a in new],
                         {"count": k}, "Critical true-positive alerts with no escalation record.")

        elif rule == "EG04":
            pool = self._human_closed(e)
            min_group = int(t["min_hash_group_size"])
            small_groups = decoy and rng.random() < 0.5
            share = t["max_comment_hash_share"] * (rng.uniform(1.2, 1.6) if small_groups else (down if decoy else up))
            n = math.ceil(share * len(pool))
            picked = rng.sample(pool, min(n, len(pool)))
            if small_groups:
                size = rng.randint(min_group - 2, min_group - 1)
                groups = math.ceil(len(picked) / size)
                key = [i // size for i in range(len(picked))]
            else:
                groups = rng.randint(2, 3)
                while groups > 1 and len(picked) // groups < min_group:
                    groups -= 1
                key = [i % groups for i in range(len(picked))]
                size = len(picked) // groups
            for i, a in enumerate(picked):
                self._closure(e, a["alert_id"])["comment_norm_hash"] = f"tpl-{self.seed}-{eid}-{key[i]}"
            self._record(sink, eid, rule, "template_closures" + ("_small_groups" if small_groups else ""),
                         [a["alert_id"] for a in picked],
                         {"share": len(picked) / max(len(pool), 1), "group_size": size, "count": len(picked)},
                         f"Human closures sharing repeated comment hashes in groups of {size}.")

        elif rule == "EG05":
            used = {(a["asset_id"], a["rule_id"]) for a in e.rows["alert"]}
            n_assets = len({a["asset_id"] for a in e.rows["alert"]})
            n_rules = len({a["rule_id"] for a in e.rows["alert"]})
            space = n_assets * n_rules
            one_pair = decoy and rng.random() < 0.5
            pairs = 1 if one_pair else (2 if rng.random() < 0.5 else rng.randint(3, 4))
            k = eg05_repeat_threshold(len(e.rows["alert"]), space)
            reps = [k + rng.randint(0, 6) for _ in range(pairs)]
            k = eg05_repeat_threshold(len(e.rows["alert"]) + sum(reps), space)
            reps = [max(r, k) for r in reps]
            chosen: list[tuple[str, str]] = []
            while len(chosen) < pairs:
                cand = (rng.choice(e.assets)["asset_id"], rng.choice(e.rules)["rule_id"])
                if cand not in used and cand not in chosen:
                    chosen.append(cand)
            affected = []
            rules_by_id = {r["rule_id"]: r for r in e.rules}
            assets_by_id = {a["asset_id"]: a for a in e.assets}
            for (asset_id, rule_id), count in zip(chosen, reps, strict=True):
                for _ in range(count):
                    a = self._add_alert(e, created=self._quiet_time(rng, e), severity=rng.choice(["low", "medium"]),
                                        disposition=rng.choice(["false_positive", "benign"]), human=True,
                                        rule=rules_by_id[rule_id], asset=assets_by_id[asset_id])
                    affected.append(a["alert_id"])
            remediated = None
            if decoy and not one_pair:  # two pairs, but one was tuned: only one unaddressed
                remediated = chosen[0]
                e.rows["remediation"].append({"entity_id": eid, "ticket_id": f"CHG-{e.letter}-R{self.seed}",
                                              "linked_asset_id": remediated[0], "linked_rule_id": remediated[1],
                                              "type": "tuning", "created_at": _ts(PERIOD_START + timedelta(days=30)), "closed_at": ""})
            self._record(sink, eid, rule, "repeat_pairs_no_remediation" + ("_one_remediated" if remediated else ""),
                         affected, {"pairs": pairs, "repeats": reps, "k": k, "remediated_pair": remediated},
                         "(asset, rule) pairs repeating at least k times, always benign or FP, without remediation.")

        elif rule == "EG06":
            b = rng.randint(5, 7) if decoy else rng.randint(int(t["min_bulk_closures_per_minute"]), 14)
            analyst = rng.choice(e.analysts)
            moment = self._quiet_time(rng, e)
            ids = []
            for _ in range(b):
                created = moment - timedelta(minutes=rng.uniform(30, 600))
                closed_offset = (moment - created).total_seconds() / 60 + rng.uniform(0, 0.9)
                a = self._add_alert(e, created=created, severity=rng.choice(["low", "medium"]), disposition="false_positive",
                                    human=True, rule=rng.choice(e.rules), asset=rng.choice(e.assets),
                                    minutes=closed_offset, analyst=analyst)
                ids.append(a["alert_id"])
            self._record(sink, eid, rule, "bulk_closures", ids, {"closures_in_one_minute": b},
                         "One analyst closing many alerts inside one clock minute.")

        elif rule == "EG07":
            c = rng.randint(20, 26) if decoy else int(t["min_closures_per_analyst_hour"]) + rng.randint(1, 15)
            analyst = rng.choice(e.analysts)
            hour = self._quiet_time(rng, e).replace(minute=0, second=0)
            per_minute: dict[int, int] = defaultdict(int)
            ids = []
            for _ in range(c):
                minute = rng.choice([m for m in range(60) if per_minute[m] < 5])
                per_minute[minute] += 1
                closed = hour + timedelta(minutes=minute, seconds=rng.randint(0, 59))
                created = closed - timedelta(minutes=rng.uniform(40, 500))
                a = self._add_alert(e, created=created, severity=rng.choice(["low", "medium"]), disposition="benign",
                                    human=True, rule=rng.choice(e.rules), asset=rng.choice(e.assets),
                                    minutes=(closed - created).total_seconds() / 60, analyst=analyst)
                ids.append(a["alert_id"])
            self._record(sink, eid, rule, "implausible_hourly_closures", ids, {"closures_in_one_hour": c},
                         "One analyst closing this many alerts inside one clock hour (at most 5 per minute).")

        elif rule == "EG08":
            u = 2 if decoy else int(t["min_unacknowledged_escalations"]) + rng.randint(0, 3)
            pool = [a for a in e.rows["alert"] if a["severity_final"] in ("high", "critical")] or e.rows["alert"]
            ids = []
            for a in rng.sample(pool, min(u, len(pool))):
                esc_id = e.next_esc_id()
                e.rows["escalation"].append({"entity_id": eid, "esc_id": esc_id, "ref_id": a["alert_id"],
                                             "escalated_at": a["created_at"] + timedelta(minutes=30), "from_role": "tier1",
                                             "to_role": "tier2", "acknowledged_at": None, "outcome": ""})
                ids.append(esc_id)
            self._record(sink, eid, rule, "escalations_never_acknowledged", ids, {"count": len(ids)},
                         "Escalations with no acknowledgement timestamp.")

        elif rule == "EG09":
            stale_days = int(t["stale_case_days"])
            recent_variant = decoy and rng.random() < 0.5
            n = int(t["min_stale_cases"]) + (0 if recent_variant else (-1 if decoy else rng.randint(0, 2)))
            ids = []
            for _ in range(n):
                age = rng.uniform(2, stale_days - 4) if recent_variant else rng.uniform(stale_days + 6, 70)
                fake = {"alert_id": "", "created_at": PERIOD_END - timedelta(days=age), "severity_final": "medium"}
                cid = self._add_case_for(e, fake, contain=False, report=False, escalate=False, link=False, status="open")
                ids.append(cid)
            self._record(sink, eid, rule, "stale_open_cases" + ("_recent" if recent_variant else ""), ids,
                         {"count": n, "recent_only": recent_variant}, "Open cases opened long before the period end.")

        elif rule == "EG10":
            # Applied after the declared KPIs are computed: see _declare_kpis.
            e.rows["_eg10"] = [{"ratio": rng.uniform(1.2, 1.45) if decoy else rng.uniform(1.7, 2.8), "decoy": decoy}]

        elif rule == "EG11":
            # Built at generation time (see _baseline): no true positive at all, or a few left and
            # a false-positive/benign rate far above the peers'. _reconcile checks the criterion.
            total = len(e.rows["alert"])
            tps = sum(1 for a in e.rows["alert"] if a["disposition"] == "true_positive")
            if self.specs[eid]["eg11_variant"] == "no_true_positives":
                self._record(sink, eid, rule, "no_true_positives", [], {"alerts": total, "true_positives": 0},
                             "No alert in the period was a true positive.")
            else:
                self._record(sink, eid, rule, "skewed_fp_rate", [], {"alerts": total, "true_positives": tps},
                             "False-positive/benign rate far above the peer cohort's, with few true positives.")

        elif rule == "EG12":
            k = 1 if decoy else int(t["min_skipped_cases"]) + rng.randint(0, 2)
            ids = []
            for _ in range(k):
                a = self._new_tp_alert(e, "critical")
                ids.append(self._add_case_for(e, a, contain=False, report=True, escalate=True))
            self._record(sink, eid, rule, "critical_cases_without_containment", ids, {"count": k},
                         "Critical cases with no contain workflow event.")

        elif rule == "NS01":
            low_crit = decoy and rng.random() < 0.5
            pool = [a for a in e.assets if (a["criticality"] <= 2 if low_crit else a["criticality"] >= 3)]
            if not pool:
                return
            assets = rng.sample(pool, 1 if decoy else min(len(pool), rng.randint(1, 2)))
            silent = {}
            for asset in assets:
                n_days = rng.randint(5, 9) if low_crit else (2 if decoy else rng.randint(3, 10))
                rows = [r for r in e.rows["log_source_daily"] if r["asset_id"] == asset["asset_id"]]
                for r in rng.sample(rows, n_days):
                    r["event_count"] = 0
                silent[asset["asset_id"]] = {"zero_days": n_days, "criticality": asset["criticality"]}
            self._record(sink, eid, rule, "silent_assets" + ("_low_criticality" if low_crit else ""), list(silent),
                         {"assets": silent}, "Monitored assets with days of zero log events.")

        elif rule == "NS02":
            cat = rng.choice(COMMON_CATEGORIES)
            other = rng.choice([c for c in COMMON_CATEGORIES if c != cat])
            for r in e.rules:
                if r["category"] == cat:
                    r["category"] = other
            for a in e.rows["alert"]:
                if a["category"] == cat:
                    a["category"] = other
            self._record(sink, eid, rule, "missing_common_category", [cat], {"category": cat},
                         "A category every peer reports is absent from this entity's alerts.")

        elif rule == "NS03":
            self._ns03_pending.append((eid, decoy))  # measured once every entity exists

        elif rule == "NS04":
            k = 2 if decoy else int(t["min_tp_without_case"]) + rng.randint(0, 3)
            new = [self._new_tp_alert(e, "high") for _ in range(k)]
            self._record(sink, eid, rule, "tp_without_case", [a["alert_id"] for a in new], {"count": k},
                         "High true-positive alerts with no linked case.")

        elif rule == "NS05":
            enabled = len(e.rules)
            share = t["max_dormant_share"] * (down if decoy else rng.uniform(1.08, 1.6))
            d = max(int(t["min_dormant_rules"]), math.ceil(share * enabled / (1 - share)))
            if decoy:
                d = max(int(t["min_dormant_rules"]), math.floor(share * enabled / (1 - share)))
            ids = []
            for k in range(d):
                rid = f"DR-{e.letter}-Z{k:02d}"
                e.rows["detection_rule"].append({"entity_id": eid, "rule_id": rid, "category": rng.choice(COMMON_CATEGORIES),
                                                 "mitre_tactic": "", "mitre_technique": "", "enabled": "true", "last_fired": ""})
                ids.append(rid)
            self._record(sink, eid, rule, "dormant_enabled_rules", ids,
                         {"share": d / (enabled + d), "dormant": d, "enabled": enabled + d},
                         "Enabled detection rules that produced no alert in the period.")

        elif rule == "NS06":
            g = 1 if decoy else int(t["min_ghost_assets"]) + rng.randint(0, 2)
            ids = []
            for k in range(g):
                asset = {"entity_id": eid, "asset_id": f"AS-{e.letter}G{k:02d}", "asset_type": rng.choice(ASSET_TYPES),
                         "criticality": rng.randint(1, 4), "monitored_flag": "true", "owner_unit": "it"}
                e.rows["asset"].append(asset)
                ids.append(asset["asset_id"])
            self._record(sink, eid, rule, "ghost_assets", ids, {"count": g},
                         "Inventory assets with no alerts and no log rows.")

        elif rule == "NS07":
            if decoy:  # a HIGH case without a report: the rule concerns critical cases only
                a = self._new_tp_alert(e, "high")
                cid = self._add_case_for(e, a, contain=True, report=False, escalate=False)
                self._record(sink, eid, rule, "high_case_unreported", [cid], {"count": 1, "severity": "high"},
                             "A high (not critical) case with no external report.")
            else:
                k = rng.randint(1, 2)
                ids = []
                for _ in range(k):
                    a = self._new_tp_alert(e, "critical")
                    ids.append(self._add_case_for(e, a, contain=True, report=False, escalate=True))
                self._record(sink, eid, rule, "critical_case_unreported", ids, {"count": k},
                             "Critical cases with no external report record.")

        elif rule == "NS08":
            spec = self.specs[eid]
            month = spec.get("thin_month") if decoy else spec.get("missing_month")
            self._record(sink, eid, rule, "thin_month" if decoy else "missing_month", [month or ""],
                         {"month": month, "volume_factor": 0.15 if decoy else 0.0},
                         "A month with no alerts at all." if not decoy else "A month at 15% of normal volume.")

    def _declare_kpis(self, e: EntityData) -> None:
        """Declared MTTR per High/Critical: the empirical mean (all closed alerts of that severity,
        created -> closed), times 0.98-1.25; for EG10 defects and decoys, divided by a ratio."""
        rng = self.rng
        eg10 = e.rows.pop("_eg10", None)
        ratio = eg10[0]["ratio"] if eg10 else None
        measured = {}
        for sev in ("high", "critical"):
            durations = [(a["closed_at"] - a["created_at"]).total_seconds() / 60 for a in e.rows["alert"]
                         if a["severity_final"] == sev and a["closed_at"] is not None and a["closed_at"] >= a["created_at"]]
            if not durations:
                continue
            actual = sum(durations) / len(durations)
            declared = actual / ratio if ratio else actual * rng.uniform(0.98, 1.25)
            measured[sev] = {"empirical_mttr": round(actual, 1), "declared_mttr": round(declared, 1), "alerts": len(durations)}
            e.rows["declared_kpi"].append({"entity_id": e.eid, "period": "2026-H2", "metric": "MTTR",
                                           "severity": sev, "value": round(declared, 2)})
        if eg10:
            sink = self.decoys if eg10[0]["decoy"] else self.defects
            self._record(sink, e.eid, "EG10", "declared_mttr_understated", [f"MTTR:{s}" for s in measured],
                         {"ratio": round(ratio or 0, 3), "per_severity": measured},
                         "Declared High/Critical MTTR below the MTTR the alert timestamps give.")

    def _reconcile(self) -> None:
        """Label the peer-relative and chance-dependent conditions by the documented criterion.

        For NS03, EG11 and EG05 whether a condition meets its rule's criterion depends on the
        peers and the random draw, not only on what was injected. So, as the last step, the
        documented criterion is computed on the data actually built (generator code, written from
        the prose; it does not call the rules) and the ground truth follows it:

        * an injected defect that ended up not meeting the criterion becomes a decoy,
        * an injected decoy that ended up meeting it becomes a defect,
        * a baseline entity that meets it by chance gets an "incidental" defect.

        Every such change is listed in `self.relabelled`.
        """
        self.relabelled: list[dict[str, Any]] = []
        self._factor = None
        alerts = {eid: e.rows["alert"] for eid, e in self.entities.items()}
        band = {eid: self.specs[eid]["size_band"] for eid in self.entities}

        def peers_of(eid: str, min_alerts: float) -> list[str]:
            return [q for q in self.entities if q != eid and band[q] == band[eid] and len(alerts[q]) >= min_alerts]

        # NS03: night share robust z <= -3.5 against peers with >= 100 alerts (fixed 3% under 3 peers).
        ns03 = DOC_THRESHOLDS["NS03"]
        night = {eid: sum(1 for a in al if a["created_at"].hour >= 20 or a["created_at"].hour < 8) / max(len(al), 1)
                 for eid, al in alerts.items()}
        ns03_flag: dict[str, tuple[bool, dict[str, Any]]] = {}
        for eid in self.entities:
            if len(alerts[eid]) < ns03["min_alert_volume"]:
                ns03_flag[eid] = (False, {"night_share": round(night[eid], 4)})
                continue
            peers = peers_of(eid, ns03["min_alert_volume"])
            if len(peers) >= 3:
                z = robust_z(night[eid], [night[q] for q in peers], 0.02)
                ns03_flag[eid] = (z <= -ns03["max_robust_z"], {"night_share": round(night[eid], 4), "robust_z": round(z, 2)})
            else:
                ns03_flag[eid] = (night[eid] < 0.03, {"night_share": round(night[eid], 4), "fixed_threshold": 0.03})

        # EG11: zero true positives, or FP/benign rate robust z >= 3.5 (fixed 98% under 3 peers), >= 200 alerts.
        eg11 = DOC_THRESHOLDS["EG11"]
        fp_rate = {eid: sum(1 for a in al if a["disposition"] in ("false_positive", "benign")) / max(len(al), 1)
                   for eid, al in alerts.items()}
        eg11_flag: dict[str, tuple[bool, dict[str, Any]]] = {}
        for eid in self.entities:
            if len(alerts[eid]) < eg11["min_alert_volume"]:
                eg11_flag[eid] = (False, {"alerts": len(alerts[eid])})
                continue
            tps = sum(1 for a in alerts[eid] if a["disposition"] == "true_positive")
            peers = peers_of(eid, eg11["min_alert_volume"])
            z11: float | None = None
            if len(peers) >= 3:
                z11 = robust_z(fp_rate[eid], [fp_rate[q] for q in peers], 0.01)
                outlier = z11 >= 3.5
            else:
                outlier = fp_rate[eid] > 0.98
            eg11_flag[eid] = (tps == 0 or outlier, {"true_positives": tps, "fp_rate": round(fp_rate[eid], 4),
                                                    "robust_z": None if z11 is None else round(z11, 2)})

        # EG05: at least 2 (asset, rule) pairs with >= k alerts, all benign/FP, no remediation.
        eg05_flag: dict[str, tuple[bool, dict[str, Any]]] = {}
        for eid, e in self.entities.items():
            pairs: dict[tuple[str, str], list[str]] = defaultdict(list)
            for a in alerts[eid]:
                pairs[(a["asset_id"], a["rule_id"])].append(a["disposition"])
            space = len({a["asset_id"] for a in alerts[eid]}) * len({a["rule_id"] for a in alerts[eid]})
            k = eg05_repeat_threshold(len(alerts[eid]), space)
            fixed = {(r["linked_asset_id"], r["linked_rule_id"]) for r in e.rows["remediation"]}
            hits = sorted(f"{pr[0]}|{pr[1]}" for pr, d in pairs.items()
                          if len(d) >= k and all(x in ("false_positive", "benign") for x in d) and pr not in fixed)
            eg05_flag[eid] = (len(hits) >= DOC_THRESHOLDS["EG05"]["min_unaddressed_pairs"], {"k": k, "unaddressed_pairs": hits})

        pending = dict(self._ns03_pending)
        for rule, flags in (("NS03", ns03_flag), ("EG11", eg11_flag), ("EG05", eg05_flag)):
            for eid, (meets, measured) in flags.items():
                if rule == "NS03" and eid in pending:
                    intended_decoy = pending[eid]
                    target = self.defects if meets else self.decoys
                    self._record(target, eid, rule, "low_night_share" + ("" if meets else "_mild"), [], measured,
                                 "Night-time (20:00-08:00) share of alerts against the peer cohort's.")
                    if meets == intended_decoy:
                        self.relabelled.append({"entity_id": eid, "rule_id": rule,
                                                "built_as": "decoy" if intended_decoy else "defect",
                                                "labelled": "defect" if meets else "decoy", "measured": measured})
                    continue
                defect = next((d for d in self.defects if d["entity_id"] == eid and d["rule_id"] == rule), None)
                decoy = next((d for d in self.decoys if d["entity_id"] == eid and d["rule_id"] == rule), None)
                if defect is not None:
                    defect["criterion"] = measured
                    if not meets:
                        self.defects.remove(defect)
                        defect["defect_type"] += "_did_not_meet_criterion"
                        self.decoys.append(defect)
                        self.relabelled.append({"entity_id": eid, "rule_id": rule, "built_as": "defect",
                                                "labelled": "decoy", "measured": measured})
                elif meets:
                    if decoy is not None:
                        self.decoys.remove(decoy)
                    self._record(self.defects, eid, rule, "incidental" if decoy is None else "decoy_met_criterion", [],
                                 measured,
                                 "Meets the documented criterion on the data as built (not deliberately injected)."
                                 if decoy is None else "Built as a decoy but meets the documented criterion.")
                    self.relabelled.append({"entity_id": eid, "rule_id": rule,
                                            "built_as": "baseline" if decoy is None else "decoy",
                                            "labelled": "defect", "measured": measured})
                elif decoy is not None:
                    decoy["criterion"] = measured

    # ------------------------------------------------------------------ build and save

    def generate(self) -> dict[str, Any]:
        self._plan()
        self._ns03_pending: list[tuple[str, bool]] = []
        for eid in self.specs:
            self.entities[eid] = self._baseline(eid)
        # NS08 first, then everything else, so later injections never land in a missing month.
        for eid, e in self.entities.items():
            spec = self.specs[eid]
            ordered = sorted(spec["rules"], key=lambda r: (r != "NS08", r))
            for rule in ordered:
                self._inject(e, rule, decoy=False)
            for rule in spec["decoy_rules"]:
                self._inject(e, rule, decoy=True)
            self._declare_kpis(e)
        self._reconcile()
        return self.ground_truth()

    def ground_truth(self) -> dict[str, Any]:
        defect_entities = sorted({d["entity_id"] for d in self.defects})
        return {
            "version": GENERATOR_VERSION,
            "seed": self.seed,
            "created_at": datetime.now(UTC).isoformat(),
            "entities": {eid: {k: v for k, v in spec.items() if k in ("sector", "size_band", "soc_model", "soc_provider", "rules", "decoy_rules")}
                         for eid, spec in self.specs.items()},
            "defects": sorted(self.defects, key=lambda d: (d["entity_id"], d["rule_id"])),
            "decoys": sorted(self.decoys, key=lambda d: (d["entity_id"], d["rule_id"])),
            "clean_entities": sorted(set(self.specs) - set(defect_entities)),
            "confounders": [],
            "systemic_expected": self.systemic_expected,
            "systemic_decoys": self.systemic_decoys,
            "relabelled": self.relabelled,
            "doc_thresholds": DOC_THRESHOLDS,
        }

    def save(self, out_dir: Path | str) -> tuple[Path, Path]:
        gt = self.generate()
        out = Path(out_dir)
        csv_dir = out / "csv"
        csv_dir.mkdir(parents=True, exist_ok=True)
        for table, columns in TABLE_COLUMNS.items():
            with open(csv_dir / f"{table}.csv", "w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=columns)
                writer.writeheader()
                for e in self.entities.values():
                    for row in e.rows.get(table, []):
                        writer.writerow({c: (_ts(v) if isinstance(v, datetime) else ("" if v is None else v))
                                         for c, v in ((c, row.get(c)) for c in columns)})
        gt_path = out / "ground_truth.json"
        gt_path.write_text(json.dumps(gt, indent=2, default=str), encoding="utf-8")
        return csv_dir, gt_path
