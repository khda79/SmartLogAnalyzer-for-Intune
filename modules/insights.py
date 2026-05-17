"""
Local diagnostic insight engine.
Builds support-focused outputs without calling an external AI provider:
device health score, top actions, likely root causes, unified timeline, WUfB
summary, and search rows.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class InsightItem:
    severity: str
    title: str
    detail: str = ""
    recommendation: str = ""
    source: str = ""


@dataclass
class TimelineItem:
    timestamp: str
    severity: str
    source: str
    title: str
    detail: str = ""


@dataclass
class ScoreResult:
    score: int = 100
    status: str = "Healthy"
    reasons: List[InsightItem] = field(default_factory=list)


@dataclass
class WufbSummary:
    status: str = "Unknown"
    entries: List[InsightItem] = field(default_factory=list)


@dataclass
class InsightBundle:
    score: ScoreResult
    top_actions: List[InsightItem]
    root_causes: List[InsightItem]
    timeline: List[TimelineItem]
    wufb: WufbSummary
    search_rows: List[tuple]


_SEV_WEIGHT = {
    "CRITICAL": 0,
    "ERROR": 1,
    "NON_COMPLIANT": 1,
    "WARN": 2,
    "WARNING": 2,
    "PENDING": 3,
    "INFO": 4,
    "OK": 5,
}


def _sev_rank(severity):
    return _SEV_WEIGHT.get(str(severity).upper(), 4)


def _dedupe(items, limit=None):
    seen = set()
    out = []
    for item in items:
        key = (item.severity, item.title, item.detail[:120], item.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if limit and len(out) >= limit:
            break
    return out


def _score_status(score):
    if score >= 85:
        return "Healthy"
    if score >= 70:
        return "Attention"
    if score >= 50:
        return "Degraded"
    return "Critical"


def build_insights(mdm_parser=None, error_detector=None, compliance_summary=None,
                   wu_parser=None, health_report=None, hardware_parser=None,
                   evtx_parsers=None, zip_info=None):
    actions = []
    causes = []
    timeline = []
    score_reasons = []
    penalty = 0

    # Critical MDM/DSReg/firewall issues
    for issue in getattr(mdm_parser, "get_all_issues", lambda: [])():
        sev = issue.get("severity", "WARNING")
        item = InsightItem(
            severity=sev,
            title=issue.get("title", ""),
            detail=issue.get("detail", ""),
            recommendation=issue.get("recommendation", ""),
            source=issue.get("source", issue.get("category", "MDM")),
        )
        actions.append(item)
        causes.append(item)
        penalty += 15 if sev == "ERROR" else 7
        score_reasons.append(item.title)

    # Compliance
    for ps in getattr(compliance_summary, "policy_statuses", []) or []:
        if ps.status in ("NON_COMPLIANT", "FAILED", "ERROR"):
            item = InsightItem(
                severity=ps.status,
                title=f"{ps.area} is not compliant",
                detail=ps.details,
                recommendation="Review the matching Intune policy and device-side evidence.",
                source=ps.source_file,
            )
            actions.append(item)
            penalty += 10
            score_reasons.append(item.title)
        elif ps.status == "PENDING":
            penalty += 3

    # IME errors
    err_events = getattr(error_detector, "events", []) if error_detector else []
    ime_errors = [e for e in err_events if e.severity == "ERROR"]
    ime_warnings = [e for e in err_events if e.severity == "WARNING"]
    if ime_errors:
        first = ime_errors[0]
        actions.append(InsightItem(
            severity="ERROR",
            title=f"IME logs contain {len(ime_errors)} error(s)",
            detail=first.message,
            recommendation="Open the IME Logs tab and investigate the first failing app/script theme.",
            source=first.source_file,
        ))
        causes.append(InsightItem(
            severity="ERROR",
            title="Application or remediation failure detected in IME",
            detail=first.error_code or first.message,
            recommendation="Correlate with app install, detection rule or remediation script output.",
            source=first.theme or "IME",
        ))
        penalty += min(20, len(ime_errors) * 2)
    if ime_warnings:
        penalty += min(8, len(ime_warnings))
    for ev in err_events[:200]:
        timeline.append(TimelineItem(
            timestamp=ev.timestamp,
            severity=ev.severity,
            source=f"IME/{ev.theme or 'log'}",
            title=ev.known_code or ev.category,
            detail=ev.message,
        ))

    # Windows Update issues and events
    if wu_parser:
        for issue in wu_parser.get_registry_issues():
            item = InsightItem(
                severity=issue.get("severity", "WARNING"),
                title=issue.get("title", ""),
                detail=issue.get("detail", ""),
                recommendation=issue.get("recommendation", ""),
                source="Windows Update",
            )
            actions.append(item)
            causes.append(item)
            penalty += 8 if item.severity == "ERROR" else 5
            score_reasons.append(item.title)
        for ev in getattr(getattr(wu_parser, "reporting", None), "events", [])[:100]:
            timeline.append(TimelineItem(ev.timestamp, ev.level, "Windows Update",
                                         ev.source, ev.message))
        for ev in getattr(getattr(wu_parser, "etl", None), "events", [])[:100]:
            timeline.append(TimelineItem(ev.timestamp, ev.level, "WU ETL",
                                         ev.source or ev.event_id, ev.message))

    # Health findings
    for f in getattr(health_report, "findings", []) if health_report else []:
        if f.severity in ("ERROR", "WARN"):
            actions.append(InsightItem(
                severity=f.severity,
                title=f.title,
                detail=f.detail,
                recommendation=f.action,
                source=f.category,
            ))
            penalty += 10 if f.severity == "ERROR" else 5
            score_reasons.append(f.title)

    # EVTX timeline
    for log_type, parser in (evtx_parsers or {}).items():
        for ev in getattr(parser, "events", [])[:80]:
            if ev.level_str in ("Critical", "Error", "Warning"):
                timeline.append(TimelineItem(
                    timestamp=ev.timestamp,
                    severity=ev.level_str,
                    source=log_type.replace("evtx_", "EventLog/"),
                    title=f"Event {ev.event_id}",
                    detail=ev.message,
                ))

    wufb = build_wufb_summary(wu_parser)
    for entry in wufb.entries:
        if entry.severity in ("ERROR", "WARNING"):
            actions.append(entry)
            penalty += 7 if entry.severity == "ERROR" else 4

    score = max(0, min(100, 100 - penalty))
    score_result = ScoreResult(score=score, status=_score_status(score),
                               reasons=_dedupe([InsightItem("INFO", r) for r in score_reasons], 8))
    top_actions = _dedupe(sorted(actions, key=lambda x: _sev_rank(x.severity)), 5)
    root_causes = _dedupe(sorted(causes, key=lambda x: _sev_rank(x.severity)), 12)
    timeline = sorted(timeline, key=lambda x: x.timestamp or "9999")[:300]
    search_rows = _build_search_rows(top_actions, root_causes, timeline, wufb)
    return InsightBundle(score_result, top_actions, root_causes, timeline, wufb, search_rows)


def build_wufb_summary(wu_parser) -> WufbSummary:
    entries = []
    if not wu_parser:
        return WufbSummary("Unknown", entries)

    info = getattr(getattr(wu_parser, "orchestrator", None), "info", {}) or {}
    policies = getattr(getattr(wu_parser, "policies", None), "entries", []) or []

    for label in ("Reboot Required", "Pre-shutdown Reboot Required",
                  "Feature Update Pause Enabled", "Quality Update Pause Enabled",
                  "Feature Update Deferral (days)", "Quality Update Deferral (days)",
                  "Next WU Refresh Time", "WUfB Policy Hash", "WUfB Policy Sync Date"):
        if info.get(label):
            sev = "WARNING" if "Required" in label and info[label] == "Yes" else "INFO"
            entries.append(InsightItem(sev, label, info[label], source="WU Orchestrator"))

    for p in policies:
        label = p.get("label", p.get("name", "Policy"))
        value = p.get("value", "")
        sev = "INFO"
        if "Disable" in label and "Yes" in value:
            sev = "WARNING"
        if "Deferral" in label:
            try:
                if int(str(value).split()[0]) > 30:
                    sev = "WARNING"
            except Exception:
                pass
        entries.append(InsightItem(sev, label, value, source=p.get("key_path", "WU Policy")))

    if not entries:
        return WufbSummary("No WUfB data found", entries)
    if any(e.severity == "ERROR" for e in entries):
        status = "Action required"
    elif any(e.severity == "WARNING" for e in entries):
        status = "Review recommended"
    else:
        status = "No blocking WUfB issue detected"
    return WufbSummary(status, entries)


def _build_search_rows(actions, causes, timeline, wufb):
    rows = []
    for item in actions:
        rows.append(("Top action", item.severity, item.title, item.detail, item.source))
    for item in causes:
        rows.append(("Root cause", item.severity, item.title, item.detail, item.source))
    for item in wufb.entries:
        rows.append(("WUfB", item.severity, item.title, item.detail, item.source))
    for item in timeline:
        rows.append(("Timeline", item.severity, item.title, item.detail, item.source))
    return rows
