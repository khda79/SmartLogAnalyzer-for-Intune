"""
error_detector.py
Scans Intune IME log files for errors and warnings.
Groups events by log theme (agentexecutor, appworkload, etc.).
Supports SCCM/IME log format and plain-text keyword scanning.
"""

import os
import re
from dataclasses import dataclass
from typing import Optional, List, Dict

IME_THEMES = [
    "agentexecutor", "appactionprocessor", "appworkload",
    "clientcertcheck", "clienthealth", "devicehealthmonitoring",
    "healthscripts", "intunemanagementextension", "intuneremediations",
    "notificationinfralogs", "sensor", "win32appinventory",
]

MDM_ERROR_CODES = {
    "0x80180001": "MDM_ENROLLMENT_FAILED",
    "0x80180002": "MDM_ENROLLMENT_INVALID_SERVER",
    "0x80180003": "MDM_ENROLLMENT_TRANSPORT_ERROR",
    "0x80180004": "MDM_ENROLLMENT_POLICY_ERROR",
    "0x80180005": "MDM_ENROLLMENT_CLIENT_CERT_FAILED",
    "0x80180006": "MDM_ENROLLMENT_SERVER_CERT_FAILED",
    "0x80180007": "MDM_ENROLLMENT_SYNC_FAILED",
    "0x80180008": "MDM_ENROLLMENT_NOT_SUPPORTED",
    "0x80180009": "MDM_ENROLLMENT_BLOCKED",
    "0x8018000A": "MDM_ENROLLMENT_ALREADY_ENROLLED",
    "0x80180014": "MDM_ENROLLMENT_QUOTA_EXCEEDED",
    "0x87D10001": "COMPLIANCE_FAILED",
    "0x87D10002": "COMPLIANCE_POLICY_NOT_FOUND",
    "0x87D11001": "APP_INSTALL_FAILED",
    "0x87D11003": "APP_NOT_APPLICABLE",
    "0x87D11004": "APP_INSTALL_TIMEOUT",
    "0x87D11006": "APP_SUPERSEDED",
    "0x87D11007": "APP_DETECTION_FAILED",
    "0x87D1FDE8": "APP_INSTALL_ERROR_GENERIC",
    "0x80070002": "FILE_NOT_FOUND",
    "0x80070005": "ACCESS_DENIED",
    "0x80070057": "INVALID_PARAMETER",
    "0x800704CF": "NETWORK_NOT_AVAILABLE",
    "0x80072EE2": "WINHTTP_TIMEOUT",
    "0x80072EE7": "WINHTTP_SERVER_NOT_FOUND",
    "0x80072EFD": "WINHTTP_CONNECTION_ABORTED",
    "0x80072EFE": "WINHTTP_CONNECTION_RESET",
    "0xCAA5001C": "AAD_TOKEN_BROKER_FAILED",
    "0xCAA20003": "AAD_INVALID_GRANT",
}
_MDM_UPPER = {k.upper(): v for k, v in MDM_ERROR_CODES.items()}

_IME_LOG_RE = re.compile(
    r'<!\[LOG\[(.*?)\]LOG\]!>'
    r'<time="([\d:.]+)"[^>]*'
    r'date="([\d-]+)"[^>]*'
    r'component="([^"]*)"[^>]*'
    r'type="(\d+)"',
    re.DOTALL
)
_hex_re = re.compile(r'0[xX][0-9A-Fa-f]{4,8}')

_ERROR_KW = ["error", "failed", "failure", "exception", "critical"]
_WARN_KW  = ["warning", "warn", "timeout", "retry"]
_IGNORE_KW = ["no error", "no failure", "errorlevel 0", "0 error", "success"]


@dataclass
class LogEvent:
    severity:    str
    category:    str
    message:     str
    source_file: str
    theme:       str  = ""
    line_number: int  = 0
    raw_line:    str  = ""
    timestamp:   str  = ""
    error_code:  str  = ""
    known_code:  str  = ""
    log_format:  str  = "text"


def _detect_theme(file_path):
    bn = os.path.basename(file_path).lower()
    for theme in IME_THEMES:
        if bn.startswith(theme):
            return theme
    return "other"


class ErrorDetector:
    """Scans IME log files and groups events by theme."""

    def __init__(self):
        self.events:          List[LogEvent]            = []
        self.events_by_theme: Dict[str, List[LogEvent]] = {}
        self.scanned_files:   List[str]                 = []
        self._error_count   = 0
        self._warning_count = 0

    def scan_files(self, file_paths):
        for fp in file_paths:
            if not os.path.isfile(fp):
                continue
            self._dispatch_file(fp)
        return self.events

    def scan_theme_files(self, theme, file_paths):
        """Scan files belonging to a specific IME theme."""
        for fp in file_paths:
            if not os.path.isfile(fp):
                continue
            self._dispatch_file(fp, force_theme=theme)
        return self.events_by_theme.get(theme, [])

    def _dispatch_file(self, file_path, force_theme=None):
        theme = force_theme or _detect_theme(file_path)
        content = self._read_file(file_path)
        if content is None:
            return
        if "<![LOG[" in content:
            self._scan_ime_log(file_path, content, theme)
        else:
            self._scan_text_file(file_path, content, theme)

    def _read_file(self, file_path):
        if os.path.getsize(file_path) > 20 * 1024 * 1024:
            return None
        for enc in ("utf-8", "utf-16", "latin-1", "cp1252"):
            try:
                with open(file_path, "r", encoding=enc, errors="replace") as f:
                    return f.read()
            except Exception:
                continue
        return None

    def _add_event(self, ev):
        self.events.append(ev)
        self.events_by_theme.setdefault(ev.theme, []).append(ev)
        if ev.severity == "ERROR":
            self._error_count += 1
        else:
            self._warning_count += 1

    def _scan_ime_log(self, file_path, content, theme):
        short = os.path.basename(file_path)
        self.scanned_files.append(file_path)
        seen = set()

        for m in _IME_LOG_RE.finditer(content):
            message   = m.group(1).strip()
            time_str  = m.group(2)
            date_str  = m.group(3)
            component = m.group(4)
            type_num  = m.group(5)

            if type_num not in ("2", "3"):
                continue

            severity = "ERROR" if type_num == "3" else "WARNING"
            ts = f"{date_str} {time_str}"

            dedup_key = (short, message[:80])
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            code = known = ""
            for cm in _hex_re.finditer(message):
                cand = cm.group(0).upper()
                if cand in _MDM_UPPER:
                    code  = cm.group(0)
                    known = _MDM_UPPER[cand]
                    severity = "ERROR"
                    break

            self._add_event(LogEvent(
                severity=severity, category=component or theme.upper(),
                message=message[:300], source_file=short, theme=theme,
                raw_line=message[:500], timestamp=ts,
                error_code=code, known_code=known, log_format="ime",
            ))

    def _scan_text_file(self, file_path, content, theme):
        short = os.path.basename(file_path)
        self.scanned_files.append(file_path)

        for lineno, line in enumerate(content.splitlines(), 1):
            ll = line.lower()
            if any(ign in ll for ign in _IGNORE_KW):
                continue

            severity = None
            if any(kw in ll for kw in _ERROR_KW):
                severity = "ERROR"
            elif any(kw in ll for kw in _WARN_KW):
                severity = "WARNING"

            if not severity:
                for cm in _hex_re.finditer(line):
                    if cm.group(0).upper() in _MDM_UPPER:
                        severity = "ERROR"
                        break

            if not severity:
                continue

            code = known = ""
            for cm in _hex_re.finditer(line):
                cand = cm.group(0).upper()
                if cand in _MDM_UPPER:
                    code  = cm.group(0)
                    known = _MDM_UPPER[cand]
                    break

            self._add_event(LogEvent(
                severity=severity, category="Log", message=line.strip()[:300],
                source_file=short, theme=theme, line_number=lineno,
                raw_line=line.strip()[:500], error_code=code, known_code=known,
                log_format="text",
            ))

    def get_summary(self):
        theme_counts = {
            t: {"errors": sum(1 for e in evs if e.severity == "ERROR"),
                "warnings": sum(1 for e in evs if e.severity == "WARNING")}
            for t, evs in self.events_by_theme.items()
        }
        return {
            "error_count":   self._error_count,
            "warning_count": self._warning_count,
            "total_events":  len(self.events),
            "scanned_files": len(self.scanned_files),
            "theme_counts":  theme_counts,
        }

    def clear(self):
        self.events.clear()
        self.events_by_theme.clear()
        self.scanned_files.clear()
        self._error_count   = 0
        self._warning_count = 0
