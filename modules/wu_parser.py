"""
wu_parser.py
Parses Windows Update diagnostic data from Intune Device Diagnostics ZIP.

Sources:
  - (N) RegistryKey HKLM_SOFTWARE_Microsoft_Windows_CurrentVersion_WindowsUpdate_Orchestrator export.reg
  - (N) FoldersFiles windir_Logs_WindowsUpdate_etl  (binary ETL - decoded via tracerpt.exe)
"""

import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional


# ---------------------------------------------------------------------------
# Known Windows Update HRESULT / error codes
# ---------------------------------------------------------------------------
WU_ERROR_CODES = {
    "0x80240001": "WU_E_NO_SERVICE - Windows Update service not found",
    "0x80240002": "WU_E_MAX_CAPACITY_REACHED - Maximum capacity reached",
    "0x80240016": "WU_E_INSTALL_NOT_ALLOWED - Install not allowed while running",
    "0x80240017": "WU_E_NOT_APPLICABLE - Update not applicable to this device",
    "0x8024001b": "WU_E_SELFUPDATE_IN_PROGRESS - Self-update in progress",
    "0x80240020": "WU_E_NO_INTERACTIVE_USER - No interactive user logged on",
    "0x80240022": "WU_E_XML_MISSINGDATA - Missing required XML data",
    "0x80240032": "WU_E_INVALID_CRITERIA - Invalid search criteria",
    "0x8024200B": "WU_E_UH_INSTALLERFAILURE - Installer returned failure",
    "0x80242006": "WU_E_UH_INVALIDMETADATA - Invalid update metadata",
    "0x80244007": "WU_E_PT_SOAPCLIENT_SOAPFAULT - SOAP fault from server",
    "0x8024402F": "WU_E_PT_ECP_SUCCEEDED_WITH_ERRORS - Cab file parse errors",
    "0x80244022": "WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL - HTTP 503 (server busy)",
    "0x80244010": "WU_E_PT_EXCEEDED_MAX_SERVER_TRIPS - Too many round trips to server",
    "0x8024D001": "WU_E_SETUP_INVALID_INFDATA - Invalid INF data",
    "0x8024D00F": "WU_E_SETUP_HANDLER_EXEC_FAILURE - Setup handler failed",
    "0x80070002": "ERROR_FILE_NOT_FOUND",
    "0x80070005": "ERROR_ACCESS_DENIED",
    "0x80070070": "ERROR_DISK_FULL",
    "0x8007000E": "ERROR_OUTOFMEMORY",
    "0x800705B4": "ERROR_TIMEOUT",
    "0x80070422": "ERROR_SERVICE_DISABLED - Windows Update service disabled",
    "0x80131500": "COR_E_EXCEPTION (.NET runtime exception)",
    "0xC1900208": "Compatibility check failed (upgrade blocked by app)",
    "0xC1900101": "Driver compatibility issue (rollback occurred)",
    "0xC1900200": "Device not eligible for upgrade",
    "0xC190020e": "Insufficient disk space for upgrade",
    "0x8007371b": "ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE",
    "0x80073701": "ERROR_SXS_ASSEMBLY_MISSING - Corrupt system files",
}


# ---------------------------------------------------------------------------
@dataclass
class WUEvent:
    timestamp:  str = ""
    level:      str = ""      # "Error", "Warning", "Information"
    source:     str = ""
    event_id:   str = ""
    message:    str = ""
    error_code: str = ""
    etl_file:   str = ""
    raw:        str = ""


# ---------------------------------------------------------------------------
class WUOrchestratorParser:
    """
    Parses the WindowsUpdate\\Orchestrator registry export.
    Extracts OS build, UBR, reboot state, scan/install timestamps,
    WUfB policy hash, and flight info.
    """

    _ROOT = "hkey_local_machine\\software\\microsoft\\windows\\currentversion\\windowsupdate\\orchestrator"

    # Human-readable labels for key names
    _LABELS = {
        # OS / build
        "OsVersion":                   "OS Version",
        "BuildString":                 "OS Build",
        "UBR":                         "Update Build Revision (UBR)",
        # Reboot state
        "Preshutdown":                 "Pre-shutdown Reboot Required",
        "RebootRequired":              "Reboot Required",
        "RebootRequiredReason":        "Reboot Required Reason",
        "DisabledAutomaticRestarts":   "Automatic Restarts Disabled",
        # Init / failures
        "UpdateManagerCtorFailures":   "Update Manager Init Failures",
        # Modern Orchestrator Stack
        "MoStackEnabled":              "Modern Orchestrator Enabled",
        "MostackEnabled":              "Modern Orchestrator Enabled",
        "MoStack":                     "Modern Orchestrator Active",
        # OOBE / setup
        "OobeCompleteTimeStamp":       "OOBE Completion Date",
        # WUfB policy
        "WUfBPolicyHash":              "WUfB Policy Hash",
        "PolicyReportHash":            "WUfB Policy Hash",
        "PolicyReportTimestamp":       "WUfB Policy Sync Date",
        "SettingsETag":                "WUfB Settings ETag",
        "SettingsRefreshInterval":     "Settings Refresh Interval",
        # Scan / install timing
        "ScanTriggerTime":             "Last Scan Trigger Time",
        "PerformScanTriggerTime":      "Next Scan Trigger Time",
        "InstallTriggerTime":          "Last Install Trigger Time",
        "NextRefreshTime":             "Next WU Refresh Time",
        # Pause / deferral
        "FeatureUpdatePauseEnabled":   "Feature Update Pause Enabled",
        "QualityUpdatePauseEnabled":   "Quality Update Pause Enabled",
        "DeferFeatureUpdatePeriodInDays":  "Feature Update Deferral (days)",
        "DeferQualityUpdatePeriodInDays":  "Quality Update Deferral (days)",
        # Flights / rings
        "FlightInfo":                  "Flight Info",
        "FlightPendingCommit":         "Flight Pending Commit",
    }

    def __init__(self):
        self.info: Dict[str, str] = {}
        self.raw_keys: Dict[str, Dict[str, str]] = {}

    def parse(self, reg_file: str) -> bool:
        if not os.path.isfile(reg_file):
            return False
        content = self._read_reg(reg_file)
        if not content:
            return False
        self._parse_reg_content(content)
        self._extract_info()
        return True

    @staticmethod
    def _read_reg(path: str) -> str:
        for enc in ["utf-16", "utf-8", "latin-1"]:
            try:
                with open(path, "r", encoding=enc, errors="replace") as f:
                    return f.read()
            except Exception:
                continue
        return ""

    def _parse_reg_content(self, content: str):
        current = None
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1]
                self.raw_keys.setdefault(current, {})
            elif "=" in line and current:
                name, _, val = line.partition("=")
                self.raw_keys[current][name.strip().strip('"')] = val.strip()

    def _extract_info(self):
        """Pull human-readable values from the parsed registry tree."""
        for key_path, values in self.raw_keys.items():
            if self._ROOT not in key_path.lower():
                continue
            for raw_name, raw_val in values.items():
                label = self._LABELS.get(raw_name, raw_name)
                decoded = self._decode_value(raw_name, raw_val)
                if decoded:
                    self.info[label] = decoded

    def _decode_value(self, name: str, val: str) -> str:
        """Convert raw registry value to display string."""
        # DWORD
        dw = re.match(r'dword:([0-9a-fA-F]+)', val, re.IGNORECASE)
        if dw:
            n = int(dw.group(1), 16)
            # Boolean-style fields
            if name in ("Preshutdown", "RebootRequired",
                        "DisabledAutomaticRestarts",
                        "FeatureUpdatePauseEnabled",
                        "QualityUpdatePauseEnabled"):
                return "Yes" if n else "No"
            if name == "UpdateManagerCtorFailures":
                return f"{n}"
            if name in ("DeferFeatureUpdatePeriodInDays",
                        "DeferQualityUpdatePeriodInDays"):
                return f"{n} day(s)"
            if name == "UBR":
                return f"{n}  (hex: 0x{n:04x})"
            return str(n)

        # QWORD (Windows FILETIME — 100ns intervals since 1601-01-01)
        qw = re.match(r'hex\(b\):([0-9a-fA-F,]+)', val, re.IGNORECASE)
        if qw:
            try:
                bs = bytes.fromhex(qw.group(1).replace(",", ""))
                # Little-endian 64-bit
                ft = int.from_bytes(bs, "little")
                if ft > 0:
                    return self._filetime_to_str(ft)
            except Exception:
                pass
            return val

        # Hex binary blob
        if val.lower().startswith("hex:"):
            return f"<binary {len(val)} bytes>"

        # String — strip surrounding quotes
        s = val.strip('"')
        return s if s else ""

    @staticmethod
    def _filetime_to_str(ft: int) -> str:
        """Convert Windows FILETIME to human-readable UTC string."""
        try:
            # FILETIME epoch: Jan 1, 1601
            epoch_diff = 116444736000000000  # 100ns intervals between 1601 and 1970
            unix_us = (ft - epoch_diff) // 10  # microseconds
            dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=unix_us)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return f"<filetime 0x{ft:016x}>"

    def get_summary_lines(self) -> List[str]:
        lines = []
        if not self.info:
            lines.append("  No data found in Windows Update Orchestrator registry key.")
            return lines
        for label, value in self.info.items():
            lines.append(f"  {label:<42} {value}")
        return lines

    def get_issues(self) -> List[Dict]:
        issues = []

        if self.info.get("Reboot Required") == "Yes":
            issues.append({
                "severity": "WARNING",
                "title": "Reboot required",
                "detail": "RebootRequired=Yes in WU Orchestrator registry",
                "recommendation": "Device needs a reboot to complete pending updates.",
            })
        if self.info.get("Pre-shutdown Reboot Required") == "Yes":
            issues.append({
                "severity": "WARNING",
                "title": "Pre-shutdown reboot pending",
                "detail": "Preshutdown=Yes — a reboot was requested at last shutdown",
                "recommendation": "Ensure device reboots to complete Windows Update installation.",
            })

        failures = self.info.get("Update Manager Init Failures", "0")
        try:
            if int(failures) > 0:
                issues.append({
                    "severity": "ERROR",
                    "title": f"Update Manager initialization failed {failures} time(s)",
                    "detail": f"UpdateManagerCtorFailures={failures}",
                    "recommendation": "Check Windows Update service state and event logs.",
                })
        except ValueError:
            pass

        # Next refresh time at Windows FILETIME epoch (1601) = WU scan not scheduled
        next_refresh = self.info.get("Next WU Refresh Time", "")
        if next_refresh.startswith("1601-"):
            issues.append({
                "severity": "WARNING",
                "title": "Windows Update scan not scheduled",
                "detail": f"NextRefreshTime is at epoch ({next_refresh}) — WU is not planning a scan",
                "recommendation": "Check WU service state. Run 'wuauclt /detectnow' or restart the Windows Update service.",
            })

        # Feature/quality update paused
        if self.info.get("Feature Update Pause Enabled") == "Yes":
            issues.append({
                "severity": "WARNING",
                "title": "Feature updates are paused",
                "detail": "FeatureUpdatePauseEnabled=Yes",
                "recommendation": "Verify that update pause is intentional via WUfB policy.",
            })
        if self.info.get("Quality Update Pause Enabled") == "Yes":
            issues.append({
                "severity": "WARNING",
                "title": "Quality updates are paused",
                "detail": "QualityUpdatePauseEnabled=Yes",
                "recommendation": "Verify that update pause is intentional via WUfB policy.",
            })

        # Deferral > 30 days
        for lbl, key in (("Feature Update Deferral (days)", "feature"),
                         ("Quality Update Deferral (days)", "quality")):
            val = self.info.get(lbl, "")
            m = re.match(r"(\d+)", val)
            if m and int(m.group(1)) > 30:
                issues.append({
                    "severity": "WARNING",
                    "title": f"{key.capitalize()} update deferral > 30 days ({val})",
                    "detail": f"{lbl}: {val}",
                    "recommendation": "Ensure deferral is aligned with your patch management policy.",
                })

        return issues


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
class ReportingEventsParser:
    """
    Parses SoftwareDistribution\\ReportingEvents.log (UTF-16 LE, tab-separated).

    Column layout (0-indexed):
      0  {SessionGUID}
      1  YYYY-MM-DD HH:MM:SS:mmm+TZ
      2  client-type (usually "1")
      3  EventID [EVENT_NAME]
      4  UpdateType (101=Software, 200=Driver)
      5  {UpdateGUID}
      6  priority
      7  HResult hex WITHOUT 0x prefix  (0 = success)
      8  ClientID / caller
      9  Success | Failure
      10 Operation type
      11 Message text
      12 session-tracking string
    """

    # Event names that are always failures worth reporting
    _FAIL_EVENTS = {
        "AGENT_DETECTION_FAILED",
        "AGENT_INSTALLING_FAILED",
        "AGENT_DOWNLOAD_FAILED",
    }
    # Event names that are warnings (non-zero HResult but recoverable)
    _WARN_EVENTS = {
        "AGENT_DOWNLOAD_CANCELED",
    }

    def __init__(self):
        self.events: List[WUEvent] = []
        self.error_count:   int = 0
        self.warning_count: int = 0
        self.total_lines:   int = 0
        self.last_status:   str = ""

    def parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        content = self._read(file_path)
        if not content:
            return False

        seen: set = set()          # used only for unique-count display
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            self.total_lines += 1
            ev = self._parse_line(line)
            if ev is None:
                continue
            # All events are kept (no deduplication) so the table shows every row
            self.events.append(ev)
            if ev.level == "Error":
                self.error_count += 1
            else:
                self.warning_count += 1
            # Track unique (source, error_code) pairs for the status label
            seen.add((ev.source, ev.error_code))

        unique = len(seen)
        self.last_status = (
            f"ReportingEvents.log: {self.total_lines} entries — "
            f"{self.error_count} errors, {self.warning_count} warnings "
            f"({unique} unique error types)")
        return True

    @staticmethod
    def _read(path: str) -> str:
        """Read UTF-16 LE (with or without BOM), fall back to cp1252."""
        for enc in ("utf-16", "utf-16-le", "utf-8", "cp1252", "latin-1"):
            try:
                with open(path, encoding=enc, errors="replace") as f:
                    txt = f.read()
                # Sanity check: should have tabs and GUIDs
                if "\t" in txt and "{" in txt:
                    return txt
            except Exception:
                continue
        return ""

    def _parse_line(self, line: str) -> Optional[WUEvent]:
        fields = line.split("\t")
        if len(fields) < 12:
            return None

        timestamp_raw = fields[1].strip()
        event_str     = fields[3].strip()   # "148 [AGENT_DETECTION_FAILED]"
        hresult_hex   = fields[7].strip()   # "80244007" or "0"
        status        = fields[9].strip()   # "Success" / "Failure"
        operation     = fields[10].strip()  # "Software Synchronization"
        message       = fields[11].strip()  # human-readable message

        # Extract event name from brackets
        m = re.search(r'\[([A-Z_]+)\]', event_str)
        event_name = m.group(1) if m else event_str

        # Determine level
        level = ""
        if event_name in self._FAIL_EVENTS or status == "Failure":
            level = "Error"
        elif event_name in self._WARN_EVENTS:
            level = "Warning"

        # Also flag any non-zero HResult even on "Success" status
        if not level and hresult_hex not in ("0", ""):
            try:
                hr = int(hresult_hex, 16)
                if hr & 0x80000000:   # HRESULT error bit set
                    level = "Error"
            except ValueError:
                pass

        if not level:
            return None

        # Format error code
        err_code = ""
        if hresult_hex not in ("0", ""):
            try:
                err_code = f"0x{int(hresult_hex, 16):08X}"
            except ValueError:
                err_code = hresult_hex

        # Clean timestamp: "2026-04-20 21:13:58:565+0200" → "2026-04-20 21:13:58"
        ts = re.sub(r':\d{3}[+-]\d{4}$', '', timestamp_raw).strip()

        return WUEvent(
            timestamp=ts,
            level=level,
            source=event_name,
            event_id="",
            message=message[:240],
            error_code=err_code,
            etl_file="ReportingEvents.log",
            raw=line[:400],
        )


class WUEtlParser:
    """
    Reads Windows Update ETL files.
    Primary method  : PowerShell Get-WinEvent -Path (decodes via installed manifests)
    Fallback method : tracerpt.exe (produces XML but EventData is often binary)
    """

    def __init__(self):
        self.events:          List[WUEvent] = []
        self.error_count:     int = 0
        self.warning_count:   int = 0
        self.etl_files_count: int = 0
        self.last_status:     str = ""
        self._use_powershell: Optional[bool] = None   # cached probe result

    # ------------------------------------------------------------------
    @staticmethod
    def is_tracerpt_available() -> bool:
        try:
            r = subprocess.run(["tracerpt.exe", "/?"],
                               capture_output=True, timeout=5)
            return r.returncode in (0, 1)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def is_powershell_available() -> bool:
        try:
            r = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive",
                 "-Command", "Write-Output OK"],
                capture_output=True, timeout=10)
            return b"OK" in r.stdout
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return False

    # HRESULT patterns & keyword upgrades
    _HRESULT_RE = re.compile(
        r'0x[89Cc][0-9A-Fa-f]{7}|0xC19[0-9A-Fa-f]{5}',
        re.IGNORECASE)
    _ERR_KEYWORDS = re.compile(
        r'\berr(?:or)?\b|\bfail(?:ed|ure)?\b|\bexception\b|\bcritical\b',
        re.IGNORECASE)
    _WARN_KEYWORDS = re.compile(
        r'\bwarn(?:ing)?\b|\bretry\b|\btimeout\b|\bdefer(?:red)?\b|\bpending\b',
        re.IGNORECASE)

    # ------------------------------------------------------------------
    def scan_etl_files(self, etl_files: List[str],
                       progress_cb=None, max_files: int = 50) -> bool:
        self.events = []
        self.error_count = 0
        self.warning_count = 0
        self.etl_files_count = len(etl_files)

        # Probe once which decoder to use
        if self._use_powershell is None:
            self._use_powershell = self.is_powershell_available()

        files_to_scan = etl_files[:max_files]
        success = False

        for idx, etl_path in enumerate(files_to_scan, 1):
            fname = os.path.basename(etl_path)
            if progress_cb:
                progress_cb(idx, len(files_to_scan), fname)

            evs = None
            if self._use_powershell:
                evs = self._decode_powershell(etl_path)
            if evs is None:                          # PS failed → try tracerpt
                evs = self._decode_tracerpt(etl_path)
            if evs is not None:
                self.events.extend(evs)
                success = True

        self.error_count   = sum(1 for e in self.events if e.level == "Error")
        self.warning_count = sum(1 for e in self.events if e.level == "Warning")
        info_count         = sum(1 for e in self.events
                                 if e.level not in ("Error", "Warning"))
        method = "Get-WinEvent" if self._use_powershell else "tracerpt"
        self.last_status = (
            f"Scanned {len(files_to_scan)}/{self.etl_files_count} ETL files "
            f"({method})  —  "
            f"{self.error_count} errors, {self.warning_count} warnings, "
            f"{info_count} informational")
        return success

    # ------------------------------------------------------------------
    def _decode_powershell(self, etl_path: str) -> Optional[List[WUEvent]]:
        """
        Use PowerShell Get-WinEvent -Path to decode a single ETL file.
        PowerShell uses locally registered event manifests, producing
        human-readable Message text (unlike tracerpt which gives raw binary).
        """
        import json as _json

        # Build a compact PS one-liner that outputs JSON
        ps_cmd = (
            "$evs = Get-WinEvent -Path '" + etl_path.replace("'", "''") + "' "
            "-ErrorAction SilentlyContinue; "
            "if ($evs) { $evs | Select-Object "
            "@{N='ts';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, "
            "@{N='id';E={$_.Id}}, "
            "@{N='level';E={$_.Level}}, "
            "@{N='lvl';E={$_.LevelDisplayName}}, "
            "@{N='prov';E={$_.ProviderName}}, "
            "@{N='msg';E={$_.Message}} | ConvertTo-Json -Compress }"
        )
        try:
            r = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive",
                 "-Command", ps_cmd],
                capture_output=True, timeout=60)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return None

        raw = r.stdout.decode("utf-8", errors="replace").strip()
        if not raw:
            return []   # file decoded OK but contained 0 events

        try:
            data = _json.loads(raw)
        except _json.JSONDecodeError:
            return None

        if isinstance(data, dict):
            data = [data]

        events = []
        fname = os.path.basename(etl_path)
        for ev in data:
            level_val = ev.get("level", 4) or 4
            level_str = {1: "Critical", 2: "Error", 3: "Warning",
                         4: "Information", 5: "Verbose"}.get(
                int(level_val), "Information")
            # Use LevelDisplayName if available
            lvl_name = (ev.get("lvl") or "").strip()
            if lvl_name in ("Critical", "Error", "Warning",
                            "Information", "Verbose"):
                level_str = lvl_name

            msg = (ev.get("msg") or "").strip()

            # Upgrade level by keywords in the decoded message
            if level_str in ("Information", "Verbose"):
                if self._ERR_KEYWORDS.search(msg):
                    level_str = "Error"
                elif self._WARN_KEYWORDS.search(msg):
                    level_str = "Warning"

            codes = self._HRESULT_RE.findall(msg)
            err_code = codes[0] if codes else ""

            events.append(WUEvent(
                timestamp=str(ev.get("ts") or ""),
                level=level_str,
                source=str(ev.get("prov") or "")[:40],
                event_id=str(ev.get("id") or ""),
                message=msg[:300],
                error_code=err_code,
                etl_file=fname,
                raw=msg[:600],
            ))
        return events

    # ------------------------------------------------------------------
    def _decode_tracerpt(self, etl_path: str) -> Optional[List[WUEvent]]:
        """Fallback: decode via tracerpt.exe → XML."""
        with tempfile.TemporaryDirectory() as tmp:
            xml_out = os.path.join(tmp, "out.xml")
            try:
                subprocess.run(
                    ["tracerpt.exe", etl_path,
                     "-of", "XML", "-o", xml_out, "-y"],
                    capture_output=True, timeout=30)
            except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
                return None
            if not os.path.isfile(xml_out):
                return None
            return self._parse_tracerpt_xml(xml_out, os.path.basename(etl_path))

    def _parse_tracerpt_xml(self, xml_path: str,
                             source_file: str) -> List[WUEvent]:
        """Parse tracerpt XML (EventData may be binary, so keyword-match carefully)."""
        events = []
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError:
            return events

        for ev_el in root.iter("Event"):
            sys_el = ev_el.find("System") or ev_el.find(".//System")
            if sys_el is None:
                continue
            level_el    = sys_el.find("Level")
            ts_el       = sys_el.find("TimeCreated")
            provider_el = sys_el.find("Provider")
            eventid_el  = sys_el.find("EventID")

            try:
                level_val = int((level_el.text or
                                 level_el.get("Value", "4"))
                                if level_el is not None else 4)
            except (ValueError, AttributeError):
                level_val = 4

            level_str = {1: "Error", 2: "Error", 3: "Warning",
                         4: "Information", 5: "Verbose"}.get(
                level_val, "Information")

            data_el   = ev_el.find(".//EventData")
            data_text = " ".join(
                (el.text or "") for el in data_el.iter()
            ) if data_el is not None else ""

            if level_str in ("Information", "Verbose"):
                if self._ERR_KEYWORDS.search(data_text):
                    level_str = "Error"
                elif self._WARN_KEYWORDS.search(data_text):
                    level_str = "Warning"

            ts = ""
            if ts_el is not None:
                ts = ts_el.get("SystemTime", "") or (ts_el.text or "")
            if "." in ts:
                ts = ts[:19].replace("T", " ")

            provider = ""
            if provider_el is not None:
                provider = (provider_el.get("Name", "")
                            or provider_el.get("Guid", ""))

            codes = self._HRESULT_RE.findall(data_text)
            events.append(WUEvent(
                timestamp=ts,
                level=level_str,
                source=provider[:40],
                event_id=(eventid_el.text or "") if eventid_el is not None else "",
                message=data_text[:300].strip(),
                error_code=codes[0] if codes else "",
                etl_file=source_file,
                raw=data_text[:600],
            ))
        return events




# ---------------------------------------------------------------------------
class WUPoliciesParser:
    """
    Scans ALL .reg files in the ZIP for HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate
    keys and sub-keys (AU, etc.).
    Extracts and labels every value found.
    """

    _ROOT = "hkey_local_machine\\software\\policies\\microsoft\\windows\\windowsupdate"

    # Human-readable labels (value name -> display label)
    _LABELS = {
        # --- WU / WUfB main key ---
        "WUServer":                                     "WSUS Server URL",
        "WUStatusServer":                               "WSUS Status Server URL",
        "TargetGroup":                                  "Target Group Name",
        "TargetGroupEnabled":                           "Target Group Enabled",
        "DisableWindowsUpdateAccess":                   "Disable WU Access for non-admins",
        "DisableDualScan":                              "Disable Dual Scan (force WSUS only)",
        "ExcludeWUDriversInQualityUpdate":              "Exclude Drivers from Quality Updates",
        "AllowMUUpdateService":                         "Allow Microsoft Update Service",
        "SetPolicyDrivenUpdateSourceForFeatureUpdates": "Policy-Driven Source: Feature Updates",
        "SetPolicyDrivenUpdateSourceForQualityUpdates": "Policy-Driven Source: Quality Updates",
        "SetPolicyDrivenUpdateSourceForDriverUpdates":  "Policy-Driven Source: Driver Updates",
        "SetPolicyDrivenUpdateSourceForOtherUpdates":   "Policy-Driven Source: Other Updates",
        # --- Deferral / Pause ---
        "DeferFeatureUpdates":                          "Defer Feature Updates",
        "DeferFeatureUpdatesPeriodInDays":              "Feature Update Deferral (days)",
        "PauseFeatureUpdatesStartTime":                 "Feature Updates Paused Since",
        "DeferQualityUpdates":                          "Defer Quality Updates",
        "DeferQualityUpdatesPeriodInDays":              "Quality Update Deferral (days)",
        "PauseQualityUpdatesStartTime":                 "Quality Updates Paused Since",
        "BranchReadinessLevel":                         "WUfB Ring / Branch Readiness",
        "ActiveHoursStart":                             "Active Hours Start",
        "ActiveHoursEnd":                               "Active Hours End",
        "ActiveHoursMaxRange":                          "Active Hours Max Range",
        "SetDisablePauseUXAccess":                      "Disable Pause Button in UI",
        "SetDisableUXWUAccess":                         "Disable WU UI Access",
        "ManagePreviewBuilds":                          "Manage Preview Builds",
        "ProductVersion":                               "Product Version (upgrade target)",
        "TargetReleaseVersion":                         "Target Release Version Enabled",
        "TargetReleaseVersionInfo":                     "Target Release Version",
        "ConfigureDeadlineForFeatureUpdates":           "Deadline: Feature Updates (days)",
        "ConfigureDeadlineForQualityUpdates":           "Deadline: Quality Updates (days)",
        "ConfigureDeadlineGracePeriod":                 "Deadline Grace Period (days)",
        "ConfigureDeadlineNoAutoReboot":                "Deadline: No Auto Reboot",
        "AutoRestartNotificationSchedule":              "Auto-Restart Notification Schedule",
        "EngagedRestartDeadline":                       "Engaged Restart Deadline (days)",
        "EngagedRestartSnoozeSchedule":                 "Engaged Restart Snooze (days)",
        "EngagedRestartTransitionSchedule":             "Engaged Restart Transition (days)",
        # --- AU sub-key ---
        "NoAutoUpdate":                                 "Disable Automatic Updates",
        "AUOptions":                                    "Automatic Updates Option",
        "UseWUServer":                                  "Use WSUS Server (AU)",
        "ScheduledInstallDay":                          "Scheduled Install Day",
        "ScheduledInstallTime":                         "Scheduled Install Time",
        "EnableFeaturedSoftware":                       "Enable Featured Software",
        "IncludeRecommendedUpdates":                    "Include Recommended Updates",
        "AutoInstallMinorUpdates":                      "Auto-Install Minor Updates",
        "RebootWarningFrequency":                       "Reboot Warning Frequency (min)",
        "RebootRelaunchTimeout":                        "Reboot Relaunch Timeout (min)",
    }

    # DWORD values that are boolean (0=No, 1=Yes)
    _BOOL_VALUES = {
        "TargetGroupEnabled", "DisableWindowsUpdateAccess", "DisableDualScan",
        "ExcludeWUDriversInQualityUpdate", "AllowMUUpdateService",
        "SetPolicyDrivenUpdateSourceForFeatureUpdates",
        "SetPolicyDrivenUpdateSourceForQualityUpdates",
        "SetPolicyDrivenUpdateSourceForDriverUpdates",
        "SetPolicyDrivenUpdateSourceForOtherUpdates",
        "DeferFeatureUpdates", "DeferQualityUpdates",
        "TargetReleaseVersion", "SetDisablePauseUXAccess", "SetDisableUXWUAccess",
        "ConfigureDeadlineNoAutoReboot", "NoAutoUpdate", "UseWUServer",
        "EnableFeaturedSoftware", "IncludeRecommendedUpdates",
        "AutoInstallMinorUpdates",
    }

    _AU_OPTIONS = {
        2: "2 – Notify before download",
        3: "3 – Auto download, notify to install",
        4: "4 – Auto download and schedule install",
        5: "5 – Allow local admin to choose",
    }

    _BRANCH_LEVELS = {
        2:  "2 – Semi-Annual Channel (Targeted)",
        4:  "4 – Semi-Annual Channel",
        8:  "8 – Long-Term Servicing Channel (LTSC)",
        16: "16 – Windows Insider Fast",
        32: "32 – Windows Insider Slow",
    }

    def __init__(self):
        self.entries: List[Dict[str, str]] = []   # [{key_path, name, label, value}]
        self.source_files: List[str] = []          # reg files where WU policies were found
        self.found: bool = False

    def scan_reg_files(self, reg_files: List[str]) -> bool:
        """Scan a list of .reg file paths and collect all WU policy entries."""
        self.entries = []
        self.source_files = []
        self.found = False

        for path in reg_files:
            if not os.path.isfile(path):
                continue
            text = self._read_reg(path)
            if not text:
                continue
            hits = self._extract_wu_policies(text, os.path.basename(path))
            if hits:
                self.entries.extend(hits)
                self.source_files.append(os.path.basename(path))
                self.found = True

        return self.found

    def get_summary_lines(self) -> List[str]:
        """Return formatted lines for display in the text widget."""
        if not self.found:
            return [
                "  No Windows Update Group Policy keys found in any .reg file of this ZIP.",
                "",
                "  This is normal for devices managed exclusively via Microsoft Intune (MDM).",
                "  Intune Update Ring policies are stored in:",
                "    HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Update\\",
                "  and are not exported as a separate .reg file in the standard Intune diagnostics package.",
                "",
                "  If WU Group Policy (GPO) were active, keys would appear under:",
                "    HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\",
            ]
        lines = []
        current_path = None
        for e in self.entries:
            if e["key_path"] != current_path:
                current_path = e["key_path"]
                lines.append("")
                lines.append(f"  [{current_path}]")
            lines.append(f"    {e['label']:<52} {e['value']}")
        lines.append("")
        lines.append(f"  Source file(s): {', '.join(self.source_files)}")
        return lines

    # ------------------------------------------------------------------
    @staticmethod
    def _read_reg(path: str) -> str:
        for enc in ["utf-16", "utf-16-le", "utf-8", "latin-1"]:
            try:
                with open(path, "r", encoding=enc, errors="replace") as f:
                    txt = f.read()
                if "Windows Registry Editor" in txt or "REGEDIT" in txt.upper():
                    return txt
            except Exception:
                continue
        return ""

    def _extract_wu_policies(self, content: str, source: str) -> List[Dict]:
        """Parse content of one .reg file, return WU policy entries."""
        results = []
        current_key = None
        in_wu_section = False

        for raw_line in content.splitlines():
            line = raw_line.strip()

            # Section header
            if line.startswith("[") and line.endswith("]"):
                key = line[1:-1]
                current_key = key
                in_wu_section = self._ROOT in key.lower()
                continue

            if not in_wu_section or "=" not in line:
                continue

            # Value line
            name_raw, _, val_raw = line.partition("=")
            name = name_raw.strip().strip('"')
            val_raw = val_raw.strip()
            if name == "@":
                name = "(Default)"

            label = self._LABELS.get(name, name)
            value = self._decode_value(name, val_raw)

            # Friendly sub-key display
            sub = current_key.split("\\")
            try:
                wu_idx = next(i for i, p in enumerate(sub) if "windowsupdate" in p.lower())
                display_key = "\\".join(sub[wu_idx:])
            except StopIteration:
                display_key = current_key

            results.append({
                "key_path": display_key,
                "name":     name,
                "label":    label,
                "value":    value,
                "source":   source,
            })

        return results

    def _decode_value(self, name: str, val: str) -> str:
        # DWORD
        m = re.match(r"dword:([0-9a-fA-F]+)", val, re.IGNORECASE)
        if m:
            n = int(m.group(1), 16)
            if name in self._BOOL_VALUES:
                return "Yes (enabled)" if n else "No (disabled)"
            if name == "AUOptions":
                return self._AU_OPTIONS.get(n, str(n))
            if name == "BranchReadinessLevel":
                return self._BRANCH_LEVELS.get(n, str(n))
            if name == "ScheduledInstallDay":
                days = {0:"Every day",1:"Sunday",2:"Monday",3:"Tuesday",
                        4:"Wednesday",5:"Thursday",6:"Friday",7:"Saturday"}
                return days.get(n, str(n))
            if name == "ScheduledInstallTime":
                return f"{n:02d}:00"
            if name in ("ActiveHoursStart", "ActiveHoursEnd"):
                return f"{n:02d}:00"
            return str(n)

        # String
        if val.startswith('"') and val.endswith('"'):
            return val[1:-1]

        # Hex binary / other
        if val.lower().startswith("hex:"):
            return f"<binary>"

        return val.strip('"')

# ---------------------------------------------------------------------------
class WUParser:
    """
    Orchestrates all Windows Update parsers:
      - WUOrchestratorParser  (registry)
      - WUEtlParser           (ETL files via PowerShell / tracerpt)
      - ReportingEventsParser (ReportingEvents.log)
    """

    def __init__(self):
        self.orchestrator   = WUOrchestratorParser()
        self.etl            = WUEtlParser()
        self.reporting      = ReportingEventsParser()
        self.policies       = WUPoliciesParser()
        self.parsed_registry  = False
        self.parsed_reporting = False
        self.parsed_policies  = False
        self.registry_file: str  = ""
        self.all_reg_files: list = []
        self.etl_files: list     = []
        self.reporting_events_file: str = ""

    def set_files(self, registry_file: str = "",
                  etl_files=None,
                  reporting_events_file: str = "",
                  all_reg_files=None):
        self.registry_file          = registry_file
        self.etl_files              = etl_files or []
        self.reporting_events_file  = reporting_events_file
        self.all_reg_files          = all_reg_files or []

    def has_registry(self) -> bool:
        return bool(self.registry_file)

    def parse_registry(self) -> bool:
        if self.registry_file:
            ok = self.orchestrator.parse(self.registry_file)
            self.parsed_registry = ok
            return ok
        return False

    def parse_policies(self) -> bool:
        """Scan ALL .reg files for WU policy keys."""
        ok = self.policies.scan_reg_files(self.all_reg_files)
        self.parsed_policies = ok
        return ok

    def parse_reporting_events(self) -> bool:
        """Parse ReportingEvents.log — fast, no external tool needed."""
        if self.reporting_events_file:
            ok = self.reporting.parse(self.reporting_events_file)
            self.parsed_reporting = ok
            return ok
        return False

    def has_etl_files(self) -> bool:
        return bool(self.etl_files)

    def has_reporting_events(self) -> bool:
        return bool(self.reporting_events_file)

    def get_registry_issues(self) -> list:
        return self.orchestrator.get_issues() if self.parsed_registry else []
