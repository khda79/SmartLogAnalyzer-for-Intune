"""
evtx_parser.py
Parses Windows Event Log (.evtx) files via wevtutil.exe (built into Windows).

Targets:
  (45) Events Application Events.evtx
  (61) Events Setup Events.evtx
  (62) Events System Events.evtx
"""

import os
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Optional

# ETW level → display string
LEVEL_NAMES = {
    0: "Unknown",
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}

# Levels worth flagging as issues
ERROR_LEVELS   = {1, 2}   # Critical + Error
WARNING_LEVELS = {3}


@dataclass
class EvtxEvent:
    level_num:  int   = 0
    level_str:  str   = ""
    timestamp:  str   = ""
    event_id:   str   = ""
    provider:   str   = ""
    channel:    str   = ""
    message:    str   = ""
    source_file: str  = ""


class EvtxParser:
    """
    Uses wevtutil.exe to read a .evtx file and return parsed events.
    Keeps up to `max_events` most recent events (newest-first read order).
    """

    _NS = "http://schemas.microsoft.com/win/2004/08/events/event"

    def __init__(self):
        self.events:          List[EvtxEvent] = []
        self.critical_count:  int = 0
        self.error_count:     int = 0
        self.warning_count:   int = 0
        self.info_count:      int = 0
        self.total_count:     int = 0
        self.last_status:     str = ""
        self.source_file:     str = ""

    # ------------------------------------------------------------------
    @staticmethod
    def is_wevtutil_available() -> bool:
        try:
            r = subprocess.run(
                ["wevtutil.exe", "/?"],
                capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return False

    # ------------------------------------------------------------------
    def scan(self, evtx_path: str, max_events: int = 2000,
             progress_cb=None) -> bool:
        """
        Parse evtx_path via wevtutil.exe.
        Returns True if at least one event was parsed.
        max_events: cap on events read (newest first).
        """
        if not os.path.isfile(evtx_path):
            self.last_status = f"File not found: {evtx_path}"
            return False

        self.source_file = os.path.basename(evtx_path)
        if progress_cb:
            progress_cb(f"Reading {self.source_file}...")

        try:
            r = subprocess.run(
                ["wevtutil.exe", "qe", evtx_path,
                 "/lf:true",            # read from file (not live channel)
                 "/f:XML",              # XML output
                 f"/c:{max_events}",    # max events
                 "/rd:true"],           # newest first
                capture_output=True,
                timeout=120)
        except (FileNotFoundError, OSError) as e:
            self.last_status = f"wevtutil.exe not available: {e}"
            return False
        except subprocess.TimeoutExpired:
            self.last_status = "wevtutil timed out (>120s)"
            return False

        raw = r.stdout
        if not raw:
            self.last_status = (f"wevtutil returned no output for "
                                f"{self.source_file}")
            return False

        # wevtutil emits events without a wrapping root — add one
        try:
            xml_text = raw.decode("utf-8", errors="replace")
        except Exception:
            xml_text = raw.decode("latin-1", errors="replace")

        self._parse_xml(xml_text)

        self.last_status = (
            f"{self.source_file}: {self.total_count} events — "
            f"{self.critical_count} critical, "
            f"{self.error_count} errors, "
            f"{self.warning_count} warnings, "
            f"{self.info_count} info"
        )
        return bool(self.events)

    # ------------------------------------------------------------------
    def _parse_xml(self, xml_text: str):
        """Wrap bare <Event> elements and parse."""
        # Strip XML declarations that wevtutil may emit per-event
        xml_text = re.sub(r'<\?xml[^?]*\?>', '', xml_text)
        # Wrap in a root element
        wrapped = f"<Events>{xml_text}</Events>"
        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError:
            # Try stripping bad characters and re-parse
            xml_text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', xml_text)
            wrapped = f"<Events>{xml_text}</Events>"
            try:
                root = ET.fromstring(wrapped)
            except ET.ParseError:
                return

        ns = self._NS
        pfx = f"{{{ns}}}"

        for ev_el in root:
            tag = ev_el.tag.replace(pfx, "")
            if tag != "Event":
                continue

            sys_el = ev_el.find(f"{pfx}System")
            if sys_el is None:
                sys_el = ev_el.find("System")
            if sys_el is None:
                continue

            def _find(parent, name):
                el = parent.find(f"{pfx}{name}")
                return el if el is not None else parent.find(name)

            level_el    = _find(sys_el, "Level")
            ts_el       = _find(sys_el, "TimeCreated")
            evid_el     = _find(sys_el, "EventID")
            prov_el     = _find(sys_el, "Provider")
            channel_el  = _find(sys_el, "Channel")

            # Level
            try:
                level_num = int(level_el.text or "0") if level_el is not None else 0
            except ValueError:
                level_num = 0
            level_str = LEVEL_NAMES.get(level_num, "Unknown")

            # Timestamp
            timestamp = ""
            if ts_el is not None:
                ts_raw = ts_el.get("SystemTime", "")
                if ts_raw:
                    # "2026-04-20T19:00:00.000000000Z" → "2026-04-20 19:00:00"
                    timestamp = ts_raw[:19].replace("T", " ")

            # Event ID
            event_id = (evid_el.text or "").strip() if evid_el is not None else ""

            # Provider
            provider = ""
            if prov_el is not None:
                provider = (prov_el.get("Name", "")
                            or prov_el.get("Guid", "")).strip()

            # Channel
            channel = (channel_el.text or "").strip() if channel_el is not None else ""

            # Message: collect all text from EventData/RenderingInfo
            msg_parts = []
            for msg_el in ev_el:
                tag2 = msg_el.tag.replace(pfx, "")
                if tag2 in ("EventData", "UserData", "RenderingInfo"):
                    for child in msg_el.iter():
                        t = (child.text or "").strip()
                        if t:
                            msg_parts.append(t)
            message = " | ".join(msg_parts)[:300]

            ev = EvtxEvent(
                level_num=level_num,
                level_str=level_str,
                timestamp=timestamp,
                event_id=event_id,
                provider=provider[:60],
                channel=channel,
                message=message,
                source_file=self.source_file,
            )
            self.events.append(ev)
            self.total_count += 1
            if level_num == 1:
                self.critical_count += 1
            elif level_num == 2:
                self.error_count += 1
            elif level_num == 3:
                self.warning_count += 1
            else:
                self.info_count += 1

    # ------------------------------------------------------------------
    def filtered(self, level_filter: str) -> List[EvtxEvent]:
        """
        Return events matching level_filter:
          "all"      → all events
          "error"    → Critical + Error
          "warning"  → Warning
          "info"     → Information + Verbose + Unknown
        """
        if level_filter == "all":
            return self.events
        if level_filter == "error":
            return [e for e in self.events if e.level_num in ERROR_LEVELS]
        if level_filter == "warning":
            return [e for e in self.events if e.level_num in WARNING_LEVELS]
        if level_filter == "info":
            return [e for e in self.events
                    if e.level_num not in ERROR_LEVELS | WARNING_LEVELS]
        return self.events
