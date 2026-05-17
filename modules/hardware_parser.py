"""
hardware_parser.py
Parsers for: Battery Report (HTML), Firewall (advfirewall),
             Certificates (certutil), Office C2R Logs.
"""

import re
import os
from html.parser import HTMLParser
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime


# ─────────────────────────────────────────────────────────────────
# Battery Report
# ─────────────────────────────────────────────────────────────────

@dataclass
class BatteryInfo:
    computer_name:        str   = ""
    system_product:       str   = ""
    os_build:             str   = ""
    bios:                 str   = ""
    design_capacity:      str   = ""
    full_charge_capacity: str   = ""
    cycle_count:          str   = ""
    battery_name:         str   = ""
    battery_serial:       str   = ""
    battery_chemistry:    str   = ""
    last_full_charge:     str   = ""
    health_pct:           float = 0.0


class _TableParser(HTMLParser):
    """Extracts (key, value) pairs from every <tr> that has >= 2 cells."""
    def __init__(self):
        super().__init__()
        self.pairs: List[tuple] = []
        self._in_td = False
        self._cells: List[str] = []
        self._cur: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self._cells = []
        elif tag in ("td", "th"):
            self._in_td = True
            self._cur = []

    def handle_endtag(self, tag):
        if tag in ("td", "th"):
            self._in_td = False
            self._cells.append("".join(self._cur).strip())
        elif tag == "tr":
            if len(self._cells) >= 2:
                self.pairs.append((self._cells[0], self._cells[1]))

    def handle_data(self, data):
        if self._in_td:
            self._cur.append(data)


class BatteryParser:
    def __init__(self):
        self.parsed = False
        self.info = BatteryInfo()

    def parse(self, html_file: str):
        if not html_file or not os.path.isfile(html_file):
            return
        content = ""
        for enc in ("utf-8", "utf-16", "latin-1", "cp1252"):
            try:
                content = open(html_file, encoding=enc, errors="replace").read()
                if content:
                    break
            except Exception:
                pass
        if not content:
            return
        self._parse_html(content)
        self.parsed = True

    def _parse_html(self, html: str):
        p = _TableParser()
        p.feed(html)
        kv = {}
        for k, v in p.pairs:
            key = k.strip().lower()
            if key and key not in kv:
                kv[key] = v.strip()

        def get(*keys):
            for k in keys:
                v = kv.get(k.lower(), "")
                if v:
                    return v
            return ""

        b = self.info
        b.computer_name        = get("computer name")
        b.system_product       = get("system product name", "system product",
                                     "platform role")
        b.os_build             = get("os build")
        b.bios                 = get("system bios", "bios")
        b.design_capacity      = get("design capacity")
        b.full_charge_capacity = get("full charge capacity")
        b.cycle_count          = get("cycle count")
        b.battery_name         = get("name", "battery name")
        b.battery_serial       = get("serial number")
        b.battery_chemistry    = get("chemistry")
        b.last_full_charge     = get("last full charge")

        # Calculate health
        try:
            design = float(re.sub(r"[^\d.]", "", b.design_capacity))
            full   = float(re.sub(r"[^\d.]", "", b.full_charge_capacity))
            if design > 0:
                b.health_pct = round(full / design * 100, 1)
        except Exception:
            b.health_pct = 0.0

    def get_summary_rows(self) -> List[tuple]:
        b = self.info
        health_str = (f"{b.health_pct}%" if b.health_pct else "N/A")
        return [
            ("Computer Name",        b.computer_name or "N/A"),
            ("System Product",       b.system_product or "N/A"),
            ("BIOS",                 b.bios or "N/A"),
            ("OS Build",             b.os_build or "N/A"),
            ("Battery Name",         b.battery_name or "N/A"),
            ("Battery Serial",       b.battery_serial or "N/A"),
            ("Chemistry",            b.battery_chemistry or "N/A"),
            ("Design Capacity",      b.design_capacity or "N/A"),
            ("Full Charge Capacity", b.full_charge_capacity or "N/A"),
            ("Battery Health",       health_str),
            ("Cycle Count",          b.cycle_count or "N/A"),
            ("Last Full Charge",     b.last_full_charge or "N/A"),
        ]


# ─────────────────────────────────────────────────────────────────
# Firewall Parser
# ─────────────────────────────────────────────────────────────────

@dataclass
class FirewallProfile:
    name:                 str = ""
    state:                str = ""
    firewall_policy:      str = ""
    remote_management:    str = ""
    inbound_notification: str = ""
    unicast_response:     str = ""
    log_allowed:          str = ""
    log_dropped:          str = ""
    log_filename:         str = ""


class FirewallParser:
    def __init__(self):
        self.parsed   = False
        self.profiles: List[FirewallProfile] = []

    def parse(self, fw_file: str):
        if not fw_file or not os.path.isfile(fw_file):
            return
        lines = []
        for enc in ("utf-8", "utf-16", "latin-1", "cp1252"):
            try:
                lines = open(fw_file, encoding=enc, errors="replace").readlines()
                break
            except Exception:
                pass
        if not lines:
            return
        self._parse_lines(lines)
        self.parsed = bool(self.profiles)

    # Profile header patterns (English / French / German / Spanish)
    _PROFILE_HEADERS = [
        ("Domain",  ["domain profile", "profil de domaine", "domänenprofil",
                     "perfil de dominio", "profilo di dominio"]),
        ("Private", ["private profile", "profil privé", "privates profil",
                     "perfil privado", "profilo privato"]),
        ("Public",  ["public profile", "profil public", "öffentliches profil",
                     "perfil público", "profilo pubblico"]),
    ]

    # State values that mean ON / OFF in various locales
    _STATE_ON  = {"on", "actif", "activé", "ein", "activo", "attivo", "enabled"}
    _STATE_OFF = {"off", "inactif", "désactivé", "aus", "desactivado", "disattivato", "disabled"}

    def _parse_lines(self, lines: List[str]):
        current: Optional[FirewallProfile] = None
        for raw in lines:
            stripped = raw.strip()
            sl = stripped.lower()

            # Detect profile section headers (multi-locale)
            matched_profile = False
            for pname, patterns in self._PROFILE_HEADERS:
                if any(p in sl for p in patterns):
                    current = FirewallProfile(name=pname)
                    self.profiles.append(current)
                    matched_profile = True
                    break
            if matched_profile:
                continue
            if current is None:
                continue
            if re.match(r"^-{10,}", stripped):
                continue

            # Key   Value  (2+ spaces separator)
            # Use \w to handle Unicode/accented first chars (e.g. French "État")
            m = re.match(r"^(\w[\w\s]{2,}?)\s{2,}(.+)$", stripped)
            if not m:
                continue
            key = m.group(1).strip().lower().replace(" ", "")
            val = m.group(2).strip()

            # Map accented/localised key names to canonical keys
            canonical_key = key
            if key in ("état", "zustand", "estado", "stato"):
                canonical_key = "state"
            elif key in ("stratégiedepare-feu", "firewallrichtlinie"):
                canonical_key = "firewallpolicy"
            elif key in ("administrationàdistance",):
                canonical_key = "remotemanagement"

            if canonical_key == "state":
                val_norm = val.strip().lower().rstrip(".")
                if val_norm in self._STATE_ON:
                    val = "ON"
                elif val_norm in self._STATE_OFF:
                    val = "OFF"
                current.state = val
            elif canonical_key == "firewallpolicy":
                current.firewall_policy = val
            elif canonical_key == "remotemanagement":
                current.remote_management = val
            elif canonical_key == "inboundusernotification":
                current.inbound_notification = val
            elif canonical_key == "unicastresponsetomulticast":
                current.unicast_response = val
            elif "logallowed" in canonical_key:
                current.log_allowed = val
            elif "logdropped" in canonical_key:
                current.log_dropped = val
            elif canonical_key == "filename" and not current.log_filename:
                current.log_filename = val


# ─────────────────────────────────────────────────────────────────
# Certificate Parser
# ─────────────────────────────────────────────────────────────────

@dataclass
class Certificate:
    index:         str           = ""
    subject:       str           = ""
    issuer:        str           = ""
    serial:        str           = ""
    not_before:    str           = ""
    not_after:     str           = ""
    thumbprint:    str           = ""
    store:         str           = ""
    days_to_expiry: Optional[int] = None
    status:        str           = "OK"    # OK | Expiring | Expired


class CertParser:
    def __init__(self):
        self.parsed = False
        self.certs: List[Certificate] = []

    def parse(self, cert_files: List[str]):
        for fp in cert_files:
            if os.path.isfile(fp):
                self._parse_file(fp)
        self.parsed = bool(self.certs)

    def _parse_file(self, fp: str):
        content = ""
        for enc in ("utf-16", "utf-16-le", "utf-8", "latin-1", "cp1252"):
            try:
                content = open(fp, encoding=enc, errors="replace").read()
                if content:
                    break
            except Exception:
                pass
        if not content:
            return
        store = os.path.basename(fp)
        self._parse_text(content, store)

    def _parse_text(self, text: str, store: str = ""):
        # Split on "================ Certificate N ================"
        blocks = re.split(r"={5,}.*?={5,}", text)
        for block in blocks:
            if not block.strip():
                continue
            cert = Certificate(store=store)
            for line in block.splitlines():
                l = line.strip()
                m = re.match(r"Serial Number:\s*(.+)", l, re.I)
                if m:
                    cert.serial = m.group(1).strip()
                    continue
                m = re.match(r"Issuer:\s*(.+)", l, re.I)
                if m:
                    cert.issuer = m.group(1).strip()
                    continue
                m = re.match(r"Subject:\s*(.+)", l, re.I)
                if m:
                    cert.subject = m.group(1).strip()
                    continue
                m = re.match(r"NotBefore:\s*(.+)", l, re.I)
                if m:
                    cert.not_before = m.group(1).strip()
                    continue
                m = re.match(r"NotAfter:\s*(.+)", l, re.I)
                if m:
                    cert.not_after = m.group(1).strip()
                    continue
                m = re.match(r"(?:Cert Hash|Thumbprint)[^:]*:\s*(.+)", l, re.I)
                if m:
                    cert.thumbprint = re.sub(r"\s+", "", m.group(1)).upper()
                    continue

            if not cert.serial and not cert.subject:
                continue

            # Compute expiry status
            if cert.not_after:
                try:
                    dt = self._parse_date(cert.not_after)
                    delta = (dt - datetime.now()).days
                    cert.days_to_expiry = delta
                    if delta < 0:
                        cert.status = "Expired"
                    elif delta < 30:
                        cert.status = "Expiring"
                    else:
                        cert.status = "OK"
                except Exception:
                    pass

            self.certs.append(cert)

    @staticmethod
    def _parse_date(s: str) -> datetime:
        fmts = [
            "%m/%d/%Y %I:%M %p",
            "%m/%d/%Y %H:%M",
            "%Y-%m-%d %H:%M",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ]
        s = s.strip()
        for fmt in fmts:
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        raise ValueError(f"Cannot parse date: {s!r}")


# ─────────────────────────────────────────────────────────────────
# Office Click-to-Run Log Parser
# ─────────────────────────────────────────────────────────────────

@dataclass
class C2RLogEntry:
    timestamp: str = ""
    process:   str = ""
    tid:       str = ""
    level:     str = ""
    message:   str = ""


class C2RLogParser:
    def __init__(self):
        self.parsed = False
        self.log_files: List[str] = []
        self.entries_by_file: Dict[str, List[C2RLogEntry]] = {}

    def set_files(self, files: List[str]):
        self.log_files = list(files)
        if files:
            self.parsed = True

    def parse_file(self, fp: str) -> List[C2RLogEntry]:
        if fp in self.entries_by_file:
            return self.entries_by_file[fp]
        entries = []
        lines = []
        for enc in ("utf-16", "utf-16-le", "utf-8", "latin-1"):
            try:
                with open(fp, encoding=enc, errors="replace") as f:
                    lines = f.readlines()
                break
            except Exception:
                pass
        for line in lines:
            parts = line.rstrip("\n\r").split("\t")
            if len(parts) >= 4:
                if len(parts) >= 5:
                    e = C2RLogEntry(
                        timestamp = parts[0].strip(),
                        process   = parts[1].strip(),
                        tid       = parts[2].strip(),
                        level     = parts[3].strip(),
                        message   = parts[4].strip(),
                    )
                else:
                    e = C2RLogEntry(
                        timestamp = parts[0].strip(),
                        process   = parts[1].strip(),
                        level     = parts[2].strip(),
                        message   = parts[3].strip(),
                    )
                entries.append(e)
        self.entries_by_file[fp] = entries
        return entries

    def get_display_name(self, fp: str) -> str:
        bn = os.path.basename(fp)
        # Strip date suffix: ClickToRun-20260414.log -> ClickToRun
        bn = re.sub(r"[-_]\d{8,}.*", "", bn)
        return bn or os.path.basename(fp)


# ─────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────

class HardwareParser:
    def __init__(self):
        self.battery   = BatteryParser()
        self.firewall  = FirewallParser()
        self.certs     = CertParser()
        self.c2r       = C2RLogParser()

        self._battery_html  = ""
        self._firewall_file = ""
        self._cert_files:    List[str] = []
        self._c2r_files:     List[str] = []

    def set_files(self,
                  battery_html:    str       = "",
                  firewall_file:   str       = "",
                  cert_files:      List[str] = None,
                  c2r_log_files:   List[str] = None):
        self._battery_html  = battery_html
        self._firewall_file = firewall_file
        self._cert_files    = cert_files or []
        self._c2r_files     = c2r_log_files or []

    def parse_all(self):
        self.battery.parse(self._battery_html)
        self.firewall.parse(self._firewall_file)
        self.certs.parse(self._cert_files)
        self.c2r.set_files(self._c2r_files)
