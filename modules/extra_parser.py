"""
extra_parser.py
Parses secondary Intune diagnostic sources:
  - ipconfig /all output   (cp850 / Windows console encoding)
  - netsh winhttp show proxy output
  - LogonUI registry key   -> last logged-on user
  - IntuneManagementExtension registry key -> last sync, IME agent version
  - CAB extraction via expand.exe
"""

import os
import re
import json
import subprocess
import tempfile
import shutil
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _read_cmd_output(file_path: str) -> str:
    """Read Windows command output (typically cp850 / OEM console encoding)."""
    if not os.path.isfile(file_path):
        return ""
    for enc in ["cp850", "cp1252", "utf-8", "latin-1"]:
        try:
            with open(file_path, encoding=enc, errors="replace") as f:
                return f.read()
        except Exception:
            continue
    return ""


def _read_reg_file(file_path: str) -> str:
    """Read a .reg file (typically UTF-16 LE with BOM)."""
    if not os.path.isfile(file_path):
        return ""
    for enc in ["utf-16", "utf-8", "cp1252", "latin-1"]:
        try:
            with open(file_path, encoding=enc, errors="replace") as f:
                txt = f.read()
            if txt.startswith("Windows Registry Editor"):
                return txt
        except Exception:
            continue
    return ""


# ---------------------------------------------------------------------------
class IpconfigParser:
    """
    Parses ipconfig /all output (French or English Windows console output).
    Extracts the first non-loopback, non-APIPA IPv4 address.
    """

    # Handles both: "IPv4 Address . . . : x.x.x.x"
    # and French:   "Adresse IPv4. . . . : x.x.x.x(prefere)"
    _IP_RE = re.compile(
        r"(?:Adresse\s+IPv4|IPv4\s+Address|IPv4-Adresse)[^:]*:\s*"
        r"((?:\d{1,3}\.){3}\d{1,3})",
        re.IGNORECASE,
    )
    _HOSTNAME_RE = re.compile(
        # Match English "Host Name" / "Hostname" and French "Nom de l’hôte".
        # The ô in "hôte" can appear as 1–3 garbled chars depending on the
        # console codepage (cp850 byte, cp1252, UTF-8 replacement sequence…),
        # so we allow .{1,5} between ‘h’ and ‘te’ to be encoding-agnostic.
        r"(?:Host\s+Name|Hostname|Nom\s+de\s+l.{0,3}h.{1,5}te)[^:]*:\s*(\S+)",
        re.IGNORECASE,
    )

    def __init__(self):
        self.ip: str = ""
        self.hostname: str = ""

    def parse(self, file_path: str) -> bool:
        txt = _read_cmd_output(file_path)
        if not txt:
            return False
        for line in txt.splitlines():
            if not self.hostname:
                m = self._HOSTNAME_RE.search(line)
                if m:
                    self.hostname = m.group(1).strip()
            if not self.ip:
                m = self._IP_RE.search(line)
                if m:
                    candidate = m.group(1).strip()
                    if not candidate.startswith("127.") and \
                       not candidate.startswith("169.254."):
                        self.ip = candidate
            if self.ip and self.hostname:
                break
        return bool(self.ip or self.hostname)


# ---------------------------------------------------------------------------
class ProxyParser:
    """
    Parses 'netsh winhttp show proxy' output.
    Detects direct access vs. configured proxy server.
    """

    # French: "Acces direct" / English: "Direct access"
    _DIRECT_RE = re.compile(r"(?:Acc[e\xe8]s\s+direct|Direct\s+access)", re.IGNORECASE)
    # French/English: "Proxy Server(s)  :" or "Serveur(s) proxy :"
    _PROXY_RE  = re.compile(
        r"(?:Proxy\s+Server|Serveurs?\s+proxy)[^:]*:\s*(\S+)",
        re.IGNORECASE,
    )
    _BYPASS_RE = re.compile(
        r"(?:Bypass\s+List|Liste\s+de\s+contournement)[^:]*:\s*(.+)",
        re.IGNORECASE,
    )

    def __init__(self):
        self.is_direct: bool    = True
        self.proxy_server: str  = ""
        self.bypass_list: str   = ""

    def parse(self, file_path: str) -> bool:
        txt = _read_cmd_output(file_path)
        if not txt:
            return False
        for line in txt.splitlines():
            if self._DIRECT_RE.search(line):
                self.is_direct = True
            m = self._PROXY_RE.search(line)
            if m:
                self.proxy_server = m.group(1).strip()
                self.is_direct = False
            m = self._BYPASS_RE.search(line)
            if m:
                self.bypass_list = m.group(1).strip()
        return True

    @property
    def summary(self) -> str:
        if self.is_direct or not self.proxy_server:
            return "Direct (no proxy)"
        return self.proxy_server


# ---------------------------------------------------------------------------
class LogonUIParser:
    """
    Parses HKLM\\...\\Authentication\\LogonUI registry export.
    Extracts last logged-on user display name and SAM account.
    """

    def __init__(self):
        self.display_name: str = ""
        self.sam_user: str     = ""
        self.user_sid: str     = ""

    def parse(self, reg_file: str) -> bool:
        txt = _read_reg_file(reg_file)
        if not txt:
            return False
        for line in txt.splitlines():
            l = line.strip()
            if l.startswith('"LastLoggedOnDisplayName"'):
                self.display_name = self._str_val(l)
            elif l.startswith('"LastLoggedOnSAMUser"'):
                self.sam_user = self._str_val(l)
            elif l.startswith('"LastLoggedOnUserSID"'):
                self.user_sid = self._str_val(l)
        return bool(self.display_name or self.sam_user)

    @staticmethod
    def _str_val(line: str) -> str:
        m = re.search(r'=\s*"(.*)"', line)
        return m.group(1) if m else ""


# ---------------------------------------------------------------------------
class IMERegistryParser:
    """
    Parses HKLM\\Software\\Microsoft\\IntuneManagementExtension registry export.
    Extracts: last sync timestamp, IME agent version, BIOS info, BitLocker status.
    """

    def __init__(self):
        self.last_sync: str      = ""
        self.agent_version: str  = ""
        self.bios_version: str   = ""
        self.bios_date: str      = ""
        self.secure_boot: str    = ""
        self.bitlocker: str      = ""

    def parse(self, reg_file: str) -> bool:
        txt = _read_reg_file(reg_file)
        if not txt:
            return False
        for line in txt.splitlines():
            l = line.strip()
            # Last sync timestamp
            if '"LastSyncFeatureList"' in l and not self.last_sync:
                self.last_sync = self._str_val(l)
            # Look for ExecutionMsg containing BIOS / SecureBoot / BitLocker data
            if '"ResultDetails"' in l or '"ExecutionMsg"' in l:
                self._scan_result_details(l)
        return True

    def _scan_result_details(self, line: str):
        """Extract agent version, BIOS, SecureBoot, BitLocker from JSON ResultDetails."""
        # AgentVersion inside SigningMsg
        if not self.agent_version:
            m = re.search(r'AgentVersion:([\d.]+)', line)
            if m:
                self.agent_version = m.group(1)

        # ExecutionMsg: "SecureBoot:Enabled|BIOSVersion:...|BIOSDate:..."
        if "SecureBoot" in line and not self.secure_boot:
            m = re.search(r'SecureBoot:(\w+)', line)
            if m:
                self.secure_boot = m.group(1)
            m = re.search(r'BIOSVersion:([^|"\\]+)', line)
            if m:
                self.bios_version = m.group(1).strip()
            m = re.search(r'BIOSDate:([\d-]+)', line)
            if m:
                self.bios_date = m.group(1)

        # BitLocker status from PreRemediationDetectScriptOutput
        if not self.bitlocker:
            if "BitLocker activ" in line or "chiffrage complet" in line:
                self.bitlocker = "Enabled / Fully Encrypted"
            elif "Compliant" in line and "bitlocker" in line.lower():
                self.bitlocker = "Compliant"

    @staticmethod
    def _str_val(line: str) -> str:
        m = re.search(r'=\s*"(.*)"', line)
        return m.group(1) if m else ""


# ---------------------------------------------------------------------------
class MsInfo32Parser:
    """
    Parses the msinfo32 report file (output of msinfo32 /report).
    File naming pattern: (34) Command windir_system32_msinfo32_exe_report...
    Encoding: typically cp850/cp1252 (Windows console OEM output).
    Extracts OS name, OS version, and build number.
    """

    # English: "OS Name:                   Microsoft Windows 10 Enterprise"
    # French:  "Nom du SE :" or "Nom du système d'exploitation :"
    _OS_NAME_RE = re.compile(
        r"(?:OS\s+Name|Nom\s+du\s+(?:syst[e\xe8]me\s+d['']\s*exploitation|SE))"
        r"[^:]*:\s*(.+)",
        re.IGNORECASE,
    )
    # English: "OS Version:                10.0.26100 N/A Build 26100"
    # French:  "Version du système d'exploitation :"
    _OS_VER_RE = re.compile(
        r"(?:OS\s+Version|Version\s+du\s+(?:syst[e\xe8]me\s+d['']\s*exploitation|SE))"
        r"[^:]*:\s*(.+)",
        re.IGNORECASE,
    )
    # Build patch level from WU orchestrator is more precise, but msinfo32 gives
    # at least the major build: "10.0.26100 N/A Build 26100" → extract "10.0.26100"
    _BUILD_RE = re.compile(r"(\d+\.\d+\.\d+(?:\.\d+)?)")

    def __init__(self):
        self.os_name: str    = ""
        self.os_version: str = ""  # e.g. "10.0.26100 Build 26100"

    def parse(self, file_path: str) -> bool:
        txt = _read_cmd_output(file_path)
        if not txt:
            return False
        for line in txt.splitlines():
            if not self.os_name:
                m = self._OS_NAME_RE.search(line)
                if m:
                    self.os_name = m.group(1).strip()
            if not self.os_version:
                m = self._OS_VER_RE.search(line)
                if m:
                    raw = m.group(1).strip()
                    # Compact: "10.0.26100 N/A Build 26100" → "10.0.26100 Build 26100"
                    raw = re.sub(r"\s+N/A\s+", " ", raw)
                    self.os_version = raw
            if self.os_name and self.os_version:
                break
        return bool(self.os_name or self.os_version)

    @property
    def display_version(self) -> str:
        """Return a compact display string, e.g. '10.0.26100 Build 26100'."""
        if self.os_version:
            return self.os_version
        return self.os_name


# ---------------------------------------------------------------------------
class CabExtractor:
    """
    Extracts Windows CAB files using expand.exe (built into Windows).
    """

    def __init__(self):
        self.extracted_files: List[str] = []
        self.last_status: str = ""

    @staticmethod
    def is_expand_available() -> bool:
        try:
            r = subprocess.run(
                ["expand.exe", "/?"],
                capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return False

    def extract(self, cab_path: str, dest_dir: Optional[str] = None,
                progress_cb=None) -> bool:
        """
        Extract all files from a CAB into dest_dir (temp dir if None).
        Returns True on success.
        """
        if not os.path.isfile(cab_path):
            self.last_status = f"CAB file not found: {cab_path}"
            return False

        if dest_dir is None:
            dest_dir = tempfile.mkdtemp(prefix="intune_cab_")

        os.makedirs(dest_dir, exist_ok=True)
        if progress_cb:
            progress_cb(f"Extracting {os.path.basename(cab_path)}...")

        try:
            r = subprocess.run(
                ["expand.exe", cab_path, "-F:*", dest_dir],
                capture_output=True, timeout=120)
            if r.returncode == 0 or os.listdir(dest_dir):
                self.extracted_files = [
                    os.path.join(dest_dir, f)
                    for f in os.listdir(dest_dir)
                ]
                self.last_status = (
                    f"Extracted {len(self.extracted_files)} file(s) from "
                    f"{os.path.basename(cab_path)}")
                return True
            else:
                err = r.stderr.decode("cp850", errors="replace").strip()
                self.last_status = f"expand.exe failed: {err[:200]}"
                return False
        except (FileNotFoundError, OSError) as e:
            self.last_status = f"expand.exe not available: {e}"
            return False
        except subprocess.TimeoutExpired:
            self.last_status = "CAB extraction timed out (>120s)"
            return False


# ---------------------------------------------------------------------------
class ExtraParser:
    """Orchestrates all extra diagnostic parsers."""

    def __init__(self):
        self.ipconfig    = IpconfigParser()
        self.proxy       = ProxyParser()
        self.logonui     = LogonUIParser()
        self.ime_reg     = IMERegistryParser()
        self.msinfo32    = MsInfo32Parser()
        self.cab         = CabExtractor()

        self._ipconfig_file: str   = ""
        self._proxy_file: str      = ""
        self._logonui_file: str    = ""
        self._ime_reg_file: str    = ""
        self._msinfo32_file: str   = ""
        self.cab_files: List[str]  = []

    def set_files(self, ipconfig: str = "", proxy: str = "",
                  logonui: str = "", ime_reg: str = "",
                  msinfo32: str = "",
                  cab_files: Optional[List[str]] = None):
        self._ipconfig_file  = ipconfig
        self._proxy_file     = proxy
        self._logonui_file   = logonui
        self._ime_reg_file   = ime_reg
        self._msinfo32_file  = msinfo32
        self.cab_files       = cab_files or []

    def parse_all(self) -> bool:
        if self._ipconfig_file:
            self.ipconfig.parse(self._ipconfig_file)
        if self._proxy_file:
            self.proxy.parse(self._proxy_file)
        if self._logonui_file:
            self.logonui.parse(self._logonui_file)
        if self._ime_reg_file:
            self.ime_reg.parse(self._ime_reg_file)
        if self._msinfo32_file:
            self.msinfo32.parse(self._msinfo32_file)
        if self.cab_files:
            for cab in self.cab_files:
                self.cab.extract(cab)
        return True
