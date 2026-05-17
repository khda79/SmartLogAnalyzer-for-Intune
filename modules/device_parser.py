"""
device_parser.py
Parsers for device-level information from Intune Device Diagnostics ZIP:
  - InstalledAppsParser   : HKLM\\...\\Uninstall reg files -> installed apps
  - DriversParser         : pnputil enum-drivers output   -> 3rd-party drivers
  - WifiParser            : netsh wlan show profiles       -> WiFi SSIDs
  - AutopatchParser       : CloudManagedUpdate reg + autopatch logs
  - CollectionErrorsParser: "No Results" files            -> what failed to collect
"""

from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional


# ---------------------------------------------------------------------------
# Installed Applications
# ---------------------------------------------------------------------------

@dataclass
class InstalledApp:
    name:         str = ""
    version:      str = ""
    publisher:    str = ""
    install_date: str = ""
    install_loc:  str = ""
    arch:         str = ""   # "x64" | "x86" | ""


class InstalledAppsParser:
    """
    Parses HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall (x64)
    and HKLM\\SOFTWARE\\WOW6432Node\\...\\Uninstall (x86) .reg files.
    """

    def __init__(self):
        self.apps: List[InstalledApp] = []
        self.parsed = False

    def parse(self, reg_files: List[str]) -> bool:
        """Accept a list of .reg file paths; parse all of them."""
        self.apps = []
        self.parsed = False
        for path in reg_files:
            if not os.path.isfile(path):
                continue
            content = self._read_reg(path)
            if not content:
                continue
            arch = "x86" if "wow6432" in path.lower() else "x64"
            self._parse_content(content, arch)

        # Sort by name
        self.apps.sort(key=lambda a: a.name.lower())
        self.parsed = bool(self.apps)
        return self.parsed

    def _parse_content(self, content: str, arch: str):
        current = {}
        in_uninstall = False

        for raw in content.splitlines():
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                # Save previous app
                if in_uninstall and current.get("DisplayName"):
                    self.apps.append(InstalledApp(
                        name=current.get("DisplayName", ""),
                        version=current.get("DisplayVersion", ""),
                        publisher=current.get("Publisher", ""),
                        install_date=self._format_date(current.get("InstallDate", "")),
                        install_loc=current.get("InstallLocation", ""),
                        arch=arch,
                    ))
                current = {}
                key = line[1:-1].lower()
                # True when the key is a direct subkey of ...Uninstall\...
                # (has \uninstall\ in the path, meaning a real app entry,
                # not the Uninstall key itself which ends without a trailing \)
                in_uninstall = "\\uninstall\\" in key or "/uninstall/" in key
                continue

            if not in_uninstall or "=" not in line:
                continue

            name_raw, _, val_raw = line.partition("=")
            name = name_raw.strip().strip('"')
            val  = val_raw.strip().strip('"')
            # Skip dword / hex blobs for string fields
            if val.startswith("dword:") or val.startswith("hex"):
                continue
            current[name] = val

        # Last entry
        if in_uninstall and current.get("DisplayName"):
            self.apps.append(InstalledApp(
                name=current.get("DisplayName", ""),
                version=current.get("DisplayVersion", ""),
                publisher=current.get("Publisher", ""),
                install_date=self._format_date(current.get("InstallDate", "")),
                install_loc=current.get("InstallLocation", ""),
                arch=arch,
            ))

    @staticmethod
    def _format_date(raw: str) -> str:
        """Convert YYYYMMDD to YYYY-MM-DD."""
        m = re.match(r"(\d{4})(\d{2})(\d{2})", raw)
        if m:
            return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
        return raw

    @staticmethod
    def _read_reg(path: str) -> str:
        for enc in ["utf-16", "utf-16-le", "utf-8", "latin-1"]:
            try:
                with open(path, "r", encoding=enc, errors="replace") as f:
                    txt = f.read()
                if "Windows Registry Editor" in txt or "HKEY_LOCAL_MACHINE" in txt.upper():
                    return txt
            except Exception:
                continue
        return ""


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------

@dataclass
class Driver:
    published_name: str = ""
    original_name:  str = ""
    provider:       str = ""
    class_name:     str = ""
    class_guid:     str = ""
    driver_version:  str = ""
    signer:         str = ""
    attributes:     str = ""


class DriversParser:
    """Parses pnputil /enum-drivers output."""

    def __init__(self):
        self.drivers: List[Driver] = []
        self.parsed = False

    def parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        content = self._read(file_path)
        if not content:
            return False

        # pnputil output: blocks separated by blank lines
        # Each block has "Key: Value" lines
        current: Dict[str, str] = {}

        def _flush():
            if current.get("original_name") or current.get("published_name"):
                self.drivers.append(Driver(
                    published_name=current.get("published_name", ""),
                    original_name=current.get("original_name", ""),
                    provider=current.get("provider", ""),
                    class_name=current.get("class_name", ""),
                    class_guid=current.get("class_guid", ""),
                    driver_version=current.get("driver_version", ""),
                    signer=current.get("signer", ""),
                    attributes=current.get("attributes", ""),
                ))

        for raw in content.splitlines():
            line = raw.strip()
            if not line:
                _flush()
                current = {}
                continue
            if ":" not in line:
                continue
            key_raw, _, val = line.partition(":")
            key = key_raw.strip().lower()
            val = val.strip()

            # Map various language labels to canonical keys
            # (pnputil output is localized)
            if any(k in key for k in ("published name", "nom publié", "nome pubblicato",
                                       "nombre publicado", "veröffentlichter name")):
                current["published_name"] = val
            elif any(k in key for k in ("original name", "nom d'origine", "nome originale",
                                         "nombre original", "ursprünglicher name")):
                current["original_name"] = val
            elif any(k in key for k in ("provider name", "nom du fournisseur",
                                         "nome del provider", "nombre del proveedor")):
                current["provider"] = val
            elif any(k in key for k in ("class name", "nom de la classe",
                                         "nome classe", "nombre de clase")):
                current["class_name"] = val
            elif any(k in key for k in ("class guid", "guid de la classe",
                                         "guid classe")):
                current["class_guid"] = val
            elif any(k in key for k in ("driver version", "version du pilote",
                                         "versione driver", "versión del controlador")):
                current["driver_version"] = val
            elif any(k in key for k in ("signer name", "nom du signataire",
                                         "nome firmatario", "nombre del firmante")):
                current["signer"] = val
            elif "attribut" in key:
                current["attributes"] = val

        _flush()

        # Sort by provider then original name
        self.drivers.sort(key=lambda d: (d.provider.lower(), d.original_name.lower()))
        self.parsed = bool(self.drivers)
        return self.parsed

    @staticmethod
    def _read(path: str) -> str:
        for enc in ["utf-8", "utf-16", "cp1252", "latin-1"]:
            try:
                with open(path, "r", encoding=enc, errors="replace") as f:
                    txt = f.read()
                if "inf" in txt.lower():
                    return txt
            except Exception:
                continue
        return ""


# ---------------------------------------------------------------------------
# WiFi Profiles
# ---------------------------------------------------------------------------

@dataclass
class WifiProfile:
    ssid:       str = ""
    profile_type: str = ""   # "GPO" | "User" | ""
    auth:       str = ""
    cipher:     str = ""


class WifiParser:
    """Parses netsh wlan show profiles output."""

    def __init__(self):
        self.profiles: List[WifiProfile] = []
        self.parsed = False

    def parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        content = self._read(file_path)
        if not content:
            return False

        self.profiles = []
        current_type = ""

        for raw in content.splitlines():
            line = raw.strip()
            ll   = line.lower()

            # Section headers
            if "group policy" in ll or "stratégie de groupe" in ll or "directiva de grupo" in ll:
                current_type = "GPO"
            elif "user profile" in ll or "profils utilisateurs" in ll or "perfiles de usuario" in ll:
                current_type = "User"

            # SSID line: "    SSIDName : emeis"
            if ":" in line and not line.startswith("["):
                key_raw, _, val = line.partition(":")
                key = key_raw.strip().lower()
                val = val.strip()
                if val and any(k in key for k in ("ssidname", "ssid name",
                                                    "nom du profil", "profile name",
                                                    "nombre del perfil")):
                    # Avoid duplicates
                    existing = [p.ssid for p in self.profiles]
                    if val not in existing:
                        self.profiles.append(WifiProfile(
                            ssid=val,
                            profile_type=current_type,
                        ))

        self.parsed = bool(self.profiles)
        return self.parsed

    @staticmethod
    def _read(path: str) -> str:
        for enc in ["utf-8", "utf-16", "cp1252", "latin-1"]:
            try:
                with open(path, "r", encoding=enc, errors="replace") as f:
                    return f.read()
            except Exception:
                continue
        return ""


# ---------------------------------------------------------------------------
# Windows Autopatch / Cloud-Managed Update
# ---------------------------------------------------------------------------

@dataclass
class AutopatchInfo:
    enabled:       str = ""
    deadline_days: str = ""
    grace_period:  str = ""
    group:         str = ""
    last_install:  str = ""   # from most recent autopatch log
    log_lines:     List[str] = field(default_factory=list)


class AutopatchParser:
    """
    Parses:
      - HKLM\\SOFTWARE\\Microsoft\\CloudManagedUpdate registry key
      - autopatchclientv2*.log files (most recent first)
    """

    def __init__(self):
        self.info = AutopatchInfo()
        self.parsed = False

    def parse(self, reg_file: Optional[str], log_files: List[str]) -> bool:
        found = False
        if reg_file and os.path.isfile(reg_file):
            found = self._parse_reg(reg_file) or found
        if log_files:
            found = self._parse_logs(log_files) or found
        self.parsed = found
        return found

    def _parse_reg(self, path: str) -> bool:
        content = self._read_reg(path)
        if not content:
            return False

        # EXP settings: hex(2):31,00,00,00 is the string "1"
        def _hex2_to_str(hex_val: str) -> str:
            """Convert hex(2):xx,xx,... (REG_EXPAND_SZ) to string."""
            try:
                raw = bytes.fromhex(hex_val.replace(",", ""))
                return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            except Exception:
                return hex_val

        in_exp = False
        for raw in content.splitlines():
            line = raw.strip()
            ll   = line.lower()
            if "[" in line and "exp\\settings" in ll:
                in_exp = True
            elif "[" in line:
                in_exp = False
            if not in_exp or "=" not in line:
                continue

            name_raw, _, val = line.partition("=")
            name = name_raw.strip().strip('"').upper()
            val  = val.strip()

            if val.startswith("hex(2):"):
                val = _hex2_to_str(val[7:])
            elif val.startswith('"') and val.endswith('"'):
                val = val[1:-1]

            if name == "EXP.ENABLED":
                self.info.enabled = "Yes" if val.strip() == "1" else "No"
            elif name == "EXP.DEADLINEDAYS":
                self.info.deadline_days = val
            elif name == "EXP.GRACEPERIOD":
                self.info.grace_period = val

        return True

    def _parse_logs(self, log_files: List[str]) -> bool:
        # Sort newest first (filename contains timestamp)
        sorted_logs = sorted(log_files, reverse=True)
        collected: List[str] = []
        for path in sorted_logs[:3]:   # only last 3 logs
            content = self._read(path)
            if not content:
                continue
            for line in content.splitlines():
                ls = line.strip()
                # Look for install/success/error/group lines
                ll = ls.lower()
                if any(k in ll for k in ("install", "success", "error", "fail",
                                          "group", "ring", "patch", "update")):
                    # Strip BOM / control chars
                    clean = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', ls)
                    if clean and len(clean) > 10:
                        collected.append(clean[:200])
                if len(collected) >= 30:
                    break
            if collected:
                break

        self.info.log_lines = collected
        return bool(collected)

    @staticmethod
    def _read_reg(path: str) -> str:
        for enc in ["utf-16", "utf-8", "latin-1"]:
            try:
                with open(path, "r", encoding=enc, errors="replace") as f:
                    return f.read()
            except Exception:
                continue
        return ""

    @staticmethod
    def _read(path: str) -> str:
        for enc in ["utf-8", "utf-16", "cp1252", "latin-1"]:
            try:
                with open(path, "r", encoding=enc, errors="replace") as f:
                    return f.read()
            except Exception:
                continue
        return ""


# ---------------------------------------------------------------------------
# Collection Errors
# ---------------------------------------------------------------------------

# Error codes -> human-readable explanation
_ERROR_EXPLANATIONS = {
    "0x80070001": "Function not implemented — feature/component not present on this device",
    "0x80070002": "File not found — the log/folder does not exist",
    "0x80070003": "Path not found — directory does not exist",
    "0x80070005": "Access denied — insufficient permissions",
    "0x8000ffff": "Unexpected failure (E_UNEXPECTED) — command/tool crashed or returned no output",
    "0x80070057": "Invalid parameter passed to the diagnostic tool",
}

# Known "No Results" names -> what they mean
_KNOWN_ITEMS = {
    "epmAgent":              "Microsoft Endpoint Privilege Management Agent — not installed",
    "cloudDesktop":          "Windows 365 / Cloud PC logs — not a Cloud PC",
    "ccmsetup":              "SCCM / ConfigMgr client — not installed (device is Intune-only)",
    "NDUP":                  "Network Device Update Protocol registry — not present",
    "SetupDiag":             "SetupDiag (Windows upgrade diagnostic) — not run or not present",
    "dism.*packages":        "DISM provisioned package list — DISM command failed",
    "Update_Health_Tools":   "Microsoft Update Health Tools logs — not present",
    "officeclicktorun":      "Microsoft 365 Click-to-Run temp logs — not present",
    "mdm_log":               "MDM system profile logs — not accessible",
    "SetupDiagResults":      "SetupDiag XML results — not present",
}


@dataclass
class CollectionError:
    item_name:   str = ""
    error_code:  str = ""
    explanation: str = ""
    raw_name:    str = ""


class CollectionErrorsParser:
    """Parses 'No Results - Error [0xXXXX]' files from the ZIP."""

    def __init__(self):
        self.errors: List[CollectionError] = []
        self.parsed = False

    def parse(self, file_paths: List[str]) -> bool:
        self.errors = []
        for path in file_paths:
            bn = os.path.basename(path)
            m = re.search(r"Error \[([^\]]+)\]", bn, re.IGNORECASE)
            error_code = m.group(1).strip() if m else ""

            # Extract human-friendly item name from filename
            # "(71) No Results - Error [0x80070003] FoldersFiles temp_CloudDesktop_log"
            m2 = re.search(r"\] (.+)$", bn)
            raw_item = m2.group(1).strip() if m2 else bn

            # Simplify: strip leading type (FoldersFiles, RegistryKey, Command)
            item = re.sub(r"^(FoldersFiles|RegistryKey|Command)\s+", "", raw_item, flags=re.IGNORECASE)
            item = item.replace("_", "\\").replace("export", "").strip()

            # Explanation
            expl_code = _ERROR_EXPLANATIONS.get(error_code.lower(),
                        _ERROR_EXPLANATIONS.get(error_code, ""))
            expl_item = ""
            for kw, desc in _KNOWN_ITEMS.items():
                if re.search(kw, raw_item, re.IGNORECASE):
                    expl_item = desc
                    break

            explanation = expl_item or expl_code or "Unknown reason"

            self.errors.append(CollectionError(
                item_name=item,
                error_code=error_code,
                explanation=explanation,
                raw_name=raw_item,
            ))

        self.errors.sort(key=lambda e: e.error_code)
        self.parsed = bool(self.errors)
        return self.parsed


# ---------------------------------------------------------------------------
# DeviceParser orchestrator
# ---------------------------------------------------------------------------

class DeviceParser:
    """Orchestrates all device-level parsers."""

    def __init__(self):
        self.apps             = InstalledAppsParser()
        self.drivers          = DriversParser()
        self.wifi             = WifiParser()
        self.autopatch        = AutopatchParser()
        self.collection_errors = CollectionErrorsParser()

        # File paths (set via set_files before parse_all)
        self.uninstall_reg_files:   List[str] = []
        self.pnputil_file:          str       = ""
        self.wlan_profiles_file:    str       = ""
        self.cloudmanagedupdate_reg: str      = ""
        self.autopatch_log_files:   List[str] = []
        self.collection_error_files: List[str] = []

    def set_files(self, *,
                  uninstall_reg_files=None,
                  pnputil_file="",
                  wlan_profiles_file="",
                  cloudmanagedupdate_reg="",
                  autopatch_log_files=None,
                  collection_error_files=None):
        self.uninstall_reg_files    = uninstall_reg_files or []
        self.pnputil_file           = pnputil_file
        self.wlan_profiles_file     = wlan_profiles_file
        self.cloudmanagedupdate_reg = cloudmanagedupdate_reg
        self.autopatch_log_files    = autopatch_log_files or []
        self.collection_error_files = collection_error_files or []

    def parse_all(self):
        if self.uninstall_reg_files:
            self.apps.parse(self.uninstall_reg_files)
        if self.pnputil_file:
            self.drivers.parse(self.pnputil_file)
        if self.wlan_profiles_file:
            self.wifi.parse(self.wlan_profiles_file)
        if self.cloudmanagedupdate_reg or self.autopatch_log_files:
            self.autopatch.parse(self.cloudmanagedupdate_reg or None,
                                 self.autopatch_log_files)
        if self.collection_error_files:
            self.collection_errors.parse(self.collection_error_files)
