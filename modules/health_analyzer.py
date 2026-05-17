"""
health_analyzer.py
Analyses collected diagnostic data for the top recurring IT issues:
  #4  Performance (CPU/RAM/Disk/Startup)
  #5  BitLocker compliance
  #6  Office / Modern Auth
  #7  Defender / EDR
  #8  Drivers (unsigned, outdated)
  #9  Storage saturation
  #10 Legacy apps (32-bit, old runtimes)
  +   Microsoft Store apps
  +   Entra Join diagnostics (RunLocalDsregcmd-V2.ps1 output)
"""

import os
import re
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional


# ── Common severity levels ─────────────────────────────────────────────────────
SEV_OK      = "OK"
SEV_WARN    = "WARN"
SEV_ERROR   = "ERROR"
SEV_INFO    = "INFO"


@dataclass
class HealthFinding:
    category:   str          # "BitLocker", "Defender", "Performance", etc.
    severity:   str          # SEV_OK / SEV_WARN / SEV_ERROR / SEV_INFO
    title:      str
    detail:     str
    value:      str = ""     # raw measured value (e.g. "3% free")
    action:     str = ""     # recommended action


@dataclass
class HealthReport:
    findings:   List[HealthFinding] = field(default_factory=list)

    def add(self, category, severity, title, detail, value="", action=""):
        self.findings.append(HealthFinding(category, severity, title, detail, value, action))

    def by_category(self, cat):
        return [f for f in self.findings if f.category == cat]

    def errors(self):
        return [f for f in self.findings if f.severity == SEV_ERROR]

    def warnings(self):
        return [f for f in self.findings if f.severity == SEV_WARN]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read(path: str) -> str:
    if not path or not os.path.isfile(path):
        return ""
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            with open(path, encoding=enc, errors="replace") as f:
                return f.read()
        except Exception:
            pass
    return ""


def _read_json(path: str) -> dict:
    txt = _read(path)
    if not txt:
        return {}
    try:
        return json.loads(txt)
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# #5 BitLocker
# ─────────────────────────────────────────────────────────────────────────────

class BitLockerAnalyzer:
    def analyse(self, ps_bitlocker_file: str) -> HealthReport:
        r = HealthReport()
        txt = _read(ps_bitlocker_file)
        if not txt:
            r.add("BitLocker", SEV_INFO, "BitLocker data unavailable",
                  "ps_bitlocker_status not found — run 'Collect diagnostics' from the app.")
            return r

        # Protection status
        if re.search(r"ProtectionStatus\s*:\s*Off", txt, re.I):
            r.add("BitLocker", SEV_ERROR, "BitLocker protection is OFF",
                  "Drive is not actively protected by BitLocker.",
                  value="ProtectionStatus=Off",
                  action="Enable BitLocker or verify via Intune Encryption policy.")
        elif re.search(r"ProtectionStatus\s*:\s*On", txt, re.I):
            r.add("BitLocker", SEV_OK, "BitLocker protection ON",
                  "Drive is actively BitLocker-protected.", value="ProtectionStatus=On")

        # Volume status
        if re.search(r"VolumeStatus\s*:\s*FullyEncrypted", txt, re.I):
            r.add("BitLocker", SEV_OK, "Volume fully encrypted", "",
                  value="FullyEncrypted")
        elif re.search(r"VolumeStatus\s*:\s*EncryptionInProgress", txt, re.I):
            r.add("BitLocker", SEV_WARN, "Encryption in progress",
                  "BitLocker encryption is not yet complete.",
                  value="EncryptionInProgress")
        elif re.search(r"VolumeStatus\s*:\s*FullyDecrypted", txt, re.I):
            r.add("BitLocker", SEV_ERROR, "Volume fully decrypted",
                  "BitLocker encryption is not active on this volume.",
                  value="FullyDecrypted",
                  action="Re-enable BitLocker encryption via Intune policy.")

        # Key protectors / escrow
        if re.search(r"KeyProtector.*RecoveryPassword", txt, re.I):
            r.add("BitLocker", SEV_OK, "Recovery password key protector present", "")
        else:
            r.add("BitLocker", SEV_WARN, "No RecoveryPassword key protector detected",
                  "Recovery key may not be escrowed to Entra ID / Intune.",
                  action="Verify BitLocker recovery key escrow in Intune portal.")

        if re.search(r"TpmProtector|Tpm\b", txt, re.I):
            r.add("BitLocker", SEV_OK, "TPM protector active", "")

        return r


# ─────────────────────────────────────────────────────────────────────────────
# #7 Defender / EDR
# ─────────────────────────────────────────────────────────────────────────────

class DefenderAnalyzer:
    # Signature age threshold (days)
    SIG_MAX_DAYS = 3

    def analyse(self, ps_defender_file: str) -> HealthReport:
        r = HealthReport()
        txt = _read(ps_defender_file)
        if not txt:
            r.add("Defender", SEV_INFO, "Defender data unavailable",
                  "ps_defender_status not found.")
            return r

        if "unavailable" in txt.lower() or "not available" in txt.lower():
            r.add("Defender", SEV_WARN, "Defender status could not be retrieved",
                  txt[:200])
            return r

        def _val(key):
            m = re.search(rf"{key}\s*:\s*(.+)", txt, re.I)
            return m.group(1).strip() if m else ""

        # Real-time protection
        rtp = _val("RealTimeProtectionEnabled")
        if rtp.lower() == "true":
            r.add("Defender", SEV_OK, "Real-time protection enabled", "")
        elif rtp:
            r.add("Defender", SEV_ERROR, "Real-time protection DISABLED",
                  f"RealTimeProtectionEnabled={rtp}",
                  action="Re-enable via Intune Defender policy or local settings.")

        # Antivirus enabled
        av = _val("AntivirusEnabled")
        if av.lower() == "false":
            r.add("Defender", SEV_ERROR, "Antivirus disabled",
                  "AntivirusEnabled=False",
                  action="Check Tamper Protection and Intune Antivirus policy.")

        # Signature age
        for key, label in (("AntivirusSignatureLastUpdated", "Antivirus"),
                           ("AntispywareSignatureLastUpdated", "Antispyware")):
            val = _val(key)
            if val:
                import datetime as _dt
                for fmt in ("%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S",
                            "%d/%m/%Y %H:%M:%S"):
                    try:
                        dt = _dt.datetime.strptime(val.split(".")[0].strip(), fmt)
                        age = (_dt.datetime.now() - dt).days
                        if age > self.SIG_MAX_DAYS:
                            r.add("Defender", SEV_WARN,
                                  f"{label} signatures outdated ({age} days old)",
                                  f"Last updated: {val}",
                                  value=f"{age} days",
                                  action="Force Defender update or check network connectivity.")
                        else:
                            r.add("Defender", SEV_OK,
                                  f"{label} signatures up to date ({age} days old)", "")
                        break
                    except Exception:
                        pass

        # AM running mode
        mode = _val("AMRunningMode")
        if mode:
            if "passive" in mode.lower():
                r.add("Defender", SEV_WARN, "Defender running in Passive mode",
                      f"AMRunningMode={mode} — another AV may be primary.",
                      action="Verify EDR configuration if using a 3rd-party AV.")
            elif "normal" in mode.lower() or "active" in mode.lower():
                r.add("Defender", SEV_OK, f"Defender mode: {mode}", "")

        # Product versions
        ver = _val("AMProductVersion")
        if ver:
            r.add("Defender", SEV_INFO, f"Defender product version: {ver}", "")

        return r


# ─────────────────────────────────────────────────────────────────────────────
# #4 Performance
# ─────────────────────────────────────────────────────────────────────────────

class PerformanceAnalyzer:
    CPU_WARN_PERCENT  = 80    # % CPU per process
    RAM_WARN_GB       = 0.5   # working set < 0.5 GB total free → warn
    STARTUP_WARN_COUNT = 15

    def analyse(self, ps_top_proc_file: str,
                ps_startup_file: str,
                ps_system_info_file: str) -> HealthReport:
        r = HealthReport()

        # Top processes
        txt_proc = _read(ps_top_proc_file)
        if txt_proc:
            top_cpu = []
            for line in txt_proc.splitlines()[2:12]:   # skip header rows
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        cpu = float(parts[2].replace(",", "."))
                        if cpu > 50:
                            top_cpu.append(f"{parts[0]} ({cpu:.0f}s CPU)")
                    except Exception:
                        pass
            if top_cpu:
                r.add("Performance", SEV_WARN,
                      f"{len(top_cpu)} process(es) with high CPU time",
                      "High CPU consumers: " + ", ".join(top_cpu[:5]),
                      action="Investigate in Task Manager or Event Viewer.")
            else:
                r.add("Performance", SEV_OK, "No runaway CPU processes detected", "")

        # Startup items
        txt_startup = _read(ps_startup_file)
        if txt_startup:
            startup_lines = [l for l in txt_startup.splitlines()
                             if l.strip() and not l.startswith("-")
                             and "Name" not in l and "Command" not in l]
            count = len(startup_lines)
            if count > self.STARTUP_WARN_COUNT:
                r.add("Performance", SEV_WARN,
                      f"High startup program count ({count} items)",
                      f"{count} startup entries detected.",
                      value=str(count),
                      action="Review startup items via msconfig or Task Manager.")
            elif count > 0:
                r.add("Performance", SEV_OK,
                      f"Startup programs: {count} items", "")

        # System info — RAM
        txt_sys = _read(ps_system_info_file)
        if txt_sys:
            m = re.search(r"CsTotalPhysicalMemory\s*:\s*(\d+)", txt_sys)
            if m:
                ram_bytes = int(m.group(1))
                ram_gb = ram_bytes / 1_073_741_824
                if ram_gb < 4:
                    r.add("Performance", SEV_ERROR,
                          f"Insufficient RAM ({ram_gb:.1f} GB)",
                          "Minimum for Windows 11 is 4 GB; 8 GB recommended for Intune workloads.",
                          value=f"{ram_gb:.1f} GB",
                          action="Upgrade RAM or investigate memory-heavy processes.")
                elif ram_gb < 8:
                    r.add("Performance", SEV_WARN,
                          f"Low RAM ({ram_gb:.1f} GB)",
                          "8 GB recommended for smooth operation.",
                          value=f"{ram_gb:.1f} GB")
                else:
                    r.add("Performance", SEV_OK,
                          f"RAM: {ram_gb:.1f} GB", "")

        return r


# ─────────────────────────────────────────────────────────────────────────────
# #9 Storage
# ─────────────────────────────────────────────────────────────────────────────

class StorageAnalyzer:
    CRIT_FREE_PCT  = 10   # < 10% free → ERROR
    WARN_FREE_PCT  = 20   # < 20% free → WARN
    CRIT_FREE_GB   = 5    # < 5 GB free → always ERROR

    def analyse(self, ps_disk_file: str) -> HealthReport:
        r = HealthReport()
        txt = _read(ps_disk_file)
        if not txt:
            r.add("Storage", SEV_INFO, "Disk usage data unavailable", "")
            return r

        # Parse table: Name  Used  Free  Total  Free%
        drives_found = False
        for line in txt.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            name = parts[0]
            if len(name) != 1 or not name.isalpha():
                continue
            try:
                free_pct = float(parts[-1].replace(",", "."))
                free_raw = parts[2].replace(",", "")
                free_bytes = int(float(free_raw))
                free_gb = free_bytes / 1_073_741_824
                total_raw = parts[3].replace(",", "")
                total_gb = int(float(total_raw)) / 1_073_741_824
                drives_found = True

                if free_pct < self.CRIT_FREE_PCT or free_gb < self.CRIT_FREE_GB:
                    r.add("Storage", SEV_ERROR,
                          f"Drive {name}: critically low disk space",
                          f"{free_gb:.1f} GB free / {total_gb:.1f} GB total ({free_pct:.1f}% free)",
                          value=f"{free_pct:.1f}%",
                          action="Run Disk Cleanup, clear WinSxS, or expand disk.")
                elif free_pct < self.WARN_FREE_PCT:
                    r.add("Storage", SEV_WARN,
                          f"Drive {name}: low disk space",
                          f"{free_gb:.1f} GB free / {total_gb:.1f} GB total ({free_pct:.1f}% free)",
                          value=f"{free_pct:.1f}%")
                else:
                    r.add("Storage", SEV_OK,
                          f"Drive {name}: {free_gb:.1f} GB free ({free_pct:.1f}%)", "")
            except Exception:
                pass

        if not drives_found:
            r.add("Storage", SEV_INFO, "Could not parse disk usage table", txt[:200])

        return r


# ─────────────────────────────────────────────────────────────────────────────
# #6 Office / Modern Auth
# ─────────────────────────────────────────────────────────────────────────────

class OfficeAuthAnalyzer:
    # Known AAD/Office error codes from event logs
    AUTH_ERRORS = {
        "70011": "Invalid scope requested",
        "70016": "OAuth2 device flow timeout — Modern Auth failed",
        "70043": "Refresh token expired",
        "50076": "MFA required but not satisfied",
        "50126": "Invalid credentials / password expired",
        "50132": "Password expired — needs reset",
        "50133": "Session expired due to password change",
        "53003": "Conditional Access block",
        "65001": "Missing consent for app",
        "700082": "Refresh token expired (long-lived)",
        "AADSTS": "Azure AD authentication error",
    }

    def analyse(self, aad_evtx_text: str, proxy_file: str) -> HealthReport:
        r = HealthReport()

        if aad_evtx_text:
            found_codes = []
            for code, desc in self.AUTH_ERRORS.items():
                if code in aad_evtx_text:
                    found_codes.append(f"{code}: {desc}")

            if found_codes:
                r.add("Office Auth", SEV_ERROR,
                      f"{len(found_codes)} Modern Auth error(s) detected",
                      "\n".join(found_codes[:8]),
                      action="Check AAD Operational event log and Conditional Access policies.")
            else:
                r.add("Office Auth", SEV_OK,
                      "No Modern Auth errors detected in AAD event log", "")
        else:
            r.add("Office Auth", SEV_INFO,
                  "AAD Operational event log not available",
                  "Enable 'Microsoft-Windows-AAD/Operational' log or run Collect Diagnostics.")

        # Proxy check
        proxy_txt = _read(proxy_file)
        if proxy_txt:
            m = re.search(r"ProxyServer\s*:\s*(.+)", proxy_txt, re.I)
            if m and m.group(1).strip().lower() not in ("", "(none)", "direct"):
                proxy = m.group(1).strip()
                r.add("Office Auth", SEV_WARN,
                      f"Proxy configured: {proxy}",
                      "Proxies can interfere with Modern Auth token acquisition.",
                      value=proxy,
                      action="Verify proxy bypass list includes *.microsoftonline.com, "
                             "*.login.microsoft.com, *.office.com.")
        return r


# ─────────────────────────────────────────────────────────────────────────────
# #8 Drivers
# ─────────────────────────────────────────────────────────────────────────────

class DriverAnalyzer:
    # Known problematic driver publishers (partial match)
    RISKY_PUBLISHERS = ["unknown", "unsigned", "test certificate"]
    # Drivers older than this many days → warn
    OLD_DRIVER_DAYS = 365 * 2   # 2 years

    def analyse(self, drivers) -> HealthReport:
        """drivers: list of Driver dataclass objects from device_parser.DriversParser"""
        r = HealthReport()
        if not drivers:
            r.add("Drivers", SEV_INFO, "No driver data available", "")
            return r

        unsigned  = []
        old       = []

        import datetime as _dt
        today = _dt.date.today()

        for d in drivers:
            pub = (d.original_manufacturer or d.provider or "").lower()
            if any(rp in pub for rp in self.RISKY_PUBLISHERS):
                unsigned.append(d.inf_name or d.driver_description or "?")

            # Check driver date
            date_str = getattr(d, "driver_date", "") or ""
            if date_str:
                for fmt in ("%m/%d/%Y", "%Y-%m-%d", "%d/%m/%Y"):
                    try:
                        dt = _dt.datetime.strptime(date_str.strip(), fmt).date()
                        age_days = (today - dt).days
                        if age_days > self.OLD_DRIVER_DAYS:
                            name = d.driver_description or d.inf_name or "?"
                            old.append(f"{name} ({date_str}, {age_days//365} yr)")
                        break
                    except Exception:
                        pass

        total = len(drivers)
        if unsigned:
            r.add("Drivers", SEV_WARN,
                  f"{len(unsigned)} potentially unsigned/unknown driver(s)",
                  ", ".join(unsigned[:10]),
                  action="Verify driver signatures via sigverif.exe.")
        else:
            r.add("Drivers", SEV_OK, f"All {total} drivers have known publishers", "")

        if old:
            r.add("Drivers", SEV_WARN,
                  f"{len(old)} driver(s) older than 2 years",
                  ", ".join(old[:8]),
                  action="Update drivers via Windows Update or manufacturer site.")
        elif total > 0:
            r.add("Drivers", SEV_OK, "No significantly outdated drivers detected", "")

        return r


# ─────────────────────────────────────────────────────────────────────────────
# #10 Legacy Apps
# ─────────────────────────────────────────────────────────────────────────────

class LegacyAppAnalyzer:
    LEGACY_RUNTIMES = [
        "Visual C++ 2005", "Visual C++ 2008", "Visual C++ 2010",
        ".NET Framework 2.0", ".NET Framework 3.0",
        "Java 6", "Java 7", "Java 8",
        "Adobe Flash", "Silverlight",
        "Python 2.",
    ]

    def analyse(self, installed_apps: list) -> HealthReport:
        """installed_apps: list of dict with 'name', 'version', 'x64' keys"""
        r = HealthReport()
        if not installed_apps:
            r.add("Legacy Apps", SEV_INFO, "Installed apps list unavailable", "")
            return r

        apps_32bit  = []
        runtimes    = []

        for app in installed_apps:
            name    = app.get("name", "")
            is_x64  = app.get("x64", True)

            if not is_x64:
                apps_32bit.append(name)

            for rt in self.LEGACY_RUNTIMES:
                if rt.lower() in name.lower():
                    runtimes.append(name)
                    break

        if apps_32bit:
            r.add("Legacy Apps", SEV_WARN,
                  f"{len(apps_32bit)} 32-bit application(s) detected",
                  ", ".join(apps_32bit[:12]),
                  action="Verify compatibility with Windows 11 x64 architecture.")
        else:
            r.add("Legacy Apps", SEV_OK, "No 32-bit apps detected", "")

        if runtimes:
            r.add("Legacy Apps", SEV_ERROR,
                  f"{len(runtimes)} legacy/EOL runtime(s) installed",
                  ", ".join(runtimes[:10]),
                  action="Update or remove legacy runtimes (security risk + compat issues).")

        return r


# ─────────────────────────────────────────────────────────────────────────────
# Microsoft Store Apps
# ─────────────────────────────────────────────────────────────────────────────

class StoreAppAnalyzer:
    KNOWN_PROBLEMATIC = [
        "Microsoft.Teams", "Microsoft.MicrosoftEdge",
        "Microsoft.WindowsStore", "Microsoft.StorePurchaseApp",
    ]

    def analyse(self, ps_store_file: str) -> HealthReport:
        r = HealthReport()
        txt = _read(ps_store_file)
        if not txt or "unavailable" in txt.lower():
            r.add("Store Apps", SEV_INFO,
                  "Store apps list unavailable",
                  "Get-AppxPackage requires PowerShell; run Collect Diagnostics from the app.")
            return r

        lines = [l for l in txt.splitlines() if l.strip() and
                 not l.startswith("-") and "Name" not in l[:10]]
        count = len(lines)

        # Count provisioned vs user-installed
        ms_apps  = sum(1 for l in lines if "microsoft" in l.lower())
        oth_apps = count - ms_apps

        r.add("Store Apps", SEV_INFO,
              f"{count} Store app packages found",
              f"Microsoft: {ms_apps}  |  Third-party/Other: {oth_apps}")

        # Check for known problematic entries
        missing_critical = []
        for pkg in self.KNOWN_PROBLEMATIC:
            if not any(pkg.lower() in l.lower() for l in lines):
                missing_critical.append(pkg)

        if missing_critical:
            r.add("Store Apps", SEV_WARN,
                  "Some critical Store packages may be missing/deprovisioned",
                  ", ".join(missing_critical),
                  action="Re-provision via Intune or reinstall from Microsoft Store.")

        return r


# ─────────────────────────────────────────────────────────────────────────────
# Entra Join (RunLocalDsregcmd-V2.ps1 output)
# ─────────────────────────────────────────────────────────────────────────────

class EntraJoinAnalyzer:
    STATUS_MESSAGES = {
        "SUCCESS":                           (SEV_OK,   "Entra Join successful"),
        "INTUNE_ENROLLED":                   (SEV_OK,   "Device is Intune-enrolled (MDM)"),
        "SKIPPED":                           (SEV_INFO, "No remediation needed or applicable"),
        "LEAVE_NOT_APPLICABLE":              (SEV_INFO, "Leave not applicable in current state"),
        "LEAVE_SUCCESS":                     (SEV_OK,   "dsregcmd /leave executed successfully"),
        "NOT_DOMAIN_JOINED":                 (SEV_WARN, "Device is NOT domain-joined"),
        "DC_NOT_REACHABLE":                  (SEV_ERROR,"Domain controller not reachable"),
        "WAITING_FOR_AAD_CONNECT_LOCAL_RETRY": (SEV_WARN, "Missing device — waiting for AAD Connect sync"),
        "WAITING_FOR_AAD_CONNECT_LOCAL_RETRY_EXHAUSTED": (SEV_ERROR, "AAD Connect sync timeout — join still failing"),
        "WAITING_POST_LEAVE_LOCAL_RETRY":    (SEV_WARN, "Post-leave join in progress"),
        "WAITING_POST_LEAVE_LOCAL_RETRY_EXHAUSTED": (SEV_ERROR, "Post-leave join failed — still not joined"),
        "ERROR":                             (SEV_ERROR,"Script error during Entra Join check"),
    }

    def analyse(self, entra_diag_file: str) -> HealthReport:
        r = HealthReport()
        obj = _read_json(entra_diag_file)
        if not obj:
            r.add("Entra Join", SEV_INFO,
                  "Entra Join diagnostics not available",
                  "Run 'Collect diagnostics' from the app to execute RunLocalDsregcmd-V2.ps1.")
            return r

        status     = obj.get("status", "")
        aad_joined = obj.get("azure_ad_joined", "")
        auth_status = obj.get("device_auth_status", "")
        sub_code   = obj.get("server_error_sub_code", "")
        client_err = obj.get("client_error_code", "")
        err_phase  = obj.get("error_phase", "")
        tenant     = obj.get("tenant_name", "")
        dev_id     = obj.get("device_id", "")

        sev, msg = self.STATUS_MESSAGES.get(status, (SEV_WARN, f"Status: {status}"))
        detail = f"AzureAdJoined={aad_joined}"
        if auth_status:
            detail += f" | DeviceAuthStatus={auth_status[:80]}"
        if tenant:
            detail += f" | Tenant={tenant}"
        if dev_id:
            detail += f" | DeviceId={dev_id[:18]}..."

        r.add("Entra Join", sev, msg, detail)

        # Specific error conditions
        if sub_code == "error_missing_device":
            r.add("Entra Join", SEV_ERROR,
                  "Device object missing in Entra ID (error_missing_device)",
                  "Device record not found — AAD Connect may not have synced yet, or object was deleted.",
                  action="Wait for AAD Connect sync cycle (default 30 min) or force sync: "
                         "Start-ADSyncSyncCycle -PolicyType Delta")

        if client_err == "0x801c03f3":
            r.add("Entra Join", SEV_ERROR,
                  "Join error 0x801c03f3 — device not found in directory",
                  "The device certificate exists locally but no matching object in Entra ID.",
                  action="Force dsregcmd /leave then re-join, or delete and re-create device object.")

        if "FAILED" in str(auth_status).upper() and "disabled or deleted" in str(auth_status).lower():
            r.add("Entra Join", SEV_ERROR,
                  "Device disabled or deleted in Entra ID",
                  f"DeviceAuthStatus: {auth_status[:120]}",
                  action="Re-enable device in Entra ID portal, or run RunLocalDsregcmd-V2.ps1 "
                         "with -RunLeave to force re-registration.")

        if err_phase:
            r.add("Entra Join", SEV_INFO,
                  f"Error phase: {err_phase}",
                  f"ClientErrorCode={client_err}")

        return r


# ─────────────────────────────────────────────────────────────────────────────
# Master Health Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class HealthAnalyzer:
    """Orchestrates all health analyzers from extended/ folder files."""

    def __init__(self):
        self.report = HealthReport()
        self._ext_dir = ""

    def _f(self, name: str) -> str:
        """Resolve a filename in the extended/ folder."""
        if not self._ext_dir:
            return ""
        candidates = [
            os.path.join(self._ext_dir, name),
            os.path.join(self._ext_dir, name + ".txt"),
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c
        # Fuzzy match
        try:
            for fn in os.listdir(self._ext_dir):
                if name.lower() in fn.lower():
                    return os.path.join(self._ext_dir, fn)
        except Exception:
            pass
        return ""

    def analyse(self, ext_dir: str, drivers=None, installed_apps=None,
                aad_evtx_text: str = "") -> HealthReport:
        self._ext_dir = ext_dir
        r = self.report

        r.findings.extend(BitLockerAnalyzer().analyse(
            self._f("ps_bitlocker_status")).findings)

        r.findings.extend(DefenderAnalyzer().analyse(
            self._f("ps_defender_status")).findings)

        r.findings.extend(PerformanceAnalyzer().analyse(
            ps_top_proc_file=self._f("ps_top_processes"),
            ps_startup_file=self._f("ps_startup_programs"),
            ps_system_info_file=self._f("ps_system_info")).findings)

        r.findings.extend(StorageAnalyzer().analyse(
            self._f("ps_disk_usage")).findings)

        r.findings.extend(OfficeAuthAnalyzer().analyse(
            aad_evtx_text, self._f("ps_proxy_config")).findings)

        r.findings.extend(DriverAnalyzer().analyse(
            drivers or []).findings)

        r.findings.extend(LegacyAppAnalyzer().analyse(
            installed_apps or []).findings)

        r.findings.extend(StoreAppAnalyzer().analyse(
            self._f("ps_store_apps")).findings)

        r.findings.extend(EntraJoinAnalyzer().analyse(
            self._f("entra_join_diag")).findings)

        return r
