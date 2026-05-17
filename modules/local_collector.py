"""
local_collector.py
Collects comprehensive diagnostic data from the local Windows device.

Goes beyond the standard Intune "Collect diagnostics" portal ZIP by leveraging
direct OS access: Group Policy, BitLocker, Defender, disk health, processes,
services, security events, TPM, Secure Boot, pending reboots, and more.

ZIP structure is compatible with IntuneZipHandler for existing parsers, and adds
an 'extended/' folder with additional diagnostics for AI analysis and manual review.
"""

import os
import re
import sys
import shutil
import zipfile
import datetime
import subprocess
import tempfile
import threading
from pathlib import Path


# ── Executables ───────────────────────────────────────────────────────────────
SYS32          = r"C:\Windows\System32"
REG_EXE        = os.path.join(SYS32, "reg.exe")
WEVTUTIL       = os.path.join(SYS32, "wevtutil.exe")
CERTUTIL       = os.path.join(SYS32, "certutil.exe")
NETSH          = os.path.join(SYS32, "netsh.exe")
POWERCFG       = os.path.join(SYS32, "powercfg.exe")
IPCONFIG       = os.path.join(SYS32, "ipconfig.exe")
PNPUTIL        = os.path.join(SYS32, "pnputil.exe")
POWERSHELL     = os.path.join(SYS32, r"WindowsPowerShell\v1.0\powershell.exe")
MANAGE_BDE     = os.path.join(SYS32, "manage-bde.exe")
W32TM          = os.path.join(SYS32, "w32tm.exe")
GPRESULT       = os.path.join(SYS32, "gpresult.exe")
SYSTEMINFO     = os.path.join(SYS32, "systeminfo.exe")
SCHTASKS       = os.path.join(SYS32, "schtasks.exe")
WMIC           = os.path.join(SYS32, "wbem", "wmic.exe")
MDM_DIAG_TOOL  = os.path.join(SYS32, "MDMDiagnosticsTool.exe")

# ── Source log directories ────────────────────────────────────────────────────
IME_LOG_DIR   = r"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
WU_ETL_DIR    = r"C:\Windows\Logs\WindowsUpdate"
AUTOPATCH_DIR = r"C:\ProgramData\Microsoft\AutopatchClient\Logs"
C2R_LOG_DIR   = r"C:\ProgramData\Microsoft\ClickToRun\Logs"
C2R_LOG_DIR2  = r"C:\Program Files\Common Files\Microsoft Shared\ClickToRun\Logs"
PANTHER_DIR   = r"C:\Windows\Panther"
MINIDUMP_DIR  = r"C:\Windows\Minidump"

# ── Registry keys (Intune-compatible naming) ─────────────────────────────────
REGISTRY_KEYS = [
    ("MDM_Policy_Result",
     r"HKLM\SOFTWARE\Microsoft\PolicyManager\current\device"),
    ("MDM_Enrollment",
     r"HKLM\SOFTWARE\Microsoft\Enrollments"),
    ("MDM_DeviceManagement",
     r"HKLM\SOFTWARE\Microsoft\DeviceManageabilityCSP"),
    ("WindowsUpdate_Settings",
     r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"),
    ("WindowsUpdate_AU",
     r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"),
    ("WindowsUpdate_Orchestrator",
     r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator"),
    ("CloudManagedUpdate",
     r"HKLM\SOFTWARE\Microsoft\CloudManagedUpdate"),
    # Named to match zip_handler categorization
    ("CurrentVersion_Uninstall",
     r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("WOW6432Node_Uninstall",
     r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("IntuneManagementExtension",
     r"HKLM\SOFTWARE\Microsoft\IntuneManagementExtension"),
    ("DSRegCmd_State",
     r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ"),
]

# ── Commands compatible with existing parsers ─────────────────────────────────
# label must match zip_handler categorization keywords:
#   "pnputil"            -> cmd_pnputil
#   "wlan_show_profiles" -> cmd_wlan_profiles
#   "certutil"           -> cmd_certutil
COMMANDS_INTUNE = [
    ("dsregcmd_status",    "dsregcmd.exe", ["/status"]),
    ("ipconfig_all",       IPCONFIG,       ["/all"]),
    ("pnputil_drivers",    PNPUTIL,        ["/enum-drivers"]),
    ("wlan_show_profiles", NETSH,          ["wlan", "show", "profiles"]),
]

# ── Event channels (Intune-compatible) ───────────────────────────────────────
EVENT_CHANNELS = [
    ("Application", "Application"),
    ("System",      "System"),
    ("Setup",       "Setup"),
    ("Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
     "MDM_Admin"),
    ("Microsoft-Windows-AAD/Operational",
     "AAD_Operational"),
]

# ── PowerShell one-liners for extended diagnostics ───────────────────────────
PS_COMMANDS = [
    # System & hardware
    ("ps_system_info",
     "Get-ComputerInfo | Select CsName,OsName,OsVersion,OsBuildNumber,"
     "OsArchitecture,CsProcessors,CsTotalPhysicalMemory,OsLastBootUpTime,"
     "BiosBIOSVersion,BiosManufacturer,CsModel,CsManufacturer,"
     "HyperVisorPresent,OsLanguage,WindowsInstallationType | Format-List"),

    ("ps_disk_usage",
     "Get-PSDrive -PSProvider FileSystem | Select Name,Used,Free,"
     "@{N='Total';E={$_.Used+$_.Free}},"
     "@{N='Free%';E={if($_.Used+$_.Free -gt 0)"
     "{[math]::Round($_.Free/($_.Used+$_.Free)*100,1)}}} | Format-Table -AutoSize"),

    ("ps_pending_reboot",
     "$regs = @("
     "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending',"
     "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired',"
     "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager',"
     "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootInProgress'"
     "); foreach($r in $regs){ $n=$r.Split('\\')[-1]; $e=Test-Path $r; "
     "if($r -like '*Session Manager'){ $pfr=(Get-ItemProperty $r -EA SilentlyContinue).PendingFileRenameOperations; "
     "$e=$pfr.Count -gt 0 }; [PSCustomObject]@{Key=$n;PendingReboot=$e} } | Format-Table -AutoSize"),

    ("ps_bitlocker_status",
     "try { Get-BitLockerVolume | Select MountPoint,VolumeStatus,ProtectionStatus,"
     "EncryptionPercentage,VolumeType,KeyProtector | Format-List } "
     "catch { 'Get-BitLockerVolume not available. Trying manage-bde:'; "
     "& manage-bde -status 2>&1 }"),

    ("ps_defender_status",
     "try { Get-MpComputerStatus | Select AMRunningMode,AntivirusEnabled,"
     "AntispywareEnabled,RealTimeProtectionEnabled,OnAccessProtectionEnabled,"
     "IoavProtectionEnabled,BehaviorMonitorEnabled,"
     "AntivirusSignatureLastUpdated,AntispywareSignatureLastUpdated,"
     "FullScanEndTime,QuickScanEndTime,LastFullScanSource,"
     "AMProductVersion,AMEngineVersion | Format-List } "
     "catch { 'Windows Defender info unavailable: ' + $_.Exception.Message }"),

    ("ps_tpm_status",
     "try { Get-Tpm | Select TpmPresent,TpmReady,TpmEnabled,TpmActivated,"
     "TpmOwned,ManagedAuthLevel,ManufacturerId,ManufacturerVersion,"
     "ManufacturerVersionFull20,SpecVersion | Format-List } "
     "catch { 'TPM info unavailable: ' + $_.Exception.Message }"),

    ("ps_secureboot",
     "try { $sb = Confirm-SecureBootUEFI; "
     "[PSCustomObject]@{SecureBootEnabled=$sb} | Format-List } "
     "catch { 'Secure Boot check: ' + $_.Exception.Message }"),

    ("ps_top_processes",
     "Get-Process | Sort-Object CPU -Descending | Select-Object -First 40 "
     "Name,Id,CPU,WorkingSet,SessionId,StartTime,Path | Format-Table -AutoSize"),

    ("ps_services_abnormal",
     "Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } | "
     "Select-Object Name,DisplayName,Status,StartType | Sort-Object Name | Format-Table -AutoSize"),

    ("ps_services_all",
     "Get-Service | Select Name,DisplayName,Status,StartType | "
     "Sort-Object StartType,Status,Name | Format-Table -AutoSize"),

    ("ps_timesync",
     "w32tm /query /status; echo '---'; w32tm /query /configuration"),

    ("ps_user_profiles",
     "Get-WmiObject Win32_UserProfile | Select LocalPath,SID,LastUseTime,Special,"
     "@{N='SizeMB';E={try{[math]::Round((Get-ChildItem $_.LocalPath -Recurse -EA SilentlyContinue | "
     "Measure-Object Length -Sum).Sum/1MB,1)}catch{0}}} | "
     "Sort-Object LastUseTime -Descending | Format-Table -AutoSize"),

    ("ps_hotfixes",
     "Get-HotFix | Select HotFixID,InstalledOn,Description,InstalledBy | "
     "Sort-Object InstalledOn -Descending | Format-Table -AutoSize"),

    ("ps_network_adapters",
     "Get-NetAdapter | Select Name,InterfaceDescription,Status,MacAddress,LinkSpeed | Format-Table -AutoSize; "
     "echo '---'; Get-NetIPConfiguration | Format-List"),

    ("ps_dns_config",
     "Get-DnsClientServerAddress | Where-Object AddressFamily -eq 2 | "
     "Select InterfaceAlias,ServerAddresses | Format-Table -AutoSize"),

    ("ps_open_ports",
     "Get-NetTCPConnection -State Listen | "
     "Select LocalAddress,LocalPort,State,"
     "@{N='Process';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}} | "
     "Sort-Object LocalPort | Format-Table -AutoSize"),

    ("ps_scheduled_tasks_abnormal",
     "Get-ScheduledTask | Where-Object { $_.State -eq 'Disabled' -or "
     "($_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -eq 'Ready') } | "
     "Select TaskName,TaskPath,State | Sort-Object TaskPath | Format-Table -AutoSize"),

    ("ps_startup_programs",
     "Get-CimInstance Win32_StartupCommand | Select Name,Command,Location,User | Format-Table -AutoSize"),

    ("ps_env_vars",
     "[System.Environment]::GetEnvironmentVariables('Machine') | "
     "ConvertTo-Json -Compress | ConvertFrom-Json | Format-List"),

    ("ps_powershell_policy",
     "Get-ExecutionPolicy -List | Format-Table -AutoSize; "
     "echo '---Constrained Language Mode:'; "
     "$ExecutionContext.SessionState.LanguageMode"),

    ("ps_windows_activation",
     "Get-WmiObject SoftwareLicensingProduct | Where-Object { "
     "$_.PartialProductKey -and $_.ApplicationId -eq '55c92734-d682-4d71-983e-d6ec3f16059f' } | "
     "Select Name,LicenseStatus,PartialProductKey,@{N='Status';E={ "
     "switch($_.LicenseStatus){1{'Licensed'};2{'OOBGrace'};3{'OOTGrace'};4{'NonGenuine'};"
     "5{'Notification'};6{'ExtendedGrace'};default{'Unknown'}} }} | Format-List"),

    ("ps_shared_folders",
     "Get-SmbShare | Select Name,Path,Description,ShareState | Format-Table -AutoSize"),

    ("ps_recent_errors",
     "Get-EventLog -LogName System -EntryType Error -Newest 50 2>$null | "
     "Select TimeGenerated,Source,EventID,Message | Format-Table -AutoSize -Wrap"),

    ("ps_proxy_config",
     "netsh winhttp show proxy; echo '---IE/System Proxy:'; "
     "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | "
     "Select ProxyEnable,ProxyServer,ProxyOverride | Format-List"),

    ("ps_update_history",
     "$Session = New-Object -ComObject Microsoft.Update.Session; "
     "$Searcher = $Session.CreateUpdateSearcher(); "
     "$Count = $Searcher.GetTotalHistoryCount(); "
     "$History = $Searcher.QueryHistory(0,[math]::Min($Count,50)); "
     "$History | Select Date,Title,"
     "@{N='Result';E={switch($_.ResultCode){1{'InProgress'};2{'Succeeded'};"
     "3{'SucceededWithErrors'};4{'Failed'};5{'Aborted'};default{$_.ResultCode}}}} | "
     "Format-Table -AutoSize"),

    ("ps_intune_enrollment",
     "dsregcmd /status; echo '---'; "
     "Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Enrollments' -EA SilentlyContinue | "
     "ForEach-Object { Get-ItemProperty $_.PSPath -EA SilentlyContinue } | "
     "Where-Object { $_.EnrollmentType } | "
     "Select PSChildName,EnrollmentType,UPN,DiscoveryServiceFullURL | Format-List"),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(cmd, timeout=60, shell=False, **kw):
    """Run a command quietly; never raises. Returns CompletedProcess."""
    try:
        return subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW,
            shell=shell, **kw)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        r = subprocess.CompletedProcess(cmd, -1)
        r.stdout = b""
        r.stderr = str(e).encode()
        return r


def _run_ps(ps_code, timeout=60):
    """Run a PowerShell one-liner; return decoded stdout string."""
    cmd = [
        POWERSHELL if os.path.isfile(POWERSHELL) else "powershell.exe",
        "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command", ps_code,
    ]
    r = _run(cmd, timeout=timeout)
    out = (r.stdout or b"").decode("utf-8", errors="replace")
    err = (r.stderr or b"").decode("utf-8", errors="replace")
    return out + (f"\n[STDERR]\n{err}" if err.strip() else "")


def _decode_console(raw: bytes) -> str:
    """Decode Windows console (OEM) output with fallback chain."""
    if not raw:
        return ""
    for enc in ("utf-8", "oem", "cp850", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", errors="replace")


def _copy_dir(src, dst, max_files=200, max_age_days=30, extensions=None):
    """Copy recent files from src to dst."""
    if not os.path.isdir(src):
        return 0
    os.makedirs(dst, exist_ok=True)
    cutoff = datetime.datetime.now().timestamp() - max_age_days * 86400
    copied = 0
    files = sorted(Path(src).iterdir(),
                   key=lambda p: p.stat().st_mtime if p.is_file() else 0,
                   reverse=True)
    for p in files:
        if not p.is_file():
            continue
        if extensions and p.suffix.lower() not in extensions:
            continue
        try:
            if p.stat().st_mtime < cutoff:
                continue
            shutil.copy2(p, os.path.join(dst, p.name))
            copied += 1
            if copied >= max_files:
                break
        except Exception:
            pass
    return copied


def _write_text(dest, text, header=None):
    """Write text to dest file with optional header comment."""
    try:
        with open(dest, "w", encoding="utf-8") as f:
            if header:
                f.write(f"# {header}\n# Collected: {datetime.datetime.now()}\n\n")
            f.write(text or "(no output)")
        return True
    except Exception:
        return False


# ── Main collector class ──────────────────────────────────────────────────────

class LocalCollector:
    """
    Comprehensive local device diagnostics collector.
    Produces a ZIP compatible with IntuneZipHandler plus extended diagnostics.
    """

    def __init__(self):
        self.results = []
        self._n = 0
        self._lock = threading.Lock()

    def _next_n(self):
        with self._lock:
            self._n += 1
            return self._n

    # ── Public API ─────────────────────────────────────────────────────────────

    def collect(self, out_dir, progress_cb=None):
        os.makedirs(out_dir, exist_ok=True)
        self._n = 0
        self.results = []

        # Extended folder for non-Intune diagnostics
        ext_dir = os.path.join(out_dir, "extended")
        os.makedirs(ext_dir, exist_ok=True)

        steps = [
            # ── Intune-compatible (parsers expect these) ──────────────────────
            ("IME Logs",            lambda d: self._step_ime_logs(d)),
            ("WU ETL Logs",         lambda d: self._step_wu_etl(d)),
            ("AutoPatch Logs",      lambda d: self._step_autopatch(d)),
            ("Office C2R Logs",     lambda d: self._step_c2r_logs(d)),
            ("Windows Setup Logs",  lambda d: self._step_panther(d)),
            ("Registry Keys",       lambda d: self._step_registry(d)),
            ("Command Outputs",     lambda d: self._step_commands_intune(d)),
            ("Event Logs (EVTX)",   lambda d: self._step_evtx(d)),
            ("Battery Report",      lambda d: self._step_battery(d)),
            ("Certificates",        lambda d: self._step_certs(d)),
            ("Firewall Status",     lambda d: self._step_firewall(d)),

            # ── Extended diagnostics (beyond Intune portal) ───────────────────
            ("System Info",          lambda d: self._step_ps("ps_system_info",            ext_dir)),
            ("Disk Usage",           lambda d: self._step_ps("ps_disk_usage",             ext_dir)),
            ("Pending Reboot",       lambda d: self._step_ps("ps_pending_reboot",         ext_dir)),
            ("BitLocker",            lambda d: self._step_ps("ps_bitlocker_status",        ext_dir)),
            ("Windows Defender",     lambda d: self._step_ps("ps_defender_status",        ext_dir)),
            ("TPM Status",           lambda d: self._step_ps("ps_tpm_status",             ext_dir)),
            ("Secure Boot",          lambda d: self._step_ps("ps_secureboot",             ext_dir)),
            ("Top Processes",        lambda d: self._step_ps("ps_top_processes",          ext_dir)),
            ("Abnormal Services",    lambda d: self._step_ps("ps_services_abnormal",      ext_dir)),
            ("All Services",         lambda d: self._step_ps("ps_services_all",           ext_dir)),
            ("Time Sync",            lambda d: self._step_ps("ps_timesync",               ext_dir)),
            ("User Profiles",        lambda d: self._step_ps("ps_user_profiles",          ext_dir)),
            ("Installed Hotfixes",   lambda d: self._step_ps("ps_hotfixes",               ext_dir)),
            ("Network Adapters",     lambda d: self._step_ps("ps_network_adapters",       ext_dir)),
            ("DNS Config",           lambda d: self._step_ps("ps_dns_config",             ext_dir)),
            ("Open Ports (Listen)",  lambda d: self._step_ps("ps_open_ports",             ext_dir)),
            ("Scheduled Tasks",      lambda d: self._step_ps("ps_scheduled_tasks_abnormal", ext_dir)),
            ("Startup Programs",     lambda d: self._step_ps("ps_startup_programs",       ext_dir)),
            ("PowerShell Policy",    lambda d: self._step_ps("ps_powershell_policy",      ext_dir)),
            ("Windows Activation",   lambda d: self._step_ps("ps_windows_activation",     ext_dir)),
            ("Shared Folders",       lambda d: self._step_ps("ps_shared_folders",         ext_dir)),
            ("Recent System Errors", lambda d: self._step_ps("ps_recent_errors",          ext_dir)),
            ("Proxy Config",         lambda d: self._step_ps("ps_proxy_config",           ext_dir)),
            ("Update History",       lambda d: self._step_ps("ps_update_history",         ext_dir)),
            ("Intune Enrollment",    lambda d: self._step_ps("ps_intune_enrollment",      ext_dir)),
            ("MDM Diagnostics CAB",  lambda d: self._step_mdmdiag(out_dir)),
            ("Group Policy Report",  lambda d: self._step_gpresult(ext_dir)),
            ("WU Decoded Log",       lambda d: self._step_wu_log(ext_dir)),
            ("Recent Crash Dumps",   lambda d: self._step_minidumps(ext_dir)),
            ("Results manifest",     lambda d: self._step_results_xml(d)),
        ]

        total = len(steps)
        for i, (name, fn) in enumerate(steps, 1):
            if progress_cb:
                progress_cb(i, total, name)
            try:
                status = fn(out_dir)
                self.results.append((name, status or "OK"))
            except Exception as exc:
                self.results.append((name, f"Error: {exc}"))

        return self.results

    # ── Intune-compatible steps ────────────────────────────────────────────────

    def _step_ime_logs(self, out_dir):
        dst = os.path.join(
            out_dir,
            "foldersfiles programdata_microsoft_intunemanagementextension_logs")
        n = _copy_dir(IME_LOG_DIR, dst, max_files=300,
                      max_age_days=30, extensions={".log"})
        return f"OK ({n} files)" if n else "Skipped (no IME logs)"

    def _step_wu_etl(self, out_dir):
        dst = os.path.join(out_dir, "foldersfiles windir_logs_windowsupdate_etl")
        n = _copy_dir(WU_ETL_DIR, dst, max_files=60,
                      max_age_days=14, extensions={".etl"})
        return f"OK ({n} files)" if n else "Skipped"

    def _step_autopatch(self, out_dir):
        dst = os.path.join(out_dir, "foldersfiles autopatchclient_logs")
        n = _copy_dir(AUTOPATCH_DIR, dst, max_files=50,
                      max_age_days=30, extensions={".log"})
        return f"OK ({n} files)" if n else "Skipped"

    def _step_c2r_logs(self, out_dir):
        dst = os.path.join(out_dir, "foldersfiles clicktorun_logs")
        n = sum(_copy_dir(src, dst, max_files=40, max_age_days=14,
                          extensions={".log"})
                for src in (C2R_LOG_DIR, C2R_LOG_DIR2))
        return f"OK ({n} files)" if n else "Skipped"

    def _step_panther(self, out_dir):
        dst = os.path.join(out_dir, "foldersfiles windir_panther")
        n = _copy_dir(PANTHER_DIR, dst, max_files=10, max_age_days=90,
                      extensions={".log", ".xml"})
        return f"OK ({n} files)" if n else "Skipped"

    def _step_registry(self, out_dir):
        exported = 0
        for label, key in REGISTRY_KEYS:
            n = self._next_n()
            fname = f"({n}) RegistryKey {label}.reg"
            dest  = os.path.join(out_dir, fname)
            r = _run([REG_EXE, "export", key, dest, "/y"], timeout=30)
            if os.path.isfile(dest) and os.path.getsize(dest) > 10:
                exported += 1
            else:
                try:
                    with open(dest, "w", encoding="utf-8") as f:
                        f.write(f"; Export failed for {key}\n; RC={r.returncode}\n")
                except Exception:
                    pass
        return f"OK ({exported}/{len(REGISTRY_KEYS)} keys)"

    def _step_commands_intune(self, out_dir):
        ran = 0
        for label, exe, args in COMMANDS_INTUNE:
            n     = self._next_n()
            fname = f"({n}) Command {label}.txt"
            dest  = os.path.join(out_dir, fname)
            cmd   = [exe] + args
            r     = _run(cmd, timeout=30)
            out   = _decode_console(r.stdout or b"")
            err   = _decode_console(r.stderr or b"")
            if _write_text(dest, out + (f"\n--- STDERR ---\n{err}" if err else "")):
                ran += 1
        return f"OK ({ran} commands)"

    def _step_evtx(self, out_dir):
        if not os.path.isfile(WEVTUTIL):
            return "Skipped (wevtutil not found)"
        exported = 0
        for channel, label in EVENT_CHANNELS:
            n    = self._next_n()
            dest = os.path.join(out_dir, f"({n}) Events {label} Events.evtx")
            r = _run([WEVTUTIL, "epl", channel, dest,
                      "/q:*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]"],
                     timeout=60)
            if os.path.isfile(dest) and os.path.getsize(dest) > 0:
                exported += 1
        return f"OK ({exported}/{len(EVENT_CHANNELS)} channels)"

    def _step_battery(self, out_dir):
        if not os.path.isfile(POWERCFG):
            return "Skipped"
        # Plain filename so zip_handler categorizes as battery_report via .html+battery check
        dest = os.path.join(out_dir, "battery-report.html")
        _run([POWERCFG, "/batteryreport", "/output", dest, "/duration", "14"],
             timeout=30)
        if os.path.isfile(dest) and os.path.getsize(dest) > 100:
            return "OK"
        return "Skipped (no battery / failed)"

    def _step_certs(self, out_dir):
        n    = self._next_n()
        dest = os.path.join(out_dir, f"({n}) Command certutil_My_store.txt")
        r = _run([CERTUTIL, "-store", "My"], timeout=30)
        out = _decode_console(r.stdout or b"")
        _write_text(dest, out)
        return "OK"

    def _step_firewall(self, out_dir):
        """Run netsh advfirewall; filename matched by find_file('advfirewall_show_allprofiles')."""
        n    = self._next_n()
        dest = os.path.join(out_dir,
                            f"({n}) Command netsh_advfirewall_show_allprofiles.txt")
        try:
            r = subprocess.run(
                'cmd /c "chcp 437 >nul 2>&1 & netsh advfirewall show allprofiles"',
                shell=True, capture_output=True, timeout=20,
                creationflags=subprocess.CREATE_NO_WINDOW)
            out = (r.stdout or b"").decode("cp437", errors="replace")
        except Exception:
            r2  = _run([NETSH, "advfirewall", "show", "allprofiles"], timeout=20)
            out = _decode_console(r2.stdout or b"")
        _write_text(dest, out)
        return "OK"

    # ── Extended diagnostic steps ─────────────────────────────────────────────

    def _step_ps(self, label, ext_dir):
        """Run a named PowerShell command from PS_COMMANDS and write to ext_dir."""
        ps_map = {cmd[0]: cmd[1] for cmd in PS_COMMANDS}
        code = ps_map.get(label, "")
        if not code:
            return f"Skipped (unknown label {label!r})"
        out = _run_ps(code, timeout=60)
        dest = os.path.join(ext_dir, f"{label}.txt")
        header = label.replace("ps_", "").replace("_", " ").title()
        _write_text(dest, out, header=header)
        lines = out.strip().count("\n") + 1 if out.strip() else 0
        return f"OK ({lines} lines)"

    def _step_mdmdiag(self, out_dir):
        """
        Run MDMDiagnosticsTool.exe -out to generate the full MDM diagnostics CAB.
        The CAB lands in a mdmdiag/ subfolder so zip_handler picks it up as
        category 'cab', which triggers auto-extract and populates MDM Diagnostics tab.
        Requires admin rights — silently skipped if tool is absent or access denied.
        """
        if not os.path.isfile(MDM_DIAG_TOOL):
            return "Skipped (MDMDiagnosticsTool.exe not found)"
        diag_dir = os.path.join(out_dir, "mdmdiag")
        os.makedirs(diag_dir, exist_ok=True)
        r = _run([MDM_DIAG_TOOL, "-out", diag_dir], timeout=120)
        cabs = list(Path(diag_dir).glob("*.cab"))
        if cabs:
            return f"OK ({len(cabs)} CAB file(s): {', '.join(c.name for c in cabs)})"
        all_files = list(Path(diag_dir).rglob("*.*"))
        if all_files:
            # Some Windows versions output files without packaging into a CAB
            return f"OK (no CAB — {len(all_files)} diagnostic file(s) generated)"
        err = _decode_console(r.stderr or b"").strip()[:120]
        return f"Skipped (no output — RC={r.returncode}{f': {err}' if err else ''})"

    def _step_gpresult(self, ext_dir):
        """Group Policy result HTML report."""
        if not os.path.isfile(GPRESULT):
            return "Skipped (gpresult not found)"
        dest = os.path.join(ext_dir, "gpresult.html")
        r = _run([GPRESULT, "/H", dest, "/F"], timeout=60)
        if os.path.isfile(dest) and os.path.getsize(dest) > 500:
            return f"OK ({os.path.getsize(dest)//1024} KB)"
        # Fallback to text report
        r2  = _run([GPRESULT, "/Z"], timeout=30)
        out = _decode_console(r2.stdout or b"")
        txt_dest = os.path.join(ext_dir, "gpresult_text.txt")
        _write_text(txt_dest, out, header="Group Policy Result (text fallback)")
        return "OK (text fallback)" if out else "Skipped (gpresult empty)"

    def _step_wu_log(self, ext_dir):
        """
        Decode all WU ETL files into a single readable WindowsUpdate.log
        using Get-WindowsUpdateLog (official Microsoft tool, Win10/11).
        Falls back to noting that raw ETL files are available in wu_etl/.
        Note: first run downloads format DLLs from Microsoft symbol server
        and may take 1-2 minutes; subsequent runs are faster.
        """
        dest = os.path.join(ext_dir, "WindowsUpdate.log")
        ps = (
            f"try {{"
            f"  Get-WindowsUpdateLog -LogPath '{dest}' -ErrorAction Stop | Out-Null; "
            f"  $size = (Get-Item '{dest}' -EA SilentlyContinue).Length; "
            f"  \"OK size=$size\" "
            f"}} catch {{"
            f"  \"FAILED: \" + $_.Exception.Message "
            f"}}"
        )
        out = _run_ps(ps, timeout=180)   # symbol download can be slow
        out_stripped = out.strip()

        if os.path.isfile(dest) and os.path.getsize(dest) > 1000:
            kb = os.path.getsize(dest) // 1024
            return f"OK ({kb} KB)"

        # Fallback: note that raw ETLs are available and explain why
        note = (
            "Get-WindowsUpdateLog could not produce the log.\n"
            f"PowerShell output: {out_stripped}\n\n"
            "Raw ETL files are collected in the wu_etl/ folder and decoded\n"
            "by the Windows Update tab using tracerpt.exe.\n\n"
            "To decode manually:\n"
            "  Get-WindowsUpdateLog -LogPath C:\\Temp\\WindowsUpdate.log\n"
            "(requires internet access to download Microsoft symbol DLLs)"
        )
        _write_text(dest, note, header="Windows Update Log (Get-WindowsUpdateLog)")
        return f"Skipped ({out_stripped[:80]})" if out_stripped else "Skipped (no output)"

    def _step_minidumps(self, ext_dir):
        """List recent BSOD crash dump files."""
        if not os.path.isdir(MINIDUMP_DIR):
            return "Skipped (no Minidump folder)"
        dumps = sorted(Path(MINIDUMP_DIR).glob("*.dmp"),
                       key=lambda p: p.stat().st_mtime, reverse=True)[:20]
        lines = ["Recent BSOD crash dumps:\n"]
        for d in dumps:
            ts = datetime.datetime.fromtimestamp(d.stat().st_mtime)
            lines.append(
                f"  {d.name:40s}  {d.stat().st_size//1024:6d} KB  {ts:%Y-%m-%d %H:%M}")
        dest = os.path.join(ext_dir, "crash_dumps_list.txt")
        _write_text(dest, "\n".join(lines),
                    header=f"Minidump files ({len(dumps)} found)")
        return f"OK ({len(dumps)} dumps found)"

    def _step_results_xml(self, out_dir):
        """Write a results.xml manifest for parser compatibility."""
        now   = datetime.datetime.now().isoformat()
        lines = ['<?xml version="1.0" encoding="utf-8"?>',
                 f'<DiagnosticResults CollectionTime="{now}" Source="LocalCollector">']
        for name, status in self.results:
            safe = (name.replace("&", "&amp;")
                    .replace("<", "&lt;").replace(">", "&gt;"))
            ok   = "true" if status.startswith("OK") else "false"
            lines.append(
                f'  <Item name="{safe}" success="{ok}" detail="{status}"/>')
        lines.append("</DiagnosticResults>")
        dest = os.path.join(out_dir, "results.xml")
        try:
            with open(dest, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            return "OK"
        except Exception as e:
            return f"Error: {e}"


# ── Public entry point ────────────────────────────────────────────────────────

def collect_and_zip(save_path, progress_cb=None):
    """
    Collect all diagnostics into a temp dir, then ZIP to save_path.
    progress_cb(current, total, step_name) is called for each step.
    Returns list of (step, status) tuples.
    """
    tmp = tempfile.mkdtemp(prefix="intune_local_full_")
    try:
        out_dir = os.path.join(tmp, "collected")
        os.makedirs(out_dir, exist_ok=True)

        collector = LocalCollector()
        results   = collector.collect(out_dir, progress_cb=progress_cb)

        if progress_cb:
            progress_cb(99, 100, "Creating ZIP archive")

        with zipfile.ZipFile(save_path, "w", zipfile.ZIP_DEFLATED,
                             allowZip64=True) as zf:
            for root, dirs, files in os.walk(out_dir):
                for fname in files:
                    full    = os.path.join(root, fname)
                    arcname = os.path.relpath(full, out_dir)
                    zf.write(full, arcname)

        return results
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
