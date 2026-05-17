"""
zip_handler.py
Handles extraction and inventory of Intune Device Diagnostics ZIP files.
Supports the real Intune naming scheme: "(N) Category Name.ext"
Also sub-categorises IME log files by theme (agentexecutor, appworkload, etc.)
"""

import zipfile
import os
import re
import tempfile
import shutil
from pathlib import Path

IME_LOG_DIR  = "foldersfiles programdata_microsoft_intunemanagementextension_logs"
WU_ETL_DIR   = "foldersfiles windir_logs_windowsupdate_etl"
WU_ORCH_KEY  = "windowsupdate_orchestrator"

IME_THEMES = [
    "agentexecutor",
    "appactionprocessor",
    "appworkload",
    "clientcertcheck",
    "clienthealth",
    "devicehealthmonitoring",
    "healthscripts",
    "intunemanagementextension",
    "intuneremediations",
    "notificationinfralogs",
    "sensor",
    "win32appinventory",
]


def _get_ime_theme(basename):
    """Return the IME log theme for a filename like 'agentexecutor-20260410.log'."""
    bn = basename.lower()
    for theme in IME_THEMES:
        if bn.startswith(theme):
            return theme
    return None


def _get_evtx_type(basename):
    """
    Identify evtx file type from the Intune diagnostic naming pattern:
      (45) Events Application Events.evtx  -> 'evtx_application'
      (61) Events Setup Events.evtx        -> 'evtx_setup'
      (62) Events System Events.evtx       -> 'evtx_system'
    Returns None for any other .evtx file.
    """
    bn = basename.lower()
    if "setup" in bn:
        return "evtx_setup"
    if "system" in bn:
        return "evtx_system"
    if "application" in bn:
        return "evtx_application"
    return None


def _categorize(name):
    """Return a category string for a file path relative to the ZIP root."""
    basename = os.path.basename(name).lower()
    dirname  = os.path.dirname(name).lower()
    ext      = Path(name).suffix.lower()

    if IME_LOG_DIR in dirname:
        return "ime_logs"
    if WU_ETL_DIR in dirname:
        return "wu_etl"
    if WU_ORCH_KEY in basename:
        return "wu_registry"
    if "diagnosticlogcsp" in dirname:
        return "etl_logs"
    if "panther" in dirname or "setupact" in basename:
        return "setup_logs"
    if "cbs" in dirname and "cbs" in basename:
        return "cbs_logs"
    if "computername_log" in dirname:
        return "system_logs"

    if re.match(r'^\(\d+\) registrykey', basename):
        # Sub-categorize specific registry keys for fast lookup
        if "cloudmanagedupdate" in basename:
            return "reg_cloudmanagedupdate"
        if "currentversion_uninstall" in basename and "wow6432" not in basename:
            return "reg_uninstall_x64"
        if "wow6432node" in basename and "uninstall" in basename:
            return "reg_uninstall_x86"
        return "registry"
    if re.match(r'^\(\d+\) command', basename):
        # Sub-categorize specific command outputs
        if "pnputil" in basename:
            return "cmd_pnputil"
        if "wlan_show_profiles" in basename:
            return "cmd_wlan_profiles"
        if "certutil" in basename:
            return "cmd_certutil"
        return "command_output"
    if re.match(r'^\(\d+\) events', basename):
        return "event_logs"
    if re.match(r'^\(\d+\) folderfiles', basename):
        return "folder_files"
    if re.match(r'^\(\d+\) no results', basename):
        return "collection_errors"

    if basename == "results.xml":
        return "results_xml"

    if ext == ".evtx":  return "event_logs"
    if ext == ".etl":   return "etl_logs"
    if ext == ".reg":   return "registry"
    if ext == ".log":   return "log_files"
    if ext == ".cab":   return "cab"
    if ext == ".xml":   return "xml"
    if ext == ".json":  return "json"
    if ext == ".html":
        if "battery" in basename:
            return "battery_report"
        return "html"
    return "unknown"


class IntuneZipHandler:
    """Extracts and categorizes files from an Intune Device Diagnostics ZIP."""

    def __init__(self):
        self.zip_path       = ""
        self.extract_dir    = ""
        self.file_inventory = {}
        self._temp_dir      = ""

    def _cleanup(self):
        if self._temp_dir and os.path.isdir(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)
        self._temp_dir   = ""
        self.extract_dir = ""

    def __del__(self):
        self._cleanup()

    def load(self, zip_path):
        if not os.path.isfile(zip_path):
            raise FileNotFoundError(f"File not found: {zip_path}")
        if not zipfile.is_zipfile(zip_path):
            raise ValueError(f"Not a valid ZIP file: {zip_path}")

        self.zip_path = zip_path
        self._cleanup()
        self._temp_dir   = tempfile.mkdtemp(prefix="intune_diag_")
        self.extract_dir = self._temp_dir

        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(self._temp_dir)

        self.file_inventory = self._build_inventory(self._temp_dir)
        return self.file_inventory

    def _build_inventory(self, root):
        inventory = {"all_files": [], "ime_themes": {}}
        for dirpath, _, filenames in os.walk(root):
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                rel  = os.path.relpath(full, root)
                inventory["all_files"].append(full)
                cat = _categorize(rel)
                inventory.setdefault(cat, []).append(full)

                # Sub-categorise autopatch logs and C2R logs
                if cat == "log_files":
                    bn_lower = fname.lower()
                    if bn_lower.startswith("autopatchclient"):
                        inventory.setdefault("autopatch_logs", []).append(full)
                    elif bn_lower.startswith("wingetcom"):
                        inventory.setdefault("winget_logs", []).append(full)
                    elif ("clicktorun" in bn_lower or "c2rservice" in bn_lower
                          or bn_lower.startswith("c2r")):
                        inventory.setdefault("c2r_logs", []).append(full)

                # Also check system_logs for C2R (they can land there too)
                if cat == "system_logs":
                    bn_lower = fname.lower()
                    if ("clicktorun" in bn_lower or "c2rservice" in bn_lower
                            or bn_lower.startswith("c2r")):
                        inventory.setdefault("c2r_logs", []).append(full)

                # Sub-categorise IME logs by theme
                if cat == "ime_logs":
                    theme = _get_ime_theme(fname)
                    if theme:
                        inventory["ime_themes"].setdefault(theme, []).append(full)

                # Sub-categorise evtx event logs by type
                if cat == "event_logs" and Path(fname).suffix.lower() == ".evtx":
                    evtx_type = _get_evtx_type(fname)
                    if evtx_type:
                        inventory.setdefault(evtx_type, []).append(full)

        return inventory

    def get_file_content(self, file_path):
        for enc in ["utf-8", "utf-16", "latin-1", "cp1252"]:
            try:
                with open(file_path, "r", encoding=enc, errors="replace") as f:
                    return f.read()
            except Exception:
                continue
        return ""

    def get_zip_info(self):
        if not self.zip_path:
            return {}
        stat  = os.stat(self.zip_path)
        total = len(self.file_inventory.get("all_files", []))
        cats  = {c: len(v) for c, v in self.file_inventory.items()
                 if c not in ("all_files", "ime_themes")}
        ime_themes = {t: len(v)
                      for t, v in self.file_inventory.get("ime_themes", {}).items()}
        return {
            "zip_path":    self.zip_path,
            "zip_name":    os.path.basename(self.zip_path),
            "zip_size_mb": round(stat.st_size / (1024 * 1024), 1),
            "total_files": total,
            "extract_dir": self.extract_dir,
            "categories":  cats,
            "ime_themes":  ime_themes,
        }


    def find_file(self, keyword):
        kw = keyword.lower()
        for f in self.file_inventory.get("all_files", []):
            if kw in os.path.basename(f).lower():
                return f
        return None

    def find_files(self, keyword):
        kw = keyword.lower()
        return [f for f in self.file_inventory.get("all_files", [])
                if kw in os.path.basename(f).lower()]
