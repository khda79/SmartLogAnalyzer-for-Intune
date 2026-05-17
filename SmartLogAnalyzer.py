"""
SmartLogAnalyzer for Intune
===========================
Analyzes Intune Device Diagnostics ZIP files downloaded from the
Microsoft Intune console: Devices > [Device] > Device diagnostics.

Usage : python SmartLogAnalyzer.py
Build : build.bat   (PyInstaller)
"""

import os
import sys
import threading
import re
import datetime
import webbrowser
import urllib.parse
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

_BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _BASE_DIR)

from modules.zip_handler        import IntuneZipHandler, IME_THEMES
from modules.mdm_parser         import MDMParser
from modules.error_detector     import ErrorDetector
from modules.compliance_checker import ComplianceChecker
from modules.report_generator   import ReportGenerator
from modules.wu_parser          import WUParser
from modules.extra_parser       import ExtraParser
from modules.mdm_diag_parser    import MDMDiagParser
from modules.evtx_parser        import EvtxParser
from modules.device_parser      import DeviceParser
from modules.hardware_parser    import HardwareParser
from modules.local_collector    import collect_and_zip
from modules.ai_analyzer        import AIAnalyzer, AIConfig, build_context, build_prompt, PROVIDERS

# Color palette
C_BG       = "#1e1e2e"
C_SURFACE  = "#2a2a3e"
C_PANEL    = "#313149"
C_ACCENT   = "#0078d4"
C_ACCENT2  = "#00bcf2"
C_TEXT     = "#cdd6f4"
C_TEXT_DIM = "#a6adc8"
C_ERROR    = "#f38ba8"
C_WARN     = "#fab387"
C_OK       = "#a6e3a1"
C_HEADER   = "#89dceb"

FONT_BODY  = ("Segoe UI", 10)
FONT_BOLD  = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 13, "bold")
FONT_MONO  = ("Consolas", 9)

# IME theme display names
IME_THEME_LABELS = {
    "agentexecutor":           "Agent Executor",
    "appactionprocessor":      "App Action Processor",
    "appworkload":             "App Workload",
    "clientcertcheck":         "Client Cert Check",
    "clienthealth":            "Client Health",
    "devicehealthmonitoring":  "Device Health Monitoring",
    "healthscripts":           "Health Scripts",
    "intunemanagementextension": "IME (Main)",
    "intuneremediations":      "Remediations",
    "notificationinfralogs":   "Notifications",
    "sensor":                  "Sensor",
    "win32appinventory":       "Win32 App Inventory",
}


class SmartLogAnalyzerApp(tk.Tk):

    APP_NAME    = "SmartLogAnalyzer for Intune"
    APP_VERSION = "2.1.0"

    def __init__(self):
        super().__init__()
        self.title(f"{self.APP_NAME}  v{self.APP_VERSION}")
        self.geometry("1280x860")
        self.minsize(960, 640)
        self.configure(bg=C_BG)

        # Window icon
        try:
            import sys as _sys, os as _os
            _base = getattr(_sys, "_MEIPASS", _os.path.dirname(_os.path.abspath(__file__)))
            _ico  = _os.path.join(_base, "logo.ico")
            if _os.path.isfile(_ico):
                self.iconbitmap(_ico)
        except Exception:
            pass

        self._zip_path           = ""
        self._analysis_done      = False
        self._zip_handler        = IntuneZipHandler()
        self._mdm_parser         = MDMParser()
        self._error_detector     = ErrorDetector()
        self._compliance         = ComplianceChecker()
        self._report_gen         = ReportGenerator()
        self._wu_parser          = WUParser()
        self._extra_parser       = ExtraParser()
        self._mdm_diag_parser    = MDMDiagParser()
        self._cab_thread         = None   # background CAB extraction thread
        self._mdm_inner_nb       = None   # inner notebook for MDM Diag sub-tabs
        self._evtx_thread        = None   # background evtx scan thread
        self._bg_scan_count      = 0      # overlay ref-count for bg scans
        self._evtx_parsers       = {}     # log_type -> EvtxParser
        self._evtx_inner_nb      = None   # inner notebook for Event Log sub-tabs
        self._evtx_widgets       = {}     # log_type -> {tree, count_lbl, filter_var}
        self._zip_info           = {}
        self._compliance_summary = None
        self._error_summary      = {}
        self._ime_inner_nb       = None   # rebuilt after each analysis
        self._ime_theme_widgets  = {}     # theme -> {tree, detail, tab}
        self._wu_etl_thread      = None   # background ETL scan thread
        self._device_parser      = DeviceParser()   # apps, drivers, wifi, autopatch
        self._hardware_parser    = HardwareParser() # battery, firewall, certs, C2R
        self._hw_inner_nb        = None             # inner notebook for Hardware & Security
        self._hw_placeholder     = None
        self._c2r_inner_built    = False            # Office Logs tab built flag
        self._ai_analyzer        = AIAnalyzer()     # multi-provider AI
        self._ai_cfg             = AIConfig.load()  # persisted config
        self._ai_running         = False
        self._tab_ai             = None

        self._build_ui()
        self._center_window()

        # Auto-trigger local collection if re-launched elevated
        if "--collect-local" in sys.argv:
            self.after(400, self._start_local_collect_elevated)

    def _center_window(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    # =========================================================================
    # UI CONSTRUCTION
    # =========================================================================

    def _build_ui(self):
        self._build_header()
        self._build_toolbar()
        self._build_status_bar()
        self._build_overlay()
        self._build_notebook()

    def _build_header(self):
        hdr = tk.Frame(self, bg=C_ACCENT, height=52)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)
        tk.Label(hdr, text=f"  {self.APP_NAME}",
                 bg=C_ACCENT, fg="white",
                 font=("Segoe UI", 14, "bold")).pack(side="left", padx=20, pady=10)
        tk.Label(hdr, text="Intune Device Diagnostics Analyzer  —  workplacecloudhub.com",
                 bg=C_ACCENT, fg="#d0e9ff",
                 font=("Segoe UI", 9)).pack(side="left", pady=10)
        tk.Label(hdr, text=f"v{self.APP_VERSION}",
                 bg=C_ACCENT, fg="#90c8ff",
                 font=("Segoe UI", 8)).pack(side="right", padx=16)

    def _build_toolbar(self):
        bar = tk.Frame(self, bg=C_SURFACE, pady=6, padx=12)
        bar.pack(fill="x", side="top")

        self._btn_analyse = self._flat_btn(
            bar, "Analyze Intune DiagLogs ZIP", self._open_and_analyze,
            bg="#107c10", fg="white", active_bg="#0a5c0a")
        self._btn_analyse.pack(side="left", padx=(0, 8))

        self._btn_local = self._flat_btn(
            bar, "Analyze local device", self._analyze_local_device,
            bg="#8b4513", fg="white", active_bg="#5c2d0e")
        self._btn_local.pack(side="left", padx=(0, 8))

        self._btn_export = self._flat_btn(
            bar, "Export HTML Report", self._export_report,
            bg="#6b47cc", fg="white", active_bg="#4e35a0", state="disabled")
        self._btn_export.pack(side="left", padx=(0, 8))

        self._btn_clear = self._flat_btn(
            bar, "Reset", self._clear_all,
            bg=C_PANEL, fg=C_TEXT, active_bg="#222235")
        self._btn_clear.pack(side="left")

        self._lbl_file = tk.Label(bar, text="No file loaded",
                                   bg=C_SURFACE, fg=C_TEXT_DIM,
                                   font=("Segoe UI", 9), anchor="w")
        self._lbl_file.pack(side="left", padx=16)

    def _flat_btn(self, parent, text, cmd, bg, fg, active_bg, state="normal", **kw):
        btn = tk.Button(parent, text=text, command=cmd,
                        bg=bg, fg=fg,
                        activebackground=active_bg, activeforeground=fg,
                        font=("Segoe UI", 9, "bold"),
                        relief="flat", borderwidth=0,
                        padx=12, pady=5,
                        cursor="hand2", state=state, **kw)
        btn.bind("<Enter>", lambda e: btn.configure(bg=active_bg)
                 if btn["state"] == "normal" else None)
        btn.bind("<Leave>", lambda e: btn.configure(bg=bg)
                 if btn["state"] == "normal" else None)
        return btn

    def _build_notebook(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Dark.TNotebook",
                        background=C_BG, borderwidth=0)
        style.configure("Dark.TNotebook.Tab",
                        background=C_PANEL, foreground=C_TEXT_DIM,
                        padding=[14, 6], font=("Segoe UI", 9, "bold"))
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", C_SURFACE)],
                  foreground=[("selected", C_ACCENT2)])

        self._nb = ttk.Notebook(self, style="Dark.TNotebook")
        self._nb.pack(fill="both", expand=True, padx=8, pady=(4, 0))

        self._tab_summary  = tk.Frame(self._nb, bg=C_BG)
        self._tab_mdm_diag = tk.Frame(self._nb, bg=C_BG)
        self._tab_wu       = tk.Frame(self._nb, bg=C_BG)
        self._tab_eventlog = tk.Frame(self._nb, bg=C_BG)
        self._tab_ime      = tk.Frame(self._nb, bg=C_BG)
        self._tab_appdrv   = tk.Frame(self._nb, bg=C_BG)
        self._tab_hardware = tk.Frame(self._nb, bg=C_BG)
        self._tab_c2r      = tk.Frame(self._nb, bg=C_BG)
        self._tab_ai       = tk.Frame(self._nb, bg=C_BG)
        self._tab_device   = tk.Frame(self._nb, bg=C_BG)
        self._tab_files    = tk.Frame(self._nb, bg=C_BG)

        self._nb.add(self._tab_summary,  text="  Summary  ")
        self._nb.add(self._tab_mdm_diag, text="  MDM Diagnostics  ")
        self._nb.add(self._tab_wu,       text="  Windows Update  ")
        self._nb.add(self._tab_eventlog, text="  Event Log  ")
        self._nb.add(self._tab_ime,      text="  IME Logs  ")
        self._nb.add(self._tab_appdrv,   text="  Apps & Drivers  ")
        self._nb.add(self._tab_hardware, text="  Hardware & Security  ")
        self._nb.add(self._tab_c2r,      text="  Office Logs  ")
        self._nb.add(self._tab_ai,       text="  🤖 AI Analysis  ")
        self._nb.add(self._tab_device,   text="  Device Info  ")
        self._nb.add(self._tab_files,    text="  ZIP Files  ")

        self._build_tab_summary()
        self._build_tab_mdm_diag()
        self._build_tab_wu()
        self._build_tab_eventlog_placeholder()
        self._build_tab_ime_placeholder()
        self._build_tab_appdrv_placeholder()
        self._build_tab_hardware_placeholder()
        self._build_tab_c2r_placeholder()
        self._build_tab_ai()
        self._build_tab_device()
        self._build_tab_files()


    # =========================================================================
    # ANALYSIS OVERLAY  (full-window loading screen)
    # =========================================================================

    def _build_overlay(self):
        """Transparent dark overlay shown while analysis is running."""
        self._overlay = tk.Frame(self, bg="#12121f")
        # Title — instance attribute so _bg_scan_start can update it
        self._overlay_title = tk.Label(
            self._overlay, text="🔍  Analyzing Intune Diagnostics",
            bg="#12121f", fg="#cdd6f4",
            font=("Segoe UI", 16, "bold"))
        self._overlay_title.pack(pady=(80, 6))
        # Sub-label updated with each step
        self._overlay_step = tk.Label(
            self._overlay, text="",
            bg="#12121f", fg="#a6adc8",
            font=("Segoe UI", 10))
        self._overlay_step.pack(pady=(0, 20))
        # Progress bar (wider than the status-bar one)
        self._overlay_progress = ttk.Progressbar(
            self._overlay, mode="indeterminate", length=340)
        self._overlay_progress.pack(pady=(0, 10))
        # Hint
        tk.Label(
            self._overlay,
            text="Please wait — this may take a few seconds.",
            bg="#12121f", fg="#585b70",
            font=("Segoe UI", 8, "italic")
        ).pack(pady=(12, 0))

    def _show_overlay(self, step_msg="", title=None):
        if title:
            self._overlay_title.configure(text=title)
        self._overlay_step.configure(text=step_msg)
        self._overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._overlay.lift()
        self._overlay_progress.start(10)

    def _hide_overlay(self):
        self._overlay_progress.stop()
        self._overlay.place_forget()

    def _bg_scan_start(self, title, step=""):
        """Increment background-scan counter and show overlay."""
        self._bg_scan_count += 1
        self._overlay_title.configure(text=f"⏳  {title}")
        self._show_overlay(step)

    def _bg_scan_end(self):
        """Decrement background-scan counter; hide overlay when all done."""
        self._bg_scan_count = max(0, self._bg_scan_count - 1)
        if self._bg_scan_count == 0:
            self._hide_overlay()


    def _overlay_set_step(self, msg):
        """Update the overlay step label (safe to call from any thread)."""
        self.after(0, lambda: self._overlay_step.configure(text=msg))

    def _build_status_bar(self):
        bar = tk.Frame(self, bg=C_SURFACE, height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self._lbl_status = tk.Label(
            bar,
            text="Ready  --  Open an Intune Device Diagnostics ZIP file",
            bg=C_SURFACE, fg=C_TEXT_DIM,
            font=("Segoe UI", 8), anchor="w")
        self._lbl_status.pack(side="left", padx=12)
        self._progress = ttk.Progressbar(bar, mode="indeterminate", length=140)
        self._progress.pack(side="right", padx=12, pady=4)

    def _set_status(self, msg):
        self.after(0, lambda: self._lbl_status.configure(text=msg))
        self._overlay_set_step(msg)

    # =========================================================================
    # TAB BUILDERS
    # =========================================================================

    def _build_tab_summary(self):
        f = self._tab_summary
        tk.Label(f, text="Analysis Overview",
                 bg=C_BG, fg=C_HEADER, font=FONT_TITLE
                 ).pack(anchor="w", padx=16, pady=(12, 4))

        # Device identity banner – row 1: PC Name / IP / OS
        dev_row = tk.Frame(f, bg=C_BG)
        dev_row.pack(fill="x", padx=16, pady=(0, 2))
        self._lbl_dev_name = self._info_card(dev_row, "Computer Name", "---")
        self._lbl_dev_ip   = self._info_card(dev_row, "IP Address",    "---")
        self._lbl_dev_os   = self._info_card(dev_row, "OS Version",    "---")

        # Device identity banner – row 2: Proxy / Last User / IME Version
        dev_row2 = tk.Frame(f, bg=C_BG)
        dev_row2.pack(fill="x", padx=16, pady=(0, 6))
        self._lbl_dev_proxy   = self._info_card(dev_row2, "Proxy",        "---")
        self._lbl_dev_user    = self._info_card(dev_row2, "Last User",     "---")
        self._lbl_dev_ime_ver = self._info_card(dev_row2, "IME Version",   "---")

        # KPI counters row
        kpi_row = tk.Frame(f, bg=C_BG)
        kpi_row.pack(fill="x", padx=16, pady=(0, 8))
        self._kpi_errors   = self._kpi_card(kpi_row, "Errors",       "---", C_TEXT_DIM)
        self._kpi_warnings = self._kpi_card(kpi_row, "Warnings",     "---", C_TEXT_DIM)
        self._kpi_files    = self._kpi_card(kpi_row, "Files Scanned","---", C_TEXT_DIM)

        # MDM Diag: Device Info + Connection Info (populated after CAB extraction)
        info_row = tk.Frame(f, bg=C_BG)
        info_row.pack(fill="x", padx=16, pady=(0, 8))

        frm_di = tk.Frame(info_row, bg=C_SURFACE, padx=12, pady=8)
        frm_di.pack(side="left", fill="both", expand=True, padx=(0, 6))
        tk.Label(frm_di, text="Device Info", bg=C_SURFACE, fg=C_HEADER,
                 font=FONT_BOLD).pack(anchor="w", pady=(0, 4))
        self._tree_sum_devinfo = self._make_tree_inline(
            frm_di, ("key", "value"), ["Property", "Value"], [170, 260])

        frm_ci = tk.Frame(info_row, bg=C_SURFACE, padx=12, pady=8)
        frm_ci.pack(side="left", fill="both", expand=True, padx=(6, 0))
        tk.Label(frm_ci, text="Connection Info", bg=C_SURFACE, fg=C_HEADER,
                 font=FONT_BOLD).pack(anchor="w", pady=(0, 4))
        self._tree_sum_conninfo = self._make_tree_inline(
            frm_ci, ("key", "value"), ["Property", "Value"], [170, 260])

        tk.Label(f, text="Analysis report:",
                 bg=C_BG, fg=C_TEXT_DIM, font=FONT_BOLD
                 ).pack(anchor="w", padx=16)
        self._txt_summary = self._scrolled_text(f, height=12)
        self._txt_summary.configure(state="normal")
        self._txt_summary.insert("end",
            "Open an Intune Device Diagnostics ZIP and click Analyze.\n\n"
            "What this tool reads from the ZIP:\n"
            "  DSRegCmd output       -> AAD join status, PRT, WAM, SSO\n"
            "  Enrollments.reg       -> active MDM enrollments\n"
            "  results.xml           -> collection success/failure per item\n"
            "  IME logs (SCCM fmt)   -> Win32App, health scripts, policies\n"
            "  netsh advfirewall     -> firewall profile states\n"
            "  Known MDM error codes -> 0x80180xxx, 0x87D1xxxx, AAD...\n\n"
            "The report can be exported as a standalone HTML file.\n")
        self._txt_summary.configure(state="disabled")

    def _info_card(self, parent, label, value):
        """Compact horizontal info card: Label / Value."""
        card = tk.Frame(parent, bg=C_SURFACE, pady=8, padx=16,
                        relief="flat", borderwidth=0)
        card.pack(side="left", padx=(0, 10), pady=4, ipadx=4, fill="x", expand=True)
        tk.Label(card, text=label, bg=C_SURFACE, fg=C_TEXT_DIM,
                 font=("Segoe UI", 8)).pack(anchor="w")
        val_lbl = tk.Label(card, text=value, bg=C_SURFACE, fg=C_ACCENT2,
                           font=("Segoe UI", 11, "bold"))
        val_lbl.pack(anchor="w")
        return val_lbl

    def _kpi_card(self, parent, label, value, color):
        card = tk.Frame(parent, bg=C_SURFACE, pady=10, padx=16,
                        relief="flat", borderwidth=0)
        card.pack(side="left", padx=(0, 10), pady=4, ipadx=4)
        val_lbl = tk.Label(card, text=value, bg=C_SURFACE, fg=color,
                           font=("Segoe UI", 22, "bold"))
        val_lbl.pack()
        tk.Label(card, text=label, bg=C_SURFACE, fg=C_TEXT_DIM,
                 font=("Segoe UI", 8)).pack()
        return val_lbl

    # -------------------------------------------------------------------------
    # IME LOGS TAB
    # -------------------------------------------------------------------------

    def _build_tab_ime_placeholder(self):
        tk.Label(self._tab_ime,
                 text="IME Logs",
                 bg=C_BG, fg=C_HEADER, font=FONT_TITLE
                 ).pack(anchor="w", padx=16, pady=(12, 4))
        self._ime_placeholder = tk.Label(
            self._tab_ime,
            text="Run an analysis to populate the IME log tabs.",
            bg=C_BG, fg=C_TEXT_DIM, font=FONT_BODY)
        self._ime_placeholder.pack(padx=16, pady=20)

    def _rebuild_ime_tabs(self):
        """Rebuild IME Logs panel with a combobox selector + single shared treeview."""
        if self._ime_inner_nb is not None:
            self._ime_inner_nb.destroy()
            self._ime_inner_nb = None
        self._ime_theme_widgets = {}

        if self._ime_placeholder and self._ime_placeholder.winfo_exists():
            self._ime_placeholder.pack_forget()

        themes_present = self._zip_handler.file_inventory.get("ime_themes", {})
        if not themes_present:
            if self._ime_placeholder and self._ime_placeholder.winfo_exists():
                self._ime_placeholder.pack(padx=16, pady=20)
            return

        theme_counts = self._error_summary.get("theme_counts", {})

        # Build ordered list of themes with their data
        ordered_themes = [t for t in IME_THEMES if t in themes_present]
        for t in themes_present:
            if t not in ordered_themes:
                ordered_themes.append(t)

        entries = []
        for theme in ordered_themes:
            counts = theme_counts.get(theme, {"errors": 0, "warnings": 0})
            err_c  = counts["errors"]
            warn_c = counts["warnings"]
            label  = IME_THEME_LABELS.get(theme, theme.replace("_", " ").title())
            badge  = f"  [{err_c}E {warn_c}W]" if (err_c + warn_c) > 0 else ""
            combo_label = f"{label}{badge}"
            entries.append((theme, label, err_c, warn_c, combo_label))

        # Container (stored in _ime_inner_nb for lifecycle management)
        container = tk.Frame(self._tab_ime, bg=C_BG)
        container.pack(fill="both", expand=True, padx=8, pady=4)
        self._ime_inner_nb = container

        # ── Top toolbar ──────────────────────────────────────────────────────
        toolbar = tk.Frame(container, bg=C_SURFACE, pady=5, padx=12)
        toolbar.pack(fill="x")

        tk.Label(toolbar, text="Theme:", bg=C_SURFACE, fg=C_TEXT_DIM,
                 font=FONT_BODY).pack(side="left")

        combo_values = [e[4] for e in entries]
        combo_var    = tk.StringVar(value=combo_values[0])

        combo = ttk.Combobox(toolbar, textvariable=combo_var,
                             values=combo_values, state="readonly",
                             width=48, font=FONT_BODY)
        combo.pack(side="left", padx=(6, 20))

        info_lbl = tk.Label(toolbar, text="", bg=C_SURFACE, fg=C_TEXT_DIM,
                            font=("Segoe UI", 8))
        info_lbl.pack(side="left")

        # ── Filter bar ───────────────────────────────────────────────────────
        flt_bar = tk.Frame(container, bg=C_BG)
        flt_bar.pack(fill="x", padx=8, pady=(4, 0))
        tk.Label(flt_bar, text="Filter:", bg=C_BG, fg=C_TEXT_DIM,
                 font=FONT_BODY).pack(side="left")

        fvar = tk.StringVar()
        ent = tk.Entry(flt_bar, textvariable=fvar,
                       bg=C_PANEL, fg=C_TEXT, insertbackground=C_TEXT,
                       font=FONT_BODY, relief="flat", borderwidth=4)
        ent.pack(side="left", padx=6, ipadx=4)
        tk.Button(flt_bar, text="Clear",
                  command=lambda: fvar.set(""),
                  bg=C_PANEL, fg=C_TEXT_DIM, relief="flat",
                  font=("Segoe UI", 8), cursor="hand2"
                  ).pack(side="left", padx=(0, 8))

        sev_var  = tk.StringVar(value="")
        btns_ref = []
        for lbl, val in [("All", ""), ("Errors", "ERROR"), ("Warnings", "WARNING")]:
            abg = {"": C_ACCENT, "ERROR": C_ERROR, "WARNING": C_WARN}[val]
            def _make_sev_btn(label, value, active_bg):
                btn = tk.Button(
                    flt_bar, text=label,
                    bg=C_PANEL, fg=C_TEXT_DIM,
                    activebackground=active_bg, activeforeground="white",
                    font=("Segoe UI", 8, "bold"),
                    relief="flat", borderwidth=0, padx=8, pady=3,
                    cursor="hand2")
                def _on_click(v=value, b=btn, abg2=active_bg):
                    sev_var.set(v)
                    for ob, ov, oabg in btns_ref:
                        ob.configure(bg=(oabg if ov == v else C_PANEL),
                                     fg=("white" if ov == v else C_TEXT_DIM))
                btn.configure(command=_on_click)
                return btn
            b = _make_sev_btn(lbl, val, abg)
            btns_ref.append((b, val, abg))
            b.pack(side="left", padx=(4, 0))
        btns_ref[0][0].configure(bg=C_ACCENT, fg="white")

        count_lbl = tk.Label(flt_bar, text="", bg=C_BG, fg=C_TEXT_DIM,
                             font=("Segoe UI", 8))
        count_lbl.pack(side="right")

        # ── Shared treeview ───────────────────────────────────────────────────
        cols = ("severity", "timestamp", "component", "message", "file")
        tree = self._make_tree(
            container, cols,
            headings=["Severity", "Timestamp", "Component", "Message", "File"],
            widths=[80, 150, 130, 480, 200])
        tree.tag_configure("ERROR",   foreground=C_ERROR)
        tree.tag_configure("WARNING", foreground=C_WARN)

        # ── Detail area ───────────────────────────────────────────────────────
        tk.Label(container, text="Raw line:",
                 bg=C_BG, fg=C_TEXT_DIM, font=FONT_BOLD
                 ).pack(anchor="w", padx=16, pady=(2, 0))
        detail_txt = self._scrolled_text(container, height=4, mono=True)

        raw_lines_map = {}

        def _on_select(event):
            sel = tree.selection()
            if sel:
                raw = raw_lines_map.get(sel[0], "")
                detail_txt.configure(state="normal")
                detail_txt.delete("1.0", "end")
                detail_txt.insert("end", raw)
                detail_txt.configure(state="disabled")

        tree.bind("<<TreeviewSelect>>", _on_select)

        # Store a single shared widget entry (keyed by each theme)
        shared_wdg = {
            "tree":      tree,
            "detail":    detail_txt,
            "raw_lines": raw_lines_map,
            "count_lbl": count_lbl,
            "sev_var":   sev_var,
        }
        for theme, _, _, _, _ in entries:
            self._ime_theme_widgets[theme] = shared_wdg

        # Fast lookup: combo_label -> theme
        label_to_theme = {e[4]: e[0] for e in entries}
        label_to_meta  = {e[4]: (e[1], e[2], e[3]) for e in entries}

        def _on_selection(*_):
            sel_label = combo_var.get()
            theme     = label_to_theme.get(sel_label)
            if theme is None:
                return
            label, err_c, warn_c = label_to_meta[sel_label]
            files_in_theme = themes_present.get(theme, [])
            info_lbl.configure(
                text=(f"{len(files_in_theme)} file(s)  |  "
                      f"{err_c} error(s)  {warn_c} warning(s)"))
            # Reset filters and repopulate
            fvar.set("")
            sev_var.set("")
            for ob, ov, oabg in btns_ref:
                ob.configure(bg=(C_ACCENT if ov == "" else C_PANEL),
                             fg=("white" if ov == "" else C_TEXT_DIM))
            raw_lines_map.clear()
            self._filter_ime_tree(tree, theme, "", count_lbl, raw_lines_map, "")

        def _do_filter(*_):
            theme = label_to_theme.get(combo_var.get())
            if theme:
                self._filter_ime_tree(tree, theme, fvar.get(),
                                      count_lbl, raw_lines_map, sev_var.get())

        combo.bind("<<ComboboxSelected>>", _on_selection)
        fvar.trace_add("write", _do_filter)
        sev_var.trace_add("write", _do_filter)

        # Initial population
        _on_selection()

    def _filter_ime_tree(self, tree, theme, term, count_lbl,
                          raw_lines_map, severity=""):
        """Re-populate an IME sub-tab tree with optional text + severity filter."""
        for item in tree.get_children():
            tree.delete(item)
        raw_lines_map.clear()

        events = self._error_detector.events_by_theme.get(theme, [])
        if severity:
            events = [e for e in events if e.severity == severity]
        if term:
            tl = term.lower()
            events = [e for e in events if (
                tl in e.severity.lower() or
                tl in e.category.lower() or
                tl in e.message.lower() or
                tl in e.source_file.lower() or
                tl in (e.error_code or "").lower())]

        for i, ev in enumerate(events):
            iid = tree.insert(
                "", "end",
                values=(ev.severity,
                        ev.timestamp or str(ev.line_number),
                        ev.category,
                        ev.message[:140],
                        ev.source_file),
                tags=(ev.severity, "even" if i % 2 == 0 else "odd"))
            raw_lines_map[iid] = ev.raw_line

        total = len(self._error_detector.events_by_theme.get(theme, []))
        shown = len(events)
        count_lbl.configure(
            text=f"{shown}/{total} events" if term else f"{total} events")

    # -------------------------------------------------------------------------

    def _build_tab_compliance(self):
        f = self._tab_compliance
        tk.Label(f, text="Compliance Status",
                 bg=C_BG, fg=C_HEADER, font=FONT_TITLE
                 ).pack(anchor="w", padx=16, pady=(12, 4))

        self._frm_compliance_banner = tk.Frame(f, bg=C_PANEL, pady=8, padx=16)
        self._frm_compliance_banner.pack(fill="x", padx=16, pady=(0, 8))
        self._lbl_compliance_overall = tk.Label(
            self._frm_compliance_banner,
            text="Awaiting analysis...",
            bg=C_PANEL, fg=C_TEXT_DIM,
            font=("Segoe UI", 12, "bold"))
        self._lbl_compliance_overall.pack(side="left")

        cols = ("area", "status", "details", "source")
        self._tree_compliance = self._make_tree(
            f, cols,
            headings=["Area", "Status", "Details", "Source"],
            widths=[160, 130, 520, 200])
        self._tree_compliance.tag_configure("COMPLIANT",     foreground=C_OK)
        self._tree_compliance.tag_configure("NON_COMPLIANT", foreground=C_ERROR)
        self._tree_compliance.tag_configure("PENDING",       foreground=C_WARN)
        self._tree_compliance.tag_configure("UNKNOWN",       foreground=C_TEXT_DIM)

    def _build_tab_enrollments(self):
        f = self._tab_enrollments
        tk.Label(f, text="MDM Enrollments",
                 bg=C_BG, fg=C_HEADER, font=FONT_TITLE
                 ).pack(anchor="w", padx=16, pady=(12, 4))

        flt = tk.Frame(f, bg=C_BG)
        flt.pack(fill="x", padx=16, pady=(0, 6))
        tk.Label(flt, text="Search:", bg=C_BG, fg=C_TEXT_DIM,
                 font=FONT_BODY).pack(side="left")
        self._pol_filter_var = tk.StringVar()
        ent = tk.Entry(flt, textvariable=self._pol_filter_var,
                       bg=C_PANEL, fg=C_TEXT, insertbackground=C_TEXT,
                       font=FONT_BODY, relief="flat", borderwidth=4)
        ent.pack(side="left", padx=6, ipadx=4)
        ent.bind("<KeyRelease>", lambda e: self._populate_enrollments())
        self._lbl_pol_count = tk.Label(flt, text="",
                                        bg=C_BG, fg=C_TEXT_DIM,
                                        font=("Segoe UI", 8))
        self._lbl_pol_count.pack(side="right")

        cols = ("guid", "state", "type", "upn", "url")
        self._tree_enrollments = self._make_tree(
            f, cols,
            headings=["GUID / ID", "State", "Type", "UPN", "Enrollment URL"],
            widths=[280, 130, 180, 200, 300])


    # =========================================================================
    # APPS & DRIVERS TAB
    # =========================================================================

    def _build_tab_appdrv_placeholder(self):
        f = self._tab_appdrv
        tk.Label(f, text="Apps & Drivers",
                 bg=C_BG, fg=C_HEADER, font=FONT_TITLE
                 ).pack(anchor="w", padx=16, pady=(12, 4))
        self._appdrv_placeholder = tk.Label(
            f,
            text="Run an analysis to populate this tab.",
            bg=C_BG, fg=C_TEXT_DIM, font=FONT_BODY)
        self._appdrv_placeholder.pack(padx=16, pady=20)
        self._appdrv_inner_nb_frame = tk.Frame(f, bg=C_BG)
        self._appdrv_inner_nb_frame.pack(fill="both", expand=True)
        self._appdrv_inner_nb = None

    def _build_appdrv_inner_nb(self):
        """Build inner notebook with sub-tabs: Apps, Drivers, WiFi, Autopatch, Errors."""
        if self._appdrv_inner_nb is not None:
            self._appdrv_inner_nb.destroy()
            self._appdrv_inner_nb = None
        if self._appdrv_placeholder.winfo_exists():
            self._appdrv_placeholder.pack_forget()

        style = ttk.Style()
        style.configure("ADR.TNotebook",
                        background=C_SURFACE, borderwidth=0)
        style.configure("ADR.TNotebook.Tab",
                        background=C_PANEL, foreground=C_TEXT_DIM,
                        padding=[10, 5], font=("Segoe UI", 8, "bold"))
        style.map("ADR.TNotebook.Tab",
                  background=[("selected", C_BG)],
                  foreground=[("selected", C_ACCENT2)])

        nb = ttk.Notebook(self._appdrv_inner_nb_frame, style="ADR.TNotebook")
        nb.pack(fill="both", expand=True)
        self._appdrv_inner_nb = nb

        dp = self._device_parser

        # ── Installed Apps ──────────────────────────────────────────────────
        if dp.apps.parsed:
            n = len(dp.apps.apps)
            frm = tk.Frame(nb, bg=C_BG)
            nb.add(frm, text=f"  Apps ({n})  ")

            # Search bar
            sbar = tk.Frame(frm, bg=C_BG)
            sbar.pack(fill="x", padx=16, pady=(6, 2))
            tk.Label(sbar, text="Search:", bg=C_BG, fg=C_TEXT_DIM,
                     font=FONT_BODY).pack(side="left")
            app_search_var = tk.StringVar()
            ent = tk.Entry(sbar, textvariable=app_search_var,
                           bg=C_PANEL, fg=C_TEXT, insertbackground=C_TEXT,
                           font=FONT_BODY, relief="flat", borderwidth=4)
            ent.pack(side="left", padx=6, ipadx=4)
            app_count_lbl = tk.Label(sbar, text=f"{n} apps", bg=C_BG,
                                     fg=C_TEXT_DIM, font=("Segoe UI", 8))
            app_count_lbl.pack(side="right")

            cols = ("name", "version", "publisher", "date", "arch")
            tree_apps = self._make_tree(
                frm, cols,
                headings=["Application", "Version", "Publisher", "Install Date", "Arch"],
                widths=[300, 130, 240, 110, 55])

            def _populate_apps(filter_text=""):
                self._tree_clear(tree_apps)
                ft = filter_text.lower()
                shown = 0
                for i, app in enumerate(dp.apps.apps):
                    if ft and ft not in app.name.lower() and ft not in app.publisher.lower():
                        continue
                    tree_apps.insert("", "end",
                        values=(app.name, app.version, app.publisher,
                                app.install_date, app.arch),
                        tags=("even" if shown % 2 == 0 else "odd",))
                    shown += 1
                app_count_lbl.configure(text=f"{shown}/{n} apps")

            app_search_var.trace_add("write",
                lambda *_: _populate_apps(app_search_var.get()))
            _populate_apps()

        # ── Drivers ─────────────────────────────────────────────────────────
        if dp.drivers.parsed:
            n = len(dp.drivers.drivers)
            frm = tk.Frame(nb, bg=C_BG)
            nb.add(frm, text=f"  Drivers ({n})  ")

            sbar2 = tk.Frame(frm, bg=C_BG)
            sbar2.pack(fill="x", padx=16, pady=(6, 2))
            tk.Label(sbar2, text="Search:", bg=C_BG, fg=C_TEXT_DIM,
                     font=FONT_BODY).pack(side="left")
            drv_search_var = tk.StringVar()
            ent2 = tk.Entry(sbar2, textvariable=drv_search_var,
                            bg=C_PANEL, fg=C_TEXT, insertbackground=C_TEXT,
                            font=FONT_BODY, relief="flat", borderwidth=4)
            ent2.pack(side="left", padx=6, ipadx=4)
            drv_count_lbl = tk.Label(sbar2, text=f"{n} drivers", bg=C_BG,
                                     fg=C_TEXT_DIM, font=("Segoe UI", 8))
            drv_count_lbl.pack(side="right")

            cols2 = ("inf", "provider", "class_name", "version", "signer")
            tree_drv = self._make_tree(
                frm, cols2,
                headings=["INF File", "Provider", "Class", "Version", "Signer"],
                widths=[160, 180, 160, 160, 280])

            def _populate_drv(filter_text=""):
                self._tree_clear(tree_drv)
                ft = filter_text.lower()
                shown = 0
                for d in dp.drivers.drivers:
                    if ft and ft not in d.original_name.lower() and                                ft not in d.provider.lower() and                                ft not in d.class_name.lower():
                        continue
                    tree_drv.insert("", "end",
                        values=(d.original_name or d.published_name,
                                d.provider, d.class_name,
                                d.driver_version, d.signer),
                        tags=("even" if shown % 2 == 0 else "odd",))
                    shown += 1
                drv_count_lbl.configure(text=f"{shown}/{n} drivers")

            drv_search_var.trace_add("write",
                lambda *_: _populate_drv(drv_search_var.get()))
            _populate_drv()

        # ── WiFi Profiles ───────────────────────────────────────────────────
        if dp.wifi.parsed:
            n = len(dp.wifi.profiles)
            frm = tk.Frame(nb, bg=C_BG)
            nb.add(frm, text=f"  WiFi ({n})  ")
            cols3 = ("ssid", "type")
            tree_wifi = self._make_tree(
                frm, cols3,
                headings=["SSID", "Profile Type"],
                widths=[300, 200])
            for i, p in enumerate(dp.wifi.profiles):
                clr = "GPO" if p.profile_type == "GPO" else ""
                tree_wifi.insert("", "end",
                    values=(p.ssid, p.profile_type),
                    tags=("even" if i % 2 == 0 else "odd",))
            tree_wifi.tag_configure("GPO", foreground=C_ACCENT2)

        # ── Autopatch ───────────────────────────────────────────────────────
        ap = dp.autopatch
        if ap.parsed:
            frm = tk.Frame(nb, bg=C_BG)
            nb.add(frm, text="  Autopatch  ")
            info_frm = tk.Frame(frm, bg=C_PANEL, padx=16, pady=10)
            info_frm.pack(fill="x", padx=16, pady=(8, 4))
            info = ap.info
            fields = [
                ("Autopatch Enabled",    info.enabled or "Unknown"),
                ("Deadline (days)",      info.deadline_days or "—"),
                ("Grace Period (days)",  info.grace_period or "—"),
            ]
            for lbl, val in fields:
                row = tk.Frame(info_frm, bg=C_PANEL)
                row.pack(fill="x", pady=1)
                tk.Label(row, text=f"{lbl}:", bg=C_PANEL, fg=C_TEXT_DIM,
                         font=FONT_BODY, width=24, anchor="w").pack(side="left")
                fg = C_OK if val == "Yes" else C_ERROR if val == "No" else C_TEXT
                tk.Label(row, text=val, bg=C_PANEL, fg=fg,
                         font=FONT_BODY).pack(side="left")

            if info.log_lines:
                tk.Label(frm, text="Recent Autopatch log activity:",
                         bg=C_BG, fg=C_TEXT_DIM, font=FONT_BOLD
                         ).pack(anchor="w", padx=16, pady=(8, 2))
                txt = self._scrolled_text(frm, height=12, mono=True)
                txt.configure(state="normal")
                txt.insert("end", "\n".join(info.log_lines))
                txt.configure(state="disabled")

        # ── Collection Errors ───────────────────────────────────────────────
        ce = dp.collection_errors
        if ce.parsed:
            n = len(ce.errors)
            frm = tk.Frame(nb, bg=C_BG)
            nb.add(frm, text=f"  Collection Errors ({n})  ")
            tk.Label(frm,
                     text="Items the diagnostic tool could not collect from this device:",
                     bg=C_BG, fg=C_TEXT_DIM, font=FONT_BODY
                     ).pack(anchor="w", padx=16, pady=(8, 2))
            cols4 = ("item", "code", "explanation")
            tree_ce = self._make_tree(
                frm, cols4,
                headings=["Item", "Error Code", "Explanation"],
                widths=[280, 110, 560])
            tree_ce.tag_configure("err0002", foreground=C_TEXT_DIM)
            tree_ce.tag_configure("err0003", foreground=C_TEXT_DIM)
            tree_ce.tag_configure("errOther", foreground=C_WARN)
            for i, e in enumerate(ce.errors):
                tag_lvl = ("err0002" if "0002" in e.error_code
                           else "err0003" if "0003" in e.error_code
                           else "errOther")
                tree_ce.insert("", "end",
                    values=(e.item_name, e.error_code, e.explanation),
                    tags=(tag_lvl, "even" if i % 2 == 0 else "odd"))


    # =========================================================================
    # HARDWARE & SECURITY TAB
    # =========================================================================

    def _build_tab_hardware_placeholder(self):
        f = self._tab_hardware
        tk.Label(f, text="Hardware & Security",
                 bg=C_BG, fg=C_HEADER, font=FONT_TITLE
                 ).pack(anchor="w", padx=16, pady=(12, 4))
        self._hw_placeholder = tk.Label(
            f, text="Run an analysis to populate this tab.",
            bg=C_BG, fg=C_TEXT_DIM, font=FONT_BODY)
        self._hw_placeholder.pack(padx=16, pady=20)
        self._hw_inner_nb_frame = tk.Frame(f, bg=C_BG)
        self._hw_inner_nb_frame.pack(fill="both", expand=True)
        self._hw_inner_nb = None

    def _build_hardware_inner_nb(self):
        """Build Battery / Firewall / Certificates sub-tabs."""
        if self._hw_inner_nb is not None:
            self._hw_inner_nb.destroy()
            self._hw_inner_nb = None
        if self._hw_placeholder and self._hw_placeholder.winfo_exists():
            self._hw_placeholder.pack_forget()

        style = ttk.Style()
        style.configure("HW.TNotebook",  background=C_SURFACE, borderwidth=0)
        style.configure("HW.TNotebook.Tab",
                        background=C_PANEL, foreground=C_TEXT_DIM,
                        padding=[10, 5], font=("Segoe UI", 8, "bold"))
        style.map("HW.TNotebook.Tab",
                  background=[("selected", C_BG)],
                  foreground=[("selected", C_ACCENT2)])

        nb = ttk.Notebook(self._hw_inner_nb_frame, style="HW.TNotebook")
        nb.pack(fill="both", expand=True)
        self._hw_inner_nb = nb

        hp = self._hardware_parser

        # ── Battery ─────────────────────────────────────────────────────────
        bat = hp.battery
        bat_frm = tk.Frame(nb, bg=C_BG)
        nb.add(bat_frm, text="  Battery  ")

        if bat.parsed:
            b = bat.info

            # Health bar (ttk.Progressbar + label)
            pct = min(max(b.health_pct, 0), 100)
            bar_color = C_OK if pct >= 80 else C_WARN if pct >= 50 else C_ERROR

            health_row = tk.Frame(bat_frm, bg=C_BG)
            health_row.pack(fill="x", padx=16, pady=(12, 4))
            tk.Label(health_row, text="Battery Health:",
                     bg=C_BG, fg=C_TEXT_DIM, font=FONT_BOLD).pack(side="left")
            tk.Label(health_row, text=f"  {pct}%",
                     bg=C_BG, fg=bar_color, font=FONT_BOLD).pack(side="left")

            pb_style = ttk.Style()
            pb_style.configure("BatHealth.Horizontal.TProgressbar",
                               troughcolor=C_PANEL, background=bar_color,
                               bordercolor=C_PANEL, lightcolor=bar_color,
                               darkcolor=bar_color)
            pb = ttk.Progressbar(bat_frm,
                                 style="BatHealth.Horizontal.TProgressbar",
                                 orient="horizontal", mode="determinate",
                                 value=pct)
            pb.pack(fill="x", padx=16, pady=(0, 8))

            # Key/value grid
            cols = ("key", "value")
            tree_bat = self._make_tree(bat_frm, cols,
                headings=["Property", "Value"], widths=[220, 600])
            for i, (k, v) in enumerate(bat.get_summary_rows()):
                tree_bat.insert("", "end", values=(k, v),
                    tags=("even" if i % 2 == 0 else "odd",))
        else:
            tk.Label(bat_frm,
                     text="No battery-report.html found in this ZIP.\n"
                          "Battery report is generated by: powercfg /batteryreport",
                     bg=C_BG, fg=C_TEXT_DIM, font=FONT_BODY
                     ).pack(padx=24, pady=24)

        # ── Firewall ─────────────────────────────────────────────────────────
        fw = hp.firewall
        fw_frm = tk.Frame(nb, bg=C_BG)
        n_profiles = len(fw.profiles)
        nb.add(fw_frm, text=f"  Firewall ({n_profiles})  ")

        if fw.parsed and fw.profiles:
            tk.Label(fw_frm, text="Windows Firewall Profiles",
                     bg=C_BG, fg=C_HEADER, font=FONT_BOLD
                     ).pack(anchor="w", padx=16, pady=(10, 4))

            cols2 = ("profile", "state", "policy", "remote", "log_allow", "log_drop")
            tree_fw = self._make_tree(fw_frm, cols2,
                headings=["Profile", "State", "Policy", "Remote Mgmt",
                          "Log Allowed", "Log Dropped"],
                widths=[90, 70, 260, 110, 110, 110])
            for i, p in enumerate(fw.profiles):
                state_color = C_OK if p.state.upper() == "ON" else C_ERROR
                tree_fw.insert("", "end",
                    values=(p.name, p.state, p.firewall_policy,
                            p.remote_management, p.log_allowed, p.log_dropped),
                    tags=("even" if i % 2 == 0 else "odd",))

            # Detail section for log path
            if any(p.log_filename for p in fw.profiles):
                tk.Label(fw_frm, text="Log file paths:",
                         bg=C_BG, fg=C_TEXT_DIM, font=("Segoe UI", 8, "bold")
                         ).pack(anchor="w", padx=16, pady=(8, 2))
                for p in fw.profiles:
                    if p.log_filename:
                        tk.Label(fw_frm,
                                 text=f"  {p.name}: {p.log_filename}",
                                 bg=C_BG, fg=C_TEXT_DIM, font=FONT_MONO
                                 ).pack(anchor="w", padx=24)
        else:
            tk.Label(fw_frm,
                     text="No firewall data found in this ZIP.",
                     bg=C_BG, fg=C_TEXT_DIM, font=FONT_BODY
                     ).pack(padx=24, pady=24)

        # ── Certificates ─────────────────────────────────────────────────────
        certs = hp.certs
        cert_frm = tk.Frame(nb, bg=C_BG)
        n_certs = len(certs.certs)
        nb.add(cert_frm, text=f"  Certificates ({n_certs})  ")

        if certs.parsed and certs.certs:
            expired  = sum(1 for c in certs.certs if c.status == "Expired")
            expiring = sum(1 for c in certs.certs if c.status == "Expiring")
            info_txt = f"{n_certs} certificates found"
            if expired:
                info_txt += f"   |  {expired} EXPIRED"
            if expiring:
                info_txt += f"   |  {expiring} expiring soon"
            tk.Label(cert_frm, text=info_txt,
                     bg=C_BG,
                     fg=(C_ERROR if expired else C_WARN if expiring else C_TEXT_DIM),
                     font=("Segoe UI", 8, "bold")
                     ).pack(anchor="w", padx=16, pady=(10, 2))

            cols3 = ("subject", "not_after", "status", "days", "issuer", "serial")
            tree_cert = self._make_tree(cert_frm, cols3,
                headings=["Subject", "Expires", "Status", "Days Left",
                          "Issuer", "Serial"],
                widths=[280, 160, 80, 80, 260, 160])
            tree_cert.tag_configure("cert_expired",  foreground=C_ERROR)
            tree_cert.tag_configure("cert_expiring", foreground=C_WARN)
            tree_cert.tag_configure("cert_ok",       foreground=C_OK)
            for i, c in enumerate(certs.certs):
                days_str = str(c.days_to_expiry) if c.days_to_expiry is not None else "?"
                row_tag = ("cert_expired" if c.status == "Expired"
                           else "cert_expiring" if c.status == "Expiring"
                           else "cert_ok")
                stripe = "even" if i % 2 == 0 else "odd"
                tree_cert.insert("", "end",
                    values=(c.subject, c.not_after, c.status,
                            days_str, c.issuer, c.serial),
                    tags=(row_tag, stripe))
        else:
            tk.Label(cert_frm,
                     text="No certutil output found in this ZIP.",
                     bg=C_BG, fg=C_TEXT_DIM, font=FONT_BODY
                     ).pack(padx=24, pady=24)

    # =========================================================================
    # OFFICE C2R LOGS TAB
    # =========================================================================

    def _build_tab_c2r_placeholder(self):
        f = self._tab_c2r
        tk.Label(f, text="Office C2R Logs",
                 bg=C_BG, fg=C_HEADER, font=FONT_TITLE
                 ).pack(anchor="w", padx=16, pady=(12, 4))
        self._c2r_placeholder = tk.Label(
            f, text="Run an analysis to populate this tab.",
            bg=C_BG, fg=C_TEXT_DIM, font=FONT_BODY)
        self._c2r_placeholder.pack(padx=16, pady=20)
        self._c2r_content_frame = tk.Frame(f, bg=C_BG)
        self._c2r_content_frame.pack(fill="both", expand=True)
        self._c2r_inner_built = False

    def _build_c2r_tab_content(self):
        """Build Office C2R combobox + treeview (similar to IME Logs)."""
        if self._c2r_inner_built:
            return
        if self._c2r_placeholder and self._c2r_placeholder.winfo_exists():
            self._c2r_placeholder.pack_forget()

        c2r = self._hardware_parser.c2r
        if not c2r.parsed or not c2r.log_files:
            tk.Label(self._c2r_content_frame,
                     text="No Office C2R log files found in this ZIP.\n"
                          "These logs are from Microsoft 365 / Office Click-to-Run.",
                     bg=C_BG, fg=C_TEXT_DIM, font=FONT_BODY
                     ).pack(padx=24, pady=24)
            self._c2r_inner_built = True
            return

        files = sorted(c2r.log_files, key=lambda f: os.path.basename(f).lower())
        display_names = [c2r.get_display_name(f) for f in files]
        combo_values  = [f"{dn}  [{os.path.basename(fp)}]"
                         for dn, fp in zip(display_names, files)]

        # ── Toolbar ──────────────────────────────────────────────────────────
        toolbar = tk.Frame(self._c2r_content_frame, bg=C_SURFACE, pady=4)
        toolbar.pack(fill="x", padx=0, pady=(0, 4))

        tk.Label(toolbar, text="Log file:", bg=C_SURFACE, fg=C_TEXT_DIM,
                 font=FONT_BODY).pack(side="left", padx=(12, 4))

        combo_var = tk.StringVar()
        combo = ttk.Combobox(toolbar, textvariable=combo_var,
                             values=combo_values, state="readonly",
                             width=54, font=FONT_BODY)
        combo.pack(side="left", padx=4)
        if combo_values:
            combo.current(0)

        # Level filter
        tk.Label(toolbar, text="Level:", bg=C_SURFACE, fg=C_TEXT_DIM,
                 font=FONT_BODY).pack(side="left", padx=(16, 4))
        level_var = tk.StringVar(value="All")
        level_combo = ttk.Combobox(toolbar, textvariable=level_var,
                                   values=["All", "Error", "Critical", "Warning", "Info"],
                                   state="readonly", width=10, font=FONT_BODY)
        level_combo.pack(side="left", padx=4)

        count_lbl = tk.Label(toolbar, text="", bg=C_SURFACE, fg=C_TEXT_DIM,
                             font=("Segoe UI", 8))
        count_lbl.pack(side="right", padx=12)

        # ── Treeview ─────────────────────────────────────────────────────────
        cols = ("timestamp", "level", "process", "message")
        tree = self._make_tree(self._c2r_content_frame, cols,
            headings=["Timestamp", "Level", "Process", "Message"],
            widths=[170, 80, 200, 700])
        tree.tag_configure("c2r_error",   foreground=C_ERROR)
        tree.tag_configure("c2r_warn",    foreground=C_WARN)

        def _populate(file_path, level_filter="All"):
            self._tree_clear(tree)
            entries = c2r.parse_file(file_path)
            lf = level_filter.lower()
            shown = 0
            for e in entries:
                if lf != "all" and e.level.lower() != lf:
                    continue
                lvl_low = e.level.lower()
                if lvl_low in ("error", "critical", "fatal"):
                    row_tag = "c2r_error"
                elif lvl_low in ("warning", "warn"):
                    row_tag = "c2r_warn"
                else:
                    row_tag = "even" if shown % 2 == 0 else "odd"
                tree.insert("", "end",
                    values=(e.timestamp, e.level, e.process, e.message),
                    tags=(row_tag,))
                shown += 1
            count_lbl.configure(text=f"{shown} entries")

        def _on_selection(*_):
            idx = combo_values.index(combo_var.get()) if combo_var.get() in combo_values else 0
            _populate(files[idx], level_var.get())

        combo.bind("<<ComboboxSelected>>", _on_selection)
        level_combo.bind("<<ComboboxSelected>>", _on_selection)

        if files:
            _populate(files[0], "All")

        self._c2r_inner_built = True

    def _build_tab_device(self):
        f = self._tab_device
        tk.Label(f, text="Device Information",
                 bg=C_BG, fg=C_HEADER, font=FONT_TITLE
                 ).pack(anchor="w", padx=16, pady=(12, 4))

        cols = ("key", "value")
        self._tree_device = self._make_tree(
            f, cols,
            headings=["Property", "Value"],
            widths=[260, 700])

    def _build_tab_wu(self):
        f = self._tab_wu
        tk.Label(f, text="Windows Update",
                 bg=C_BG, fg=C_HEADER, font=FONT_TITLE
                 ).pack(anchor="w", padx=16, pady=(12, 4))

        # ---- Orchestrator Registry section ----
        tk.Label(f, text="Orchestrator Registry (WU state):",
                 bg=C_BG, fg=C_TEXT_DIM, font=FONT_BOLD
                 ).pack(anchor="w", padx=16)
        self._txt_wu_registry = self._scrolled_text(f, height=8, mono=True)

        # ---- WU Group Policy section ----
        tk.Label(f, text="Windows Update Group Policy (HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate):",
                 bg=C_BG, fg=C_TEXT_DIM, font=FONT_BOLD
                 ).pack(anchor="w", padx=16, pady=(6, 0))
        self._txt_wu_policies = self._scrolled_text(f, height=7, mono=True)

        # ---- ETL section ----
        etl_bar = tk.Frame(f, bg=C_BG, pady=4, padx=16)
        etl_bar.pack(fill="x")
        self._btn_wu_etl = self._flat_btn(
            etl_bar, "Scan ETL files (Get-WinEvent/tracerpt)", self._run_wu_etl_scan,
            bg=C_PANEL, fg=C_TEXT, active_bg="#222235", state="disabled")
        self._btn_wu_etl.pack(side="left")
        self._lbl_wu_etl = tk.Label(
            etl_bar,
            text="ETL scan not started  (uses Get-WinEvent or tracerpt on up to 50 ETL files)",
            bg=C_BG, fg=C_TEXT_DIM, font=("Segoe UI", 8))
        self._lbl_wu_etl.pack(side="left", padx=12)

        tk.Label(f, text="ETL Events (ReportingEvents + ETL scan):",
                 bg=C_BG, fg=C_TEXT_DIM, font=FONT_BOLD
                 ).pack(anchor="w", padx=16)
        cols = ("level", "timestamp", "event_id", "source", "message", "code", "file")
        self._tree_wu = self._make_tree(
            f, cols,
            headings=["Level", "Timestamp", "Event ID", "Source",
                      "Message", "Error Code", "ETL File"],
            widths=[90, 155, 70, 160, 420, 110, 200])
        self._tree_wu.tag_configure("Error",       foreground=C_ERROR)
        self._tree_wu.tag_configure("Warning",     foreground=C_WARN)
        self._tree_wu.tag_configure("Information", foreground=C_TEXT)
        self._tree_wu.tag_configure("Verbose",     foreground=C_TEXT_DIM)

    def _build_tab_mdm_diag(self):
        """MDM Diagnostics tab: CAB extraction + rich sub-tab viewer."""
        f = self._tab_mdm_diag
        tk.Label(f, text="MDM Diagnostics",
                 bg=C_BG, fg=C_HEADER, font=FONT_TITLE
                 ).pack(anchor="w", padx=16, pady=(12, 4))

        # Extraction toolbar
        cab_bar = tk.Frame(f, bg=C_BG, pady=4, padx=16)
        cab_bar.pack(fill="x")
        self._btn_cab = self._flat_btn(
            cab_bar, "Extract CAB (expand.exe)", self._run_cab_extract,
            bg=C_ACCENT, fg="white", active_bg="#005ea6", state="disabled")
        self._btn_cab.pack(side="left")
        self._lbl_cab = tk.Label(
            cab_bar,
            text="No CAB file found in this ZIP  "
                 "((74) FoldersFiles temp_MDMDiagnostics_..._cab)",
            bg=C_BG, fg=C_TEXT_DIM, font=("Segoe UI", 8))
        self._lbl_cab.pack(side="left", padx=12)

        # Placeholder shown before extraction
        self._mdm_diag_placeholder = tk.Label(
            f,
            text="Extract the CAB above to view MDMDiagHTMLReport.html analysis.",
            bg=C_BG, fg=C_TEXT_DIM, font=FONT_BODY)
        self._mdm_diag_placeholder.pack(padx=16, pady=20)

        # Sub-notebook placeholder (built after extraction)
        self._mdm_inner_nb_frame = tk.Frame(f, bg=C_BG)
        self._mdm_inner_nb_frame.pack(fill="both", expand=True)

    def _build_mdm_diag_inner_nb(self):
        """Build inner notebook with sub-tabs after MDMDiagHTMLReport.html is parsed."""
        if self._mdm_inner_nb is not None:
            self._mdm_inner_nb.destroy()
            self._mdm_inner_nb = None

        if self._mdm_diag_placeholder.winfo_exists():
            self._mdm_diag_placeholder.pack_forget()

        p = self._mdm_diag_parser
        errors, warnings = p.issue_count

        style = ttk.Style()
        style.configure("MDM.TNotebook",
                        background=C_SURFACE, borderwidth=0)
        style.configure("MDM.TNotebook.Tab",
                        background=C_PANEL, foreground=C_TEXT_DIM,
                        padding=[10, 5], font=("Segoe UI", 8, "bold"))
        style.map("MDM.TNotebook.Tab",
                  background=[("selected", C_BG)],
                  foreground=[("selected", C_ACCENT2)])

        nb = ttk.Notebook(self._mdm_inner_nb_frame, style="MDM.TNotebook")
        nb.pack(fill="both", expand=True)
        self._mdm_inner_nb = nb

        issue_badge = f"  ({errors}E {warnings}W)" if (errors + warnings) else ""

        # ---- Tab 1 : Overview ----
        tab_ov = tk.Frame(nb, bg=C_BG)
        nb.add(tab_ov, text=f"  Overview{issue_badge}  ")

        # Device Info + Connection Info side by side
        info_row = tk.Frame(tab_ov, bg=C_BG)
        info_row.pack(fill="x", padx=16, pady=(8, 0))

        # Left: Device Info
        frm_di = tk.Frame(info_row, bg=C_SURFACE, padx=12, pady=8)
        frm_di.pack(side="left", fill="both", expand=True, padx=(0, 6))
        tk.Label(frm_di, text="Device Info", bg=C_SURFACE, fg=C_HEADER,
                 font=FONT_BOLD).pack(anchor="w", pady=(0, 4))
        cols_di = ("key", "value")
        self._tree_mdm_devinfo = self._make_tree_inline(frm_di, cols_di,
            headings=["Property", "Value"], widths=[180, 280])

        # Right: Connection Info
        frm_ci = tk.Frame(info_row, bg=C_SURFACE, padx=12, pady=8)
        frm_ci.pack(side="left", fill="both", expand=True, padx=(6, 0))
        tk.Label(frm_ci, text="Connection Info", bg=C_SURFACE, fg=C_HEADER,
                 font=FONT_BOLD).pack(anchor="w", pady=(0, 4))
        cols_ci = ("key", "value")
        self._tree_mdm_conninfo = self._make_tree_inline(frm_ci, cols_ci,
            headings=["Property", "Value"], widths=[180, 280])

        # Issues section below
        tk.Label(tab_ov, text="Issues detected:", bg=C_BG, fg=C_TEXT_DIM,
                 font=FONT_BOLD).pack(anchor="w", padx=16, pady=(10, 0))
        self._txt_mdm_issues = self._scrolled_text(tab_ov, height=10, mono=False)

        # ---- Tab 2 : Policies ----
        n_pol = len(p.managed_policies)
        tab_pol = tk.Frame(nb, bg=C_BG)
        nb.add(tab_pol, text=f"  Policies ({n_pol})  ")

        # Filter bar
        flt_pol = tk.Frame(tab_pol, bg=C_BG)
        flt_pol.pack(fill="x", padx=8, pady=4)
        tk.Label(flt_pol, text="Filter:", bg=C_BG, fg=C_TEXT_DIM,
                 font=FONT_BODY).pack(side="left")
        self._pol_filter_mdm = tk.StringVar()
        ent = tk.Entry(flt_pol, textvariable=self._pol_filter_mdm,
                       bg=C_PANEL, fg=C_TEXT, insertbackground=C_TEXT,
                       font=FONT_BODY, relief="flat", borderwidth=4)
        ent.pack(side="left", padx=6, ipadx=4)
        self._pol_count_mdm = tk.Label(flt_pol, text="", bg=C_BG, fg=C_TEXT_DIM,
                                       font=("Segoe UI", 8))
        self._pol_count_mdm.pack(side="right")

        cols_pol = ("area", "policy", "value")
        self._tree_mdm_pol = self._make_tree(
            tab_pol, cols_pol,
            headings=["Area", "Policy", "Value"],
            widths=[160, 360, 200])
        self._pol_filter_mdm.trace_add("write",
            lambda *_: self._filter_mdm_policies())

        # ---- Tab 3 : Blocked GPs ----
        n_bgp = len(p.blocked_gps)
        tab_bgp = tk.Frame(nb, bg=C_BG)
        nb.add(tab_bgp, text=f"  Blocked GPs ({n_bgp})  ")
        cols_bgp = ("path", "name")
        self._tree_mdm_bgp = self._make_tree(
            tab_bgp, cols_bgp,
            headings=["GPO Path", "Blocked Setting"],
            widths=[480, 300])
        self._tree_mdm_bgp.tag_configure("odd", background=C_BG)

        # ---- Tab 4 : LAPS ----
        tab_laps = tk.Frame(nb, bg=C_BG)
        nb.add(tab_laps, text="  LAPS  ")
        cols_laps = ("setting", "value")
        self._tree_mdm_laps = self._make_tree(
            tab_laps, cols_laps,
            headings=["Setting", "Value"],
            widths=[340, 340])

        # ---- Tab 5 : Config Sources ----
        n_src = sum(len(v) for v in p.config_sources.values())
        tab_src = tk.Frame(nb, bg=C_BG)
        nb.add(tab_src, text=f"  Sources ({n_src})  ")
        cols_src = ("source", "count", "ids")
        self._tree_mdm_src = self._make_tree(
            tab_src, cols_src,
            headings=["Configuration Source", "Resources", "IDs (sample)"],
            widths=[260, 90, 560])

        # ---- Tab 6 : Files in CAB ----
        tab_files = tk.Frame(nb, bg=C_BG)
        nb.add(tab_files, text="  CAB Files  ")
        cols_cf = ("name", "size", "path")
        self._tree_cab = self._make_tree(
            tab_files, cols_cf,
            headings=["File Name", "Size", "Full Path"],
            widths=[280, 90, 580])

        # Populate all sub-tabs
        self._populate_mdm_diag()

    def _populate_mdm_diag(self):
        """Fill all MDM Diagnostics sub-tabs from the parsed report."""
        p = self._mdm_diag_parser
        if not p.parsed:
            return

        # --- Overview: Device Info tree ---
        self._tree_clear(self._tree_mdm_devinfo)
        DI_KEYS = ('PC name', 'Organization', 'Edition', 'OS Build',
                   'Processor', 'Installed RAM', 'System Type')
        di = p.device_info
        for i, k in enumerate(DI_KEYS):
            if k in di:
                self._tree_mdm_devinfo.insert(
                    "", "end", values=(k, di[k]),
                    tags=("even" if i % 2 == 0 else "odd",))
        # Any remaining keys not in the fixed list
        for i, (k, v) in enumerate(di.items()):
            if k not in DI_KEYS:
                self._tree_mdm_devinfo.insert(
                    "", "end", values=(k, v),
                    tags=("even" if i % 2 == 0 else "odd",))

        # --- Overview: Connection Info tree ---
        self._tree_clear(self._tree_mdm_conninfo)
        CI_KEYS = ('Managed by', 'Last sync', 'Management server address')
        ci = p.connection_info
        ai = p.account_info
        all_conn = {**{k: ci[k] for k in CI_KEYS if k in ci},
                    **{k: ai[k] for k in ('EntDMID', 'OMADM protocol version')
                       if k in ai}}
        # Certificates
        for issued_to, issued_by in p.certificates:
            all_conn[f"Cert: {issued_to[:40]}"] = f"by {issued_by[:40]}"
        # Summary counts
        n_src = sum(len(v) for v in p.config_sources.values())
        all_conn["Config sources"]   = f"{len(p.config_sources)} types, {n_src} resources"
        all_conn["Managed policies"] = str(len(p.managed_policies))
        all_conn["Blocked GPs"]      = str(len(p.blocked_gps))
        for i, (k, v) in enumerate(all_conn.items()):
            self._tree_mdm_conninfo.insert(
                "", "end", values=(k, v),
                tags=("even" if i % 2 == 0 else "odd",))

        # --- Overview: Issues text ---
        self._txt_mdm_issues.configure(state="normal")
        self._txt_mdm_issues.delete("1.0", "end")
        self._txt_mdm_issues.tag_configure("err",  foreground=C_ERROR)
        self._txt_mdm_issues.tag_configure("warn", foreground=C_WARN)
        self._txt_mdm_issues.tag_configure("info", foreground=C_TEXT_DIM)
        if p.issues:
            for iss in p.issues:
                tag  = {"ERROR": "err", "WARNING": "warn"}.get(iss.severity, "info")
                icon = {"ERROR": "[!]", "WARNING": "[~]"}.get(iss.severity, "[i]")
                self._txt_mdm_issues.insert("end", f"{icon} [{iss.area}] {iss.title}\n", tag)
                self._txt_mdm_issues.insert("end", f"     {iss.detail}\n")
                if iss.recommendation:
                    self._txt_mdm_issues.insert("end", f"     => {iss.recommendation}\n")
                self._txt_mdm_issues.insert("end", "\n")
        else:
            self._txt_mdm_issues.insert("end", "No issues detected.", "info")
        self._txt_mdm_issues.configure(state="disabled")

        # --- Policies tree ---
        self._filter_mdm_policies()

        # --- Blocked GPs tree ---
        self._tree_clear(self._tree_mdm_bgp)
        for i, gp in enumerate(p.blocked_gps):
            self._tree_mdm_bgp.insert(
                "", "end",
                values=(gp['path'], gp['name']),
                tags=("even" if i % 2 == 0 else "odd",))

        # --- LAPS tree ---
        self._tree_clear(self._tree_mdm_laps)
        LAPS_WARN = {
            'BackupDirectory': lambda v: v == '0',
            'PasswordAgeDays': lambda v: int(v) > 60 if v.isdigit() else False,
            'PasswordLength':  lambda v: int(v) < 12 if v.isdigit() else False,
        }
        for i, (k, v) in enumerate(p.laps.items()):
            tag = "even" if i % 2 == 0 else "odd"
            iid = self._tree_mdm_laps.insert(
                "", "end", values=(k, v), tags=(tag,))
            if LAPS_WARN.get(k, lambda x: False)(v):
                self._tree_mdm_laps.item(iid, tags=(tag, "warn_laps"))
        self._tree_mdm_laps.tag_configure("warn_laps", foreground=C_WARN)

        # --- Config Sources tree ---
        self._tree_clear(self._tree_mdm_src)
        for i, (src, ids) in enumerate(sorted(p.config_sources.items())):
            sample = ", ".join(ids[:3])
            if len(ids) > 3:
                sample += f" +{len(ids)-3}"
            self._tree_mdm_src.insert(
                "", "end",
                values=(src, str(len(ids)), sample),
                tags=("even" if i % 2 == 0 else "odd",))

        # --- CAB Files tree ---
        self._tree_clear(self._tree_cab)
        for i, fp in enumerate(self._extra_parser.cab.extracted_files):
            try:
                size = os.path.getsize(fp)
                size_str = (f"{size/1024:.1f} KB"
                            if size < 1_048_576
                            else f"{size/1_048_576:.1f} MB")
            except OSError:
                size_str = "?"
            self._tree_cab.insert(
                "", "end",
                values=(os.path.basename(fp), size_str, fp),
                tags=("even" if i % 2 == 0 else "odd",))

    def _filter_mdm_policies(self):
        """Re-populate the policies tree with optional text filter."""
        if not hasattr(self, '_tree_mdm_pol'):
            return
        self._tree_clear(self._tree_mdm_pol)
        p   = self._mdm_diag_parser
        term = getattr(self, '_pol_filter_mdm', tk.StringVar()).get().lower()
        shown = 0
        AREA_COLOURS = {
            'Update': C_ACCENT2, 'Security': C_WARN,
            'DeviceGuard': C_WARN, 'ControlPolicyConflict': C_ERROR,
            'DmaGuard': C_WARN, 'DeviceHealthMonitoring': C_TEXT_DIM,
        }
        for i, pol in enumerate(p.managed_policies):
            if pol['area'] == 'knobs':
                continue   # skip internal knobs — too verbose
            if term and not (term in pol['area'].lower() or
                             term in pol['policy'].lower() or
                             term in pol['value'].lower()):
                continue
            iid = self._tree_mdm_pol.insert(
                "", "end",
                values=(pol['area'], pol['policy'], pol['value']),
                tags=(f"area_{pol['area']}", "even" if i % 2 == 0 else "odd"))
            shown += 1
        # Apply area colours
        for area, colour in AREA_COLOURS.items():
            self._tree_mdm_pol.tag_configure(f"area_{area}", foreground=colour)
        total = sum(1 for p2 in p.managed_policies if p2['area'] != 'knobs')
        if hasattr(self, '_pol_count_mdm'):
            self._pol_count_mdm.configure(
                text=f"{shown}/{total} policies" if term else f"{total} policies")

    # -------------------------------------------------------------------------
    # EVENT LOG TAB
    # -------------------------------------------------------------------------

    # Map internal key -> display name, file number hint, treeview column width
    _EVTX_LOG_DEFS = [
        ("evtx_setup",       "Setup Events",       "(61)"),
        ("evtx_system",      "System Events",      "(62)"),
        ("evtx_application", "Application Events", "(45)"),
    ]

    def _build_tab_eventlog_placeholder(self):
        f = self._tab_eventlog
        tk.Label(f, text="Event Log",
                 bg=C_BG, fg=C_HEADER, font=FONT_TITLE
                 ).pack(anchor="w", padx=16, pady=(12, 4))
        self._evtx_placeholder = tk.Label(
            f,
            text="Run an analysis to populate the Event Log tabs.",
            bg=C_BG, fg=C_TEXT_DIM, font=FONT_BODY)
        self._evtx_placeholder.pack(padx=16, pady=20)
        # Frame that holds the inner notebook (packed after scan)
        self._evtx_inner_nb_frame = tk.Frame(f, bg=C_BG)
        self._evtx_inner_nb_frame.pack(fill="both", expand=True)

    def _build_evtx_inner_nb(self):
        """Build Event Log panel with a combobox selector + single shared treeview."""
        # Destroy any previous content
        if self._evtx_inner_nb is not None:
            self._evtx_inner_nb.destroy()
            self._evtx_inner_nb = None
        self._evtx_widgets = {}

        if self._evtx_placeholder.winfo_exists():
            self._evtx_placeholder.pack_forget()

        if not self._evtx_parsers:
            return

        # Build sorted list of (log_type, display_name, parser)
        entries = []
        for log_type, parser in sorted(self._evtx_parsers.items()):
            if parser is None:
                continue
            display_name = (log_type
                            .replace("evtx_", "")
                            .replace("_", " ")
                            .title())
            err_c  = parser.error_count + parser.critical_count
            warn_c = parser.warning_count
            badge  = f"  [{err_c}E {warn_c}W]" if (err_c + warn_c) > 0 else ""
            combo_label = f"{display_name}{badge}"
            entries.append((log_type, display_name, parser, combo_label))

        if not entries:
            return

        # Container (stored as _evtx_inner_nb so _clear_all can destroy it)
        container = tk.Frame(self._evtx_inner_nb_frame, bg=C_BG)
        container.pack(fill="both", expand=True)
        self._evtx_inner_nb = container   # reuse slot for lifetime management

        # ── Top toolbar ──────────────────────────────────────────────────────
        toolbar = tk.Frame(container, bg=C_SURFACE, pady=5, padx=12)
        toolbar.pack(fill="x")

        tk.Label(toolbar, text="Log:", bg=C_SURFACE, fg=C_TEXT_DIM,
                 font=FONT_BODY).pack(side="left")

        combo_values = [e[3] for e in entries]
        combo_var    = tk.StringVar(value=combo_values[0])

        combo = ttk.Combobox(toolbar, textvariable=combo_var,
                             values=combo_values, state="readonly",
                             width=52, font=FONT_BODY)
        combo.pack(side="left", padx=(6, 20))

        # Info label (event counts for selected log)
        info_lbl = tk.Label(toolbar, text="", bg=C_SURFACE, fg=C_TEXT_DIM,
                            font=("Segoe UI", 8))
        info_lbl.pack(side="left")

        # ── Filter buttons ────────────────────────────────────────────────────
        flt_bar = tk.Frame(container, bg=C_BG)
        flt_bar.pack(fill="x", padx=8, pady=(4, 0))
        tk.Label(flt_bar, text="Show:", bg=C_BG, fg=C_TEXT_DIM,
                 font=FONT_BODY).pack(side="left")

        lv_var = tk.StringVar(value="all")
        btn_defs = [
            ("All",      "all",     C_ACCENT),
            ("Errors",   "error",   C_ERROR),
            ("Warnings", "warning", C_WARN),
            ("Info",     "info",    C_TEXT_DIM),
        ]
        btns_ref = []

        for lbl, val, abg in btn_defs:
            def _make_btn(label, value, active_bg):
                btn = tk.Button(
                    flt_bar, text=label,
                    bg=C_PANEL, fg=C_TEXT_DIM,
                    activebackground=active_bg, activeforeground="white",
                    font=("Segoe UI", 8, "bold"),
                    relief="flat", borderwidth=0, padx=8, pady=3,
                    cursor="hand2")
                def _click(v=value, b=btn, abg2=active_bg):
                    lv_var.set(v)
                    for ob, ov, oabg in btns_ref:
                        ob.configure(bg=(oabg if ov == v else C_PANEL),
                                     fg=("white" if ov == v else C_TEXT_DIM))
                btn.configure(command=_click)
                return btn
            b = _make_btn(lbl, val, abg)
            btns_ref.append((b, val, abg))
            b.pack(side="left", padx=(4, 0))

        btns_ref[0][0].configure(bg=C_ACCENT, fg="white")   # "All" active

        count_lbl = tk.Label(flt_bar, text="", bg=C_BG, fg=C_TEXT_DIM,
                             font=("Segoe UI", 8))
        count_lbl.pack(side="right")

        # ── Shared treeview ───────────────────────────────────────────────────
        cols = ("level", "timestamp", "event_id", "provider", "message")
        tree = self._make_tree(
            container, cols,
            headings=["Level", "Timestamp", "EventID", "Provider", "Message"],
            widths=[80, 160, 70, 220, 560])
        tree.tag_configure("Critical",    foreground=C_ERROR)
        tree.tag_configure("Error",       foreground=C_ERROR)
        tree.tag_configure("Warning",     foreground=C_WARN)
        tree.tag_configure("Information", foreground=C_TEXT)
        tree.tag_configure("Verbose",     foreground=C_TEXT_DIM)
        tree.tag_configure("Unknown",     foreground=C_TEXT_DIM)

        # Store widgets so _filter_evtx_events can reach them
        # We store a single shared entry keyed by "__shared__"
        self._evtx_widgets["__shared__"] = {
            "tree":      tree,
            "count_lbl": count_lbl,
            "lv_var":    lv_var,
        }
        # Also register each log_type pointing to the same tree
        for log_type, _, _, _ in entries:
            self._evtx_widgets[log_type] = self._evtx_widgets["__shared__"]

        # Build a fast lookup: combo_label -> log_type
        label_to_type = {e[3]: e[0] for e in entries}
        label_to_info = {e[3]: (e[1], e[2]) for e in entries}

        def _on_selection(*_):
            sel_label = combo_var.get()
            log_type  = label_to_type.get(sel_label)
            if log_type is None:
                return
            display_name, parser = label_to_info[sel_label]
            err_c  = parser.error_count + parser.critical_count
            warn_c = parser.warning_count
            info_lbl.configure(
                text=(f"{parser.total_count} events  |  "
                      f"{err_c} error(s)  {warn_c} warning(s)  "
                      f"{parser.info_count} info"))
            # Reset to "All" filter and repopulate
            lv_var.set("all")
            for ob, ov, oabg in btns_ref:
                ob.configure(bg=(C_ACCENT if ov == "all" else C_PANEL),
                             fg=("white" if ov == "all" else C_TEXT_DIM))
            self._filter_evtx_events(log_type, "all", tree, count_lbl)

        combo.bind("<<ComboboxSelected>>", _on_selection)

        # Filter button also repopulates the current selection
        lv_var.trace_add("write", lambda *_: (
            self._filter_evtx_events(
                label_to_type.get(combo_var.get(), ""),
                lv_var.get(), tree, count_lbl)
        ))

        # Initial population
        _on_selection()

    def _filter_evtx_events(self, log_type, level_filter, tree, count_lbl):
        """Re-populate an evtx sub-tab tree with the requested level filter."""
        for item in tree.get_children():
            tree.delete(item)

        parser = self._evtx_parsers.get(log_type)
        if parser is None:
            count_lbl.configure(text="no file")
            return

        events = parser.filtered(level_filter)
        total  = parser.total_count

        for i, ev in enumerate(events):
            tree.insert(
                "", "end",
                values=(ev.level_str, ev.timestamp, ev.event_id,
                        ev.provider[:50], ev.message[:200]),
                tags=(ev.level_str, "even" if i % 2 == 0 else "odd"))

        shown = len(events)
        count_lbl.configure(
            text=(f"{shown}/{total} events" if shown != total
                  else f"{total} events"))

    # -------------------------------------------------------------------------
    # EVTX BACKGROUND SCAN
    # -------------------------------------------------------------------------

    def _run_evtx_scan(self):
        """Scan evtx files in a background thread (uses wevtutil.exe)."""
        if self._evtx_thread and self._evtx_thread.is_alive():
            return

        inv = self._zip_handler.file_inventory

        # Collect (log_type, file_path) pairs — dynamically from ALL evtx files
        to_scan = []
        seen_types = set()
        for fp in inv.get("event_logs", []):
            if not fp.lower().endswith(".evtx"):
                continue
            # Derive a stable log_type key from filename
            bn = os.path.basename(fp)
            # Strip leading "(N) Events " prefix
            clean = re.sub(r"^\(\d+\)\s*Events?\s*", "", bn, flags=re.IGNORECASE)
            clean = clean.replace(".evtx", "").strip()
            log_type = "evtx_" + re.sub(r"[^a-z0-9]", "_",
                                         clean.lower()).strip("_")
            to_scan.append((log_type, fp))
            seen_types.add(log_type)

        if not to_scan:
            return

        self._set_status("Scanning Event Log files (wevtutil.exe)...")
        self.after(0, lambda: self._bg_scan_start(
            "Scanning Windows Event Logs",
            f"0 / {len(to_scan)} file(s) — wevtutil.exe"))

        def _do_scan():
            # Verify wevtutil availability once
            if not EvtxParser.is_wevtutil_available():
                self.after(0, lambda: self._set_status(
                    "Event Log scan skipped — wevtutil.exe not available"))
                self.after(0, self._bg_scan_end)
                return

            parsers = {}
            total = len(to_scan)
            for idx, (log_type, fp) in enumerate(to_scan, 1):
                fname = os.path.basename(fp)
                self.after(0, lambda i=idx, t=total, n=fname: (
                    self._set_status(f"Scanning Event Log ({i}/{t}): {n}..."),
                    self._overlay_set_step(f"File {i}/{t}: {n}")))
                if log_type not in parsers:
                    parsers[log_type] = EvtxParser()
                parsers[log_type].scan(fp, max_events=2000)

            self._evtx_parsers = parsers
            self.after(0, self._on_evtx_done)

        self._evtx_thread = threading.Thread(target=_do_scan, daemon=True)
        self._evtx_thread.start()

    def _on_evtx_done(self):
        """Called on the main thread after evtx scan completes."""
        self._bg_scan_end()
        total_err  = sum(p.error_count + p.critical_count
                         for p in self._evtx_parsers.values())
        total_warn = sum(p.warning_count for p in self._evtx_parsers.values())
        total_ev   = sum(p.total_count   for p in self._evtx_parsers.values())

        self._set_status(
            f"Event Log scan complete  --  {total_ev} events, "
            f"{total_err} error(s), {total_warn} warning(s)")

        self._build_evtx_inner_nb()

    # -------------------------------------------------------------------------

    def _build_tab_files(self):
        f = self._tab_files
        tk.Label(f, text="ZIP File Inventory",
                 bg=C_BG, fg=C_HEADER, font=FONT_TITLE
                 ).pack(anchor="w", padx=16, pady=(12, 4))

        cols = ("name", "category", "size", "path")
        self._tree_files = self._make_tree(
            f, cols,
            headings=["File Name", "Category", "Size", "Relative Path"],
            widths=[260, 140, 80, 520])

    # =========================================================================
    # SHARED WIDGET HELPERS
    # =========================================================================

    def _scrolled_text(self, parent, height=10, mono=False):
        frm = tk.Frame(parent, bg=C_BG)
        frm.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        sb = tk.Scrollbar(frm, orient="vertical", bg=C_PANEL)
        txt = tk.Text(frm, height=height,
                      bg=C_SURFACE, fg=C_TEXT,
                      insertbackground=C_TEXT,
                      font=FONT_MONO if mono else FONT_BODY,
                      relief="flat", borderwidth=0,
                      wrap="word", yscrollcommand=sb.set,
                      state="disabled", padx=8, pady=6)
        sb.configure(command=txt.yview)
        sb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        return txt

    def _make_tree(self, parent, columns, headings, widths):
        style = ttk.Style()
        style.configure("Dark.Treeview",
                        background=C_SURFACE, foreground=C_TEXT,
                        fieldbackground=C_SURFACE, rowheight=22,
                        font=("Segoe UI", 9))
        style.configure("Dark.Treeview.Heading",
                        background=C_PANEL, foreground=C_TEXT_DIM,
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Dark.Treeview",
                  background=[("selected", C_ACCENT)],
                  foreground=[("selected", "white")])

        frm = tk.Frame(parent, bg=C_BG)
        frm.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        vsb = tk.Scrollbar(frm, orient="vertical",   bg=C_PANEL)
        hsb = tk.Scrollbar(frm, orient="horizontal", bg=C_PANEL)
        tree = ttk.Treeview(frm, columns=columns, show="headings",
                             style="Dark.Treeview",
                             yscrollcommand=vsb.set,
                             xscrollcommand=hsb.set,
                             selectmode="browse")
        vsb.configure(command=tree.yview)
        hsb.configure(command=tree.xview)

        for col, hdr, w in zip(columns, headings, widths):
            tree.heading(col, text=hdr, anchor="w")
            tree.column(col, width=w, minwidth=40, anchor="w")

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        tree.pack(side="left", fill="both", expand=True)
        tree.tag_configure("odd",  background=C_BG)
        tree.tag_configure("even", background=C_SURFACE)
        self._attach_tree_context_menu(tree)
        return tree

    def _make_tree_inline(self, parent, columns, headings, widths):
        """Like _make_tree but packs directly into parent (no extra Frame wrapper)."""
        vsb = tk.Scrollbar(parent, orient="vertical", bg=C_PANEL)
        tree = ttk.Treeview(parent, columns=columns, show="headings",
                             style="Dark.Treeview",
                             yscrollcommand=vsb.set,
                             selectmode="browse", height=7)
        vsb.configure(command=tree.yview)
        for col, hdr, w in zip(columns, headings, widths):
            tree.heading(col, text=hdr, anchor="w")
            tree.column(col, width=w, minwidth=40, anchor="w")
        vsb.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        tree.tag_configure("odd",  background=C_BG)
        tree.tag_configure("even", background=C_SURFACE)
        self._attach_tree_context_menu(tree)
        return tree

    def _attach_tree_context_menu(self, tree):
        """Attach a right-click context menu to any Treeview for copy actions."""
        menu = tk.Menu(self, tearoff=0, bg=C_PANEL, fg=C_TEXT,
                       activebackground=C_ACCENT, activeforeground="white",
                       font=FONT_BODY, bd=0, relief="flat")

        def copy_row():
            sel = tree.selection()
            if not sel:
                return
            vals = tree.item(sel[0], "values")
            text = "\t".join(str(v) for v in vals)
            self.clipboard_clear()
            self.clipboard_append(text)

        def copy_cell():
            sel = tree.selection()
            if not sel:
                return
            # Identify which column was clicked via the stored x position
            col_id = getattr(tree, "_ctx_col", None)
            if col_id is None:
                copy_row()
                return
            cols = tree["columns"]
            try:
                idx = list(cols).index(col_id)
            except ValueError:
                copy_row()
                return
            vals = tree.item(sel[0], "values")
            text = str(vals[idx]) if idx < len(vals) else ""
            self.clipboard_clear()
            self.clipboard_append(text)

        def copy_all():
            rows = []
            for iid in tree.get_children():
                vals = tree.item(iid, "values")
                rows.append("\t".join(str(v) for v in vals))
            self.clipboard_clear()
            self.clipboard_append("\n".join(rows))

        def _get_search_text():
            """Return the best text for web / AI search (cell if meaningful, else row)."""
            sel = tree.selection()
            if not sel:
                return ""
            vals = tree.item(sel[0], "values")
            col_id = getattr(tree, "_ctx_col", None)
            if col_id:
                cols = tree["columns"]
                try:
                    idx = list(cols).index(col_id)
                    cell = str(vals[idx]) if idx < len(vals) else ""
                    if cell.strip():
                        return cell.strip()
                except ValueError:
                    pass
            return " ".join(str(v) for v in vals if str(v).strip())

        def search_internet():
            text = _get_search_text()
            if not text:
                return
            query = urllib.parse.quote_plus(text + " Intune Windows Update")
            webbrowser.open(f"https://www.google.com/search?q={query}")

        def ask_ai():
            text = _get_search_text()
            if not text:
                return
            prompt = (
                f"Dans le contexte de Microsoft Intune et Windows Update, "
                f"Explain this log entry and how to resolve the issue: {text}"
            )
            query = urllib.parse.quote_plus(prompt)
            webbrowser.open(f"https://claude.ai/new?q={query}")

        menu.add_command(label="Copy row",      command=copy_row)
        menu.add_command(label="Copy cell",     command=copy_cell)
        menu.add_separator()
        menu.add_command(label="Copy all rows", command=copy_all)
        menu.add_separator()
        menu.add_command(label="🔍  Rechercher sur internet", command=search_internet)
        menu.add_command(label="🤖  Ask AI",       command=ask_ai)

        def on_right_click(event):
            # Select the row under cursor
            iid = tree.identify_row(event.y)
            if iid:
                tree.selection_set(iid)
            # Store the column that was clicked
            col_id = tree.identify_column(event.x)
            if col_id:
                cols = tree["columns"]
                try:
                    col_idx = int(col_id.replace("#", "")) - 1
                    tree._ctx_col = cols[col_idx] if col_idx < len(cols) else None
                except (ValueError, IndexError):
                    tree._ctx_col = None
            menu.tk_popup(event.x_root, event.y_root)

        tree.bind("<Button-3>", on_right_click)

    def _tree_clear(self, tree):
        for item in tree.get_children():
            tree.delete(item)

    # =========================================================================
    # ACTIONS
    # =========================================================================

    @staticmethod
    def _parse_ipconfig(file_path):
        """
        Parse ipconfig /all output to extract the first IPv4 address
        and OS version (Windows IP Configuration -> Host Name is not OS,
        so OS comes from the file header line if present).
        Returns (ip_str, os_str).
        """
        ip  = ""
        os_ = ""
        ip_re  = re.compile(r"IPv4\s+Address[^:]*:\s*([\d]{1,3}(?:\.[\d]{1,3}){3})", re.IGNORECASE)
        # ipconfig /all sometimes has "Windows IP Configuration" as first line
        for enc in ("utf-8", "utf-16", "latin-1"):
            try:
                content = open(file_path, encoding=enc, errors="replace").read()
                break
            except Exception:
                content = ""
        for line in content.splitlines():
            m = ip_re.search(line)
            if m and not ip:
                candidate = m.group(1)
                # Skip loopback / APIPA
                if not candidate.startswith("127.") and not candidate.startswith("169.254."):
                    ip = candidate
            if ip:
                break
        return ip, os_


    # =========================================================================
    # LOCAL DEVICE COLLECTION
    # =========================================================================


    def _start_local_collect_elevated(self):
        """Called on startup when re-launched with --collect-local.
        Skips the admin check and goes straight to the save dialog + collection."""
        import subprocess, shutil, tempfile, ctypes, datetime
        from tkinter.filedialog import asksaveasfilename

        device_name = os.environ.get("COMPUTERNAME", "") or __import__("socket").gethostname()
        default_name = f"{device_name}_DiagLogs_{datetime.datetime.now():%Y%m%d_%H%M%S}.zip"
        save_path = asksaveasfilename(
            title="Save collected diagnostics ZIP as...",
            initialfile=default_name,
            defaultextension=".zip",
            filetypes=[("ZIP archive", "*.zip"), ("All files", "*.*")])
        if not save_path:
            return

        self._clear_all()
        self._btn_local.configure(state="disabled")
        self._btn_analyse.configure(state="disabled")
        self._show_overlay("Starting diagnostic collection...",
                           title="⏳  Collecting local device diagnostics")
        self._set_status("Collecting local device diagnostics...")

        def _collect():
            try:
                def _progress(current, total, step):
                    self._overlay_set_step(f"[{current}/{total}] {step}")

                collect_and_zip(save_path, progress_cb=_progress)
                self.after(0, lambda zp=save_path:
                           self._local_collect_done(zp, None))

            except Exception:
                import traceback
                self.after(0, lambda e=traceback.format_exc():
                           self._local_collect_failed(e, None))

        import threading
        threading.Thread(target=_collect, daemon=True).start()

    def _analyze_local_device(self):
        """Collect Intune diagnostics from the local device, then analyze.

        Strategy:
          1. Check if already running as admin; if not, re-launch with UAC elevation.
          Collects IME logs, WU ETL, registry, commands, event logs, certs.
        """
        import subprocess, shutil, tempfile, ctypes

        # ── Check admin rights ───────────────────────────────────────────────
        def _is_admin():
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except Exception:
                return False

        if not _is_admin():
            from tkinter import simpledialog
            choice = messagebox.askquestion(
                "Administrator rights recommended",
                "Some data (registry, event logs, system info) requires "
                "administrator rights for a complete collection.\n\n"
                "Click Yes to re-launch with elevated privileges (recommended).\n"
                "Click No to continue without elevation (partial collection).",
                icon="warning")
            if choice == "yes":
                try:
                    import sys
                    args = [a for a in sys.argv if a != "--collect-local"]
                    args.append("--collect-local")
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable,
                        " ".join(f'"{a}"' for a in args), None, 1)
                    self.after(500, self.destroy)
                except Exception as exc:
                    messagebox.showerror("Elevation failed", str(exc))
                return
            # else: continue without elevation (best-effort collection)

        # ── Ask where to save the ZIP ────────────────────────────────────
        from tkinter.filedialog import asksaveasfilename
        import datetime
        device_name = os.environ.get("COMPUTERNAME", "") or __import__("socket").gethostname()
        default_name = f"{device_name}_DiagLogs_{datetime.datetime.now():%Y%m%d_%H%M%S}.zip"
        save_path = asksaveasfilename(
            title="Save collected diagnostics ZIP as...",
            initialfile=default_name,
            defaultextension=".zip",
            filetypes=[("ZIP archive", "*.zip"), ("All files", "*.*")])
        if not save_path:
            return  # user cancelled

        self._clear_all()
        self._btn_local.configure(state="disabled")
        self._btn_analyse.configure(state="disabled")
        self._show_overlay("Starting diagnostic collection...",
                           title="⏳  Collecting local device diagnostics")
        self._set_status("Collecting local device diagnostics...")

        def _collect():
            try:
                def _progress(current, total, step):
                    self._overlay_set_step(f"[{current}/{total}] {step}")

                collect_and_zip(save_path, progress_cb=_progress)
                self.after(0, lambda zp=save_path:
                           self._local_collect_done(zp, None))

            except Exception:
                import traceback
                self.after(0, lambda e=traceback.format_exc():
                           self._local_collect_failed(e, None))

        import threading
        threading.Thread(target=_collect, daemon=True).start()

    def _local_collect_done(self, zip_path, tmp_dir):
        """ZIP collected — wire it into the normal analysis pipeline."""
        self._btn_local.configure(state="normal")
        name = os.path.basename(zip_path)
        self._zip_path = zip_path
        self._lbl_file.configure(text=f"  {name}  (local device)", fg=C_TEXT)
        # Run normal analysis (overlay already visible — it will switch to analysis mode)
        self._show_overlay("Extracting collected ZIP...",
                           title="🔍  Analyzing local device diagnostics")
        self._btn_analyse.configure(state="normal")
        self._btn_export.configure(state="disabled")
        self._btn_local.configure(state="normal")
        self._progress.start(12)
        self._set_status("Extracting collected ZIP...")
        import threading
        threading.Thread(target=self._analysis_thread, daemon=True).start()

    def _local_collect_failed(self, error_msg, tmp_dir):
        """Collection failed — restore UI and show error."""
        self._hide_overlay()
        self._btn_local.configure(state="normal")
        self._set_status("Local collection failed.")
        messagebox.showerror(
            "Collection failed",
            f"Diagnostic collection failed:\n\n{error_msg}")
        if tmp_dir and os.path.isdir(tmp_dir):
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _open_and_analyze(self):
        """Open a ZIP file picker then immediately run analysis."""
        path = filedialog.askopenfilename(
            title="Select Intune Device Diagnostics ZIP",
            filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")])
        if not path:
            return
        self._clear_all()
        self._zip_path = path
        name = os.path.basename(path)
        self._lbl_file.configure(text=f"  {name}", fg=C_TEXT)
        self._btn_export.configure(state="disabled")
        self._run_analysis()

    def _open_zip(self):
        """Alias kept for internal callers that only need to pick a file."""
        self._open_and_analyze()

    def _run_analysis(self):
        if not self._zip_path:
            self._open_and_analyze()
            return
        self._btn_analyse.configure(state="disabled")
        self._btn_export.configure(state="disabled")
        self._progress.start(12)
        self._set_status("Extracting ZIP...")
        self._show_overlay("Extracting ZIP archive...", title="🔍  Analyzing Intune Diagnostics")
        threading.Thread(target=self._analysis_thread, daemon=True).start()

    def _analysis_thread(self):
        try:
            self._set_status("Extracting ZIP...")
            inventory = self._zip_handler.load(self._zip_path)
            self._zip_info = self._zip_handler.get_zip_info()

            self._set_status("Parsing DSRegCmd, registry, results.xml...")
            self._mdm_parser = MDMParser()
            for f in inventory.get("results_xml", []):
                self._mdm_parser.parse_results_xml(f)
            dsreg = self._zip_handler.find_file("dsregcmd")
            if dsreg:
                self._mdm_parser.parse_dsregcmd(dsreg)
            enroll = self._zip_handler.find_file("enrollments")
            if enroll and enroll.lower().endswith(".reg"):
                self._mdm_parser.parse_enrollments_reg(enroll)
            fw = self._zip_handler.find_file("advfirewall_show_allprofiles")
            if fw:
                self._mdm_parser.parse_firewall(fw)

            # Extra parsers: ipconfig, proxy, logonui, IME reg, CAB
            self._set_status("Parsing ipconfig / proxy / registry...")
            self._extra_parser = ExtraParser()

            # ipconfig /all  (32) Command windir_system32_ipconfig_exe_all
            ipconfig_file = self._zip_handler.find_file("ipconfig_exe_all")
            if not ipconfig_file:
                ipconfig_file = self._zip_handler.find_file("ipconfig")

            # netsh winhttp show proxy  (38) Command windir_system32_netsh_exe_winhttp_show_proxy
            proxy_file = self._zip_handler.find_file("winhttp_show_proxy")
            if not proxy_file:
                proxy_file = self._zip_handler.find_file("winhttp")

            # LogonUI registry  (11) RegistryKey ...Authentication_LogonUI
            logonui_file = self._zip_handler.find_file("logonui")

            # IME registry  (6) RegistryKey ...IntuneManagementExtension
            ime_reg_file = self._zip_handler.find_file("intunemanagementextension")
            if not ime_reg_file:
                ime_reg_file = self._zip_handler.find_file("intunemanagement")

            # msinfo32 report  (34) Command windir_system32_msinfo32_exe_report
            msinfo32_file = self._zip_handler.find_file("msinfo32")

            # CAB files: (74) FoldersFiles temp_MDMDiagnostics_..._cab
            cab_files = list(inventory.get("cab", []))

            self._extra_parser.set_files(
                ipconfig=ipconfig_file or "",
                proxy=proxy_file or "",
                logonui=logonui_file or "",
                ime_reg=ime_reg_file or "",
                msinfo32=msinfo32_file or "",
                cab_files=cab_files,
            )
            self._extra_parser.parse_all()

            # IP address and OS version
            self._device_ip = self._extra_parser.ipconfig.ip
            self._device_os = ""
            if not self._device_os:
                # Fallback: read OS from DSRegCmd "OS Version" field
                for section in self._mdm_parser.dsregcmd.sections.values():
                    v = section.get("OS Version", "")
                    if v:
                        self._device_os = v
                        break

            # Scan IME logs theme by theme
            self._error_detector = ErrorDetector()
            ime_themes = inventory.get("ime_themes", {})
            total_themes = len(ime_themes)
            for i, (theme, files) in enumerate(ime_themes.items(), 1):
                lbl = IME_THEME_LABELS.get(theme, theme)
                self._set_status(
                    f"Scanning IME logs ({i}/{total_themes}): {lbl}...")
                self._error_detector.scan_theme_files(theme, files)

            self._error_summary = self._error_detector.get_summary()

            # Windows Update registry
            self._wu_parser = WUParser()
            wu_reg = None
            for f in inventory.get("wu_registry", []):
                wu_reg = f
                break
            if not wu_reg:
                wu_reg = self._zip_handler.find_file("windowsupdate_orchestrator")
            wu_etl_files  = list(inventory.get("wu_etl", []))
            # Collect ALL .reg files for the policies scanner
            all_reg_files = (list(inventory.get("registry", [])) +
                             list(inventory.get("wu_registry", [])))
            # ReportingEvents.log: (86) FoldersFiles windir_SoftwareDistribution_ReportingEvents_log
            wu_reporting = self._zip_handler.find_file("reportingevents")
            self._wu_parser.set_files(registry_file=wu_reg or "",
                                      etl_files=wu_etl_files,
                                      reporting_events_file=wu_reporting or "",
                                      all_reg_files=all_reg_files)
            if wu_reg:
                self._set_status("Parsing Windows Update registry...")
                self._wu_parser.parse_registry()
            if wu_reporting:
                self._set_status("Parsing Windows Update ReportingEvents.log...")
                self._wu_parser.parse_reporting_events()
            self._set_status("Scanning .reg files for WU Group Policy keys...")
            self._wu_parser.parse_policies()

            self._set_status("Evaluating compliance...")
            self._compliance = ComplianceChecker()
            self._compliance_summary = self._compliance.analyse_from_mdm_parser(
                self._mdm_parser)

            # Device-level parsers: apps, drivers, wifi, autopatch, collection errors
            self._set_status("Parsing installed apps, drivers, WiFi profiles...")
            self._device_parser = DeviceParser()
            uninstall_regs = (list(inventory.get("reg_uninstall_x64", [])) +
                              list(inventory.get("reg_uninstall_x86", [])))
            pnputil_file     = next(iter(inventory.get("cmd_pnputil", [])), "")
            wlan_file        = next(iter(inventory.get("cmd_wlan_profiles", [])), "")
            cmu_reg          = next(iter(inventory.get("reg_cloudmanagedupdate", [])), "")
            autopatch_logs   = list(inventory.get("autopatch_logs", []))
            coll_errors      = list(inventory.get("collection_errors", []))
            self._device_parser.set_files(
                uninstall_reg_files=uninstall_regs,
                pnputil_file=pnputil_file,
                wlan_profiles_file=wlan_file,
                cloudmanagedupdate_reg=cmu_reg,
                autopatch_log_files=autopatch_logs,
                collection_error_files=coll_errors,
            )
            self._device_parser.parse_all()

            # Hardware & Security: battery, firewall, certificates, C2R logs
            self._set_status("Parsing battery report, firewall, certificates...")
            self._hardware_parser = HardwareParser()
            battery_html   = (next(iter(inventory.get("battery_report", [])), "")
                              or self._zip_handler.find_file("battery-report")
                              or self._zip_handler.find_file("batteryreport") or "")
            # Firewall already found above as `fw` variable
            cert_files     = list(inventory.get("cmd_certutil", []))
            c2r_log_files  = sorted(inventory.get("c2r_logs", []),
                                    key=lambda f: os.path.basename(f).lower())
            self._hardware_parser.set_files(
                battery_html   = battery_html,
                firewall_file  = fw or "",
                cert_files     = cert_files,
                c2r_log_files  = c2r_log_files,
            )
            self._hardware_parser.parse_all()

            self._set_status("Updating UI...")
            self.after(0, self._populate_ui)

        except Exception as exc:
            import traceback
            tb = traceback.format_exc()
            self.after(0, lambda: messagebox.showerror(
                "Analysis Error",
                f"An error occurred:\n\n{exc}\n\n{tb[:600]}"))
            self.after(0, self._analysis_done_ui)

    # ── Chained UI population — yields to tkinter between each heavy step ────

    def _populate_ui(self):
        """Entry point: runs each populate step via after() so the UI stays responsive."""
        self._set_status("Updating UI: Summary...")
        self._update_kpis()
        self._populate_summary()
        self.after(10, self._populate_ui_s2)

    def _populate_ui_s2(self):
        self._set_status("Updating UI: IME Logs...")
        self._rebuild_ime_tabs()
        self.after(10, self._populate_ui_s3)

    def _populate_ui_s3(self):
        self._set_status("Updating UI: Apps & Drivers...")
        self._build_appdrv_inner_nb()
        self.after(10, self._populate_ui_s4)

    def _populate_ui_s4(self):
        self._set_status("Updating UI: IME log entries...")
        self._populate_ime_trees()
        self.after(10, self._populate_ui_s5)

    def _populate_ui_s5(self):
        self._set_status("Updating UI: Device info...")
        self._populate_device_info()
        self.after(10, self._populate_ui_s6)

    def _populate_ui_s6(self):
        self._set_status("Updating UI: Windows Update...")
        self._populate_wu()
        self.after(10, self._populate_ui_s7)

    def _populate_ui_s7(self):
        self._set_status("Updating UI: Hardware & Office...")
        self._build_hardware_inner_nb()
        self._build_c2r_tab_content()
        self.after(10, self._populate_ui_s8)

    def _populate_ui_s8(self):
        self._set_status("Updating UI: File index...")
        self._populate_ai_after_analysis()
        self._populate_files()
        self._analysis_done = True
        self._analysis_done_ui()

    def _analysis_done_ui(self):
        self._progress.stop()
        self._hide_overlay()
        self._btn_analyse.configure(state="normal")
        if self._analysis_done:
            self._btn_export.configure(state="normal")
        self._set_status(
            "Analysis complete  --  Browse tabs or export the HTML report")

        # Auto-extract CAB if present (provides MDM Diag details + OS version)
        if self._analysis_done and self._extra_parser.cab_files:
            self._run_cab_extract()

        # Auto-scan WU ETL files if present (runs Get-WinEvent/tracerpt in background)
        if self._analysis_done and self._wu_parser.has_etl_files():
            self._run_wu_etl_scan()

        # Auto-scan evtx event logs if present
        if self._analysis_done:
            inv = self._zip_handler.file_inventory
            if inv.get("event_logs"):
                self._run_evtx_scan()

    # =========================================================================
    # POPULATE METHODS
    # =========================================================================

    def _update_kpis(self):
        errors   = self._error_summary.get("error_count",   0)
        warnings = self._error_summary.get("warning_count", 0)
        files    = self._error_summary.get("scanned_files", 0)

        self._kpi_errors.configure(
            text=str(errors), fg=C_ERROR if errors > 0 else C_OK)
        self._kpi_warnings.configure(
            text=str(warnings), fg=C_WARN if warnings > 0 else C_OK)
        self._kpi_files.configure(text=str(files), fg=C_TEXT)

        # Device identity banner – row 1
        dev  = self._mdm_parser.device_info
        name = dev.get("Device Name", "")
        if not name:
            # Fallback: extract from DSRegCmd Header section
            hdr = self._mdm_parser.dsregcmd.sections.get("Header", {})
            name = hdr.get("DeviceName", hdr.get("Device Name", ""))
            if not name:
                name = self._extra_parser.ipconfig.hostname
        ip  = getattr(self, "_device_ip",  "")
        os_ = getattr(self, "_device_os",  "")
        if not os_:
            wu_info = self._wu_parser.orchestrator.info
            os_ = (wu_info.get("OS Version", "") or
                   wu_info.get("OS Build", ""))
        if not os_:
            # Fallback: msinfo32 report (parsed upfront, no CAB needed)
            os_ = self._extra_parser.msinfo32.display_version
        if not os_:
            # Last fallback: MDM Diag HTML (available after CAB extraction)
            os_ = self._mdm_diag_parser.device_info.get("OS Build", "")
        self._lbl_dev_name.configure(text=name or "Unknown",
                                     fg=C_ACCENT2 if name else C_TEXT_DIM)
        self._lbl_dev_ip.configure(text=ip   or "Not found",
                                   fg=C_ACCENT2 if ip   else C_TEXT_DIM)
        self._lbl_dev_os.configure(text=os_  or "Unknown",
                                   fg=C_ACCENT2 if os_  else C_TEXT_DIM)

        # Device identity banner – row 2
        ep = self._extra_parser
        proxy_txt   = ep.proxy.summary
        user_txt    = ep.logonui.display_name or ep.logonui.sam_user
        ime_ver_txt = ep.ime_reg.agent_version
        self._lbl_dev_proxy.configure(
            text=proxy_txt or "Unknown",
            fg=C_OK if "direct" in proxy_txt.lower() else
               C_WARN if proxy_txt and proxy_txt != "Unknown" else C_TEXT_DIM)
        self._lbl_dev_user.configure(
            text=user_txt or "Unknown",
            fg=C_ACCENT2 if user_txt else C_TEXT_DIM)
        self._lbl_dev_ime_ver.configure(
            text=ime_ver_txt or "Unknown",
            fg=C_ACCENT2 if ime_ver_txt else C_TEXT_DIM)

        # MDM Diag Device Info + Connection Info trees in Summary
        self._tree_clear(self._tree_sum_devinfo)
        self._tree_clear(self._tree_sum_conninfo)
        p = self._mdm_diag_parser
        if p.parsed:
            DI_KEYS = ('PC name', 'Organization', 'Edition', 'OS Build',
                       'Processor', 'Installed RAM', 'System Type')
            for i, k in enumerate(DI_KEYS):
                v = p.device_info.get(k, "")
                if v:
                    self._tree_sum_devinfo.insert(
                        "", "end", values=(k, v),
                        tags=("even" if i % 2 == 0 else "odd",))
            CI_KEYS = ('Managed by', 'Last sync', 'Management server address',
                       'EntDMID', 'OMADM protocol version',
                       'Config sources', 'Managed policies')
            for i, k in enumerate(CI_KEYS):
                v = p.connection_info.get(k, "")
                if v:
                    self._tree_sum_conninfo.insert(
                        "", "end", values=(k, v),
                        tags=("even" if i % 2 == 0 else "odd",))

    def _populate_summary(self):
        es = self._error_summary
        cs = self._compliance_summary
        zi = self._zip_info
        overall = getattr(cs, "overall_status", "UNKNOWN")
        icon_map = {"COMPLIANT": "[OK]", "NON_COMPLIANT": "[KO]",
                    "PENDING": "[??]", "UNKNOWN": "[--]"}

        lines = [
            "=" * 64,
            "  SmartLogAnalyzer for Intune -- Analysis Report",
            f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 64,
            "",
            f"  File        : {zi.get('zip_name', '')}",
            f"  Size        : {zi.get('zip_size_mb', '')} MB",
            f"  ZIP files   : {zi.get('total_files', '')}",
            "",
            "-" * 64,
            f"{icon_map.get(overall, '[--]')} OVERALL COMPLIANCE : {overall}",
            f"   Compliant     : {getattr(cs, 'compliant_count',     0)}",
            f"   Non-compliant : {getattr(cs, 'non_compliant_count', 0)}",
            f"   Pending       : {getattr(cs, 'pending_count',       0)}",
            "",
            "-" * 64,
            f"[!] Errors        : {es.get('error_count',   0)}",
            f"[~] Warnings      : {es.get('warning_count', 0)}",
            f"    Files scanned : {es.get('scanned_files', 0)}",
            "",
        ]

        issues = self._mdm_parser.get_all_issues()
        if issues:
            lines += ["-" * 64, "CRITICAL ISSUES:"]
            for iss in issues:
                pfx = "[ERROR]" if iss["severity"] == "ERROR" else "[WARN]"
                lines.append(f"  {pfx} [{iss['category']}] {iss['title']}")
                lines.append(f"     Detail: {iss['detail']}")
                if iss.get("recommendation"):
                    lines.append(f"     => {iss['recommendation']}")
                lines.append("")

        tc = es.get("theme_counts", {})
        if tc:
            lines += ["-" * 64, "IME Log Errors/Warnings by Theme:"]
            for theme in IME_THEMES:
                if theme in tc:
                    c = tc[theme]
                    if c["errors"] + c["warnings"] > 0:
                        lbl = IME_THEME_LABELS.get(theme, theme)
                        lines.append(
                            f"   {lbl:<36} {c['errors']:>3} errors  "
                            f"{c['warnings']:>3} warnings")
            lines.append("")

        dev = self._mdm_parser.device_info
        if dev:
            lines += ["-" * 64, "Device Info (DSRegCmd):"]
            for k, v in dev.items():
                lines.append(f"   {k:<32} {v}")
            lines.append("")

        enroll = self._mdm_parser.enrollment_info
        if enroll:
            lines += ["Enrollment:"]
            for k, v in enroll.items():
                lines.append(f"   {k:<32} {v}")
            lines.append("")

        coll_errors = self._mdm_parser.results_xml.errors
        if coll_errors:
            lines += ["-" * 64,
                      f"Collection errors in results.xml: {len(coll_errors)}"]
            for ce in coll_errors[:8]:
                lines.append(
                    f"   {ce.get('name','')[:54]}  --  {ce.get('status','')}")
            if len(coll_errors) > 8:
                lines.append(f"   ... and {len(coll_errors)-8} more")
            lines.append("")

        text = "\n".join(lines)
        self._txt_summary.configure(state="normal")
        self._txt_summary.delete("1.0", "end")
        self._txt_summary.insert("end", text)
        self._txt_summary.configure(state="disabled")

    def _populate_ime_trees(self):
        """Population handled by _rebuild_ime_tabs -> _on_selection()."""
        pass

    def _populate_compliance(self):
        cs = self._compliance_summary
        if cs is None:
            return
        overall = cs.overall_status
        col_map = {"COMPLIANT": C_OK, "NON_COMPLIANT": C_ERROR,
                   "PENDING": C_WARN, "UNKNOWN": C_TEXT_DIM}
        self._lbl_compliance_overall.configure(
            text=(f"Overall: {overall.replace('_',' ')}  "
                  f"({cs.compliant_count} OK / "
                  f"{cs.non_compliant_count} KO / "
                  f"{cs.pending_count} Pending)"),
            fg=col_map.get(overall, C_TEXT_DIM), bg=C_SURFACE)
        self._frm_compliance_banner.configure(bg=C_SURFACE)
        self._tree_clear(self._tree_compliance)
        for ps in cs.policy_statuses:
            self._tree_compliance.insert(
                "", "end",
                values=(ps.area, ps.status.replace("_", " "),
                        ps.details[:200], ps.source_file),
                tags=(ps.status,))

    def _populate_enrollments(self):
        self._tree_clear(self._tree_enrollments)
        term = self._pol_filter_var.get().lower() \
            if hasattr(self, "_pol_filter_var") else ""
        enrollments = getattr(
            getattr(self._mdm_parser, "enrollments", None),
            "enrollments", [])
        filtered = [e for e in enrollments
                    if not term or
                    any(term in str(v).lower() for v in e.values())]
        for i, e in enumerate(filtered):
            self._tree_enrollments.insert(
                "", "end",
                values=(e.get("GUID",""), e.get("State",""),
                        e.get("Type",""), e.get("UPN",""),
                        e.get("EnrollmentURL","")),
                tags=("even" if i % 2 == 0 else "odd",))
        total = len(enrollments)
        shown = len(filtered)
        self._lbl_pol_count.configure(
            text=f"{shown}/{total} enrollments" if term
            else f"{total} enrollments")

    def _populate_device_info(self):
        self._tree_clear(self._tree_device)
        info = {**self._mdm_parser.device_info,
                **self._mdm_parser.enrollment_info}
        zi = self._zip_info
        info["[ZIP] File"]        = zi.get("zip_name", "")
        info["[ZIP] Size"]        = f"{zi.get('zip_size_mb','')} MB"
        info["[ZIP] Total Files"] = str(zi.get("total_files", ""))
        for section, kv in self._mdm_parser.dsregcmd.sections.items():
            for k, v in kv.items():
                info[f"[{section}] {k}"] = v
        for i, (k, v) in enumerate(info.items()):
            self._tree_device.insert(
                "", "end", values=(k, v),
                tags=("even" if i % 2 == 0 else "odd",))



    def _populate_wu(self):
        """Fill the Windows Update tab with registry data and ETL scan button state."""
        wp = self._wu_parser

        self._txt_wu_registry.configure(state="normal")
        self._txt_wu_registry.delete("1.0", "end")

        if wp.has_registry():
            if wp.parsed_registry and wp.orchestrator.info:
                lines = ["  Windows Update Orchestrator -- Registry State\n",
                         "  " + "-" * 56 + "\n"]
                for label, value in wp.orchestrator.info.items():
                    lines.append(f"  {label:<44} {value}\n")
                issues = wp.get_registry_issues()
                if issues:
                    lines.append("\n  " + "-" * 56 + "\n")
                    lines.append("  ISSUES DETECTED:\n")
                    for iss in issues:
                        pfx = "  [!]" if iss["severity"] == "ERROR" else "  [~]"
                        lines.append(f"{pfx} {iss['title']}\n")
                        lines.append(f"       {iss['detail']}\n")
                        if iss.get("recommendation"):
                            lines.append(f"       => {iss['recommendation']}\n")
                self._txt_wu_registry.insert("end", "".join(lines))
            else:
                self._txt_wu_registry.insert(
                    "end",
                    "  Registry file found but could not be parsed.\n"
                    f"  Path: {wp.registry_file}\n")
        else:
            self._txt_wu_registry.insert(
                "end",
                "  No Windows Update Orchestrator registry key found in this ZIP.\n\n"
                "  Expected file: (N) RegistryKey HKLM_SOFTWARE_Microsoft_Windows_"
                "CurrentVersion_WindowsUpdate_Orchestrator export.reg\n")
        self._txt_wu_registry.configure(state="disabled")

        # WU Group Policy
        self._txt_wu_policies.configure(state="normal")
        self._txt_wu_policies.delete("1.0", "end")
        policy_lines = wp.policies.get_summary_lines()
        self._txt_wu_policies.insert("end", "\n".join(policy_lines))
        self._txt_wu_policies.configure(state="disabled")

        # ReportingEvents.log results (parsed during analysis, no button needed)
        if wp.parsed_reporting and wp.reporting.events:
            rep = wp.reporting
            self._lbl_wu_etl.configure(
                text=rep.last_status)
            self._tree_clear(self._tree_wu)
            for i, ev in enumerate(rep.events):
                self._tree_wu.insert(
                    "", "end",
                    values=(ev.level, ev.timestamp, "", ev.source,
                            ev.message, ev.error_code, ev.etl_file),
                    tags=(ev.level, "even" if i % 2 == 0 else "odd"))

        # ETL button state
        if wp.has_etl_files():
            n = len(wp.etl_files)
            self._btn_wu_etl.configure(state="normal")
            suffix = f"  ({rep.last_status})" if wp.parsed_reporting else ""
            self._lbl_wu_etl.configure(
                text=f"{n} ETL file(s) — Click to scan (Get-WinEvent/tracerpt){suffix}")
        else:
            self._btn_wu_etl.configure(state="disabled")
            if not wp.parsed_reporting:
                self._lbl_wu_etl.configure(
                    text="No ETL files found  ((82) FoldersFiles windir_Logs_WindowsUpdate_etl)")

        # CAB button state
        ep = self._extra_parser
        if ep.cab_files:
            n = len(ep.cab_files)
            names = ", ".join(os.path.basename(f) for f in ep.cab_files[:2])
            if n > 2:
                names += f" +{n - 2} more"
            self._btn_cab.configure(state="normal")
            self._lbl_cab.configure(
                text=f"{n} CAB file(s): {names}  --  Click to extract via expand.exe")
        else:
            self._btn_cab.configure(state="disabled")
            self._lbl_cab.configure(
                text="No CAB file found in this ZIP  ((74) FoldersFiles temp_MDMDiagnostics_..._cab)")

    def _run_wu_etl_scan(self):
        """Triggered by the Scan ETL files button -- runs in a background thread."""
        if self._wu_etl_thread and self._wu_etl_thread.is_alive():
            return
        self._btn_wu_etl.configure(state="disabled")
        self._lbl_wu_etl.configure(text="Probing ETL decoder (Get-WinEvent / tracerpt)...")
        self._bg_scan_start("Scanning Windows Update ETL files",
                            "Probing ETL decoder...")

        def _check_and_run():
            etl = self._wu_parser.etl
            # Try PowerShell first; if unavailable, fall back to tracerpt
            ps_ok = etl.is_powershell_available()
            tp_ok = etl.is_tracerpt_available()
            if not ps_ok and not tp_ok:
                self.after(0, lambda: self._lbl_wu_etl.configure(
                    text="No ETL decoder available (need PowerShell or tracerpt.exe)."))
                self.after(0, lambda: self._btn_wu_etl.configure(state="normal"))
                self.after(0, self._bg_scan_end)
                return
            etl_files = self._wu_parser.etl_files

            def _progress(current, total_, fname):
                self.after(0, lambda c=current, t=total_, n=fname: (
                    self._lbl_wu_etl.configure(text=f"Decoding ETL {c}/{t}: {n}..."),
                    self._overlay_set_step(f"ETL {c}/{t}: {n}")))

            etl.scan_etl_files(etl_files, progress_cb=_progress)
            self.after(0, self._populate_wu_etl_results)

        self._wu_etl_thread = threading.Thread(target=_check_and_run, daemon=True)
        self._wu_etl_thread.start()

    def _populate_wu_etl_results(self):
        """Called on the main thread after ETL scan completes.
        Merges ReportingEvents rows (already parsed) with ETL rows."""
        self._bg_scan_end()
        wp  = self._wu_parser
        etl = wp.etl
        self._lbl_wu_etl.configure(text=etl.last_status)
        self._btn_wu_etl.configure(state="normal")
        self._tree_clear(self._tree_wu)
        i = 0
        # Keep ReportingEvents rows on top (parsed before ETL scan)
        if wp.parsed_reporting and wp.reporting.events:
            for ev in wp.reporting.events:
                self._tree_wu.insert(
                    "", "end",
                    values=(ev.level, ev.timestamp, "",
                            ev.source, ev.message,
                            ev.error_code, ev.etl_file),
                    tags=(ev.level, "even" if i % 2 == 0 else "odd"))
                i += 1
        # Append ETL events below
        for ev in etl.events:
            self._tree_wu.insert(
                "", "end",
                values=(ev.level, ev.timestamp, ev.event_id,
                        ev.source[:40], ev.message[:120],
                        ev.error_code, ev.etl_file),
                tags=(ev.level, "even" if i % 2 == 0 else "odd"))
            i += 1

    def _run_cab_extract(self):
        """Triggered automatically after analysis, or manually via the button."""
        if self._cab_thread and self._cab_thread.is_alive():
            return
        self._btn_cab.configure(state="disabled")
        self._lbl_cab.configure(text="Extracting CAB...")
        self._bg_scan_start("Extracting CAB file", "expand.exe...")

        def _do_extract():
            ep = self._extra_parser
            if not ep.cab.is_expand_available():
                self.after(0, lambda: self._lbl_cab.configure(
                    text="expand.exe not found. This tool must run on Windows."))
                self.after(0, lambda: self._btn_cab.configure(state="normal"))
                self.after(0, self._bg_scan_end)
                return

            def _progress(msg):
                self.after(0, lambda m=msg: (
                    self._lbl_cab.configure(text=m),
                    self._overlay_set_step(m)))

            for cab_path in ep.cab_files:
                ep.cab.extract(cab_path, progress_cb=_progress)

            # After extraction, look for MDMDiagHTMLReport.html and parse it
            html_file = next(
                (f for f in ep.cab.extracted_files
                 if os.path.basename(f).lower() == "mdmdiaghtmlreport.html"),
                None)
            if html_file:
                self.after(0, lambda hf=html_file: self._lbl_cab.configure(
                    text="Parsing MDMDiagHTMLReport.html..."))
                self._mdm_diag_parser = MDMDiagParser()
                self._mdm_diag_parser.parse(html_file)

            self.after(0, self._on_cab_extract_done)

        self._cab_thread = threading.Thread(target=_do_extract, daemon=True)
        self._cab_thread.start()

    def _on_cab_extract_done(self):
        """Called on main thread after CAB extraction (and optional MDM parse) complete."""
        self._bg_scan_end()
        ep = self._extra_parser
        self._lbl_cab.configure(text=ep.cab.last_status)
        self._btn_cab.configure(state="normal")

        # Build/rebuild the MDM Diag inner notebook
        self._build_mdm_diag_inner_nb()

        # Refresh Summary banner — OS Build is now available from MDM Diag HTML
        self._update_kpis()

        # Surface MDM Diag issues in the summary
        if self._mdm_diag_parser.parsed:
            errors, warnings = self._mdm_diag_parser.issue_count
            if errors + warnings > 0:
                self._set_status(
                    f"CAB extracted  --  MDM Diag: {errors} error(s), {warnings} warning(s) detected")
            else:
                self._set_status("CAB extracted and parsed  --  No issues found in MDM Diag report")

    def _populate_files(self):
        self._tree_clear(self._tree_files)
        inventory   = self._zip_handler.file_inventory
        extract_dir = self._zip_handler.extract_dir or ""
        i = 0
        for cat, files in inventory.items():
            if cat in ("all_files", "ime_themes"):
                continue
            for fp in files:
                try:
                    size = os.path.getsize(fp)
                    size_str = (f"{size/1024:.1f} KB"
                                if size < 1_048_576
                                else f"{size/1_048_576:.1f} MB")
                except OSError:
                    size_str = "?"
                rel = os.path.relpath(fp, extract_dir) if extract_dir else fp
                self._tree_files.insert(
                    "", "end",
                    values=(os.path.basename(fp), cat, size_str, rel),
                    tags=("even" if i % 2 == 0 else "odd",))
                i += 1

    # =========================================================================
    # EXPORT
    # =========================================================================

    def _export_report(self):
        if not self._analysis_done:
            messagebox.showinfo("No analysis", "Run an analysis first.")
            return
        default_name = (
            os.path.splitext(os.path.basename(self._zip_path))[0]
            + "_report.html")
        out_path = filedialog.asksaveasfilename(
            title="Save HTML Report",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile=default_name)
        if not out_path:
            return
        try:
            # Build device identity dict (mirrors Analysis Overview)
            ep   = self._extra_parser
            dev  = self._mdm_parser.device_info
            name = dev.get("Device Name", "")
            if not name:
                hdr  = self._mdm_parser.dsregcmd.sections.get("Header", {})
                name = hdr.get("DeviceName", hdr.get("Device Name", ""))
            if not name:
                name = ep.ipconfig.hostname
            os_  = getattr(self, "_device_os", "")
            if not os_:
                wu_info = self._wu_parser.orchestrator.info
                os_ = wu_info.get("OS Version", "") or wu_info.get("OS Build", "")
            if not os_:
                os_ = ep.msinfo32.display_version
            if not os_:
                os_ = self._mdm_diag_parser.device_info.get("OS Build", "")
            mdm_diag = self._mdm_diag_parser
            device_summary = {
                "Computer Name":    name or "Unknown",
                "IP Address":       getattr(self, "_device_ip", "") or "Not found",
                "OS Version":       os_ or "Unknown",
                "Proxy":            ep.proxy.summary or "Unknown",
                "Last User":        ep.logonui.display_name or ep.logonui.sam_user or "Unknown",
                "IME Version":      ep.ime_reg.agent_version or "Unknown",
                "PC Name (MDM)":    mdm_diag.device_info.get("PC name", ""),
                "Organisation":     mdm_diag.device_info.get("Organization", ""),
                "Edition":          mdm_diag.device_info.get("Edition", ""),
                "Processor":        mdm_diag.device_info.get("Processor", ""),
                "RAM":              mdm_diag.device_info.get("Installed RAM", ""),
                "Managed by":       mdm_diag.connection_info.get("Managed by", ""),
                "Last sync":        mdm_diag.connection_info.get("Last sync", ""),
                "MDM Server":       mdm_diag.connection_info.get("Management server address", ""),
                "Managed policies": mdm_diag.connection_info.get("Managed policies", ""),
            }
            self._report_gen.generate(
                zip_info          = self._zip_info,
                device_info       = self._mdm_parser.device_info,
                enrollment_info   = self._mdm_parser.enrollment_info,
                error_summary     = self._error_summary,
                error_events      = self._error_detector.events,
                compliance_summary= self._compliance_summary,
                policies          = self._mdm_parser.policies,
                critical_issues   = self._mdm_parser.get_all_issues(),
                wu_parser         = self._wu_parser,
                device_parser     = self._device_parser,
                hardware_parser   = self._hardware_parser,
                evtx_parsers      = self._evtx_parsers,
                device_summary    = device_summary,
                output_path       = out_path)
            if messagebox.askyesno(
                    "Report exported",
                    f"Report saved:\n{out_path}\n\nOpen in browser?"):
                import webbrowser
                webbrowser.open(f"file:///{out_path.replace(os.sep, '/')}")
        except Exception as exc:
            messagebox.showerror("Export error", f"Could not export:\n{exc}")

    # =========================================================================
    # RESET
    # =========================================================================


    # =========================================================================
    # AI ANALYSIS TAB
    # =========================================================================

    def _build_tab_ai(self):
        """Build the AI Analysis tab UI (settings + output)."""
        f = self._tab_ai
        for w in f.winfo_children():
            w.destroy()

        # ── Title ─────────────────────────────────────────────────────────────
        tk.Label(f, text="\U0001f916  AI-Assisted Diagnostics",
                 bg=C_BG, fg=C_TEXT, font=("Segoe UI", 13, "bold")).pack(
            anchor="w", padx=16, pady=(14, 2))
        tk.Label(f,
                 text="Analyze parsed data with an LLM to get prioritized recommendations.",
                 bg=C_BG, fg=C_TEXT_DIM, font=("Segoe UI", 9)).pack(anchor="w", padx=16)

        # ── Settings panel ────────────────────────────────────────────────────
        cfg_frame = tk.LabelFrame(f, text=" Settings ", bg=C_BG, fg=C_TEXT_DIM,
                                   font=("Segoe UI", 9), bd=1, relief="solid")
        cfg_frame.pack(fill="x", padx=16, pady=(10, 6))

        # Row 0 – Provider
        tk.Label(cfg_frame, text="Provider:", bg=C_BG, fg=C_TEXT,
                 font=("Segoe UI", 9)).grid(row=0, column=0, sticky="w",
                                             padx=(10, 4), pady=5)
        self._ai_provider_var = tk.StringVar(value=self._ai_cfg.provider)
        provider_names = list(PROVIDERS.keys())
        self._combo_ai_provider = ttk.Combobox(
            cfg_frame, textvariable=self._ai_provider_var,
            values=provider_names, state="readonly", width=14)
        self._combo_ai_provider.grid(row=0, column=1, sticky="w", padx=(0, 12), pady=5)
        self._combo_ai_provider.bind("<<ComboboxSelected>>", self._on_ai_provider_changed)

        # Row 0 – Model
        tk.Label(cfg_frame, text="Model:", bg=C_BG, fg=C_TEXT,
                 font=("Segoe UI", 9)).grid(row=0, column=2, sticky="w", padx=(0, 4), pady=5)
        self._ai_model_var = tk.StringVar(value=self._ai_cfg.model)
        self._combo_ai_model = ttk.Combobox(
            cfg_frame, textvariable=self._ai_model_var,
            values=PROVIDERS.get(self._ai_cfg.provider, {}).get("models", []),
            state="readonly", width=28)
        self._combo_ai_model.grid(row=0, column=3, sticky="w", padx=(0, 12), pady=5)

        # Row 1 – API Key (hidden if Ollama)
        self._ai_apikey_label = tk.Label(cfg_frame, text="API Key:", bg=C_BG, fg=C_TEXT,
                                          font=("Segoe UI", 9))
        self._ai_apikey_label.grid(row=1, column=0, sticky="w", padx=(10, 4), pady=5)
        self._ai_key_var = tk.StringVar(value=self._ai_cfg.api_key)
        self._entry_ai_key = tk.Entry(
            cfg_frame, textvariable=self._ai_key_var, show="*",
            bg=C_SURFACE, fg=C_TEXT, insertbackground=C_TEXT,
            relief="flat", width=48)
        self._entry_ai_key.grid(row=1, column=1, columnspan=3, sticky="w",
                                 padx=(0, 12), pady=5)

        # Row 2 – Ollama URL (hidden if not Ollama)
        self._ai_ollama_label = tk.Label(cfg_frame, text="Ollama URL:", bg=C_BG, fg=C_TEXT,
                                          font=("Segoe UI", 9))
        self._ai_ollama_url_var = tk.StringVar(value=self._ai_cfg.ollama_url)
        self._entry_ollama_url = tk.Entry(
            cfg_frame, textvariable=self._ai_ollama_url_var,
            bg=C_SURFACE, fg=C_TEXT, insertbackground=C_TEXT,
            relief="flat", width=36)

        # Row 3 – Max tokens
        tk.Label(cfg_frame, text="Max tokens:", bg=C_BG, fg=C_TEXT,
                 font=("Segoe UI", 9)).grid(row=3, column=0, sticky="w",
                                             padx=(10, 4), pady=5)
        self._ai_tokens_var = tk.StringVar(value=str(self._ai_cfg.max_tokens))
        tk.Entry(cfg_frame, textvariable=self._ai_tokens_var,
                 bg=C_SURFACE, fg=C_TEXT, insertbackground=C_TEXT,
                 relief="flat", width=8).grid(row=3, column=1, sticky="w",
                                               padx=(0, 12), pady=5)

        # Refresh visibility for current provider
        self._refresh_ai_provider_ui()

        # ── Action row ────────────────────────────────────────────────────────
        action_row = tk.Frame(f, bg=C_BG)
        action_row.pack(fill="x", padx=16, pady=(0, 8))

        self._btn_ai_analyze = tk.Button(
            action_row, text="▶  Analyze",
            bg=C_ACCENT, fg="#ffffff", activebackground="#0056d6",
            relief="flat", padx=14, pady=5, font=("Segoe UI", 10, "bold"),
            command=self._run_ai_analysis,
            state="disabled")
        self._btn_ai_analyze.pack(side="left")

        self._btn_ai_copy = tk.Button(
            action_row, text="Copy result",
            bg=C_PANEL, fg=C_TEXT, relief="flat", padx=10, pady=5,
            font=("Segoe UI", 9),
            command=self._ai_copy_result)
        self._btn_ai_copy.pack(side="left", padx=(8, 0))

        self._btn_ai_save = tk.Button(
            action_row, text="Save .txt",
            bg=C_PANEL, fg=C_TEXT, relief="flat", padx=10, pady=5,
            font=("Segoe UI", 9),
            command=self._ai_save_result)
        self._btn_ai_save.pack(side="left", padx=(6, 0))

        self._ai_status_lbl = tk.Label(
            action_row, text="Run an analysis first.",
            bg=C_BG, fg=C_TEXT_DIM, font=("Segoe UI", 9, "italic"))
        self._ai_status_lbl.pack(side="left", padx=(14, 0))

        # ── Output area ───────────────────────────────────────────────────────
        out_frame = tk.Frame(f, bg=C_BG)
        out_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        from tkinter.scrolledtext import ScrolledText
        self._txt_ai = ScrolledText(
            out_frame,
            bg=C_PANEL, fg=C_TEXT, insertbackground=C_TEXT,
            relief="flat", wrap="word",
            font=("Consolas", 9),
            state="disabled")
        self._txt_ai.pack(fill="both", expand=True)
        self._txt_ai.tag_configure("heading", foreground=C_ACCENT,
                                    font=("Segoe UI", 10, "bold"))
        self._txt_ai.tag_configure("subheading", foreground="#4ec9b0",
                                    font=("Segoe UI", 9, "bold"))
        self._txt_ai.tag_configure("bullet",  foreground=C_TEXT)
        self._txt_ai.tag_configure("warning", foreground="#f7c948")
        self._txt_ai.tag_configure("error",   foreground=C_ERROR)

        self._ai_write(
            "Run an analysis to get AI-powered recommendations.\n"
            "All data stays local -- only parsed text is sent to the provider API.\n")

    def _refresh_ai_provider_ui(self):
        """Show/hide API key vs Ollama URL fields depending on selected provider."""
        provider = self._ai_provider_var.get()
        is_ollama = (provider == "ollama")

        if is_ollama:
            self._ai_apikey_label.grid_remove()
            self._entry_ai_key.grid_remove()
            self._ai_ollama_label.grid(row=2, column=0, sticky="w",
                                        padx=(10, 4), pady=5)
            self._entry_ollama_url.grid(row=2, column=1, columnspan=3, sticky="w",
                                         padx=(0, 12), pady=5)
        else:
            self._ai_ollama_label.grid_remove()
            self._entry_ollama_url.grid_remove()
            self._ai_apikey_label.grid(row=1, column=0, sticky="w",
                                        padx=(10, 4), pady=5)
            self._entry_ai_key.grid(row=1, column=1, columnspan=3, sticky="w",
                                     padx=(0, 12), pady=5)

    def _on_ai_provider_changed(self, _event=None):
        provider = self._ai_provider_var.get()
        models = PROVIDERS.get(provider, {}).get("models", [])
        self._combo_ai_model["values"] = models
        if models:
            self._ai_model_var.set(models[0])
        self._refresh_ai_provider_ui()

    def _populate_ai_after_analysis(self):
        """Enable the Analyze button once an analysis is done."""
        if hasattr(self, "_btn_ai_analyze"):
            self._btn_ai_analyze.configure(state="normal")
        if hasattr(self, "_ai_status_lbl"):
            self._ai_status_lbl.configure(
                text="Analysis ready. Click Analyze to run AI diagnostics.")

    def _ai_write(self, text):
        """Append text to the AI output area (safe to call from main thread)."""
        self._txt_ai.configure(state="normal")
        self._txt_ai.delete("1.0", "end")
        self._txt_ai.insert("end", text)
        self._txt_ai.configure(state="disabled")
        self._txt_ai.see("end")

    def _run_ai_analysis(self):
        """Start AI analysis in a background thread."""
        if self._ai_running:
            return
        if not self._analysis_done:
            tk.messagebox.showwarning("No data",
                "Please open and analyze a ZIP file first.")
            return

        # Save config
        provider  = self._ai_provider_var.get()
        model     = self._ai_model_var.get()
        api_key   = self._ai_key_var.get().strip()
        ollama_url = self._ai_ollama_url_var.get().strip()
        try:
            max_tokens = int(self._ai_tokens_var.get())
        except ValueError:
            max_tokens = 2048

        self._ai_cfg = AIConfig(
            provider=provider, model=model, api_key=api_key,
            ollama_url=ollama_url, max_tokens=max_tokens)
        self._ai_cfg.save()

        # Validation
        if provider != "ollama" and not api_key:
            tk.messagebox.showerror("Missing API key",
                f"Please enter an API key for {PROVIDERS[provider]['name']}.")
            return

        self._ai_running = True
        self._btn_ai_analyze.configure(state="disabled", text="Analyzing…")
        self._ai_status_lbl.configure(text="⏳ Calling AI provider…")
        self._ai_write("Sending data to the AI provider, please wait…\n")

        import threading
        threading.Thread(target=self._ai_analysis_thread, daemon=True).start()

    def _ai_analysis_thread(self):
        """Worker thread: build context, call API, display result."""
        try:
            # Collect device summary (same structure used for HTML report)
            device_info    = self._device_parser.get_device_info()
            enrollment_info = self._device_parser.get_enrollment_info()
            device_summary = {
                "computer_name":   device_info.get("ComputerName", ""),
                "os":              device_info.get("OSVersion", ""),
                "serial":          device_info.get("SerialNumber", ""),
                "last_user":       device_info.get("LastUser", ""),
                "ip":              self._device_ip,
                "ime_version":     enrollment_info.get("IMEVersion", ""),
                "aad_device_id":   enrollment_info.get("AADDeviceId", ""),
                "mdm_device_id":   enrollment_info.get("MDMDeviceId", ""),
                "enrolled_user":   enrollment_info.get("EnrolledUser", ""),
            }

            compliance_summary = self._compliance_summary

            ctx    = build_context(
                device_summary    = device_summary,
                compliance_summary = compliance_summary,
                error_detector    = self._error_detector,
                wu_parser         = self._wu_parser,
                evtx_parsers      = self._evtx_parsers,
                hardware_parser   = self._hardware_parser,
            )
            prompt = build_prompt(ctx)

            result = self._ai_analyzer.analyze(prompt, self._ai_cfg)

            # Update UI from main thread
            self.after(0, lambda r=result: self._ai_show_result(r))

        except Exception as exc:
            import traceback
            err = traceback.format_exc()
            self.after(0, lambda e=err: self._ai_show_error(e))

    def _ai_show_result(self, result: str):
        self._ai_running = False
        self._btn_ai_analyze.configure(state="normal", text="▶  Analyze")
        self._ai_status_lbl.configure(
            text="Analysis complete. Use Copy or Save to keep the result.")
        self._ai_write(result)

    def _ai_show_error(self, error: str):
        self._ai_running = False
        self._btn_ai_analyze.configure(state="normal", text="▶  Analyze")
        self._ai_status_lbl.configure(text="Error during AI analysis.")
        self._ai_write(f"Error calling AI provider:\n\n{error}")

    def _ai_copy_result(self):
        content = self._txt_ai.get("1.0", "end").strip()
        if content:
            self.clipboard_clear()
            self.clipboard_append(content)
            self._ai_status_lbl.configure(text="Copied to clipboard.")

    def _ai_save_result(self):
        from tkinter.filedialog import asksaveasfilename
        content = self._txt_ai.get("1.0", "end").strip()
        if not content:
            return
        path = asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            title="Save AI analysis result")
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            self._ai_status_lbl.configure(text=f"Saved: {path}")

    def _clear_all(self):
        self._zip_path      = ""
        self._analysis_done = False
        self._lbl_file.configure(text="No file loaded", fg=C_TEXT_DIM)
        self._btn_analyse.configure(state="normal")
        self._btn_export.configure(state="disabled")
        self._set_status("Reset  --  Open a new Intune Device Diagnostics ZIP")

        for tree in (self._tree_device, self._tree_wu, self._tree_files,
                     self._tree_sum_devinfo, self._tree_sum_conninfo):
            self._tree_clear(tree)
        self._txt_wu_registry.configure(state="normal")
        self._txt_wu_registry.delete("1.0", "end")
        self._txt_wu_registry.configure(state="disabled")
        self._txt_wu_policies.configure(state="normal")
        self._txt_wu_policies.delete("1.0", "end")
        self._txt_wu_policies.configure(state="disabled")
        self._btn_wu_etl.configure(state="disabled")
        self._lbl_wu_etl.configure(
            text="ETL scan not started  (uses Get-WinEvent or tracerpt on up to 50 ETL files)")
        self._btn_cab.configure(state="disabled")
        self._lbl_cab.configure(
            text="No CAB file found in this ZIP")

        # Reset MDM Diag inner notebook
        if self._mdm_inner_nb is not None:
            self._mdm_inner_nb.destroy()
            self._mdm_inner_nb = None
        if self._mdm_diag_placeholder.winfo_exists():
            self._mdm_diag_placeholder.pack(padx=16, pady=20)
        self._mdm_diag_parser = MDMDiagParser()

        if self._ime_inner_nb is not None:
            self._ime_inner_nb.destroy()
            self._ime_inner_nb = None
            self._ime_theme_widgets = {}
        self._ime_placeholder.pack(padx=16, pady=20)

        # Reset Apps & Drivers tab
        if self._appdrv_inner_nb is not None:
            self._appdrv_inner_nb.destroy()
            self._appdrv_inner_nb = None
        if self._appdrv_placeholder.winfo_exists():
            self._appdrv_placeholder.pack(padx=16, pady=20)
        self._device_parser = DeviceParser()

        # Reset Event Log tab
        if self._evtx_inner_nb is not None:
            self._evtx_inner_nb.destroy()
            self._evtx_inner_nb = None
        self._evtx_parsers = {}
        self._evtx_widgets = {}
        if self._evtx_placeholder.winfo_exists():
            self._evtx_placeholder.configure(
                text="Run an analysis to populate the Event Log tabs.")
            self._evtx_placeholder.pack(padx=16, pady=20)

        # Reset Hardware & Security tab
        if self._hw_inner_nb is not None:
            self._hw_inner_nb.destroy()
            self._hw_inner_nb = None
        if self._hw_placeholder and self._hw_placeholder.winfo_exists():
            self._hw_placeholder.pack(padx=16, pady=20)
        self._hardware_parser = HardwareParser()

        # Reset Office C2R Logs tab
        for widget in self._c2r_content_frame.winfo_children():
            widget.destroy()
        self._c2r_inner_built = False
        if self._c2r_placeholder and self._c2r_placeholder.winfo_exists():
            self._c2r_placeholder.pack(padx=16, pady=20)

        self._txt_summary.configure(state="normal")
        self._txt_summary.delete("1.0", "end")
        self._txt_summary.insert(
            "end", "Open an Intune Device Diagnostics ZIP and click Analyze.\n")
        self._txt_summary.configure(state="disabled")

        for lbl in (self._kpi_errors, self._kpi_warnings, self._kpi_files):
            lbl.configure(text="---", fg=C_TEXT_DIM)
        for lbl in (self._lbl_dev_name, self._lbl_dev_ip, self._lbl_dev_os,
                    self._lbl_dev_proxy, self._lbl_dev_user, self._lbl_dev_ime_ver):
            lbl.configure(text="---", fg=C_TEXT_DIM)
        self._device_ip = ""
        self._device_os = ""

        # Reset AI Analysis tab
        self._ai_running = False
        if self._tab_ai:
            for w in self._tab_ai.winfo_children():
                w.destroy()
            self._build_tab_ai()


if __name__ == "__main__":
    app = SmartLogAnalyzerApp()
    app.mainloop()
