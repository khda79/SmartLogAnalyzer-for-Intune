"""
report_generator.py
Generates a rich, self-contained HTML report from Intune diagnostic analysis.
"""

import os
import datetime

# ─────────────────────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────────────────────

_CSS = """
:root {
  --accent:    #3aa0ff;
  --accent-dk: #1a6bb5;
  --sidebar-w: 220px;
  --bg:        #f0f4fa;
  --card-bg:   #ffffff;
  --text:      #0d1b2e;
  --text-dim:  #637083;
  --border:    #d6e0ef;
  --ok:        #3dba69;
  --warn:      #c9901a;
  --err:       #e5534b;
  --info:      #3aa0ff;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', system-ui, Arial, sans-serif;
  background: var(--bg); color: var(--text);
  display: flex; min-height: 100vh;
}

/* ── Sidebar ── */
#sidebar {
  width: var(--sidebar-w); min-width: var(--sidebar-w);
  background: #071527; color: #dfe8f4;
  position: sticky; top: 0; height: 100vh;
  overflow-y: auto; flex-shrink: 0;
  display: flex; flex-direction: column;
  border-right: 1px solid #0d2747;
}
#sidebar .brand {
  padding: 18px 16px 14px;
  background: linear-gradient(135deg, #3aa0ff 0%, #8367ff 100%);
  color: white; font-weight: 700; font-size: .95em;
  line-height: 1.3;
}
#sidebar .brand small { display:block; font-weight:400; font-size:.75em; opacity:.8; margin-top:2px; }
#sidebar nav { padding: 8px 0; flex: 1; }
#sidebar nav a {
  display: flex; align-items: center; gap: 8px;
  padding: 9px 16px; color: #93aac4;
  text-decoration: none; font-size: .84em; font-weight: 500;
  border-left: 3px solid transparent;
  transition: all .15s;
}
#sidebar nav a:hover  { color: #dfe8f4; background: rgba(58,160,255,.08); }
#sidebar nav a.active { color: white; border-left-color: var(--accent); background: rgba(58,160,255,.18); }
#sidebar nav .nav-section {
  padding: 12px 16px 4px; font-size: .7em; text-transform: uppercase;
  letter-spacing: .08em; color: #3d5270; font-weight: 600;
}

/* ── Main ── */
#main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
header.page-header {
  background: linear-gradient(135deg, #071527 0%, #0d2747 100%);
  border-bottom: 3px solid var(--accent);
  color: white;
  padding: 20px 32px; position: sticky; top: 0; z-index: 10;
}
header.page-header h1 { font-size: 1.4em; font-weight: 700; }
header.page-header p  { font-size: .85em; opacity: .85; margin-top: 3px; }
.content { padding: 28px 32px; max-width: 1180px; }

/* ── Section ── */
section { margin-bottom: 32px; scroll-margin-top: 72px; }
.section-title {
  font-size: 1.05em; font-weight: 700; color: var(--accent);
  margin-bottom: 14px; padding-bottom: 6px;
  border-bottom: 2px solid var(--border);
  display: flex; align-items: center; gap: 8px;
}

/* ── Card ── */
.card {
  background: var(--card-bg); border-radius: 10px;
  box-shadow: 0 1px 6px rgba(0,0,0,.07);
  overflow: hidden; margin-bottom: 16px;
}
.card-header {
  padding: 11px 18px; font-weight: 600; font-size: .9em;
  background: #f9fafb; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 8px;
}
.card-body { padding: 16px 18px; }

/* ── KPI grid ── */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 14px; margin-bottom: 0;
}
.kpi {
  background: var(--card-bg); border-radius: 10px;
  padding: 18px 16px; text-align: center;
  box-shadow: 0 1px 6px rgba(0,0,0,.07);
  border-top: 4px solid var(--border);
}
.kpi.ok   { border-top-color: var(--ok); }
.kpi.warn { border-top-color: var(--warn); }
.kpi.err  { border-top-color: var(--err); }
.kpi.info { border-top-color: var(--info); }
.kpi .val { font-size: 2em; font-weight: 800; line-height: 1; }
.kpi .lbl { font-size: .75em; color: var(--text-dim); margin-top: 5px; }

/* ── Tables ── */
.tbl-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: .86em; }
th {
  background: #e8f0fb; text-align: left;
  padding: 9px 13px; border-bottom: 2px solid var(--border);
  white-space: nowrap; font-weight: 600; color: var(--text-dim);
}
td {
  padding: 8px 13px; border-bottom: 1px solid #f0f0f4;
  vertical-align: top; word-break: break-word;
}
tr:hover td { background: #fafafa; }
.info-table td:first-child {
  font-weight: 600; color: #374151; width: 220px; white-space: nowrap;
}

/* ── Badges ── */
.badge {
  display: inline-block; padding: 2px 9px; border-radius: 20px;
  font-size: .75em; font-weight: 700; color: white; white-space: nowrap;
}
.badge-ok   { background: var(--ok); }
.badge-warn { background: var(--warn); }
.badge-err  { background: var(--err); }
.badge-info { background: var(--info); }
.badge-grey { background: #9ca3af; }

/* ── Health bar ── */
.health-bar-wrap { background: #e5e7eb; border-radius: 6px; overflow: hidden; height: 22px; margin: 6px 0; }
.health-bar { height: 100%; border-radius: 6px; display: flex; align-items: center; padding: 0 10px; }
.health-bar span { font-size: .8em; font-weight: 700; color: white; }

/* ── Filter box ── */
.tbl-filter {
  display: flex; align-items: center; gap: 8px; margin-bottom: 10px;
}
.tbl-filter input {
  border: 1px solid var(--border); border-radius: 6px;
  padding: 5px 10px; font-size: .85em; color: var(--text);
  outline: none; width: 280px;
}
.tbl-filter input:focus { border-color: var(--accent); }
.tbl-filter label { font-size: .8em; color: var(--text-dim); }

/* ── Alert box ── */
.alert {
  border-radius: 8px; padding: 14px 18px; margin-bottom: 12px;
  border-left: 4px solid;
}
.alert-err  { background: #fef2f2; border-color: var(--err);  color: #7f1d1d; }
.alert-warn { background: #fffbeb; border-color: var(--warn); color: #78350f; }
.alert-ok   { background: #f0fdf4; border-color: var(--ok);   color: #14532d; }
.alert-info { background: #eff6ff; border-color: var(--info); color: #1e3a5f; }

/* ── Code block ── */
pre {
  background: #071527; color: #dfe8f4; font-family: 'Consolas', monospace;
  font-size: .8em; padding: 12px 16px; border-radius: 6px;
  overflow-x: auto; white-space: pre-wrap; word-break: break-all;
  max-height: 320px; overflow-y: auto;
}

/* ── Two-column grid ── */
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } }

/* ── Footer ── */
footer { text-align: center; color: var(--text-dim); font-size: .78em; padding: 24px; }

/* ── Print ── */
@media print {
  #sidebar { display: none; }
  header.page-header { position: static; }
  .card { box-shadow: none; border: 1px solid var(--border); }
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# JS
# ─────────────────────────────────────────────────────────────────────────────

_JS = """
function filterTable(inputId, tableId) {
  var q = document.getElementById(inputId).value.toLowerCase();
  var rows = document.getElementById(tableId).querySelectorAll('tbody tr');
  rows.forEach(function(r) {
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
// Highlight active sidebar link on scroll
(function() {
  var links = document.querySelectorAll('#sidebar nav a[href^="#"]');
  var observer = new IntersectionObserver(function(entries) {
    entries.forEach(function(e) {
      if (e.isIntersecting) {
        links.forEach(function(l) { l.classList.remove('active'); });
        var a = document.querySelector('#sidebar nav a[href="#' + e.target.id + '"]');
        if (a) a.classList.add('active');
      }
    });
  }, { rootMargin: '-20% 0px -70% 0px' });
  document.querySelectorAll('section[id]').forEach(function(s) { observer.observe(s); });
})();
"""

# ─────────────────────────────────────────────────────────────────────────────
# Severity helpers
# ─────────────────────────────────────────────────────────────────────────────

def _badge(text, cls="grey"):
    return f'<span class="badge badge-{cls}">{_esc(text)}</span>'

def _sev_badge(sev):
    s = str(sev).upper()
    cls = ("err"  if s in ("ERROR","NON_COMPLIANT","FAILED","EXPIRED")
           else "warn" if s in ("WARNING","WARN","EXPIRING","PENDING")
           else "ok"   if s in ("OK","COMPLIANT","PASS","PASSED")
           else "info" if s in ("INFO","INFORMATION")
           else "grey")
    return _badge(sev, cls)

def _esc(t):
    return (str(t)
            .replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))

def _tbl(cols, headings, rows_html, tbl_id=None, filterable=False):
    id_attr = f' id="{tbl_id}"' if tbl_id else ""
    heads   = "".join(f"<th>{h}</th>" for h in headings)
    out = ""
    if filterable and tbl_id:
        inp_id = f"fi_{tbl_id}"
        out += (f'<div class="tbl-filter">'
                f'<input id="{inp_id}" placeholder="Filtrer..." '
                f'oninput="filterTable(\'{inp_id}\',\'{tbl_id}\')">'
                f'</div>')
    out += (f'<div class="tbl-wrap"><table{id_attr}>'
            f"<thead><tr>{heads}</tr></thead>"
            f"<tbody>{rows_html}</tbody></table></div>")
    return out

def _info_rows(pairs):
    rows = ""
    for k, v in pairs:
        rows += f"<tr><td>{_esc(k)}</td><td>{_esc(str(v))}</td></tr>"
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Main class
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:

    def __init__(self):
        self._sections = []
        self._nav_items = []

    # ──────────────────────────────────────────────────────────────
    def generate(self,
                 zip_info          = None,
                 device_info       = None,
                 enrollment_info   = None,
                 error_summary     = None,
                 error_events      = None,
                 compliance_summary= None,
                 policies          = None,
                 critical_issues   = None,
                 output_path       = "",
                 wu_parser         = None,
                 device_parser     = None,
                 hardware_parser   = None,
                 evtx_parsers      = None,
                 device_summary    = None,
                 health_report     = None):

        zip_info         = zip_info         or {}
        device_info      = device_info      or {}
        enrollment_info  = enrollment_info  or {}
        error_summary    = error_summary    or {}
        error_events     = error_events     or []
        policies         = policies         or []
        critical_issues  = critical_issues  or []

        self._sections  = []
        self._nav_items = []

        self._add_summary_kpis(error_summary, compliance_summary,
                               hardware_parser, device_summary or {})
        if critical_issues:
            self._add_section("s-issues", "⚠️ Critical Issues",
                              self._html_critical(critical_issues))
        self._add_section("s-device", "💻 Device & Enrollment",
                          self._html_device(device_info, enrollment_info, zip_info,
                                            device_summary or {}))
        self._add_section("s-hardware", "🔧 Hardware & Security",
                          self._html_hardware(hardware_parser))
        self._add_section("s-ime", "📋 IME Log Errors",
                          self._html_ime_errors(error_events, error_summary))
        self._add_section("s-wu", "🪟 Windows Update",
                          self._html_wu(wu_parser))
        self._add_section("s-compliance", "✅ Compliance & Policies",
                          self._html_compliance(compliance_summary, policies))
        if device_parser:
            self._add_section("s-apps",    "📦 Installed Applications",
                              self._html_apps(device_parser))
            self._add_section("s-drivers", "🔩 Pilotes",
                              self._html_drivers(device_parser))
            self._add_section("s-network", "📶 WiFi Profiles",
                              self._html_wifi(device_parser))
        if health_report and getattr(health_report, "findings", []):
            self._add_section("s-health", "🩺 Health Analysis",
                              self._html_health(health_report))
        self._add_section("s-eventlog", "🪟 Event Logs Windows",
                          self._html_evtx(evtx_parsers))

        html = self._build_html(zip_info.get("zip_name", "unknown"))
        if output_path:
            d = os.path.dirname(output_path)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)
        return output_path

    # ──────────────────────────────────────────────────────────────
    def _add_section(self, sid, title, body):
        self._nav_items.append((sid, title))
        self._sections.append(
            f'<section id="{sid}">'
            f'<div class="section-title">{title}</div>'
            f'{body}'
            f'</section>'
        )

    # ──────────────────────────────────────────────────────────────
    def _add_summary_kpis(self, es, cs, hp, device_summary):
        overall   = getattr(cs, "overall_status", "UNKNOWN") if cs else "UNKNOWN"
        errors    = es.get("error_count",   0)
        warnings  = es.get("warning_count", 0)
        compliant = getattr(cs, "compliant_count",     0) if cs else 0
        nc        = getattr(cs, "non_compliant_count", 0) if cs else 0
        pending   = getattr(cs, "pending_count",       0) if cs else 0

        def kpi(val, lbl, cls, sub=""):
            sub_html = (f'<div style="font-size:.68em;color:#6b7280;margin-top:2px">{sub}</div>'
                        if sub else "")
            return (f'<div class="kpi {cls}">'
                    f'<div class="val">{_esc(str(val))}</div>'
                    f'<div class="lbl">{lbl}</div>{sub_html}</div>')

        if "COMPLIANT" in overall and "NON" not in overall:
            comp_label = "Compliant"
            comp_cls   = "ok"
        elif nc > 0 or "NON" in overall or "FAIL" in overall:
            comp_label = f"{nc} issue(s)"
            comp_cls   = "err"
        else:
            comp_label = overall.replace("_", " ").title() or "Unknown"
            comp_cls   = "warn"
        comp_sub = (f"{compliant} OK · {nc} KO · {pending} pending"
                    if (compliant + nc + pending) else "")
        err_cls  = "err"  if errors   > 0 else "ok"
        warn_cls = "warn" if warnings > 0 else "ok"
        nc_cls   = "err"  if nc       > 0 else "ok"

        tiles = [
            kpi(comp_label, "Compliance", comp_cls, comp_sub),
            kpi(errors,                    "IME Errors",   err_cls),
            kpi(warnings,                  "Warnings",warn_cls),
            kpi(nc,                        "Policies KO", nc_cls),
            kpi(es.get("scanned_files",0), "Fichiers",      "info"),
        ]
        if hp and hp.battery.parsed and hp.battery.info.health_pct:
            pct = hp.battery.info.health_pct
            b_cls = "ok" if pct >= 80 else "warn" if pct >= 50 else "err"
            tiles.append(kpi(f"{pct}%", "Battery", b_cls))

        kpi_html = '<div class="kpi-grid">' + "".join(tiles) + "</div>"

        # ── Device identity banner ──────────────────────────────
        def di(icon, label, val, color="var(--text)"):
            if not val or str(val) in ("Unknown", "Not found", "---", ""):
                v = '<span style="color:var(--text-dim)">—</span>'
            else:
                v = f'<strong style="color:{color}">{_esc(str(val))}</strong>'
            return (
                f'<div style="display:flex;align-items:center;gap:8px;'
                f'padding:5px 0;border-bottom:1px solid var(--border)">'
                f'<span style="width:22px;text-align:center">{icon}</span>'
                f'<span style="color:var(--text-dim);font-size:.82em;'
                f'min-width:145px">{label}</span>'
                f'{v}</div>'
            )

        ds = device_summary
        col1 = (
            di("🖥️",  "Computer Name",     ds.get("Computer Name",""), "var(--accent)") +
            di("🌐",  "Adresse IP",              ds.get("IP Address",""),    "var(--accent)") +
            di("⚙️",  "Operating System", ds.get("OS Version","")) +
            di("👤",  "Dernier utilisateur",     ds.get("Last User",""),     "var(--accent)")
        )
        proxy = ds.get("Proxy","")
        proxy_color = ("var(--ok)"   if proxy and "direct" in proxy.lower()
                       else "var(--warn)" if proxy and proxy not in ("Unknown","")
                       else "var(--text-dim)")
        col2 = (
            di("🔌",  "Proxy",           proxy,                          proxy_color) +
            di("📦",  "IME Version",     ds.get("IME Version",""),       "var(--accent)") +
            di("🏢",  "Organisation",    ds.get("Organisation","") or ds.get("Managed by","")) +
            di("🔄",  "Dernier sync MDM",ds.get("Last sync",""))
        )
        mdm_srv = ds.get("MDM Server","")
        pol     = ds.get("Managed policies","")
        if mdm_srv:
            col2 += di("🖧", "Serveur MDM", mdm_srv)
        if pol:
            col2 += di("📋", "Managed Policies", pol)

        # apostrophe-safe card header
        card_hdr = "Device Identity"
        banner = (
            '<div class="card" style="margin-top:16px">'
            f'<div class="card-header">&#128187; {card_hdr}</div>'
            '<div class="card-body"><div class="two-col">'
            f'<div style="border-right:1px solid var(--border);padding-right:16px">{col1}</div>'
            f'<div style="padding-left:8px">{col2}</div>'
            '</div></div></div>'
        )

        # ── Non-compliant detail summary ────────────────────────
        nc_html = ""
        if cs and nc > 0:
            statuses = getattr(cs, "policy_statuses", [])
            bad = [ps for ps in statuses
                   if ps.status in ("NON_COMPLIANT","FAILED","ERROR")][:20]
            if bad:
                rows = "".join(
                    f"<tr><td style='font-weight:600'>{_esc(ps.area)}</td>"
                    f"<td>{_esc(ps.details)}</td>"
                    f"<td style='font-size:.78em;color:var(--text-dim)'>"
                    f"{_esc(ps.source_file)}</td></tr>"
                    for ps in bad
                )
                nc_html = (
                    '<div class="alert alert-err" style="margin-top:16px">'
                    f'<strong>{nc} politique(s) non conforme(s) :</strong>'
                    '<table style="margin-top:10px;width:100%;font-size:.84em">'
                    '<thead><tr><th>Domaine</th><th>Detail</th><th>Source</th></tr></thead>'
                    f'<tbody>{rows}</tbody></table></div>'
                )

        body = kpi_html + banner + nc_html
        self._nav_items.append(("s-summary", "&#128202; Resume"))
        self._sections.insert(0,
            '<section id="s-summary">'
            '<div class="section-title">&#128202; Resume</div>'
            + body + '</section>'
        )

    # ──────────────────────────────────────────────────────────────
    def _html_critical(self, issues):
        rows = ""
        for iss in issues:
            sev = iss.get("severity", "ERROR")
            rows += (
                "<tr>"
                f'<td>{_sev_badge(sev)}</td>'
                f'<td><strong>{_esc(iss.get("category",""))}</strong></td>'
                f'<td>{_esc(iss.get("title",""))}</td>'
                f'<td>{_esc(iss.get("detail",""))}</td>'
                f'<td style="color:var(--warn)">{_esc(iss.get("recommendation",""))}</td>'
                "</tr>"
            )
        return _tbl(
            ["sev","cat","title","detail","reco"],
            ["Severity","Category","Issue","Detail","Recommendation"],
            rows, "tbl_issues", filterable=True
        )

    # ──────────────────────────────────────────────────────────────
    def _html_device(self, device_info, enrollment_info, zip_info, device_summary=None):
        zi = zip_info
        meta_rows = _info_rows([
            ("ZIP",      zi.get("zip_name","")),
            ("Taille",   f"{zi.get('zip_size_mb','')} Mo"),
            ("Fichiers", zi.get("total_files","")),
        ])
        dev_rows = _info_rows(list(device_info.items())[:40])
        enr_rows = _info_rows(list(enrollment_info.items())[:40])

        # MDM Diag extra details
        extra_rows = ""
        if device_summary:
            extra_keys = [
                ("PC Name (MDM)", "PC Name (MDM)"),
                ("Edition",       "Edition"),
                ("Processor",     "Processor"),
                ("RAM",           "RAM"),
                ("Managed by",    "Managed by"),
                ("MDM Server",    "MDM Server"),
                ("Last sync",     "Last sync"),
                ("Managed policies", "Managed policies"),
            ]
            extra_pairs = [(lbl, device_summary[k])
                           for lbl, k in extra_keys
                           if device_summary.get(k)]
            extra_rows = _info_rows(extra_pairs)

        return (
            '<div class="two-col">'
            '<div class="card"><div class="card-header">Informations appareil (DSRegCmd)</div>'
            f'<div class="card-body"><table class="info-table"><tbody>{meta_rows}{dev_rows}</tbody></table></div></div>'
            '<div class="card"><div class="card-header">Enrollment & MDM Diagnostics</div>'
            f'<div class="card-body"><table class="info-table"><tbody>{enr_rows}{extra_rows}</tbody></table></div></div>'
            '</div>'
        )

    # ──────────────────────────────────────────────────────────────
    def _html_hardware(self, hp):
        if not hp:
            return '<p style="color:var(--text-dim)">Hardware data not available.</p>'

        out = ""

        # ── Battery ──────────────────────────────────────────────
        bat = hp.battery
        if bat.parsed:
            pct   = bat.info.health_pct
            color = ("#16a34a" if pct >= 80
                     else "#d97706" if pct >= 50 else "#dc2626")
            bar_w = int(pct)
            bar_html = (
                f'<div class="health-bar-wrap">'
                f'<div class="health-bar" style="width:{bar_w}%;background:{color}">'
                f'<span>Battery health: {pct}%</span></div></div>'
            )
            rows = _info_rows(bat.get_summary_rows())
            out += (
                '<div class="card"><div class="card-header">🔋 Battery</div>'
                f'<div class="card-body">{bar_html}'
                f'<table class="info-table" style="margin-top:10px"><tbody>{rows}</tbody></table>'
                '</div></div>'
            )
        else:
            out += ('<div class="alert alert-info">No battery-report.html '
                    'found in this ZIP.</div>')

        # ── Firewall ─────────────────────────────────────────────
        fw = hp.firewall
        if fw.parsed and fw.profiles:
            rows = ""
            for p in fw.profiles:
                state_cls = "ok" if p.state.upper() == "ON" else "err"
                rows += (
                    f"<tr><td><strong>{_esc(p.name)}</strong></td>"
                    f"<td>{_sev_badge(p.state) if p.state else '-'}</td>"
                    f"<td>{_esc(p.firewall_policy)}</td>"
                    f"<td>{_esc(p.remote_management)}</td>"
                    f"<td>{_esc(p.log_allowed)}</td>"
                    f"<td>{_esc(p.log_dropped)}</td></tr>"
                )
            out += (
                '<div class="card"><div class="card-header">🛡️ Windows Firewall</div>'
                '<div class="card-body">' +
                _tbl([], ["Profile","State","Policy","Remote Mgmt",
                          "Log Allowed","Log Blocked"], rows) +
                '</div></div>'
            )
        else:
            out += '<div class="alert alert-info">No firewall data available.</div>'

        # ── Certificates ─────────────────────────────────────────
        certs = hp.certs
        if certs.parsed and certs.certs:
            expired  = sum(1 for c in certs.certs if c.status == "Expired")
            expiring = sum(1 for c in certs.certs if c.status == "Expiring")
            if expired:
                out += (f'<div class="alert alert-err">'
                        f'<strong>{expired} certificate(s) expired</strong> detected!</div>')
            elif expiring:
                out += (f'<div class="alert alert-warn">'
                        f'{expiring} certificate(s) expiring soon.</div>')
            rows = ""
            for c in certs.certs:
                days_str = (str(c.days_to_expiry) if c.days_to_expiry is not None else "?")
                rows += (
                    f"<tr><td>{_esc(c.subject)}</td>"
                    f"<td>{_esc(c.not_after)}</td>"
                    f"<td>{_sev_badge(c.status)}</td>"
                    f"<td>{_esc(days_str)}</td>"
                    f"<td>{_esc(c.issuer)}</td>"
                    f"<td>{_esc(c.serial)}</td></tr>"
                )
            out += (
                '<div class="card"><div class="card-header">🔐 Certificates</div>'
                '<div class="card-body">' +
                _tbl([], ["Subject","Expires","Status","Days Left",
                          "Issuer","Serial"], rows, "tbl_certs", filterable=True) +
                '</div></div>'
            )
        else:
            out += '<div class="alert alert-info">No certificates (certutil) found.</div>'

        return out

    # ──────────────────────────────────────────────────────────────
    def _html_ime_errors(self, events, es):
        if not events:
            return '<div class="alert alert-ok">No IME errors detected.</div>'

        rows = ""
        for ev in events[:1000]:
            ts  = getattr(ev, "timestamp", "") or str(getattr(ev, "line_number", ""))
            rows += (
                "<tr>"
                f'<td>{_sev_badge(ev.severity)}</td>'
                f"<td>{_esc(ev.category)}</td>"
                f"<td>{_esc(ev.error_code or '')}</td>"
                f"<td>{_esc(ev.message)}</td>"
                f"<td style='font-size:.78em;color:var(--text-dim)'>{_esc(ev.source_file)}</td>"
                f"<td style='white-space:nowrap'>{_esc(ts)}</td>"
                "</tr>"
                f'<tr><td colspan="6"><pre>{_esc(ev.raw_line)}</pre></td></tr>'
            )
        tbl = _tbl([], ["Sev.","Category","Code","Message","File","Timestamp"],
                   rows, "tbl_ime", filterable=True)
        note = ""
        if len(events) > 1000:
            note = f'<p style="color:var(--text-dim);margin-top:8px">... and {len(events)-1000} additional events</p>'
        return f'<div class="card"><div class="card-body">{tbl}{note}</div></div>'

    # ──────────────────────────────────────────────────────────────
    def _html_wu(self, wu):
        if not wu:
            return '<div class="alert alert-info">No Windows Update data available.</div>'

        out = ""

        # Registry summary
        reg = getattr(wu, "registry", None)
        if reg and getattr(reg, "parsed", False):
            pairs = [
                ("Last Search",     getattr(reg, "last_search_time", "")),
                ("Last Download",   getattr(reg, "last_download_time", "")),
                ("Last Install",    getattr(reg, "last_install_time", "")),
                ("Result Code",     getattr(reg, "result_code", "")),
                ("Reboot Required", getattr(reg, "reboot_required", "")),
                ("WU Server",       getattr(reg, "wu_server", "")),
                ("WU Status",       getattr(reg, "wu_status_server", "")),
            ]
            rows = _info_rows([(k,v) for k,v in pairs if v])
            if rows:
                out += (
                    '<div class="card"><div class="card-header">Registre Windows Update</div>'
                    f'<div class="card-body"><table class="info-table"><tbody>{rows}</tbody></table></div></div>'
                )

        # ReportingEvents
        re_parser = getattr(wu, "reporting_events", None)
        if re_parser and getattr(re_parser, "events", []):
            events = re_parser.events[:500]
            rows = ""
            for ev in events:
                rows += (
                    f"<tr><td style='white-space:nowrap'>{_esc(ev.timestamp)}</td>"
                    f"<td>{_esc(ev.source)}</td>"
                    f"<td><code>{_esc(ev.error_code)}</code></td>"
                    f"<td>{_esc(ev.message)}</td></tr>"
                )
            note = f' ({len(re_parser.events)} total)' if len(re_parser.events) > 500 else f' ({len(re_parser.events)})'
            out += (
                f'<div class="card"><div class="card-header">ReportingEvents{note}</div>'
                '<div class="card-body">' +
                _tbl([], ["Timestamp","Source","Code","Message"],
                     rows, "tbl_wu_ev", filterable=True) +
                '</div></div>'
            )

        # WU Policies
        wp = getattr(wu, "policies", None)
        if wp:
            lines = wp.get_summary_lines() if hasattr(wp, "get_summary_lines") else []
            if lines:
                pre_content = _esc("\n".join(lines))
                out += (
                    '<div class="card"><div class="card-header">WU Policies (GPO / REG)</div>'
                    f'<div class="card-body"><pre>{pre_content}</pre></div></div>'
                )

        return out or '<div class="alert alert-info">No Windows Update data.</div>'

    # ──────────────────────────────────────────────────────────────
    def _html_compliance(self, cs, policies):
        out = ""
        if cs:
            statuses = getattr(cs, "policy_statuses", [])
            if statuses:
                rows = ""
                for ps in statuses[:500]:
                    rows += (
                        f"<tr><td>{_esc(ps.area)}</td>"
                        f"<td>{_sev_badge(ps.status.replace('_',' '))}</td>"
                        f"<td>{_esc(ps.details)}</td>"
                        f"<td style='font-size:.78em;color:var(--text-dim)'>{_esc(ps.source_file)}</td></tr>"
                    )
                out += (
                    '<div class="card"><div class="card-header">Compliance Results</div>'
                    '<div class="card-body">' +
                    _tbl([], ["Domain","Status","Details","Source"],
                         rows, "tbl_comp", filterable=True) +
                    '</div></div>'
                )

        if policies:
            headers = list(policies[0].keys()) if policies else []
            rows = ""
            for p in policies[:300]:
                rows += "<tr>" + "".join(
                    f"<td>{_esc(str(v))}</td>" for v in p.values()) + "</tr>"
            out += (
                f'<div class="card"><div class="card-header">Applied Policies ({len(policies)})</div>'
                '<div class="card-body">' +
                _tbl([], headers, rows, "tbl_pol", filterable=True) +
                '</div></div>'
            )

        return out or '<div class="alert alert-info">No compliance data.</div>'

    # ──────────────────────────────────────────────────────────────
    def _html_apps(self, dp):
        if not dp or not dp.apps.parsed:
            return '<div class="alert alert-info">No applications found.</div>'
        apps = dp.apps.apps
        rows = ""
        for i, a in enumerate(apps):
            rows += (
                f"<tr><td>{_esc(a.name)}</td><td>{_esc(a.version)}</td>"
                f"<td>{_esc(a.publisher)}</td><td>{_esc(a.install_date)}</td>"
                f"<td><span style='font-size:.78em;color:var(--text-dim)'>{_esc(a.arch)}</span></td></tr>"
            )
        return (
            f'<div class="card"><div class="card-header">{len(apps)} applications</div>'
            '<div class="card-body">' +
            _tbl([], ["Name","Version","Publisher","Install Date","Arch"],
                 rows, "tbl_apps", filterable=True) +
            '</div></div>'
        )

    # ──────────────────────────────────────────────────────────────
    def _html_drivers(self, dp):
        if not dp or not dp.drivers.parsed:
            return '<div class="alert alert-info">No drivers found.</div>'
        drivers = dp.drivers.drivers
        rows = ""
        for d in drivers:
            rows += (
                f"<tr><td>{_esc(d.original_name or d.published_name)}</td>"
                f"<td>{_esc(d.provider)}</td><td>{_esc(d.class_name)}</td>"
                f"<td>{_esc(d.driver_version)}</td>"
                f"<td style='font-size:.78em'>{_esc(d.signer)}</td></tr>"
            )
        return (
            f'<div class="card"><div class="card-header">{len(drivers)} pilotes</div>'
            '<div class="card-body">' +
            _tbl([], ["INF","Provider","Class","Version","Signer"],
                 rows, "tbl_drv", filterable=True) +
            '</div></div>'
        )

    # ──────────────────────────────────────────────────────────────
    def _html_wifi(self, dp):
        if not dp or not dp.wifi.parsed:
            return '<div class="alert alert-info">No WiFi profiles found.</div>'
        profiles = dp.wifi.profiles
        rows = ""
        for p in profiles:
            rows += (
                f"<tr><td>{_esc(p.ssid)}</td>"
                f"<td>{_esc(p.profile_type)}</td></tr>"
            )
        return (
            f'<div class="card"><div class="card-header">{len(profiles)} profil(s) WiFi</div>'
            '<div class="card-body">' +
            _tbl([], ["SSID","Type"], rows) +
            '</div></div>'
        )

    # ──────────────────────────────────────────────────────────────
    def _html_evtx(self, evtx_parsers):
        if not evtx_parsers:
            return '<div class="alert alert-info">No Windows Event Logs (EVTX) available in this report.</div>'

        out = ""
        total_errors   = 0
        total_warnings = 0
        total_events   = 0

        # Summary table of all logs
        sum_rows = ""
        for log_type, parser in sorted(evtx_parsers.items()):
            if not parser.events and parser.total_count == 0:
                continue
            errs  = parser.error_count + parser.critical_count
            warns = parser.warning_count
            total_errors   += errs
            total_warnings += warns
            total_events   += parser.total_count
            err_badge  = f'<span class="badge badge-err">{errs}</span>'   if errs  else '<span style="color:var(--ok)">0</span>'
            warn_badge = f'<span class="badge badge-warn">{warns}</span>' if warns else '<span style="color:var(--ok)">0</span>'
            clean_name = log_type.replace("evtx_", "").replace("_", " ").title()
            sum_rows += (
                f"<tr><td><strong>{_esc(clean_name)}</strong></td>"
                f"<td>{parser.total_count}</td>"
                f"<td>{err_badge}</td>"
                f"<td>{warn_badge}</td>"
                f"<td style='font-size:.78em;color:var(--text-dim)'>{_esc(parser.last_status)}</td></tr>"
            )

        if not sum_rows:
            return '<div class="alert alert-info">Event Logs present but no events loaded (run the EVTX scan in the interface).</div>'

        # Global alert
        if total_errors:
            out += f'<div class="alert alert-err"><strong>{total_errors}</strong> error(s)/critical event(s) detected out of {total_events} events.</div>'
        elif total_warnings:
            out += f'<div class="alert alert-warn"><strong>{total_warnings}</strong> warning(s) detected.</div>'
        else:
            out += f'<div class="alert alert-ok">No errors in Event Logs ({total_events} events analyzed).</div>'

        # Summary card
        out += (
            '<div class="card"><div class="card-header">Overview by Log Channel</div>'
            '<div class="card-body">' +
            _tbl([], ["Channel", "Total", "Errors/Crit.", "Warnings", "Status"],
                 sum_rows) +
            '</div></div>'
        )

        # Detailed events per log (errors & warnings only, max 200 per log)
        for log_type, parser in sorted(evtx_parsers.items()):
            error_events = [e for e in parser.events if e.level_num in (1, 2)]
            warn_events  = [e for e in parser.events if e.level_num == 3]
            notable = error_events + warn_events
            if not notable:
                continue
            clean_name = log_type.replace("evtx_", "").replace("_", " ").title()
            rows = ""
            for ev in notable[:200]:
                lvl_cls = ("err"  if ev.level_num in (1, 2)
                           else "warn" if ev.level_num == 3 else "info")
                rows += (
                    f"<tr>"
                    f"<td style='white-space:nowrap'>{_esc(ev.timestamp)}</td>"
                    f'<td><span class="badge badge-{lvl_cls}">{_esc(ev.level_str)}</span></td>'
                    f"<td>{_esc(ev.event_id)}</td>"
                    f"<td>{_esc(ev.provider)}</td>"
                    f"<td>{_esc(ev.message[:300])}</td>"
                    f"</tr>"
                )
            tbl_id = f"tbl_evtx_{log_type}"
            out += (
                f'<div class="card">'
                f'<div class="card-header">🪟 {_esc(clean_name)} '
                f'— {len(notable)} notable events</div>'
                '<div class="card-body">' +
                _tbl([], ["Timestamp", "Level", "Event ID", "Provider", "Message"],
                     rows, tbl_id, filterable=True) +
                '</div></div>'
            )

        return out

    # ──────────────────────────────────────────────────────────────
    def _html_health(self, hr):
        """Render HealthAnalyzer findings as HTML."""
        findings = getattr(hr, "findings", [])
        if not findings:
            return '<div class="alert alert-ok">No health issues detected.</div>'

        # Severity order for sorting
        _sev_order = {"ERROR": 0, "WARNING": 1, "WARN": 1, "INFO": 2, "OK": 3}
        findings = sorted(findings, key=lambda f: _sev_order.get(f.severity.upper(), 9))

        errors   = sum(1 for f in findings if f.severity.upper() in ("ERROR",))
        warnings = sum(1 for f in findings if f.severity.upper() in ("WARNING", "WARN"))

        # Summary banner
        if errors:
            banner = (f'<div class="alert alert-err">'
                      f'<strong>{errors} critical issue(s)</strong> and '
                      f'{warnings} warning(s) detected.</div>')
        elif warnings:
            banner = (f'<div class="alert alert-warn">'
                      f'<strong>{warnings} warning(s)</strong> detected — no critical issues.</div>')
        else:
            banner = '<div class="alert alert-ok">Device health looks good.</div>'

        # Score tile (count non-OK findings as penalty)
        total = len(findings)
        ok_count = sum(1 for f in findings if f.severity.upper() == "OK")
        score = max(0, 100 - errors * 15 - warnings * 5)
        score_cls = "ok" if score >= 80 else "warn" if score >= 50 else "err"
        score_html = (
            f'<div class="kpi-grid" style="margin-bottom:16px">'
            f'<div class="kpi {score_cls}"><div class="val">{score}</div>'
            f'<div class="lbl">Health Score</div></div>'
            f'<div class="kpi err"><div class="val">{errors}</div>'
            f'<div class="lbl">Critical</div></div>'
            f'<div class="kpi warn"><div class="val">{warnings}</div>'
            f'<div class="lbl">Warnings</div></div>'
            f'<div class="kpi ok"><div class="val">{ok_count}</div>'
            f'<div class="lbl">OK checks</div></div>'
            f'<div class="kpi info"><div class="val">{total}</div>'
            f'<div class="lbl">Total checks</div></div>'
            f'</div>'
        )

        # Group by category
        categories = {}
        for f in findings:
            categories.setdefault(f.category, []).append(f)

        cards_html = ""
        for cat, items in categories.items():
            cat_errors = sum(1 for f in items if f.severity.upper() == "ERROR")
            cat_cls = "err" if cat_errors else (
                "warn" if any(f.severity.upper() in ("WARNING", "WARN") for f in items)
                else "ok"
            )
            hdr_badge = _badge(f"{len(items)}", cat_cls)
            rows = ""
            for f in items:
                sev_cls = ("err"  if f.severity.upper() == "ERROR"
                           else "warn" if f.severity.upper() in ("WARNING", "WARN")
                           else "ok"   if f.severity.upper() == "OK"
                           else "info")
                action_cell = (
                    f'<span style="color:var(--warn);font-size:.82em">{_esc(f.action)}</span>'
                    if f.action else '<span style="color:var(--text-dim)">—</span>'
                )
                rows += (
                    f"<tr>"
                    f'<td>{_badge(f.severity, sev_cls)}</td>'
                    f'<td><strong>{_esc(f.title)}</strong>'
                    f'<div style="color:var(--text-dim);font-size:.82em;margin-top:2px">'
                    f'{_esc(f.detail)}</div></td>'
                    f'<td style="font-size:.82em;color:var(--text-dim)">'
                    f'{_esc(f.value)}</td>'
                    f'<td>{action_cell}</td>'
                    f"</tr>"
                )
            cards_html += (
                f'<div class="card">'
                f'<div class="card-header">🩺 {_esc(cat)} {hdr_badge}</div>'
                '<div class="card-body">' +
                _tbl([], ["Severity", "Finding", "Value", "Recommended Action"],
                     rows, f"tbl_health_{cat.replace(' ','_').lower()}", filterable=False) +
                '</div></div>'
            )

        return banner + score_html + cards_html

    # ──────────────────────────────────────────────────────────────
    def _build_html(self, zip_name):
        now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        body = "\n".join(self._sections)

        nav_links = ""
        for sid, title in self._nav_items:
            nav_links += f'<a href="#{sid}">{title}</a>\n'

        return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SmartLogAnalyzer — {_esc(zip_name)}</title>
<style>{_CSS}</style>
</head>
<body>

<aside id="sidebar">
  <div class="brand">WorkplaceCloudHub<small>SmartLogAnalyzer for Intune</small></div>
  <nav>
    <div class="nav-section">Navigation</div>
    {nav_links}
  </nav>
</aside>

<div id="main">
  <header class="page-header">
    <h1>Intune Device Diagnostics Report</h1>
    <p>Source: <strong>{_esc(zip_name)}</strong> &nbsp;|&nbsp; Generated on {now}</p>
  </header>
  <div class="content">
    {body}
  </div>
  <footer>SmartLogAnalyzer for Intune &nbsp;&bull;&nbsp; {now}</footer>
</div>

<script>{_JS}</script>
</body>
</html>"""

    # ──────────────────────────────────────────────────────────────
    @staticmethod
    def _esc(t):
        return _esc(t)
