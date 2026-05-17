"""
mdm_diag_parser.py
Parses MDMDiagHTMLReport.html extracted from the MDM Diagnostics CAB.
Sections: Device Info, Connection Info, Device Mgmt Account, Certificates,
          Config Sources, Managed Policies, LAPS, Blocked GPs, Unmanaged Policies.
"""

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
def _strip(t: str) -> str:
    """Remove HTML tags and normalise whitespace."""
    t = re.sub(r'<[^>]+>', '', t)
    t = t.replace('&quot;', '"').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
    return ' '.join(t.split())


def _read_html(file_path: str) -> str:
    for enc in ('utf-8', 'utf-16', 'cp1252', 'latin-1'):
        try:
            with open(file_path, encoding=enc, errors='replace') as f:
                txt = f.read()
            if 'MDM Diagnostic' in txt or 'Device Info' in txt:
                return txt
        except Exception:
            continue
    return ''


def _extract_sections(html: str) -> List[str]:
    return re.findall(r'<section[^>]*>(.*?)</section>', html, re.DOTALL)


def _section_rows(sec: str) -> List[List[str]]:
    """Return list of [cell0, cell1, cell2, ...] for each <tr>."""
    rows = re.findall(r'<tr[^>]*>(.*?)</tr>', sec, re.DOTALL)
    result = []
    for row in rows:
        cells = re.findall(r'<t[dh][^>]*>(.*?)</t[dh]>', row, re.DOTALL)
        cells = [_strip(c) for c in cells]
        if any(c for c in cells):
            result.append(cells)
    return result


def _section_by_title(sections: List[str], keyword: str) -> Optional[str]:
    for sec in sections:
        title_m = re.search(r'SectionTitle[^>]*>(.*?)</(?:span|div|a)', sec, re.DOTALL)
        if title_m and keyword.lower() in _strip(title_m.group(1)).lower():
            return sec
    return None


# ---------------------------------------------------------------------------
@dataclass
class MDMIssue:
    severity: str   # ERROR | WARNING | INFO
    area: str
    title: str
    detail: str
    recommendation: str = ""


# ---------------------------------------------------------------------------
class MDMDiagParser:
    """
    Parses MDMDiagHTMLReport.html from an MDM Diagnostics CAB.
    """

    def __init__(self):
        self.html_file: str = ""
        self.parsed: bool = False

        # Parsed data
        self.device_info: Dict[str, str] = {}
        self.connection_info: Dict[str, str] = {}
        self.account_info: Dict[str, str] = {}
        self.certificates: List[Tuple[str, str]] = []

        # Config sources: {source_name: [id, id, ...]}
        self.config_sources: Dict[str, List[str]] = {}

        # Managed policies: [{area, policy, value}]
        self.managed_policies: List[Dict[str, str]] = []

        # Policies by area
        self.policies_by_area: Dict[str, List[Dict[str, str]]] = {}

        # LAPS settings: {setting: value}
        self.laps: Dict[str, str] = {}

        # Blocked GPs: [{path, name}]
        self.blocked_gps: List[Dict[str, str]] = []

        # Unmanaged policy areas: {area: [policies]}
        self.unmanaged_areas: Dict[str, List[str]] = {}

        # Issues detected by analysis
        self.issues: List[MDMIssue] = []

    # ------------------------------------------------------------------
    def parse(self, html_file: str) -> bool:
        self.html_file = html_file
        html = _read_html(html_file)
        if not html:
            return False

        sections = _extract_sections(html)

        sec_device = _section_by_title(sections, 'Device Info')
        sec_conn   = _section_by_title(sections, 'Connection Info')
        sec_acct   = _section_by_title(sections, 'Device Management Account')
        sec_certs  = _section_by_title(sections, 'Certificates')
        sec_src    = _section_by_title(sections, 'Enrolled configuration')
        sec_pol    = _section_by_title(sections, 'Managed policies')
        sec_laps   = _section_by_title(sections, 'LAPS')
        sec_bgp    = _section_by_title(sections, 'Blocked Group')
        sec_unm    = _section_by_title(sections, 'Unmanaged')

        if sec_device:
            self._parse_kv(sec_device, self.device_info)
        if sec_conn:
            self._parse_kv(sec_conn, self.connection_info)
        if sec_acct:
            self._parse_kv(sec_acct, self.account_info)
        if sec_certs:
            self._parse_certs(sec_certs)
        if sec_src:
            self._parse_config_sources(sec_src)
        if sec_pol:
            self._parse_managed_policies(sec_pol)
        if sec_laps:
            self._parse_kv(sec_laps, self.laps, skip_header=True)
        if sec_bgp:
            self._parse_blocked_gps(sec_bgp)
        if sec_unm:
            self._parse_unmanaged(sec_unm)

        self._detect_issues()
        self.parsed = True
        return True

    # ------------------------------------------------------------------
    def _parse_kv(self, sec: str, target: Dict, skip_header: bool = False):
        rows = _section_rows(sec)
        for i, row in enumerate(rows):
            if skip_header and i == 0:
                continue
            if len(row) >= 2 and row[0]:
                target[row[0]] = row[1]

    def _parse_certs(self, sec: str):
        rows = _section_rows(sec)
        for row in rows[1:]:   # skip header
            if len(row) >= 2 and row[0] and row[0] != 'Issued to':
                self.certificates.append((row[0], row[1]))

    def _parse_config_sources(self, sec: str):
        rows = _section_rows(sec)
        for row in rows:
            if len(row) >= 2 and row[0] and row[0] != 'Configuration source':
                self.config_sources.setdefault(row[0], []).append(row[1])

    def _parse_managed_policies(self, sec: str):
        rows = _section_rows(sec)
        for row in rows:
            if len(row) >= 2 and row[0] and row[0] != 'Area':
                area  = row[0]
                policy = row[1] if len(row) > 1 else ''
                value  = row[2] if len(row) > 2 else ''
                entry  = {'area': area, 'policy': policy, 'value': value}
                self.managed_policies.append(entry)
                self.policies_by_area.setdefault(area, []).append(entry)

    def _parse_blocked_gps(self, sec: str):
        rows = _section_rows(sec)
        for row in rows:
            if len(row) >= 2 and row[0] and row[0] not in ('Blocked GP Entity', 'Target'):
                self.blocked_gps.append({'path': row[0], 'name': row[1]})

    def _parse_unmanaged(self, sec: str):
        rows = _section_rows(sec)
        for row in rows:
            if len(row) >= 2 and row[0] and row[0] != 'Area':
                area     = row[0]
                policies = row[1] if len(row) > 1 else ''
                # Policies string may list multiple entries in a single cell
                self.unmanaged_areas[area] = policies

    # ------------------------------------------------------------------
    def _detect_issues(self):
        issues = self.issues

        # VBS / Device Guard
        for p in self.policies_by_area.get('DeviceGuard', []):
            if p['policy'] == 'EnableVirtualizationBasedSecurity' and p['value'] == '0':
                issues.append(MDMIssue(
                    severity='WARNING',
                    area='DeviceGuard',
                    title='Virtualization Based Security (VBS) disabled',
                    detail='EnableVirtualizationBasedSecurity = 0 — Credential Guard and '
                           'Memory Integrity cannot protect against kernel attacks.',
                    recommendation='Enable VBS in Intune: Endpoint Security > Attack Surface Reduction.'))

        # MDM wins over GP
        for p in self.policies_by_area.get('ControlPolicyConflict', []):
            if p['policy'] == 'MDMWinsOverGP' and p['value'] == '0':
                issues.append(MDMIssue(
                    severity='WARNING',
                    area='ControlPolicyConflict',
                    title='Group Policy wins over MDM (MDMWinsOverGP = 0)',
                    detail='When the same setting is configured by both GPO and MDM, '
                           'GPO takes precedence. MDM policies may be silently overridden.',
                    recommendation='Set MDMWinsOverGP = 1 to ensure MDM takes priority, '
                                   'or audit conflicting GPO settings.'))

        # Device Health Monitoring disabled
        for p in self.policies_by_area.get('DeviceHealthMonitoring', []):
            if p['policy'] == 'AllowDeviceHealthMonitoring' and p['value'] == '0':
                issues.append(MDMIssue(
                    severity='INFO',
                    area='DeviceHealthMonitoring',
                    title='Device Health Monitoring disabled',
                    detail='AllowDeviceHealthMonitoring = 0 — health telemetry '
                           'uploads are not configured.',
                    recommendation='Enable via Intune Device Health Monitoring profile.'))

        # Blocked GPs
        if len(self.blocked_gps) > 0:
            # Group by GPO path prefix
            paths = set(gp['path'].split('/')[0] for gp in self.blocked_gps)
            issues.append(MDMIssue(
                severity='WARNING',
                area='GroupPolicy',
                title=f'{len(self.blocked_gps)} Group Policy setting(s) blocked by MDM',
                detail=f'Affected GPO areas: {", ".join(sorted(paths)[:5])}. '
                       f'These GPO settings conflict with MDM policy and are blocked.',
                recommendation='Review blocked GPO list. Consider migrating these settings '
                               'to Intune to avoid management conflicts.'))

        # No Intune certs
        if not self.certificates:
            issues.append(MDMIssue(
                severity='ERROR',
                area='Certificates',
                title='No Intune MDM certificates found',
                detail='The device may not be properly enrolled or certificate '
                       'has expired.',
                recommendation='Re-enroll the device or renew the MDM certificate.'))

    # ------------------------------------------------------------------
    def get_summary_lines(self) -> List[str]:
        """Return a list of text lines for the summary report."""
        lines = []
        di = self.device_info
        ci = self.connection_info

        lines.append('-' * 64)
        lines.append('MDM Diagnostics Report (MDMDiagHTMLReport.html)')
        lines.append('-' * 64)
        for k in ('PC name', 'Edition', 'OS Build', 'Processor', 'Installed RAM'):
            if k in di:
                lines.append(f'  {k:<32} {di[k]}')
        lines.append('')
        for k in ('Managed by', 'Last sync', 'Management server address'):
            if k in ci:
                lines.append(f'  {k:<32} {ci[k]}')
        lines.append('')

        n_src  = sum(len(v) for v in self.config_sources.values())
        n_pol  = len(self.managed_policies)
        n_bgp  = len(self.blocked_gps)
        n_cert = len(self.certificates)
        lines.append(f'  Config sources:     {len(self.config_sources)} types, {n_src} resources')
        lines.append(f'  Managed policies:   {n_pol}')
        lines.append(f'  Blocked GPs:        {n_bgp}')
        lines.append(f'  MDM Certificates:   {n_cert}')
        lines.append('')

        if self.issues:
            lines.append('  Issues:')
            for iss in self.issues:
                pfx = '  [!]' if iss.severity == 'ERROR' else '  [~]' if iss.severity == 'WARNING' else '  [i]'
                lines.append(f'{pfx} [{iss.area}] {iss.title}')
        return lines

    # ------------------------------------------------------------------
    @property
    def issue_count(self) -> Tuple[int, int]:
        """Return (error_count, warning_count)."""
        errors   = sum(1 for i in self.issues if i.severity == 'ERROR')
        warnings = sum(1 for i in self.issues if i.severity == 'WARNING')
        return errors, warnings
