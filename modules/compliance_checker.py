"""
compliance_checker.py - Intune Device Diagnostics compliance analysis.
Adapted for real Intune ZIP format: DSRegCmd, registry, firewall.
"""

import re
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class PolicyStatus:
    area:        str
    status:      str
    details:     str
    source_file: str


@dataclass
class ComplianceSummary:
    overall_status:      str
    compliant_count:     int
    non_compliant_count: int
    pending_count:       int
    unknown_count:       int
    policy_statuses:     list
    raw_notes:           list


_AREA_PATTERNS = {
    "BitLocker":          r'\bBitLocker\b',
    "Windows Defender":   r'\bDefender\b|\bMpEngine\b|\bAntivirus\b|\bSENSE\b',
    "Firewall":           r'\bFirewall\b|\badvfirewall\b',
    "Windows Update":     r'\bWindows.*Update\b|\bWUfB\b|\bWindowsUpdate\b',
    "AAD / PRT":          r'\bAzureAdPrt\b|\bPRT\b|\bAzureAd\b|\bAAD\b',
    "MDM Enrollment":     r'\bEnrollment\b|\bMDM\b|\benroll\b',
    "Conditional Access": r'\bConditional.?Access\b',
    "Autopilot":          r'\bAutopilot\b|\bESP\b',
    "Certificates":       r'\bCertif\b|\bcertificate\b',
    "OS Version":         r'\bOS.*Version\b|\bBuild.*Number\b|\bOSVersion\b',
    "TPM":                r'\bTPM\b|\bTpmProtect\b',
    "Hello for Business": r'\bHello.?for.?Business\b|\bHfB\b|\bNgc\b',
    "SCHANNEL / TLS":     r'\bSCHANNEL\b|\bTLS\b|\bSSL\b',
}

_AREA_RE = {
    area: re.compile(pat, re.IGNORECASE)
    for area, pat in _AREA_PATTERNS.items()
}

_COMPLIANT_KW     = ["compliant", "success", "enforced", "enabled",
                     "protected", "yes", "passed", "active", "joined"]
_NON_COMPLIANT_KW = ["not compliant", "non-compliant", "noncompliant",
                     "failed", "error", "disabled", "no", "blocked",
                     "not enrolled", "not joined", "not protected"]
_PENDING_KW       = ["pending", "not evaluated", "grace period", "in progress"]


class ComplianceChecker:
    """Builds a compliance picture from the MDM parser results."""

    def __init__(self):
        self._statuses = []
        self._notes    = []

    # ------------------------------------------------------------------
    def analyse_from_mdm_parser(self, mdm_parser) -> ComplianceSummary:
        self._statuses = []
        self._notes    = []

        dsreg  = mdm_parser.dsregcmd
        dev    = dsreg.sections.get("Device State",   {})
        detail = dsreg.sections.get("Device Details", {})
        sso    = dsreg.sections.get("SSO State",      {})
        usr    = dsreg.sections.get("User State",     {})

        aad_joined       = dev.get("AzureAdJoined",   "NO").strip().upper()
        workplace_joined = (dev.get("WorkplaceJoined", "") or
                            usr.get("WorkplaceJoined", "")).strip().upper()
        is_byod = (aad_joined != "YES" and workplace_joined == "YES")

        if is_byod:
            # BYOD / Workplace Join device — AzureAdJoined=NO is expected
            # Evaluate based on WorkplaceJoined state and device certificate presence
            self._statuses.append(PolicyStatus(
                area="Device Join",
                status="COMPLIANT",
                details=f"WorkplaceJoined=YES (BYOD/Personal device — AzureAdJoined=NO is expected)",
                source_file="DSRegCmd",
            ))
            # WAM errors are still relevant for BYOD
            wam = (sso.get("WamDefaultSet", "") or usr.get("WamDefaultSet", ""))
            if wam and "ERROR" in wam.upper():
                self._statuses.append(PolicyStatus(
                    area="Device Join",
                    status="NON_COMPLIANT",
                    details=f"WamDefaultSet={wam} — WAM error on BYOD device",
                    source_file="DSRegCmd",
                ))
        else:
            # Corporate AAD-Joined device — full AAD/PRT checks
            self._add("AAD / PRT",
                      dev.get("AzureAdJoined", "UNKNOWN"),
                      f"AzureAdJoined={dev.get('AzureAdJoined','?')}",
                      "DSRegCmd")

            # PRT
            prt = sso.get("AzureAdPrt", "UNKNOWN").upper()
            self._statuses.append(PolicyStatus(
                area="AAD / PRT",
                status=("COMPLIANT" if prt == "YES"
                        else "NON_COMPLIANT" if prt == "NO"
                        else "UNKNOWN"),
                details=f"AzureAdPrt={prt}" + (
                    f" | Error: {sso.get('Attempt Status','')}"
                    if prt != "YES" else ""),
                source_file="DSRegCmd",
            ))

            # WAM
            wam = sso.get("WamDefaultSet", "")
            if wam:
                self._statuses.append(PolicyStatus(
                    area="AAD / PRT",
                    status="NON_COMPLIANT" if "ERROR" in wam.upper() else "COMPLIANT",
                    details=f"WamDefaultSet={wam}",
                    source_file="DSRegCmd",
                ))

            # Device auth
            auth = detail.get("DeviceAuthStatus", "")
            if auth:
                self._statuses.append(PolicyStatus(
                    area="MDM Enrollment",
                    status="COMPLIANT" if "success" in auth.lower() else "NON_COMPLIANT",
                    details=f"DeviceAuthStatus={auth}",
                    source_file="DSRegCmd",
                ))

        # TPM (relevant for both corporate and BYOD)
        tpm = detail.get("TpmProtected", "")
        if tpm:
            self._add("TPM", tpm, f"TpmProtected={tpm}", "DSRegCmd")

        # NgcSet (Hello for Business)
        ngc = sso.get("NgcSet", "")
        if ngc:
            self._add("Hello for Business", ngc, f"NgcSet={ngc}", "DSRegCmd")

        # Enrollments from registry
        enroll_obj = mdm_parser.enrollments
        if hasattr(enroll_obj, "enrollments") and enroll_obj.enrollments:
            active = sum(
                1 for e in enroll_obj.enrollments
                if "Inscrit (actif)" in e.get("State", "")
            )
            self._statuses.append(PolicyStatus(
                area="MDM Enrollment",
                status="COMPLIANT" if active > 0 else "NON_COMPLIANT",
                details=f"{active}/{len(enroll_obj.enrollments)} enrollments actifs",
                source_file="Enrollments.reg",
            ))

        # Firewall profiles
        fw = mdm_parser.firewall
        for profile, settings in fw.profiles.items():
            state = settings.get("State", "").upper()
            if "ON" in state:
                self._statuses.append(PolicyStatus(
                    area="Firewall",
                    status="COMPLIANT",
                    details=f"Profil {profile}: active",
                    source_file="netsh firewall",
                ))
            elif "OFF" in state:
                self._statuses.append(PolicyStatus(
                    area="Firewall",
                    status="NON_COMPLIANT",
                    details=f"Profil {profile}: DESACTIVE",
                    source_file="netsh firewall",
                ))

        # Collection errors from results.xml
        for err in mdm_parser.results_xml.errors:
            area = self._guess_area(err.get("name", ""))
            self._statuses.append(PolicyStatus(
                area=area,
                status="UNKNOWN",
                details=f"Collecte echouee: {err.get('name','?')} -- {err.get('status','')}",
                source_file="results.xml",
            ))

        return self._build_summary()

    # ------------------------------------------------------------------
    def analyse_from_text_files(self, file_paths) -> ComplianceSummary:
        for fp in file_paths:
            if not os.path.isfile(fp):
                continue
            if os.path.getsize(fp) > 5 * 1024 * 1024:
                continue
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue
            short = os.path.basename(fp)
            for line in content.splitlines():
                area   = self._guess_area(line)
                status = self._infer_status(line)
                if status != "UNKNOWN":
                    self._statuses.append(PolicyStatus(
                        area=area,
                        status=status,
                        details=line[:200],
                        source_file=short,
                    ))
        return self._build_summary()

    # ------------------------------------------------------------------
    def _add(self, area, raw_value, details, source):
        status = self._infer_status(raw_value)
        self._statuses.append(PolicyStatus(
            area=area, status=status,
            details=details, source_file=source))

    def _guess_area(self, text):
        for area, pattern in _AREA_RE.items():
            if pattern.search(text):
                return area
        return "MDM Enrollment"

    def _infer_status(self, text):
        tl = text.lower()
        for kw in _NON_COMPLIANT_KW:
            if kw in tl:
                return "NON_COMPLIANT"
        for kw in _COMPLIANT_KW:
            if kw in tl:
                return "COMPLIANT"
        for kw in _PENDING_KW:
            if kw in tl:
                return "PENDING"
        return "UNKNOWN"

    def _build_summary(self):
        seen  = set()
        uniq  = []
        for ps in self._statuses:
            key = (ps.area, ps.status, ps.details[:60])
            if key not in seen:
                seen.add(key)
                uniq.append(ps)
        self._statuses = uniq

        counts = {"COMPLIANT": 0, "NON_COMPLIANT": 0, "PENDING": 0, "UNKNOWN": 0}
        for ps in self._statuses:
            counts[ps.status] = counts.get(ps.status, 0) + 1

        if counts["NON_COMPLIANT"] > 0:
            overall = "NON_COMPLIANT"
        elif counts["PENDING"] > 0 and counts["COMPLIANT"] == 0:
            overall = "PENDING"
        elif counts["COMPLIANT"] > 0:
            overall = "COMPLIANT"
        else:
            overall = "UNKNOWN"

        return ComplianceSummary(
            overall_status=overall,
            compliant_count=counts["COMPLIANT"],
            non_compliant_count=counts["NON_COMPLIANT"],
            pending_count=counts["PENDING"],
            unknown_count=counts["UNKNOWN"],
            policy_statuses=self._statuses,
            raw_notes=self._notes,
        )
