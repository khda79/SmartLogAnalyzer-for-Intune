"""
mdm_parser.py
Parses real Intune Device Diagnostics ZIP files:
  - DSRegCmd output  -> AAD/domain join, PRT, WAM, tenant info
  - Enrollments .reg -> MDM enrollment details
  - results.xml      -> collection success/failure per item
  - netsh firewall   -> firewall profile states (EN + FR)
"""

import os
import re
import xml.etree.ElementTree as ET


HRESULT_CODES = {
    "0":           "SUCCESS",
    "-2147024893": "Succes (cle collectee)",
    "-2147024895": "ERREUR - Cle de registre introuvable (0x80070001)",
    "-2147418113": "ERREUR - Echec non specifie (0x8000ffff)",
}

ENROLLMENT_STATES = {
    "0": "Non inscrit",
    "1": "Inscrit (actif)",
    "2": "En cours d'inscription",
    "3": "Desinscription en cours",
    "4": "En attente de renouvellement",
}

ENROLLMENT_TYPES = {
    "0":  "Unknown",
    "1":  "DeviceEnrollment (MDM Device)",
    "2":  "UserEnrollment (MDM User)",
    "6":  "ExternallyManaged",
    "18": "Autopilot",
    "30": "DeployAuthority",
}


# ---------------------------------------------------------------------------
class DSRegCmdParser:
    """Parses dsregcmd /status output."""

    def __init__(self):
        self.sections        = {}
        self.raw_text        = ""
        self.critical_issues = []

    def parse(self, file_path):
        if not os.path.isfile(file_path):
            return False
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                self.raw_text = f.read()
            self._parse_sections()
            self._detect_critical_issues()
            return True
        except Exception:
            return False

    def _parse_sections(self):
        current = "Header"
        for line in self.raw_text.splitlines():
            title_m = re.match(r'\|\s*(.+?)\s*\|', line)
            if title_m and "---" not in line and "===" not in line:
                t = title_m.group(1).strip()
                if len(t) > 2:
                    current = t
                    self.sections.setdefault(current, {})
            else:
                kv = re.match(r'^\s{10,}(\S[^:]*?)\s*:\s*(.*?)\s*$', line)
                if kv and current:
                    self.sections.setdefault(current, {})[kv.group(1).strip()] = kv.group(2).strip()

    def _detect_critical_issues(self):
        self.critical_issues = []
        sso = self.sections.get("SSO State",   {})
        dev = self.sections.get("Device State", {})

        if sso.get("AzureAdPrt", "").upper() == "NO":
            attempt  = sso.get("Attempt Status", "")
            srv_err  = sso.get("Server Error Code", "")
            srv_desc = sso.get("Server Error Description", "")
            http_st  = sso.get("HTTP status", "")
            detail = "AzureAdPrt=NO"
            if attempt:  detail += f" | AttemptStatus: {attempt}"
            if srv_err:  detail += f" | ServerError: {srv_err}"
            if http_st and http_st != "0": detail += f" | HTTP: {http_st}"

            rec = ""
            if "AADSTS50034" in srv_desc:
                rec = "L'utilisateur N'EXISTE PAS dans le tenant AAD. Verifiez l'UPN et la synchronisation AAD Connect."
            elif "invalid_grant" in srv_err:
                rec = "Token invalide. Verifiez la synchro AAD Connect et les politiques de Conditional Access."
            elif attempt == "0xc0000072":
                rec = "Compte desactive ou verrouille dans l'AD local."
            elif "AADSTS50076" in srv_desc:
                rec = "MFA requis - l'utilisateur doit completer l'authentification MFA."

            self.critical_issues.append({
                "severity":       "ERROR",
                "category":       "AAD PRT",
                "title":          "Primary Refresh Token (PRT) non acquis",
                "detail":         detail,
                "recommendation": rec,
                "source":         "DSRegCmd",
            })

        wam = sso.get("WamDefaultSet", "")
        if "ERROR" in wam.upper():
            self.critical_issues.append({
                "severity":       "WARNING",
                "category":       "WAM",
                "title":          f"WAM Default Set error: {wam}",
                "detail":         f"WamDefaultSet={wam}",
                "recommendation": "Erreur WAM - peut empecher l'authentification SSO.",
                "source":         "DSRegCmd",
            })

        if dev.get("AzureAdJoined", "").upper() == "NO":
            self.critical_issues.append({
                "severity":       "ERROR",
                "category":       "AAD Join",
                "title":          "Device NON joint a Azure AD",
                "detail":         f"AzureAdJoined=NO, DomainJoined={dev.get('DomainJoined','?')}",
                "recommendation": "Le device doit etre Hybrid AAD Joined ou AAD Joined pour Intune.",
                "source":         "DSRegCmd",
            })

    def get_device_info(self):
        info   = {}
        dev    = self.sections.get("Device State",   {})
        detail = self.sections.get("Device Details", {})
        tenant = self.sections.get("Tenant Details", {})
        for k, attr in [("Device Name","Device Name"),("AAD Joined","AzureAdJoined"),
                        ("Domain Joined","DomainJoined"),("Domain Name","DomainName"),
                        ("Virtual Desktop","Virtual Desktop")]:
            if dev.get(attr): info[k] = dev[attr]
        for k, attr in [("Device ID","DeviceId"),("TPM Protected","TpmProtected"),
                        ("Device Auth Status","DeviceAuthStatus")]:
            if detail.get(attr): info[k] = detail[attr]
        for k, attr in [("Tenant Name","TenantName"),("Tenant ID","TenantId"),
                        ("MDM URL","MdmUrl")]:
            if tenant.get(attr): info[k] = tenant[attr]
        return info

    def get_sso_info(self):
        return {**self.sections.get("SSO State", {}), **self.sections.get("User State", {})}


# ---------------------------------------------------------------------------
class RegistryParser:
    """Parses Windows .reg export files."""

    def __init__(self):
        self.keys = {}

    def parse(self, file_path):
        if not os.path.isfile(file_path):
            return False
        content = ""
        for enc in ["utf-16", "utf-8", "latin-1"]:
            try:
                with open(file_path, "r", encoding=enc, errors="replace") as f:
                    content = f.read()
                break
            except Exception:
                continue
        if not content:
            return False
        current = None
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1]
                self.keys.setdefault(current, {})
            elif "=" in line and current:
                name, _, val = line.partition("=")
                self.keys[current][name.strip().strip('"')] = val.strip()
        return True


# ---------------------------------------------------------------------------
class EnrollmentParser:
    """Extracts MDM enrollments from HKLM\\Software\\Microsoft\\Enrollments .reg"""

    def __init__(self):
        self.enrollments = []

    def parse(self, reg_file):
        rp = RegistryParser()
        if not rp.parse(reg_file):
            return False
        root = "hkey_local_machine\\software\\microsoft\\enrollments"
        for key, values in rp.keys.items():
            if key.lower() == root:
                continue
            rel = key.lower()[len(root):].strip("\\") if key.lower().startswith(root) else ""
            if not rel or "\\" in rel:
                continue
            state_int = self._dword(values.get("EnrollmentState", ""))
            type_int  = self._dword(values.get("EnrollmentType",  ""))
            entry = {
                "GUID":          rel.upper(),
                "State":         ENROLLMENT_STATES.get(str(state_int), f"Unknown ({state_int})"),
                "Type":          ENROLLMENT_TYPES.get(str(type_int),  f"Unknown ({type_int})"),
                "ProviderID":    values.get("ProviderID", "").strip('"'),
                "UPN":           values.get("UPN",        "").strip('"'),
                "EnrollmentURL": values.get("EnrollmentURL", "").strip('"'),
            }
            entry = {k: v for k, v in entry.items() if v}
            self.enrollments.append(entry)
        return True

    @staticmethod
    def _dword(val):
        m = re.search(r'dword:([0-9a-fA-F]+)', val)
        if m:
            return int(m.group(1), 16)
        try:
            return int(val)
        except (ValueError, TypeError):
            return -1


# ---------------------------------------------------------------------------
class ResultsXmlParser:
    """Parses results.xml collection manifest with HRESULT codes."""

    def __init__(self):
        self.items  = []
        self.errors = []

    def parse(self, file_path):
        if not os.path.isfile(file_path):
            return False
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except ET.ParseError:
            return False
        for child in root:
            hresult = child.get("HRESULT", "0")
            name    = child.text.strip() if child.text else child.tag
            ok      = hresult in ("0", "-2147024893")
            item = {
                "type":    child.tag,
                "name":    name,
                "hresult": hresult,
                "status":  HRESULT_CODES.get(hresult, f"Code: {hresult}"),
                "ok":      ok,
            }
            self.items.append(item)
            if not ok:
                self.errors.append(item)
        return True


# ---------------------------------------------------------------------------
class FirewallParser:
    """Parses netsh advfirewall show allprofiles output (EN and FR)."""

    _FR_PROFILE = {
        "domaine": "Domain",
        "domain":  "Domain",
        "prive":   "Private",
        "prive":   "Private",
        "private": "Private",
        "public":  "Public",
    }

    def __init__(self):
        self.profiles = {}

    @staticmethod
    def _norm(line):
        """Normalize non-breaking spaces to regular spaces."""
        return line.replace(" ", " ").replace("\xa0", " ")

    def parse(self, file_path):
        if not os.path.isfile(file_path):
            return False
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return False
        current = None
        for raw_line in content.splitlines():
            line = self._norm(raw_line)
            # English: "Domain Profile Settings:"
            m_en = re.match(r'^(\w+)\s+Profile\s+Settings:', line, re.IGNORECASE)
            # French: "Parametres Profil de domaine :" or "Parametres Profil prive :"
            m_fr = re.match(
                r'^Param[e\xe8]tres\s+Profil\s+(?:de\s+)?(\w+)\s*[:\-]',
                line, re.IGNORECASE)
            if m_en:
                raw = m_en.group(1).lower()
                current = self._FR_PROFILE.get(raw, m_en.group(1).capitalize())
                self.profiles[current] = {}
            elif m_fr:
                raw = m_fr.group(1).lower()
                # normalise accented chars for dict lookup
                raw_n = raw.replace("\xe9","e").replace("\xe8","e")
                current = self._FR_PROFILE.get(raw_n, raw.capitalize())
                self.profiles[current] = {}
            elif current and line.strip():
                kv = re.match(r'^(.+?)\s{2,}(\S.*?)\s*$', line)
                if kv:
                    key = kv.group(1).strip()
                    val = kv.group(2).strip()
                    if key and len(key) < 60:
                        self.profiles[current][key] = val
        return True

    def _is_inactive(self, s):
        s = s.upper()
        return "OFF" in s or "INACTIF" in s or "DESACTIV" in s

    def get_issues(self):
        issues = []
        for profile, settings in self.profiles.items():
            state = (settings.get("State") or settings.get("\xc9tat")
                     or settings.get("Etat") or settings.get("État") or "")
            inbound = (settings.get("Inbound connections")
                       or settings.get("Strat\xe9gie de pare-feu") or "")
            if self._is_inactive(state):
                issues.append({
                    "severity":       "ERROR",
                    "category":       "Firewall",
                    "title":          f"Firewall desactive - profil {profile}",
                    "detail":         f"Profile {profile}: State={state}",
                    "recommendation": "Activez le pare-feu Windows pour ce profil.",
                })
            # Only warn when inbound is explicitly OPEN
            # "BlockInbound,AllowOutbound" is normal - do not flag it
            inbound_u = inbound.upper().replace(" ","")
            inbound_open = (
                "ALLOWINBOUND" in inbound_u
                or inbound_u == "ALLOW"
                or "AUTORISERENTRANT" in inbound_u
            )
            if inbound_open:
                issues.append({
                    "severity":       "WARNING",
                    "category":       "Firewall",
                    "title":          f"Connexions entrantes autorisees - {profile}",
                    "detail":         f"Profile {profile}: Inbound={inbound}",
                    "recommendation": "Verifiez si cette configuration est intentionnelle.",
                })
        return issues


# ---------------------------------------------------------------------------
class MDMParser:
    """Orchestrates all sub-parsers for a complete MDM diagnostic picture."""

    def __init__(self):
        self.dsregcmd    = DSRegCmdParser()
        self.enrollments = EnrollmentParser()
        self.results_xml = ResultsXmlParser()
        self.firewall    = FirewallParser()
        self.device_info     = {}
        self.enrollment_info = {}
        self.policies        = []
        self.parse_errors    = []

    # Compatibility shims
    def parse_xml(self, path):
        return self.results_xml.parse(path)

    def parse_html(self, path):
        return False

    @property
    def raw_sections(self):
        return {}

    def parse_dsregcmd(self, path):
        ok = self.dsregcmd.parse(path)
        if ok:
            self.device_info.update(self.dsregcmd.get_device_info())
        return ok

    def parse_enrollments_reg(self, path):
        ok = self.enrollments.parse(path)
        if ok and self.enrollments.enrollments:
            for e in self.enrollments.enrollments:
                if e.get("UPN"):
                    self.enrollment_info["UPN"] = e["UPN"]
                if e.get("EnrollmentURL"):
                    self.enrollment_info["Enrollment URL"] = e["EnrollmentURL"]
            self.enrollment_info["Enrollment Count"] = str(len(self.enrollments.enrollments))
        return ok

    def parse_results_xml(self, path):
        return self.results_xml.parse(path)

    def parse_firewall(self, path):
        return self.firewall.parse(path)

    def get_all_issues(self):
        return list(self.dsregcmd.critical_issues) + self.firewall.get_issues()

    def get_summary(self):
        return {
            "device_info":       self.device_info,
            "enrollment_info":   self.enrollment_info,
            "policies":          self.policies,
            "parse_errors":      self.parse_errors,
            "critical_issues":   self.get_all_issues(),
            "collection_errors": self.results_xml.errors,
        }
