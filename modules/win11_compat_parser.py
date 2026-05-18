r"""
Windows 11 upgrade compatibility indicator parser.

Reads registry exports from:
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\
TargetVersionUpgradeExperienceIndicators

This mirrors the Intune remediation detection logic used by
SmartM365-W11-Upgrade-Compatibility-Indicators-Detection.ps1.
"""

import os
import re
from dataclasses import dataclass
from typing import Dict, List


ROOT_KEY = (
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    r"\AppCompatFlags\TargetVersionUpgradeExperienceIndicators"
)

NON_BLOCKING_PLACEHOLDER_VALUES = {
    "none",
    "n/a",
    "notapplicable",
    "not applicable",
}


@dataclass
class Win11CompatibilityIndicator:
    target_version: str
    up_ex: str = ""
    gated_block_id: str = ""
    red_reason: str = ""
    sys_req_issue: str = ""
    source_file: str = ""

    @property
    def is_blocking(self) -> bool:
        return is_blocking_indicator(self)

    @property
    def reason_text(self) -> str:
        return indicator_reason_text(self)


def safe_indicator_value(value, maximum_length=100) -> str:
    """Return a compact, non-placeholder registry indicator value."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(v).strip() for v in value if str(v).strip())
    text = str(value).strip().strip('"').strip()
    if not text:
        return ""
    if text.lower() in NON_BLOCKING_PLACEHOLDER_VALUES:
        return ""
    if maximum_length and len(text) > maximum_length:
        return text[: max(0, maximum_length - 3)] + "..."
    return text


def is_blocking_indicator(indicator) -> bool:
    up_ex = safe_indicator_value(getattr(indicator, "up_ex", ""))
    if re.search(r"(^|,\s*)(Red|Blocked|Hold)(\s*,|$)", up_ex, re.IGNORECASE):
        return True
    for attr in ("gated_block_id", "red_reason", "sys_req_issue"):
        if safe_indicator_value(getattr(indicator, attr, "")):
            return True
    return False


def indicator_reason_text(indicator) -> str:
    parts = []
    pairs = (
        ("UpEx", "up_ex"),
        ("GatedBlockId", "gated_block_id"),
        ("RedReason", "red_reason"),
        ("SysReqIssue", "sys_req_issue"),
    )
    for label, attr in pairs:
        value = safe_indicator_value(getattr(indicator, attr, ""))
        if value:
            parts.append(f"{label}={value}")
    return "; ".join(parts) if parts else "No blocking indicator fields"


class Win11CompatibilityIndicatorsParser:
    """Parse TargetVersionUpgradeExperienceIndicators registry exports."""

    def __init__(self):
        self.source_file = ""
        self.indicators: List[Win11CompatibilityIndicator] = []
        self.read_errors: List[str] = []
        self.status = "NoIndicatorsPath"

    @property
    def blocking_indicators(self):
        return [i for i in self.indicators if i.is_blocking]

    def parse(self, reg_file: str) -> bool:
        self.source_file = reg_file or ""
        self.indicators = []
        self.read_errors = []
        self.status = "NoIndicatorsPath"

        if not reg_file or not os.path.isfile(reg_file):
            return False

        content = self._read_text(reg_file)
        if not content:
            self.read_errors.append(reg_file)
            self.status = "ReadError"
            return False

        keys = self._parse_reg_content(content)
        root_lower = ROOT_KEY.lower()
        for key, values in keys.items():
            key_lower = key.lower()
            if key_lower == root_lower:
                continue
            if not key_lower.startswith(root_lower + "\\"):
                continue
            rel = key[len(ROOT_KEY):].strip("\\")
            if not rel:
                continue
            target_version = rel.split("\\", 1)[0] or "(unknown)"
            self.indicators.append(Win11CompatibilityIndicator(
                target_version=target_version,
                up_ex=safe_indicator_value(values.get("UpEx")),
                gated_block_id=safe_indicator_value(values.get("GatedBlockId")),
                red_reason=safe_indicator_value(values.get("RedReason")),
                sys_req_issue=safe_indicator_value(values.get("SysReqIssue")),
                source_file=reg_file,
            ))

        blocking = self.blocking_indicators
        if blocking:
            self.status = "BlockingConditionDetected"
        elif self.read_errors and self.indicators:
            self.status = "PartialReadNoBlockingCondition"
        elif self.indicators:
            self.status = "NoBlockingConditionDetected"
        elif self.read_errors:
            self.status = "ReadError"
        else:
            self.status = "NoIndicators"
        return True

    def to_search_rows(self):
        rows = []
        for indicator in self.indicators:
            severity = "ERROR" if indicator.is_blocking else "INFO"
            rows.append((
                "Win11 upgrade",
                severity,
                f"TargetVersion {indicator.target_version}",
                indicator.reason_text,
                os.path.basename(indicator.source_file) or "Registry",
            ))
        return rows

    @staticmethod
    def _read_text(path: str) -> str:
        for enc in ("utf-16", "utf-8-sig", "utf-8", "cp1252", "latin-1"):
            try:
                with open(path, "r", encoding=enc, errors="replace") as fh:
                    text = fh.read()
                if text:
                    return text
            except Exception:
                continue
        return ""

    @staticmethod
    def _parse_reg_content(content: str) -> Dict[str, Dict[str, str]]:
        keys: Dict[str, Dict[str, str]] = {}
        current = None
        pending = ""

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(";"):
                continue
            if pending:
                line = pending + line
                pending = ""
            if line.endswith("\\"):
                pending = line[:-1].rstrip()
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1]
                keys.setdefault(current, {})
                continue
            if current and "=" in line:
                name, _, raw_value = line.partition("=")
                key_name = name.strip().strip('"')
                keys[current][key_name] = _decode_reg_value(raw_value.strip())

        return keys


def _decode_reg_value(raw_value: str) -> str:
    if raw_value.startswith('"') and raw_value.endswith('"'):
        value = raw_value[1:-1]
        return value.replace(r"\\", "\\").replace(r"\"", '"')
    if raw_value.lower().startswith("dword:"):
        try:
            return str(int(raw_value.split(":", 1)[1], 16))
        except Exception:
            return raw_value
    return raw_value
