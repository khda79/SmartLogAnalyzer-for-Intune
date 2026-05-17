"""
Anonymization helpers for support-safe diagnostic ZIP exports.
The ZIP exporter keeps binary files intact and redacts common identifiers in
text-like files.
"""

import os
import re
import zipfile


TEXT_EXTENSIONS = {
    ".csv", ".html", ".json", ".log", ".md", ".reg", ".txt", ".xml",
}

_PATTERNS = [
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "<EMAIL>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<GUID>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IPV4>"),
    (re.compile(r"\b([A-Z]:\\Users\\)[^\\\r\n]+", re.I), r"\1<USER>"),
    (re.compile(r"(?i)\b(TenantId|Tenant ID|DeviceId|Device ID|SerialNumber|Serial Number)\s*[:=]\s*([^\r\n,;]+)"), r"\1=<REDACTED>"),
    (re.compile(r"(?i)\b(UPN|UserPrincipalName|Email|PrimaryUser)\s*[:=]\s*([^\r\n,;]+)"), r"\1=<REDACTED>"),
]


def anonymize_text(text: str) -> str:
    """Redact common user, tenant, device and network identifiers."""
    out = text
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def _decode_text(data: bytes):
    for enc in ("utf-8", "utf-16", "utf-16-le", "cp1252", "latin-1"):
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return None, None


def export_anonymized_zip(source_zip: str, output_zip: str) -> str:
    """Create an anonymized copy of source_zip and return output_zip."""
    if not zipfile.is_zipfile(source_zip):
        raise ValueError(f"Not a valid ZIP file: {source_zip}")

    out_dir = os.path.dirname(output_zip)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with zipfile.ZipFile(source_zip, "r") as src, zipfile.ZipFile(
        output_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
    ) as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            ext = os.path.splitext(info.filename)[1].lower()
            if ext in TEXT_EXTENSIONS:
                text, enc = _decode_text(data)
                if text is not None:
                    data = anonymize_text(text).encode(enc or "utf-8", errors="replace")
            dst.writestr(info, data)

    return output_zip
