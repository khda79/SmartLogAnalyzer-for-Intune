"""
Shared helpers that build compact device summaries for reports and AI prompts.
Keeping this logic outside the Tkinter app reduces duplication in
SmartLogAnalyzer.py and makes the data contract easier to test.
"""


def build_report_device_summary(extra_parser, mdm_parser, wu_parser,
                                mdm_diag_parser, device_ip="", device_os=""):
    """Return the device identity dict used by the HTML report."""
    dev = getattr(mdm_parser, "device_info", {}) or {}
    dsregcmd = getattr(mdm_parser, "dsregcmd", None)
    sections = getattr(dsregcmd, "sections", {}) if dsregcmd else {}

    name = dev.get("Device Name", "")
    if not name:
        hdr = sections.get("Header", {})
        name = hdr.get("DeviceName", hdr.get("Device Name", ""))
    if not name:
        name = getattr(getattr(extra_parser, "ipconfig", None), "hostname", "")

    os_value = device_os or ""
    if not os_value:
        orchestrator = getattr(wu_parser, "orchestrator", None)
        wu_info = getattr(orchestrator, "info", {}) if orchestrator else {}
        os_value = wu_info.get("OS Version", "") or wu_info.get("OS Build", "")
    if not os_value:
        msinfo32 = getattr(extra_parser, "msinfo32", None)
        os_value = getattr(msinfo32, "display_version", "")
    if not os_value:
        mdm_device = getattr(mdm_diag_parser, "device_info", {}) or {}
        os_value = mdm_device.get("OS Build", "")

    ipconfig = getattr(extra_parser, "ipconfig", None)
    proxy = getattr(extra_parser, "proxy", None)
    logonui = getattr(extra_parser, "logonui", None)
    ime_reg = getattr(extra_parser, "ime_reg", None)
    mdm_device = getattr(mdm_diag_parser, "device_info", {}) or {}
    mdm_conn = getattr(mdm_diag_parser, "connection_info", {}) or {}

    return {
        "Computer Name": name or "Unknown",
        "IP Address": device_ip or "Not found",
        "OS Version": os_value or "Unknown",
        "Proxy": getattr(proxy, "summary", "") or "Unknown",
        "Last User": (
            getattr(logonui, "display_name", "")
            or getattr(logonui, "sam_user", "")
            or "Unknown"
        ),
        "IME Version": getattr(ime_reg, "agent_version", "") or "Unknown",
        "PC Name (MDM)": mdm_device.get("PC name", ""),
        "Organisation": mdm_device.get("Organization", ""),
        "Edition": mdm_device.get("Edition", ""),
        "Processor": mdm_device.get("Processor", ""),
        "RAM": mdm_device.get("Installed RAM", ""),
        "Managed by": mdm_conn.get("Managed by", ""),
        "Last sync": mdm_conn.get("Last sync", ""),
        "MDM Server": mdm_conn.get("Management server address", ""),
        "Managed policies": mdm_conn.get("Managed policies", ""),
    }


def build_ai_device_summary(extra_parser=None, mdm_parser=None,
                            mdm_diag_parser=None, device_ip="", device_os=""):
    """Return a compact, lowercase-key summary for the AI context builder."""
    report_summary = build_report_device_summary(
        extra_parser=extra_parser,
        mdm_parser=mdm_parser,
        wu_parser=None,
        mdm_diag_parser=mdm_diag_parser,
        device_ip=device_ip,
        device_os=device_os,
    )

    enrollment = getattr(mdm_parser, "enrollment_info", {}) if mdm_parser else {}
    dev = getattr(mdm_parser, "device_info", {}) if mdm_parser else {}

    return {
        "computer_name": report_summary.get("Computer Name", ""),
        "os": report_summary.get("OS Version", ""),
        "last_user": report_summary.get("Last User", ""),
        "ip": report_summary.get("IP Address", ""),
        "ime_version": report_summary.get("IME Version", ""),
        "aad_device_id": dev.get("Device ID", ""),
        "mdm_device_id": dev.get("Device ID", ""),
        "enrolled_user": enrollment.get("UPN", ""),
    }
