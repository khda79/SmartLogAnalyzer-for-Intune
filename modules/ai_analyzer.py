"""
ai_analyzer.py
Multi-provider AI client for SmartLogAnalyzer for Intune.
Supports: Anthropic Claude, OpenAI, Ollama (local).
No external SDK — uses urllib only (works in PyInstaller EXE).
"""

import json
import os
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable

# ─────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────

CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".smartloganalyzer_ai.json")

PROVIDERS = {
    "claude": {
        "name":   "Claude (Anthropic)",
        "models": [
            "claude-haiku-4-5-20251001",
            "claude-sonnet-4-6",
            "claude-opus-4-6",
        ],
    },
    "openai": {
        "name":   "OpenAI",
        "models": [
            "gpt-4o-mini",
            "gpt-4o",
            "gpt-4-turbo",
        ],
    },
    "ollama": {
        "name":   "Ollama (local)",
        "models": [
            "llama3.2",
            "llama3.1",
            "mistral",
            "phi3",
            "gemma2",
            "qwen2.5",
        ],
    },
}

SYSTEM_PROMPT = (
    "You are an expert Microsoft Intune administrator and Windows systems engineer. "
    "You analyze Intune device diagnostic data and provide clear, actionable guidance.\n\n"
    "For each analysis, structure your response as follows:\n"
    "1. **Executive Summary** — 2-3 sentences on overall device health\n"
    "2. **Priority Issues** — Top issues ranked by severity and business impact "
    "(use 🔴 Critical / 🟠 High / 🟡 Medium)\n"
    "3. **Root Cause Analysis** — For each major issue, explain why it happened\n"
    "4. **Remediation Steps** — Specific, ordered steps with PowerShell commands "
    "where applicable\n"
    "5. **Preventive Recommendations** — How to avoid recurrence\n\n"
    "Be direct and practical. Use markdown formatting. "
    "Always mention the specific error codes and event IDs found."
)


# ─────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────

@dataclass
class AIConfig:
    provider:    str   = "claude"
    api_key:     str   = ""
    model:       str   = "claude-haiku-4-5-20251001"
    ollama_url:  str   = "http://localhost:11434"
    max_tokens:  int   = 2048
    temperature: float = 0.3

    def save(self):
        data = {
            "provider":   self.provider,
            "api_key":    self.api_key,
            "model":      self.model,
            "ollama_url": self.ollama_url,
            "max_tokens": self.max_tokens,
        }
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    @classmethod
    def load(cls) -> "AIConfig":
        cfg = cls()
        if os.path.isfile(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, encoding="utf-8") as f:
                    data = json.load(f)
                for k, v in data.items():
                    if hasattr(cfg, k):
                        setattr(cfg, k, v)
            except Exception:
                pass
        return cfg


# ─────────────────────────────────────────────────────────────────
# Context builder
# ─────────────────────────────────────────────────────────────────

def build_context(device_summary=None,
                  compliance_summary=None,
                  error_detector=None,
                  wu_parser=None,
                  evtx_parsers=None,
                  hardware_parser=None,
                  critical_issues=None) -> dict:
    """
    Assemble a structured context dict from all available parsers.
    This is passed to AIAnalyzer.build_prompt().
    """
    ctx = {}

    # Device identity
    if device_summary:
        ctx["device_summary"] = {k: v for k, v in device_summary.items()
                                 if v and v not in ("Unknown", "Not found", "---")}

    # Compliance
    if compliance_summary:
        cs = compliance_summary
        statuses = getattr(cs, "policy_statuses", [])
        nc_list = [
            {"area": ps.area, "detail": ps.details, "source": ps.source_file}
            for ps in statuses
            if ps.status in ("NON_COMPLIANT", "FAILED", "ERROR")
        ][:20]
        ctx["compliance"] = {
            "overall":    getattr(cs, "overall_status", "UNKNOWN"),
            "compliant":  getattr(cs, "compliant_count",     0),
            "nc":         getattr(cs, "non_compliant_count", 0),
            "pending":    getattr(cs, "pending_count",       0),
            "nc_policies": nc_list,
        }

    # IME errors
    if error_detector:
        events = getattr(error_detector, "events", [])
        ctx["ime_errors"] = [
            {
                "severity":   ev.severity,
                "category":   ev.category,
                "error_code": ev.error_code or "",
                "message":    ev.message,
                "source":     ev.source_file,
            }
            for ev in events
            if ev.severity in ("ERROR", "WARNING")
        ][:50]
        ctx["ime_error_count"]   = sum(1 for e in events if e.severity == "ERROR")
        ctx["ime_warning_count"] = sum(1 for e in events if e.severity == "WARNING")

    # Windows Update
    if wu_parser:
        reg = getattr(wu_parser, "registry", None)
        wu_ctx = {}
        if reg and getattr(reg, "parsed", False):
            for attr, label in [
                ("last_search_time",  "Last Search"),
                ("last_download_time","Last Download"),
                ("last_install_time", "Last Install"),
                ("result_code",       "Result Code"),
                ("reboot_required",   "Reboot Required"),
                ("wu_server",         "WU Server"),
            ]:
                v = getattr(reg, attr, "")
                if v:
                    wu_ctx[label] = v
        re_parser = getattr(wu_parser, "reporting_events", None)
        if re_parser and getattr(re_parser, "events", []):
            wu_errors = [
                {
                    "source":     ev.source,
                    "error_code": ev.error_code,
                    "message":    ev.message,
                    "timestamp":  ev.timestamp,
                }
                for ev in re_parser.events
                if ev.error_code and ev.error_code not in ("0x00000000", "")
            ][:20]
            ctx["wu_errors"] = wu_errors
            wu_ctx["Recent errors"] = str(len(wu_errors))
        if wu_ctx:
            ctx["wu"] = wu_ctx

    # EVTX event log errors
    if evtx_parsers:
        evtx_errors = []
        for log_type, parser in evtx_parsers.items():
            for ev in parser.events:
                if ev.level_num in (1, 2):  # Critical / Error
                    evtx_errors.append({
                        "level":    ev.level_str,
                        "channel":  log_type.replace("evtx_", "").replace("_", " ").title(),
                        "event_id": ev.event_id,
                        "provider": ev.provider,
                        "message":  ev.message[:300],
                        "timestamp": ev.timestamp,
                    })
        ctx["evtx_errors"] = evtx_errors[:40]
        ctx["evtx_error_count"] = len(evtx_errors)

    # Critical issues
    if critical_issues:
        ctx["critical_issues"] = [
            {
                "severity":       i.get("severity", ""),
                "category":       i.get("category", ""),
                "title":          i.get("title", ""),
                "detail":         i.get("detail", ""),
                "recommendation": i.get("recommendation", ""),
            }
            for i in critical_issues
        ]

    # Hardware / Security
    if hardware_parser:
        hw_ctx = {}
        bat = getattr(hardware_parser, "battery", None)
        if bat and getattr(bat, "parsed", False):
            hw_ctx["battery_health_pct"] = round(bat.health_pct or 0, 1)
            hw_ctx["battery_design_mwh"] = bat.design_mwh
            hw_ctx["battery_full_mwh"]   = bat.full_charge_mwh
            hw_ctx["battery_cycle_count"] = bat.cycle_count
        fw = getattr(hardware_parser, "firewall", None)
        if fw and getattr(fw, "parsed", False):
            for prof in fw.profiles:
                hw_ctx[f"firewall_{prof.name.lower()}_state"] = prof.state
                hw_ctx[f"firewall_{prof.name.lower()}_inbound"] = prof.inbound_action
        certs = getattr(hardware_parser, "certs", [])
        expiring_soon = [c.subject for c in certs if c.status in ("Expiring", "Expired")]
        if expiring_soon:
            hw_ctx["certs_expiring_or_expired"] = expiring_soon[:10]
        if hw_ctx:
            ctx["hardware"] = hw_ctx


    return ctx


# ─────────────────────────────────────────────────────────────────
# Prompt builder
# ─────────────────────────────────────────────────────────────────

def build_prompt(ctx: dict) -> str:
    parts = ["# Intune Device Diagnostic Analysis\n"]

    # Device info
    ds = ctx.get("device_summary", {})
    if ds:
        parts.append("## Device Information")
        for k, v in ds.items():
            parts.append(f"- **{k}**: {v}")
        parts.append("")

    # Compliance
    cs = ctx.get("compliance", {})
    if cs:
        parts.append("## Compliance Status")
        parts.append(f"- Overall: **{cs.get('overall', 'UNKNOWN')}**")
        parts.append(f"- Compliant policies: {cs.get('compliant', 0)}")
        parts.append(f"- Non-compliant: {cs.get('nc', 0)}")
        parts.append(f"- Pending: {cs.get('pending', 0)}")
        nc = cs.get("nc_policies", [])
        if nc:
            parts.append("\nNon-compliant policies:")
            for p in nc:
                parts.append(f"  - **[{p['area']}]** {p['detail']}")
        parts.append("")

    # Critical issues
    issues = ctx.get("critical_issues", [])
    if issues:
        parts.append("## Critical Issues Detected")
        for i in issues:
            parts.append(f"- **[{i['severity']}]** [{i['category']}] {i['title']}")
            if i.get("detail"):
                parts.append(f"  → {i['detail']}")
        parts.append("")

    # IME errors
    ime = ctx.get("ime_errors", [])
    if ime:
        total = ctx.get("ime_error_count", len(ime))
        warns = ctx.get("ime_warning_count", 0)
        parts.append(f"## IME Log Issues ({total} errors, {warns} warnings — showing top {len(ime)})")
        for e in ime:
            line = f"- [{e['severity']}] [{e['category']}] {e['message']}"
            if e.get("error_code"):
                line += f" (code: {e['error_code']})"
            parts.append(line)
        parts.append("")

    # WU
    wu = ctx.get("wu", {})
    if wu:
        parts.append("## Windows Update Status")
        for k, v in wu.items():
            parts.append(f"- **{k}**: {v}")
        wu_errors = ctx.get("wu_errors", [])
        if wu_errors:
            parts.append(f"\nRecent WU errors ({len(wu_errors)}):")
            for e in wu_errors[:15]:
                parts.append(f"  - [{e.get('source','')}] {e.get('error_code','')} — {e.get('message','')}")
        parts.append("")

    # EVTX
    evtx = ctx.get("evtx_errors", [])
    if evtx:
        total = ctx.get("evtx_error_count", len(evtx))
        parts.append(f"## Windows Event Log Errors ({total} total — showing top {len(evtx)})")
        for e in evtx[:30]:
            parts.append(
                f"- [{e.get('level','')}] "
                f"[{e.get('channel','')}] "
                f"EventID {e.get('event_id','')} "
                f"({e.get('provider','')}) — "
                f"{e.get('message','')}"
            )
        parts.append("")

    parts.append("---")
    parts.append("Please analyze this data and provide your expert assessment with prioritized issues and remediation steps.")
    # Hardware & Security
    hw = ctx.get("hardware")
    if hw:
        parts.append("## Hardware & Security")
        bat_pct = hw.get("battery_health_pct")
        if bat_pct is not None:
            status_tag = " ⚠️ LOW" if bat_pct < 50 else (" ⚠️ DEGRADED" if bat_pct < 80 else "")
            parts.append(f"Battery Health: {bat_pct}%{status_tag}")
            cycle = hw.get("battery_cycle_count")
            if cycle:
                parts.append(f"Battery Cycle Count: {cycle}")
        for profile in ("domain", "private", "public"):
            state   = hw.get(f"firewall_{profile}_state", "")
            inbound = hw.get(f"firewall_{profile}_inbound", "")
            if state:
                flag = " ⚠️ OFF" if state.upper() in ("OFF", "DISABLED") else ""
                parts.append(f"Firewall {profile.title()}: {state}{flag} | Inbound: {inbound}")
        exp = hw.get("certs_expiring_or_expired", [])
        if exp:
            parts.append("Certificates expiring/expired: " + ", ".join(exp))
        parts.append("")


    return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────
# AI Analyzer
# ─────────────────────────────────────────────────────────────────

class AIAnalyzer:

    def __init__(self):
        self.config = AIConfig.load()

    def analyze(self, prompt_or_ctx, cfg: 'AIConfig' = None) -> str:
        """Run AI analysis. Returns the response text.
        Accepts either a pre-built prompt str or a context dict.
        cfg overrides self.config when provided.
        """
        if isinstance(prompt_or_ctx, dict):
            prompt = build_prompt(prompt_or_ctx)
        else:
            prompt = prompt_or_ctx
        cfg = cfg if cfg is not None else self.config

        if not cfg.api_key and cfg.provider != "ollama":
            raise ValueError(
                f"No API key configured for {PROVIDERS[cfg.provider]['name']}.\n"
                "Please enter your API key in the AI Analysis settings."
            )

        if cfg.provider == "claude":
            return self._call_claude(prompt, cfg)
        elif cfg.provider == "openai":
            return self._call_openai(prompt, cfg)
        elif cfg.provider == "ollama":
            return self._call_ollama(prompt, cfg)
        else:
            raise ValueError(f"Unknown provider: {cfg.provider}")

    # ── Claude ───────────────────────────────────────────────────
    def _call_claude(self, prompt: str, cfg: AIConfig) -> str:
        url     = "https://api.anthropic.com/v1/messages"
        payload = {
            "model":      cfg.model,
            "max_tokens": cfg.max_tokens,
            "system":     SYSTEM_PROMPT,
            "messages":   [{"role": "user", "content": prompt}],
        }
        headers = {
            "Content-Type":    "application/json",
            "x-api-key":       cfg.api_key,
            "anthropic-version": "2023-06-01",
        }
        return self._http_post(url, payload, headers, "content[0].text")

    # ── OpenAI ───────────────────────────────────────────────────
    def _call_openai(self, prompt: str, cfg: AIConfig) -> str:
        url     = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model":       cfg.model,
            "max_tokens":  cfg.max_tokens,
            "temperature": cfg.temperature,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
        }
        headers = {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {cfg.api_key}",
        }
        return self._http_post(url, payload, headers, "choices[0].message.content")

    # ── Ollama ───────────────────────────────────────────────────
    def _call_ollama(self, prompt: str, cfg: AIConfig) -> str:
        url     = f"{cfg.ollama_url.rstrip('/')}/api/generate"
        payload = {
            "model":  cfg.model,
            "prompt": f"{SYSTEM_PROMPT}\n\n{prompt}",
            "stream": False,
            "options": {
                "num_predict": cfg.max_tokens,
                "temperature": cfg.temperature,
            },
        }
        headers = {"Content-Type": "application/json"}
        return self._http_post(url, payload, headers, "response", timeout=120)

    # ── HTTP helper ──────────────────────────────────────────────
    @staticmethod
    def _http_post(url: str, payload: dict, headers: dict,
                   result_path: str, timeout: int = 60) -> str:
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                result = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code}: {body[:400]}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Network error: {e.reason}") from e

        # Navigate the result path (e.g. "content[0].text")
        obj = result
        for part in result_path.replace("[", ".").replace("]", "").split("."):
            if part.isdigit():
                obj = obj[int(part)]
            else:
                obj = obj[part]
        return str(obj)

    # ── Token estimate ───────────────────────────────────────────
    @staticmethod
    def estimate_tokens(ctx: dict) -> int:
        """Rough token estimate (1 token ≈ 4 chars)."""
        prompt = build_prompt(ctx)
        return len(prompt) // 4
