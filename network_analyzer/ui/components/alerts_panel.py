"""
ui/components/alerts_panel.py — Live alerts feed with severity color coding.
"""

from __future__ import annotations

import time
from typing import List

import streamlit as st


_LEVEL_EMOJI = {"INFO": "ℹ️", "WARN": "⚠️", "CRITICAL": "🚨"}
_LEVEL_COLOR = {
    "INFO":     "#3a6a8a",
    "WARN":     "#7a5a10",
    "CRITICAL": "#8a1a1a",
}
_LEVEL_BADGE = {
    "INFO":     "#5bc8ff",
    "WARN":     "#ffd45b",
    "CRITICAL": "#ff5b5b",
}


def render_alerts_panel(alerts: List[object], max_alerts: int = 50) -> None:
    """Render the alerts panel.

    Args:
        alerts:     List of :class:`~analysis.anomaly.Alert` objects,
                    or plain dicts with keys ``level``, ``message``,
                    ``timestamp``, ``src_ip``.
        max_alerts: Maximum number of alerts to display.
    """
    if not alerts:
        st.success("✅ No anomalies detected.")
        return

    recent = alerts[-max_alerts:]
    recent_reversed = list(reversed(recent))

    for alert in recent_reversed:
        if hasattr(alert, "level"):
            level = alert.level.value if hasattr(alert.level, "value") else str(alert.level)
            message = alert.message
            ts = alert.timestamp
            src_ip = alert.src_ip
        else:
            level = alert.get("level", "INFO")
            message = alert.get("message", "")
            ts = alert.get("timestamp", 0.0)
            src_ip = alert.get("src_ip", "")

        bg = _LEVEL_COLOR.get(level, "#2a2a2a")
        badge_color = _LEVEL_BADGE.get(level, "#aaa")
        emoji = _LEVEL_EMOJI.get(level, "•")
        time_str = time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "-"

        st.markdown(
            f"""
<div style="
    background: {bg};
    border-left: 4px solid {badge_color};
    border-radius: 6px;
    padding: 10px 14px;
    margin-bottom: 8px;
    font-family: 'Inter', sans-serif;
">
    <div style="display:flex; justify-content:space-between; align-items:center;">
        <span style="color:{badge_color}; font-weight:700; font-size:13px;">
            {emoji} {level}
        </span>
        <span style="color:#888; font-size:11px;">{time_str}</span>
    </div>
    <div style="color:#e0e0e0; margin-top:4px; font-size:13px;">{message}</div>
    {f'<div style="color:#888; font-size:11px; margin-top:2px;">Source: {src_ip}</div>' if src_ip else ''}
</div>
""",
            unsafe_allow_html=True,
        )
