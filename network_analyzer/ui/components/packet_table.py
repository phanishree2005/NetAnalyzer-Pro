"""ui/components/packet_table.py — Clean white enterprise packet table."""
from __future__ import annotations
import time
from typing import List
import pandas as pd
import streamlit as st

_PROTO_BADGE = {
    "TCP":   ("#EFF6FF","#1D4ED8"),
    "UDP":   ("#ECFDF5","#047857"),
    "ICMP":  ("#FEF2F2","#B91C1C"),
    "DNS":   ("#F5F3FF","#6D28D9"),
    "HTTP":  ("#FFFBEB","#B45309"),
    "HTTPS": ("#FDF4FF","#7E22CE"),
    "ARP":   ("#F0FDF4","#15803D"),
    "OTHER": ("#F9FAFB","#6B7280"),
}

def render_packet_table(records: List[object], max_rows: int = 200) -> None:
    if not records:
        st.markdown("""
<div style="text-align:center;padding:60px 20px;background:#FFFFFF;
border-radius:12px;border:1px solid #E5E7EB">
  <div style="font-size:48px">📭</div>
  <div style="font-size:16px;font-weight:600;color:#374151;margin-top:12px">
    No packets captured yet
  </div>
  <div style="font-size:13px;color:#9CA3AF;margin-top:6px">
    Select an interface and click Start to begin capturing
  </div>
</div>""", unsafe_allow_html=True)
        return

    recent = list(reversed(records[-max_rows:]))
    rows = [{
        "Time":     _ts(getattr(r,"timestamp",0)),
        "Protocol": getattr(r,"protocol",""),
        "Src IP":   getattr(r,"src_ip","") or "—",
        "Src Port": getattr(r,"src_port",0) or "—",
        "Dst IP":   getattr(r,"dst_ip","") or "—",
        "Dst Port": getattr(r,"dst_port",0) or "—",
        "Size":     _sz(getattr(r,"size",0)),
        "Flags":    getattr(r,"flags","") or "—",
        "TTL":      getattr(r,"ttl",0) or "—",
        "Summary":  getattr(r,"payload_summary","")[:72],
    } for r in recent]

    df = pd.DataFrame(rows)

    def _row_style(row):
        bg, fg = _PROTO_BADGE.get(row.get("Protocol","OTHER"), ("#F9FAFB","#6B7280"))
        base = f"background-color:#FFFFFF;color:#374151;font-size:12px;"
        proto_style = f"background-color:{bg};color:{fg};font-weight:600;font-size:11px;border-radius:4px;padding:1px 4px;"
        styles = []
        for col in row.index:
            if col == "Protocol":
                styles.append(proto_style)
            else:
                styles.append(base)
        return styles

    styled = df.style.apply(_row_style, axis=1)
    st.dataframe(styled, width='stretch', height=440, hide_index=True)
    st.caption(f"Showing {len(rows):,} of {len(records):,} packets · newest first")

def _ts(ts):
    if not ts: return "—"
    t = time.localtime(ts)
    ms = int((ts%1)*1000)
    return f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}.{ms:03d}"

def _sz(n):
    if n < 1024: return f"{n} B"
    if n < 1024**2: return f"{n/1024:.1f} KB"
    return f"{n/1024**2:.2f} MB"
