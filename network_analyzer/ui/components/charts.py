"""ui/components/charts.py — Clean Plotly charts for white SaaS dashboard."""
from __future__ import annotations
import time
from typing import Dict, List, Tuple
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

_PALETTE = {
    "TCP":"#2563EB","UDP":"#059669","ICMP":"#DC2626",
    "DNS":"#7C3AED","HTTP":"#D97706","HTTPS":"#9333EA",
    "ARP":"#0891B2","OTHER":"#9CA3AF",
}

_LAYOUT = dict(
    paper_bgcolor="#FFFFFF", plot_bgcolor="#FFFFFF",
    font=dict(family="Inter, sans-serif", color="#374151"),
    margin=dict(l=8,r=8,t=36,b=8),
)

def render_protocol_pie(counts: Dict[str,int]) -> None:
    if not counts:
        st.info("No protocol data yet."); return
    labels = list(counts.keys())
    values = list(counts.values())
    colors = [_PALETTE.get(l,"#9CA3AF") for l in labels]
    total  = sum(values)
    fig = go.Figure(go.Pie(
        labels=labels, values=values, hole=0.6,
        marker=dict(colors=colors, line=dict(color="#FFFFFF",width=2)),
        textinfo="label+percent",
        textfont=dict(color="#374151",size=11),
        hovertemplate="<b>%{label}</b><br>%{value:,} packets · %{percent}<extra></extra>",
    ))
    fig.add_annotation(text=f"<b>{total:,}</b><br><span style='font-size:10px'>packets</span>",
                       x=0.5,y=0.5,showarrow=False,font=dict(color="#111827",size=14))
    fig.update_layout(**_LAYOUT,
        title=dict(text="Protocol Mix",font=dict(size=13,color="#111827"),x=0.5),
        legend=dict(font=dict(size=11),bgcolor="#FFFFFF",
                    bordercolor="#E5E7EB",borderwidth=1))
    st.plotly_chart(fig, use_container_width=True)


def render_throughput_chart(history: List[Tuple[float,float,float]]) -> None:
    if len(history) < 2:
        st.info("Collecting data…"); return
    df = pd.DataFrame(history, columns=["ts","pps","bps"])
    df["time"] = df["ts"].apply(lambda t: time.strftime("%H:%M:%S",time.localtime(t)))
    df["kbs"]  = df["bps"] / 1024

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df["time"], y=df["pps"], name="Packets/s", mode="lines",
        line=dict(color="#2563EB",width=2),
        fill="tozeroy", fillcolor="rgba(37,99,235,0.06)",
        hovertemplate="%{y:.1f} pkt/s<extra>Packets/s</extra>",
    ))
    fig.add_trace(go.Scatter(
        x=df["time"], y=df["kbs"], name="KB/s", mode="lines",
        line=dict(color="#059669",width=2,dash="dot"), yaxis="y2",
        hovertemplate="%{y:.1f} KB/s<extra>Throughput</extra>",
    ))
    fig.update_layout(**_LAYOUT,
        title=dict(text="Live Network Throughput",font=dict(size=13,color="#111827"),x=0.5),
        xaxis=dict(showgrid=False,color="#9CA3AF",tickfont=dict(size=10),tickangle=-30),
        yaxis=dict(title="Packets/s",showgrid=True,gridcolor="#F3F4F6",
                   color="#2563EB",tickfont=dict(color="#2563EB",size=10),zeroline=False),
        yaxis2=dict(title="KB/s",overlaying="y",side="right",
                    color="#059669",tickfont=dict(color="#059669",size=10),
                    showgrid=False,zeroline=False),
        legend=dict(font=dict(size=11),bgcolor="#FFFFFF",
                    bordercolor="#E5E7EB",borderwidth=1),
        hovermode="x unified",
    )
    st.plotly_chart(fig, use_container_width=True)
