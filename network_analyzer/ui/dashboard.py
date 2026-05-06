"""ui/dashboard.py — NetAnalyzer Pro: White SaaS enterprise dashboard."""
from __future__ import annotations
import os, sys, time, threading, queue
from typing import List, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import streamlit as st

st.set_page_config(page_title="NetAnalyzer Pro", page_icon="🔬", layout="wide",
                   initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
*, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }
html, body, .stApp { background: #F9FAFB !important; color: #111827 !important; }

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #FFFFFF !important;
    border-right: 1px solid #E5E7EB;
    box-shadow: 2px 0 8px rgba(0,0,0,0.04);
}
section[data-testid="stSidebar"] * { color: #374151 !important; }

/* Hide default header */
header[data-testid="stHeader"] { background: transparent; }

/* Cards */
.kpi-card {
    background: #FFFFFF;
    border-radius: 12px;
    padding: 20px 22px;
    border: 1px solid #E5E7EB;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    transition: box-shadow .2s;
}
.kpi-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.1); }
.kpi-value { font-size: 28px; font-weight: 700; color: #111827; line-height:1.1; }
.kpi-label { font-size: 12px; color: #6B7280; font-weight: 500;
             text-transform: uppercase; letter-spacing:.6px; margin-top:4px; }
.kpi-icon  { font-size: 20px; margin-bottom: 8px; }

/* Section header */
.sec-title {
    font-size: 14px; font-weight: 600; color: #111827;
    margin-bottom: 12px; padding-bottom: 8px;
    border-bottom: 2px solid #E5E7EB;
}

/* Status badge */
.badge-live {
    display:inline-flex;align-items:center;gap:6px;
    background:#DCFCE7;color:#15803D;border:1px solid #BBF7D0;
    border-radius:20px;padding:4px 12px;font-size:12px;font-weight:600;
}
.badge-idle {
    display:inline-flex;align-items:center;gap:6px;
    background:#FEF2F2;color:#DC2626;border:1px solid #FECACA;
    border-radius:20px;padding:4px 12px;font-size:12px;font-weight:600;
}

/* Insight cards */
.insight-card {
    background:#EFF6FF;border:1px solid #BFDBFE;border-radius:10px;
    padding:12px 16px;margin-bottom:8px;font-size:13px;color:#1E40AF;
}
.insight-warn {
    background:#FFFBEB;border:1px solid #FDE68A;
    color:#92400E;
}
.insight-danger {
    background:#FEF2F2;border:1px solid #FECACA;
    color:#991B1B;
}

/* Main container card */
.panel {
    background:#FFFFFF;border-radius:12px;
    border:1px solid #E5E7EB;
    box-shadow:0 1px 4px rgba(0,0,0,0.06);
    padding:20px;margin-bottom:16px;
}

/* Table */
[data-testid="stDataFrame"] {
    border-radius:10px;border:1px solid #E5E7EB !important;
    overflow:hidden;
}

/* Buttons */
.stButton > button {
    border-radius:8px !important; font-weight:600 !important;
    font-size:13px !important; transition:all .2s !important;
    border: 1px solid #2563EB !important;
    background:#2563EB !important; color:#fff !important;
}
.stButton > button:hover {
    background:#1D4ED8 !important;
    box-shadow:0 4px 12px rgba(37,99,235,.3) !important;
    transform:translateY(-1px);
}

/* Tabs */
button[data-baseweb="tab"] {
    background:transparent !important;
    color:#6B7280 !important;
    font-weight:500 !important;
    border-bottom:2px solid transparent !important;
}
button[data-baseweb="tab"][aria-selected="true"] {
    color:#2563EB !important;
    border-bottom:2px solid #2563EB !important;
}

/* Inputs */
.stTextInput>div>input, .stSelectbox>div {
    border-radius:8px !important;
    border:1px solid #D1D5DB !important;
    background:#FFFFFF !important;
}

/* scrollbar */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:#F9FAFB}
::-webkit-scrollbar-thumb{background:#D1D5DB;border-radius:3px}
</style>
""", unsafe_allow_html=True)

from capture.sniffer import PacketSniffer
from capture.interface import get_interfaces, get_default_interface
from processing.parser import PacketParser
from analysis.stats import StatisticsEngine
from analysis.anomaly import AnomalyDetector
from analysis.sessions import SessionTracker
from data.buffer import PacketBuffer
from data.store import DataStore
from utils.config import DEFAULT_CONFIG
from utils.logger import configure_root_logger, get_logger
from ui.filters import FilterState
from ui.components.packet_table import render_packet_table
from ui.components.charts import render_protocol_pie, render_throughput_chart

configure_root_logger()
logger = get_logger(__name__)


# ── Session state ─────────────────────────────────────────────────────────────
def _init():
    if "initialized" in st.session_state:
        return
    cfg = DEFAULT_CONFIG
    st.session_state.sniffer      = PacketSniffer(config=cfg.capture)
    st.session_state.buffer       = PacketBuffer(config=cfg.buffer)
    st.session_state.stats        = StatisticsEngine(config=cfg.stats)
    st.session_state.anomaly      = AnomalyDetector(config=cfg.anomaly)
    st.session_state.sessions     = SessionTracker()
    st.session_state.store        = DataStore(config=cfg.store, buffer=st.session_state.buffer)
    st.session_state.store.start()
    st.session_state.parser       = None
    st.session_state.cstop        = None
    st.session_state.is_running   = False
    st.session_state.filters      = FilterState()
    st.session_state.tph: List[Tuple[float,float,float]] = []
    st.session_state.initialized  = True
_init()


def _consumer(q, buf, stats, anomaly, sess, store, stop):
    while not stop.is_set():
        try:
            r = q.get(timeout=0.05)
        except queue.Empty:
            continue
        buf.append(r); stats.record_packet(r)
        anomaly.analyze(r); sess.update(r); store.ingest(r)


def _start(iface, bpf):
    ss = st.session_state
    ss.sniffer.start(interface=iface, bpf_filter=bpf)
    p = PacketParser(raw_queue=ss.sniffer.get_queue())
    p.start(); ss.parser = p
    stop = threading.Event(); ss.cstop = stop
    threading.Thread(target=_consumer,
        args=(p.get_queue(), ss.buffer, ss.stats, ss.anomaly,
              ss.sessions, ss.store, stop),
        daemon=True, name="Consumer").start()
    ss.is_running = True


def _stop():
    ss = st.session_state
    if ss.cstop: ss.cstop.set()
    if ss.parser: ss.parser.stop()
    ss.sniffer.stop(); ss.is_running = False


# ── Sidebar ───────────────────────────────────────────────────────────────────
def _sidebar():
    ss = st.session_state
    with st.sidebar:
        st.markdown("""
<div style="padding:16px 0 12px">
  <div style="font-size:20px;font-weight:700;color:#2563EB">🔬 NetAnalyzer Pro</div>
  <div style="font-size:11px;color:#9CA3AF;margin-top:2px;letter-spacing:.5px">
    REAL-TIME PROTOCOL ANALYZER
  </div>
</div>
<hr style="border-color:#E5E7EB;margin:0 0 14px"/>
""", unsafe_allow_html=True)

        if ss.is_running:
            st.markdown('<div class="badge-live">● LIVE</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="badge-idle">○ IDLE</div>', unsafe_allow_html=True)
        st.markdown("<br/>", unsafe_allow_html=True)

        st.markdown("**🖥 Capture Settings**")
        ifaces = get_interfaces()
        def_i  = get_default_interface() or (ifaces[0] if ifaces else "")
        idx    = ifaces.index(def_i) if def_i in ifaces else 0
        iface  = st.selectbox("Interface", ifaces or ["<none>"],
                              index=idx, disabled=ss.is_running, key="iface_sel")
        bpf    = st.text_input("BPF Filter", placeholder='e.g. "tcp port 443"',
                               disabled=ss.is_running, key="bpf_sel")

        c1, c2 = st.columns(2)
        with c1:
            if st.button("▶ Start", width='stretch', key="btn_start",
                         disabled=ss.is_running):
                _start(iface if iface != "<none>" else "", bpf)
                st.rerun()
        with c2:
            if st.button("■ Stop", width='stretch', key="btn_stop",
                         disabled=not ss.is_running):
                _stop(); st.rerun()
        if st.button("🗑 Clear Buffer", width='stretch', key="btn_clear"):
            ss.buffer.clear(); ss.stats.reset()
            ss.anomaly.clear_alerts(); ss.sessions.reset()
            ss.tph.clear(); st.rerun()

        st.divider()
        st.markdown("**🔍 Filters**")
        all_p  = DEFAULT_CONFIG.ui.default_protocols
        sel_p  = st.multiselect("Protocols", all_p, default=all_p, key="proto_f")
        src    = st.text_input("Source IP", placeholder="partial match", key="src_f")
        dst    = st.text_input("Dest IP",   placeholder="partial match", key="dst_f")
        port   = st.number_input("Port", 0, 65535, 0, key="port_f")
        srch   = st.text_input("Search payload", key="srch_f")
        ss.filters = FilterState(selected_protocols=sel_p, src_ip=src,
                                 dst_ip=dst, port=int(port), search_text=srch)

        st.divider()
        st.markdown("**⚙️ Settings**")
        DEFAULT_CONFIG.anomaly.packets_per_sec_spike = st.slider(
            "Spike threshold (pkt/s)", 50, 5000,
            value=DEFAULT_CONFIG.anomaly.packets_per_sec_spike, step=50)
        DEFAULT_CONFIG.ui.refresh_interval_seconds = st.slider(
            "Refresh interval (s)", 0.5, 5.0,
            value=DEFAULT_CONFIG.ui.refresh_interval_seconds, step=0.5)

        st.divider()
        st.markdown("**💾 Export**")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("CSV", width='stretch', key="btn_csv"):
                n = ss.store.export_csv("packets_export.csv", ss.filters.matches)
                st.success(f"{n} rows") if n else st.warning("Empty")
        with c2:
            if st.button("JSON", width='stretch', key="btn_json"):
                n = ss.store.export_json("packets_export.json", ss.filters.matches)
                st.success(f"{n} rows") if n else st.warning("Empty")


# ── Insights ──────────────────────────────────────────────────────────────────
def _insights(snap, alerts):
    items = []
    if snap.total_packets == 0:
        items.append(("info", "📡 Awaiting capture — press Start to begin monitoring."))
    else:
        top_proto = max(snap.protocol_counts, key=snap.protocol_counts.get) \
                    if snap.protocol_counts else None
        if top_proto:
            pct = snap.protocol_counts[top_proto] / max(snap.total_packets,1) * 100
            items.append(("info", f"📊 Dominant protocol: <b>{top_proto}</b> "
                                  f"({pct:.0f}% of traffic)"))
        if snap.packets_per_sec > DEFAULT_CONFIG.anomaly.packets_per_sec_spike * 0.8:
            items.append(("warn", f"⚡ High packet rate: <b>{snap.packets_per_sec:.0f} pkt/s</b> "
                                  f"— approaching spike threshold"))
        if snap.top_talkers:
            top_ip = next(iter(snap.top_talkers))
            items.append(("info", f"🏆 Top source: <b>{top_ip}</b> "
                                  f"({snap.top_talkers[top_ip]:,} packets)"))
        crit = [a for a in alerts if getattr(a.level, 'value', str(a.level)) == "CRITICAL"]
        if crit:
            items.append(("danger", f"🚨 <b>{len(crit)} critical alert(s)</b> — "
                                    f"{crit[-1].message[:60]}…"))
        if not items:
            items.append(("info", "✅ Network traffic looks normal."))

    cls_map = {"info": "insight-card", "warn": "insight-card insight-warn",
               "danger": "insight-card insight-danger"}
    st.markdown('<div class="sec-title">💡 Smart Insights</div>', unsafe_allow_html=True)
    for kind, msg in items[:4]:
        st.markdown(f'<div class="{cls_map[kind]}">{msg}</div>',
                    unsafe_allow_html=True)


# ── KPI row ───────────────────────────────────────────────────────────────────
def _kpi_row(snap, alerts, active):
    ss = st.session_state
    ss.tph.append((snap.timestamp, snap.packets_per_sec, snap.bytes_per_sec))
    if len(ss.tph) > 180: ss.tph = ss.tph[-180:]

    kpis = [
        ("📦", f"{snap.total_packets:,}", "Total Packets"),
        ("⚡", f"{snap.packets_per_sec:.1f}", "Packets / sec"),
        ("📡", f"{snap.bytes_per_sec/1024:.1f} KB/s", "Throughput"),
        ("🔗", f"{active:,}", "Active Sessions"),
        ("🚨", f"{len(alerts)}", "Alerts"),
    ]
    cols = st.columns(5)
    for col, (icon, val, label) in zip(cols, kpis):
        col.markdown(f"""
<div class="kpi-card">
  <div class="kpi-icon">{icon}</div>
  <div class="kpi-value">{val}</div>
  <div class="kpi-label">{label}</div>
</div>""", unsafe_allow_html=True)


# ── Header ────────────────────────────────────────────────────────────────────
def _header(snap):
    ss = st.session_state
    status = "🟢 LIVE" if ss.is_running else "🔴 IDLE"
    iface  = st.session_state.get("iface_sel", "—")
    ts     = time.strftime("%H:%M:%S")
    total_mb = snap.total_bytes / (1024*1024)
    st.markdown(f"""
<div style="
    background:#FFFFFF;border-radius:12px;padding:16px 24px;
    border:1px solid #E5E7EB;box-shadow:0 1px 4px rgba(0,0,0,0.06);
    display:flex;justify-content:space-between;align-items:center;
    margin-bottom:20px;
">
  <div>
    <div style="font-size:22px;font-weight:700;color:#111827">
      🔬 NetAnalyzer Pro
    </div>
    <div style="font-size:12px;color:#6B7280;margin-top:2px">
      Interface: <b style="color:#374151">{iface}</b> &nbsp;·&nbsp;
      {snap.total_packets:,} packets &nbsp;·&nbsp;
      {total_mb:.2f} MB captured
    </div>
  </div>
  <div style="text-align:right">
    <div style="font-size:14px;font-weight:600;color:#374151">{status}</div>
    <div style="font-size:11px;color:#9CA3AF;margin-top:2px">{ts}</div>
  </div>
</div>
""", unsafe_allow_html=True)


# ── Tabs ──────────────────────────────────────────────────────────────────────
def _tab_packets(filtered, snap):
    import pandas as pd
    st.markdown('<div class="sec-title">📋 Live Packet Stream</div>',
                unsafe_allow_html=True)
    render_packet_table(filtered, DEFAULT_CONFIG.ui.max_table_rows)


def _tab_analytics(snap):
    import pandas as pd
    if snap.total_packets == 0:
        st.markdown("""
<div style="text-align:center;padding:60px 0;color:#9CA3AF">
  <div style="font-size:48px">📊</div>
  <div style="font-size:16px;font-weight:600;margin-top:12px;color:#6B7280">No data yet</div>
  <div style="font-size:13px;margin-top:6px">Start capture to see analytics</div>
</div>""", unsafe_allow_html=True)
        return

    col1, col2 = st.columns([1,2])
    with col1:
        st.markdown('<div class="sec-title">🥧 Protocol Distribution</div>',
                    unsafe_allow_html=True)
        render_protocol_pie(snap.protocol_counts)
    with col2:
        st.markdown('<div class="sec-title">📈 Live Throughput</div>',
                    unsafe_allow_html=True)
        render_throughput_chart(st.session_state.tph)

    if snap.top_talkers:
        st.markdown('<div class="sec-title" style="margin-top:16px">🏆 Top Talkers</div>',
                    unsafe_allow_html=True)
        total = max(snap.total_packets, 1)
        df = pd.DataFrame([
            {"Source IP": ip, "Packets": f"{c:,}",
             "% Share": f"{c/total*100:.1f}%",
             "Bytes (est)": f"{c*500/1024:.0f} KB"}
            for ip, c in sorted(snap.top_talkers.items(), key=lambda x: -x[1])
        ])
        st.dataframe(df, width='stretch', hide_index=True)


def _tab_alerts(alerts):
    if not alerts:
        st.markdown("""
<div style="text-align:center;padding:50px 0">
  <div style="font-size:40px">✅</div>
  <div style="font-size:15px;font-weight:600;color:#15803D;margin-top:10px">
    No anomalies detected
  </div>
  <div style="font-size:13px;color:#6B7280;margin-top:4px">
    Network traffic is normal
  </div>
</div>""", unsafe_allow_html=True)
        return

    from collections import Counter
    lvl_counts = Counter(
        getattr(a.level, 'value', str(a.level)) for a in alerts)
    c1,c2,c3 = st.columns(3)
    c1.metric("🚨 Critical", lvl_counts.get("CRITICAL",0))
    c2.metric("⚠️ Warning",  lvl_counts.get("WARN",0))
    c3.metric("ℹ️ Info",     lvl_counts.get("INFO",0))
    st.markdown("<br/>", unsafe_allow_html=True)

    _bg  = {"CRITICAL":"#FEF2F2","WARN":"#FFFBEB","INFO":"#EFF6FF"}
    _bdr = {"CRITICAL":"#FECACA","WARN":"#FDE68A","INFO":"#BFDBFE"}
    _clr = {"CRITICAL":"#991B1B","WARN":"#92400E","INFO":"#1E40AF"}
    _ico = {"CRITICAL":"🚨","WARN":"⚠️","INFO":"ℹ️"}

    for a in reversed(alerts[-50:]):
        lvl = getattr(a.level,'value', str(a.level))
        ts  = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
        src = f"<span style='color:#6B7280;font-size:11px'>  src: {a.src_ip}</span>" if a.src_ip else ""
        st.markdown(f"""
<div style="background:{_bg.get(lvl,'#EFF6FF')};border:1px solid {_bdr.get(lvl,'#BFDBFE')};
border-left:4px solid {_clr.get(lvl,'#1E40AF')};border-radius:8px;
padding:12px 16px;margin-bottom:8px;">
  <div style="display:flex;justify-content:space-between;align-items:center">
    <span style="font-weight:700;font-size:12px;color:{_clr.get(lvl,'#1E40AF')}">
      {_ico.get(lvl,'•')} {lvl}
    </span>
    <span style="font-size:11px;color:#9CA3AF">{ts}</span>
  </div>
  <div style="font-size:13px;color:#374151;margin-top:4px">{a.message} {src}</div>
</div>""", unsafe_allow_html=True)


def _tab_sessions():
    import pandas as pd
    smap = st.session_state.sessions.get_sessions()
    if not smap:
        st.markdown("""
<div style="text-align:center;padding:50px 0;color:#9CA3AF">
  <div style="font-size:40px">🔗</div>
  <div style="font-size:15px;font-weight:600;margin-top:10px;color:#6B7280">
    No sessions tracked yet
  </div>
</div>""", unsafe_allow_html=True)
        return

    rows = []
    for s in smap.values():
        nb = s.byte_count
        sz = f"{nb/1024:.1f} KB" if nb>=1024 else f"{nb} B"
        rows.append({
            "Src IP": s.src_ip, "Dst IP": s.dst_ip,
            "Src Port": s.src_port or "—", "Dst Port": s.dst_port or "—",
            "Protocol": s.protocol, "Packets": f"{s.packet_count:,}",
            "Data": sz, "Duration": f"{s.duration_seconds:.1f}s",
            "State": s.state,
            "Started": time.strftime("%H:%M:%S", time.localtime(s.start_time)),
        })

    df = pd.DataFrame(rows)

    def _sty(v):
        if v == "ACTIVE": return "color:#15803D;font-weight:700;background:#DCFCE7"
        if v == "IDLE":   return "color:#92400E;background:#FFFBEB"
        return "color:#6B7280"

    st.dataframe(df.style.map(_sty, subset=["State"]),
                 width='stretch', height=420, hide_index=True)
    active = sum(1 for s in smap.values() if s.state=="ACTIVE")
    st.caption(f"{len(rows)} sessions  ·  {active} active")


# ── Main loop ─────────────────────────────────────────────────────────────────
_sidebar()
ph = st.empty()

while True:
    with ph.container():
        ss   = st.session_state
        snap = ss.stats.get_snapshot()
        alrts= ss.anomaly.get_alerts()
        active = ss.sessions.get_active_count()
        filtered = [r for r in ss.buffer.get_recent(DEFAULT_CONFIG.ui.max_table_rows*5)
                    if ss.filters.matches(r)]

        _header(snap)
        _kpi_row(snap, alrts, active)
        st.markdown("<br/>", unsafe_allow_html=True)

        # Insights panel
        with st.container():
            st.markdown('<div class="panel">', unsafe_allow_html=True)
            _insights(snap, alrts)
            st.markdown('</div>', unsafe_allow_html=True)

        # Main tabs
        t1,t2,t3,t4 = st.tabs([
            f"📋 Packets ({len(filtered):,})",
            "📊 Analytics",
            f"🚨 Alerts ({len(alrts)})",
            f"🔗 Sessions ({active})",
        ])
        with t1: _tab_packets(filtered, snap)
        with t2: _tab_analytics(snap)
        with t3: _tab_alerts(alrts)
        with t4: _tab_sessions()

    time.sleep(DEFAULT_CONFIG.ui.refresh_interval_seconds)
    st.rerun()
