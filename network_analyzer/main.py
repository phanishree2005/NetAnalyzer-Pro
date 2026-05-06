"""
main.py — Application entrypoint for the Network Protocol Analyzer.

Two run modes:
  1. UI mode (default):  Launches the Streamlit dashboard.
  2. CLI mode (--cli):   Headless capture + live stats printed to stdout.
                         Useful for servers without a browser.

Usage:
    # UI mode (default)
    python main.py

    # UI mode on a specific interface
    python main.py --interface eth0 --filter "tcp"

    # Headless CLI mode
    python main.py --cli --interface eth0 --filter "udp" --duration 30
"""

from __future__ import annotations

import argparse
import io
import os
import subprocess
import sys
import time

from utils.logger import configure_root_logger, get_logger
from utils.config import DEFAULT_CONFIG

configure_root_logger()
logger = get_logger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed :class:`argparse.Namespace`.
    """
    parser = argparse.ArgumentParser(
        prog="network_analyzer",
        description="🛡️  NetAnalyzer Pro — Real-time Network Protocol Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                            # Open Streamlit UI (default)
  python main.py --interface eth0           # UI on specific interface
  python main.py --cli --duration 60        # Headless 60-second capture
  python main.py --cli -i Wi-Fi -f "tcp"   # CLI with BPF filter
        """,
    )

    parser.add_argument(
        "--cli", "-C",
        action="store_true",
        help="Run in headless CLI mode instead of launching the Streamlit UI.",
    )
    parser.add_argument(
        "--interface", "-i",
        default="",
        metavar="IFACE",
        help="Network interface to sniff (default: auto-detect).",
    )
    parser.add_argument(
        "--filter", "-f",
        default="",
        metavar="BPF",
        help='Berkeley Packet Filter string, e.g. "tcp port 80".',
    )
    parser.add_argument(
        "--duration", "-d",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Auto-stop after N seconds (0 = run until Ctrl-C). CLI mode only.",
    )
    parser.add_argument(
        "--buffer-size",
        type=int,
        default=DEFAULT_CONFIG.buffer.max_capacity,
        metavar="N",
        help=f"In-memory buffer capacity (default: {DEFAULT_CONFIG.buffer.max_capacity}).",
    )
    parser.add_argument(
        "--sqlite",
        action="store_true",
        help="Enable SQLite persistence (written to packets.db).",
    )
    parser.add_argument(
        "--db-path",
        default="packets.db",
        metavar="PATH",
        help="SQLite database path (requires --sqlite).",
    )

    return parser.parse_args()


def run_ui(args: argparse.Namespace) -> None:
    """Launch the Streamlit dashboard as a subprocess.

    Args:
        args: Parsed CLI arguments.
    """
    dashboard = os.path.join(os.path.dirname(__file__), "ui", "dashboard.py")
    if not os.path.exists(dashboard):
        logger.error("Dashboard not found at: %s", dashboard)
        sys.exit(1)

    cmd = [
        sys.executable, "-m", "streamlit", "run",
        dashboard,
        "--server.headless", "false",
        "--browser.gatherUsageStats", "false",
    ]

    logger.info("Launching Streamlit UI: %s", " ".join(cmd))
    print("\n" + "=" * 60)
    print("  [*] NetAnalyzer Pro -- Starting UI")
    print("=" * 60)
    print(f"  Dashboard: http://localhost:8501")
    print(f"  Interface: {args.interface or '<auto-detect>'}")
    print(f"  BPF Filter: {args.filter or '<none>'}")
    print("  Press Ctrl+C to stop.")
    print("=" * 60 + "\n")

    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print("\n\nShutting down NetAnalyzer Pro. Goodbye!")


def run_cli(args: argparse.Namespace) -> None:
    """Run a headless capture session, printing stats to stdout.

    Args:
        args: Parsed CLI arguments.
    """
    import queue as _queue

    from capture.sniffer import PacketSniffer
    from capture.interface import get_interfaces, get_default_interface
    from processing.parser import PacketParser
    from analysis.stats import StatisticsEngine
    from analysis.anomaly import AnomalyDetector
    from analysis.sessions import SessionTracker
    from data.buffer import PacketBuffer
    from data.store import DataStore

    # Apply overrides from CLI
    DEFAULT_CONFIG.buffer.max_capacity = args.buffer_size
    DEFAULT_CONFIG.store.enabled = args.sqlite
    DEFAULT_CONFIG.store.db_path = args.db_path

    # Interface validation
    interface = args.interface
    if not interface:
        interface = get_default_interface() or ""
        logger.info("Auto-detected interface: %s", interface or "<none>")

    available = get_interfaces()
    if interface and interface not in available:
        logger.warning(
            "Interface '%s' not found. Available: %s", interface, available
        )

    # Build pipeline
    buffer = PacketBuffer(config=DEFAULT_CONFIG.buffer)
    stats = StatisticsEngine(config=DEFAULT_CONFIG.stats)
    anomaly = AnomalyDetector(config=DEFAULT_CONFIG.anomaly)
    sessions = SessionTracker()
    store = DataStore(config=DEFAULT_CONFIG.store, buffer=buffer)
    store.start()

    sniffer = PacketSniffer(config=DEFAULT_CONFIG.capture)
    sniffer.start(interface=interface, bpf_filter=args.filter)

    parser = PacketParser(raw_queue=sniffer.get_queue())
    parser.start()

    parsed_q: _queue.Queue = parser.get_queue()

    print("\n" + "=" * 60)
    print("  [*] NetAnalyzer Pro -- CLI Mode")
    print("=" * 60)
    print(f"  Interface : {interface or '<auto>'}")
    print(f"  BPF Filter: {args.filter or '<none>'}")
    print(f"  Duration  : {args.duration}s (0=inf)")
    print(f"  SQLite    : {'ON -> ' + args.db_path if args.sqlite else 'OFF'}")
    print("  Press Ctrl+C to stop early.")
    print("=" * 60 + "\n")

    start_time = time.time()
    last_print = 0.0

    try:
        while True:
            # Drain parsed queue
            try:
                while True:
                    record = parsed_q.get_nowait()
                    buffer.append(record)
                    stats.record_packet(record)
                    anomaly.analyze(record)
                    sessions.update(record)
                    store.ingest(record)
            except _queue.Empty:
                pass

            now = time.time()

            # Print stats every second
            if now - last_print >= 1.0:
                snap = stats.get_snapshot()
                active_sess = sessions.get_active_count()
                alerts = anomaly.get_alerts(clear=True)
                elapsed = int(now - start_time)

                print(
                    f"\r[{elapsed:>4}s] "
                    f"Total: {snap.total_packets:>7,}  "
                    f"PPS: {snap.packets_per_sec:>6.1f}  "
                    f"BPS: {snap.bytes_per_sec / 1024:>6.1f} KB/s  "
                    f"Sessions: {active_sess:>4}  "
                    f"Buf: {buffer.size:>5}  "
                    f"Alerts: {len(alerts):>3}",
                    end="",
                    flush=True,
                )

                for alert in alerts:
                    print(
                        f"\n  [!] [{alert.level.value}] {alert.message}"
                    )

                last_print = now

            # Auto-stop
            if args.duration and (now - start_time) >= args.duration:
                print(f"\n\nDuration ({args.duration}s) reached — stopping.")
                break

            time.sleep(0.02)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
    finally:
        sniffer.stop()
        parser.stop()
        store.stop()

        snap = stats.get_snapshot()
        print("\n" + "=" * 60)
        print("  [=] Final Statistics")
        print("=" * 60)
        print(f"  Total packets  : {snap.total_packets:,}")
        print(f"  Total bytes    : {snap.total_bytes:,}")
        print(f"  Protocol breakdown:")
        for proto, count in sorted(snap.protocol_counts.items(), key=lambda x: -x[1]):
            pct = count / max(snap.total_packets, 1) * 100
            print(f"    {proto:<8}: {count:>7,}  ({pct:.1f}%)")
        print(f"  Top talkers:")
        for ip, count in snap.top_talkers.items():
            print(f"    {ip:<18}: {count:>7,} pkts")
        print("=" * 60)


def main() -> None:
    """Entry point -- parse args and dispatch to UI or CLI mode."""
    # Force UTF-8 stdout/stderr on Windows to avoid cp1252 UnicodeEncodeError
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

    args = parse_args()

    if args.cli:
        run_cli(args)
    else:
        run_ui(args)


if __name__ == "__main__":
    main()
