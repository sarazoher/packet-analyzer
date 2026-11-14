"""Command-line entry point: python -m packet_analyzer [options]"""

from __future__ import annotations

import argparse
import datetime as dt
import sys

from .parsers import ICMPHeader, Packet, ParseError, TCPHeader, UDPHeader, parse_packet
from .sources import live_capture, read_pcap, write_pcap
from .tcp_tracker import TCPTracker


def hexdump(data: bytes, width: int = 16, indent: str = "    ") -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexes = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{off:04x}  {hexes:<{width * 3}} {text}")
    return "\n".join(lines)


def describe(n: int, ts: float, pkt: Packet, show_hex: bool) -> str:
    ip = pkt.ip
    when = dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
    chk = "ok" if ip.checksum_ok else "BAD"
    out = [f"#{n} {when}  {ip.protocol_name}  {ip.src} -> {ip.dst}",
           f"  IPv4  ver={ip.version} ihl={ip.header_length}B len={ip.total_length} "
           f"id={ip.identification} ttl={ip.ttl} DF={int(ip.dont_fragment)} "
           f"MF={int(ip.more_fragments)} frag_off={ip.fragment_offset} checksum=0x{ip.checksum:04x} ({chk})"]

    t = pkt.transport
    if isinstance(t, TCPHeader):
        out.append(f"  TCP   {t.src_port} -> {t.dst_port}  flags=[{','.join(t.flag_names)}] "
                   f"seq={t.seq} ack={t.ack} win={t.window} hdr={t.header_length}B "
                   f"payload={len(t.payload)}B")
    elif isinstance(t, UDPHeader):
        out.append(f"  UDP   {t.src_port} -> {t.dst_port}  length={t.length} "
                   f"checksum=0x{t.checksum:04x} payload={len(t.payload)}B")
    elif isinstance(t, ICMPHeader):
        out.append(f"  ICMP  {t.type_name} (type={t.type} code={t.code}) "
                   f"checksum={'ok' if t.checksum_ok else 'BAD'}")

    payload = getattr(t, "payload", b"")
    if payload:
        preview = payload[:64].decode("utf-8", errors="replace").replace("\n", "\\n")
        out.append(f"  data  \"{preview}\"" + (" ..." if len(payload) > 64 else ""))
        if show_hex:
            out.append(hexdump(payload))
    return "\n".join(out)


def matches(pkt: Packet, args: argparse.Namespace) -> bool:
    if args.proto and pkt.ip.protocol_name.lower() != args.proto:
        return False
    if args.host and args.host not in (pkt.ip.src, pkt.ip.dst):
        return False
    if args.port and args.port not in (pkt.src_port, pkt.dst_port):
        return False
    return True


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="packet_analyzer", description="Minimal IPv4/TCP/UDP/ICMP packet analyzer.")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--pcap", help="read packets from a classic .pcap file instead of a live socket")
    src.add_argument("-i", "--interface", help="Linux: interface name (default: all). Windows: local IP to bind")
    p.add_argument("--proto", choices=["tcp", "udp", "icmp"], help="only show this protocol")
    p.add_argument("--host", help="only show packets to/from this IPv4 address")
    p.add_argument("--port", type=int, help="only show packets to/from this port")
    p.add_argument("-c", "--count", type=int, help="stop after this many matching packets")
    p.add_argument("-x", "--hex", action="store_true", help="hex-dump payloads")
    p.add_argument("-w", "--write", metavar="FILE", help="also save the shown packets to a .pcap file")
    p.add_argument("--no-track", action="store_true", help="don't report TCP handshake/teardown events")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        source = read_pcap(args.pcap) if args.pcap else live_capture(args.interface)
    except (OSError, ParseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    tracker = TCPTracker()
    shown = 0
    saved: list[tuple[float, bytes]] = []
    try:
        for ts, ip_bytes in source:
            try:
                pkt = parse_packet(ip_bytes)
            except ParseError as exc:
                print(f"[skip] {exc}", file=sys.stderr)
                continue
            if not matches(pkt, args):
                continue
            shown += 1
            saved.append((ts, ip_bytes))
            print(describe(shown, ts, pkt, args.hex))
            if not args.no_track and (event := tracker.update(pkt)):
                print(f"  >> {event}")
            print()
            if args.count and shown >= args.count:
                break
    except PermissionError:
        print("error: live capture needs root (Linux) or an Administrator shell (Windows)", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:  # output piped into e.g. `head`
        sys.stderr.close()
        return 0
    if args.write:
        write_pcap(args.write, saved)
        print(f"saved {len(saved)} packet(s) to {args.write}", file=sys.stderr)
    print(f"{shown} packet(s) shown", file=sys.stderr)
    return 0
