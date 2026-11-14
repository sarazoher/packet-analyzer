"""Where packets come from: a live raw socket, or a classic libpcap file.

Every source yields ``(timestamp, ipv4_bytes)`` so the rest of the program never
has to care about link layers or operating systems.
"""

from __future__ import annotations

import socket
import struct
import sys
import time
from collections.abc import Iterator

from .parsers import ETH_P_IP, ParseError, parse_ethernet

ETH_P_ALL = 0x0003

# libpcap link-layer types we understand
LINKTYPE_NULL = 0        # BSD/macOS loopback: 4-byte address-family header
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101       # bare IP packets
LINKTYPE_LINUX_SLL = 113 # "any" interface on Linux

PCAP_MAGIC = {
    0xA1B2C3D4: ("<", 1e-6), 0xD4C3B2A1: (">", 1e-6),  # microsecond timestamps
    0xA1B23C4D: ("<", 1e-9), 0x4D3CB2A1: (">", 1e-9),  # nanosecond timestamps
}


def _strip_link_layer(frame: bytes, linktype: int) -> bytes | None:
    """Return the IPv4 packet inside a link-layer frame, or None for non-IPv4 frames."""
    if linktype == LINKTYPE_RAW:
        return frame if frame and frame[0] >> 4 == 4 else None
    if linktype == LINKTYPE_ETHERNET:
        eth = parse_ethernet(frame)
        return eth.payload if eth.ethertype == ETH_P_IP else None
    if linktype == LINKTYPE_NULL:
        family = int.from_bytes(frame[:4], sys.byteorder)
        return frame[4:] if family == socket.AF_INET else None
    if linktype == LINKTYPE_LINUX_SLL:
        (proto,) = struct.unpack("!H", frame[14:16])
        return frame[16:] if proto == ETH_P_IP else None
    raise ParseError(f"unsupported pcap link type {linktype}")


# --------------------------------------------------------------------------- pcap files
def read_pcap(path: str) -> Iterator[tuple[float, bytes]]:
    """Yield IPv4 packets from a classic .pcap file (not .pcapng)."""
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            raise ParseError("file too short to be a pcap")
        magic = struct.unpack("<I", header[:4])[0]
        if magic not in PCAP_MAGIC:
            raise ParseError("not a classic pcap file (pcapng is not supported; "
                             "convert with `editcap -F pcap in.pcapng out.pcap`)")
        endian, tick = PCAP_MAGIC[magic]
        linktype = struct.unpack(endian + "I", header[20:24])[0]

        while record := fh.read(16):
            if len(record) < 16:
                break
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", record)
            frame = fh.read(incl_len)
            ip_bytes = _strip_link_layer(frame, linktype)
            if ip_bytes is not None:
                yield ts_sec + ts_frac * tick, ip_bytes


def write_pcap(path: str, packets: list[tuple[float, bytes]]) -> None:
    """Write bare IPv4 packets to a pcap file (LINKTYPE_RAW). Opens in Wireshark."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_RAW))
        for ts, data in packets:
            sec = int(ts)
            fh.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(data), len(data)))
            fh.write(data)


# --------------------------------------------------------------------------- live capture
def live_capture(interface: str | None = None) -> Iterator[tuple[float, bytes]]:
    """Yield IPv4 packets from a raw socket. Needs root / Administrator.

    * Linux: AF_PACKET socket, sees every protocol on every (or one) interface.
    * Windows: AF_INET raw socket in promiscuous mode via SIO_RCVALL.
    * macOS/BSD: the kernel does not hand TCP/UDP to raw sockets, so live capture is
      not supported -- capture with `tcpdump -w file.pcap` and use --pcap instead.
    """
    if sys.platform.startswith("linux"):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        if interface:
            sock.bind((interface, 0))
        try:
            while True:
                frame, addr = sock.recvfrom(65535)
                # addr[2] is the packet type; skip PACKET_OUTGOING (4) duplicates on loopback
                if addr[0] == "lo" and addr[2] == socket.PACKET_OUTGOING:
                    continue
                ip_bytes = _strip_link_layer(frame, LINKTYPE_ETHERNET)
                if ip_bytes is not None:
                    yield time.time(), ip_bytes
        finally:
            sock.close()

    elif sys.platform == "win32":
        host = interface or socket.gethostbyname(socket.gethostname())
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((host, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        try:
            while True:
                yield time.time(), sock.recv(65535)
        finally:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()

    else:
        raise OSError(f"live capture is not supported on {sys.platform}; "
                      "record with `sudo tcpdump -i lo0 -w capture.pcap` and pass --pcap")
