"""Pure byte-level parsers for Ethernet, IPv4, TCP, UDP and ICMP headers.

Nothing here touches a socket: every function takes ``bytes`` and returns a
dataclass, which makes the parsers easy to unit-test with hand-built packets.
All multi-byte fields are network byte order (big-endian), hence the ``!``
prefix on every ``struct`` format string.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

ETH_P_IP = 0x0800

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_NAMES = {PROTO_ICMP: "ICMP", PROTO_TCP: "TCP", PROTO_UDP: "UDP"}

TCP_FLAG_BITS = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]

ICMP_TYPES = {0: "Echo Reply", 3: "Destination Unreachable", 8: "Echo Request", 11: "Time Exceeded"}


class ParseError(ValueError):
    """Raised when a buffer is too short or malformed for the header it should hold."""


def internet_checksum(data: bytes) -> int:
    """RFC 1071 one's-complement checksum. Returns 0 when run over a header that
    already contains a correct checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


# --------------------------------------------------------------------------- Ethernet
@dataclass(frozen=True)
class EthernetFrame:
    dst_mac: str
    src_mac: str
    ethertype: int
    payload: bytes = field(repr=False)


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def parse_ethernet(frame: bytes) -> EthernetFrame:
    if len(frame) < 14:
        raise ParseError(f"Ethernet frame too short ({len(frame)} bytes)")
    dst, src, ethertype = struct.unpack("!6s6sH", frame[:14])
    return EthernetFrame(_mac(dst), _mac(src), ethertype, frame[14:])


# --------------------------------------------------------------------------- IPv4
@dataclass(frozen=True)
class IPv4Header:
    version: int
    header_length: int  # bytes, i.e. IHL * 4
    dscp: int
    ecn: int
    total_length: int
    identification: int
    dont_fragment: bool
    more_fragments: bool
    fragment_offset: int  # bytes
    ttl: int
    protocol: int
    checksum: int
    src: str
    dst: str
    options: bytes
    checksum_ok: bool
    payload: bytes = field(repr=False)

    @property
    def protocol_name(self) -> str:
        return PROTO_NAMES.get(self.protocol, f"proto-{self.protocol}")


def parse_ipv4(packet: bytes) -> IPv4Header:
    if len(packet) < 20:
        raise ParseError(f"IPv4 packet too short ({len(packet)} bytes)")

    (ver_ihl, tos, total_length, ident, flags_frag,
     ttl, proto, checksum, src, dst) = struct.unpack("!BBHHHBBH4s4s", packet[:20])

    version = ver_ihl >> 4
    header_length = (ver_ihl & 0x0F) * 4
    if version != 4:
        raise ParseError(f"not an IPv4 packet (version={version})")
    if header_length < 20 or len(packet) < header_length:
        raise ParseError(f"bad IHL ({header_length} bytes) for a {len(packet)}-byte buffer")

    # total_length bounds the payload; anything beyond it is link-layer padding
    # (e.g. Ethernet pads frames to 60 bytes).
    end = total_length if header_length <= total_length <= len(packet) else len(packet)

    return IPv4Header(
        version=version,
        header_length=header_length,
        dscp=tos >> 2,
        ecn=tos & 0x03,
        total_length=total_length,
        identification=ident,
        dont_fragment=bool(flags_frag & 0x4000),
        more_fragments=bool(flags_frag & 0x2000),
        fragment_offset=(flags_frag & 0x1FFF) * 8,
        ttl=ttl,
        protocol=proto,
        checksum=checksum,
        src=str(ipaddress.IPv4Address(src)),
        dst=str(ipaddress.IPv4Address(dst)),
        options=packet[20:header_length],
        checksum_ok=internet_checksum(packet[:header_length]) == 0,
        payload=packet[header_length:end],
    )


# --------------------------------------------------------------------------- TCP
@dataclass(frozen=True)
class TCPHeader:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    header_length: int  # bytes, i.e. data offset * 4
    flags: int
    window: int
    checksum: int
    urgent_pointer: int
    options: bytes
    payload: bytes = field(repr=False)

    @property
    def flag_names(self) -> list[str]:
        return [name for bit, name in TCP_FLAG_BITS if self.flags & bit]

    def has(self, *names: str) -> bool:
        return all(name in self.flag_names for name in names)


def parse_tcp(segment: bytes) -> TCPHeader:
    if len(segment) < 20:
        raise ParseError(f"TCP segment too short ({len(segment)} bytes)")
    (src_port, dst_port, seq, ack, offset_reserved, flags,
     window, checksum, urg) = struct.unpack("!HHIIBBHHH", segment[:20])
    header_length = (offset_reserved >> 4) * 4
    if header_length < 20 or len(segment) < header_length:
        raise ParseError(f"bad TCP data offset ({header_length} bytes)")
    return TCPHeader(src_port, dst_port, seq, ack, header_length, flags, window,
                     checksum, urg, segment[20:header_length], segment[header_length:])


# --------------------------------------------------------------------------- UDP
@dataclass(frozen=True)
class UDPHeader:
    src_port: int
    dst_port: int
    length: int
    checksum: int
    payload: bytes = field(repr=False)


def parse_udp(datagram: bytes) -> UDPHeader:
    if len(datagram) < 8:
        raise ParseError(f"UDP datagram too short ({len(datagram)} bytes)")
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", datagram[:8])
    end = length if 8 <= length <= len(datagram) else len(datagram)
    return UDPHeader(src_port, dst_port, length, checksum, datagram[8:end])


# --------------------------------------------------------------------------- ICMP
@dataclass(frozen=True)
class ICMPHeader:
    type: int
    code: int
    checksum: int
    rest: int
    checksum_ok: bool
    payload: bytes = field(repr=False)

    @property
    def type_name(self) -> str:
        return ICMP_TYPES.get(self.type, f"type-{self.type}")


def parse_icmp(message: bytes) -> ICMPHeader:
    if len(message) < 8:
        raise ParseError(f"ICMP message too short ({len(message)} bytes)")
    icmp_type, code, checksum, rest = struct.unpack("!BBHI", message[:8])
    return ICMPHeader(icmp_type, code, checksum, rest,
                      internet_checksum(message) == 0, message[8:])


# --------------------------------------------------------------------------- dispatch
@dataclass(frozen=True)
class Packet:
    ip: IPv4Header
    transport: TCPHeader | UDPHeader | ICMPHeader | None

    @property
    def src_port(self) -> int | None:
        return getattr(self.transport, "src_port", None)

    @property
    def dst_port(self) -> int | None:
        return getattr(self.transport, "dst_port", None)


def parse_packet(ip_bytes: bytes) -> Packet:
    """Parse an IPv4 packet and, if it is the first fragment, its transport header."""
    ip = parse_ipv4(ip_bytes)
    transport = None
    if ip.fragment_offset == 0:
        parser = {PROTO_TCP: parse_tcp, PROTO_UDP: parse_udp, PROTO_ICMP: parse_icmp}.get(ip.protocol)
        if parser is not None:
            transport = parser(ip.payload)
    return Packet(ip, transport)
