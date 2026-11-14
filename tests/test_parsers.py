import socket
import struct

import pytest

from packet_analyzer.parsers import (
    PROTO_ICMP, PROTO_TCP, PROTO_UDP, ParseError, internet_checksum,
    parse_ethernet, parse_icmp, parse_ipv4, parse_packet, parse_tcp, parse_udp,
)
from packet_analyzer.sources import read_pcap, write_pcap
from packet_analyzer.tcp_tracker import TCPTracker


# ----------------------------------------------------------------- packet builders
def ipv4(payload: bytes, proto: int, src="10.0.0.1", dst="10.0.0.2", ttl=64,
         ident=0x1234, flags_frag=0x4000, options=b"") -> bytes:
    ihl = (20 + len(options)) // 4
    hdr = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, 20 + len(options) + len(payload),
                      ident, flags_frag, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst)) + options
    csum = internet_checksum(hdr)
    return hdr[:10] + struct.pack("!H", csum) + hdr[12:] + payload


def tcp(sport, dport, seq=0, ack=0, flags=0, payload=b"", options=b"") -> bytes:
    offset = (20 + len(options)) // 4
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, offset << 4, flags,
                       65535, 0, 0) + options + payload


def udp(sport, dport, payload=b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_echo(ident=1, seq=1, payload=b"ping") -> bytes:
    msg = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
    return msg[:2] + struct.pack("!H", internet_checksum(msg)) + msg[4:]


SYN, ACK, FIN, PSH, RST = 0x02, 0x10, 0x01, 0x08, 0x04


# ----------------------------------------------------------------- checksum
def test_checksum_matches_rfc1071_example():
    # Example from RFC 1071 section 3: words 0001 f203 f4f5 f6f7 sum to 0xddf2 -> checksum 0x220d
    assert internet_checksum(bytes.fromhex("0001f203f4f5f6f7")) == 0x220D


def test_checksum_of_valid_header_is_zero():
    assert internet_checksum(ipv4(b"", PROTO_UDP)[:20]) == 0


# ----------------------------------------------------------------- IPv4
def test_ipv4_fields():
    pkt = ipv4(b"x" * 10, PROTO_TCP, src="192.168.1.5", dst="8.8.8.8", ttl=128, ident=0xBEEF)
    ip = parse_ipv4(pkt)
    assert (ip.version, ip.header_length, ip.total_length) == (4, 20, 30)
    assert (ip.src, ip.dst, ip.ttl, ip.identification) == ("192.168.1.5", "8.8.8.8", 128, 0xBEEF)
    assert ip.protocol_name == "TCP"
    assert ip.dont_fragment and not ip.more_fragments and ip.fragment_offset == 0
    assert ip.checksum_ok
    assert ip.payload == b"x" * 10


def test_total_length_is_not_byte_swapped():
    # Regression: the original assignment applied socket.ntohs() on top of struct's "!" format,
    # which swaps the bytes twice and turns a 300-byte packet into 11265 on little-endian hosts.
    ip = parse_ipv4(ipv4(b"\x00" * 280, PROTO_UDP))
    assert ip.total_length == 300


def test_ipv4_options_and_padding():
    opts = b"\x01\x01\x01\x00"  # NOP NOP NOP EOL
    pkt = ipv4(b"data", PROTO_UDP, options=opts) + b"\x00" * 6  # trailing Ethernet padding
    ip = parse_ipv4(pkt)
    assert ip.header_length == 24 and ip.options == opts
    assert ip.payload == b"data"  # padding beyond total_length is dropped


def test_corrupted_checksum_is_detected():
    pkt = bytearray(ipv4(b"", PROTO_UDP))
    pkt[8] ^= 0xFF  # flip the TTL without fixing the checksum
    assert not parse_ipv4(bytes(pkt)).checksum_ok


def test_fragment_fields():
    ip = parse_ipv4(ipv4(b"", PROTO_UDP, flags_frag=0x2000 | 185))
    assert ip.more_fragments and not ip.dont_fragment and ip.fragment_offset == 185 * 8


@pytest.mark.parametrize("bad", [b"", b"\x45" * 19, b"\x65" + b"\x00" * 19, b"\x44" + b"\x00" * 19])
def test_ipv4_rejects_malformed(bad):
    with pytest.raises(ParseError):
        parse_ipv4(bad)


# ----------------------------------------------------------------- transport
def test_tcp_fields_and_flags():
    seg = tcp(54321, 80, seq=1000, ack=2000, flags=PSH | ACK, payload=b"GET /",
              options=b"\x01\x01\x08\x0a" + b"\x00" * 8)
    t = parse_tcp(seg)
    assert (t.src_port, t.dst_port, t.seq, t.ack) == (54321, 80, 1000, 2000)
    assert t.flag_names == ["PSH", "ACK"] and t.has("ACK") and not t.has("SYN")
    assert t.header_length == 32 and len(t.options) == 12
    assert t.payload == b"GET /"


def test_udp_fields():
    u = parse_udp(udp(5353, 15004, b"hello"))
    assert (u.src_port, u.dst_port, u.length, u.payload) == (5353, 15004, 13, b"hello")


def test_icmp_echo():
    i = parse_icmp(icmp_echo())
    assert i.type_name == "Echo Request" and i.checksum_ok and i.payload == b"ping"


def test_parse_packet_dispatch():
    assert parse_packet(ipv4(udp(1, 2), PROTO_UDP)).dst_port == 2
    assert parse_packet(ipv4(icmp_echo(), PROTO_ICMP)).src_port is None
    assert parse_packet(ipv4(b"??", 47)).transport is None  # GRE: unknown, not parsed


def test_non_first_fragment_has_no_transport_header():
    assert parse_packet(ipv4(b"\x00" * 16, PROTO_UDP, flags_frag=10)).transport is None


def test_ethernet():
    frame = bytes.fromhex("ffffffffffff 001122334455 0800") + ipv4(b"", PROTO_UDP)
    eth = parse_ethernet(frame)
    assert eth.src_mac == "00:11:22:33:44:55" and eth.ethertype == 0x0800


# ----------------------------------------------------------------- handshake tracking
def handshake_packets():
    c, s = ("10.0.0.1", 40000), ("10.0.0.2", 80)
    def pkt(src, dst, **kw):
        return ipv4(tcp(src[1], dst[1], **kw), PROTO_TCP, src=src[0], dst=dst[0])
    return [
        pkt(c, s, seq=100, flags=SYN),
        pkt(s, c, seq=500, ack=101, flags=SYN | ACK),
        pkt(c, s, seq=101, ack=501, flags=ACK),
        pkt(c, s, seq=101, ack=501, flags=PSH | ACK, payload=b"hi"),
        pkt(s, c, seq=501, ack=103, flags=FIN | ACK),
        pkt(c, s, seq=103, ack=502, flags=FIN | ACK),
        pkt(s, c, seq=502, ack=104, flags=ACK),
    ]


def test_tracker_follows_handshake_and_teardown():
    tracker = TCPTracker()
    events = [tracker.update(parse_packet(p)) for p in handshake_packets()]
    assert events[0].startswith("handshake 1/3")
    assert events[1].startswith("handshake 2/3")
    assert events[2].endswith("ESTABLISHED")
    assert events[3] is None
    assert events[4].startswith("FIN") and events[5].startswith("FIN")
    assert events[6].endswith("closed")
    assert tracker.connections == {}


def test_tracker_rejects_wrong_synack_ack_number():
    pkts = handshake_packets()
    bad = bytearray(pkts[1])
    struct.pack_into("!I", bad, 20 + 8, 999)  # wrong ack in the SYN-ACK
    tracker = TCPTracker()
    tracker.update(parse_packet(pkts[0]))
    assert tracker.update(parse_packet(bytes(bad))).startswith("unexpected SYN-ACK")


# ----------------------------------------------------------------- pcap round trip
def test_pcap_round_trip(tmp_path):
    path = tmp_path / "hs.pcap"
    pkts = handshake_packets()
    write_pcap(str(path), [(1_700_000_000 + i * 0.001, p) for i, p in enumerate(pkts)])
    read = list(read_pcap(str(path)))
    assert [b for _, b in read] == pkts
    assert read[1][0] == pytest.approx(1_700_000_000.001, abs=1e-6)


def test_pcap_rejects_other_files(tmp_path):
    path = tmp_path / "x.pcap"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 30)  # pcapng magic
    with pytest.raises(ParseError, match="pcapng"):
        list(read_pcap(str(path)))
