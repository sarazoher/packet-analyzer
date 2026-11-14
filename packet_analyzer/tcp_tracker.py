"""Follows TCP connections and reports handshakes and teardowns as they happen.

A connection is keyed by its 4-tuple, normalised so both directions map to the
same entry. The tracker checks sequence numbers, not only flags: the SYN-ACK must
acknowledge client_ISN + 1 and the final ACK must acknowledge server_ISN + 1.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .parsers import Packet, TCPHeader

Endpoint = tuple[str, int]


@dataclass
class Connection:
    client: Endpoint
    server: Endpoint
    client_isn: int
    server_isn: int | None = None
    state: str = "SYN_SENT"
    fins: set[Endpoint] = field(default_factory=set)


class TCPTracker:
    def __init__(self) -> None:
        self.connections: dict[frozenset[Endpoint], Connection] = {}

    def update(self, packet: Packet) -> str | None:
        """Feed one packet; return a human-readable event or None."""
        tcp = packet.transport
        if not isinstance(tcp, TCPHeader):
            return None
        src: Endpoint = (packet.ip.src, tcp.src_port)
        dst: Endpoint = (packet.ip.dst, tcp.dst_port)
        key = frozenset((src, dst))
        conn = self.connections.get(key)

        if tcp.has("SYN") and not tcp.has("ACK"):
            self.connections[key] = Connection(client=src, server=dst, client_isn=tcp.seq)
            return f"handshake 1/3  SYN      {_fmt(src)} -> {_fmt(dst)}  seq={tcp.seq}"

        if conn is None:
            return None

        if tcp.has("RST"):
            del self.connections[key]
            return f"connection reset by {_fmt(src)}"

        if conn.state == "SYN_SENT" and tcp.has("SYN", "ACK") and src == conn.server:
            if tcp.ack != (conn.client_isn + 1) % 2**32:
                return f"unexpected SYN-ACK: ack={tcp.ack}, expected {conn.client_isn + 1}"
            conn.server_isn, conn.state = tcp.seq, "SYN_RECEIVED"
            return f"handshake 2/3  SYN-ACK  {_fmt(src)} -> {_fmt(dst)}  seq={tcp.seq} ack={tcp.ack}"

        if conn.state == "SYN_RECEIVED" and tcp.has("ACK") and src == conn.client:
            if tcp.ack == (conn.server_isn + 1) % 2**32:
                conn.state = "ESTABLISHED"
                return (f"handshake 3/3  ACK      {_fmt(src)} -> {_fmt(dst)}  ack={tcp.ack}"
                        f"  => ESTABLISHED")

        if tcp.has("FIN"):
            conn.fins.add(src)
            if len(conn.fins) == 2:
                conn.state = "CLOSING"
            return f"FIN from {_fmt(src)}"

        if conn.state == "CLOSING" and tcp.has("ACK") and not tcp.payload:
            del self.connections[key]
            return f"connection {_fmt(conn.client)} <-> {_fmt(conn.server)} closed"

        return None


def _fmt(ep: Endpoint) -> str:
    return f"{ep[0]}:{ep[1]}"
