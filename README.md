# packet-analyzer

A small, dependency-free packet analyzer written in pure Python. It reads raw bytes from a
raw socket (or a `.pcap` file), parses IPv4, TCP, UDP and ICMP headers by hand with
`struct`, verifies checksums, and follows TCP connections through the three-way handshake
and FIN teardown.

It started as three separate Computer Networks course exercises (IP, UDP and TCP) and was
rewritten into one tested tool.

```
$ sudo python -m packet_analyzer -i lo --port 15003
#1 21:07:50.023  TCP  127.0.0.1 -> 127.0.0.1
  IPv4  ver=4 ihl=20B len=60 id=19507 ttl=64 DF=1 MF=0 frag_off=0 checksum=0xf086 (ok)
  TCP   58228 -> 15003  flags=[SYN] seq=1886476156 ack=0 win=65495 hdr=40B payload=0B
  >> handshake 1/3  SYN      127.0.0.1:58228 -> 127.0.0.1:15003  seq=1886476156

#2 21:07:50.023  TCP  127.0.0.1 -> 127.0.0.1
  IPv4  ver=4 ihl=20B len=60 id=0 ttl=64 DF=1 MF=0 frag_off=0 checksum=0x3cba (ok)
  TCP   15003 -> 58228  flags=[SYN,ACK] seq=4056274800 ack=1886476157 win=65483 hdr=40B payload=0B
  >> handshake 2/3  SYN-ACK  127.0.0.1:15003 -> 127.0.0.1:58228  seq=4056274800 ack=1886476157

#3 21:07:50.023  TCP  127.0.0.1 -> 127.0.0.1
  IPv4  ver=4 ihl=20B len=52 id=19508 ttl=64 DF=1 MF=0 frag_off=0 checksum=0xf08d (ok)
  TCP   58228 -> 15003  flags=[ACK] seq=1886476157 ack=4056274801 win=64 hdr=32B payload=0B
  >> handshake 3/3  ACK      127.0.0.1:58228 -> 127.0.0.1:15003  ack=4056274801  => ESTABLISHED

#4 21:07:50.023  TCP  127.0.0.1 -> 127.0.0.1
  IPv4  ver=4 ihl=20B len=77 id=19509 ttl=64 DF=1 MF=0 frag_off=0 checksum=0xf073 (ok)
  TCP   58228 -> 15003  flags=[PSH,ACK] seq=1886476157 ack=4056274801 win=64 hdr=32B payload=25B
  data  "THIS IS A TCP PACKET TEST"
...
```

## Features

- **Header parsing from raw bytes:** Ethernet, IPv4 (including options, DF/MF flags and
  fragment offset), TCP (all 8 flags, seq/ack, options, data offset), UDP and ICMP.
- **Checksum verification:** RFC 1071 one's-complement checksum for IPv4 headers and ICMP.
- **TCP connection tracking:** reports SYN → SYN-ACK → ACK and checks the sequence
  numbers (the SYN-ACK must acknowledge `client_ISN + 1`), then FIN/FIN/ACK teardown and RST.
- **Live capture or offline:** raw sockets on Linux (`AF_PACKET`) and Windows (`SIO_RCVALL`),
  or read any classic `.pcap` file (Ethernet, raw IP, BSD loopback, Linux "any").
  Packets you capture can be saved with `-w` and opened in Wireshark.
- **Filters:** by protocol, host, port and packet count; optional payload hex dump.
- **No dependencies:** standard library only. Tests run on Linux, Windows and macOS in CI.

## Usage

```bash
# Live capture (Linux: needs root. Windows: run from an Administrator shell)
sudo python -m packet_analyzer                         # everything, all interfaces
sudo python -m packet_analyzer -i lo --proto tcp       # TCP on loopback
sudo python -m packet_analyzer --port 443 -c 20 -x     # 20 packets to/from :443, with hex dump
sudo python -m packet_analyzer -i eth0 -w out.pcap     # also save to a pcap for Wireshark

# Offline: works anywhere, no root needed
python -m packet_analyzer --pcap examples/tcp_session.pcap
python -m packet_analyzer --pcap examples/udp_exchange.pcap -x
```

To generate traffic to look at, run the demo programs in two other terminals:

```bash
python demo/tcp_server.py      # then: python demo/tcp_client.py
python demo/udp_server.py      # then: python demo/udp_client.py
```

### macOS

The BSD kernel does not deliver TCP or UDP packets to raw `AF_INET` sockets, so live
capture is not supported there. Record with `sudo tcpdump -i lo0 -w capture.pcap` and run
the analyzer with `--pcap capture.pcap`.

## Project layout

```
packet_analyzer/
  parsers.py      pure functions: bytes -> header dataclasses, plus the checksum
  sources.py      live raw-socket capture (Linux/Windows) and pcap read/write
  tcp_tracker.py  per-connection state machine for handshakes and teardowns
  cli.py          argument parsing, filtering and output formatting
demo/             tiny TCP/UDP client-server pairs that generate test traffic
examples/         pcap files captured with this tool
tests/            pytest suite built on hand-assembled packets
```

The parsers never touch a socket, so every one of them is tested against packets built
byte by byte in `tests/test_parsers.py`: field extraction, IPv4 options and Ethernet
padding, corrupted checksums, fragments, malformed input, the full handshake/teardown
sequence and a pcap write/read round trip.

```bash
pip install pytest
pytest -q
```

## Design notes

- **Byte order.** Every `struct` format uses `!` (network order), so values come out
  already converted. An earlier version also called `socket.ntohs()` on the total length,
  which swaps the bytes a second time; there is a regression test for this.
- **Padding.** Ethernet pads short frames to 60 bytes, so the IPv4 payload is cut at
  `total_length` rather than at the end of the buffer.
- **Loopback duplicates.** On Linux, an `AF_PACKET` socket sees each loopback packet twice
  (outgoing and incoming); outgoing copies on `lo` are skipped.
- **Fragments.** Only the first fragment (offset 0) carries the transport header, so later
  fragments are shown as IPv4 only.

## Limitations

IPv4 only (no IPv6), no IP fragment reassembly, no TCP stream reassembly, classic pcap
only (convert pcapng with `editcap -F pcap in.pcapng out.pcap`).

## License

MIT
