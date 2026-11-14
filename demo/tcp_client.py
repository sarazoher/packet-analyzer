"""Tiny TCP client used to generate traffic for the analyzer (python demo/tcp_client.py)."""

import argparse
import socket


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=15003)
    ap.add_argument("--message", default="THIS IS A TCP PACKET TEST")
    args = ap.parse_args()

    with socket.create_connection((args.host, args.port), timeout=5) as sock:
        sock.sendall(args.message.encode("utf-8"))
        reply = sock.recv(1024)
        print(f"server replied: {reply.decode('utf-8', errors='replace')!r}")


if __name__ == "__main__":
    main()
