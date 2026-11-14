"""Tiny UDP client used to generate traffic for the analyzer."""

import argparse
import socket


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=15004)
    ap.add_argument("--message", default="THIS IS A UDP PACKET TEST")
    args = ap.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(args.message.encode("utf-8"), (args.host, args.port))
        reply, _ = sock.recvfrom(1024)
        print(f"server replied: {reply.decode('utf-8', errors='replace')!r}")


if __name__ == "__main__":
    main()
