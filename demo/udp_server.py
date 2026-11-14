"""Tiny UDP echo-style server used to generate traffic for the analyzer."""

import argparse
import socket


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=15004)
    args = ap.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((args.host, args.port))
        print(f"UDP server listening on {args.host}:{args.port}")
        data, client = sock.recvfrom(1024)
        print(f"received {data.decode('utf-8', errors='replace')!r} from {client[0]}:{client[1]}")
        sock.sendto(b"UDP server received your message", client)


if __name__ == "__main__":
    main()
