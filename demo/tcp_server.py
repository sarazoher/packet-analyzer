"""Tiny TCP server used to generate traffic for the analyzer (python demo/tcp_server.py)."""

import argparse
import socket


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=15003)
    args = ap.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port))
        srv.listen()
        print(f"TCP server listening on {args.host}:{args.port}")
        conn, client = srv.accept()
        with conn:
            print(f"accepted connection from {client[0]}:{client[1]}")
            data = conn.recv(1024)
            print(f"received: {data.decode('utf-8', errors='replace')!r}")
            conn.sendall(b"TCP server received your message")


if __name__ == "__main__":
    main()
