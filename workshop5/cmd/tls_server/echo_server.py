#!/usr/bin/env python
import os.path
from http.server import HTTPServer, BaseHTTPRequestHandler

import ssl
import contextlib
import threading
import json
import sys
import signal

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(CURRENT_DIR, "certs")
KEY_PEM = os.path.join(CERTS_DIR, "key.pem")
CERT_PEM = os.path.join(CERTS_DIR, "cert.pem")


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        content_len = int(self.headers.get('content-length'))
        post_body = self.rfile.read(content_len)
        try:
            json.loads(post_body)
        except Exception:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "request body is not json",
                "original body": post_body
            }).encode())
            return

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-length', str(content_len))

        self.end_headers()
        self.wfile.write(post_body)


@contextlib.contextmanager
def tls_server(host, port):
    httpd = HTTPServer((host, port), SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=KEY_PEM, certfile=CERT_PEM, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield
    httpd.server_close()
    thread.join(timeout=5)


def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"{sys.argv[0]} <port>")
        sys.exit(1)
    with tls_server("0.0.0.0", int(sys.argv[1])):
        print(f"TLS server (PID {os.getpid()}) is listening on 0.0.0.0:{sys.argv[1]}")
        signal.signal(signal.SIGINT, signal_handler)
        print('Press Ctrl+C')
        signal.pause()
