"""Local echo upstream for the container-free E2E.

Replies 200 with the received request headers AND body as JSON, so the client
can verify exactly what the proxy put on the wire (header injection, body
substitution, composite rendering). Handles both Content-Length and chunked
transfer encoding — the AVP body injector streams substituted bodies chunked.
Binds loopback only.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def _read_body(self) -> bytes:
        te = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in te:
            data = b""
            while True:
                size_line = self.rfile.readline().strip()
                if not size_line:
                    break
                size = int(size_line.split(b";", 1)[0], 16)
                if size == 0:
                    self.rfile.readline()  # trailing CRLF after the last chunk
                    break
                data += self.rfile.read(size)
                self.rfile.readline()  # CRLF terminating this chunk
            return data
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length else b""

    def _echo(self):
        raw = self._read_body()
        body = json.dumps(
            {
                "headers": dict(self.headers.items()),
                "body": raw.decode("utf-8", "replace"),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _echo  # noqa: N815 — BaseHTTPRequestHandler dispatch names
    do_POST = _echo  # noqa: N815

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
