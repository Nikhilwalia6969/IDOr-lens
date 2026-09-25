#!/usr/bin/env python3
"""Local-only, intentionally vulnerable demonstration with synthetic data."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        account = {"Bearer demo-alice": "alice", "Bearer demo-bob": "bob"}.get(self.headers.get("Authorization"))
        parts = self.path.split("/")
        status, body = 404, {"error": "not found"}
        if not account:
            status, body = 401, {"error": "unauthorized"}
        elif len(parts) == 4 and parts[1] in {"vulnerable", "secure"} and parts[2] == "orders":
            owner = {"101": "alice", "202": "bob"}.get(parts[3])
            if owner:
                if parts[1] == "secure" and account != owner:
                    status, body = 403, {"error": "forbidden"}
                else:
                    status, body = 200, {"id": parts[3], "owner": owner, "item": "Demo notebook"}
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("Synthetic IDOR lab at http://127.0.0.1:8765; Ctrl+C to stop", flush=True)
    try:
        HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
