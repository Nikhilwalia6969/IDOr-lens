import json
import os
from pathlib import Path
import threading
import unittest
from unittest.mock import patch
from http.server import HTTPServer, BaseHTTPRequestHandler
import idor_lens as lens
from demo_server import Handler


class Tests(unittest.TestCase):
    def test_classification(self):
        def response(status, data):
            return {"status": status, "json": data}
        self.assertEqual(lens.classify(True, response(200, {"id": "202"}), "/id", "202"), "potential_idor")
        for data in [{"error": "login required"}, {"id": "101"}, None]:
            self.assertEqual(lens.classify(True, response(200, data), "/id", "202"), "inconclusive")
        for status in [401, 403, 404]:
            self.assertEqual(lens.classify(True, response(status, {}), "/id", "202"), "access_denied_observed")
        self.assertEqual(lens.classify(False, response(200, {"id": "202"}), "/id", "202"), "inconclusive_baseline")
        self.assertEqual(lens.classify(True, response(None, None), "/id", "202"), "inconclusive")

    def test_pointer(self):
        self.assertEqual(lens.lookup({"a/b": [{"~id": 42}]}, "/a~1b/0/~0id"), 42)

    def config(self):
        return json.loads((Path(__file__).resolve().parents[1] / "examples/demo_config.json").read_text())

    @patch.dict(os.environ, {"IDOR_ALICE_AUTH": "Bearer demo-alice", "IDOR_BOB_AUTH": "Bearer demo-bob"})
    def test_end_to_end(self):
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = self.config()
            config["base_url"] = f"http://127.0.0.1:{server.server_port}"
            config["requests_per_second"] = 10
            report = lens.scan(config)
            self.assertEqual([r["result"] for r in report["results"]], ["potential_idor"] * 2 + ["access_denied_observed"] * 2)
            serialized = json.dumps(report)
            self.assertNotIn("demo-alice", serialized)
            self.assertNotIn("Demo notebook", serialized)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    @patch.dict(os.environ, {"IDOR_ALICE_AUTH": "Bearer demo-alice", "IDOR_BOB_AUTH": "Bearer demo-bob"})
    def test_rate_limit_stops(self):
        class Limited:
            count = 0
            def get(self, *args):
                self.count += 1
                return {"status": 429, "json": {}}
        client = Limited()
        report = lens.scan(self.config(), client)
        self.assertTrue(report["stopped_on_rate_limit"])
        self.assertEqual(client.count, 1)

    def test_redirect_not_followed(self):
        hits = []
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/destination")
                self.end_headers()
            def log_message(self, *args):
                pass
        server = HTTPServer(("127.0.0.1", 0), Redirect)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            response = lens.Client(10).get(f"http://127.0.0.1:{server.server_port}/start", {})
            self.assertEqual(response["status"], 302)
            self.assertEqual(hits, ["/start"])
        finally:
            server.shutdown()
            thread.join()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
