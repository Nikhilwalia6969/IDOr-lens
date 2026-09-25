"""Integration checks shared by Bash and PHP; unavailable runtimes are skipped."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler

ROOT = Path(__file__).resolve().parents[1]

class PortTests(unittest.TestCase):
    def run_port(self, command):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                mode, oid = self.path.strip('/').split('/')
                own = {'Bearer demo-alice':'101', 'Bearer demo-bob':'202'}.get(self.headers.get('Authorization'))
                status, data = 200, {'id':oid}
                if mode == 'secure' and oid != own: status, data = 403, {}
                if mode == 'expired': status, data = 200, {'error':'login'}
                if mode == 'redirect': status, data = 302, {}
                if mode == 'limited': status, data = 429, {}
                self.send_response(status)
                if status == 302: self.send_header('Location', '/vulnerable/'+oid)
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())
            def log_message(self, *args): pass
        server = HTTPServer(('127.0.0.1',0),Handler)
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                cfg=json.loads((ROOT/'examples/demo_config.json').read_text())
                cfg['base_url']=f'http://127.0.0.1:{server.server_port}'
                cfg['requests_per_second']=10
                env=dict(os.environ,IDOR_ALICE_AUTH='Bearer demo-alice',IDOR_BOB_AUTH='Bearer demo-bob')
                for mode, expected, exit_code in [('vulnerable','potential_idor',1),('secure','access_denied_observed',0),('expired','inconclusive_baseline',0),('redirect','inconclusive_baseline',0),('limited',None,2)]:
                    cfg['cases']=[{'path':f'/{mode}/{{id}}','id_pointer':'/id','objects':{'alice':'101','bob':'202'}}]
                    config=Path(td)/'config.json'; config.write_text(json.dumps(cfg))
                    report=Path(td)/'report.json'
                    run=subprocess.run(command+[str(config),'--output',str(report)],cwd=ROOT,env=env,capture_output=True,text=True,timeout=20)
                    self.assertEqual(run.returncode,exit_code,run.stderr)
                    data=json.loads(report.read_text())
                    self.assertEqual(data['stopped_on_rate_limit'],mode=='limited')
                    self.assertEqual([r['result'] for r in data['results']],[] if expected is None else [expected]*2)
                    self.assertNotIn('Bearer',report.read_text())
        finally:
            server.shutdown(); thread.join(); server.server_close()

    @unittest.skipUnless(all(shutil.which(x) for x in ['bash','curl','jq','shasum']), 'Bash dependencies unavailable')
    def test_bash(self): self.run_port(['bash','idor_lens.sh'])

    @unittest.skipUnless(shutil.which('php'), 'PHP runtime unavailable')
    def test_php(self): self.run_port(['php','idor_lens.php'])
