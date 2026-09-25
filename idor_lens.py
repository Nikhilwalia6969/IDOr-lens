#!/usr/bin/env python3
"""Compare object access between two controlled accounts. Python 3.10+."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

LIMIT = 1_048_576


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def lookup(document, pointer):
    """Resolve an RFC 6901 JSON pointer, including array indices."""
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise ValueError("JSON pointers must start with /")
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(document, list):
            if not part.isdigit():
                raise KeyError(part)
            document = document[int(part)]
        else:
            document = document[part]
    return document


def validate(config):
    base = urlsplit(config["base_url"])
    if (base.scheme not in {"https", "http"} or not base.hostname
            or base.username or base.password or base.query or base.fragment
            or base.path not in {"", "/"}):
        raise ValueError("base_url must be an HTTP(S) origin without credentials")
    if base.scheme == "http" and base.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Use HTTPS for remote targets")
    rate = config.get("requests_per_second", 1)
    if not isinstance(rate, (int, float)) or not math.isfinite(rate) or not 0 < rate <= 10:
        raise ValueError("requests_per_second must be greater than 0 and at most 10")
    accounts = config["accounts"]
    if len(accounts) != 2:
        raise ValueError("Exactly two controlled accounts are required")
    names = [a["name"] for a in accounts]
    if len(set(names)) != 2:
        raise ValueError("Account names must differ")
    credentials = []
    for account in accounts:
        headers = {}
        for header, env in account["headers_from_env"].items():
            if header.lower() not in {"authorization", "cookie", "x-api-key"}:
                raise ValueError("Supported credential headers: Authorization, Cookie, X-API-Key")
            value = os.environ.get(env)
            if not value or "\n" in value or "\r" in value:
                raise ValueError("Missing or invalid credential environment variable")
            headers[header.lower()] = value
        if not headers:
            raise ValueError("Each account needs credential headers")
        credentials.append(headers)
    if credentials[0] == credentials[1]:
        raise ValueError("Account credentials must differ")
    cases = config["cases"]
    if not cases:
        raise ValueError("At least one case is required")
    for case in cases:
        path = case["path"]
        if not path.startswith("/") or path.startswith("//") or "#" in path or "\\" in path:
            raise ValueError("Case paths must be relative to base_url")
        if path.count("{id}") != 1 or any(ord(c) < 33 for c in path):
            raise ValueError("Each path needs exactly one {id} and no whitespace")
        if set(case["objects"]) != set(names):
            raise ValueError("Each case needs one known object per account")
        ids = list(case["objects"].values())
        if any(type(i) not in {str, int} or not str(i) for i in ids) or str(ids[0]) == str(ids[1]):
            raise ValueError("Object IDs must be distinct nonempty strings or integers")
        if not case["id_pointer"].startswith("/"):
            raise ValueError("id_pointer must identify an object ID field")
    return credentials


class Client:
    def __init__(self, rate):
        self.interval = 1 / rate
        self.last = 0.0
        # No ambient proxy, cookie jar, redirect following, or credential forwarding.
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def get(self, url, headers):
        time.sleep(max(0, self.interval - (time.monotonic() - self.last)))
        self.last = time.monotonic()
        try:
            request = Request(url, headers={"Accept": "application/json", **headers})
            try:
                response = self.opener.open(request, timeout=10)
            except HTTPError as exc:
                response = exc
            with response:
                body = response.read(LIMIT + 1)
                result = {"status": response.code, "bytes": len(body),
                          "truncated": len(body) > LIMIT, "json": None}
                if len(body) <= LIMIT:
                    result["sha256"] = hashlib.sha256(body).hexdigest()
                    try:
                        result["json"] = json.loads(body)
                    except (ValueError, UnicodeError):
                        pass
                return result
        except (URLError, TimeoutError, OSError, ValueError):
            return {"status": None, "error": "request_failed", "json": None}


def matches(response, pointer, expected):
    if response.get("truncated") or not 200 <= (response["status"] or 0) < 300:
        return False
    try:
        value = lookup(response["json"], pointer)
        return type(value) in {str, int} and str(value) == str(expected)
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def evidence(response):
    return {key: value for key, value in response.items() if key != "json"}


def classify(baseline_ok, response, pointer, expected):
    if not baseline_ok:
        return "inconclusive_baseline"
    if matches(response, pointer, expected):
        return "potential_idor"
    if response["status"] in {401, 403, 404}:
        return "access_denied_observed"
    return "inconclusive"


def scan(config, client=None):
    headers = validate(config)
    client = client or Client(config.get("requests_per_second", 1))
    names = [a["name"] for a in config["accounts"]]
    rows = []
    stopped = False
    for number, case in enumerate(config["cases"], 1):
        baseline = {}
        def fetch(actor, owner):
            oid = case["objects"][names[owner]]
            url = config["base_url"].rstrip("/") + case["path"].replace("{id}", quote(str(oid), safe=""))
            return client.get(url, headers[actor])
        for owner in range(2):
            baseline[owner] = fetch(owner, owner)
            if baseline[owner]["status"] == 429:
                stopped = True
                break
        if stopped:
            break
        baseline_ok = all(matches(baseline[i], case["id_pointer"], case["objects"][names[i]]) for i in range(2))
        for actor, owner in [(0, 1), (1, 0)]:
            response = fetch(actor, owner)
            rows.append({"case": number, "actor": names[actor], "owner": names[owner],
                         "result": classify(baseline_ok, response, case["id_pointer"], case["objects"][names[owner]]),
                         "owner_baseline": evidence(baseline[owner]),
                         "actor_baseline": evidence(baseline[actor]),
                         "cross_account": evidence(response)})
            if response["status"] == 429:
                stopped = True
                break
        if stopped:
            break
    return {"tool": "IDOR Lens", "version": "1.0.0", "stopped_on_rate_limit": stopped,
            "complete": not stopped, "results": rows,
            "note": "Candidates require manual ownership, identity, and access-policy verification."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--output", type=Path, default=Path("reports/report.json"))
    args = parser.parse_args()
    try:
        report = scan(json.loads(args.config.read_text()))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"Configuration or output error ({type(exc).__name__}); check config and environment.\n")
    for row in report["results"]:
        print(f"Case {row['case']}: {row['actor']} -> {row['owner']}: {row['result']}")
    print(f"Report: {args.output}")
    if report["stopped_on_rate_limit"]:
        print("Stopped: server returned HTTP 429.")
        return 2
    return 1 if any(r["result"] == "potential_idor" for r in report["results"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
