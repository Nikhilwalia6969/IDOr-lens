# IDOR Lens

**Two accounts. Known objects. Repeatable access-control checks.**

A dependency-free Python CLI that checks whether one authenticated account can read an object belonging to another. Built for authorized labs and assessments, with a reproducible local demonstration.

IDOR (Insecure Direct Object Reference) occurs when a server accepts a reference to an object without enforcing the caller's access rights. This tool tests a supplied access-control hypothesis: the two accounts should not be able to read each other's objects.

## Quick start

Requires Python **3.10+**. Works on macOS, Linux, and Windows; no pip packages required.

Extract this project, open a terminal in its folder, and start the synthetic lab:

```bash
python3 demo_server.py
```

In a second terminal, from the same folder:

```bash
export IDOR_ALICE_AUTH='Bearer demo-alice'
export IDOR_BOB_AUTH='Bearer demo-bob'
python3 idor_lens.py examples/demo_config.json --output reports/demo.json
```

PowerShell users can set credentials with `$env:IDOR_ALICE_AUTH = 'Bearer demo-alice'` and `$env:IDOR_BOB_AUTH = 'Bearer demo-bob'`, then use `python` if that is their interpreter command.

Expected output:

```text
Case 1: alice -> bob: potential_idor
Case 1: bob -> alice: potential_idor
Case 2: alice -> bob: access_denied_observed
Case 2: bob -> alice: access_denied_observed
Report: reports/demo.json
```

The vulnerable route checks authentication but omits object ownership enforcement. The secure route enforces ownership and returns 403 for cross-account access. All demo objects and tokens are fictional; the lab binds only to localhost.

## How the comparison works

For each endpoint, the tool sends four GET requests:

| Request | Purpose |
| --- | --- |
| Alice reads Alice's object | Validate Alice's baseline |
| Bob reads Bob's object | Validate Bob's baseline |
| Alice reads Bob's object | Check cross-account access |
| Bob reads Alice's object | Check the reverse direction |

Both baselines must return a successful response containing the expected object ID at the configured JSON pointer. A cross-account response becomes a candidate only if it also contains the target object's expected ID. IDs can be strings, integers, or UUID strings; values are URL-encoded.

## Configure an authorized target

Copy `examples/demo_config.json` to `config.local.json`. Set `base_url` to an HTTPS origin, configure the credential environment variables, and supply one known private object per account for each case. The two accounts must actually be different users with the intended roles; distinct token strings alone cannot establish identity.

Example case:

```json
{
  "path": "/api/orders/{id}",
  "id_pointer": "/data/id",
  "objects": {"alice": "alice-owned-object", "bob": "bob-owned-object"}
}
```

Query parameters also work: `/api/order?order_id={id}`. JSON pointers support nested fields, arrays, and `~0` / `~1` escaping. Credential headers supported: `Authorization`, `Cookie`, and `X-API-Key`. Each `headers_from_env` value is an environment variable name; its value is the complete header value, including `Bearer ` where required.

```bash
python3 idor_lens.py config.local.json --output reports/assessment.json
```

Use only against systems you own or have permission to assess. Verify the selected GET endpoints are safe to read before running.

## Results and interpretation

| Result | Meaning |
| --- | --- |
| `potential_idor` | Both baselines worked and cross-account access returned the expected ID; inspect the actual data and access policy manually |
| `access_denied_observed` | Cross-account request returned 401, 403, or 404 after valid baselines |
| `inconclusive_baseline` | At least one account could not retrieve its expected own object |
| `inconclusive` | Redirect, network error, unexpected JSON, oversized response, or another ambiguous result |

A candidate is **not a confirmed vulnerability**. Public objects, shared permissions, ID echoes, and application errors can still create false positives. An observed denial is only evidence for this request and session, not proof that the entire endpoint is secure. Exit code 0 does not certify security: inspect inconclusive results.

Reports include status codes, response sizes, and SHA-256 fingerprints of complete response bodies, but omit response bodies, credentials, URLs, and object IDs. Case numbers map to the configuration order. Account labels and response metadata remain sensitive assessment information; review any report before publishing it. Fingerprints can differ due to timestamps or dynamic fields and do not drive classification.

## Operational details

- Default global rate: one request per second; configurable up to ten.
- Stops immediately on HTTP 429; no automatic retries.
- Ten-second socket timeout and 1 MiB response body limit; oversized responses are inconclusive. The timeout is not a whole-scan deadline.
- TLS verification enabled. Plain HTTP restricted to localhost for the demo.
- Redirects are recorded, never followed. No ambient proxies or shared cookie jar.
- No range enumeration, endpoint discovery, session refresh, JavaScript execution, POST/PUT/DELETE, or automatic exploitation.
- Credentials come from the environment. Never commit real tokens or assessment configurations.

Exit codes: **0** = completed with no candidates (may include inconclusive results); **1** = candidates found; **2** = configuration/output failure or rate-limit interruption.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Tests exercise the local HTTP lab, positive and negative classification, invalid baselines, JSON pointers, HTTP 429 stopping, and redirect isolation. No external target is contacted by the tests.

## Portfolio discussion

The interesting engineering decisions are baseline validation, explicit object matching, bidirectional access checks, and conservative interpretation. Be ready to explain why a 200 response cannot prove IDOR, how shared objects complicate findings, and why object-level authorization belongs on the server. Future extensions could add identity endpoint checks and application-specific response validators.

## Bash and PHP versions

The repository also includes native Bash and PHP implementations. Both use the **same configuration file**, credentials, matching logic, report structure, and exit codes as the Python version. Neither invokes Python.

| Implementation | Requirements | Command |
| --- | --- | --- |
| Bash | Bash 3.2+, curl 8.4+, jq 1.6+, shasum | `bash idor_lens.sh examples/demo_config.json --output reports/bash.json` |
| PHP | PHP 8.1+ CLI with the cURL extension | `php idor_lens.php examples/demo_config.json --output reports/php.json` |

Start the supplied Python demo server and export the two demo credentials as shown in Quick start, then run either command. Python is needed only for that demo server and the integration test suite, not for the Bash or PHP scanners themselves. In Bash, account 0 is the first configured account and account 1 is the second; reports contain the configured names.

Bash writes temporary response data and header files into a private temporary directory, then removes it on normal exit or handled interruption. Abrupt termination such as SIGKILL can leave that directory behind. Curl credentials are read from these files rather than placed in command-line arguments. PHP holds credentials and response data in memory. Both ports use a ten-second total request timeout. Bash conservatively waits the configured interval before every request, so its actual rate may be lower than requested.

For oversized responses, `bytes` in the ports is the number of retained bytes (Bash records zero when curl aborts); it is not the full response size. No fingerprint is reported for an incomplete response. Bash requires curl 8.4+ to enforce the size limit during streaming, including responses without a Content-Length header.

`tests/test_ports.py` checks vulnerable access, protected access, expired-session responses, redirects, and rate-limit interruption for both ports. Missing runtimes are reported as skipped. In the build workspace, Bash passed these checks; PHP could not be executed because its runtime was unavailable. Run the following on a machine with PHP and ext-curl before publishing the PHP version as tested:

```bash
php -l idor_lens.php
python3 -m unittest discover -s tests -v
```
