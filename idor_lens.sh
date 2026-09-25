#!/usr/bin/env bash
# IDOR Lens: Bash 3.2+, curl 8.4+, jq 1.6+, shasum. No Python/PHP required.
set -euo pipefail
umask 077
fail() { printf '%s\n' "$1" >&2; exit 2; }
for dep in curl jq shasum; do command -v "$dep" >/dev/null || fail "Missing dependency: $dep"; done
[[ $# == 1 || ( $# == 3 && ${2:-} == --output ) ]] || fail 'Usage: bash idor_lens.sh CONFIG [--output REPORT]'
curl_version=$(curl -q --version | head -n 1 | cut -d ' ' -f 2)
curl_major=${curl_version%%.*}
curl_rest=${curl_version#*.}
curl_minor=${curl_rest%%.*}
[[ $curl_major =~ ^[0-9]+$ && $curl_minor =~ ^[0-9]+$ ]] || fail 'Cannot determine curl version.'
(( curl_major > 8 || (curl_major == 8 && curl_minor >= 4) )) || fail 'curl 8.4+ is required for streamed response size limits.'
config=$1
output=${3:-reports/report.json}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
jq -e '
  (.base_url | type == "string" and test("^https?://(\\[[0-9a-fA-F:]+\\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?/?$")) and
  (.base_url | startswith("https://") or test("^http://(localhost|127\\.0\\.0\\.1|\\[::1\\])(:[0-9]{1,5})?/?$")) and
  ((.requests_per_second // 1) | type == "number" and . > 0 and . <= 10) and
  (.accounts | type == "array" and length == 2) and
  (.accounts[0].name != .accounts[1].name) and
  (all(.accounts[]; (.name | type == "string" and length > 0) and
    (.headers_from_env | type == "object" and length > 0) and
    all(.headers_from_env | to_entries[]; (.key | ascii_downcase | . == "authorization" or . == "cookie" or . == "x-api-key") and (.value | type == "string" and test("^[A-Za-z_][A-Za-z0-9_]*$"))))) and
  (.accounts | map(.name) | sort) as $names |
  . and (.cases | type == "array" and length > 0) and
  all(.cases[];
    (.path | type == "string" and startswith("/") and (startswith("//") | not) and (test("[\\x00-\\x20\\x7f#\\\\]") | not) and (split("{id}") | length == 2)) and
    (.id_pointer | type == "string" and startswith("/")) and
    (.objects | keys == $names) and
    all(.objects[]; (type == "string" or type == "number" and floor == .) and (tostring | length > 0)) and
    ([.objects[] | tostring] | unique | length == 2))
' "$config" >/dev/null 2>&1 || fail 'Invalid configuration.'
base=$(jq -r .base_url "$config")
interval=$(jq -r '1 / (.requests_per_second // 1)' "$config")
for actor in 0 1; do
  : > "$tmp/headers-$actor"
  while IFS=$'\t' read -r header envname; do
    value=${!envname:-}
    [[ -n $value && $value != *$'\r'* && $value != *$'\n'* ]] || fail 'Missing or invalid credential environment variable.'
    printf '%s: %s\n' "$header" "$value" >> "$tmp/headers-$actor"
  done < <(jq -r --argjson a "$actor" '.accounts[$a].headers_from_env | to_entries | sort_by(.key | ascii_downcase)[] | [(.key | ascii_downcase), .value] | @tsv' "$config")
done
cmp -s "$tmp/headers-0" "$tmp/headers-1" && fail 'Account credentials must differ.'
cat > "$tmp/match.jq" <<'JQ'
def lookup($p): reduce ($p | ltrimstr("/") | split("/")[] | gsub("~1"; "/") | gsub("~0"; "~")) as $k (.; if type == "array" then .[$k | tonumber] else .[$k] end);
(.status >= 200 and .status < 300 and (.truncated != true)) and
(try (.json | lookup($p) | (type == "string" or type == "number") and tostring == $id) catch false)
JQ
fetch() {
  local actor=$1 owner=$2 dest=$3 oid encoded path url code rc bytes digest
  oid=$(jq -r --argjson c "$case_index" --argjson o "$owner" '.cases[$c].objects[.accounts[$o].name] | tostring' "$config")
  encoded=$(printf %s "$oid" | jq -sRr @uri)
  path=$(jq -r --argjson c "$case_index" '.cases[$c].path' "$config")
  url="${base%/}${path/\{id\}/$encoded}"
  sleep "$interval"
  rc=0
  code=$(curl -q --silent --globoff --proxy '' --proto '=http,https' --max-time 10 --connect-timeout 10 \
    --max-filesize 1048576 --header 'Accept: application/json' --header "@$tmp/headers-$actor" \
    --output "$tmp/body" --write-out '%{http_code}' "$url" 2>/dev/null) || rc=$?
  if [[ $rc != 0 && $rc != 63 ]]; then
    printf '%s\n' '{"status":null,"error":"request_failed","json":null}' > "$dest"
  elif [[ $rc == 63 ]]; then
    jq -n --arg s "$code" '{status:($s|tonumber),bytes:0,truncated:true,json:null}' > "$dest"
  else
    bytes=$(wc -c < "$tmp/body" | tr -d ' ')
    digest=$(shasum -a 256 "$tmp/body" | cut -d ' ' -f 1)
    jq -n --argjson s "$code" --argjson b "$bytes" --arg h "$digest" --rawfile body "$tmp/body" \
      '{status:$s,bytes:$b,truncated:false,sha256:$h,json:(try ($body|fromjson) catch null)}' > "$dest"
  fi
}
matches() { jq -e --arg p "$pointer" --arg id "$2" -f "$tmp/match.jq" "$1" >/dev/null 2>&1; }
: > "$tmp/rows"
stopped=false
case_index=0
count=$(jq '.cases|length' "$config")
while (( case_index < count )); do
  pointer=$(jq -r --argjson c "$case_index" '.cases[$c].id_pointer' "$config")
  valid=true
  for owner in 0 1; do
    fetch "$owner" "$owner" "$tmp/base-$owner"
    if [[ $(jq -r .status "$tmp/base-$owner") == 429 ]]; then stopped=true; break; fi
    oid=$(jq -r --argjson c "$case_index" --argjson o "$owner" '.cases[$c].objects[.accounts[$o].name]|tostring' "$config")
    matches "$tmp/base-$owner" "$oid" || valid=false
  done
  [[ $stopped == false ]] || break
  for actor in 0 1; do
    owner=$((1-actor))
    fetch "$actor" "$owner" "$tmp/cross"
    oid=$(jq -r --argjson c "$case_index" --argjson o "$owner" '.cases[$c].objects[.accounts[$o].name]|tostring' "$config")
    status=$(jq -r .status "$tmp/cross")
    result=inconclusive
    if [[ $valid == false ]]; then result=inconclusive_baseline
    elif matches "$tmp/cross" "$oid"; then result=potential_idor
    elif [[ $status == 401 || $status == 403 || $status == 404 ]]; then result=access_denied_observed; fi
    jq -nc --argjson c "$((case_index+1))" --arg a "$(jq -r --argjson a "$actor" '.accounts[$a].name' "$config")" \
      --arg o "$(jq -r --argjson a "$owner" '.accounts[$a].name' "$config")" --arg r "$result" \
      --slurpfile b "$tmp/base-$owner" --slurpfile ab "$tmp/base-$actor" --slurpfile x "$tmp/cross" \
      '{case:$c,actor:$a,owner:$o,result:$r,owner_baseline:($b[0]|del(.json)),actor_baseline:($ab[0]|del(.json)),cross_account:($x[0]|del(.json))}' >> "$tmp/rows"
    printf 'Case %s: account %s -> account %s: %s\n' "$((case_index+1))" "$actor" "$owner" "$result"
    if [[ $status == 429 ]]; then stopped=true; break; fi
  done
  [[ $stopped == false ]] || break
  case_index=$((case_index+1))
done
mkdir -p "$(dirname "$output")"
jq -s --argjson stopped "$stopped" '{tool:"IDOR Lens",version:"1.0.0",stopped_on_rate_limit:$stopped,complete:($stopped|not),results:.,note:"Candidates require manual ownership, identity, and access-policy verification."}' "$tmp/rows" > "$output"
printf 'Report: %s\n' "$output"
[[ $stopped == false ]] || exit 2
if jq -e 'any(.results[]; .result == "potential_idor")' "$output" >/dev/null; then exit 1; fi
exit 0
