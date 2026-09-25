#!/usr/bin/env php
<?php
/** IDOR Lens: PHP 8.1+ CLI with ext-curl; same JSON config as Python. */
declare(strict_types=1);
const BODY_LIMIT = 1048576;
function fail(string $message): never { fwrite(STDERR, $message . PHP_EOL); exit(2); }
function pointer(mixed $data, string $path): mixed {
    foreach (explode('/', substr($path, 1)) as $part) {
        $part = str_replace(['~1', '~0'], ['/', '~'], $part);
        if (is_object($data) && property_exists($data, $part)) $data = $data->$part;
        elseif (is_array($data) && ctype_digit($part) && array_key_exists((int)$part, $data)) $data = $data[(int)$part];
        else return null;
    }
    return $data;
}
function matches(array $r, string $pointer, mixed $expected): bool {
    $value = pointer($r['json'] ?? null, $pointer);
    return !($r['truncated'] ?? false) && ($r['status'] ?? 0) >= 200 && ($r['status'] ?? 0) < 300
        && (is_string($value) || is_int($value)) && (string)$value === (string)$expected;
}
function evidence(array $r): array { unset($r['json']); return $r; }
function fetch(string $url, array $headers, float $rate): array {
    static $last = 0.0;
    $now = hrtime(true) / 1e9;
    usleep((int)(max(0, 1 / $rate - ($now - $last)) * 1e6));
    $last = hrtime(true) / 1e9;
    $body = ''; $truncated = false;
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_HTTPHEADER => array_merge(['Accept: application/json'], $headers),
        CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROXY => '', CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 10, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_WRITEFUNCTION => function ($ch, string $chunk) use (&$body, &$truncated): int {
            if (strlen($body) + strlen($chunk) > BODY_LIMIT) { $truncated = true; return 0; }
            $body .= $chunk; return strlen($chunk);
        }]);
    $ok = curl_exec($ch); $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE); curl_close($ch);
    if ($ok === false && !$truncated) return ['status' => null, 'error' => 'request_failed', 'json' => null];
    $r = ['status' => $status ?: null, 'bytes' => strlen($body), 'truncated' => $truncated, 'json' => null];
    if (!$truncated) { $r['sha256'] = hash('sha256', $body); $r['json'] = json_decode($body); }
    return $r;
}
if (PHP_SAPI !== 'cli') fail('Run this tool from the command line.');
if (!extension_loaded('curl')) fail('The PHP curl extension is required.');
if ($argc !== 2 && !($argc === 4 && $argv[2] === '--output')) fail('Usage: php idor_lens.php CONFIG [--output REPORT]');
try {
    $cfg = json_decode(@file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
    $base = $cfg['base_url'] ?? '';
    if (!preg_match('~^https?://(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(?::[0-9]{1,5})?/?$~D', $base)) throw new Exception();
    $u = parse_url($base);
    if ($u === false || ($u['scheme'] === 'http' && !in_array($u['host'], ['localhost','127.0.0.1','[::1]'], true))) throw new Exception();
    $rate = $cfg['requests_per_second'] ?? 1;
    if (!is_numeric($rate) || !is_finite((float)$rate) || $rate <= 0 || $rate > 10) throw new Exception();
    $accounts = $cfg['accounts'] ?? [];
    if (count($accounts) !== 2) throw new Exception();
    $names = []; $headers = []; $identities = [];
    foreach ($accounts as $a) {
        if (!is_string($a['name']) || $a['name'] === '') throw new Exception();
        $names[] = $a['name']; $h = [];
        foreach ($a['headers_from_env'] as $key => $env) {
            $key = strtolower($key); $value = getenv($env);
            if (!in_array($key, ['authorization','cookie','x-api-key'], true) || !$value || strpbrk($value, "\r\n") !== false) throw new Exception();
            $h[$key] = $value;
        }
        if (!$h) throw new Exception();
        ksort($h); $identities[] = $h;
        $headers[] = array_map(fn($k, $v) => "$k: $v", array_keys($h), array_values($h));
    }
    if ($names[0] === $names[1] || $identities[0] === $identities[1]) throw new Exception();
    if (empty($cfg['cases'])) throw new Exception();
    foreach ($cfg['cases'] as $case) {
        $path = $case['path']; $ids = $case['objects'];
        if (!is_string($path) || !str_starts_with($path, '/') || str_starts_with($path, '//') || preg_match('/[\x00-\x20\x7f#\\\\]/', $path)
            || substr_count($path, '{id}') !== 1 || !str_starts_with($case['id_pointer'], '/') || count($ids) !== 2) throw new Exception();
        foreach ($names as $name) if (!isset($ids[$name]) || (!is_string($ids[$name]) && !is_int($ids[$name])) || (string)$ids[$name] === '') throw new Exception();
        if ((string)$ids[$names[0]] === (string)$ids[$names[1]]) throw new Exception();
    }
} catch (Throwable $e) { fail('Invalid configuration or missing credential environment variable.'); }
$rows = []; $stopped = false;
foreach ($cfg['cases'] as $index => $case) {
    $request = function(int $actor, int $owner) use ($base, $case, $names, $headers, $rate): array {
        return fetch(rtrim($base, '/') . str_replace('{id}', rawurlencode((string)$case['objects'][$names[$owner]]), $case['path']), $headers[$actor], (float)$rate);
    };
    $baseline = [];
    for ($i = 0; $i < 2; $i++) {
        $baseline[$i] = $request($i, $i);
        if ($baseline[$i]['status'] === 429) { $stopped = true; break; }
    }
    if ($stopped) break;
    $valid = matches($baseline[0], $case['id_pointer'], $case['objects'][$names[0]]) && matches($baseline[1], $case['id_pointer'], $case['objects'][$names[1]]);
    foreach ([[0,1], [1,0]] as [$actor,$owner]) {
        $r = $request($actor, $owner);
        $result = !$valid ? 'inconclusive_baseline' : (matches($r, $case['id_pointer'], $case['objects'][$names[$owner]]) ? 'potential_idor' : (in_array($r['status'], [401,403,404], true) ? 'access_denied_observed' : 'inconclusive'));
        $rows[] = ['case' => $index + 1, 'actor' => $names[$actor], 'owner' => $names[$owner], 'result' => $result,
            'owner_baseline' => evidence($baseline[$owner]), 'actor_baseline' => evidence($baseline[$actor]), 'cross_account' => evidence($r)];
        printf("Case %d: %s -> %s: %s\n", $index+1, $names[$actor], $names[$owner], $result);
        if ($r['status'] === 429) { $stopped = true; break; }
    }
    if ($stopped) break;
}
$report = ['tool' => 'IDOR Lens', 'version' => '1.0.0', 'stopped_on_rate_limit' => $stopped, 'complete' => !$stopped,
    'results' => $rows, 'note' => 'Candidates require manual ownership, identity, and access-policy verification.'];
$output = $argv[3] ?? 'reports/report.json';
if (!is_dir(dirname($output)) && !@mkdir(dirname($output), 0700, true)) fail('Cannot create report directory.');
if (@file_put_contents($output, json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR)."\n") === false) fail('Cannot write report.');
echo "Report: $output\n";
exit($stopped ? 2 : (in_array('potential_idor', array_column($rows, 'result'), true) ? 1 : 0));
