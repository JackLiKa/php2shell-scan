# php-scan

**English** | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md)

CVE-2026-109618 / CVE-2026-109619 **exposure & prerequisite scanner**
for legacy PHP applications.

Single-file, zero-dependency (Python 3 stdlib only), **strictly
non-destructive**: never sends memory-corruption payloads, never stalls
connections, never injects executable code (inert markers only).

> ⚖️ **License**: Personal, non-commercial use only (learning, research,
> authorized testing). **Commercial use requires written permission —
> contact https://github.com/JackLiKa. Unauthorized commercial use will
> be prosecuted.** See [LICENSE](LICENSE) (trilingual).

---

## Features

| Mode | What it does |
|---|---|
| `--target` | Remote black-box probe of a single endpoint: HTTP headers, PHP version, SAPI inference, session-cookie-name learning, `session.upload_progress` reachability, session fixation, filename-marker injection |
| `--targets` | Batch scan — one URL per line (`#` comments allowed) |
| `--crawl` | **Same-domain recursive crawler** — BFS follows links + form actions, skips static assets & external domains, then scans every discovered page and endpoint |
| `--path` | Local source/config audit: `*.ini` / `.htaccess` settings, Dockerfile/compose image tags (version + SAPI evidence), nginx/apache/fpm confs, `composer.json`/`.lock` + known POP-gadget packages, code sinks (`unserialize`/LFI/serialize-handler mismatch), magic-method gadgets |
| `--confirm` | **Behavioral confirmation** — actually triggers benign primitives and verifies them host-side (session file creation, marker in session data, mod_php "Unknown on line 0" OOM signature) via `--session-path` / `--exec-cmd` |

## Usage

```bash
# Remote probe of a single endpoint
python3 php_scan.py --target https://example.com --probe-path /login

# Recursive same-domain crawl + scan
python3 php_scan.py --target https://example.com --crawl \
    --crawl-depth 2 --max-pages 30

# Batch scan
python3 php_scan.py --targets targets.txt

# Local source/config audit
python3 php_scan.py --path /srv/legacy-app/

# Behavioral confirmation (host-side channel)
python3 php_scan.py --target http://127.0.0.1:18080 --confirm \
    --session-path /tmp \
    --exec-cmd 'docker exec php-fpm sh -c "{cmd}"'

# Authenticated scan (session cookies stripped — scanner uses its own SID)
python3 php_scan.py --target https://example.com \
    --cookie 'PHPSESSID=xxx; other=val' --confirm

# Report control — default appends to reports/php-scan-results.xlsx
python3 php_scan.py --target https://example.com --output out.md  # .md/.json/.xlsx
python3 php_scan.py --target https://example.com --no-report      # stdout only
```

## Report

Every scan appends to a **single cumulative workbook**
`reports/php-scan-results.xlsx` (Traditional Chinese labels, wrapped
cells, column widths). Three sheets:

- **掃描記錄** — timestamp / target / severity / verdict summary (one row per scan)
- **檢查明細** — every check with status, description and raw evidence
- **判定** — verdict lines per target with severity

Severity: `critical` / `high` / `medium` / `low` / `info`
(affected + mod_php, or a confirmed OOM signature → `critical`;
EOL versions → `critical`).

## Verdict semantics

| Status | Meaning |
|---|---|
| `affected` | PHP version inside the officially affected range (< 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) — **exposure, not proof of exploitability** |
| `eol` | EOL branch (e.g. PHP ≤ 8.1): no official patch exists |
| `patched` | Version ≥ fixed release (the Chain A filename-injection primitive persists by design — the patch does not cover it) |
| `confirmed` | Behavioral fingerprint verified host-side (real trigger, real evidence) |
| `likely_exposed` / `needs_host_check` | Trigger accepted remotely; host-side confirmation required |
| `resisted` / `not_triggered` / `inconclusive` | Honest negative / indeterminate states — never overclaimed |

**`affected` ≠ `exploitable`.** CVE-2026-109618 has no side-effect-free
remote exploit-verification method; the scanner reports exposure +
prerequisites + mitigation — never fake "RCE success".

## Limitations

- With `expose_php=Off` the version cannot be judged remotely → use
  `--path` or `php -v` on the host
- Session-file confirmation needs a host-side channel
  (`--session-path` / `--exec-cmd`)
- Front WAF/CDN (ESA, Cloudflare …) may drop probes → reported honestly
  as `inconclusive`, never forced
- Code-sink scan is regex-level heuristics; framework wrappers /
  indirect calls may be missed
- Does not check `fatal_error_backtraces` (PHP 8.5 arm) or OPcache state

## Mitigation checklist

- Upgrade ≥ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (EOL versions must
  upgrade — no patch exists)
- `session.upload_progress.enabled = Off` (primary trigger surface)
- `session.use_only_cookies = 1`; unify `session.serialize_handler`
- `expose_php = Off`; audit `unserialize()` and dynamic `include` sinks
- Isolate EOL deployments behind VPN / ACL

---

**For authorized security assessment only.**
Commercial use requires written permission — contact
https://github.com/JackLiKa.
