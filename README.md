# php-scan

**English** | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md)

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-non--commercial-orange)

CVE-2026-109618 / CVE-2026-109619 **exposure & prerequisite scanner**
for legacy PHP applications.

Single-file, zero-dependency (Python 3 stdlib only), **strictly
non-destructive**: never sends memory-corruption payloads, never stalls
connections, never injects executable code (inert markers only).

> ⚖️ **License**: Personal, non-commercial use only (learning, research,
> authorized testing). **Commercial use requires written permission —
> contact jacklika.business@gmail.com. Unauthorized commercial use will
> be prosecuted.** See [LICENSE](LICENSE) (trilingual).

---

## ✨ Features

| Mode | What it does |
|---|---|
| `--target` | Remote black-box probe: HTTP headers, **worst-of PHP version fingerprint** (a reassuring banner can't mask a vulnerable build), SAPI inference, session-cookie-name learning, `upload_progress` reachability (with **PUT fallback** for PHP 8.4 `request_parse_body`), session fixation, filename-marker injection |
| `--crawl` *(default)* | **Same-domain recursive crawler** — follows links + form actions, skips static assets & external domains, scans every discovered page (`--no-crawl` to scan only the given URL) |
| `--targets` + `--threads` | Batch scan — one URL per line (`#` comments), parallel workers |
| `--path` | Local audit: ini / `.htaccess` / **php-fpm pool** / Dockerfile evidence, **runtime ground truth** via `php -r`, distro **backport detection** (`dpkg`/`rpm` vs vendor-fixed advisories), code sinks (`unserialize`, LFI, handler mismatch), POP-gadget packages |
| `--confirm` | **Behavioral confirmation** via `--session-path` / `--exec-cmd`: session-file creation, marker in session data, **3-strategy OOM fingerprint** (`chunked` / `headers` / `nested`), `host_patch_status` ground truth |
| `--emit-rules` | Export **Suricata / ModSecurity / Sigma** detection rules |

New signal depth: **SID heap-leak signature** (anomalous session cookies),
**response-body IoCs** (`Session object destruction failed`,
`Unknown on line 0`), `display_errors` fingerprinting, edge-WAF
awareness, mitigation audit, and honest negative states.

## 🚀 Usage

```bash
# Remote scan — crawls the same domain automatically
python3 php_scan.py --target https://example.com/

# Scan only the given URL
python3 php_scan.py --target https://example.com/ --no-crawl

# Tune the crawl
python3 php_scan.py --target https://example.com/ --crawl-depth 2 --max-pages 30

# Batch + threads + only the interesting findings
python3 php_scan.py --targets urls.txt --threads 8 \
    --status confirmed,exposed,leak_signature --min-severity high -q

# Local source/config audit
python3 php_scan.py --path /srv/legacy-app/

# Behavioral confirmation (host-side channel)
python3 php_scan.py --target http://127.0.0.1:18080 --confirm \
    --session-path /var/lib/php/sessions \
    --exec-cmd 'docker exec php-fpm sh -c "{cmd}"'

# Authenticated scan (session cookies stripped — scanner uses its own SID)
python3 php_scan.py --target https://example.com --cookie 'k=v; …'

# IDS/Sigma detection rules for your SOC
python3 php_scan.py --emit-rules ./detection/
```

## ⚙️ Options

| Option | Description |
|---|---|
| `--target URL` | Remote target URL |
| `--targets FILE` | Batch targets, one URL per line (`#` comments) |
| `--crawl` / `--no-crawl` | Same-domain crawl — **on by default** with `--target` |
| `--crawl-depth N` | Crawl link depth (default `3`) |
| `--max-pages N` | Crawl page cap (default `50`) |
| `--path DIR` | Local PHP project dir for code/config audit |
| `--probe-path PATH` | Endpoint override (default: path from `--target`) |
| `--cookie 'k=v;…'` | Auth cookie (session-id cookies are stripped) |
| `--progress-name NAME` | Field name if `session.upload_progress.name` was renamed |
| `--confirm` | Enable behavioral confirmation |
| `--session-path DIR` | `session.save_path`, local or via `--exec-cmd` |
| `--exec-cmd 'TPL'` | Host exec template, `{cmd}` placeholder |
| `--oom-mb N` | OOM probe body size (default `64`) |
| `--confirm-oom` | Force the OOM probe past SAPI/version heuristics |
| `--oom-strategy S` | `auto` / `chunked` / `headers` / `nested` |
| `--json` | Emit JSON to stdout |
| `--output FILE` | Report path; suffix picks format (`.xlsx`/`.md`/`.json`) |
| `--cumulative` | Append to shared `reports/php-scan-results.xlsx` |
| `--report-format F` | `xlsx` / `md` / `json` for the auto-named report |
| `--no-report` | Skip report file entirely |
| `--threads N` | Parallel workers for batch/crawl (default `1`) |
| `--timeout N` | Per-request timeout (default `10`s) |
| `-q, --quiet` | Print reports with severity ≥ medium only |
| `--status a,b` | Show only checks with these statuses |
| `--hide-status a,b` | Hide checks with these statuses |
| `--check REGEX` | Filter checks by name/desc/detail |
| `--min-severity S` | Verdict floor (default `info`) |
| `--emit-rules DIR` | Write Suricata/ModSecurity/Sigma rules |

## 🔍 Output filters

```bash
--status confirmed,exposed,affected,leak_signature   # signal only
--hide-status info,unknown,done,not_applicable       # hide noise
--check 'oom|upload'                                  # regex on checks
--min-severity high -q                                # high+ verdicts only
```

## 📊 Reports

Each run writes **one timestamped file** to
`<script_dir>/reports/<YYYYMMDD-HHMMSS>_<domain[-port]>_<SEV>.<fmt>`
— e.g. `20261023-112935_www.example.com_CRITICAL.xlsx`.

Three worksheets (Traditional Chinese labels, wrapped cells, autoFilter):

| Sheet | Contents |
|---|---|
| 掃描記錄 | timestamp / target / severity / verdict summary |
| 檢查明細 | every check — status, description, raw evidence (respects `--status`/`--hide-status`/`--check`) |
| 判定 | verdict lines per target (respects `--min-severity`) |

`--cumulative` appends into the shared workbook instead (schema-tolerant
row merge). Exit code is `1` when any target is ≥ `high` → CI-friendly.

## 🧭 Verdict semantics

| Status | Meaning |
|---|---|
| `affected` | Version inside affected range (< 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) — **exposure, not proof of exploitability** |
| `eol` | EOL branch — no official patch exists |
| `patched` / `likely_patched` | Fixed release, or delayed-OOM shape observed |
| `confirmed` | Behavioral fingerprint verified host-side |
| `leak_signature` / `crash_signature` | Heap leak via session cookie / worker did not recover — **critical** |
| `likely_exposed` / `needs_host_check` | Trigger accepted; needs host-side confirmation |
| `resisted` / `not_triggered` / `inconclusive` | Honest negatives — never overclaimed |

**`affected` ≠ `exploitable`.** The scanner reports exposure +
prerequisites + mitigations — never fake "RCE success".

## ⚠️ Limitations

- Banners can lie — distro backports don't change the version string;
  `host_patch_status` / `vendor_packages` give ground truth when reachable
- 405 ≠ safe: the rfc1867 handler runs at request startup, **before**
  routing — confirm via host channel
- Edge WAF/CDN may drop probes → reported as `inconclusive`, retry inside
- Session-file confirmation needs `--session-path` / `--exec-cmd`
- Code-sink scan is regex-level heuristic

## 🛡 Mitigation checklist

- Upgrade ≥ **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** (EOL → upgrade or isolate)
- `session.upload_progress.enabled = Off` *(blocks the 109619 session arm
  only — the 109618 OOM still needs the patch)*
- `session.use_only_cookies = 1`; unify `session.serialize_handler`
- `expose_php = Off`; audit `unserialize()` / dynamic `include` sinks
- php-fpm: `pm.max_requests=1` mitigates the stale-BG chain

---

**For authorized security assessment only.**
Commercial use requires written permission — contact
jacklika.business@gmail.com.
