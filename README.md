# php-scan

CVE-2026-109618 / CVE-2026-109619 **exposure & prerequisite scanner** —
老 PHP 项目暴露面与前置条件扫描器。

Single-file, zero-dependency (Python 3 stdlib only), **strictly
non-destructive**: never sends memory-corruption payloads, never stalls
connections, never injects executable code (inert markers only).

单文件、Python 3 标准库零依赖、**严格非破坏式**：不发内存破坏
payload、不挂起连接、不注入可执行代码（只发惰性 marker）。

> ⚖️ **License / 许可 / 許可**：Personal, non-commercial use only
> (learning, research, authorized testing). **Commercial use requires
> written permission — contact https://github.com/JackLiKa. Unauthorized
> commercial use will be prosecuted.** See [LICENSE](LICENSE).
> 仅供个人学习/测试/授权环境使用；商用须联系作者取得书面授权，违者必究。

---

## Features / 功能 / 功能

| Mode | What it does | 說明 |
|---|---|---|
| `--target` | Remote black-box probe: headers, PHP version, SAPI, session-name learning, upload_progress reachability, session fixation, filename-marker injection | 远程黑盒探测单个端点 |
| `--targets` | Batch scan, one URL per line | 批次掃描（每行一個 URL） |
| `--crawl` | **Same-domain recursive crawler** — BFS follows links + form actions, skips static assets & external domains, then scans every discovered page/endpoint | 同域遞歸爬取：自動發現頁面與表單接口並逐一掃描 |
| `--path` | Local audit: ini/.htaccess configs, Dockerfile/compose image tags (version + SAPI evidence), nginx/apache confs, composer.json/lock + known POP-gadget packages, code sinks (unserialize/LFI/handler-mismatch), magic-method gadgets | 本地代碼與配置審計 |
| `--confirm` | **Behavioral confirmation**: actually triggers benign primitives and verifies server-side (session file creation, marker in session data, mod_php "Unknown on line 0" OOM signature) via `--session-path` / `--exec-cmd` host channel | 行為確認模式：真實觸發良性原語並在主機側閉環驗證 |

## Usage / 用法

```bash
# Remote probe of a single endpoint
python3 php_scan.py --target https://example.com --probe-path /login

# Recursive same-domain crawl + scan (skips static assets & externals)
python3 php_scan.py --target https://example.com --crawl \
    --crawl-depth 2 --max-pages 30

# Batch from file
python3 php_scan.py --targets targets.txt

# Local source/config audit
python3 php_scan.py --path /srv/legacy-app/

# Behavioral confirmation (needs a host-side channel)
python3 php_scan.py --target http://127.0.0.1:18080 --confirm \
    --session-path /tmp \
    --exec-cmd 'docker exec php-fpm sh -c "{cmd}"'

# Authenticated scan (session cookie stripped — scanner uses its own SID)
python3 php_scan.py --target https://example.com \
    --cookie 'PHPSESSID=xxx; other=val' --confirm

# Report control — default appends to reports/php-scan-results.xlsx
python3 php_scan.py --target https://example.com --output out.md  # .md/.json/.xlsx
python3 php_scan.py --target https://example.com --no-report      # stdout only
```

## Report / 報告

每次扫描自动追加到**单一 Excel 文件** `reports/php-scan-results.xlsx`，
繁体中文、自动换行列宽，三个工作表：

- **掃描記錄** — 时间 / 目标 / 严重度 / 判定摘要（每次扫描一行）
- **檢查明細** — 每个检查项的状态与原始证据
- **判定** — 每个目标的结论，带严重度

Severity 严重度：`critical` / `high` / `medium` / `low` / `info`
（affected + mod_php 或 confirmed OOM → critical；EOL 版本 → critical）

## Verdict semantics / 判定語義

| Status | Meaning |
|---|---|
| `affected` | PHP version inside the officially affected range (< 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) — **exposure, not proof of exploitability** |
| `eol` | EOL branch (e.g. PHP ≤ 8.1): no official patch exists |
| `patched` | Version ≥ fixed release (Chain A filename-injection primitive persists by design — patch doesn't cover it) |
| `confirmed` | Behavioral fingerprint verified on the host side (real trigger, real evidence) |
| `likely_exposed` / `needs_host_check` | Trigger accepted remotely; host-side confirmation needed |
| `resisted` / `not_triggered` / `inconclusive` | Honest negative/indeterminate states — never overclaimed |

**`affected` ≠ `exploitable`.** CVE-2026-109618 has no side-effect-free
remote exploit-verification method; the scanner reports exposure +
prerequisites + mitigation, never fake "RCE success".

`affected` ≠ 可利用——本工具输出「受影响版本 + 哪些前置条件成立 +
缓解建议」，绝不虚报「打进去了」。

## Limitations / 限制

- `expose_php=Off` 时远程无法判版本 → 用 `--path` 或主机 `php -v` 确认
- session 文件确认需要主机侧通道（`--session-path` / `--exec-cmd`）
- 前置 WAF/CDN（ESA、Cloudflare 等）会拦截部分探针 → 状态如实标
  `inconclusive`，不硬判
- 代码 sink 扫描是 regex 级启发式，框架封装/间接调用可能漏报
- 不检测 `fatal_error_backtraces`（PHP 8.5 arm）与 OPcache 状态

## Mitigation checklist / 緩解建議

- 升级 ≥ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12（EOL 版本必须升级，无补丁）
- `session.upload_progress.enabled = Off`（两条链的主要触发面）
- `session.use_only_cookies = 1`、统一 `session.serialize_handler`
- `expose_php = Off`、审计 `unserialize()` 与动态 `include` sink
- EOL 版本隔离 / VPN 限制访问

---

**For authorized security assessment only. / 仅限授权安全测试。**
Commercial use requires written permission — contact
https://github.com/JackLiKa. 商用请联系授权，非法必究。
