# php-scan

[English](README.md) | **简体中文** | [繁體中文](README.zh-TW.md)

CVE-2026-109618 / CVE-2026-109619 **暴露面与前置条件扫描器**，
面向老旧 PHP 项目。

单文件、Python 3 标准库零依赖、**严格非破坏式**：不发内存破坏
payload、不挂起连接、不注入可执行代码（只发惰性 marker）。

> ⚖️ **许可**：仅限个人非商业用途（学习、研究、授权测试）。
> **商用须取得书面授权——请联系 https://github.com/JackLiKa，
> 未经授权的商用行为依法追究。** 详见 [LICENSE](LICENSE)（三语）。

---

## 功能

| 模式 | 说明 |
|---|---|
| `--target` | 远程黑盒探测单个端点：HTTP 头、PHP 版本、SAPI 推断、session cookie 名自动学习、`session.upload_progress` 可达性、会话固定、文件名 marker 注入 |
| `--targets` | 批量扫描——每行一个 URL（`#` 为注释） |
| `--crawl` | **同域递归爬取**——BFS 跟随链接与表单 action，跳过静态资源与外部域名，逐一扫描发现的每个页面与接口 |
| `--path` | 本地代码/配置审计：`*.ini` / `.htaccess` 配置、Dockerfile/compose 镜像 tag（版本 + SAPI 证据）、nginx/apache/fpm 配置、`composer.json`/`.lock` 与已知 POP gadget 包、代码 sink（`unserialize`/LFI/serialize_handler 冲突）、magic method gadget |
| `--confirm` | **行为确认**——真实触发良性原语并在主机侧闭环验证（session 文件创建、marker 落盘、mod_php "Unknown on line 0" OOM 指纹），通过 `--session-path` / `--exec-cmd` 通道 |

## 用法

```bash
# 远程探测单个端点
python3 php_scan.py --target https://example.com --probe-path /login

# 同域递归爬取 + 扫描
python3 php_scan.py --target https://example.com --crawl \
    --crawl-depth 2 --max-pages 30

# 批量扫描
python3 php_scan.py --targets targets.txt

# 本地代码/配置审计
python3 php_scan.py --path /srv/legacy-app/

# 行为确认模式（需要主机侧通道）
python3 php_scan.py --target http://127.0.0.1:18080 --confirm \
    --session-path /tmp \
    --exec-cmd 'docker exec php-fpm sh -c "{cmd}"'

# 带登录态扫描（session cookie 会被剥离——扫描器使用自己的 SID）
python3 php_scan.py --target https://example.com \
    --cookie 'PHPSESSID=xxx; other=val' --confirm

# 报告控制——默认追加到 reports/php-scan-results.xlsx
python3 php_scan.py --target https://example.com --output out.md  # .md/.json/.xlsx
python3 php_scan.py --target https://example.com --no-report      # 只输出终端
```

## 报告

每次扫描自动追加到**单一累积工作簿** `reports/php-scan-results.xlsx`
（繁体中文标签、自动换行列宽），三个工作表：

- **掃描記錄** — 时间 / 目标 / 严重度 / 判定摘要（每次扫描一行）
- **檢查明細** — 每个检查项的状态、说明与原始证据
- **判定** — 每个目标的结论，带严重度

严重度：`critical` / `high` / `medium` / `low` / `info`
（受影响 + mod_php、或确认 OOM 指纹 → `critical`；EOL 版本 → `critical`）

## 判定语义

| 状态 | 含义 |
|---|---|
| `affected` | PHP 版本落在官方受影响区间（< 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12）——**暴露面结论，非可利用性证明** |
| `eol` | EOL 分支（如 PHP ≤ 8.1）：无官方补丁 |
| `patched` | 版本 ≥ 修复版（Chain A 文件名注入原语属设计行为，补丁不覆盖） |
| `confirmed` | 行为指纹已在主机侧验证（真触发、真证据） |
| `likely_exposed` / `needs_host_check` | 触发被远程接受；需主机侧确认 |
| `resisted` / `not_triggered` / `inconclusive` | 诚实的阴性/不确定状态——绝不虚报 |

**`affected` ≠ `exploitable`。** CVE-2026-109618 没有无副作用的远程
利用验证法；扫描器报告的是暴露面 + 前置条件 + 缓解建议——绝不虚报
"RCE 成功"。

## 限制

- `expose_php=Off` 时远程无法判版本 → 用 `--path` 或主机 `php -v` 确认
- session 文件确认需要主机侧通道（`--session-path` / `--exec-cmd`）
- 前置 WAF/CDN（ESA、Cloudflare 等）可能拦截探针 → 如实标 `inconclusive`
- 代码 sink 扫描是 regex 级启发式，框架封装/间接调用可能漏报
- 不检测 `fatal_error_backtraces`（PHP 8.5 arm）与 OPcache 状态

## 缓解清单

- 升级 ≥ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12（EOL 版本必须升级，无补丁）
- `session.upload_progress.enabled = Off`（主要触发面）
- `session.use_only_cookies = 1`、统一 `session.serialize_handler`
- `expose_php = Off`、审计 `unserialize()` 与动态 `include` sink
- EOL 部署隔离 / VPN / ACL 限制访问

---

**仅限授权安全测试。**
商用须取得书面授权——请联系 https://github.com/JackLiKa，违者必究。
