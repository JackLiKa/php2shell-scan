# php-scan

[English](README.md) | **简体中文** | [繁體中文](README.zh-TW.md)

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-non--commercial-orange)

面向存量 PHP 应用的 CVE-2026-109618 / CVE-2026-109619
**暴露面与前置条件扫描器**。

单文件、零依赖（仅 Python 3 标准库）、**严格非破坏性**：
不发送内存破坏 payload、不拖死连接、不注入可执行代码（仅惰性标记）。

> ⚖️ **许可**：仅限个人非商业用途（学习、研究、授权测试）。
> **商用需书面授权——联系 jacklika.business@gmail.com，
> 违规商用将被追责。** 详见 [LICENSE](LICENSE)（三语）。

---

## ✨ 功能

| 模式 | 说明 |
|---|---|
| `--target` | 远程黑盒探测：HTTP 头、**worst-of 版本指纹**（安心 banner 掩盖不了漏洞版本）、SAPI 推断、session cookie 名自动学习、`upload_progress` 可达性（**PUT 回退**，覆盖 PHP 8.4 `request_parse_body` 面）、session fixation、filename 标记注入 |
| `--crawl`（默认） | **同域递归爬扫**——跟随链接 + 表单 action，跳过静态资源与外域，逐页扫描（`--no-crawl` 只扫给定 URL） |
| `--targets` + `--threads` | 批量扫描——每行一个 URL（`#` 注释），并行 worker |
| `--path` | 本地审计：ini / `.htaccess` / **php-fpm pool** / Dockerfile 证据、`php -r` **运行时真值**、发行版 **backport 判定**（`dpkg`/`rpm` 对照 vendor-fixed 公告）、代码 sink（`unserialize`/LFI/handler 冲突）、POP gadget 包 |
| `--confirm` | **行为确认**，经 `--session-path` / `--exec-cmd`：sess 文件创建、session 数据内标记、**三策略 OOM 指纹**（`chunked`/`headers`/`nested`）、`host_patch_status` 地面真值 |
| `--emit-rules` | 导出 **Suricata / ModSecurity / Sigma** 检测规则 |

新增信号深度：**SID 堆泄漏特征**（异常 session cookie）、
**响应体 IoC**（`Session object destruction failed`、
`Unknown on line 0`）、`display_errors` 指纹、边缘 WAF 感知、
缓解措施审计、诚实的阴性状态。

判定保真：探测**跟随一跳 30x 重定向**（含跨域）；rfc1867 暴露判定
在**任意状态码**上成立——404/405 响应里下发 session `Set-Cookie`
即证明 handler 在 pre-RINIT 已运行（早于路由）。chunked OOM 探测
**自动阶梯升级 64 → `--oom-mb` → 256MB**，命中 OOM 字符串即停；
chunked 中途断连会如实标注为歧义（WAF 丢包 *或* 已修复的
hard-OOM worker 退出，远程无法区分）。

## 🚀 用法

```bash
# 远程扫描——自动爬取同域页面
python3 php_scan.py --target https://example.com/

# 只扫给定 URL
python3 php_scan.py --target https://example.com/ --no-crawl

# 调整爬扫参数
python3 php_scan.py --target https://example.com/ --crawl-depth 2 --max-pages 30

# 批量 + 并发 + 只看有价值的发现
python3 php_scan.py --targets urls.txt --threads 8 \
    --status confirmed,exposed,leak_signature --min-severity high -q

# 本地代码/配置审计
python3 php_scan.py --path /srv/legacy-app/

# 行为确认（需要主机侧通道）
python3 php_scan.py --target http://127.0.0.1:18080 --confirm \
    --session-path /var/lib/php/sessions \
    --exec-cmd 'docker exec php-fpm sh -c "{cmd}"'

# 认证扫描（session 类 cookie 会被剥离，scanner 自带 probe SID）
python3 php_scan.py --target https://example.com --cookie 'k=v; …'

# 为 SOC 导出 IDS/Sigma 规则
python3 php_scan.py --emit-rules ./detection/
```

## ⚙️ 参数

| 参数 | 说明 |
|---|---|
| `--target URL` | 远程目标 URL |
| `--targets FILE` | 批量目标文件，每行一个 URL（`#` 注释） |
| `--crawl` / `--no-crawl` | 同域爬扫——`--target` 时**默认开启** |
| `--crawl-depth N` | 爬取深度（默认 `3`） |
| `--max-pages N` | 爬取页面上限（默认 `50`） |
| `--path DIR` | 本地 PHP 项目审计目录 |
| `--probe-path PATH` | 手动指定探测端点 |
| `--cookie 'k=v;…'` | 认证 cookie（session-id 类会被剥离） |
| `--progress-name NAME` | `session.upload_progress.name` 被改名时的字段名 |
| `--confirm` | 行为确认模式 |
| `--session-path DIR` | `session.save_path`，本地或经 `--exec-cmd` |
| `--exec-cmd 'TPL'` | 主机命令模板，`{cmd}` 占位符 |
| `--oom-mb N` | OOM 探测 body 大小（默认 `160`；chunked 自动 64→N→256MB 阶梯升级——`headers`/`nested` 带 Content-Length 受 `post_max_size` 约束保持定值） |
| `--confirm-oom` | 跳过 SAPI/版本启发，强制 OOM 探测 |
| `--oom-strategy S` | `auto` / `chunked` / `headers` / `nested` |
| `--json` | JSON 输出到 stdout |
| `--output FILE` | 报告路径，后缀定格式（`.xlsx`/`.md`/`.json`） |
| `--cumulative` | 追加进共享工作簿 `reports/php-scan-results.xlsx` |
| `--report-format F` | 自动命名报告的格式 `xlsx`/`md`/`json` |
| `--no-report` | 不写报告文件 |
| `--threads N` | 批量/爬扫并发数（默认 `1`） |
| `--timeout N` | 单请求超时（默认 `10` 秒） |
| `-q, --quiet` | 只打印 severity ≥ medium 的报告 |
| `--status a,b` | 只显示指定状态的检查项 |
| `--hide-status a,b` | 隐藏指定状态 |
| `--check REGEX` | 按名称/说明/细节过滤检查项 |
| `--min-severity S` | verdict 最低严重度（默认 `info`） |
| `--emit-rules DIR` | 导出 Suricata/ModSecurity/Sigma 规则 |

## 🔍 输出筛选

```bash
--status confirmed,exposed,affected,leak_signature   # 只看信号
--hide-status info,unknown,done,not_applicable       # 隐藏噪音
--check 'oom|upload'                                  # 按 regex 过滤检查项
--min-severity high -q                                # 只要 high+ 判定
```

## 📊 报告

每次运行写入**一个时间戳文件**到
`<script_dir>/reports/<YYYYMMDD-HHMMSS>_<域名[-端口]>_<严重度>.<fmt>`
——例如 `20261023-112935_www.example.com_CRITICAL.xlsx`。

三个工作表（繁体中文表头、自动换行、autoFilter）：

| Sheet | 内容 |
|---|---|
| 掃描記錄 | 时间 / 目标 / 严重度 / 判定摘要 |
| 檢查明細 | 每项检查：状态、说明、原始证据（受 `--status`/`--hide-status`/`--check` 过滤） |
| 判定 | 每目标的分级结论（受 `--min-severity` 过滤） |

`--cumulative` 改为追加进共享工作簿（旧 schema 自动补空列合并）。
任一目标 ≥ `high` 时退出码为 `1` —— 可直接进 CI。

## 🧭 判定语义

| 状态 | 含义 |
|---|---|
| `affected` | 版本在受影响区间（< 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12）——**暴露面，非可利用性证明** |
| `eol` | EOL 分支——无官方补丁 |
| `patched` / `likely_patched` | 已修复版本，或观测到 delayed-OOM 修补形态 |
| `confirmed` | 行为指纹经主机侧验证 |
| `leak_signature` / `crash_signature` | session cookie 堆泄漏 / worker 未恢复——**critical** |
| `likely_exposed` / `needs_host_check` | 触发被接受，需主机侧确认 |
| `resisted` / `not_triggered` / `inconclusive` | 诚实的阴性/不确定状态——绝不夸大 |

**`affected` ≠ `exploitable`。** 扫描器只报暴露面 + 前置条件 +
缓解措施——绝不伪造「RCE 成功」。

## ⚠️ 局限

- banner 可能说谎——发行版 backport 不改版本号；
  `host_patch_status`/`vendor_packages` 可达时给出地面真值
- 405 ≠ 安全：rfc1867 handler 在 request startup 运行，**早于**路由——
  任意状态码上的 session `Set-Cookie` 即判 handler 触发；但 sess 文件
  内容仍需主机通道确认
- 边缘 WAF/CDN 可能丢包 → 如实报 `inconclusive`，建议网络内侧重试
- chunked 上传中途断连**有歧义**：WAF 丢包 *或* 已修复的 hard-OOM
  worker 退出——远程无法区分
- sess 文件确认需要 `--session-path` / `--exec-cmd`
- 代码 sink 扫描是正则级启发式，框架封装/间接调用可能漏检

## 🛡 缓解清单

- 升级 ≥ **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**（EOL 必须升级或隔离）
- `session.upload_progress.enabled = Off`（*只挡 109619 session 臂——
  109618 OOM 仍需补丁*）
- `session.use_only_cookies = 1`；统一 `session.serialize_handler`
- `expose_php = Off`；审计 `unserialize()` / 动态 `include` sink
- php-fpm：`pm.max_requests=1` 可缓解 stale-BG 链

---

**仅限授权安全评估使用。**
商用需书面授权——联系 jacklika.business@gmail.com。
