# php-scan

CVE-2026-109618 / CVE-2026-109619 **暴露面扫描器**（防御用途）。

与原 `php2shell-poc` 的 exploit 不同：本工具**只探测暴露面和前置条件**，
不发送内存破坏 payload、不 crash worker、不注入可执行代码。

## 用法

```bash
# 远程黑盒探测（对授权目标）
python3 php_scan.py --target http://127.0.0.1:18080 --probe-path /sess.php

# 批量：每行一个 URL，# 开头为注释
python3 php_scan.py --targets targets.txt --confirm ...

# 本地代码/配置审计（有源码访问权限时）
python3 php_scan.py --path /var/www/myapp

# 两者结合 + JSON 输出
python3 php_scan.py --target http://target --path ./src --json

# 自定义报告文件（.md/.json/.xlsx 后缀自动识别）；--no-report 不落盘
python3 php_scan.py --target http://target --output /tmp/scan.xlsx
```

每次扫描结束**自动追加到单一报告文件**：默认 `reports/php-scan-results.xlsx`
（在脚本目录下）。Excel 报告含三个工作表（掃描記錄 / 檢查明細 / 判定），
每行帶掃描時間、目標與嚴重度，多次掃描逐行累積便於對比；說明欄為繁體中文。
`--output` 可覆蓋路徑與格式（.md/.json/.xlsx），`--no-report` 跳过落盘。

`--probe-path` 建议指向一个会调用 `session_start()` 的端点；缺省时取
`--target` URL 里的路径。扫描器会**自动学习 session cookie 名**
（`session.name`，框架常改名如 `laravel_session`/`symfony`）——SID 探针
用学到的名字发送，否则 rfc1867/upload_progress 一律假阴性。

## --confirm 行为确认模式

默认模式只做暴露面判定。`--confirm` 会**真实触发良性原语**并到主机侧
闭环验证指纹，输出 `confirmed` 级判定：

```bash
# 主机侧通道二选一（也可都用）
python3 php_scan.py --target http://127.0.0.1:18080 --confirm \
    --session-path /tmp \
    --exec-cmd 'docker exec lab-a-vuln sh -c "{cmd}"'
# 或挂载卷场景：--session-path 直接指向本机可见的 session 目录，不需 --exec-cmd
```

带登录态扫描（后台页需要 session cookie 时）：

```bash
python3 php_scan.py --target https://example.com --probe-path /admin/panel.php \
    --cookie 'PHPSESSID=你的会话id; other=val' --confirm
# 注意：cookie 里的 PHPSESSID 会被剥离——探测用自己的 SID，其余 cookie 原样带上
```

| 确认项 | 触发 | 指纹 | 副作用 |
|---|---|---|---|
| upload_progress | POST body 探测 SID | `sess_<probe>` 在主机被创建 | 生成一个探测会话文件 |
| session fixation | 同上 | 同上（rfc1867 绕过 use_only_cookies） | 同上 |
| filename 注入 | 文件名塞 marker 文本 | marker 原样存在于 sess 文件 | `cleanup=On` 时会被清除 → not_confirmed |
| mod_php OOM | chunked multipart 大字段（绕 post_max_size） | `Allowed memory size ... in Unknown on line 0` | **一次 memory_limit fatal error**（单请求，不 crash worker，无堆喷射） |

OOM 探针是确认 CVE-2026-109618 触发原语的**行为指纹**：在 8.2.34 上
复现 "Unknown on line 0"，在 8.2.35 上不触发（soft-OOM 路径）——
这是本工具唯一的 vuln/patched 行为区分项，其余检查在两版上表现一致
（session 注入 primitive 补丁不修）。

判定等级：`affected`（版本）< `confirmed`（行为指纹）< `exploited`
（真 RCE 回显——本工具不做，请在 lab 用 exploit 验证）。

## 检查项

**远程**（良性探测，无副作用）

| 检查 | 方法 | 判定 |
|---|---|---|
| PHP 版本 | `X-Powered-By` / 响应体指纹 | < 8.2.35/8.3.36/8.4.27/8.5.12 → affected；<8.2 → eol |
| SAPI | Server 头推断（apache→mod_php、nginx/caddy→fpm、litespeed→LSAPI） | mod_php 风险最高 |
| session cookie 名 | `Set-Cookie` 自动学习 | 后续 SID 探针全部使用该名 |
| upload_progress | 发送 `PHP_SESSION_UPLOAD_PROGRESS` 字段 | 被接受 → CVE 触发面开放 |
| session fixation | POST body SID → 观察 Set-Cookie | 固定 SID 被接受 → exposed；被替换 → resisted |
| filename 注入 | 文件名塞**标记字符串**（非代码） | 需在主机确认 sess 文件含 marker |

**本地**（静态审计）

- ini 面：`php.ini` / `.user.ini` / 任意 `*.ini` / `.htaccess` 的 `php_value|php_flag`——
  `memory_limit`、`post_max_size`、`use_only_cookies`、`save_path`、
  `upload_progress.*`、`expose_php`、`disable_functions`、`open_basedir`、
  `allow_url_include`
- **版本线报**：`Dockerfile`/`docker-compose`/`compose.yml` 的 `php:X.Y.Z` 镜像 tag、
  `composer.json` php 约束 → `cve_range_local` 本地版本判定
- **SAPI 证据**：镜像 tag（`-apache`→mod_php、`-fpm`）、`nginx.conf` 的
  `fastcgi_pass`、apache conf 的 `libphp/php_module`
- `session.serialize_handler` 跨目录不一致 → `serialize_handler_conflict`
  （Chain C 前提，high）
- `session.upload_progress.enabled` 未显式 Off → 默认 On 计为 exposed
- `composer.lock` 中已知 POP gadget 包（laravel/monolog/guzzle/twig/phpunit/
  faker/swiftmailer/phpspreadsheet/doctrine/symfony）
- 代码 sink：`unserialize()`、`include/require` 变量（LFI）、
  `ini_set('session.serialize_handler')`、`session_set_save_handler()`
- POP gadget：`__destruct`/`__wakeup`/`__unserialize`/`__call`/`__invoke`/
  `__toString` 内含危险调用（区分 app/vendor）

## 严重度分级

`critical` / `high` / `medium` / `low` / `info`，汇总进报告与 Excel：

- affected + mod_php/Apache → **critical**（厂商在 mod_php 上演示过未授权 RCE）
- affected + fpm/其他 → high；EOL 版本（<8.2，无官方补丁）→ critical
- patched → low（Chain A 原语是设计行为，补丁不修）
- confirmed 级行为指纹提升严重度：OOM 指纹 → critical，session 原语确认 → high

## 判定语义

输出的是 **"受影响版本 + 哪些前置条件成立 + 缓解建议"**，
不是 "我打进去了"。原因：

- CVE-2026-109618（OOM→内存损坏）**没有无副作用的远程探测法**，
  可利用性判定只能靠版本号
- Chain A 的 filename 注入 primitive **补丁不修复**（8.5.12 上仍有效），
  单独报为 "LFI 组合风险"
- `affected` ≠ `exploitable`，实际武器化还需要 LFI sink / POP gadget /
  堆喷射等

## 限制

- `expose_php=Off` 时版本无法远程判定 → 配合 `--path` 或手工确认
- session 文件确认需要主机侧访问（工具会打印要执行的 grep 命令）
- 不检测 `fatal_error_backtraces`（PHP 8.5 特有 arm）和 OPcache 状态
