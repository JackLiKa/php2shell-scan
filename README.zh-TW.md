# php-scan

[English](README.md) | [简体中文](README.zh-CN.md) | **繁體中文**

CVE-2026-109618 / CVE-2026-109619 **暴露面與前置條件掃描器**，
面向老舊 PHP 專案。

單一檔案、Python 3 標準函式庫零依賴、**嚴格非破壞式**：不發記憶體破壞
payload、不掛起連線、不注入可執行程式碼（只發惰性 marker）。

> ⚖️ **許可**：僅限個人非商業用途（學習、研究、授權測試）。
> **商用須取得書面授權——請聯繫 https://github.com/JackLiKa，
> 未經授權之商用行為依法追究。** 詳見 [LICENSE](LICENSE)（三語）。

---

## 功能

| 模式 | 說明 |
|---|---|
| `--target` | 遠端黑盒探測單一端點：HTTP 標頭、PHP 版本、SAPI 推斷、session cookie 名自動學習、`session.upload_progress` 可達性、工作階段固定、檔名 marker 注入 |
| `--targets` | 批次掃描——每行一個 URL（`#` 為註解） |
| `--crawl` | **同域遞迴爬取**——BFS 跟隨連結與表單 action，略過靜態資源與外部網域，逐一掃描發現的每個頁面與接口 |
| `--path` | 本地程式碼/配置審計：`*.ini` / `.htaccess` 配置、Dockerfile/compose 映像 tag（版本 + SAPI 證據）、nginx/apache/fpm 配置、`composer.json`/`.lock` 與已知 POP gadget 套件、程式碼 sink（`unserialize`/LFI/serialize_handler 衝突）、magic method gadget |
| `--confirm` | **行為確認**——真實觸發良性原語並在主機側閉環驗證（session 檔案建立、marker 落碟、mod_php「Unknown on line 0」OOM 指紋），透過 `--session-path` / `--exec-cmd` 通道 |

## 用法

```bash
# 遠端探測單一端點
python3 php_scan.py --target https://example.com --probe-path /login

# 同域遞迴爬取 + 掃描
python3 php_scan.py --target https://example.com --crawl \
    --crawl-depth 2 --max-pages 30

# 批次掃描
python3 php_scan.py --targets targets.txt

# 本地程式碼/配置審計
python3 php_scan.py --path /srv/legacy-app/

# 行為確認模式（需要主機側通道）
python3 php_scan.py --target http://127.0.0.1:18080 --confirm \
    --session-path /tmp \
    --exec-cmd 'docker exec php-fpm sh -c "{cmd}"'

# 帶登入態掃描（session cookie 會被剝離——掃描器使用自己的 SID）
python3 php_scan.py --target https://example.com \
    --cookie 'PHPSESSID=xxx; other=val' --confirm

# 報告控制——預設追加至 reports/php-scan-results.xlsx
python3 php_scan.py --target https://example.com --output out.md  # .md/.json/.xlsx
python3 php_scan.py --target https://example.com --no-report      # 只輸出終端
```

## 報告

每次掃描自動追加到**單一累積工作簿** `reports/php-scan-results.xlsx`
（繁體中文標籤、自動換行欄寬），三個工作表：

- **掃描記錄** — 時間 / 目標 / 嚴重度 / 判定摘要（每次掃描一列）
- **檢查明細** — 每個檢查項的狀態、說明與原始證據
- **判定** — 每個目標的結論，帶嚴重度

嚴重度：`critical` / `high` / `medium` / `low` / `info`
（受影響 + mod_php、或確認 OOM 指紋 → `critical`；EOL 版本 → `critical`）

## 判定語義

| 狀態 | 含義 |
|---|---|
| `affected` | PHP 版本落在官方受影響區間（< 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12）——**暴露面結論，非可利用性證明** |
| `eol` | EOL 分支（如 PHP ≤ 8.1）：無官方修補程式 |
| `patched` | 版本 ≥ 修復版（Chain A 檔名注入原語屬設計行為，修補不涵蓋） |
| `confirmed` | 行為指紋已在主機側驗證（真觸發、真證據） |
| `likely_exposed` / `needs_host_check` | 觸發被遠端接受；需主機側確認 |
| `resisted` / `not_triggered` / `inconclusive` | 誠實的陰性/不確定狀態——絕不虛報 |

**`affected` ≠ `exploitable`。** CVE-2026-109618 沒有無副作用的遠端
利用驗證法；掃描器報告的是暴露面 + 前置條件 + 緩解建議——絕不虛報
「RCE 成功」。

## 限制

- `expose_php=Off` 時遠端無法判版本 → 用 `--path` 或主機 `php -v` 確認
- session 檔案確認需要主機側通道（`--session-path` / `--exec-cmd`）
- 前置 WAF/CDN（ESA、Cloudflare 等）可能攔截探針 → 如實標 `inconclusive`
- 程式碼 sink 掃描是 regex 級啟發式，框架封裝/間接呼叫可能漏報
- 不檢測 `fatal_error_backtraces`（PHP 8.5 arm）與 OPcache 狀態

## 緩解清單

- 升級 ≥ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12（EOL 版本必須升級，無修補）
- `session.upload_progress.enabled = Off`（主要觸發面）
- `session.use_only_cookies = 1`、統一 `session.serialize_handler`
- `expose_php = Off`、審計 `unserialize()` 與動態 `include` sink
- EOL 部署隔離 / VPN / ACL 限制存取

---

**僅限授權安全測試。**
商用須取得書面授權——請聯繫 https://github.com/JackLiKa，違者必究。
