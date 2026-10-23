# php-scan

[English](README.md) | [简体中文](README.zh-CN.md) | **繁體中文**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-non--commercial-orange)

面向存量 PHP 應用的 CVE-2026-109618 / CVE-2026-109619
**暴露面與前置條件掃描器**。

單檔案、零依賴（僅 Python 3 標準函式庫）、**嚴格非破壞性**：
不發送記憶體破壞 payload、不拖垮連線、不注入可執行程式碼（僅惰性標記）。

> ⚖️ **授權**：僅限個人非商業用途（學習、研究、授權測試）。
> **商用需書面授權——請聯絡 jacklika.business@gmail.com，
> 違規商用將被追責。** 詳見 [LICENSE](LICENSE)（三語）。

---

## ✨ 功能

| 模式 | 說明 |
|---|---|
| `--target` | 遠端黑盒探測：HTTP 標頭、**worst-of 版本指紋**（安心的 banner 掩蓋不了漏洞版本）、SAPI 推斷、session cookie 名自動學習、`upload_progress` 可達性（**PUT 回退**，涵蓋 PHP 8.4 `request_parse_body` 面）、session fixation、filename 標記注入 |
| `--crawl`（預設） | **同域遞迴爬掃**——跟隨連結 + 表單 action，略過靜態資源與外域，逐頁掃描（`--no-crawl` 只掃給定 URL） |
| `--targets` + `--threads` | 批次掃描——每行一個 URL（`#` 註解），並行 worker |
| `--path` | 本機稽核：ini / `.htaccess` / **php-fpm pool** / Dockerfile 證據、`php -r` **執行時真值**、發行版 **backport 判定**（`dpkg`/`rpm` 對照 vendor-fixed 公告）、程式碼 sink（`unserialize`/LFI/handler 衝突）、POP gadget 套件 |
| `--confirm` | **行為確認**，經 `--session-path` / `--exec-cmd`：sess 檔案建立、session 資料內標記、**三策略 OOM 指紋**（`chunked`/`headers`/`nested`）、`host_patch_status` 地面真值 |
| `--emit-rules` | 匯出 **Suricata / ModSecurity / Sigma** 偵測規則 |

新增訊號深度：**SID 堆積洩漏特徵**（異常 session cookie）、
**回應內容 IoC**（`Session object destruction failed`、
`Unknown on line 0`）、`display_errors` 指紋、邊緣 WAF 感知、
緩解措施稽核、誠實的陰性狀態。

判定保真：探測**跟隨一跳 30x 重新導向**（含跨域）；rfc1867 暴露
判定在**任意狀態碼**上成立——404/405 回應裡下發 session
`Set-Cookie` 即證明 handler 在 pre-RINIT 已執行（早於路由）。
chunked OOM 探測**自動階梯升級 64 → `--oom-mb` → 256MB**，命中
OOM 字串即停；chunked 中途斷連會如實標註為歧義（WAF 丟包 *或*
已修補的 hard-OOM worker 退出，遠端無法區分）。

## 🚀 用法

```bash
# 遠端掃描——自動爬取同域頁面
python3 php_scan.py --target https://example.com/

# 只掃給定 URL
python3 php_scan.py --target https://example.com/ --no-crawl

# 調整爬掃參數
python3 php_scan.py --target https://example.com/ --crawl-depth 2 --max-pages 30

# 批次 + 並行 + 只看有價值的發現
python3 php_scan.py --targets urls.txt --threads 8 \
    --status confirmed,exposed,leak_signature --min-severity high -q

# 本機程式碼/設定稽核
python3 php_scan.py --path /srv/legacy-app/

# 行為確認（需要主機側通道）
python3 php_scan.py --target http://127.0.0.1:18080 --confirm \
    --session-path /var/lib/php/sessions \
    --exec-cmd 'docker exec php-fpm sh -c "{cmd}"'

# 認證掃描（session 類 cookie 會被剝離，scanner 自帶 probe SID）
python3 php_scan.py --target https://example.com --cookie 'k=v; …'

# 為 SOC 匯出 IDS/Sigma 規則
python3 php_scan.py --emit-rules ./detection/
```

## ⚙️ 參數

| 參數 | 說明 |
|---|---|
| `--target URL` | 遠端目標 URL |
| `--targets FILE` | 批次目標檔，每行一個 URL（`#` 註解） |
| `--crawl` / `--no-crawl` | 同域爬掃——`--target` 時**預設開啟** |
| `--crawl-depth N` | 爬取深度（預設 `3`） |
| `--max-pages N` | 爬取頁面上限（預設 `50`） |
| `--path DIR` | 本機 PHP 專案稽核目錄 |
| `--probe-path PATH` | 手動指定探測端點 |
| `--cookie 'k=v;…'` | 認證 cookie（session-id 類會被剝離） |
| `--progress-name NAME` | `session.upload_progress.name` 被改名時的欄位名 |
| `--confirm` | 行為確認模式 |
| `--session-path DIR` | `session.save_path`，本機或經 `--exec-cmd` |
| `--exec-cmd 'TPL'` | 主機指令範本，`{cmd}` 佔位符 |
| `--oom-mb N` | OOM 探測 body 大小（預設 `160`；chunked 自動 64→N→256MB 階梯升級——`headers`/`nested` 帶 Content-Length 受 `post_max_size` 約束保持定值） |
| `--confirm-oom` | 略過 SAPI/版本啟發式，強制 OOM 探測 |
| `--oom-strategy S` | `auto` / `chunked` / `headers` / `nested` |
| `--json` | JSON 輸出到 stdout |
| `--output FILE` | 報告路徑，後綴定格式（`.xlsx`/`.md`/`.json`） |
| `--cumulative` | 追加進共用活頁簿 `reports/php-scan-results.xlsx` |
| `--report-format F` | 自動命名報告的格式 `xlsx`/`md`/`json` |
| `--no-report` | 不寫報告檔 |
| `--threads N` | 批次/爬掃並行數（預設 `1`） |
| `--timeout N` | 單請求逾時（預設 `10` 秒） |
| `-q, --quiet` | 只列印 severity ≥ medium 的報告 |
| `--status a,b` | 只顯示指定狀態的檢查項 |
| `--hide-status a,b` | 隱藏指定狀態 |
| `--check REGEX` | 依名稱/說明/細節過濾檢查項 |
| `--min-severity S` | verdict 最低嚴重度（預設 `info`） |
| `--emit-rules DIR` | 匯出 Suricata/ModSecurity/Sigma 規則 |

## 🔍 輸出篩選

```bash
--status confirmed,exposed,affected,leak_signature   # 只看訊號
--hide-status info,unknown,done,not_applicable       # 隱藏噪音
--check 'oom|upload'                                  # 依 regex 過濾檢查項
--min-severity high -q                                # 只要 high+ 判定
```

## 📊 報告

每次執行寫入**一個時間戳檔案**到
`<script_dir>/reports/<YYYYMMDD-HHMMSS>_<網域[-埠號]>_<嚴重度>.<fmt>`
——例如 `20261023-112935_www.example.com_CRITICAL.xlsx`。

三個工作表（繁體中文標頭、自動換行、autoFilter）：

| Sheet | 內容 |
|---|---|
| 掃描記錄 | 時間 / 目標 / 嚴重度 / 判定摘要 |
| 檢查明細 | 每項檢查：狀態、說明、原始證據（受 `--status`/`--hide-status`/`--check` 過濾） |
| 判定 | 每目標的分級結論（受 `--min-severity` 過濾） |

`--cumulative` 改為追加進共用活頁簿（舊 schema 自動補空欄合併）。
任一目標 ≥ `high` 時結束碼為 `1` —— 可直接接 CI。

## 🧭 判定語意

| 狀態 | 意義 |
|---|---|
| `affected` | 版本在受影響區間（< 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12）——**暴露面，非可利用性證明** |
| `eol` | EOL 分支——無官方修補程式 |
| `patched` / `likely_patched` | 已修復版本，或觀測到 delayed-OOM 修補形態 |
| `confirmed` | 行為指紋經主機側驗證 |
| `leak_signature` / `crash_signature` | session cookie 堆積洩漏 / worker 未復原——**critical** |
| `likely_exposed` / `needs_host_check` | 觸發被接受，需主機側確認 |
| `resisted` / `not_triggered` / `inconclusive` | 誠實的陰性/不確定狀態——絕不誇大 |

**`affected` ≠ `exploitable`。** 掃描器只回報暴露面 + 前置條件 +
緩解措施——絕不偽造「RCE 成功」。

## ⚠️ 限制

- banner 可能說謊——發行版 backport 不改版本號；
  `host_patch_status`/`vendor_packages` 可達時給出地面真值
- 405 ≠ 安全：rfc1867 handler 在 request startup 執行，**早於**路由——
  任意狀態碼上的 session `Set-Cookie` 即判 handler 觸發；但 sess 檔案
  內容仍需主機通道確認
- 邊緣 WAF/CDN 可能丟棄探測 → 如實回報 `inconclusive`，建議網路內側重試
- chunked 上傳中途斷連**有歧義**：WAF 丟包 *或* 已修補的 hard-OOM
  worker 退出——遠端無法區分
- sess 檔案確認需要 `--session-path` / `--exec-cmd`
- 程式碼 sink 掃描是正則級啟發式，框架封裝/間接呼叫可能漏檢

## 🛡 緩解清單

- 升級 ≥ **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**（EOL 必須升級或隔離）
- `session.upload_progress.enabled = Off`（*只擋 109619 session 臂——
  109618 OOM 仍需修補程式*）
- `session.use_only_cookies = 1`；統一 `session.serialize_handler`
- `expose_php = Off`；稽核 `unserialize()` / 動態 `include` sink
- php-fpm：`pm.max_requests=1` 可緩解 stale-BG 鏈

---

**僅限授權安全評估使用。**
商用需書面授權——請聯絡 jacklika.business@gmail.com。
