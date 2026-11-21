# ModSecurity 安裝手冊（nginx + libmodsecurity v3 + OWASP CRS 4）

[English](MODSECURITY.md) · **繁體中文** · [日本語](MODSECURITY.ja.md)

這份手冊從一台只有 nginx（或什麼都還沒有）的主機開始，裝好 jt-waf-mgr 需要的 ModSecurity 環境。你要準備的是 nginx、
ModSecurity 模組、`modsecurity.conf` 與主設定檔（第 1–5 節）；OWASP CRS 接著交給 jt-waf-mgr：由它下載、驗證、安裝 CRS 4，
並透過經過核准的變更保持最新（第 6 節，建議的做法）。也可以自己手動安裝 CRS（第 7 節）。已經有 ModSecurity 的站台不必照做，
對照第 8 節最後列出的「jt-waf-mgr 需要的設定」確認即可。

第一次建置時，nginx 的設定由你自己修改：`modsecurity on;`（第 3 節）與管理介面的 vhost（[README](../README_zh-TW.md#連到管理介面)）。
之後 jt-waf-mgr 寫的是 ModSecurity 的規則檔；它會讀 nginx 設定（找出站台與 ModSecurity 主設定檔）、執行 `nginx -t` 並 reload。
會碰到 nginx 設定的只有這幾種，而且都經過變更流程（檢查、核准、`nginx -t`、reload、失敗還原）：

- 為站台啟用或停用 WAF、部署封鎖頁：在符合條件的 `server` 區塊加上或移除一行帶標記的 `include`；
- 暫時封鎖 IP：只寫一個只有 `deny` 行的清單檔，由你自己在 `http { }` include 一次。

> 先以「只記錄」（`DetectionOnly`）上線，用 jt-waf-mgr 看一段時間的事件、處理誤判，再改成封鎖（`On`）。

## 1. 系統與套件

- Debian 12 / 13：`libnginx-mod-http-modsecurity`，libmodsecurity 3.0.9 以上隨套件安裝。
- Ubuntu 24.04：`libnginx-mod-http-modsecurity`，libmodsecurity 3.0.12（套件名稱 `libmodsecurity3t64`）。
- Ubuntu 26.04：`libnginx-mod-http-modsecurity`，libmodsecurity 3.0.14（套件名稱 `libmodsecurity3t64`）。
- Ubuntu 22.04：套件的 libmodsecurity 低於 3.0.9，請改用 24.04 或自行編譯。

全新主機（`--no-install-recommends`：連接器把發行版的 CRS 3 列為建議套件，預設會一起裝進來）：

```sh
sudo apt install --no-install-recommends nginx libnginx-mod-http-modsecurity
```

確認套件版本與來源，以及實際載入的設定（套件裝了不等於模組或規則有載入）：

```sh
# 版本 ≥ 3.0.9；nginx 與連接器來自同一個套件庫
apt-cache policy nginx libnginx-mod-http-modsecurity libmodsecurity3 libmodsecurity3t64
# 有效設定裡要有 load_module、modsecurity on 與 modsecurity_rules_file
sudo nginx -T 2>/dev/null | grep -E 'load_module .*modsecurity|modsecurity (on|off)|modsecurity_rules_file'
```

連接器模組必須與執行中的 nginx 版本及模組 ABI 相容（Debian / Ubuntu 的套件以 `nginx-abi-*` 相依條件配對）。如果你用的是
nginx.org 的套件，發行版的模組載入不了：請改用發行版的 nginx，或以同一版 nginx 原始碼
（`./configure --with-compat --add-dynamic-module=ModSecurity-nginx`）編譯動態模組。

發行版的 `modsecurity-crs` 套件是 CRS 3.3，**不要用**。已經裝了的主機，先用上面的 `nginx -T` 看實際 Include 的是哪一份規則；
CRS 4 由 jt-waf-mgr 幫你安裝（第 6 節），或自己手動安裝（第 7 節）。

## 2. ModSecurity 基本設定

設定放在 `/etc/nginx/modsec/`。`modsecurity.conf-recommended` 與 `unicode.mapping` 取自 ModSecurity 原始碼中**與你的
libmodsecurity 相同版本**的標籤（[github.com/owasp-modsecurity/ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)）。

```sh
sudo install -d -m 755 /etc/nginx/modsec
# 上游版本號：apt-cache policy 顯示 3.0.9-1+deb12u2 時填 3.0.9（不含 Debian / Ubuntu 的修訂字尾）
V=3.0.9
cd /etc/nginx/modsec
sudo curl -fLo modsecurity.conf https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v$V/modsecurity.conf-recommended
sudo curl -fLO https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v$V/unicode.mapping
```

在 `modsecurity.conf` 確認或修改這幾行：

```apache
# 先只記錄；觀察後改 On（第 9 節）
SecRuleEngine DetectionOnly
SecAuditEngine RelevantOnly
SecAuditLogType Serial
# jt-waf-mgr 讀 JSON 格式
SecAuditLogFormat JSON
SecAuditLog /var/log/modsecurity/modsec_audit.log
```

`SecAuditLogParts` 保留檔案原本的值即可。jt-waf-mgr 在寫入資料庫前會遮蔽請求內容裡的敏感欄位（密碼、權杖、Cookie 等），
但 nginx 主機上的**原始稽核記錄檔仍可能含有這些資料**：目錄與檔案只開放給需要讀的帳號（第 4 節）。

## 3. 主設定檔與 nginx

`/etc/nginx/modsec/main.conf`：

```apache
Include /etc/nginx/modsec/modsecurity.conf
```

建議的做法只需要這一行：jt-waf-mgr 安裝 CRS 時會在它後面插入 CRS 的 Include，納管時再在 CRS 規則前後加上 jt-waf-mgr
受管理的規則檔。站台自己的規則檔是選用的（第 7 節），沒有也能納管。

在 nginx 的 `http { }`（全部站台）或個別 `server { }` 加上：

```nginx
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```

**大型上傳。** nginx 的 ModSecurity 模組會先把整個請求內容讀進記憶體 (以及暫存檔)，ModSecurity 才開始檢查；
`SecRequestBodyLimit`、`SecRequestBodyLimitAction` 與 `ctl:requestBodyAccess=Off` 都改變不了。實測 libmodsecurity 3.0.14 與模組 1.0.3
(Ubuntu 26.04)：1 GB 上傳讓 nginx worker 用到 1.6～1.9 GB 記憶體；`modsecurity off` 時邊收邊轉，只用 8 MB。接收大檔的站台
(NAS、檔案分享) 請把 `client_max_body_size` 設在遠低於主機記憶體的值，或只對專門接收上傳的 location 關閉 ModSecurity
(前提是應用程式無法經由它做別的事)。系統檢查會對開了 ModSecurity、又設 `client_max_body_size 0` 或超過記憶體四分之一的站台發出警告。

## 4. 稽核記錄目錄與輪替

```sh
sudo install -d -m 750 -o root -g adm /var/log/modsecurity
```

這裡用 `adm` 群組當例子。jt-waf-mgr 的服務不在這個群組裡也沒關係：`install.sh` 會偵測稽核記錄目錄與檔案的群組（不是 root 的那個），
在 systemd 服務設定 `SupplementaryGroups`。

`/etc/logrotate.d/modsecurity`（libmodsecurity 在 reload 時不會重開檔案，所以要用 `copytruncate`）：

```
/var/log/modsecurity/modsec_audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

## 5. 檢查 nginx

```sh
sudo nginx -t && sudo systemctl reload nginx
```

此時尚未載入 OWASP CRS。`modsecurity.conf` 裡的基礎規則（例如請求本體解析錯誤、multipart 異常），或符合
`SecAuditLogRelevantStatus` 的回應，仍可能產生記錄；裝好 CRS 之後，依第 8 節確認事件裡出現 **CRS 的規則編號**。

## 6. 由 jt-waf-mgr 安裝 OWASP CRS 4（建議）

1. 照 [README](../README_zh-TW.md#安裝) 安裝 jt-waf-mgr、連到管理介面，並啟用套用程式（`sudo ./install.sh --enable-apply`）。
   執行 `sudo jt-waf-mgr check`（輸出見第 9 節）：`main_config` 是 nginx 載入的主設定檔，`crs.version` 此時是空的。
2. 在 CRS 頁開啟「由本系統保持 CRS 最新」。
3. jt-waf-mgr 會在最新的 CRS 4.x 發布滿 `wait_days`（預設 7 天）後下載，並用釘選的 CRS 簽章金鑰驗證。
4. 按「在沙箱比對並提出安裝」建立一筆變更。
5. 由人核准後，jt-waf-mgr 安裝 `crs-<版本>`、建立 `crs` 連結與 `crs-setup.conf`，並在 `modsecurity.conf` 之後插入
   Include。之後 `main.conf` 會是：

   ```apache
   Include /etc/nginx/modsec/modsecurity.conf
   Include /etc/nginx/modsec/crs-setup.conf
   Include /etc/nginx/modsec/crs/rules/*.conf
   ```

6. 接著納管（「規則 → 受管理的規則」，跟一般變更一樣由 admin 核准），在 CRS 規則前後加上 jt-waf-mgr 受管理的規則檔
   （`/etc/nginx/modsec/jt-waf-mgr/before-crs.conf` 與 `after-crs.conf`）。

之後的 CRS 更新也一樣：下載、驗證、沙箱比對、由人核准、安裝；保留 3 個版本可以退回。

## 7. 另一個做法：手動安裝 CRS

從 [CRS 的 GitHub releases](https://github.com/coreruleset/coreruleset/releases) 下載最新的 4.x 發行檔與對應的 `.asc`
簽章，依 CRS 文件以 `gpg --verify` 驗證後再解開。目錄用 `crs-<版本>` 命名、`crs` 連結指向它，之後才能交給 jt-waf-mgr
更新與退回（它認得的是 `crs-<版本>` 目錄）：

```sh
CRS=4.x.y                           # 換成實際版本
cd /etc/nginx/modsec
sudo mkdir crs-$CRS
sudo tar xzf ~/coreruleset-$CRS.tar.gz -C crs-$CRS --strip-components=1   # 檔名以 releases 頁面為準
sudo ln -sfn crs-$CRS crs           # 之後升級 CRS 只要換連結
sudo cp crs/crs-setup.conf.example crs-setup.conf
```

這時 `/etc/nginx/modsec/main.conf` 是：

```apache
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs-setup.conf
# 選用：站台自己的規則，放在 CRS 規則之前與之後（先建立檔案再取消註解：Include 不存在的檔案會讓設定載入失敗）
# Include /etc/nginx/modsec/site-before-crs.conf
Include /etc/nginx/modsec/crs/rules/*.conf
# Include /etc/nginx/modsec/site-after-crs.conf
```

這兩個站台規則檔是選用的，放站台自己的規則（排除、封鎖）。要用時先建立（可以是空的：
`sudo touch /etc/nginx/modsec/site-before-crs.conf /etc/nginx/modsec/site-after-crs.conf`），再取消上面兩行的註解。
沒有這兩個檔案時，納管會在 CRS 規則前後加入空的受管理檔案；有的話，納管會把其中的規則原樣匯入，並讓 `main.conf`
改為載入它管理的檔案。不論哪一種，之後的規則變更都經過 jt-waf-mgr 的流程，之後的 CRS 更新也可以照第 6 節交給 jt-waf-mgr。

## 8. 測試

用**實際受保護的站名**測試（多站台的主機上，`localhost` 可能進入預設的 vhost 或只收到轉址）。HTTPS 站台用 `--resolve`
連本機，保留正確的 Host 與 SNI；請求帶一個這次才用的值，方便在記錄裡找到這一筆：

```sh
sudo nginx -t && sudo systemctl reload nginx
SITE=www.example.com                 # 換成受保護的站名
T=jtwaf-test-$(date +%s)
curl -sk -o /dev/null -w '%{http_code}\n' --resolve $SITE:443:127.0.0.1 "https://$SITE/?q=<script>alert(1)</script>&t=$T"
sudo grep "$T" /var/log/modsecurity/modsec_audit.log | tail -n 1 | python3 -m json.tool | grep -iE '"(host|ruleid)"'
```

驗收標準：**這一筆請求在這個站台命中 CRS 的規則**（`ruleId` 是 9xxxxx 的 CRS 編號）。只記錄模式下回應碼照常（例如 200）。
jt-waf-mgr 啟動後，事件頁也會出現這一筆。

jt-waf-mgr 需要的設定：

- `SecAuditLogFormat JSON`，且 `SecAuditEngine` 不是 `Off`；
- 一個 Include `modsecurity.conf` 的主設定檔，由 nginx 的 `modsecurity on;` 與 `modsecurity_rules_file` 載入；
- 服務能穿越稽核記錄的每一層目錄並讀取檔案（`install.sh` 依檔案的群組設定，見第 4 節），而且確實收到新事件；
- OWASP CRS 4，由 jt-waf-mgr 安裝（第 6 節）或手動安裝（第 7 節）。

## 9. 檢查並改成封鎖

執行 `sudo jt-waf-mgr check`。它輸出 JSON，結束碼 0 表示沒有問題、1 表示有問題（列在 `problems`）：

- `main_config`：nginx 載入的 ModSecurity 主設定檔；
- `nginx_errors`、`modsec_errors`：設定解析錯誤；
- `crs.version`、`crs.rule_count`、`crs.engine_mode`：CRS 版本、規則數、`SecRuleEngine` 的值；
- `warnings`：例如 `audit_log_not_json`、`audit_engine_off`；
- `audit_log`、`audit_log_readable`、`audit_log_last_read`：稽核記錄檔、服務能不能讀（依 systemd 給服務的群組判斷；目錄只開放給服務的群組、從命令列看不到檔案權限時，依服務最近一次讀取的時間判斷，看不出來時是 `null`），以及服務最近一次讀取的時間；
- `problems`：會讓 jt-waf-mgr 無法運作的項目，以文字說明。

觀察一段時間、處理誤判之後，把 `modsecurity.conf` 的 `SecRuleEngine` 改成 `On`，再檢查並 reload：

```sh
sudo nginx -t && sudo systemctl reload nginx
sudo jt-waf-mgr check                # crs.engine_mode 應為 On
```

最後用第 8 節的請求再測一次：回應應為 403，稽核記錄裡同一筆請求命中 CRS 規則。
