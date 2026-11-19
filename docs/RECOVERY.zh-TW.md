# nginx 升級後起不來時

[English](RECOVERY.md) · **繁體中文** · [日本語](RECOVERY.ja.md)

jt-waf-mgr 升級 nginx 與 ModSecurity 模組時不中斷服務，任何一步失敗 (新程式沒起來、`nginx -t` 不過、健康檢查回應不同) 都會自動裝回舊的套件與模組。這份手冊處理剩下的情況：升級後過一陣子才出問題，或連自動還原都沒成功。

## 1. jt-waf-mgr 保留了什麼

- 每次 nginx 升級 (以及換模組、退回) 之前，root 程式會把舊的 nginx 套件和正在使用的模組保留在自己的目錄 (`/var/lib/jt-waf-mgr-apply/nginx-update/`)，最近幾次成功的升級都留著；nginx 更新頁會顯示哪一筆變更可以退回。
- nginx 更新頁 (以及 nginx 更新的核准畫面) 的「下載備份」可以在核准前先存一份：nginx 設定、使用中的模組，以及手動還原步驟 `RESTORE.txt`。私鑰與密碼檔不會放進去；每次下載都要一次性驗證碼並記錄。

## 2. 管理介面連不上

管理介面平常透過 nginx 存取，但網頁服務本身不需要 nginx，它在主機上監聽 (預設 `127.0.0.1:8095`)。

- 從自己的電腦：`ssh -L 8095:127.0.0.1:8095 root@<WAF 主機>`，再用 Chrome 或 Edge 開 `http://localhost:8095`，照常登入 (已用 Chromium 內核的瀏覽器驗證)。
- 在主機上用指令也能做一樣的事 (同樣不經過 nginx)：

```
jt-waf-mgr nginx status
jt-waf-mgr nginx rollback --reason "升級後站台出問題" --as <管理者>
jt-waf-mgr changes approve <編號> --note "退回 nginx：站台出問題" --totp <驗證碼> --as <管理者>
jt-waf-mgr nginx backup -o /var/tmp/nginx-backup.tar.gz --totp <驗證碼> --as <管理者>
```

退回和其他 nginx 變更一樣：管理者用一次性驗證碼與至少 10 個字的說明核准，root 程式不中斷服務地換回去，同樣經過健康檢查。

## 3. 手動退回 (jt-waf-mgr 也無法處理時)

在 WAF 主機上用 root：

1. 先看狀況：`systemctl status nginx`、`nginx -t`、`journalctl -u nginx -n 50`。
2. 模組：備份裡的 `module/ngx_http_modsecurity_module.so`，或 `/var/lib/jt-waf-mgr-apply/nginx-update/` 最新目錄裡保留的 `previous-ngx_http_modsecurity_module.so`：
   `install -m 644 <檔案> /usr/lib/nginx/modules/ngx_http_modsecurity_module.so`
3. 套件也要換回時：同一個目錄裡的 `old.deb` (`dpkg -i old.deb`)，或 `apt-get install nginx=<舊版本>`；之後 `apt-mark hold nginx`。
4. `nginx -t` 通過後 `systemctl reload nginx` (執行中的 nginx 要換模組，只能用 `kill -USR2 $(cat /run/nginx.pid)`，新主程序正常後再 `kill -QUIT $(cat /run/nginx.pid.oldbin)`；nginx 完全沒在跑時用 `systemctl start nginx`)。
5. 確認站台正常後，把 jt-waf-mgr 發出的「設定被外部修改」警示標記已處理，寫上做了什麼。

## 4. 下次升級之前

- 在設定 → 變更流程的「健康檢查網址」加入重要站台 (包含管理介面本身)：升級弄壞其中任何一個都會自動還原。
- 除非你要不經核准就升級，否則「nginx 安全更新自動套用」保持關閉；預設是關閉的，開啟要管理者的一次性驗證碼。
