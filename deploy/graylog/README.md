# jt-waf-mgr Graylog 內容套件

jt-waf-mgr 以 GELF 1.1 外送的 WAF 事件、警示與稽核記錄，在 Graylog 中的串流、管線、儀表板與事件定義。

- 檔案：`jt-waf-mgr.json` (Graylog 內容套件，名稱 `jt-waf-mgr`，版本 1)
- 適用：Graylog 6.3 以上 (從 6.3.15 匯出；已在 6.3.15 與 7.2.2 實際安裝並驗證)
- jt-waf-mgr：0.5.48 以上 (送出 `_site`、`_country`、`_country_name`)。較舊版本仍可使用，但「依站台」與「依國家」沒有資料。

## 內容

| 類型 | 名稱 | 說明 |
|---|---|---|
| 串流 | jt-waf-mgr WAF 事件/警示/稽核 | 條件：`jt_type` 等於 `event`/`alert`/`audit`，且有 `jt_event` 欄位。訊息仍保留在 Default Stream。 |
| 管線 | jt-waf-mgr (2 條規則) | 只處理 WAF 事件：把逗號分隔的 `rules`、`families` 拆成多值的 `waf_rule`、`waf_family`，才能統計前幾名規則與攻擊類型。 |
| 儀表板 | jt-waf-mgr 總覽 | 封鎖/只記錄/內外部來源封鎖數、時間趨勢、依站台、內外部、來源 IP 前幾名、依國家、前幾名規則、攻擊類型、外部來源封鎖地圖、最新封鎖事件。 |
| 儀表板 | jt-waf-mgr 警示 | 嚴重警示數、依嚴重度、依來源、趨勢、依類型 (不寫死類型清單)、最新警示。 |
| 儀表板 | jt-waf-mgr 稽核 | 結果不是 ok 的數量與清單、誰做了什麼、最新稽核記錄。 |
| 事件定義 | 嚴重警示 | `severity:critical` 的警示，每筆產生事件。 |
| 事件定義 | 封鎖量暴增 | 5 分鐘內封鎖 1,000 次以上。 |
| 事件定義 | 內部來源被封鎖 | 內部來源被封鎖，依來源 IP 分開。 |
| 事件定義 | 稽核失敗 | 稽核結果不是 `ok`，每筆產生事件。 |
| 事件定義 | 單一來源大量封鎖 | 同一來源 IP 在 5 分鐘內被封鎖 300 次以上。 |

事件定義的門檻刻意保守，請依站台流量調整。套件**沒有**附帶任何通知：事件只會出現在 Graylog 的「Alerts」頁面，需要通知時請自行在各事件定義加入。

## 匯入步驟

1. Graylog 要有 GELF 輸入 (TCP、UDP 或 TLS 皆可)，jt-waf-mgr 的「設定 → 外送記錄」指向它。
2. Graylog「System → Content Packs → Upload」上傳 `jt-waf-mgr.json`，再按「Install」。
3. 到「Streams」把三條 `jt-waf-mgr` 串流**啟用 (Start Stream)**：Graylog 匯入的串流一律是暫停狀態，暫停時串流與管線都不會處理記錄。
4. 確認「System → Configurations → Message Processors」中，Message Filter Chain 排在 Pipeline Processor 之前 (Graylog 預設如此)，管線才會在串流分流後執行。
5. 外部來源封鎖地圖需要 Graylog 的 GeoIP：「System → Configurations → Geo-Location Processor」啟用並指定 MaxMind 資料庫，且在 Message Processors 中啟用 GeoIP Resolver。它會替 `src` 加上 `src_geolocation`。沒有 GeoIP 時地圖是空的，其他元件照常可用；「依國家」使用 jt-waf-mgr 自己送的國家欄位，不需要 GeoIP。

## 欄位 (Graylog 收到後的名稱)

GELF 附加欄位的底線會被去掉：`_src` → `src`、`_outcome` → `outcome`，以此類推。實測結果：

- GELF 的 `host` 會成為 `source` (WAF 主機名稱)。
- **`_host` 會被 Graylog 丟掉** (實測 Graylog 7.2.2)，所以站台名稱改用 `_site` → `site`。
- `_message` 與 `short_message` 合併成同一個 `message`。
- `_status`、`_score`、`_alert_id`、`_audit_id` 是數字。
- `rules`、`families` 保留原本的逗號分隔字串；拆開後的值在 `waf_rule`、`waf_family`。

## 移除

「System → Content Packs」找到 `jt-waf-mgr` → 移除安裝。Graylog 列出的移除清單只包含這個套件建立的項目；GELF 輸入不在套件中，不會被移除。

## 實測記錄

用拋棄式 Graylog 安裝本套件，送入合成的 jt-waf-mgr GELF 記錄 (1,503 筆 WAF 事件、4 筆警示、3 筆稽核，加上一筆不屬於 jt-waf-mgr 的訊息)，確認：

- 三條串流各自收到全部對應記錄，不屬於 jt-waf-mgr 的訊息不會進入。
- `waf_rule`、`waf_family` 的統計與送出的值完全一致。
- 五個事件定義都在排程執行後產生事件。
- 三個儀表板開啟時每個元件都正常顯示。

所有範例只使用合成資料 (example.com、192.0.2.0/24、198.51.100.0/24、203.0.113.0/24)。
