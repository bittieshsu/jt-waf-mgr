# ModSecurity インストールガイド（nginx + libmodsecurity v3 + OWASP CRS 4）

[English](MODSECURITY.md) · [繁體中文](MODSECURITY.zh-TW.md) · **日本語**

nginx だけがある（またはまだ何もない）ホストから、jt-waf-mgr が必要とする ModSecurity 環境を構築する手順です。
用意するのは nginx、ModSecurity モジュール、`modsecurity.conf` とメイン設定ファイルです（第 1–5 節）。OWASP CRS はその後
jt-waf-mgr に任せます。jt-waf-mgr が CRS 4 をダウンロード・検証・インストールし、承認された変更を通じて最新に保ちます（第 6 節、
推奨する方法）。CRS を手動でインストールすることもできます（第 7 節）。すでに ModSecurity を運用しているサイトは、第 8 節の
最後にある「jt-waf-mgr に必要な設定」と照らし合わせるだけで構いません。

最初の構築では、nginx の設定は自分で変更します：`modsecurity on;`（第 3 節）と管理画面の vhost
（[README](../README_ja.md)）。その後 jt-waf-mgr が書き込むのは ModSecurity のルールファイルです。nginx の設定を読み（サイトと
ModSecurity のメイン設定ファイルを見つけるため）、`nginx -t` を実行して reload します。nginx の設定に触れるのは次の場合だけで、
いずれも変更フロー（検査、承認、`nginx -t`、reload、失敗時は元に戻す）を通ります：

- サイトの WAF の有効化/無効化、ブロックページの配置：条件に合う `server` ブロックに印付きの `include` を 1 行追加または削除；
- 一時的な IP ブロック：`deny` 行だけのリストファイル 1 つ。`http { }` での include は一度だけ自分で行います。

> まず「記録のみ」（`DetectionOnly`）で稼働させ、jt-waf-mgr でしばらくイベントを観察して誤検知を処理してから、ブロック
> （`On`）に切り替えてください。

## 1. システムとパッケージ

- Debian 12 / 13：`libnginx-mod-http-modsecurity`。libmodsecurity 3.0.9 以上が一緒にインストールされます。
- Ubuntu 24.04：`libnginx-mod-http-modsecurity`。libmodsecurity 3.0.12（パッケージ名 `libmodsecurity3t64`）。
- Ubuntu 26.04：`libnginx-mod-http-modsecurity`。libmodsecurity 3.0.14（パッケージ名 `libmodsecurity3t64`）。
- Ubuntu 22.04：パッケージの libmodsecurity が 3.0.9 未満です。24.04 を使うか、自分でビルドしてください。

新しいホスト（`--no-install-recommends`：コネクターはディストリビューションの CRS 3 を推奨パッケージにしており、既定では一緒に
入ります）：

```sh
sudo apt install --no-install-recommends nginx libnginx-mod-http-modsecurity
```

パッケージのバージョンと入手元、実際に読み込まれている設定を確認します（パッケージがあることと、モジュールやルールが読み込まれて
いることは別です）：

```sh
# バージョン 3.0.9 以上。nginx とコネクターが同じリポジトリから
apt-cache policy nginx libnginx-mod-http-modsecurity libmodsecurity3 libmodsecurity3t64
# 有効な設定に load_module、modsecurity on、modsecurity_rules_file があること
sudo nginx -T 2>/dev/null | grep -E 'load_module .*modsecurity|modsecurity (on|off)|modsecurity_rules_file'
```

コネクターモジュールは、実行中の nginx のバージョンとモジュール ABI に互換である必要があります（Debian / Ubuntu のパッケージは
`nginx-abi-*` の依存関係で対応させています）。nginx.org のパッケージではディストリビューションのモジュールは読み込めません。
ディストリビューションの nginx を使うか、同じバージョンの nginx ソース（`./configure --with-compat --add-dynamic-module=ModSecurity-nginx`）
で動的モジュールをビルドしてください。

ディストリビューションの `modsecurity-crs` パッケージは CRS 3.3 なので、**使わないでください**。すでに入っているホストでは、上の
`nginx -T` で実際に Include されているルールを確認します。CRS 4 は jt-waf-mgr がインストールする（第 6 節）か、手動でインストールします
（第 7 節）。

## 2. ModSecurity の基本設定

設定は `/etc/nginx/modsec/` に置きます。`modsecurity.conf-recommended` と `unicode.mapping` は、ModSecurity のソースの
**お使いの libmodsecurity と同じバージョン**のタグから取得します（[github.com/owasp-modsecurity/ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)）。

```sh
sudo install -d -m 755 /etc/nginx/modsec
# 上流のバージョン：apt-cache policy が 3.0.9-1+deb12u2 なら 3.0.9（Debian / Ubuntu の改訂番号を除く）
V=3.0.9
cd /etc/nginx/modsec
sudo curl -fLo modsecurity.conf https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v$V/modsecurity.conf-recommended
sudo curl -fLO https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v$V/unicode.mapping
```

`modsecurity.conf` で次の行を確認または変更します：

```apache
# まず記録のみ。観察後に On（第 9 節）
SecRuleEngine DetectionOnly
SecAuditEngine RelevantOnly
SecAuditLogType Serial
# jt-waf-mgr は JSON 形式を読みます
SecAuditLogFormat JSON
SecAuditLog /var/log/modsecurity/modsec_audit.log
```

`SecAuditLogParts` はファイル元の値のままで構いません。jt-waf-mgr はリクエストの機密項目（パスワード、トークン、Cookie など）を
データベースに書き込む前にマスクしますが、**nginx ホスト上の元の監査ログには残る可能性があります**。ディレクトリとファイルは
必要なアカウントだけに開放してください（第 4 節）。

## 3. メイン設定ファイルと nginx

`/etc/nginx/modsec/main.conf`：

```apache
Include /etc/nginx/modsec/modsecurity.conf
```

推奨する方法ではこの 1 行だけで済みます。jt-waf-mgr が CRS をインストールするときにこの後へ CRS の Include を挿入し、取り込み時に
CRS ルールの前後へ jt-waf-mgr の管理ルールファイルを追加します。サイト独自のルールファイルは任意で（第 7 節）、なくても取り込めます。

nginx の `http { }`（全サイト）または個別の `server { }` に追加します：

```nginx
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```

## 4. 監査ログのディレクトリとローテーション

```sh
sudo install -d -m 750 -o root -g adm /var/log/modsecurity
```

`adm` は例です。jt-waf-mgr のサービスがこのグループに入っている必要はありません。`install.sh` が監査ログのディレクトリとファイルの
グループ（root 以外）を調べ、systemd サービスの `SupplementaryGroups` に設定します。

`/etc/logrotate.d/modsecurity`（libmodsecurity は reload でファイルを開き直さないため `copytruncate` を使います）：

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

## 5. nginx の確認

```sh
sudo nginx -t && sudo systemctl reload nginx
```

この時点では OWASP CRS はまだ読み込まれていません。`modsecurity.conf` の基本ルール（リクエスト本体の解析エラー、multipart の異常
など）や `SecAuditLogRelevantStatus` に合う応答は記録されることがあります。CRS を入れた後、第 8 節でイベントに **CRS のルール番号**
が出ることを確認してください。

## 6. jt-waf-mgr による OWASP CRS 4 のインストール（推奨）

1. [README](../README_ja.md) のとおりに jt-waf-mgr をインストールし、管理画面に接続して、適用プログラムを有効にします
   （`sudo ./install.sh --enable-apply`）。`sudo jt-waf-mgr check` を実行します（出力は第 9 節）：`main_config` が nginx の
   読み込むメイン設定ファイルで、この時点では `crs.version` は空です。
2. CRS ページで「このシステムで CRS を最新に保つ」をオンにします。
3. jt-waf-mgr は最新の CRS 4.x が公開から `wait_days`（既定 7 日）たった後にダウンロードし、固定した CRS 署名鍵で検証します。
4. 「サンドボックスで比較してインストールを提案」で変更を作成します。
5. 人が承認すると、jt-waf-mgr は `crs-<バージョン>` をインストールし、`crs` リンクと `crs-setup.conf` を作り、`modsecurity.conf`
   の後に Include を挿入します。その後の `main.conf` は次のとおりです：

   ```apache
   Include /etc/nginx/modsec/modsecurity.conf
   Include /etc/nginx/modsec/crs-setup.conf
   Include /etc/nginx/modsec/crs/rules/*.conf
   ```

6. 続いて取り込みます（「ルール → 管理ルール」、通常の変更と同じく admin が承認）。CRS ルールの前後に jt-waf-mgr の管理ルール
   ファイル（`/etc/nginx/modsec/jt-waf-mgr/before-crs.conf` と `after-crs.conf`）が入ります。

以後の CRS 更新も同じです：ダウンロード、検証、サンドボックスでの比較、人による承認、インストール。戻せるように 3 バージョンを
残します。

## 7. 別の方法：CRS の手動インストール

[CRS の GitHub releases](https://github.com/coreruleset/coreruleset/releases) から最新の 4.x リリースと対応する `.asc` 署名を
ダウンロードし、CRS のドキュメントに従って `gpg --verify` で検証してから展開します。ディレクトリ名は `crs-<バージョン>` にし、
`crs` リンクをそこへ向けます。こうすると後で jt-waf-mgr が更新・戻しを行えます（jt-waf-mgr が認識するのは `crs-<バージョン>`
ディレクトリです）：

```sh
CRS=4.x.y                           # 実際のバージョン
cd /etc/nginx/modsec
sudo mkdir crs-$CRS
sudo tar xzf ~/coreruleset-$CRS.tar.gz -C crs-$CRS --strip-components=1   # ファイル名は releases ページのとおり
sudo ln -sfn crs-$CRS crs           # 以後の CRS の更新はリンクを変えるだけ
sudo cp crs/crs-setup.conf.example crs-setup.conf
```

このときの `/etc/nginx/modsec/main.conf`：

```apache
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs-setup.conf
# 任意：サイト独自のルールを CRS ルールの前後に（先にファイルを作ってからコメントを外す。存在しないファイルを
# Include すると設定の読み込みに失敗します）
# Include /etc/nginx/modsec/site-before-crs.conf
Include /etc/nginx/modsec/crs/rules/*.conf
# Include /etc/nginx/modsec/site-after-crs.conf
```

この 2 つのサイト用ファイルは任意で、サイト独自のルール（除外、ブロック）を置きます。使う場合は先に作成し（空でも構いません：
`sudo touch /etc/nginx/modsec/site-before-crs.conf /etc/nginx/modsec/site-after-crs.conf`）、上の 2 行のコメントを外します。
ファイルがない場合、取り込みは CRS ルールの前後に空の管理ファイルを追加します。ある場合は、その中のルールをそのまま取り込み、
`main.conf` が管理ファイルを読み込むように変えます。どちらの場合も、以後のルール変更は jt-waf-mgr のフローを通り、CRS の更新も
第 6 節のように jt-waf-mgr に任せられます。

## 8. テスト

**実際に保護しているサイト名**でテストします（複数サイトのホストでは、`localhost` は既定の vhost に入ったり、リダイレクトだけ
受け取ったりします）。HTTPS のサイトは `--resolve` でこのホストに接続し、正しい Host と SNI を保ちます。リクエストには今回だけ
使う値を付け、記録の中で見つけられるようにします：

```sh
sudo nginx -t && sudo systemctl reload nginx
SITE=www.example.com                 # 保護しているサイト名
T=jtwaf-test-$(date +%s)
curl -sk -o /dev/null -w '%{http_code}\n' --resolve $SITE:443:127.0.0.1 "https://$SITE/?q=<script>alert(1)</script>&t=$T"
sudo grep "$T" /var/log/modsecurity/modsec_audit.log | tail -n 1 | python3 -m json.tool | grep -iE '"(host|ruleid)"'
```

合格の基準：**このリクエストが、このサイトで CRS のルールに一致した**こと（`ruleId` が 9xxxxx の CRS 番号）。記録のみモードでは
応答コードは通常どおり（例えば 200）です。jt-waf-mgr の起動後は、イベントページにもこのリクエストが表示されます。

jt-waf-mgr に必要な設定：

- `SecAuditLogFormat JSON`、かつ `SecAuditEngine` が `Off` でないこと；
- `modsecurity.conf` を Include するメイン設定ファイルが、nginx の `modsecurity on;` と `modsecurity_rules_file` で読み込まれていること；
- サービスが監査ログのすべてのディレクトリを通過してファイルを読めること（`install.sh` がファイルのグループから設定、第 4 節）、
  そして新しいイベントが実際に届くこと；
- OWASP CRS 4。jt-waf-mgr がインストール（第 6 節）または手動でインストール（第 7 節）。

## 9. 確認してからブロックへ

`sudo jt-waf-mgr check` を実行します。JSON を出力し、終了コード 0 は問題なし、1 は問題あり（`problems` に一覧）です：

- `main_config`：nginx が読み込む ModSecurity のメイン設定ファイル；
- `nginx_errors`、`modsec_errors`：設定の解析エラー；
- `crs.version`、`crs.rule_count`、`crs.engine_mode`：CRS のバージョン、ルール数、`SecRuleEngine` の値；
- `warnings`：例えば `audit_log_not_json`、`audit_engine_off`；
- `audit_log`、`audit_log_readable`、`audit_log_last_read`：監査ログ、サービスが読めるかどうか（systemd がサービスに与えるグループで判断。サービスのグループにだけ開いたディレクトリでコマンドラインからファイルの権限が見えないときは、サービスが最後に読んだ時刻で判断し、分からなければ `null`）、サービスが最後に読んだ時刻；
- `problems`：jt-waf-mgr が動作できない理由の説明。

しばらく観察して誤検知を処理したら、`modsecurity.conf` の `SecRuleEngine` を `On` に変え、確認して reload します：

```sh
sudo nginx -t && sudo systemctl reload nginx
sudo jt-waf-mgr check                # crs.engine_mode が On になっていること
```

最後に第 8 節のリクエストをもう一度送ります：応答は 403 になり、監査ログの同じリクエストが CRS のルールに一致しているはずです。
