# 更新後に nginx が戻らないとき

[English](RECOVERY.md) · [繁體中文](RECOVERY.zh-TW.md) · **日本語**

jt-waf-mgr は nginx と ModSecurity モジュールをサービスを止めずに更新し、いずれかの手順が失敗すると (新しいプログラムが起動しない、`nginx -t` の失敗、ヘルスチェックの応答の変化) 以前のパッケージとモジュールを自動で戻します。このページはそれ以外の場合、つまり更新後しばらくしてから問題が出た場合や、自動の戻しも成功しなかった場合のためのものです。

## 1. jt-waf-mgr が保管するもの

- nginx の更新 (およびモジュールの切り替え、戻し) の前に、root プログラムは以前の nginx パッケージと使用中のモジュールを自分のディレクトリ (`/var/lib/jt-waf-mgr-apply/nginx-update/`) に保管します。直近の成功した更新分が残り、nginx 更新ページにどの変更を戻せるかが表示されます。
- nginx 更新ページ (と nginx 更新の承認画面) の「バックアップをダウンロード」で、承認前に nginx 設定、使用中のモジュール、手動手順の `RESTORE.txt` を保存できます。秘密鍵とパスワードファイルは含めません。ワンタイムコードが必要で、記録されます。

## 2. 管理画面に接続できない

管理画面は通常 nginx 経由ですが、Web サービス自体は nginx を必要とせず、ホスト上で待ち受けています (既定は `127.0.0.1:8095`)。

- 自分の PC から：`ssh -L 8095:127.0.0.1:8095 root@<WAF ホスト>` の後、Chrome または Edge で `http://localhost:8095` を開き、通常どおりサインインします (Chromium 系ブラウザーで確認済み)。
- ホスト上ではコマンドで同じことができます (こちらも nginx を経由しません)：

```
jt-waf-mgr nginx status
jt-waf-mgr nginx rollback --reason "更新後にサイトが壊れた" --as <管理者>
jt-waf-mgr changes approve <ID> --note "nginx を戻す：サイトが壊れた" --totp <コード> --as <管理者>
jt-waf-mgr nginx backup -o /var/tmp/nginx-backup.tar.gz --totp <コード> --as <管理者>
```

戻しは他の nginx 変更と同じく、管理者がワンタイムコードと 10 文字以上の説明で承認し、root プログラムがサービスを止めずに戻します (ヘルスチェックも同じ)。

## 3. 手動で戻す (jt-waf-mgr でも戻せないとき)

WAF ホストで root として：

1. まず確認：`systemctl status nginx`、`nginx -t`、`journalctl -u nginx -n 50`。
2. モジュール：バックアップの `module/ngx_http_modsecurity_module.so`、または `/var/lib/jt-waf-mgr-apply/nginx-update/` の最新ディレクトリにある `previous-ngx_http_modsecurity_module.so`：
   `install -m 644 <ファイル> /usr/lib/nginx/modules/ngx_http_modsecurity_module.so`
3. パッケージも戻す場合：同じディレクトリの `old.deb` (`dpkg -i old.deb`)、または `apt-get install nginx=<以前のバージョン>`。その後 `apt-mark hold nginx`。
4. `nginx -t` が通ったら `systemctl reload nginx` (実行中の nginx のモジュールを切り替えるには `kill -USR2 $(cat /run/nginx.pid)`、新しいマスターが応答したら `kill -QUIT $(cat /run/nginx.pid.oldbin)`。nginx が動いていなければ `systemctl start nginx`)。
5. サイトを確認したら、jt-waf-mgr が出す「設定が外部で変更された」アラートを、行った内容を書いて処理済みにします。

## 4. 次の更新の前に

- 設定 → 変更ワークフローで重要なサイト (管理画面を含む) のヘルスチェック URL を設定してください。更新でどれかが壊れると自動で戻ります。
- 承認なしで更新したい場合を除き、「nginx のセキュリティ更新を自動適用」は無効のままにしてください。既定は無効で、有効にするには管理者のワンタイムコードが必要です。
