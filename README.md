# pyl2tpvpn

OS全体をVPNに接続せず、Pythonプログラムで使う通信だけをVPNへ流すためのライブラリです。
L2TP/IPsecとネイティブIKEv2/IPsecに対応し、RequestsでHTTP・HTTPS通信を試せるコンソールも付けています。

例えば、普段の通信はそのままにして、Pythonから行うAPIへのアクセスだけをVPN経由にしたい場合などに使えます。
OSのルーティング設定やDNS設定は変更せず、VPN用の通信処理をPythonプログラム内で動かします。

**現在はベータ版です。** Python 3.11以降を対象にしています。実機での動作確認はWindowsで行っており、対応範囲と制限は[こちら](docs/PROTOCOLS.md)にまとめています。

## まずはコンソールで試す

Python 3.11以降を用意し、ソース一式を展開してください。Windowsでは、展開したフォルダーでPowerShellを開き、次のように実行できます。

```powershell
.\start_console.cmd --server vpn.example.net --username alice
```

これはL2TP/IPsecで接続する例です。初回は仮想環境と必要なライブラリを準備しますので、インターネット接続が必要です。
`vpn.example.net` と `alice` は、それぞれ接続先とユーザー名に置き換えてください。PPPパスワードと事前共有鍵は、起動後に非表示で入力します。

接続できたら、次のようにコマンドを入力してください。

```text
vpn> requests https://example.com/
vpn> requests example.com/example
vpn> status
vpn> disconnect
vpn> connect
vpn> quit
```

URLの `https://` を省略した場合はHTTPSでアクセスします。`example.com/example` のように存在しないページへアクセスして404が返った場合も、HTTPの応答として表示します。
コマンド一覧は `help`、詳しい使い方は `help requests` で確認できます。

### IKEv2で接続する場合

```powershell
.\start_console.cmd --ike-version 2 --server vpn.example.net --local-id client.example.net --remote-id gateway.example.net
```

接続先に合わせて、クライアントIDとサーバーの応答IDを指定してください。ネイティブIKEv2ではL2TP・PPPを使わないため、PPPユーザー名やPPPパスワードの入力は不要です。

**一部のリモートアクセス構成では、IKEリキー後に旧SAを削除すると通信が停止する現象を確認しています。** その場合は、上のコマンドに `--ikev2-renewal reauthenticate` を追加し、再認証によって鍵を更新できます。
同じIPアドレスが再割り当てされた場合は既存のTCP接続を保ちますが、更新時に短い通信の空白があります。[設定と検証した範囲](docs/INTEROPERABILITY.md)も確認してください。

## Pythonプログラムから使う

Requestsを使う場合は、Releaseのwheelから必要なライブラリをまとめてインストールできます。

```sh
python -m pip install "pyl2tpvpn[console] @ https://github.com/miniai-saka/pyl2tpvpn/releases/download/v0.3.0/pyl2tpvpn-0.3.0-py3-none-any.whl"
```

次はL2TP/IPsecで接続し、HTTPSへアクセスする例です。`VPN_SERVER` と `VPN_USERNAME` を環境変数に設定してから実行してください。
パスワードと事前共有鍵は非表示で入力します。

```python
import getpass
import os
from pyl2tpvpn import VPNConfig
from pyl2tpvpn.runtime import VPNRuntime
from pyl2tpvpn.console import make_requests_session

config = VPNConfig(
    server=os.environ["VPN_SERVER"],
    username=os.environ["VPN_USERNAME"],
    password=getpass.getpass("PPPパスワード: "),
    psk=getpass.getpass("事前共有鍵: "),
)
runtime = VPNRuntime(config)
try:
    runtime.connect()
    with make_requests_session(runtime.request_route()) as session:
        response = session.get("https://example.com/", timeout=20)
        print(response.status_code)
        print(response.text)
finally:
    runtime.close()
```

`VPNRuntime` は別スレッドでVPNを動かしますので、Requestsの応答を待っている間も鍵更新と死活監視を継続します。
非同期処理では `VPNClient` からTCP・UDP通信、名前解決、pingを利用できます。

通常の `requests.get()` を呼ぶだけでVPN経由になるわけではありません。このライブラリのAPIや、同梱コンソールのVPN用セッションから行う通信が対象です。

- [ライブラリの使い方：IKEv2設定・TCP・UDP・API一覧](docs/LIBRARY.md)
- [インストールとコンソールの使い方](docs/USAGE.md)
- [非同期APIの例](examples/basic.py)
- [Requestsを使う例](examples/requests_vpn.py)
- [UDP通信の例](examples/udp_echo.py)

コンソールでは、名前解決もVPN内で行い、HTTPSの証明書を検証します。VPNが切れた際に、直接接続へ自動で切り替えることはありません。

## 対応範囲について

このバージョンでは、PSK認証、AES-CBC、HMAC-SHA1を使うIPv4通信を対象にしています。
AHはパケット処理の実装・検証のみで、AHを交渉するVPN接続には対応していません。IPv6、EAP・証明書認証、MOBIKEなども未対応です。

暗号処理にはPyCryptodomeを使用しています。Scapyとcryptographyは相互検証テストに使用しており、VPN本体の実行には必要ありません。
詳しい内容は、必要に応じて次の文書を参照してください。

- [対応プロトコルと未対応機能](docs/PROTOCOLS.md)
- [通信の仕組みと実装上の上限](docs/ARCHITECTURE.md)
- [接続先による設定の違い・鍵更新の注意点](docs/INTEROPERABILITY.md)
- [セキュリティについて](SECURITY.md)

## 動作確認

手元の環境で約10時間、さまざまなプロトコルを使って検証し、問題なく動作することを確認しています。
接続先の設定や対応する認証方式は環境によって異なりますので、[対応範囲](docs/PROTOCOLS.md)と[接続先ごとの設定](docs/INTEROPERABILITY.md)を確認したうえで使ってください。

## 作者・ライセンス

作者：miniai-saka

MITライセンスです。利用条件は [LICENSE](LICENSE) を確認してください。

[qwj/python-vpn](https://github.com/qwj/python-vpn) を参考にし、同プロジェクトのMITライセンス付きコードをテスト用の参照実装として収録しています。
出典と変更点は [tests/reference_pvpn/ORIGIN.md](tests/reference_pvpn/ORIGIN.md)、参照実装のライセンスは [こちら](tests/reference_pvpn/LICENSE) に記載しています。

変更点は [CHANGELOG.md](CHANGELOG.md)、開発・修正に関する案内は [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。
