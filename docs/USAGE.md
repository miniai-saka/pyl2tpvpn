# 使い方

Python 3.11以降と、接続先のVPNサーバーに合った設定が必要です。接続先のホスト名、事前共有鍵、認証情報は、ご自身の環境のものを指定してください。

## インストール

ソース一式を展開し、そのフォルダーで実行します。

### Windows

コンソールを使う場合は、`start_console.cmd` が仮想環境の作成とライブラリのインストールを行います。Pythonを別のプログラムから使う場合など、手動で準備する場合は次のように実行してください。

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install ".[console]"
```

### Linux・macOS

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[console]'
```

以降の `python` は、用意した仮想環境のPythonに読み替えてください。Windowsでは `.\.venv\Scripts\python.exe`、Linux・macOSでは `.venv/bin/python` を使えます。
Linux・macOSについては、ここでは準備方法を記載しています。実機での確認済み環境はWindowsです。

VPN本体だけを組み込む場合は `python -m pip install .` でインストールできます。Requestsコンソールを使う場合は `.[console]` を指定してください。

Releaseのwheelからもインストールできます。VPN本体だけを使う場合は次のように指定します。

```sh
python -m pip install "https://github.com/miniai-saka/pyl2tpvpn/releases/download/v0.3.0/pyl2tpvpn-0.3.0-py3-none-any.whl"
```

Requestsも使う場合は、[READMEのインストール例](../README.md#pythonプログラムから使う)のように `[console]` を指定してください。ライブラリとして組み込む際の設定とAPIは [LIBRARY.md](LIBRARY.md) にまとめています。

## 接続する

L2TP/IPsecでは、接続先・PPPユーザー名・PPPパスワード・事前共有鍵を使います。

```sh
python -m pyl2tpvpn console --server vpn.example.net --username alice
```

ネイティブIKEv2では、接続先・事前共有鍵・接続先に合うIDを使います。

```sh
python -m pyl2tpvpn console --ike-version 2 --server vpn.example.net --local-id client.example.net --remote-id gateway.example.net
```

`--local-id` は自分側のIDで、指定した文字列をFQDN形式として送信します。`--remote-id` は相手が認証応答で返すIDを照合するための値です。
サーバーの接続先ホスト名と応答IDが同じとは限りませんので、設定を確認してください。IDrを要求にも含める必要がある場合は `--request-remote-id` を追加できます。

PPPパスワードと事前共有鍵は、通常は起動後に非表示で入力します。`VPN_SERVER`、`VPN_USERNAME`、`VPN_PASSWORD`、`VPN_PSK`、`VPN_LOCAL_ID`、`VPN_REMOTE_ID` の環境変数から指定することもできます。
同梱の `.env.example` は設定項目の例です。`.env` ファイルを自動で読み込む機能はありません。

## コンソールの操作

HTTP・HTTPSのアクセスには `requests` コマンドを使います。

```text
vpn> requests https://example.com/
vpn> requests example.com/example --preview 500
vpn> requests POST https://api.example.net/items --json '{"name":"test"}'
vpn> requests https://example.com/file --save download.bin
vpn> resolve example.com
vpn> status
vpn> disconnect
vpn> connect
vpn> quit
```

- URLのスキームを省略した場合はHTTPSになります。
- `--preview` は画面に表示する本文の文字数です。
- `--save` は応答本文をファイルへ保存します。既に存在するファイルには上書きしません。
- 404などのHTTPエラーも、アクセス先から返ってきた応答として表示します。
- `status` では接続状態・割り当てIP・鍵更新の回数などを確認できます。

詳しいオプションは `help requests` を確認してください。
コマンドをまとめて実行し、終了する使い方もできます。

```sh
python -m pyl2tpvpn console --server vpn.example.net --username alice --command "requests https://example.com/" --command status
```

実行後も入力を続ける場合は `--interactive` を追加してください。

## PythonからRequestsを使う

同期処理では `VPNRuntime` が別スレッドでVPNの通信処理を動かします。そのため、Requestsの応答やコンソール入力を待っている間も、鍵更新や死活監視を継続できます。

```python
import getpass
from pyl2tpvpn import VPNConfig
from pyl2tpvpn.runtime import VPNRuntime
from pyl2tpvpn.console import make_requests_session

config = VPNConfig(
    server="vpn.example.net",
    ike_version=2,
    local_id="client.example.net",
    remote_id="gateway.example.net",
    psk=getpass.getpass("事前共有鍵: "),
    mtu=1280,
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

このセッションは認証付きのローカルSOCKS5を使い、名前解決もVPN内で行います。環境変数のプロキシを使わず、HTTPSの証明書も検証します。
VPNを切断した後は、改めて接続し、新しい経路からセッションを作り直してください。

L2TP/IPsecで使う場合は、`VPNConfig` の `ike_version=1` と `username`・`password` を指定します。
接続先によって再認証方式が必要な場合は、`ikev2_renewal="reauthenticate"` を追加してください。[互換性について](INTEROPERABILITY.md)に動作と制限を記載しています。

## 非同期APIを使う

```python
import asyncio
import getpass
from pyl2tpvpn import VPNClient, VPNConfig

async def main():
    config = VPNConfig(
        server="vpn.example.net",
        ike_version=2,
        local_id="client.example.net",
        remote_id="gateway.example.net",
        psk=getpass.getpass("事前共有鍵: "),
        mtu=1280,
    )
    async with VPNClient(config) as vpn:
        print("割り当てIP:", vpn.local_ip)
        print("名前解決:", await vpn.resolve("example.com"))
        reader, writer = await vpn.open_connection("example.com", 443, ssl=True)
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            await writer.drain()
            async with asyncio.timeout(30):
                data = await reader.read()
            print(data.decode("utf-8", errors="replace"))
        finally:
            writer.close()

asyncio.run(main())
```

`open_connection()` がTCP、`open_datagram()` がUDP、`resolve()` が名前解決、`ping()` がICMP Echoです。
`ssl=True` を指定すると、標準の証明書検証を行うTLS通信になります。

非同期APIを使う間は、イベントループを継続して動かしてください。長時間ブロックする同期処理を同じスレッドで動かす場合は、`VPNRuntime` を使う構成も検討してください。

## 接続できない場合

認証方式とID、事前共有鍵が接続先の設定と合っているかを確認してください。L2TP用とネイティブIKEv2用で設定が分かれているサーバーでは、それぞれに合うものを使います。

DNSが通知されない場合は、コンソールの `--dns 192.0.2.53`、またはAPIの `dns_servers=("192.0.2.53",)` でVPN内のDNSサーバーを指定できます。例のアドレスは、ご自身の環境に合わせて置き換えてください。
OSの名前解決へ自動で切り替えることはありません。

最初は接続・切断ができても、鍵更新後に通信できなくなる場合は、[互換性について](INTEROPERABILITY.md)を確認してください。
