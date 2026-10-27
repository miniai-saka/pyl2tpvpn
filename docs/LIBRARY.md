# ライブラリとして使う

同期処理でRequestsを使う場合は `VPNRuntime`、`asyncio` で通信を扱う場合は `VPNClient` を使ってください。
どちらもOS全体の経路を変えず、このライブラリから行う通信をVPNへ流します。

Python 3.11以降が必要です。実機での確認済み環境はWindowsで、[対応範囲](PROTOCOLS.md)に未対応の機能も記載しています。

## インストール

VPN本体だけを使う場合は、Releaseのwheelを指定してインストールできます。

```sh
python -m pip install "https://github.com/miniai-saka/pyl2tpvpn/releases/download/v0.3.0/pyl2tpvpn-0.3.0-py3-none-any.whl"
```

Requestsを使う場合は、SOCKS対応を含む `[console]` を指定してください。コンソールを起動せず、ライブラリとして使う場合も同じです。

```sh
python -m pip install "pyl2tpvpn[console] @ https://github.com/miniai-saka/pyl2tpvpn/releases/download/v0.3.0/pyl2tpvpn-0.3.0-py3-none-any.whl"
```

ソースから導入する場合は、リポジトリのフォルダーで `python -m pip install .`、Requestsも使う場合は `python -m pip install ".[console]"` を実行してください。

## 接続設定を用意する

以下のサンプルでは、接続先やIDを環境変数から読み、秘密情報は `getpass` で入力します。
`.env` ファイルを自動で読み込む機能はありません。必要な値は、ご自身のプログラムや実行環境で用意してください。

### L2TP/IPsec

`VPN_SERVER` と `VPN_USERNAME` を環境変数に設定します。

```python
import getpass
import os
from pyl2tpvpn import VPNConfig

config = VPNConfig(
    server=os.environ["VPN_SERVER"],
    username=os.environ["VPN_USERNAME"],
    password=getpass.getpass("PPPパスワード: "),
    psk=getpass.getpass("事前共有鍵: "),
    ike_version=1,
)
```

PPP認証は既定でMSCHAP-v2を使います。PAPやCHAP-MD5が必要な接続先では、対応する方式を `auth_methods` に明示してください。

### ネイティブIKEv2/IPsec

`VPN_SERVER`、`VPN_LOCAL_ID`、`VPN_REMOTE_ID` を環境変数に設定します。
こちらはL2TP・PPPを使わないため、PPPのユーザー名とパスワードは不要です。

```python
import getpass
import os
from pyl2tpvpn import VPNConfig

config = VPNConfig(
    server=os.environ["VPN_SERVER"],
    ike_version=2,
    local_id=os.environ["VPN_LOCAL_ID"],
    remote_id=os.environ["VPN_REMOTE_ID"],
    psk=getpass.getpass("事前共有鍵: "),
    mtu=1280,
)
```

`local_id` はFQDN形式として送信します。`remote_id` は、認証応答で相手が返すIDを文字列で照合するための値です。
接続先のホスト名と応答IDが同じとは限りません。相手から指定された値を使ってください。
IDrを要求にも含める接続先では `request_remote_id=True` を指定できます。

既定の鍵更新方式は `ikev2_renewal="rekey"` です。一部の構成では、IKEリキー後に旧SAを削除すると通信が停止する現象を確認しています。
その場合は `ikev2_renewal="reauthenticate"` を追加してください。再認証で鍵を更新するため短い通信の空白があり、割り当てIPが変わると既存接続を終了します。
同じIPが再割り当てされた場合は既存のTCP接続を保ちます。[接続先による違い](INTEROPERABILITY.md)も確認してください。

## RequestsからHTTP・HTTPSへアクセスする

次のコードは、上で用意した `config` に続けて使えます。L2TP/IPsecとネイティブIKEv2のどちらも同じ呼び方です。
最初から実行できるL2TP/IPsecの例は [README](../README.md#pythonプログラムから使う)、IKEv2の例は [examples/requests_vpn.py](../examples/requests_vpn.py) にあります。

```python
from pyl2tpvpn.runtime import VPNRuntime
from pyl2tpvpn.console import make_requests_session

runtime = VPNRuntime(config)
try:
    runtime.connect()
    print("割り当てIP:", runtime.status()["local_ip"])
    with make_requests_session(runtime.request_route()) as session:
        response = session.get("https://example.com/", timeout=20)
        response.raise_for_status()
        print(response.text)
finally:
    runtime.close()
```

返されるのは通常の `requests.Session` です。`session.post(..., json=...)` や `headers`、`stream=True` など、Requestsの機能を使えます。
`raise_for_status()` は4xx・5xxの応答を例外として扱いたい場合に使ってください。

このセッションは認証付きのローカルSOCKS5を使い、対象ホストの名前解決もVPN内で行います。
環境変数のプロキシは使わず、HTTPSの証明書を検証します。VPNを切断した際に、直接接続へ自動で切り替えることはありません。
`session.proxies` や `trust_env` を変更すると、この経路の設定も変わりますので、そのまま使ってください。

通常の `requests.get()` や、別に作ったセッション、標準の `socket` はVPNへ自動で切り替わりません。
VPN経由にする処理では、必ず上で作ったセッションを使ってください。

`VPNRuntime` が別スレッドで通信処理を続けるため、同期処理の待ち時間も鍵更新や死活監視を行えます。
終了時はRequestsのセッションを閉じてから、`runtime.close()` を呼んでください。
切断・再接続する場合は、以前のセッションを閉じ、`runtime.connect()` 後の新しい `request_route()` からセッションを作り直します。

## asyncioからTCP・TLSを使う

次はL2TP/IPsecで接続する、単独で実行できる例です。`VPN_SERVER` と `VPN_USERNAME` を設定して実行してください。
ネイティブIKEv2で使う場合は、`VPNConfig` の部分を上のIKEv2用設定に置き換えます。

```python
import asyncio
import getpass
import os
from pyl2tpvpn import VPNClient, VPNConfig


async def main():
    config = VPNConfig(
        server=os.environ["VPN_SERVER"],
        username=os.environ["VPN_USERNAME"],
        password=getpass.getpass("PPPパスワード: "),
        psk=getpass.getpass("事前共有鍵: "),
    )
    async with VPNClient(config) as vpn:
        print("割り当てIP:", vpn.local_ip)
        print("名前解決:", await vpn.resolve("example.com"))
        reader, writer = await vpn.open_connection(
            "example.com", 443, ssl=True, timeout=20
        )
        try:
            async with asyncio.timeout(30):
                writer.write(
                    b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
                while chunk := await reader.read(65536):
                    print(chunk.decode("utf-8", errors="replace"), end="")
        finally:
            writer.close()


if __name__ == "__main__":
    asyncio.run(main())
```

`async with VPNClient(...)` が接続と終了処理を行います。手動で管理する場合は `await vpn.connect()` と `await vpn.close()` を使ってください。
閉じた `VPNClient` を再利用せず、新しいインスタンスを作成してください。

`open_connection()` の `timeout` は名前解決・TCP接続・TLSハンドシェイクの待ち時間です。
接続後の送受信時間は、例のように `asyncio.timeout()` で別に制限してください。
`ssl=True` は標準の証明書検証を使います。独自CAが必要な場合は、CAを設定した `ssl.SSLContext` を `ssl=` に渡せます。

読み書きにはストリーム形式のAPIを使えますが、OSのソケットを返すAPIではありません。
ソケットを直接要求するライブラリへ、そのまま渡すことはできません。

## UDP通信とping

接続中の `vpn` から、次のようにUDP通信を行えます。`echo.example.net:9999` は、ご自身で用意したUDP Echoサーバーに置き換えてください。
名前解決も含む上限時間と、応答の待ち時間を指定しています。

```python
async with asyncio.timeout(10):
    channel = await vpn.open_datagram("echo.example.net", 9999)
try:
    channel.send(b"hello")
    reply = await channel.recv(timeout=5)
    print(reply)
finally:
    channel.close()
```

`send()` は送信処理で、受信確認や再送は行いません。`recv()` は、指定した相手から受信した1つのデータグラムを `bytes` で返します。
通信相手ごとにチャネルを作成し、使い終わったら `close()` してください。
環境変数で接続先を指定できる実行例は [examples/udp_echo.py](../examples/udp_echo.py) にあります。
この例では、VPN用の4項目（`VPN_SERVER`・`VPN_USERNAME`・`VPN_PASSWORD`・`VPN_PSK`）に加え、`VPN_UDP_HOST` と `VPN_UDP_PORT` を使います。パスワードと事前共有鍵は、未設定なら入力できます。

```python
seconds = await vpn.ping("192.0.2.1", timeout=5)
print(f"応答時間: {seconds * 1000:.1f} ms")
```

このアドレスも、応答を確認したいVPN内のIPv4アドレスへ置き換えてください。`ping()` の戻り値は秒単位です。

## 主なAPI

`VPNClient` の通信メソッドは、接続後に同じイベントループから呼びます。

| API | 内容 |
| --- | --- |
| `await vpn.connect()` | VPNに接続し、使用可能になるまで待つ |
| `vpn.local_ip` | VPNで割り当てられたIPv4アドレス |
| `await vpn.resolve(host, timeout=5)` | VPN内のDNSで名前解決し、IPv4アドレスのリストを返す |
| `await vpn.open_connection(host, port, ssl=None, server_hostname=None, timeout=30)` | TCP接続を作り、reader・writerを返す。TLSには `ssl=True` または `SSLContext` を指定する |
| `await vpn.open_datagram(host, port)` | UDPチャネルを作る |
| `await vpn.ping(host, timeout=5)` | ICMP Echoの応答時間を秒で返す |
| `await vpn.wait_closed()` | 正常切断または障害を待つ。障害時はその例外を送出する |
| `await vpn.close()` | 通信とVPNを終了する |

同期処理用の `VPNRuntime` では、`connect()`、`disconnect()`、`close()`、`status()`、`resolve(host)`、`ping(host)` をそのまま呼べます。
`request_route()` はRequests用セッションに渡すプロキシURLを返します。このURLには一時的な認証情報が含まれるため、ログへ記録しないでください。
`disconnect()` は再接続できる状態で切断し、`close()` は通信処理用のスレッドも終了します。

## 主な設定項目

`VPNConfig` は作成後に変更できません。値を変える場合は新しい設定を作り、新しく接続してください。

| 設定 | 既定値 | 内容 |
| --- | --- | --- |
| `ike_version` | `1` | `1` がIKEv1、`2` がIKEv2 |
| `data_mode` | `"auto"` | 自動設定ではIKEv1がL2TP、IKEv2がネイティブIPsec。IKEv2でL2TPを使う場合は `"l2tp"` |
| `username`・`password` | 空文字 | L2TPで使うPPP認証情報 |
| `psk` | 空文字 | 接続先の事前共有鍵 |
| `local_id`・`remote_id` | `None` | IKEのID。IKEv2では接続先に合わせて指定する |
| `request_remote_id` | `False` | IKEv2の要求にもIDrを含める |
| `dns_servers` | `()` | 接続先から通知されるDNSを使う。明示する場合は `("192.0.2.53",)` のようにIPv4で指定する |
| `mtu` | `1360` | VPN内のMTU。指定できる範囲は576〜1400 |
| `auth_methods` | `("mschapv2",)` | PPP認証方式。ほかに `"pap"`・`"chap-md5"` を指定できる |
| `ikev2_renewal` | `"rekey"` | IKEv2の鍵更新方式。互換性のための再認証は `"reauthenticate"` |
| `ike_lifetime`・`child_lifetime` | `28800`・`3600` | IKE SA・CHILD SAの寿命。秒単位で指定する |
| `rekey_margin` | `0.2` | 寿命の何割を残して鍵更新を始めるか |
| `child_byte_limit` | `1 << 30` | CHILD SAの送信量の上限。バイト単位 |
| `keepalive_interval`・`dpd_interval` | `20`・`30` | NAT保持・相手の死活監視の間隔。秒単位 |
| `connect_timeout`・`shutdown_timeout` | `90`・`8` | 接続全体・切断時の各待ち時間の上限。秒単位 |

全項目と値の制約は [config.py](../src/pyl2tpvpn/config.py) を確認してください。鍵更新や互換性の条件は [INTEROPERABILITY.md](INTEROPERABILITY.md) に記載しています。

## 障害時と終了時の扱い

認証失敗などのVPNのエラーは `VPNError` 系、通信やTLSのエラーは `OSError`、`TimeoutError` などとして通知されます。
Requestsを使う場合は、Requests側の例外も処理してください。例外になった通信を直接接続へ切り替える処理は入っていません。

`asyncio` を使う場合は、イベントループを継続して動かしてください。同じスレッドで長時間の同期処理を動かすと、通信や鍵更新も止まります。
そのような処理と組み合わせる場合は `VPNRuntime` を使うか、同期処理を `asyncio.to_thread()` などで別スレッドへ移してください。

接続や送受信が失敗した場合も、`finally` または `async with` で終了処理を行ってください。再接続時は、新しいVPNと、そのVPNから作った通信オブジェクトを使います。
