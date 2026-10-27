# pyl2tpvpn v0.3.0（ベータ版）

OS全体をVPNに接続せず、Pythonプログラムで使う通信だけをVPNへ流すためのライブラリです。
L2TP/IPsecとネイティブIKEv2/IPsecに対応し、RequestsでHTTP・HTTPS通信を試せるコンソールも付けています。

まずはコンソールで接続とアクセスを確認し、その後Pythonプログラムへ組み込む使い方ができます。準備と操作は [README](README.md)、ライブラリの設定とAPIは [ライブラリの使い方](docs/LIBRARY.md) に記載しています。

## できること

- IKEv1のL2TP/IPsecと、ネイティブIKEv2/IPsecでの接続
- PythonからのTCP・UDP通信、名前解決、ping、TLS通信
- Requestsを使ったHTTP・HTTPSアクセス
- 定期的な鍵更新、死活監視、再送、切断処理

## 動作確認

手元の環境で約10時間、さまざまなプロトコルを使って検証し、問題なく動作することを確認しています。

## 利用にあたって

Python 3.11以降が必要です。現在はベータ版で、実機での確認済み環境はWindowsです。
AHを交渉するVPN接続、IPv6、EAP・証明書認証、MOBIKEなどは未対応です。[対応範囲](docs/PROTOCOLS.md)も確認してください。

一部のリモートアクセス構成では、IKEリキー後に旧SAを削除すると通信が停止する現象を確認しています。その場合は `--ikev2-renewal reauthenticate` を指定し、再認証によって鍵を更新できます。
更新中に短い通信の空白があり、割り当てIPが変わった場合は既存接続を終了します。詳しくは[互換性について](docs/INTEROPERABILITY.md)を参照してください。

作者はminiai-saka、ライセンスはMITです。接続先の設定に合わせて使ってください。
