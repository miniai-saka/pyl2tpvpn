# 対応プロトコルと制限

このバージョンは、PSK認証・AES-CBC・HMAC-SHA1を使うIPv4のVPNクライアントです。
接続先が対応している方式と、以下の実装範囲が合うことを確認して使ってください。

## 接続方式

| 指定 | VPN内の通信 |
| --- | --- |
| IKEv1 / data_mode="auto" | NAT-T・ESP transport → L2TP → PPP → IPv4 |
| IKEv2 / data_mode="auto" | NAT-T・ESP tunnel → IPv4 |
| IKEv2 / data_mode="l2tp" | ESP transport → L2TP → PPP。これに対応した接続先向けの実験用機能です |

ネイティブIKEv2は、Configuration PayloadでIPアドレスとDNSサーバーを取得します。L2TP・PPPや、その中のMSCHAP-v2認証は使いません。

## 実装している機能

| 層 | 内容 |
| --- | --- |
| IKEv1 | Main ModeのPSK認証、Quick Mode、DPD、フェーズ1の再認証 |
| IKEv2 | PSK認証、SA_INIT・AUTH、IPv4のアドレス・DNS取得、Traffic Selectorの検査、CHILD/IKEリキー、再認証、暗号化された死活監視 |
| 鍵更新 | 時間・バイト数・シーケンス番号による更新、旧受信SAとの重複期間、同時リキーのnonce比較、一時的な競合時の再試行 |
| 暗号 | AES-CBC 128/192/256 bit、PRF-HMAC-SHA1、HMAC-SHA1-96、DHグループ2/5/14、任意指定のPFS |
| ESP・NAT-T | UDPによるESPの転送、整合性検証、リプレイ防御、鍵の寿命・使用量上限 |
| L2TPv2 | 単一トンネル・セッション、制御メッセージの再送、シーケンス番号、HELLO、StopCCNの応答待ち |
| PPP | LCP/IPCP、MSCHAP-v2相互認証、明示的に選択したPAP/CHAP-MD5、Echo、Terminateの応答待ち |
| IPv4 | TCP・UDP・ICMP、断片化と上限付きの再構成、VPN内DNS、TLS |
| コンソール | Requests、認証付きローカルSOCKS5、HTTPリダイレクト、証明書検証 |

PAPとCHAP-MD5は標準では使いません。既定のPPP認証はMSCHAP-v2です。
DHグループ2/5は既存機器との互換用として実装しています。接続先が対応している場合は `dh_groups=(14,)` に限定できます。

## 未対応の機能

- AHを交渉して接続するVPN、生ESP・生AHによる転送
- IPv6
- IKEv1のAggressive Mode・XAUTH
- IKEv2のEAP・証明書認証・MOBIKE・IKE fragmentation
- AES-GCM・SHA2・ESN
- L2TPトンネル認証

AHはIPv4のパケット処理とScapyとの相互検証のみです。AHのテストが通ることと、AHを使ったVPNへ接続できることは別になります。
対応しない方式を接続先から要求された場合、別の方式へ暗黙で切り替えて接続することはありません。

## 利用上の範囲

TCPはクライアントから接続を開始するための実装で、OSのソケット機能すべてを置き換えるものではありません。待ち受けTCPサーバーや、すべてのソケットオプションには対応していません。
複数のクライアントで同じ固定IPのVPNプロファイルを同時に使う構成も避けてください。

接続先の認証方式や設定が対応範囲と合っていることを確認してください。[鍵更新に関する互換性](INTEROPERABILITY.md)にも、接続先に合わせて選ぶ設定を記載しています。
