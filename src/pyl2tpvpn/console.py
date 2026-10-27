"""Interactive Requests console. All HTTP traffic goes through this VPN."""
import argparse
import cmd
import ctypes
import getpass
import ipaddress
import json
import logging
import os
from pathlib import Path
import shlex
import sys
import time
from urllib.parse import urlsplit
from .config import VPNConfig
from .runtime import VPNRuntime
from . import __version__


class CommandError(ValueError):
    pass


class CommandParser(argparse.ArgumentParser):
    def error(self, message):
        raise CommandError(message)


def split_command(line):
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    lexer.escape = ""  # Preserve Windows paths and JSON backslashes.
    try:
        return list(lexer)
    except ValueError as error:
        raise CommandError(str(error)) from error


def normalize_url(value):
    if not value or any(ord(c) < 33 for c in value):
        raise CommandError("URLに空白や制御文字は使えません")
    if value.startswith("//"):
        value = "https:"+value
    elif "://" not in value:
        value = "https://"+value
    try:
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise CommandError("http:// または https:// のURLを指定してください")
        _ = parts.port
        try:
            address = ipaddress.ip_address(parts.hostname)
        except ValueError:
            address = None
        if isinstance(address, ipaddress.IPv6Address):
            raise CommandError("このVPNクライアントはIPv4のみ対応しています")
    except ValueError as error:
        raise CommandError(str(error)) from error
    return value


def safe_text(value):
    text = str(value).replace("\r\n", "\n")
    return "".join(c if c.isprintable() or c in "\n\t" else
                   f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}" for c in text)


def make_requests_session(proxy_url):
    try:
        import requests
        import socks  # noqa: F401 -- Requests' SOCKS dependency is required.
    except ImportError as error:
        raise RuntimeError('コンソールには python -m pip install ".[console]" が必要です') from error
    proxy = urlsplit(proxy_url)
    if proxy.scheme != "socks5h" or proxy.hostname != "127.0.0.1" or not proxy.port:
        raise ValueError("VPN console requires a loopback socks5h proxy")
    session = requests.Session()
    session.trust_env = False
    session.proxies = {"http": proxy_url, "https": proxy_url}
    session.headers["Connection"] = "close"
    return session


def request_parser():
    parser = CommandParser(prog="requests", add_help=False)
    parser.add_argument("targets", nargs="+")
    parser.add_argument("-X", "--method")
    parser.add_argument("-H", "--header", action="append", default=[])
    body = parser.add_mutually_exclusive_group()
    body.add_argument("--data")
    body.add_argument("--json")
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--preview", type=int, default=2000)
    parser.add_argument("--max-bytes", type=int, default=8*1024*1024)
    parser.add_argument("-o", "--save")
    parser.add_argument("--no-redirect", action="store_true")
    return parser


def parse_request(line):
    args = request_parser().parse_args(split_command(line))
    methods = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
    method = "GET"
    if len(args.targets) == 1:
        target = args.targets[0]
    elif len(args.targets) == 2 and args.targets[0].upper() in methods:
        method, target = args.targets[0].upper(), args.targets[1]
    else:
        raise CommandError("使い方: requests [METHOD] URL [--timeout 秒] [--preview 文字数]")
    if args.method:
        if method != "GET" and method != args.method.upper():
            raise CommandError("HTTPメソッドの指定が重複しています")
        method = args.method.upper()
    if method not in methods:
        raise CommandError("対応メソッド: "+", ".join(sorted(methods)))
    if not 0 < args.timeout <= 600 or not 0 <= args.preview <= 100000 or not 1 <= args.max_bytes <= 64*1024*1024:
        raise CommandError("timeoutは0超～600秒、previewは0～100000文字、max-bytesは1～67108864です")
    headers = {}
    for value in args.header:
        name, separator, content = value.partition(":")
        if not separator or not name.strip() or "\r" in value or "\n" in value:
            raise CommandError("ヘッダーは -H 'Name: Value' の形式で指定してください")
        headers[name.strip()] = content.strip()
    args.url, args.method, args.headers = normalize_url(target), method, headers
    args.json_data = None
    if args.json is not None:
        try:
            args.json_data = json.loads(args.json)
        except json.JSONDecodeError as error:
            raise CommandError(f"JSONが不正です: {error.msg}") from error
    return args


def fetch(proxy_url, args):
    save_path = Path(args.save).expanduser() if args.save else None
    if save_path is not None and save_path.exists():
        raise FileExistsError(f"保存先は既に存在します: {save_path}")
    start = time.monotonic()
    with make_requests_session(proxy_url) as session:
        kwargs = dict(headers=args.headers, timeout=(args.timeout, args.timeout),
                      allow_redirects=not args.no_redirect, stream=True,
                      proxies=dict(session.proxies), verify=True)
        if args.data is not None:
            kwargs["data"] = args.data
        if args.json is not None:
            if args.json_data is None:
                kwargs["data"] = "null"
                kwargs["headers"] = dict(args.headers)
                if not any(k.lower() == "content-type" for k in kwargs["headers"]):
                    kwargs["headers"]["Content-Type"] = "application/json"
            else:
                kwargs["json"] = args.json_data
        with session.request(args.method, args.url, **kwargs) as response:
            body = bytearray()
            truncated = False
            for chunk in response.iter_content(chunk_size=16384):
                remaining = args.max_bytes-len(body)
                body.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break
            result = dict(url=response.url, status=response.status_code, reason=response.reason,
                          headers=dict(response.headers), body=bytes(body), truncated=truncated,
                          encoding=response.encoding or "utf-8", seconds=time.monotonic()-start,
                          redirects=[dict(status=r.status_code, url=r.url) for r in response.history])
    if args.save:
        path = save_path
        # A mistyped output path must not overwrite an existing file.
        with path.open("xb") as handle:
            handle.write(result["body"])
        result["saved"] = str(path.resolve())
    return result


class VPNConsole(cmd.Cmd):
    prompt = "vpn> "

    def __init__(self, runtime, *, stdin=None, stdout=None):
        super().__init__(stdin=stdin, stdout=stdout)
        self.runtime = runtime
        self.last_result = None
        self.command_failed = False

    def say(self, message=""):
        self.stdout.write(safe_text(message)+"\n")
        self.stdout.flush()

    def emptyline(self):
        pass

    def default(self, line):
        self.command_failed = True
        self.say("不明なコマンドです。helpで一覧を表示します。")

    def onecmd(self, line):
        self.command_failed = False
        try:
            return super().onecmd(line)
        except KeyboardInterrupt:
            self.command_failed = True
            self.say("\nコマンドを中断しました。VPNは接続状態を維持します。")
        except Exception as error:
            self.command_failed = True
            message = str(error)
            for secret in (self.runtime.config.password, self.runtime.config.psk):
                if secret:
                    message = message.replace(secret, "[redacted]")
            if self.runtime.proxy_url:
                message = message.replace(self.runtime.proxy_url, "socks5h://[console-proxy]")
            self.say(f"エラー: {type(error).__name__}: {message}")
        return False

    def do_help(self, line):
        self.say("""requests example.com/example       HTTPS GET (スキーム省略時)
requests http://example.com/         HTTP GET
requests HEAD https://example.com/  メソッドを明示
requests URL --preview 500          本文の表示文字数
requests URL --timeout 10           接続・受信待ちのタイムアウト
requests URL -H 'Name: Value'       リクエストヘッダーを追加
requests POST URL --json '{"k":1}'   JSONを送信
requests URL --save response.txt    本文を新規ファイルへ保存
status                              接続状態・VPNアドレス・更新回数
ip                                  VPN経由の出口IPを表示
resolve example.com                 VPN内DNSで名前解決
ping example.com                    VPN経由のICMP Echo
connect / disconnect / reconnect    VPNの接続操作
wait 10                             VPN処理を動かしたまま10秒待つ
quit / exit                         VPNを切断して終了

HTTP 404/500も応答として表示します。通信例外とは区別します。
requestsは専用SOCKS5経由です。DNSもVPN内で行います。
IKEv1再認証時は既存の通信が切れます。新しいrequestsコマンドで再試行できます。""")

    def do_requests(self, line):
        if line.strip() in ("-h", "--help"):
            self.do_help("")
            return
        args = parse_request(line)
        proxy_url = self.runtime.request_route()
        self.say(f"{args.method} {args.url}  [VPN / requests]")
        result = fetch(proxy_url, args)
        self.last_result = result
        self.say(f"HTTP {result['status']} {result['reason']} | {len(result['body'])} bytes | {result['seconds']:.3f}s")
        self.say("URL: "+result["url"])
        if result["redirects"]:
            self.say("Redirects: "+", ".join(str(r["status"]) for r in result["redirects"]))
        for name, value in result["headers"].items():
            self.say(f"{name}: {value}")
        if "saved" in result:
            self.say("保存: "+result["saved"])
        if result["truncated"]:
            self.say(f"本文は{args.max_bytes} bytesで読み取りを打ち切りました。保存時もこの範囲です。")
        content_type = next((v for k,v in result["headers"].items() if k.lower() == "content-type"),"").lower()
        is_text = (not content_type or content_type.startswith("text/") or
                   any(t in content_type for t in ("json", "xml", "javascript", "x-www-form-urlencoded")))
        if args.preview and is_text:
            try:
                text = result["body"].decode(result["encoding"], errors="replace")
            except LookupError:
                text = result["body"].decode("utf-8", errors="replace")
            self.say("\n"+text[:args.preview])
            if len(text) > args.preview:
                self.say(f"... 本文表示は先頭{args.preview}文字まで")
        elif args.preview and result["body"]:
            self.say("\nバイナリ本文（先頭32 bytes）: "+result["body"][:32].hex(" "))

    def do_status(self, line):
        if line.strip():
            raise CommandError("statusに引数はありません")
        state = self.runtime.status()
        self.say(json.dumps(state, ensure_ascii=False, indent=2))

    def do_connect(self, line):
        if line.strip():
            raise CommandError("connectに引数はありません")
        if self.runtime.status()["state"] in ("connected", "refreshing"):
            self.say("VPNは接続済みです。")
            return
        self.say("VPNに接続しています...")
        state = self.runtime.connect()
        self.say(f"接続しました。VPN address: {state['local_ip']}")

    def do_disconnect(self, line):
        if line.strip():
            raise CommandError("disconnectに引数はありません")
        self.runtime.disconnect()
        self.say("VPNを切断しました。")

    def do_reconnect(self, line):
        if line.strip():
            raise CommandError("reconnectに引数はありません")
        self.runtime.disconnect()
        self.do_connect("")

    def do_ip(self, line):
        if line.strip():
            raise CommandError("ipに引数はありません")
        self.do_requests("https://api.ipify.org --preview 100")

    def do_resolve(self, line):
        args = split_command(line)
        if len(args) != 1:
            raise CommandError("使い方: resolve HOST")
        self.say("\n".join(self.runtime.resolve(args[0])))

    def do_ping(self, line):
        args = split_command(line)
        if len(args) != 1:
            raise CommandError("使い方: ping HOST")
        self.say(f"応答: {self.runtime.ping(args[0])*1000:.2f} ms")

    def do_wait(self, line):
        try:
            seconds = float(line)
        except ValueError as error:
            raise CommandError("使い方: wait SECONDS") from error
        if not 0 <= seconds <= 3600:
            raise CommandError("waitは0～3600秒です")
        time.sleep(seconds)
        self.say(f"{seconds:g}秒待ちました。")

    def do_quit(self, line):
        self.say("VPNを切断して終了します。")
        return True

    do_exit = do_quit
    do_EOF = do_quit


def console_parser():
    parser = argparse.ArgumentParser(description="RequestsをVPN経由で使う対話型コンソール")
    parser.add_argument("--server", default=os.getenv("VPN_SERVER"))
    parser.add_argument("--username", default=os.getenv("VPN_USERNAME"))
    parser.add_argument("--ike-version", type=int, choices=(1,2), default=1)
    parser.add_argument("--data-mode", choices=("auto","l2tp","tunnel"), default="auto")
    parser.add_argument("--local-id", default=os.getenv("VPN_LOCAL_ID"))
    parser.add_argument("--remote-id", default=os.getenv("VPN_REMOTE_ID"))
    parser.add_argument("--request-remote-id", action="store_true", help="照合に加えてIDrをIKE_AUTHで送信")
    parser.add_argument("--ikev2-renewal", choices=("rekey","reauthenticate"), default="rekey")
    parser.add_argument("--mtu", type=int, default=1280)
    parser.add_argument("--dns", action="append", default=[])
    parser.add_argument("--child-lifetime", type=float, default=3600)
    parser.add_argument("--ike-lifetime", type=float, default=28800)
    parser.add_argument("--no-connect", action="store_true")
    parser.add_argument("--command", action="append", default=[], help="コマンドを実行して終了。複数指定可能")
    parser.add_argument("--interactive", action="store_true", help="--command実行後も入力を受け付ける")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--ready-file", help=argparse.SUPPRESS)
    return parser


def run_console(config, *, commands=(), auto_connect=True, ready_file=None, interactive=False):
    runtime = VPNRuntime(config)
    shell = VPNConsole(runtime)
    try:
        shell.say("Python VPN Requests Console "+__version__)
        shell.say("helpでコマンド一覧、quitで終了します。")
        if auto_connect:
            shell.onecmd("connect")
        if commands:
            failed = shell.command_failed if auto_connect else False
            for command in commands:
                shell.say("vpn> "+command)
                stop = shell.onecmd(command)
                failed |= shell.command_failed
                if stop:
                    return 1 if failed else 0
            if not interactive:
                return 1 if failed else 0
        if ready_file:
            state = runtime.status()
            state.update(pid=os.getpid(),interactive_ready=True,
                         last_http_status=shell.last_result['status'] if shell.last_result else None)
            if os.name == "nt":
                ctypes.windll.kernel32.GetConsoleWindow.restype = ctypes.c_void_p
                handle = ctypes.windll.kernel32.GetConsoleWindow()
                ctypes.windll.user32.IsWindowVisible.argtypes = [ctypes.c_void_p]
                state["console_window_visible"] = bool(ctypes.windll.user32.IsWindowVisible(handle))
            Path(ready_file).write_text(json.dumps(state,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        while True:
            try:
                shell.cmdloop()
                break
            except KeyboardInterrupt:
                shell.say("\n入力を中断しました。終了はquitです。")
        return 0
    finally:
        runtime.close()


def main(argv=None):
    args = console_parser().parse_args(argv)
    try:
        if os.name == "nt":
            ctypes.windll.kernel32.SetConsoleTitleW(f"Python VPN Requests Console {__version__} / IKEv{args.ike_version}")
        if hasattr(sys.stdout,"reconfigure"):
            sys.stdout.reconfigure(errors="backslashreplace")
        server = args.server or input("VPNサーバー: ").strip()
        uses_l2tp = args.data_mode == "l2tp" or (args.data_mode == "auto" and args.ike_version == 1)
        username = (args.username or input("ユーザーID: ").strip()) if uses_l2tp else ""
        password = os.environ.pop("VPN_PASSWORD",None)
        psk = os.environ.pop("VPN_PSK",None)
        if uses_l2tp and password is None:
            password = getpass.getpass("PPPパスワード: ")
        if psk is None:
            psk = getpass.getpass("事前共有鍵: ")
        config = VPNConfig(server,username,password or "",psk,ike_version=args.ike_version,
                           data_mode=args.data_mode,request_remote_id=args.request_remote_id,
                           ikev2_renewal=args.ikev2_renewal,mtu=args.mtu,dns_servers=tuple(args.dns),
                           local_id=args.local_id,remote_id=args.remote_id,
                           child_lifetime=args.child_lifetime,ike_lifetime=args.ike_lifetime)
        # Validate the optional dependency before starting any VPN connection.
        with make_requests_session("socks5h://127.0.0.1:1"):
            pass
        logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
        return run_console(config,commands=args.command,auto_connect=not args.no_connect,
                           ready_file=args.ready_file,interactive=args.interactive)
    except (EOFError,KeyboardInterrupt):
        print("\n終了しました。")
        return 130
    except Exception as error:
        print(f"{type(error).__name__}: {safe_text(error)}",file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
