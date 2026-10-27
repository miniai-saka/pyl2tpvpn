import asyncio
import io
import time
from types import SimpleNamespace
import pytest
from pyl2tpvpn import VPNConfig
from pyl2tpvpn.console import (CommandError, VPNConsole, fetch, make_requests_session,
                              normalize_url, parse_request, safe_text, split_command)
from pyl2tpvpn.errors import TunnelClosed
from pyl2tpvpn.proxy import start_socks_proxy
from pyl2tpvpn.runtime import VPNRuntime


@pytest.mark.parametrize('value,expected',[
    ('example.com/example','https://example.com/example'),
    ('http://example.com/a?b=c#d','http://example.com/a?b=c#d'),
    ('example.com:8443/path','https://example.com:8443/path'),
    ('//example.com/','https://example.com/'),
])
def test_normalize_url(value,expected):
    assert normalize_url(value) == expected


@pytest.mark.parametrize('value',['file:///tmp/test','https://','example.com bad','https://[::1]/','https://example.com:wrong/'])
def test_reject_bad_url(value):
    with pytest.raises(CommandError):
        normalize_url(value)


def test_command_quotes_json_and_windows_path():
    parsed=parse_request(r'''POST example.com/api --json '{"path":"C:\\test","value":1}' -H "X-Test: a b" --save "C:\temp\my file.json"''')
    assert parsed.method == 'POST' and parsed.headers == {'X-Test':'a b'}
    assert parsed.json_data == {'path':r'C:\test','value':1}
    assert parsed.save == r'C:\temp\my file.json'
    assert parse_request('example.com/').method == 'GET'
    with pytest.raises(CommandError):
        parse_request('example.com --timeout 0')
    with pytest.raises(CommandError):
        parse_request("example.com --json '{broken}'")
    with pytest.raises(CommandError):
        split_command('"unfinished')


def test_requests_session_pins_both_protocols_and_ignores_environment(monkeypatch):
    monkeypatch.setenv('HTTP_PROXY','http://unwanted.invalid:9999')
    monkeypatch.setenv('NO_PROXY','*')
    proxy='socks5h://user:pass@127.0.0.1:12345'
    with make_requests_session(proxy) as session:
        assert session.trust_env is False
        assert session.proxies == {'http':proxy,'https':proxy}
    with pytest.raises(ValueError):
        make_requests_session('socks5://127.0.0.1:12345')


def test_requests_redirects_traverse_vpn_proxy_without_local_dns(monkeypatch):
    async def run():
        destinations=[]
        async def serve(reader,writer):
            head=await reader.readuntil(b'\r\n\r\n')
            if b'Host: start.test' in head:
                writer.write(b'HTTP/1.1 302 Found\r\nLocation: http://finish.test/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            else:
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server=await asyncio.start_server(serve,'127.0.0.1',0)
        port=server.sockets[0].getsockname()[1]
        class VPN:
            async def open_connection(self,host,destination_port):
                destinations.append((host,destination_port))
                return await asyncio.open_connection('127.0.0.1',port)
        try:
            async with await start_socks_proxy(VPN(),port=0,username='test',password='secret') as proxy:
                route=f'socks5h://test:secret@127.0.0.1:{proxy.sockets[0].getsockname()[1]}'
                args=parse_request('http://start.test/ --timeout 3')
                result=await asyncio.to_thread(fetch,route,args)
                assert result['status'] == 200 and result['body'] == b'OK'
                assert result['url'] == 'http://finish.test/final'
                assert [r['status'] for r in result['redirects']] == [302]
                assert destinations == [('start.test',80),('finish.test',80)]
        finally:
            server.close()
            await server.wait_closed()
    monkeypatch.setenv('ALL_PROXY','http://127.0.0.1:1')
    monkeypatch.setenv('NO_PROXY','*')
    asyncio.run(run())


def test_disconnected_command_does_not_attempt_http(monkeypatch):
    class Runtime:
        config=VPNConfig('server','user','private-password','private-psk')
        proxy_url=None
        def request_route(self):
            raise TunnelClosed('VPN is disconnected')
    def forbidden(*a,**kw):
        raise AssertionError('HTTP was attempted after disconnect')
    monkeypatch.setattr('pyl2tpvpn.console.fetch',forbidden)
    output=io.StringIO()
    shell=VPNConsole(Runtime(),stdout=output)
    shell.onecmd('requests example.com/example')
    assert shell.command_failed and 'TunnelClosed' in output.getvalue()


def test_http_404_is_a_response_and_terminal_controls_are_escaped(monkeypatch):
    class Runtime:
        config=VPNConfig('server','user','private-password','private-psk')
        proxy_url='socks5h://127.0.0.1:12345'
        def request_route(self):
            return self.proxy_url
    monkeypatch.setattr('pyl2tpvpn.console.fetch',lambda *a:dict(
        url='https://example.com/example',status=404,reason='Not Found',headers={'Content-Type':'text/plain'},
        body=b'\x1b[2Jnot found',truncated=False,encoding='utf-8',seconds=.1,redirects=[]))
    output=io.StringIO()
    shell=VPNConsole(Runtime(),stdout=output)
    shell.onecmd('requests example.com/example')
    assert not shell.command_failed and 'HTTP 404' in output.getvalue()
    assert '\x1b' not in output.getvalue() and r'\x1b[2J' in output.getvalue()


def test_body_limit_and_save_never_overwrites(tmp_path,monkeypatch):
    calls=[]
    class Response:
        url='https://example.com/'
        status_code=200
        reason='OK'
        headers={}
        encoding='utf-8'
        history=[]
        def __enter__(self):
            return self
        def __exit__(self,*a):
            pass
        def iter_content(self,**kw):
            yield b'0123456789'
    class Session:
        proxies={'http':'socks5h://127.0.0.1:12345','https':'socks5h://127.0.0.1:12345'}
        def __enter__(self):
            return self
        def __exit__(self,*a):
            pass
        def request(self,*args,**kwargs):
            calls.append(kwargs)
            return Response()
    monkeypatch.setattr('pyl2tpvpn.console.make_requests_session',lambda url:Session())
    path=tmp_path/'response.txt'
    args=parse_request(f'example.com/ --max-bytes 5 --save "{path}"')
    result=fetch('socks5h://127.0.0.1:12345',args)
    assert path.read_bytes() == b'01234' and result['truncated']
    assert calls[0]['verify'] is True and set(calls[0]['proxies']) == {'http','https'}
    with pytest.raises(FileExistsError):
        fetch('socks5h://127.0.0.1:12345',args)
    assert path.read_bytes() == b'01234'
    assert len(calls) == 1


def test_vpn_event_loop_continues_while_console_thread_blocks():
    runtime=VPNRuntime(VPNConfig('server','user','password','secret'))
    ticks=[]
    async def schedule():
        async def ticker():
            while True:
                ticks.append(1)
                await asyncio.sleep(.02)
        asyncio.create_task(ticker())
    try:
        runtime.call(schedule())
        time.sleep(.15)
        assert len(ticks) >= 3
    finally:
        runtime.close()
    assert not runtime.thread.is_alive()


def test_runtime_forwards_dns_and_ping_host_arguments():
    runtime=VPNRuntime(VPNConfig('server','user','password','secret'))
    calls=[]
    class VPN:
        async def resolve(self,host):
            calls.append(('resolve',host))
            return ['192.0.2.1']
        async def ping(self,host):
            calls.append(('ping',host))
            return .01
        async def close(self):
            pass
    runtime.vpn=VPN()
    try:
        assert runtime.resolve('dns.example') == ['192.0.2.1']
        assert runtime.ping('ping.example') == .01
        assert calls == [('resolve','dns.example'),('ping','ping.example')]
    finally:
        runtime.close()


def test_batch_reports_initial_connection_failure(monkeypatch):
    from pyl2tpvpn.console import run_console
    class Runtime:
        config=VPNConfig('server','user','password','secret')
        proxy_url=None
        def status(self):
            return {'state':'disconnected'}
        def connect(self):
            raise ConnectionError('test connection failed')
        def close(self):
            pass
    monkeypatch.setattr('pyl2tpvpn.console.VPNRuntime',lambda config:Runtime())
    assert run_console(Runtime.config,commands=['status']) == 1


def test_quit_exits_even_when_interactive_after_commands_is_enabled(monkeypatch):
    from pyl2tpvpn.console import run_console
    class Runtime:
        config=VPNConfig('server','user','password','secret')
        proxy_url=None
        def close(self):
            pass
    monkeypatch.setattr('pyl2tpvpn.console.VPNRuntime',lambda config:Runtime())
    def forbidden(*a):
        raise AssertionError('cmdloop continued after quit')
    monkeypatch.setattr(VPNConsole,'cmdloop',forbidden)
    assert run_console(Runtime.config,commands=['quit'],auto_connect=False,interactive=True) == 0
