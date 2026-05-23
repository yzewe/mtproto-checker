import asyncio
import unittest

from mtproto_checker.info import collect_proxy_info
from mtproto_checker import ProxyStatus, check_proxy, parse_proxy_url


class ParseProxyUrlTests(unittest.TestCase):
    def test_parses_tg_proxy_url(self):
        target = parse_proxy_url(
            "tg://proxy?server=185.86.147.17&port=443&secret=eeabc"
        )

        self.assertEqual(target.server, "185.86.147.17")
        self.assertEqual(target.port, 443)
        self.assertEqual(target.secret, "eeabc")
        self.assertEqual(target.kind, "mtproto")

    def test_parses_host_port(self):
        target = parse_proxy_url("127.0.0.1:8080")

        self.assertEqual(target.server, "127.0.0.1")
        self.assertEqual(target.port, 8080)
        self.assertEqual(target.kind, "tcp")

    def test_parses_socks_url(self):
        target = parse_proxy_url(
            "https://t.me/socks?server=127.0.0.1&port=1080&user=name&pass=secret"
        )

        self.assertEqual(target.kind, "socks5")
        self.assertEqual(target.username, "name")
        self.assertEqual(target.password, "secret")

    def test_rejects_bad_port(self):
        with self.assertRaises(ValueError):
            parse_proxy_url("tg://proxy?server=127.0.0.1&port=99999")

    def test_status_values_are_strings(self):
        self.assertEqual(ProxyStatus.LIVE.value, "live")

    def test_info_decodes_fake_tls_secret(self):
        info = collect_proxy_info(
            "tg://proxy?server=109.120.191.135&port=853&secret=7t16ej1vTPH3w_rpz_KLc3lhZHMueDUucnU",
            include_ipwhois=False,
        )

        self.assertEqual(info["secret"]["mode"], "fake_tls")
        self.assertEqual(info["secret"]["domain"], "ads.x5.ru")
        self.assertEqual(set(info), {"target", "canonical", "secret"})


class CheckProxyTests(unittest.IsolatedAsyncioTestCase):
    async def test_tcp_live_result_includes_probe_name(self):
        async def handle_client(reader, writer):
            await reader.read(8)
            await asyncio.sleep(0.6)
            writer.close()

        server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            result = await check_proxy(f"127.0.0.1:{port}", timeout=2, attempts=1)
        finally:
            server.close()
            await server.wait_closed()

        self.assertEqual(result.status, ProxyStatus.LIVE)
        self.assertEqual(result.probe, "tcp")


if __name__ == "__main__":
    unittest.main()
