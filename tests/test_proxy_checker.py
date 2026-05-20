import unittest

from mtproto_checker import ProxyStatus, parse_proxy_url


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


if __name__ == "__main__":
    unittest.main()
