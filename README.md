# MTProto Checker

Быстрый CLI-чекер для Telegram MTProto, FakeTLS и SOCKS5 proxy.

Проверка не ограничивается TCP-портом: для MTProto/SOCKS5 чекер отправляет `req_pq_multi` и ждёт валидный `resPQ` от Telegram.

## Возможности

- `tg://proxy?...` и `https://t.me/proxy?...`
- `https://t.me/socks?...`
- `host:port`
- параллельная проверка списков
- повторы через `--attempts`
- строгий режим через `--min-successes`
- JSON-вывод
- `--info`: secret mode, FakeTLS domain/SNI, ipwho.is
- `LIVE` показывает route/probe: DC, transport или SOCKS tunnel

## Установка

```bash
pip install pycryptodome
```

## Примеры

Один proxy:

```bash
python proxy_checker.py "tg://proxy?server=1.2.3.4&port=443&secret=ee..."
```

Файл:

```bash
python proxy_checker.py --file proxies.txt
```

Ближе к Telegram-клиенту:

```bash
python proxy_checker.py --file proxies.txt --timeout 12 --concurrency 10 --attempts 2
```

Строже:

```bash
python proxy_checker.py --file proxies.txt --attempts 3 --min-successes 2
```

Только живые:

```bash
python proxy_checker.py --file proxies.txt --alive-only
```

Информация:

```bash
python proxy_checker.py --file proxies.txt --info
python proxy_checker.py --file proxies.txt --info --json
python proxy_checker.py --file proxies.txt --info --no-ipwhois
```

## Статусы

- `LIVE` — получен валидный Telegram `resPQ`.
- `DEAD` — валидный ответ не получен.
- `INVALID` — ошибка URL, порта, secret или зависимости.

Пример:

```text
[LIVE] 138.124.49.226:443 901.3 ms via faketls modern dc2/faketls-padded
[DEAD] 94.183.170.27:443 (ConnectionError)
[INVALID] ... (pycryptodome is required for MTProto checks)
```

## Формат файла

```text
tg://proxy?server=1.2.3.4&port=443&secret=ee...
https://t.me/proxy?server=1.2.3.4&port=443&secret=...
https://t.me/socks?server=1.2.3.4&port=1080&user=name&pass=secret
1.2.3.4:8080
# комментарии игнорируются
```

## Что можно узнать без Telegram-сессии

- живой proxy или нет;
- latency;
- какой probe прошёл: FakeTLS/plain/dd/SOCKS5;
- DC и transport, если проверка прошла;
- mode secret: `plain`, `secure`, `fake_tls`;
- домен/SNI из FakeTLS secret;
- IP, ASN, провайдер и гео через ipwho.is.

## Структура

- `mtproto_checker/parser.py` — URL и secret.
- `mtproto_checker/probes.py` — MTProto, FakeTLS, SOCKS5.
- `mtproto_checker/core.py` — `check_proxy`, `check_many`.
- `mtproto_checker/info.py` — `--info`.
- `mtproto_checker/cli.py` — CLI.

## Тесты

```bash
python -m unittest discover -s tests
```

## Лицензия

MIT
