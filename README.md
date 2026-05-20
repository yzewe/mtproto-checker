# MTProto Checker

Быстрый асинхронный чекер для Telegram MTProto proxy-ссылок, SOCKS5-ссылок и обычных целей в формате `host:port`.

Чекер старается вести себя ближе к Telegram:

- для обычных и `dd` MTProto proxy отправляет нативный plaintext-запрос `req_pq_multi` и ждёт настоящий `resPQ` от Telegram DC;
- для `ee`/FakeTLS проверяет подписанный FakeTLS ServerHello и MTProxy `req_pq_multi` внутри TLS application-data;
- для SOCKS5 выполняет handshake, `CONNECT` к нескольким Telegram DC и тоже проверяет `req_pq_multi`.

`LIVE` означает, что проверка прошла на уровне Telegram MTProto/FakeTLS/SOCKS5, а не просто открылся TCP-порт.

## Возможности

- параллельная проверка большого списка прокси;
- поддержка ссылок `tg://proxy?server=...&port=...&secret=...`;
- поддержка ссылок `https://t.me/proxy?server=...&port=...&secret=...`;
- поддержка ссылок `https://t.me/socks?server=...&port=...&user=...&pass=...`;
- поддержка простого формата `host:port`;
- чтение прокси из текстовых файлов;
- повторные probe-попытки и consensus-режим через `--attempts` / `--min-successes`;
- вывод в обычном виде или JSON;
- простой вывод: `LIVE`, `DEAD` или `INVALID`.

## Требования

- Python 3.10+
- pycryptodome

```bash
pip install pycryptodome
```

## Использование

Проверить один прокси:

```bash
python proxy_checker.py "tg://proxy?server=185.86.147.17&port=443&secret=ee..."
```

Проверить список из файла:

```bash
python proxy_checker.py --file proxies.txt
```

Для результата ближе к Telegram не ставь слишком большую параллельность:

```bash
python proxy_checker.py --file proxies.txt --concurrency 10 --timeout 12
```

Более строгая проверка для флапающих прокси:

```bash
python proxy_checker.py --file proxies.txt --attempts 2 --min-successes 2
```

Показать только живые:

```bash
python proxy_checker.py --file proxies.txt --alive-only
```

JSON:

```bash
python proxy_checker.py --file proxies.txt --json
```

## Формат списка

```text
tg://proxy?server=185.86.147.17&port=443&secret=ee...
https://t.me/socks?server=127.0.0.1&port=1080&user=name&pass=secret
127.0.0.1:8080
# комментарии игнорируются
```

## Тесты

```bash
python -m unittest discover -s tests
```

## Лицензия

MIT
