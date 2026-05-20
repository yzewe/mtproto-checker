# MTProto Checker

Асинхронный чекер Telegram MTProto и SOCKS5 proxy. Проверяет не просто открытый TCP-порт, а пытается дойти до Telegram-уровня: отправляет `req_pq_multi` и ждёт корректный `resPQ`.

## Что проверяет

- MTProto `plain` и `dd`: обфускация MTProxy, перебор DC `1..5`, транспорты `intermediate`, `abridged`, `padded_intermediate`.
- MTProto `ee`/FakeTLS: HMAC-подписанный ClientHello, проверка ServerHello, затем MTProxy `req_pq_multi` внутри TLS application-data.
- FakeTLS fallback: дополнительный legacy ClientHello для старых/нестандартных прокси; результат всё равно засчитывается только после валидного `resPQ`.
- SOCKS5: handshake, username/password при наличии, `CONNECT` к нескольким Telegram DC и нативный MTProto probe.
- Обычный `host:port`: только базовая TCP-проверка.

`LIVE` означает, что proxy прошёл Telegram-подобную проверку. `DEAD` означает, что чекер не смог получить валидный ответ за заданные попытки. `INVALID` означает ошибку формата URL, порта или secret.

## Возможности

- ссылки `tg://proxy?...` и `https://t.me/proxy?...`;
- ссылки `https://t.me/socks?...`;
- простой формат `host:port`;
- проверка списка из файла;
- параллельная проверка с ограничением `--concurrency`;
- повторные попытки `--attempts` и consensus-порог `--min-successes`;
- JSON-вывод;
- `--info`: secret mode, FakeTLS domain/SNI, пассивные признаки sponsor, ipwho.is.

## Установка

Нужен Python 3.10+.

```bash
pip install pycryptodome
```

## Использование

Проверить один proxy:

```bash
python proxy_checker.py "tg://proxy?server=185.86.147.17&port=443&secret=ee..."
```

Проверить файл:

```bash
python proxy_checker.py --file proxies.txt
```

Режим ближе к поведению Telegram:

```bash
python proxy_checker.py --file proxies.txt --timeout 12 --concurrency 10 --attempts 2
```

Более строгий режим для нестабильных proxy:

```bash
python proxy_checker.py --file proxies.txt --attempts 3 --min-successes 2
```

Показать только живые:

```bash
python proxy_checker.py --file proxies.txt --alive-only
```

JSON:

```bash
python proxy_checker.py --file proxies.txt --json
```

Полная информация:

```bash
python proxy_checker.py --file proxies.txt --info
python proxy_checker.py --file proxies.txt --info --json
python proxy_checker.py --file proxies.txt --info --no-ipwhois
```

## Формат файла

```text
tg://proxy?server=185.86.147.17&port=443&secret=ee...
https://t.me/proxy?server=127.0.0.1&port=443&secret=...
https://t.me/socks?server=127.0.0.1&port=1080&user=name&pass=secret
127.0.0.1:8080
# комментарии игнорируются
```

## Как вычисляется sponsor

Точный sponsor не зашит в публичную proxy-ссылку. В URL обычно есть только `server`, `port`, `secret` и иногда `title`. Для FakeTLS secret может содержать домен/SNI, например `google.com` или рекламный домен, но это не доказывает sponsor.

Telegram получает точный promoted peer отдельным RPC после подключения через MTProxy. В текущей схеме это `help.getPromoData`: если proxy зарегистрирован со sponsor-каналом, Telegram возвращает `help.promoData` с флагами `proxy` и `peer`. Старый механизм назывался `help.getProxyData` и возвращал `help.proxyDataPromo` или `help.proxyDataEmpty`.

Без пользовательской Telegram-сессии чекер не может честно получить точный канал или даже гарантированно доказать наличие sponsor. Поэтому `--info` показывает два уровня:

- `passive_url_secret_analysis`: признаки из URL, title, secret domain/SNI;
- `exact`: объяснение, что точный sponsor/presence требует Telegram user-session RPC.

Полезные ссылки:

- https://core.telegram.org/method/help.getPromoData
- https://core.telegram.org/constructor/help.promoData
- https://core.telegram.org/proxy

## Структура проекта

- `mtproto_checker/parser.py` — разбор URL и MTProto secret.
- `mtproto_checker/probes.py` — низкоуровневые MTProto, FakeTLS и SOCKS5 probe.
- `mtproto_checker/core.py` — `check_proxy` и `check_many`.
- `mtproto_checker/info.py` — расширенная информация о proxy.
- `mtproto_checker/cli.py` — CLI.
- `proxy_checker.py` — совместимый входной файл.

## Тесты

```bash
python -m unittest discover -s tests
```

## Лицензия

MIT
