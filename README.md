# mtproto-checker

Чекер Telegram-прокси на Go: MTProto, FakeTLS, WEB-прокси и SOCKS5. Без зависимостей, один бинарник, всё асинхронно.

## Что умеет

- MTProto (`plain`, `dd`/secure, `ee`/FakeTLS), WEB-прокси и SOCKS5;
- два режима проверки: быстрый `resPQ` и полный клиентский handshake (`--full`);
- ссылки `tg://proxy`, `tg://webproxy`, `https://t.me/proxy`, `t.me/socks`, `socks5://`, а также `host:port`;
- источники: аргументы, файлы, stdin, HTTP(S)-подписки (`--url`) — ссылки вытаскиваются даже из HTML и постов канала;
- дедупликация одинаковых прокси, повторы (`--attempts`), строгий режим (`--min-successes`);
- оценка качества: буква A–D и очки по задержке, джиттеру и потерям;
- фазы отдельно: TCP-коннект, FakeTLS/SOCKS5-рукопожатие, ответ Telegram;
- серия зашифрованных пингов в режиме `--full`: медиана, джиттер, потери;
- реальная страна выхода и проверка подмены дата-центров (`--inspect`);
- замер скорости скачивания через прокси (`--speedtest`);
- проверка стабильности сессии во времени (`--hold`);
- качество маскировки FakeTLS (`--masking`) и приём чужого секрета (`--check-open`);
- предел параллельных подключений (`--max-conns`);
- фильтры: `--mode`, `--port`, `--country`, `--asn`, `--exclude`;
- сортировка по задержке, `--top N`, `--alive-only`;
- сводка по странам, сетям (ASN) и причинам отказа;
- вывод: текст с цветом, JSON, CSV, список ссылок;
- сохранение в файлы: `--out`, `--save-live`, `--save-dead`, `--save-links`;
- машиночитаемые коды ошибок (`error_kind`) в JSON и CSV;
- `--info`: режим секрета, домен FakeTLS, IP, страна, ASN и провайдер через ipwho.is.

## Установка

Готовые бинарники для Linux, macOS и Windows — во [вкладке Releases](https://github.com/yzewe/mtproto-checker/releases).

Через Go:

```bash
go install github.com/yzewe/mtproto-checker/cmd/mtproto-checker@latest
```

Или из исходников:

```bash
go build -o mtproto-checker ./cmd/mtproto-checker
```

## Примеры

Одна ссылка:

```bash
mtproto-checker "tg://proxy?server=192.0.2.10&port=443&secret=ee..."
```

Список из файла, только живые, по возрастанию задержки:

```bash
mtproto-checker --file proxies.txt --sort --alive-only
```

Подписка из канала, полный handshake, сохранение результатов:

```bash
mtproto-checker --url "https://t.me/s/channel_name" --full --sort --save-links live.txt --out results.json
```

Только немецкие и нидерландские FakeTLS-прокси на 443 порту:

```bash
mtproto-checker --file proxies.txt --mode fake_tls --port 443 --country de,nl --alive-only
```

Строгая проверка (два успешных прохода из трёх) с деталями:

```bash
mtproto-checker --file proxies.txt --attempts 3 --min-successes 2 --info
```

Конвейер: взять живые прокси и передать дальше:

```bash
mtproto-checker --file proxies.txt --format links --alive-only --quiet --save-links live.txt
cat proxies.txt | mtproto-checker --stdin --format json > results.json
```

## WEB-прокси

`tg://webproxy?server=H&secret=...` — транспорт из
[tproxy-server](https://github.com/telegramdesktop/tproxy-server): поток MTProxy
едет мультиплексированными кадрами поверх HTTPS или WebSocket на 443 порту.

```bash
mtproto-checker "tg://webproxy?server=proxy.example.com&secret=00112233445566778899aabbccddeeff"
```

Чекер повторяет клиентскую последовательность целиком: выводит bridge-способность
как `HMAC-SHA256(secret, "tdesktop-web-proxy-bridge-v1\n" + host)`, забирает
одноразовый bootstrap-токен со страницы моста, создаёт релей-сессию через
`HELLO`/`WELCOME`, открывает поток и гоняет по нему обычное обфусцированное
рукопожатие MTProto. Поэтому `--full`, `--inspect`, `--speedtest` и `--hold`
работают через WEB-прокси так же, как через обычный.

Поддержаны все четыре режима переносчика: `https`, `https-lanes`, `websocket`,
`websocket-lanes` — режим выбирает сам сервер, чекер показывает его в маршруте
(`webproxy -> websocket`). Неверный секрет виден сразу: мост не отдаёт
bootstrap-токен, результат помечается кодом `secret_rejected`.

WebSocket-переносчик заметно быстрее: на одном и том же хосте 1846 КБ/с против
956 КБ/с у последовательного HTTPS — у того потолок в один запрос за раз.

## Глубокие проверки

Всё ниже работает без аккаунта: после `--full` у чекера есть auth key, а часть
API Telegram отвечает и без авторизации — те методы, что клиент вызывает на
экране входа.

`--inspect` и `--speedtest` требуют `--api-id`: Telegram отвергает запросы с
чужим или пустым `api_id`. Свой берётся на [my.telegram.org](https://my.telegram.org),
`api_hash` не нужен.

```bash
mtproto-checker --api-id 123456 --inspect --speedtest --masking --check-open proxies.txt
```

| Флаг | Что показывает |
|---|---|
| `--inspect` | страну, из которой Telegram видит трафик, и список дата-центров: чужие адреса в нём означают, что прокси заворачивает трафик через себя |
| `--speedtest` | скорость скачивания — тянет языковой пакет, самый большой ответ, доступный без аккаунта |
| `--hold 30s` | держит сессию заданное время с пингами, ловит прокси, которые отваливаются после первых секунд, и показывает дрейф задержки |
| `--masking` | что FakeTLS-прокси отвечает обычному TLS-клиенту: хорошо настроенный отдаёт сертификат заявленного домена, плохой молчит и потому заметен для DPI |
| `--check-open` | повторяет рукопожатие с неверным секретом; если прокси пускает, он не проверяет секрет вообще |
| `--max-conns N` | сколько одновременных подключений прокси реально обслуживает |

Заявленная страна и страна выхода расходятся — значит трафик идёт не туда, куда
написано; гео по IP этого не покажет, там будет страна самого прокси.

Скорость отдачи (upload) без аккаунта измерить нельзя: `upload.saveFilePart`
требует авторизованного пользователя.

## Режимы проверки

| Режим | Что делает | Когда использовать |
|---|---|---|
| по умолчанию | обфусцированное рукопожатие + `req_pq_multi`, проверка `resPQ` и nonce | массовая проверка списков |
| `--full` | всё то же плюс полный обмен как в клиенте: факторизация `pq`, RSA_PAD, Diffie-Hellman, создание auth key и зашифрованный `ping` → `pong` | когда нужно убедиться, что прокси реально пропускает трафик Telegram |

`--full` делает четыре round-trip вместо одного, поэтому он заметно медленнее, зато прокси, который отвечает только на первый пакет, его не пройдёт.

## Статусы

- `LIVE` — Telegram ответил через прокси.
- `DEAD` — не ответил (в скобках причина).
- `INVALID` — ссылку не удалось разобрать.

```text
[LIVE] A 192.0.2.10:4443  49.1 ms via faketls dc2/padded +authkey
           phases: connect 44.4 · handshake 46.1 · resPQ 56.1 ms
           ping:   3/3, median 49.1 ms, jitter 17.8 ms
           secret: fake_tls, sni=www.google.com
           geo:    192.0.2.10 🇳🇱 NL, Amsterdam AS64500 Example Hosting
           exit:   NL, Telegram put us on dc2
           config: 19 datacenters, all official
           speed:  1830 KB/s (681 KB in 0.37s)
           mask:   good (*.google.com, issued by WR2)
           secret: rejects a wrong secret
[DEAD] 198.51.100.7:443 (dial tcp 198.51.100.7:443: i/o timeout)
[INVALID] tg://proxy?server=203.0.113.5 (missing port)

summary: 3 live, 1 dead, 1 invalid of 5 in 10.04s
by country: 🇳🇱 NL 2/2 · 🇩🇪 DE 1/1 · 🇫🇷 FR 0/1
by ASN:     AS64500 Example Hosting 2/2 · AS64501 Other Hosting 1/1
failures:   dial_timeout 1
best: 192.0.2.10:4443 🇳🇱 NL  49.1 ms  grade A
      tg://proxy?server=192.0.2.10&port=4443&secret=ee...
```

Оценка: `A` — быстро и стабильно, `D` — пользоваться больно. Считается по медианной
задержке, джиттеру, потерям пингов и доле неудачных попыток. Строки с фазами и
пингом показываются с `--info`.

Задержка в строке `LIVE` — это медиана пингов (или ответ на `req_pq_multi`), а не
общее время проверки: полный handshake тратит несколько round-trip на обмен
ключами, и это говорит о протоколе, а не о прокси. Общее время есть в JSON как
`timings.total_ms`.

### Коды ошибок

В JSON и CSV каждая неудача помечена стабильным кодом: `dial_timeout`,
`dial_refused`, `dns_failed`, `unreachable`, `secret_rejected`,
`handshake_failed`, `timeout`, `connection_closed`, `no_respq`,
`socks_auth_failed`, `socks_rejected`, `canceled`. По ним удобно считать
статистику, не разбирая текст ошибок.

## Формат входного файла

```text
tg://proxy?server=192.0.2.10&port=443&secret=ee...
tg://webproxy?server=proxy.example.com&secret=00112233445566778899aabbccddeeff
https://t.me/proxy?server=192.0.2.11&port=443&secret=dd...
https://t.me/socks?server=192.0.2.12&port=1080&user=name&pass=secret
socks5://name:secret@192.0.2.12:1080
192.0.2.13:8080
# строки с # и // игнорируются
```

Строки без ссылок пропускаются, поэтому можно скармливать сохранённую HTML-страницу или выгрузку канала целиком.

## Флаги

```text
--file        файл со ссылками (можно несколько раз)
--url         HTTP(S)-подписка со ссылками (можно несколько раз)
--stdin       читать ссылки из stdin
--timeout     таймаут одного соединения (по умолчанию 8s)
--concurrency сколько прокси проверять параллельно (32)
--attempts    попыток на прокси (2)
--min-successes сколько успешных попыток нужно для LIVE (1)
--full        полный клиентский handshake с auth key
--pings       сколько зашифрованных пингов слать в режиме --full (3)
--api-id      api_id с my.telegram.org, нужен для --inspect и --speedtest
--inspect     страна выхода и проверка подмены дата-центров
--speedtest   скорость скачивания через прокси
--hold        держать сессию заданное время и мерить дрейф задержки
--masking     что FakeTLS-прокси показывает обычному TLS-клиенту
--check-open  принимает ли прокси неверный секрет
--max-conns   сколько параллельных подключений открыть
--retry-delay пауза перед второй попыткой, дальше экспоненциально (250ms)
--info        секрет, домен FakeTLS и гео через ipwho.is
--mode        оставить только fake_tls, secure, plain, webproxy, socks5 или tcp
--port        оставить только эти порты
--country     оставить только эти страны (включает --info)
--asn         оставить только эти автономные системы (включает --info)
--exclude     файл со ссылками или хостами, которые пропустить
--format      text | json | csv | links
--out         сохранить показанные результаты (.json, .csv или .txt)
--save-live   сохранить живые в JSON
--save-dead   сохранить мёртвые в JSON
--save-links  сохранить живые как tg:// ссылки
--sort        сортировать живые по задержке
--top         показать только первые N
--alive-only  показывать только живые
--quiet       без текстового вывода (файлы и код возврата остаются)
--no-color    без цвета
--version     версия
```

Код возврата: `0` — есть живые прокси, `1` — живых нет, `2` — ошибка запуска.

## Структура

```text
cmd/mtproto-checker    точка входа и разбор флагов
internal/input         сбор ссылок из аргументов, файлов, stdin и подписок
internal/proxy         разбор ссылок и секретов (dd, ee, hex, base64)
internal/webproxy      WEB-прокси: мост, релей-сессия, кадры, HTTPS и WebSocket
internal/mtproto       транспорт и протокол: обфускация, FakeTLS, SOCKS5,
                       RSA_PAD, AES-IGE, Diffie-Hellman, auth key, ping,
                       вызовы API и проверки прокси
internal/checker       параллельный прогон, повторы, оценка качества
internal/filter        отбор по режиму, порту, стране, ASN, исключениям
internal/geo           ipwho.is с кэшем на запуск
internal/report        text, JSON, CSV, links, сводки, запись в файлы
```

Обфускация и порядок сообщений повторяют поведение официальных клиентов (см. `tgnet` в исходниках Telegram для Android).

## Сборка

```bash
make build     # бинарник с версией из git
make vet       # go vet
make fmt       # gofmt
```

## Лицензия

MIT
