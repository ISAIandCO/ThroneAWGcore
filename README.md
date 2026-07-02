# ThroneAWGcore

`throne-awg-core` - внешнее ядро AmneziaWG для Throne. Throne запускает его как
Extra Core, подключается к локальному SOCKS5, а сам `throne-awg-core` проводит
TCP/UDP-трафик через AmneziaWG в userspace без системного TUN-интерфейса.

## Возможности

- Не требует изменений в Throne.
- Работает через штатный профиль `ExtraCore`.
- Поддерживает Windows, Linux и macOS x64.
- Принимает обычный WireGuard/AmneziaWG INI-конфиг.
- Поддерживает `Jc`, `Jmin`, `Jmax`, `S1-S4`, `H1-H4`, `I1-I5`.

## Быстрый старт в Throne

1. Скачайте архив для своей ОС из Releases и распакуйте его.
2. В Throne создайте профиль типа `ExtraCore`.
3. Укажите:
   - `Socks address`: `127.0.0.1`
   - `Socks port`: `1080`
   - `Core path`: путь к `throne-awg-core` или `throne-awg-core.exe`
   - `Args`: `run --listen 127.0.0.1:1080 --config %s`
   - `Config`: содержимое AmneziaWG-конфига.
4. Запустите профиль.

Throne сам создаст временный файл конфига вместо `%s`, запустит процесс и
направит трафик в SOCKS5 на `127.0.0.1:1080`.

## Формат конфига

```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.8.0.2/32
DNS = 1.1.1.1
MTU = 1280
Jc = 5
Jmin = 40
Jmax = 90
S1 = 10
S2 = 20
H1 = 100-200
H2 = 201-300
I1 = <b 0x01020304>

[Peer]
PublicKey = <server-public-key>
PresharedKey = <optional-preshared-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

Перед использованием можно проверить конфиг:

```bash
throne-awg-core check --config awg.conf
```

Для подробной диагностики можно временно включить verbose-логи:

```text
run --listen 127.0.0.1:1080 --config %s --verbose
```

При рабочем обмене в verbose-логе должны появляться строки `socks: request ...`
и `socks: tcp connect ... ok` или `socks: udp associate ...`.

## Сборка

```bash
go test ./...
go build -o throne-awg-core ./cmd/throne-awg-core
```

Релизные сборки создаются GitHub Actions при публикации тега:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Также релиз можно создать вручную через `workflow_dispatch`: укажите имя тега
в поле `release_tag`, например `v0.1.0`. Workflow соберет архивы и прикрепит их
к GitHub Release с этим тегом.

## Ограничения

- Это не системный VPN и не создает TUN-интерфейс ОС.
- Весь трафик должен идти через Extra Core профиль Throne.
- SOCKS5 работает без авторизации и должен слушать только loopback-адрес.
- Первый релиз рассчитан на `amd64` desktop-платформы.

## Диагностика

- Если Throne пишет, что Extra Core завершился, запустите `check` с тем же
  конфигом и проверьте ключи, endpoint и `AllowedIPs`.
- Сообщения вида `Handshake did not complete` и `Retrying handshake` относятся
  к verbose-логам AmneziaWG. В обычном режиме они скрыты; включайте
  `--verbose` только для диагностики.
- Если `Address` в конфиге указан без маски, ядро автоматически использует
  `/32` для IPv4 и `/128` для IPv6.
- Если порт занят, поменяйте одновременно `Socks port` и `--listen`.
- Если DNS-имена не открываются, укажите IP DNS-сервера в `DNS`.
