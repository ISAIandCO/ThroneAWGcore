# ThroneAWGcore

`throne-awg-core` - userspace SOCKS5-прокси поверх AmneziaWG. Он принимает
обычный WireGuard/AmneziaWG INI-конфиг, поднимает AmneziaWG через netstack и
отдает локальный SOCKS5 без системного TUN-интерфейса и root/admin-доступа.

Throne не обязателен: бинарник можно использовать как самостоятельный локальный
SOCKS5-прокси. Для Throne он дополнительно подходит как штатное внешнее ядро
через профиль `ExtraCore`.

## Возможности

- Самостоятельный SOCKS5-прокси: по умолчанию слушает `127.0.0.1:1080`.
- Не требует изменений в Throne и работает через штатный профиль `ExtraCore`.
- Поддерживает Windows, Linux и macOS x64.
- Принимает обычный WireGuard/AmneziaWG INI-конфиг.
- Поддерживает `Jc`, `Jmin`, `Jmax`, `S1-S4`, `H1-H4`, `I1-I5`.
- По умолчанию пытается автоматически привязать UDP-сокеты AWG к системному
  интерфейсу маршрута до endpoint, чтобы не попадать в уже включенный TUN.

## Быстрый старт без Throne

```bash
throne-awg-core run --config awg.conf
```

После запуска укажите в приложении SOCKS5-прокси:

- адрес: `127.0.0.1`
- порт: `1080`
- авторизация: выключена

Переопределить адрес прослушивания можно флагом `--listen`:

```bash
throne-awg-core run --config awg.conf --listen 127.0.0.1:2080
```

## Быстрый старт в Throne

1. Скачайте архив для своей ОС из Releases и распакуйте его.
2. В Throne создайте профиль типа `ExtraCore`.
3. Укажите:
   - `Socks address`: `127.0.0.1`
   - `Socks port`: `1080`
   - `Core path`: путь к `throne-awg-core` или `throne-awg-core.exe`
   - `Args`: `run --config %s`
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
run --config %s --verbose
```

При рабочем обмене в verbose-логе должны появляться строки `socks: request ...`
и `socks: tcp connect ... ok` или `socks: udp associate ...`.

Проверить сам AWG-туннель без Throne можно командой:

```bash
throne-awg-core probe --config awg.conf --target 1.1.1.1:443 --verbose
```

Если нужно проверить альтернативный UDP bind на Windows, добавьте `--std-bind`.

### Если включен TUN в Throne

Если `probe` работает без TUN Throne, но перестает работать при включенном TUN,
значит исходящий UDP-трафик самого AmneziaWG-процесса попадает обратно в TUN
Throne. Автоопределение системного интерфейса включено по умолчанию, поэтому
обычно достаточно базового запуска:

```text
run --config %s
```

Проверить тот же обход можно без Throne:

```powershell
.\throne-awg-core.exe probe --config .\awg.conf --target google.com:443 --verbose
```

В verbose-логе должна появиться строка вида
`awg: bound UDP sockets to interface index 12, iftype 6, metric 25`.

Если endpoint указан доменом и системный DNS под TUN Throne мешает
автоопределению, используйте ручной индекс интерфейса.

В PowerShell найдите индекс активного адаптера:

```powershell
Get-NetAdapter | Where-Object Status -eq Up | Format-Table ifIndex,Name,InterfaceDescription
```

Выберите обычный сетевой адаптер с интернетом, не Throne/Wintun/TUN, и добавьте
его индекс в аргументы Extra Core:

```text
run --config %s --interface-index 12
```

Автоопределение можно отключить:

```text
run --config %s --no-auto-interface
```

Проверка ручного варианта:

```powershell
.\throne-awg-core.exe probe --config .\awg.conf --target google.com:443 --verbose --interface-index 12
```

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
- Проксируемое приложение должно уметь работать через SOCKS5 или через клиент,
  который направляет трафик в этот SOCKS5.
- SOCKS5 работает без авторизации и должен слушать только loopback-адрес.

## Диагностика

- Если Throne пишет, что Extra Core завершился, запустите `check` с тем же
  конфигом и проверьте ключи, endpoint и `AllowedIPs`.
- Сообщения вида `Handshake did not complete` и `Retrying handshake` относятся
  к verbose-логам AmneziaWG. В обычном режиме они скрыты; включайте
  `--verbose` только для диагностики.
- Если `Address` в конфиге указан без маски, ядро автоматически использует
  `/32` для IPv4 и `/128` для IPv6.
- Если DNS-имена не открываются, укажите IP DNS-сервера в `DNS`.
