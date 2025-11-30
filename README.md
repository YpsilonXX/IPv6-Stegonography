# IPv6-Steganography: Covert Channel in Destination Options (Python/Scapy 2025)

[![Python](https://img.shields.io/badge/Python-3.13%2B-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-yellow.svg)](https://scapy.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

## Описание проекта

**IPv6-Steganography** — это простой и мощный инструмент для скрытой передачи данных через IPv6-пакеты с использованием **стеганографии в Destination Options Header** (расширение заголовка IPv6). Данные прячутся в опции **PadN (тип 1)**, которая предназначена для "мусорного" заполнения и часто игнорируется сетевым оборудованием. Это позволяет передавать до ~1 КБ+ на пакет незаметно.

### Ключевые особенности
- **Скрытность**: PadN — легитимная опция RFC 8200; пакеты выглядят как обычный TCP SYN (имитация HTTP-запроса).
- **Шифрование**: AES-256-GCM (с nonce и аутентификацией) для безопасности.
- **Кроссплатформенность**: Работает на Linux (Arch, Ubuntu), macOS; на Windows — с Npcap.
- **Ёмкость**: До 1500 байт на пакет (минус заголовки); для больших файлов — ручная фрагментация.
- **Тестирование**: Loopback (::1) для локального теста; легко адаптировать для сети.
- **Актуальность 2025**: Совместимо с kernel 6.11+, Scapy 2.6+ и Python 3.13.

Проект создан для образовательных целей (изучение стеганографии в сетях). **Не используйте для незаконной деятельности!**

## Требования

- **Python**: 3.13+ (протестировано на Arch Linux).
- **Библиотеки**:
  - `scapy` (для манипуляции IPv6-пакетами).
  - `cryptography` (для AES-256-GCM).
- **Права**: Raw sockets требуют `sudo` или `setcap cap_net_raw,cap_net_admin+eip` (для Linux).

## Установка

### На Arch Linux (рекомендуется)
```bash
# Установка пакетов
sudo pacman -Syu python python-scapy python-cryptography

# Права для raw sockets без sudo (один раз)
sudo setcap cap_net_raw,cap_net_admin+eip $(which python)

# Клонируй репозиторий
git clone https://github.com/yourusername/ipv6-steganography.git
cd ipv6-steganography

# Тест IPv6 на loopback
ping6 ::1  # Должен ответить
```

### На других Linux/macOS
```bash
# Ubuntu/Debian
sudo apt install python3-scapy python3-cryptography

# macOS (с Homebrew)
brew install python@3.13 scapy cryptography

# Права (Linux)
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
```

### На Windows
- Установи Npcap (драйвер для raw sockets): [npcap.com](https://npcap.com).
- Запускай как Administrator.
- `pip install scapy cryptography`.

## Использование

Скрипт `stego_ipv6.py` работает в двух режимах: **send** (отправка) и **listen** (приём). Ключ шифрования хардкод (32 байта) — меняй в коде для реального использования.

### Пример 1: Локальный тест (loopback)
1. **Запусти приёмник** (терминал 1):
   ```bash
   python stego_ipv6.py listen
   ```
   Вывод: `[*] Listening for IPv6 DestOpt traffic... (Ctrl+C to stop)`

2. **Отправь сообщение** (терминал 2):
   ```bash
   python stego_ipv6.py send ::1 "Hello from IPv6 stego!"
   ```
   Вывод:
   ```
   [+] Scapy IPv6 route for ::1/lo added
   [+] Sending message: Hello from IPv6 stego!
   [+] Packet built successfully (XXX bytes)
   [+] Sending XX encrypted bytes via DestOpt PadN to ::1
   [+] Sent!
   ```

3. **На приёмнике**:
   ```
   [+] COVERT DATA RECEIVED (XX bytes): Hello from IPv6 stego!
   ```

### Пример 2: Отправка файла
```bash
# Создай тестовый файл
echo "Секретные данные 2025" > secret.txt

# Отправь
python stego_ipv6.py send ::1 secret.txt

# На приёмнике: файл сохранится как received_XXXX.bin
```

### Пример 3: Сетевая передача (между двумя машинами)
- На машине A (отправитель): `python stego_ipv6.py send 2001:db8::2 "Remote stego test"`
- На машине B (приёмник): `python stego_ipv6.py listen` (iface='enp1s0' в коде для реального интерфейса).
- Убедись в IPv6-роутинге: `ip -6 route add 2001:db8::/64 dev enp1s0`.

**Примечание**: Для больших файлов (>1 КБ) добавь фрагментацию (IPv6ExtHdrFragment) в код.

## Структура кода

Код — один файл `stego_ipv6.py` (~150 строк), модульный и самодокументированный. Вот разбор:

### Импорты и константы (строки 1–20)
- `scapy.all.*`: Для IPv6, TCP, Raw, HBHOptUnknown (для PadN).
- `cryptography.hazmat.primitives.ciphers.aead.AESGCM`: Для шифрования.
- `SECRET_KEY`: 32-байтный ключ (хардкод; в реале — из env или файла).

### Функции шифрования (строки 22–43)
- `encrypt_data(plaintext: bytes) -> bytes`: Генерирует nonce (12 байт), шифрует AES-256-GCM, возвращает nonce + ciphertext + tag.
- `decrypt_data(ciphertext: bytes) -> bytes`: Извлекает nonce, расшифровывает; возвращает '' при ошибке (неверный ключ/длина).

### Отправка: `send_stego(dst_ip: str, payload: bytes)` (строки 45–70)
- Шифрует payload.
- Создаёт опцию PadN: `HBHOptUnknown(otype=1, optdata=encrypted)` (тип 1 = PadN; unknown для DestOpt).
- Собирает пакет: `IPv6(dst) / DestOpt(options=[padn_opt]) / TCP(SYN) / Raw(HTTP-like)`.
- Тестирует сборку: `bytes(pkt)` (ловит ошибки).
- Отправляет: `send(pkt, iface='lo')`.

### Приём: `sniff_stego(pkt)` (строки 72–95)
- Фильтрует: IPv6 с nh=60 (DestOpt) и IPv6ExtHdrDestOpt.
- Проверяет опции: `otype==1` и `len(optdata)>=28` (минимум для nonce+tag).
- Извлекает `opt.optdata`, расшифровывает, выводит/сохраняет (если бинарно >100 байт).
- Возвращает после первого валидного (избегает спама).

### Главная: `main()` (строки 97–130)
- Добавляет маршрут Scapy для ::1/lo (фикс роутинга).
- Парсит аргументы: `send <dst> <payload>` или `listen`.
- Для send: Читает файл/строку, вызывает `send_stego`.
- Для listen: `sniff(iface='lo', filter="ip6 and ip6[6]==60 and tcp[13]&0x02!=0")` (только SYN-пакеты).
- Fallback: Без BPF, если фильтр сломается.

### Запуск: `if __name__ == "__main__": main()`
- Рекомендует `sudo` в usage (для raw sockets).

## Тестирование

1. **Локально**: См. Пример 1.
2. **В сети**: Используй Wireshark/tcpdump: `tcpdump -i lo ip6` — увидишь пакеты с DestOpt (nh=60).
3. **Проверка скрытности**: `scapy -c "pkt=IPv6()/IPv6ExtHdrDestOpt()/TCP(); hexdump(pkt)"` — PadN выглядит как padding.
4. **Производительность**: 1000 пакетов/сек на loopback; в сети — зависит от MTU.

## Возможные проблемы и решения

| Проблема | Решение |
|----------|---------|
| **Permission denied (raw sockets)** | `sudo setcap cap_net_raw,cap_net_admin+eip $(which python)` или запусти с `sudo`. |
| **BPF filter error** | Fallback сработает; обнови Scapy: `sudo pacman -Syu python-scapy`. |
| **No route to ::1** | `sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=0`; проверь `ping6 ::1`. |
| **Build error (alignment_delta)** | Убедись в `HBHOptUnknown(otype=1, optdata=...)` — фиксит tuple в опциях. |
| **No packet received** | Проверь фильтр: `sniff(filter="ip6", count=1)`; iface на реальный (e.g., 'enp1s0'). |
| **Windows Npcap** | Установи драйвер; run as Admin. |

## Лицензия
MIT License — свободное использование/модификация. См. [LICENSE](LICENSE).

