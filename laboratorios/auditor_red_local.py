#!/usr/bin/env python3
"""Inspector defensivo de puertos locales (restringido estrictamente a redes privadas RFC 1918 y loopback).
Uso educativo para inventario de superficie expuesta en laboratorio propio (Tomo I · Cap. 1.6).
"""
import ipaddress
import socket
import sys
from datetime import datetime, timezone

PUERTOS_COMUNES = [22, 53, 80, 135, 139, 389, 443, 445, 3306, 3389, 5050, 5432, 8080, 8443]

def es_destino_privado(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return ip.is_private or ip.is_loopback
    except OSError:
        return False

def verificar_puerto(host: str, puerto: int, timeout: float = 0.6) -> tuple[bool, str]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((host, puerto)) == 0:
            banner = ""
            try:
                if puerto in (80, 5050, 8080):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                banner = s.recv(120).decode("utf-8", errors="replace").splitlines()[0].strip()
            except Exception:
                banner = "(sin banner inmediato)"
            return True, banner
    return False, ""

def main():
    objetivo = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    if not es_destino_privado(objetivo):
        print("[BLOQUEADO] Este script educativo solo permite direcciones loopback (127.0.0.0/8) o privadas RFC 1918.")
        sys.exit(1)

    print(f"=== Inventario local de puertos en {objetivo} ({datetime.now(timezone.utc).isoformat()}) ===")
    abiertos = 0
    for p in PUERTOS_COMUNES:
        ok, banner = verificar_puerto(objetivo, p)
        if ok:
            abiertos += 1
            print(f"  [ABIERTO] TCP/{p:<5} | {banner}")
    print(f"Total de puertos detectados: {abiertos}/{len(PUERTOS_COMUNES)}")

if __name__ == "__main__":
    main()
