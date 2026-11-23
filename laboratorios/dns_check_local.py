#!/usr/bin/env python3
"""Verificador básico de resolución de nombres para entorno de laboratorio local."""
import datetime
import socket

OBJETIVOS_LOCALES = ["localhost", "web-lab.local"]


def verificar_resolucion_local(objetivos=OBJETIVOS_LOCALES):
    ahora_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(f"[INFO] Inicio de prueba UTC: {ahora_utc}")

    for nombre in objetivos:
        try:
            # getaddrinfo usa el resolvedor del SO (incluyendo /etc/hosts o DNS local)
            registros = socket.getaddrinfo(nombre, None, proto=socket.IPPROTO_TCP)
            ips = sorted({item[4][0] for item in registros})
            print(f"[OK]   {nombre} -> {', '.join(ips)}")
        except socket.gaierror as err:
            print(f"[MISS] {nombre} -> sin resolución ({err})")


if __name__ == "__main__":
    verificar_resolucion_local()
