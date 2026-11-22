#!/usr/bin/env python3
"""Analizador defensivo de logs de autenticación / acceso web para prácticas SOC (Tomo I y IV).
Detecta umbrales de fallos repetidos por IP y emite alertas estructuradas en JSON.
"""
import collections
import json
import re
import sys

PATRON_SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
PATRON_HTTP_4XX = re.compile(r'^(?P<ip>\S+) .* "(?P<metodo>GET|POST|PUT|DELETE|HEAD) (?P<ruta>\S+) HTTP/.*" (?P<codigo>401|403|404) ')

def analizar_archivo(ruta: str, umbral: int = 5):
    ssh_fails = collections.Counter()
    http_4xx = collections.Counter()
    usuarios_por_ip = collections.defaultdict(set)

    with open(ruta, "r", encoding="utf-8", errors="replace") as f:
        for linea in f:
            m_ssh = PATRON_SSH_FAIL.search(linea)
            if m_ssh:
                ip = m_ssh.group("ip")
                ssh_fails[ip] += 1
                usuarios_por_ip[ip].add(m_ssh.group("user"))
                continue
            m_http = PATRON_HTTP_4XX.search(linea)
            if m_http:
                http_4xx[m_http.group("ip")] += 1

    alertas = []
    for ip, cuenta in ssh_fails.items():
        if cuenta >= umbral:
            alertas.append({
                "regla": "SOC-AUTH-001",
                "severidad": "media" if cuenta < 20 else "alta",
                "tactica_mitre": "Credential Access",
                "ip_origen": ip,
                "intentos_fallidos": cuenta,
                "usuarios_distintos": sorted(usuarios_por_ip[ip])[:10],
            })
    for ip, cuenta in http_4xx.items():
        if cuenta >= umbral * 3:
            alertas.append({
                "regla": "SOC-WEB-002",
                "severidad": "media",
                "tactica_mitre": "Discovery",
                "ip_origen": ip,
                "respuestas_4xx": cuenta,
            })

    print(json.dumps({"archivo": ruta, "total_alertas": len(alertas), "alertas": alertas}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python analizador_logs_soc.py <archivo_log> [umbral]")
        sys.exit(1)
    umbral = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    analizar_archivo(sys.argv[1], umbral)
