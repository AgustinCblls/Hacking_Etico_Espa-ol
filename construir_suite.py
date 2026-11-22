# -*- coding: utf-8 -*-
"""Constructor maestro de 'Hacking Ético Español' (Edición 2.0 · Hiper Biblioteca).
Genera el sitio HTML 100 % offline (54 capítulos en 7 Tomos + Portada + Mapa + Catálogo interactivo de 358 módulos y 25 paths
+ Cheat Sheets + Glosario ampliado + Preguntas de repaso + Buscador offline + Orden de impresión)
y compila los 9 PDFs A4 (Tomos I–VII + Separata + Maestro único) con TOC paginado, marcadores jerárquicos y paridad par estricta.
"""
import html as _html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

import pypdf

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
TRABAJO_DIR = os.path.join(REPO_ROOT, "_trabajo")
SRC_DIR = os.path.join(TRABAJO_DIR, "src")
GUIA_DIR = os.path.join(REPO_ROOT, "guia")
DATOS_DIR = os.path.join(REPO_ROOT, "datos")
BUILD_TMP = os.path.join(TRABAJO_DIR, "build_pdf")
os.makedirs(BUILD_TMP, exist_ok=True)
os.makedirs(GUIA_DIR, exist_ok=True)

sys.path.insert(0, TRABAJO_DIR)
from contenidos_apoyo import (
    CHEAT_SHEETS_HTML,
    FUENTES_LIMITES_HTML,
    GLOSARIO_ITEMS,
    LABORATORIOS_HTML,
)

EDICION_LABEL = "edición 2.0 · Hiper Biblioteca · Noviembre 2026"
CURSO_NOMBRE = "Hacking Ético Español"

TOMOS_META = [
    {
        "num": 1,
        "key": "Tomo I",
        "dir": "tomo1",
        "slug_html": "tomo1.html",
        "pdf": "Tomo_1_Fundamentos_Sistemas_Redes.pdf",
        "titulo": "Tomo I · Fundamentos, Laboratorio, Sistemas, Redes y Criptografía",
        "subtitulo": "Ruta 1 · Principiante — Base técnica obligatoria (Linux, Windows, TCP/IP, Scripting, HTTP y TLS/PKI)",
        "nivel_css": "principiante",
        "nivel_txt": "Principiante",
        "horas": "50–68 h",
        "resumen": "Construye desde cero el laboratorio aislado, la comprensión de redes TCP/IP, el dominio operativo de Linux y Windows, la automatización con Bash/PowerShell/Python, los fundamentos de protocolos/web y la criptografía aplicada con TLS y PKI.",
    },
    {
        "num": 2,
        "key": "Tomo II",
        "dir": "tomo2",
        "slug_html": "tomo2.html",
        "pdf": "Tomo_2_Pentesting_y_Seguridad_Web.pdf",
        "titulo": "Tomo II · Pentesting General y Seguridad Web (Junior → Senior)",
        "subtitulo": "Ruta 2 · Intermedio — Reconocimiento, OWASP Top 10, APIs/GraphQL, Whitebox y Reporting",
        "nivel_css": "intermedio",
        "nivel_txt": "Intermedio",
        "horas": "52–68 h",
        "resumen": "Desarrolla la metodología de evaluación autorizada, enumeración con Nmap y ffuf, vulnerabilidades web del lado servidor y cliente, autenticación/JWT/OAuth, seguridad de APIs y redacción de informes ejecutivos y técnicos.",
    },
    {
        "num": 3,
        "key": "Tomo III",
        "dir": "tomo3",
        "slug_html": "tomo3.html",
        "pdf": "Tomo_3_Infraestructura_PrivEsc_y_AD.pdf",
        "titulo": "Tomo III · Infraestructura, Escalada de Privilegios y Active Directory",
        "subtitulo": "Ruta 3 · Avanzado — Post-explotación controlada, PrivEsc Linux/Windows, Pivoting, Kerberos, ADCS y Hardening",
        "nivel_css": "avanzado",
        "nivel_txt": "Avanzado",
        "horas": "62–78 h",
        "resumen": "Aborda sesiones en laboratorio, auditoría de contraseñas (NIST SP 800-63B), escalada de privilegios y hardening en Linux y Windows, pivoting/microsegmentación y dominio profundo de Active Directory ofensivo y defensivo.",
    },
    {
        "num": 4,
        "key": "Tomo IV",
        "dir": "tomo4",
        "slug_html": "tomo4.html",
        "pdf": "Tomo_4_Defensivo_SOC_y_DFIR.pdf",
        "titulo": "Tomo IV · Defensivo, SOC, SIEM, DFIR y Detection Engineering",
        "subtitulo": "Ruta 4 · Especialista Blue Team — Operaciones SOC, Sysmon, Splunk/Elastic, NSM, Sigma/YARA, Hunting y Forense",
        "nivel_css": "especialista",
        "nivel_txt": "Especialista",
        "horas": "62–78 h",
        "resumen": "Forma capacidades reales de defensa: triage SOC y respuesta a incidentes (NIST SP 800-61), telemetría Windows/Sysmon/auditd, SIEM (SPL/KQL), tráfico de red (Wireshark/Zeek/Suricata), Sigma/YARA, Threat Hunting, DFIR y triage estático.",
    },
    {
        "num": 5,
        "key": "Tomo V",
        "dir": "tomo5",
        "slug_html": "tomo5.html",
        "pdf": "Tomo_5_Cloud_Contenedores_y_DevSecOps.pdf",
        "titulo": "Tomo V · Multi-Cloud, Contenedores, Kubernetes y DevSecOps",
        "subtitulo": "Ruta 5 · Cloud y DevSecOps — AWS/Azure/Entra ID/GCP, Docker, K8s RBAC, CI/CD, IaC y Forense Cloud",
        "nivel_css": "avanzado",
        "nivel_txt": "Avanzado",
        "horas": "51–65 h",
        "resumen": "Integra la seguridad ofensiva y defensiva en la nube moderna: políticas IAM y Entra ID, Storage/VPC/IMDSv2, escapes y hardening en Docker y Kubernetes, pipelines CI/CD e IaC, CloudTrail/GuardDuty/WAF/Cloud Armor y forense en AWS, Azure y GCP.",
    },
    {
        "num": 6,
        "key": "Tomo VI",
        "dir": "tomo6",
        "slug_html": "tomo6.html",
        "pdf": "Tomo_6_Web_Avanzado_CodeReview_y_OPSEC.pdf",
        "titulo": "Tomo VI · Web Avanzado, Code Review, Threat Modeling y Red Team / OPSEC",
        "subtitulo": "Ruta 6 · Ingeniería Ofensiva Avanzada — PortSwigger/WSTG, STRIDE/PASTA, White-Box Multi-lenguaje y OPSEC/AV-EDR",
        "nivel_css": "especialista",
        "nivel_txt": "Especialista",
        "horas": "54–68 h",
        "resumen": "Profundiza en el nivel experto más allá del pentest tradicional: Race Conditions HTTP/2, Cache Poisoning/Deception, OAuth/OIDC complejo, lógica de negocio, Threat Modeling, auditoría White-Box en 5 lenguajes, OPSEC/LOLBAS, arquitectura AV/EDR e Ingeniería Social controlada.",
    },
    {
        "num": 7,
        "key": "Tomo VII",
        "dir": "tomo7",
        "slug_html": "tomo7.html",
        "pdf": "Tomo_7_Mobile_Wireless_OT_y_GRC.pdf",
        "titulo": "Tomo VII · Mobile (MASTG), Wi-Fi, Hardware/IoT, OT/ICS y GRC Legal",
        "subtitulo": "Ruta 7 · Dominios Especializados — Android/iOS, 802.11/WPA3/802.1X, RFID/DMA/Firmware, Purdue/SCADA e ISO 27001/NIST CSF",
        "nivel_css": "especialista",
        "nivel_txt": "Especialista",
        "horas": "47–61 h",
        "resumen": "Completa la biblioteca integral cubriendo seguridad móvil estática, dinámica y forense (Android/iOS), redes inalámbricas WEP/WPS/WPA2/WPA3/Enterprise, seguridad física y hardware/IoT, redes industriales OT/SCADA (Modelo Purdue) y GRC, riesgos y marcos legales.",
    },
]


def buscar_chrome():
    candidatos = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    for c in candidatos:
        if os.path.exists(c):
            return c
    return shutil.which("chrome") or shutil.which("msedge") or "chrome.exe"


CHROME = buscar_chrome()


def slugify(text):
    t = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-") or "sec"


def esc(t):
    return _html.escape(t, quote=False)


def inline(text):
    piezas = []

    def guardar(m):
        piezas.append("<code>" + esc(m.group(1)) + "</code>")
        return f"\x00{len(piezas)-1}\x00"

    text = re.sub(r"`([^`]+)`", guardar, text)
    text = esc(text)
    text = re.sub(r"\*\*((?:(?!\*\*).)+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", text)
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda m: f'<a href="{m.group(2).strip()}">{m.group(1)}</a>',
        text,
    )

    def restaurar(m):
        return piezas[int(m.group(1))]

    return re.sub(r"\x00(\d+)\x00", restaurar, text)


def parse_tabla(block):
    lineas = [l.strip() for l in block.strip().split("\n") if l.strip()]
    if len(lineas) < 2:
        return None
    cab = [c.strip() for c in lineas[0].strip("|").split("|")]
    filas = [l for l in lineas[1:] if not re.match(r"^[\s:|-]+$", l.strip("|"))]
    salida = ['<div class="tabla"><table>', "<thead><tr>"]
    salida += [f"<th>{inline(c)}</th>" for c in cab]
    salida.append("</tr></thead><tbody>")
    for f in filas:
        celdas = [c.strip() for c in f.strip("|").split("|")]
        while len(celdas) < len(cab):
            celdas.append("")
        salida.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in celdas[: len(cab)]) + "</tr>")
    salida.append("</tbody></table></div>")
    return "\n".join(salida)


def md_to_html(texto, section_prefix=""):
    texto = texto.replace("\r\n", "\n")
    lineas = texto.split("\n")
    out = []
    parrafo = []
    i = 0

    def cerrar_parrafo():
        if parrafo:
            out.append("<p>" + inline(" ".join(parrafo)) + "</p>")
            parrafo.clear()

    while i < len(lineas):
        line = lineas[i]
        s = line.strip()

        if s.startswith("```"):
            cerrar_parrafo()
            lang = s[3:].strip()
            bloque = []
            i += 1
            while i < len(lineas) and not lineas[i].strip().startswith("```"):
                bloque.append(lineas[i])
                i += 1
            i += 1
            clase = f' class="lenguaje-{esc(lang)}"' if lang else ""
            out.append(f"<pre><code{clase}>" + esc("\n".join(bloque)) + "</code></pre>")
            continue

        if s.startswith(":::"):
            cerrar_parrafo()
            cab = s[3:].strip().split(" ", 1)
            tipo = (cab[0] or "nota").strip("{}").lower()
            if tipo not in ("nota", "aviso", "peligro", "practica", "defensa", "respuesta"):
                tipo = "nota"
            titulo = cab[1] if len(cab) > 1 else ""
            cuerpo = []
            i += 1
            while i < len(lineas) and not lineas[i].strip().startswith(":::"):
                cuerpo.append(lineas[i])
                i += 1
            i += 1
            h = f'<p class="callout-titulo">{inline(titulo)}</p>' if titulo else ""
            out.append(f'<aside class="callout {esc(tipo)}">{h}{md_to_html(chr(10).join(cuerpo), section_prefix)}</aside>')
            continue

        if s.startswith("#"):
            cerrar_parrafo()
            nivel = min(len(s) - len(s.lstrip("#")), 6)
            titulo = s[nivel:].strip()
            anchor_base = slugify(titulo)
            anchor = f"{section_prefix}-{anchor_base}" if section_prefix else anchor_base
            out.append(f'<h{nivel} id="{esc(anchor)}">{inline(titulo)}</h{nivel}>')
            i += 1
            continue

        if s.startswith("|") and "|" in s[1:]:
            cerrar_parrafo()
            bloque = []
            while i < len(lineas) and lineas[i].strip().startswith("|"):
                bloque.append(lineas[i])
                i += 1
            t = parse_tabla("\n".join(bloque))
            if t:
                out.append(t)
            continue

        if re.match(r"^[-*] ", s):
            cerrar_parrafo()
            items = []
            while i < len(lineas) and re.match(r"^[-*] ", lineas[i].strip()):
                raw_it = re.sub(r"^[-*] ", "", lineas[i].strip())
                raw_it = re.sub(r"^\[ \]\s*", "☐ ", raw_it)
                raw_it = re.sub(r"^\[[xX]\]\s*", "☑ ", raw_it)
                items.append(raw_it)
                i += 1
            out.append("<ul>" + "".join(f"<li>{inline(x)}</li>" for x in items) + "</ul>")
            continue

        if re.match(r"^\d+\. ", s):
            cerrar_parrafo()
            first_num = int(re.match(r"^(\d+)\. ", s).group(1))
            items = []
            while i < len(lineas) and re.match(r"^\d+\. ", lineas[i].strip()):
                items.append(re.sub(r"^\d+\. ", "", lineas[i].strip()))
                i += 1
            start_attr = f' start="{first_num}"' if first_num > 1 else ""
            out.append(f"<ol{start_attr}>" + "".join(f"<li>{inline(x)}</li>" for x in items) + "</ol>")
            continue

        if s.startswith(">"):
            cerrar_parrafo()
            cita = []
            while i < len(lineas) and lineas[i].strip().startswith(">"):
                cita.append(lineas[i].strip().lstrip(">").strip())
                i += 1
            out.append("<blockquote>" + md_to_html("\n".join(cita), section_prefix) + "</blockquote>")
            continue

        if s in ("---", "***"):
            cerrar_parrafo()
            out.append("<hr>")
            i += 1
            continue

        if not s:
            cerrar_parrafo()
            i += 1
            continue

        parrafo.append(s)
        i += 1

    cerrar_parrafo()
    return "\n".join(out)


def page_shell(title, description, body_html, depth=0, extra_head="", extra_script=""):
    p = "../" * depth
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} · {CURSO_NOMBRE}</title>
<meta name="description" content="{esc(description)}">
<link rel="stylesheet" href="{p}guia/estilo.css">
{extra_head}
</head>
<body>
<a class="salto" href="#contenido">Saltar al contenido</a>
<header class="cabecera">
  <div class="marca"><a href="{p}00_EMPEZAR_AQUI.html">{CURSO_NOMBRE}</a> <span class="edicion">{EDICION_LABEL}</span></div>
  <nav class="principal" aria-label="Navegación principal">
    <a href="{p}00_EMPEZAR_AQUI.html">Inicio</a>
    <a href="{p}guia/index.html">Curso</a>
    <a href="{p}catalogo_completo.html">Catálogo 358</a>
    <a href="{p}laboratorios.html">Laboratorios</a>
    <a href="{p}hojas-referencia-rapida.html">Cheat Sheets</a>
    <a href="{p}glosario.html">Glosario</a>
    <a href="{p}preguntas_y_respuestas.html">Repaso</a>
    <a href="{p}buscar.html">Buscar</a>
  </nav>
</header>
<main id="contenido">
{body_html}
</main>
<footer class="pie">
  <p>Manual técnico libre, educativo y defensivo. Todas las prácticas están diseñadas exclusivamente para laboratorios locales aislados (VMs propias o Docker en <code>127.0.0.1</code>).</p>
  <p><a href="{p}00_EMPEZAR_AQUI.html">Inicio</a> · <a href="{p}guia/index.html">Mapa del curso</a> · <a href="{p}catalogo_completo.html">Catálogo 358</a> · <a href="{p}orden_impresion.html">Imprenta y PDFs</a> · <a href="{p}fuentes_y_limites.html">Fuentes y límites</a></p>
</footer>
{extra_script}
</body>
</html>
"""


def strip_html(h):
    t = re.sub(r"<script.*?</script>", " ", h, flags=re.S)
    t = re.sub(r"<style.*?</style>", " ", t, flags=re.S)
    t = re.sub(r"<[^>]+>", " ", t)
    t = _html.unescape(t)
    return re.sub(r"\s+", " ", t).strip()


def extraer_preguntas(md_text):
    """Extrae preguntas **1. ¿...?** Respuesta... de la sección Preguntas de repaso."""
    m = re.search(r"##\s+[0-9.]*\s*Preguntas de repaso(.*?)(?:\n##\s+|\Z)", md_text, flags=re.S | re.I)
    if not m:
        return []
    bloque = m.group(1).strip()
    qa = []
    patron = re.compile(r"\*\*(\d+\.\s+(?:(?!\*\*).)+?)\*\*\s*(.+?)(?=\n\*\*\d+\.|\Z)", flags=re.S)
    for pm in patron.finditer(bloque):
        preg = pm.group(1).strip()
        resp = re.sub(r"\s+", " ", pm.group(2).strip())
        qa.append((preg, resp))
    return qa


def enfoque_badge_css(enfoque):
    e = enfoque.lower()
    if "defensivo" in e and "ofensivo" in e:
        return "mixto"
    if "defensivo" in e:
        return "defensivo"
    if "ofensivo" in e:
        return "ofensivo"
    return "mixto"


def construir_sitio_html(data):
    caps = data["capitulos_curso"]
    mods = data["modulos"]
    paths = data["paths"]

    mods_by_cap = {}
    for m in mods:
        mods_by_cap.setdefault(m.get("capitulo_asignado", "—"), []).append(m)

    tomo_dir_map = {t["key"]: t["dir"] for t in TOMOS_META}
    tomo_meta_map = {t["key"]: t for t in TOMOS_META}

    rendered_chapters = {}  # cap_id -> dict(html_body, md_text, qa, plain_text)
    all_qa = []
    search_docs = []

    # 1. Build all 32 chapters
    for idx, c in enumerate(caps):
        cid = c["id"]
        tdir = tomo_dir_map[c["tomo"]]
        md_file = os.path.join(SRC_DIR, tdir, c["archivo"].replace(".html", ".md"))
        if not os.path.exists(md_file):
            raise FileNotFoundError(f"Falta archivo fuente Markdown: {md_file}")
        md_text = open(md_file, "r", encoding="utf-8").read()
        # Strip accidental leading H1
        md_clean = re.sub(r"^\s*#\s+[^\n]+\n+", "", md_text, count=1)
        body_inner = md_to_html(md_clean, section_prefix=f"cap-{cid.replace('.', '-')}")

        # Mapped catalog modules reference block
        mapped = mods_by_cap.get(cid, [])
        mapped_html = ""
        if mapped:
            rows = []
            for mm in mapped:
                rows.append(
                    f'<tr><td>{esc(mm["title"])}</td><td>{esc(mm.get("difficulty",""))}</td>'
                    f'<td>{esc(mm.get("category",""))}</td><td>{mm.get("sections_count","")}</td></tr>'
                )
            mapped_html = f"""
<details class="qa" style="margin-top:1.5rem">
  <summary>Trazabilidad curricular: {len(mapped)} módulo(s) del catálogo público de referencia cubiertos en este capítulo</summary>
  <div class="respuesta">
    <p>Este capítulo fue redactado de forma 100 % original integrando los tópicos de referencia de los siguientes módulos del catálogo público:</p>
    <div class="tabla"><table>
      <thead><tr><th>Módulo de referencia</th><th>Dificultad</th><th>Categoría</th><th>Secciones</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table></div>
  </div>
</details>"""

        # Next / Prev navigation
        prev_c = caps[idx - 1] if idx > 0 else None
        next_c = caps[idx + 1] if idx + 1 < len(caps) else None
        sig_html = f'Siguiente paso: <a href="{next_c["archivo"]}">{next_c["id"]} {esc(next_c["titulo"])}</a>' if next_c else 'Último capítulo · <a href="../preguntas_y_respuestas.html">Ir al Repaso Integral</a>'

        meta_bar = (
            f'<div class="meta-nivel">'
            f'<span class="nivel-badge {c["nivel_css"]}">{esc(c["ruta"].split("·")[-1].strip())}</span> '
            f'<span class="nivel-badge {enfoque_badge_css(c["enfoque"])}">{esc(c["enfoque"])}</span> '
            f'<span><strong>{esc(c["tomo"])} · {esc(c["ruta"])}</strong></span> '
            f'<span class="meta-sep">·</span> <span>{sig_html}</span>'
            f'</div>'
        )

        migas = (
            f'<nav class="migas" aria-label="Ubicación">'
            f'<a href="../00_EMPEZAR_AQUI.html">Inicio</a><span aria-hidden="true">›</span>'
            f'<a href="index.html">Curso</a><span aria-hidden="true">›</span>'
            f'<a href="../{tomo_meta_map[c["tomo"]]["slug_html"]}">{esc(c["tomo"])}</a><span aria-hidden="true">›</span>'
            f'<span>Cap. {cid}</span></nav>'
        )

        pager_left = f'<a href="{prev_c["archivo"]}">← {prev_c["id"]} {esc(prev_c["titulo"])}</a>' if prev_c else '<a href="index.html">← Mapa del curso</a>'
        pager_right = f'<a href="{next_c["archivo"]}">{next_c["id"]} {esc(next_c["titulo"])} →</a>' if next_c else '<a href="../preguntas_y_respuestas.html">Repaso integral →</a>'
        pager = f'<nav class="pager" aria-label="Navegación entre capítulos"><div>{pager_left}</div><div>{pager_right}</div></nav>'

        full_body = f'{migas}\n<h1 id="cap-{cid.replace(".", "-")}">Capítulo {cid} · {esc(c["titulo"])}</h1>\n{meta_bar}\n{body_inner}\n{mapped_html}\n{pager}'
        html_out = page_shell(f"Cap. {cid} · {c['titulo']}", c["puerta_salida"], full_body, depth=1)

        with open(os.path.join(GUIA_DIR, c["archivo"]), "w", encoding="utf-8") as f:
            f.write(html_out)

        qa_items = extraer_preguntas(md_text)
        all_qa.append((c, qa_items))
        plain = strip_html(body_inner)
        rendered_chapters[cid] = {
            "meta": c,
            "body_html": body_inner,
            "meta_bar": meta_bar,
            "mapped_count": len(mapped),
            "qa_count": len(qa_items),
            "words": len(plain.split()),
        }
        search_docs.append({
            "t": f"Cap. {cid} · {c['titulo']}",
            "u": f"guia/{c['archivo']}",
            "k": f"{c['tomo']} · {c['enfoque']}",
            "b": plain[:6000],
        })

    # 2. Build guia/index.html (Mapa completo del curso)
    mapa_sections = []
    for tm in TOMOS_META:
        tcaps = [c for c in caps if c["tomo"] == tm["key"]]
        rows = []
        for c in tcaps:
            info = rendered_chapters[c["id"]]
            rows.append(
                f'<tr><td><strong>{c["id"]}</strong></td>'
                f'<td><a href="{c["archivo"]}">{esc(c["titulo"])}</a></td>'
                f'<td><span class="nivel-badge {enfoque_badge_css(c["enfoque"])}">{esc(c["enfoque"])}</span></td>'
                f'<td>{esc(c["horas"])}</td>'
                f'<td>{info["mapped_count"]}</td>'
                f'<td>{esc(c["puerta_salida"])}</td></tr>'
            )
        mapa_sections.append(f"""
<h2 id="tomo-{tm['num']}">{esc(tm['titulo'])}</h2>
<p><span class="nivel-badge {tm['nivel_css']}">{esc(tm['nivel_txt'])}</span> · <strong>{esc(tm['horas'])}</strong> · <a href="../{tm['slug_html']}">Ver portada del tomo</a> · <a href="../{tm['pdf']}">PDF A4</a></p>
<p>{esc(tm['resumen'])}</p>
<div class="tabla"><table>
<thead><tr><th>Cap.</th><th>Título</th><th>Enfoque</th><th>Horas</th><th>Mód. ref.</th><th>Puerta de salida</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table></div>""")

    guia_index_body = (
        '<nav class="migas"><a href="../00_EMPEZAR_AQUI.html">Inicio</a><span>›</span><span>Mapa del curso</span></nav>'
        f'<h1 id="siete-rutas-de-estudio">Mapa completo de la biblioteca ({len(TOMOS_META)} Tomos · {len(caps)} capítulos)</h1>'
        f'<p>La biblioteca se recorre en progresión ordenada de <strong>Ruta 1 a Ruta {len(TOMOS_META)}</strong>. Cada capítulo combina teoría desde cero, comandos verificables, práctica en laboratorio local, perspectiva defensiva y 5 preguntas de autoevaluación.</p>'
        '<div class="ruta-mapa"><p class="callout-titulo">Progresión recomendada sin saltos bruscos</p><ol>'
        '<li><strong>Ruta 1 · Principiante (Tomo I, 1.1–1.9):</strong> Laboratorio, TCP/IP, Linux, Windows, Bash/PowerShell, Python, protocolos, HTTP y Criptografía/TLS/PKI.</li>'
        '<li><strong>Ruta 2 · Intermedio (Tomo II, 2.1–2.8):</strong> Nmap, fuzzing web, SQLi/NoSQLi/CMDi, XSS/CSRF/CORS, JWT/OAuth/IDOR, SSRF/XXE/SSTI, APIs/GraphQL y reportes.</li>'
        '<li><strong>Ruta 3 · Avanzado (Tomo III, 3.1–3.8):</strong> Shells/transferencias, contraseñas/NIST, PrivEsc + hardening Linux/Windows, pivoting y Active Directory integral.</li>'
        '<li><strong>Ruta 4 · Especialista Blue Team / SOC (Tomo IV, 4.1–4.8):</strong> Operaciones SOC, Sysmon/auditd, SIEM (SPL/KQL), NSM (Wireshark/Zeek/Suricata), Sigma/YARA, Hunting/CTI, DFIR y triage estático.</li>'
        '<li><strong>Ruta 5 · Cloud y DevSecOps (Tomo V, 5.1–5.7):</strong> Multi-Cloud IAM/Entra ID, Storage/VPC/IMDSv2, Docker escapes, Kubernetes RBAC/PSS, CI/CD e IaC, CloudTrail/GuardDuty/WAF y Forense Cloud.</li>'
        '<li><strong>Ruta 6 · Ingeniería Ofensiva y OPSEC (Tomo VI, 6.1–6.7):</strong> Race Conditions HTTP/2, Cache Poisoning, OAuth/Lógica de Negocio, Threat Modeling (STRIDE/PASTA), White-Box Code Review, OPSEC/LOLBAS, AV/EDR e Ingeniería Social.</li>'
        '<li><strong>Ruta 7 · Mobile, Wireless, OT y GRC (Tomo VII, 7.1–7.7):</strong> Mobile Android/iOS (MASTG/Frida/Forense), Wi-Fi WEP/WPA2/WPA3/802.1X/WIDS, Física/Hardware/IoT, OT/ICS/SCADA (Purdue) y GRC/ISO 27001/NIST CSF/GDPR.</li>'
        '</ol></div>'
        + "\n".join(mapa_sections)
    )
    with open(os.path.join(GUIA_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(page_shell("Mapa del curso", f"Índice completo de los {len(TOMOS_META)} Tomos y {len(caps)} capítulos.", guia_index_body, depth=1))

    # 3. Build individual Tomo hub pages (tomo1.html .. tomo4.html)
    for tm in TOMOS_META:
        tcaps = [c for c in caps if c["tomo"] == tm["key"]]
        cards = []
        for c in tcaps:
            info = rendered_chapters[c["id"]]
            cards.append(
                f'<div class="tarjeta"><div class="num">Capítulo {c["id"]} · {esc(c["horas"])}</div>'
                f'<h3><a href="guia/{c["archivo"]}">{esc(c["titulo"])}</a></h3>'
                f'<p>{esc(c["puerta_salida"])}</p>'
                f'<p class="meta">Enfoque: {esc(c["enfoque"])} · {info["mapped_count"]} mód. catálogo · ~{info["words"]:,} palabras</p></div>'
            )
        tbody = f"""
<nav class="migas"><a href="00_EMPEZAR_AQUI.html">Inicio</a><span>›</span><a href="guia/index.html">Curso</a><span>›</span><span>{esc(tm['key'])}</span></nav>
<h1>{esc(tm['titulo'])}</h1>
<div class="meta-nivel"><span class="nivel-badge {tm['nivel_css']}">{esc(tm['nivel_txt'])}</span> <span><strong>{esc(tm['subtitulo'])}</strong></span> <span class="meta-sep">·</span> <span>PDF listo para imprimir: <a href="{tm['pdf']}">{tm['pdf']}</a></span></div>
<p>{esc(tm['resumen'])}</p>
<div class="grid">{"".join(cards)}</div>
<p><a href="guia/{tcaps[0]['archivo']}"><strong>Empezar el {esc(tm['key'])} por el Capítulo {tcaps[0]['id']} →</strong></a></p>
"""
        with open(os.path.join(REPO_ROOT, tm["slug_html"]), "w", encoding="utf-8") as f:
            f.write(page_shell(tm["titulo"], tm["resumen"], tbody, depth=0))

    # 4. Build 00_EMPEZAR_AQUI.html (Portada Maestra)
    total_words = sum(v["words"] for v in rendered_chapters.values())
    total_qa = sum(v["qa_count"] for v in rendered_chapters.values())
    en_alcance = sum(1 for m in mods if m["alcance"] == "En alcance")
    fuera_cloud = sum(1 for m in mods if "Cloud" in m["alcance"])
    fuera_wifi = sum(1 for m in mods if "Wi-Fi" in m["alcance"])
    fuera_android = sum(1 for m in mods if "Android" in m["alcance"])
    puente_cls = sum(1 for m in mods if "CLS_Guia" in m["alcance"])
    anexo_ia = sum(1 for m in mods if "Complementario" in m["alcance"])

    tomos_rows = []
    for tm in TOMOS_META:
        tcaps = [c for c in caps if c["tomo"] == tm["key"]]
        mcount = sum(rendered_chapters[c["id"]]["mapped_count"] for c in tcaps)
        tomos_rows.append(
            f'<tr><td><strong><a href="{tm["slug_html"]}">{esc(tm["key"])}</a></strong> ({len(tcaps)} caps.)</td>'
            f'<td>{esc(tm["titulo"].split("·", 1)[1].strip())}</td>'
            f'<td><span class="nivel-badge {tm["nivel_css"]}">{esc(tm["nivel_txt"])}</span></td>'
            f'<td>{esc(tm["horas"])}</td>'
            f'<td>{mcount} mód.</td>'
            f'<td><a href="{tm["pdf"]}">PDF A4</a></td></tr>'
        )

    portada_body = f"""
<h1 id="portada">Cómo estudiar este curso de Hacking Ético Español</h1>
<p>Esta obra reúne un recorrido completo, progresivo y <strong>100 % original</strong> en español que integra <strong>seguridad ofensiva y defensiva</strong>: fundamentos de sistemas, redes y criptografía, pentesting general, seguridad web y APIs, infraestructura y Active Directory, operaciones SOC, SIEM, DFIR e ingeniería de detección.</p>
<p>No es una colección de apuntes sueltos: cada uno de los <strong>{len(caps)} capítulos</strong> explica el mecanismo técnico desde cero, muestra comandos y salidas verificables, incluye la <strong>perspectiva defensiva y de mitigación</strong>, propone una práctica en laboratorio local aislado y cierra con 5 preguntas razonadas de autoevaluación ({total_qa} preguntas en total, ~{total_words:,} palabras técnicas originales).</p>

<div class="stats-grid">
  <div class="stat-box"><div class="big">{len(TOMOS_META)} Tomos</div><div class="lbl">{len(caps)} capítulos progresivos</div></div>
  <div class="stat-box"><div class="big">358</div><div class="lbl">Módulos públicos clasificados</div></div>
  <div class="stat-box"><div class="big">{en_alcance}</div><div class="lbl">Módulos mapeados (I–VII)</div></div>
  <div class="stat-box"><div class="big">25</div><div class="lbl">Paths oficiales relevados</div></div>
  <div class="stat-box"><div class="big">{total_qa}</div><div class="lbl">Preguntas con respuesta</div></div>
</div>

<aside class="callout nota">
<p class="callout-titulo">Empezá por acá</p>
<ol>
  <li>Leé esta portada y las reglas de seguridad (5 minutos).</li>
  <li>Explorá el <a href="guia/index.html">Mapa del curso</a> o el <a href="catalogo_completo.html">Catálogo interactivo de 358 módulos</a>.</li>
  <li>Armá tu laboratorio aislado siguiendo el <a href="guia/01-laboratorio-y-etica.html">Capítulo 1.1</a> y el <a href="laboratorios.html">Kit de Laboratorios</a>.</li>
  <li>Avanzá un capítulo por vez y anotá tu progreso en <a href="seguimiento.csv"><code>seguimiento.csv</code></a>.</li>
</ol>
</aside>

<h2 id="estructura-siete-tomos">Estructura de la Hiper Biblioteca: {len(TOMOS_META)} Tomos · {len(TOMOS_META)} Rutas Progresivas</h2>
<div class="tabla"><table>
<thead><tr><th>Tomo</th><th>Foco principal</th><th>Nivel</th><th>Horas est.</th><th>Catálogo ref.</th><th>PDF</th></tr></thead>
<tbody>{"".join(tomos_rows)}</tbody>
</table></div>

<aside class="callout aviso">
<p class="callout-titulo">Cobertura integral de la Edición 2.0 (358 / 358 módulos) y Puente con Curso de Reversing</p>
<p>Esta Hiper Biblioteca integra en <strong>{len(TOMOS_META)} Tomos ({len(caps)} capítulos)</strong> el espectro completo de la ciberseguridad moderna: Fundamentos, Pentesting Web/APIs, Infraestructura/AD, Blue Team/SOC/DFIR, Multi-Cloud/Docker/K8s/DevSecOps, Web Avanzado (PortSwigger/WSTG), Threat Modeling, White-Box Code Review, Red Team/OPSEC, Mobile (OWASP MASTG), Wi-Fi/802.1X/WPA3, Hardware/IoT/OT-SCADA y GRC/Legal ({en_alcance} módulos del catálogo público integrados directamente). Adicionalmente, incluye {anexo_ia} módulos complementarios de IA/LLM en el catálogo y enlaza los {puente_cls} módulos de ensamblador, depuración y reversing de binarios hacia nuestra obra hermana <a href="../CLS_Guia/00_EMPEZAR_AQUI.html"><strong>Curso de Reversing en Windows</strong></a>.</p>
</aside>

<h2 id="que-hay-en-el-paquete">Qué incluye este paquete (100 % offline)</h2>
<div class="tabla"><table>
<thead><tr><th>Archivo / Recurso</th><th>Para qué sirve</th></tr></thead>
<tbody>
<tr><td><a href="guia/index.html"><code>guia/</code></a></td><td>Los {len(caps)} capítulos completos en HTML navegable con trazabilidad curricular.</td></tr>
<tr><td><a href="catalogo_completo.html"><code>catalogo_completo.html</code></a></td><td>Explorador filtrable offline de los 358 módulos (con sus descripciones, prerrequisitos y 4,068 secciones) y 25 rutas públicas + <a href="datos/catalogo_htb_publico.csv">CSV</a>.</td></tr>
<tr><td><a href="laboratorios.html"><code>laboratorios/</code></a></td><td>Entorno Docker local (<code>127.0.0.1</code>), app educativa Flask/SQLite, auditor White-Box AST, manifests endurecidos Docker/K8s/Terraform, logs simulados, muestras DFIR/YARA/Suricata y plantillas RoE/STRIDE/Pentest/IR.</td></tr>
<tr><td><a href="hojas-referencia-rapida.html"><code>hojas-referencia-rapida.html</code></a></td><td>Cheat Sheets de escritorio (Redes/Nmap, Linux/Windows, OWASP, AD, SOC/Sysmon/SPL/KQL/Sigma, Cripto, Cloud/K8s, Web Avanzado/OPSEC y Mobile/Wi-Fi/OT/GRC).</td></tr>
<tr><td><a href="glosario.html"><code>glosario.html</code></a></td><td>Glosario técnico alfabético con {len(GLOSARIO_ITEMS)} conceptos clave.</td></tr>
<tr><td><a href="preguntas_y_respuestas.html"><code>preguntas_y_respuestas.html</code></a></td><td>Banco consolidado de repaso con {total_qa} preguntas y respuestas razonadas.</td></tr>
<tr><td><a href="buscar.html"><code>buscar.html</code></a></td><td>Buscador instantáneo offline sobre todo el contenido del curso.</td></tr>
<tr><td><a href="orden_impresion.html"><code>orden_impresion.html</code></a></td><td>Especificación de imprenta y acceso directo a los {len(TOMOS_META) + 2} PDFs A4 (Tomos I–VII + Separata + Maestro único con paridad par estricta).</td></tr>
<tr><td><a href="seguimiento.csv"><code>seguimiento.csv</code></a></td><td>Planilla de avance capítulo por capítulo lista para Excel o LibreOffice Calc.</td></tr>
<tr><td><a href="../CLS_Guia/00_EMPEZAR_AQUI.html"><code>../CLS_Guia/</code></a></td><td>Obra hermana complementaria especializada en Reversing de binarios Windows, Assembly, WinDbg, Windows Internals y Kernel.</td></tr>
</tbody></table></div>

<h2 id="seguridad-y-legalidad">Seguridad, ética y marco legal</h2>
<aside class="callout peligro">
<p class="callout-titulo">Leé esto antes de ejecutar cualquier comando</p>
<ul>
  <li>Todo el contenido tiene fines estrictamente <strong>educativos, defensivos y de auditoría autorizada</strong>.</li>
  <li>Nunca escanees, pruebes inyecciones ni audites credenciales contra redes, aplicaciones, entornos cloud o puntos inalámbricos que no sean de tu propiedad o sobre los que no cuentes con autorización escrita explícita.</li>
  <li>Ejecutá las prácticas exclusivamente en tus propias máquinas virtuales aisladas, emuladores locales o en contenedores ligados a <code>127.0.0.1</code>.</li>
</ul>
</aside>
"""
    with open(os.path.join(REPO_ROOT, "00_EMPEZAR_AQUI.html"), "w", encoding="utf-8") as f:
        f.write(page_shell("Portada", f"Hiper Biblioteca completa de Hacking Ético Español ({len(TOMOS_META)} Tomos, {len(caps)} capítulos).", portada_body, depth=0))

    # 5. Build catalogo_completo.html (Interactive offline explorer for 358 modules + 25 paths)
    cap_file_map = {c["id"]: c["archivo"] for c in caps}
    cap_title_map = {c["id"]: c["titulo"] for c in caps}
    mods_compact = []
    for m in mods:
        cid = m.get("capitulo_asignado", "—")
        mods_compact.append({
            "id": m["id_orden"],
            "t": m["title"],
            "d": m.get("difficulty", ""),
            "c": m.get("category", ""),
            "s": m.get("sections_count", ""),
            "dom": m.get("dominio", ""),
            "alc": m.get("alcance", ""),
            "tom": m.get("tomo_asignado", ""),
            "cap": cid,
            "href": f"guia/{cap_file_map[cid]}" if cid in cap_file_map else "",
            "cap_t": cap_title_map.get(cid, ""),
            "p": m.get("paths", []),
            "sum": m.get("summary", ""),
            "pre": m.get("prerrequisitos", []),
            "sec": m.get("secciones", []),
        })

    paths_html_blocks = []
    for p in sorted(paths, key=lambda x: (0 if x.get("type") == "Job Role" else 1, x.get("title", ""))):
        pmods = p.get("modules", [])
        li = "".join(f'<li>{esc(pm.get("title", ""))}</li>' for pm in pmods)
        paths_html_blocks.append(
            f'<details class="qa"><summary><strong>{esc(p.get("title",""))}</strong> '
            f'<span class="meta">({esc(p.get("type",""))} · {len(pmods)} módulos · {esc(p.get("difficulty",""))})</span></summary>'
            f'<div class="respuesta"><p>{esc(p.get("summary",""))}</p><ol>{li}</ol></div></details>'
        )

    cat_body = f"""
<nav class="migas"><a href="00_EMPEZAR_AQUI.html">Inicio</a><span>›</span><span>Catálogo de 358 módulos y 25 paths</span></nav>
<h1>Catálogo público clasificado (358 módulos y 25 rutas de estudio)</h1>
<p>Este tablero offline consolida la taxonomía pública completa utilizada para estructurar el curso. Cada módulo en alcance enlaza directamente al capítulo original de nuestra obra que desarrolla sus fundamentos técnicos. También podés abrir la tabla en Excel desde <a href="datos/catalogo_htb_publico.csv"><code>datos/catalogo_htb_publico.csv</code></a>.</p>

<div class="stats-grid">
  <div class="stat-box"><div class="big">{en_alcance}</div><div class="lbl">En alcance (Tomos I–VII)</div></div>
  <div class="stat-box"><div class="big">{puente_cls}</div><div class="lbl">Puente con Curso de Reversing</div></div>
  <div class="stat-box"><div class="big">{anexo_ia}</div><div class="lbl">Complementario: IA</div></div>
  <div class="stat-box"><div class="big">{len(caps)}</div><div class="lbl">Capítulos en {len(TOMOS_META)} Tomos</div></div>
</div>

<h2 id="explorador-modulos">Explorador filtrable de los 358 módulos</h2>
<div class="filtros-bar">
  <input id="f-q" type="search" placeholder="Filtrar por título, descripción, sección, dominio o path (ej. Kerberos, CloudTrail, Frida, WPA3, XSS)...">
  <select id="f-alc">
    <option value="">Todos los alcances (358)</option>
    <option value="En alcance">En alcance ({en_alcance})</option>
    <option value="Puente con CLS_Guia">Puente con Curso de Reversing ({puente_cls})</option>
    <option value="Complementario (Anexo)">Complementario: IA ({anexo_ia})</option>
  </select>
  <select id="f-tom">
    <option value="">Todos los tomos</option>
    <option value="Tomo I">Tomo I · Fundamentos</option>
    <option value="Tomo II">Tomo II · Pentest &amp; Web</option>
    <option value="Tomo III">Tomo III · Infra &amp; AD</option>
    <option value="Tomo IV">Tomo IV · Blue/SOC/DFIR</option>
    <option value="Tomo V">Tomo V · Cloud &amp; DevSecOps</option>
    <option value="Tomo VII">Tomo VII · Mobile &amp; Wi-Fi</option>
    <option value="Puente · CLS_Guia">Puente · Curso de Reversing</option>
    <option value="Anexo · Catálogo">Anexo · IA</option>
  </select>
  <select id="f-dif">
    <option value="">Todas las dificultades</option>
    <option value="Fundamental">Fundamental</option>
    <option value="Easy">Easy</option>
    <option value="Medium">Medium</option>
    <option value="Hard">Hard</option>
  </select>
  <select id="f-cat">
    <option value="">Todas las categorías</option>
    <option value="General">General</option>
    <option value="Offensive">Offensive</option>
    <option value="Defensive">Defensive</option>
    <option value="Purple">Purple</option>
  </select>
</div>
<p class="meta" id="f-count">Mostrando 358 de 358 módulos.</p>
<div class="tabla"><table>
<thead><tr><th>#</th><th>Módulo</th><th>Dificultad</th><th>Categoría</th><th>Dominio</th><th>Alcance</th><th>Destino en la suite</th></tr></thead>
<tbody id="cat-tbody"></tbody>
</table></div>

<h2 id="paths-oficiales">Rutas de estudio públicas relevadas (9 Job Role Paths + 16 Skill Paths)</h2>
<p>Hacé clic en cualquier ruta para desplegar el orden completo de módulos de referencia que la integran:</p>
{"".join(paths_html_blocks)}
"""
    cat_script = f"""<script>
const MODS = {json.dumps(mods_compact, ensure_ascii=False)};
const tbody = document.getElementById('cat-tbody');
const qEl = document.getElementById('f-q');
const alcEl = document.getElementById('f-alc');
const tomEl = document.getElementById('f-tom');
const difEl = document.getElementById('f-dif');
const catEl = document.getElementById('f-cat');
const cntEl = document.getElementById('f-count');

function escHtml(s){{ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }}
function badgeAlc(a){{
  if(a==='En alcance') return '<span class="pill ok">En alcance</span>';
  if(a==='Puente con CLS_Guia') return '<span class="pill pend">Puente Curso de Reversing</span>';
  if(a.indexOf('Fuera')===0) return '<span class="pill no">'+escHtml(a)+'</span>';
  return '<span class="pill pend">'+escHtml(a)+'</span>';
}}
function render(){{
  const q = qEl.value.trim().toLowerCase();
  const alc = alcEl.value, tom = tomEl.value, dif = difEl.value, cat = catEl.value;
  const rows = [];
  let shown = 0;
  for(const m of MODS){{
    if(alc && m.alc !== alc) continue;
    if(tom && m.tom !== tom) continue;
    if(dif && m.d !== dif) continue;
    if(cat && m.c !== cat) continue;
    if(q){{
      const hay = (m.t+' '+m.dom+' '+m.tom+' '+m.cap+' '+m.p.join(' ')+' '+(m.sum||'')+' '+(m.sec||[]).join(' ')).toLowerCase();
      if(!hay.includes(q)) continue;
    }}
    shown++;
    let capLink = '<span class="meta">—</span>';
    if(m.href) capLink = '<a href="'+m.href+'"><strong>'+escHtml(m.tom)+' · Cap. '+escHtml(m.cap)+'</strong></a>';
    else if(m.alc==='Puente con CLS_Guia') capLink = '<a href="../CLS_Guia/00_EMPEZAR_AQUI.html"><strong>Ver Curso de Reversing (Reversing)</strong></a>';
    let det = '';
    if(m.sum || (m.sec && m.sec.length) || (m.pre && m.pre.length)){{
      let inner = '';
      if(m.sum) inner += '<p style="margin:6px 0 4px;">'+escHtml(m.sum)+'</p>';
      if(m.pre && m.pre.length) inner += '<div class="meta" style="margin:4px 0;"><strong>Prerrequisitos:</strong> '+m.pre.map(escHtml).join(', ')+'</div>';
      if(m.sec && m.sec.length){{
        inner += '<div class="meta" style="margin-top:4px;"><strong>Secciones del temario ('+m.sec.length+'):</strong></div><ol style="margin:4px 0 6px 18px;padding:0;">'+m.sec.map(s=>'<li>'+escHtml(s)+'</li>').join('')+'</ol>';
      }}
      const lbl = (m.sec && m.sec.length) ? 'Ver descripción y '+m.sec.length+' temas' : 'Ver descripción';
      det = '<details style="margin-top:4px;"><summary class="meta" style="cursor:pointer;">'+lbl+'</summary><div style="font-size:12px;line-height:1.45;">'+inner+'</div></details>';
    }}
    rows.push('<tr><td>'+m.id+'</td><td><strong>'+escHtml(m.t)+'</strong>'+(m.p.length?'<div class="meta">Paths: '+escHtml(m.p.slice(0,3).join(', '))+(m.p.length>3?'…':'')+'</div>':'')+det+'</td><td>'+escHtml(m.d)+'</td><td>'+escHtml(m.c)+'</td><td>'+escHtml(m.dom)+'</td><td>'+badgeAlc(m.alc)+'</td><td>'+capLink+'</td></tr>');
  }}
  tbody.innerHTML = rows.join('');
  cntEl.textContent = 'Mostrando '+shown+' de '+MODS.length+' módulos.';
}}
[qEl, alcEl, tomEl, difEl, catEl].forEach(el => el.addEventListener('input', render));
[alcEl, tomEl, difEl, catEl].forEach(el => el.addEventListener('change', render));
render();
</script>"""
    with open(os.path.join(REPO_ROOT, "catalogo_completo.html"), "w", encoding="utf-8") as f:
        f.write(page_shell("Catálogo 358 módulos", "Catálogo público completo de 358 módulos y 25 rutas de estudio clasificados.", cat_body, depth=0, extra_script=cat_script))

    # 6. Build laboratorios.html, hojas-referencia-rapida.html, glosario.html, fuentes_y_limites.html
    with open(os.path.join(REPO_ROOT, "laboratorios.html"), "w", encoding="utf-8") as f:
        f.write(page_shell("Kit de Laboratorios", "Entorno local aislado en Docker, scripts defensivos y plantillas.", LABORATORIOS_HTML, depth=0))

    with open(os.path.join(REPO_ROOT, "hojas-referencia-rapida.html"), "w", encoding="utf-8") as f:
        f.write(page_shell("Hojas de referencia rápida", "Cheat Sheets de Redes, Linux, Windows, Web, AD y SOC.", CHEAT_SHEETS_HTML, depth=0))
    search_docs.append({"t": "Hojas de referencia rápida (Cheat Sheets)", "u": "hojas-referencia-rapida.html", "k": "Apoyo", "b": strip_html(CHEAT_SHEETS_HTML)})

    glos_rows = "".join(f'<tr><td><strong>{esc(k)}</strong></td><td>{esc(v)}</td></tr>' for k, v in sorted(GLOSARIO_ITEMS, key=lambda x: x[0].lower()))
    glos_body = f"""
<nav class="migas"><a href="00_EMPEZAR_AQUI.html">Inicio</a><span>›</span><span>Glosario</span></nav>
<h1 id="glosario">Glosario técnico ({len(GLOSARIO_ITEMS)} términos esenciales)</h1>
<p>Definiciones claras y directas de los conceptos fundamentales de redes, pentesting, web avanzada, Code Review, Active Directory, SOC/DFIR, Cloud/Kubernetes, Mobile, Wi-Fi, OT/ICS y GRC usados a lo largo de los {len(TOMOS_META)} tomos.</p>
<div class="tabla"><table>
<thead><tr><th style="width:24%">Término</th><th>Definición técnica</th></tr></thead>
<tbody>{glos_rows}</tbody>
</table></div>
"""
    with open(os.path.join(REPO_ROOT, "glosario.html"), "w", encoding="utf-8") as f:
        f.write(page_shell("Glosario técnico", "Definiciones técnicas de ciberseguridad ofensiva y defensiva.", glos_body, depth=0))
    search_docs.append({"t": "Glosario técnico", "u": "glosario.html", "k": "Apoyo", "b": " ".join(f"{k}: {v}" for k, v in GLOSARIO_ITEMS)})

    with open(os.path.join(REPO_ROOT, "fuentes_y_limites.html"), "w", encoding="utf-8") as f:
        f.write(page_shell("Fuentes y límites", "Estándares abiertos, transparencia curricular y marco ético.", FUENTES_LIMITES_HTML, depth=0))

    # 7. Build preguntas_y_respuestas.html (Aggregated Q&A from all 32 chapters)
    qa_sections = []
    for tm in TOMOS_META:
        qa_sections.append(f'<h2 id="qa-tomo-{tm["num"]}">{esc(tm["titulo"])}</h2>')
        for c, items in all_qa:
            if c["tomo"] != tm["key"]:
                continue
            qa_sections.append(f'<h3><a href="guia/{c["archivo"]}">Capítulo {c["id"]} · {esc(c["titulo"])}</a></h3>')
            for preg, resp in items:
                qa_sections.append(
                    f'<details class="qa"><summary>{inline(preg)}</summary>'
                    f'<div class="respuesta"><p>{inline(resp)}</p></div></details>'
                )
    qa_body = f"""
<nav class="migas"><a href="00_EMPEZAR_AQUI.html">Inicio</a><span>›</span><span>Banco de repaso</span></nav>
<h1 id="repaso">Banco integral de repaso ({total_qa} preguntas con respuesta)</h1>
<p>Intentá responder cada pregunta en voz alta o por escrito antes de desplegar la respuesta razonada. Si fallás dos o más preguntas de un capítulo, volvé a repasar su práctica de laboratorio.</p>
{"".join(qa_sections)}
"""
    with open(os.path.join(REPO_ROOT, "preguntas_y_respuestas.html"), "w", encoding="utf-8") as f:
        f.write(page_shell("Banco de repaso", f"{total_qa} preguntas con respuestas razonadas de los {len(TOMOS_META)} Tomos.", qa_body, depth=0))

    # 8. Build buscar.html (100% offline full-text search)
    buscar_body = f"""
<nav class="migas"><a href="00_EMPEZAR_AQUI.html">Inicio</a><span>›</span><span>Buscar</span></nav>
<h1>Buscador offline del curso</h1>
<p>Buscá cualquier comando, vulnerabilidad, Event ID, concepto o herramienta en los {len(caps)} capítulos, las hojas de referencia y el glosario sin necesidad de conexión a internet.</p>
<div class="filtros-bar">
  <input id="q-search" type="search" placeholder="Escribí una palabra o comando (ej. Kerberoasting, Sysmon, Race Condition, STRIDE, Kubernetes, Frida, GDPR)..." autofocus>
</div>
<p class="meta" id="q-stats">Escribí al menos 2 caracteres para buscar.</p>
<div id="q-results"></div>
"""
    buscar_script = f"""<script>
const DOCS = {json.dumps(search_docs, ensure_ascii=False)};
const inp = document.getElementById('q-search');
const st = document.getElementById('q-stats');
const res = document.getElementById('q-results');
function escH(s){{ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }}
function norm(s){{ return s.toLowerCase().normalize('NFD').replace(/[\\u0300-\\u036f]/g,''); }}
function run(){{
  const raw = inp.value.trim();
  if(raw.length < 2){{ st.textContent='Escribí al menos 2 caracteres para buscar.'; res.innerHTML=''; return; }}
  const terms = norm(raw).split(/\\s+/).filter(Boolean);
  const hits = [];
  for(const d of DOCS){{
    const hay = norm(d.t + ' ' + d.b);
    let score = 0, ok = true;
    for(const term of terms){{
      const idx = hay.indexOf(term);
      if(idx === -1){{ ok = false; break; }}
      score += (norm(d.t).includes(term) ? 10 : 1);
    }}
    if(ok){{
      const pos = hay.indexOf(terms[0]);
      const start = Math.max(0, pos - 90);
      const snip = d.b.slice(start, start + 240);
      hits.push({{d, score, snip}});
    }}
  }}
  hits.sort((a,b)=>b.score-a.score);
  st.textContent = hits.length + ' resultado(s) para "' + raw + '".';
  res.innerHTML = hits.map(h => '<div class="tarjeta" style="margin:.7rem 0"><div class="num">'+escH(h.d.k)+'</div><h3><a href="'+h.d.u+'">'+escH(h.d.t)+'</a></h3><p>…'+escH(h.snip)+'…</p></div>').join('');
}}
inp.addEventListener('input', run);
</script>"""
    with open(os.path.join(REPO_ROOT, "buscar.html"), "w", encoding="utf-8") as f:
        f.write(page_shell("Buscar", "Buscador offline instantáneo sobre todo el curso.", buscar_body, depth=0, extra_script=buscar_script))

    print(f"[HTML] {len(caps)} capítulos + 12 páginas de soporte generados (~{total_words:,} palabras, {total_qa} preguntas).")
    return rendered_chapters


# -----------------------------------------------------------------------------
# Compilación de PDFs A4 (Chrome Headless + pypdf + Paridad Par + Marcadores)
# -----------------------------------------------------------------------------

PRINT_CSS_EXTRA = """
@page {
  size: A4;
  margin: 18mm 16mm 19mm 16mm;
  @top-left { content: none; }
  @top-center { content: none; }
  @top-right { content: none; }
  @bottom-left { content: none; }
  @bottom-right { content: none; }
  @bottom-center {
    content: counter(page);
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 9pt;
    color: #333;
  }
}
@page :first {
  @bottom-center { content: none; }
}
body {
  background: #ffffff !important;
  color: #111111 !important;
  font-size: 10.2pt !important;
  line-height: 1.48 !important;
}
main { max-width: none !important; padding: 0 !important; margin: 0 !important; }
.portada-pdf {
  page-break-after: always;
  min-height: 245mm;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  border: 2px solid #0b5f6b;
  border-radius: 10px;
  padding: 22mm 16mm;
}
.portada-pdf .kicker { font-size: 10pt; font-weight: 700; letter-spacing: 1.2px; text-transform: uppercase; color: #0b5f6b; }
.portada-pdf h1 { font-size: 26pt; margin: 8mm 0 4mm; color: #111111; line-height: 1.15; }
.portada-pdf .sub { font-size: 12pt; color: #333333; margin-bottom: 10mm; }
.portada-pdf .caja-meta { background: #f4f7f8; border-left: 5px solid #0b5f6b; padding: 6mm 7mm; border-radius: 6px; font-size: 10pt; }
.portada-pdf .pie-portada { border-top: 1px solid #cccccc; padding-top: 4mm; font-size: 9pt; color: #444444; }
.toc-pdf { page-break-after: always; }
.toc-pdf h1 { font-size: 18pt; margin-bottom: 6mm; border-bottom: 2px solid #0b5f6b; padding-bottom: 2mm; }
.toc-lista { list-style: none; padding: 0; margin: 0; }
.toc-lista li { display: flex; justify-content: space-between; align-items: baseline; gap: 6mm; padding: 2.2mm 0; border-bottom: 1px dotted #c8c8c8; font-size: 10pt; }
.toc-lista li .toc-pag { font-family: "Cascadia Mono", Consolas, monospace; font-size: 9pt; color: #0b5f6b; white-space: nowrap; font-weight: 700; }
.print-sec { page-break-before: always; }
.print-sec h1 { font-size: 17pt; margin-top: 0; border-bottom: 2px solid #0b5f6b; padding-bottom: 2mm; }
.print-sec h2 { font-size: 12.5pt; margin-top: 1.3rem; break-after: avoid; }
.print-sec h3 { font-size: 10.8pt; margin-top: 1rem; break-after: avoid; }
pre {
  background: #f6f8fa !important;
  color: #111111 !important;
  -webkit-text-fill-color: #111111 !important;
  border: 1px solid #cfd7df !important;
  font-size: 8.2pt !important;
  line-height: 1.38 !important;
  padding: 7px 9px !important;
  white-space: pre-wrap !important;
  word-break: break-word !important;
  page-break-inside: avoid;
}
code { background: #eef1f4 !important; color: #111111 !important; -webkit-text-fill-color: #111111 !important; font-size: 8.6pt !important; }
pre code { background: transparent !important; }
table { font-size: 8.6pt !important; width: 100%; table-layout: auto; }
th, td { padding: 4px 6px !important; word-wrap: break-word; overflow-wrap: anywhere; }
.callout, .meta-nivel, .tarjeta { break-inside: avoid; page-break-inside: avoid; }
a { color: #0b5f6b !important; text-decoration: none !important; }
"""


def render_chrome_pdf(html_path, pdf_path):
    prof_dir = os.path.join(BUILD_TMP, "chrome-prof")
    os.makedirs(prof_dir, exist_ok=True)
    url = Path(html_path).resolve().as_uri()
    cmd = [
        CHROME,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-extensions",
        f"--user-data-dir={prof_dir}",
        "--no-pdf-header-footer",
        f"--print-to-pdf={pdf_path}",
        url,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if res.returncode != 0 or not os.path.exists(pdf_path):
        raise RuntimeError(f"Error Chrome PDF ({res.returncode}): {res.stderr[:500]}")


def leer_paginas_destinos(pdf_path, anchors):
    """Lee las páginas exactas (base 1) de cada ancla HTML usando named_destinations de pypdf."""
    reader = pypdf.PdfReader(pdf_path)
    total = len(reader.pages)
    dests = reader.named_destinations or {}
    paginas = {}
    for anc in anchors:
        d = dests.get(anc) or dests.get("/" + anc)
        if d is not None:
            try:
                p0 = reader.get_destination_page_number(d)
                if p0 is not None and p0 >= 0:
                    paginas[anc] = p0 + 1
            except Exception:
                pass
    return paginas, total


def compilar_volumen_pdf(nombre_slug, pdf_filename, portada_html, secciones, css_base):
    """
    secciones: lista de dicts { 'anchor': str, 'titulo': str, 'html': str }
    """
    toc_anchors = [s["anchor"] for s in secciones]
    html_tmp = os.path.join(BUILD_TMP, f"{nombre_slug}.html")
    draft_pdf = os.path.join(BUILD_TMP, f"{nombre_slug}_draft.pdf")
    final_pdf = os.path.join(REPO_ROOT, pdf_filename)

    def armar_html(etiquetas, extra_parity_html=""):
        toc_items = []
        for s in secciones:
            anc = s["anchor"]
            et = etiquetas.get(anc, "p. —")
            toc_items.append(
                f'<li><a href="#{anc}">{esc(s["titulo"])}</a><span class="toc-pag" data-anchor="{anc}">{esc(et)}</span></li>'
            )
        secs_html = "\n".join(
            f'<section class="print-sec" id="{s["anchor"]}">{s["html"]}</section>'
            for s in secciones
        )
        return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>{esc(CURSO_NOMBRE)}</title>
<style>
{css_base}
{PRINT_CSS_EXTRA}
</style>
</head>
<body>
<main>
{portada_html}
<section class="toc-pdf" id="toc-{nombre_slug}">
  <h1>Índice de Contenidos</h1>
  <ul class="toc-lista">{"".join(toc_items)}</ul>
</section>
{secs_html}
{extra_parity_html}
</main>
</body>
</html>
"""

    etiquetas = {}
    paginas = {}
    total = 0
    for intento in range(4):
        doc_html = armar_html(etiquetas)
        with open(html_tmp, "w", encoding="utf-8") as f:
            f.write(doc_html)
        render_chrome_pdf(html_tmp, draft_pdf)
        paginas, total = leer_paginas_destinos(draft_pdf, toc_anchors)
        nuevas = {}
        for i, anc in enumerate(toc_anchors):
            ini = paginas.get(anc)
            if ini is None:
                nuevas[anc] = "—"
                continue
            fin = total
            for sig in toc_anchors[i + 1 :]:
                if sig in paginas and paginas[sig] > ini:
                    fin = paginas[sig] - 1
                    break
            cant = max(1, fin - ini + 1)
            rango = str(ini) if ini == fin else f"{ini}–{fin}"
            nuevas[anc] = f"p. {rango} ({cant} {'pág.' if cant == 1 else 'págs.'})"
        if intento > 0 and nuevas == etiquetas:
            break
        etiquetas = nuevas

    # Paridad par estricta
    if total % 2 != 0:
        parity_sec = f"""
<section class="print-sec" id="notas-paridad-{nombre_slug}">
  <h1>Bitácora de Laboratorio y Notas de Estudio</h1>
  <p><em>Página de cierre editorial incorporada para garantizar paridad par exacta (múltiplo de 2 páginas) en impresión profesional a doble faz.</em></p>
  <div class="tabla"><table>
    <thead><tr><th>Fecha</th><th>Capítulo / Lab</th><th>Entorno / Snapshot / Hash SHA-256</th><th>Hallazgos y notas clave</th></tr></thead>
    <tbody>
      <tr><td style="height:28mm"></td><td></td><td></td><td></td></tr>
      <tr><td style="height:28mm"></td><td></td><td></td><td></td></tr>
      <tr><td style="height:28mm"></td><td></td><td></td><td></td></tr>
      <tr><td style="height:28mm"></td><td></td><td></td><td></td></tr>
      <tr><td style="height:28mm"></td><td></td><td></td><td></td></tr>
    </tbody>
  </table></div>
  <p style="margin-top:10mm;font-size:9pt;color:#555;text-align:center"><em>{CURSO_NOMBRE} · {EDICION_LABEL}</em></p>
</section>"""
        with open(html_tmp, "w", encoding="utf-8") as f:
            f.write(armar_html(etiquetas, parity_sec))
        render_chrome_pdf(html_tmp, draft_pdf)
        paginas, total = leer_paginas_destinos(draft_pdf, toc_anchors)

    # Inyectar marcadores con pypdf
    reader = pypdf.PdfReader(draft_pdf)
    writer = pypdf.PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.add_outline_item(title="Portada", page_number=0)
    writer.add_outline_item(title="Índice de Contenidos", page_number=1 if len(reader.pages) > 1 else 0)
    for s in secciones:
        p_idx = max(0, paginas.get(s["anchor"], 1) - 1)
        writer.add_outline_item(title=s["titulo"], page_number=p_idx)
    with open(final_pdf, "wb") as f:
        writer.write(f)

    final_pages = len(pypdf.PdfReader(final_pdf).pages)
    size_mb = os.path.getsize(final_pdf) / (1024 * 1024)
    print(f"  [PDF] {pdf_filename:44s} | {final_pages:3d} págs ({final_pages//2:3d} hojas) | {'PAR OK' if final_pages%2==0 else 'IMPAR ERR'} | {size_mb:.2f} MB")
    return {
        "archivo": pdf_filename,
        "paginas": final_pages,
        "hojas": final_pages // 2,
        "paridad": final_pages % 2 == 0,
        "size_mb": round(size_mb, 2),
        "secciones": [(s["titulo"], max(0, paginas.get(s["anchor"], 1) - 1)) for s in secciones],
    }


def compilar_todos_los_pdfs(data, rendered_chapters):
    css_base = open(os.path.join(GUIA_DIR, "estilo.css"), "r", encoding="utf-8").read()
    caps = data["capitulos_curso"]
    resultados = []

    print(f"\n[PDF] Compilando los {len(TOMOS_META)} Tomos + Separata + Obra Maestra Digital...")
    # 1..7: Tomos I a VII
    for tm in TOMOS_META:
        tcaps = [c for c in caps if c["tomo"] == tm["key"]]
        secciones = []
        for c in tcaps:
            info = rendered_chapters[c["id"]]
            sec_html = f'<h1>Capítulo {c["id"]} · {esc(c["titulo"])}</h1>\n{info["meta_bar"]}\n{info["body_html"]}'
            secciones.append({
                "anchor": f'cap-{c["id"].replace(".", "-")}',
                "titulo": f'Capítulo {c["id"]} · {c["titulo"]}',
                "html": sec_html,
            })
        portada = f"""
<div class="portada-pdf">
  <div>
    <div class="kicker">{CURSO_NOMBRE} · {EDICION_LABEL}</div>
    <h1>{esc(tm['titulo'])}</h1>
    <div class="sub">{esc(tm['subtitulo'])}</div>
    <div class="caja-meta">
      <p><strong>Nivel sugerido:</strong> {esc(tm['nivel_txt'])} · <strong>Carga horaria estimada:</strong> {esc(tm['horas'])}</p>
      <p>{esc(tm['resumen'])}</p>
      <p><strong>Capítulos incluidos:</strong> {tcaps[0]['id']} a {tcaps[-1]['id']} ({len(tcaps)} capítulos completos con teoría, laboratorios locales, perspectiva defensiva y {len(tcaps)*5} preguntas de repaso).</p>
    </div>
  </div>
  <div class="pie-portada">
    <p><strong>Marco ético:</strong> Obra técnica 100 % original con fines educativos, defensivos y de auditoría autorizada en laboratorio local propio.</p>
  </div>
</div>"""
        res = compilar_volumen_pdf(f"tomo_{tm['num']}", tm["pdf"], portada, secciones, css_base)
        res["nombre"] = tm["titulo"]
        resultados.append(res)

    # 5: Separata Cheat Sheets, Glosario y Resumen de Rutas
    glos_rows = "".join(f'<tr><td><strong>{esc(k)}</strong></td><td>{esc(v)}</td></tr>' for k, v in sorted(GLOSARIO_ITEMS, key=lambda x: x[0].lower()))
    glos_pdf_html = f'<h1>Glosario Técnico ({len(GLOSARIO_ITEMS)} términos)</h1><div class="tabla"><table><thead><tr><th style="width:26%">Término</th><th>Definición</th></tr></thead><tbody>{glos_rows}</tbody></table></div>'
    paths_rows = "".join(
        f'<tr><td><strong>{esc(p.get("title",""))}</strong></td><td>{esc(p.get("type",""))}</td><td>{esc(p.get("difficulty",""))}</td><td>{len(p.get("modules",[]))}</td></tr>'
        for p in sorted(data["paths"], key=lambda x: (0 if x.get("type") == "Job Role" else 1, x.get("title", "")))
    )
    paths_pdf_html = (
        '<h1>Mapa de Rutas Públicas Relevadas (25 Paths) y Alcance Integral</h1>'
        f'<p>Referencia resumida de las 25 rutas públicas (9 Job Role Paths y 16 Skill Paths) y los 358 módulos analizados e integrados en esta Edición 2.0 (332 módulos en Tomos I–VII, 10 puente con Curso de Reversing y 16 complementarios de IA).</p>'
        f'<div class="tabla"><table><thead><tr><th>Ruta de referencia</th><th>Tipo</th><th>Nivel</th><th>Módulos</th></tr></thead><tbody>{paths_rows}</tbody></table></div>'
    )
    sep_secciones = [
        {"anchor": "sep-cheatsheets", "titulo": "Hojas de Referencia Rápida (Cheat Sheets)", "html": CHEAT_SHEETS_HTML},
        {"anchor": "sep-glosario", "titulo": f"Glosario Técnico ({len(GLOSARIO_ITEMS)} términos)", "html": glos_pdf_html},
        {"anchor": "sep-rutas", "titulo": "Mapa de 25 Rutas Públicas y Alcance Curricular", "html": paths_pdf_html},
        {"anchor": "sep-fuentes", "titulo": "Fuentes Abiertas y Límites Éticos", "html": FUENTES_LIMITES_HTML},
    ]
    sep_portada = f"""
<div class="portada-pdf">
  <div>
    <div class="kicker">{CURSO_NOMBRE} · {EDICION_LABEL}</div>
    <h1>Separata de Escritorio: Cheat Sheets, Glosario y Mapa Curricular</h1>
    <div class="sub">Referencia rápida imprimible para laboratorio local (Redes, Linux, Windows, OWASP, AD, SOC, Cloud/K8s, Web Avanzado/OPSEC, Mobile/Wi-Fi/OT/GRC)</div>
    <div class="caja-meta">
      <p>Pensada para tener anillada al lado del teclado mientras estudiás los Tomos I a VII.</p>
    </div>
  </div>
  <div class="pie-portada"><p>Edición A4 de alto contraste · Paridad par garantizada para impresión doble faz.</p></div>
</div>"""
    sep_res = compilar_volumen_pdf("separata", "Separata_CheatSheets_y_Glosario.pdf", sep_portada, sep_secciones, css_base)
    sep_res["nombre"] = "Separata de Escritorio (Cheat Sheets, Glosario y Rutas)"
    resultados.append(sep_res)

    # Obra Maestra Digital Consolidada (merge de los 8 volúmenes con marcadores jerárquicos)
    master_name = "Hacking_Etico_Español_Completo.pdf"
    master_path = os.path.join(REPO_ROOT, master_name)
    writer = pypdf.PdfWriter()
    offset = 0
    for r in resultados:
        rpath = os.path.join(REPO_ROOT, r["archivo"])
        rd = pypdf.PdfReader(rpath)
        for p in rd.pages:
            writer.add_page(p)
        parent = writer.add_outline_item(title=r["nombre"], page_number=offset)
        for stit, spage in r["secciones"]:
            writer.add_outline_item(title=stit, page_number=offset + spage, parent=parent)
        offset += len(rd.pages)
    with open(master_path, "wb") as f:
        writer.write(f)
    m_pages = len(pypdf.PdfReader(master_path).pages)
    m_size = round(os.path.getsize(master_path) / (1024 * 1024), 2)
    print(f"  [PDF] {master_name:44s} | {m_pages:3d} págs ({m_pages//2:3d} hojas) | {'PAR OK' if m_pages%2==0 else 'IMPAR ERR'} | {m_size:.2f} MB")
    master_res = {
        "nombre": f"Obra Maestra Digital Consolidada (Tomos I–VII + Separata)",
        "archivo": master_name,
        "paginas": m_pages,
        "hojas": m_pages // 2,
        "paridad": m_pages % 2 == 0,
        "size_mb": m_size,
    }

    # Build orden_impresion.html
    rows_imp = []
    tot_p = 0
    tot_h = 0
    for r in resultados:
        tot_p += r["paginas"]
        tot_h += r["hojas"]
        rows_imp.append(
            f'<tr><td><strong>{esc(r["nombre"])}</strong></td>'
            f'<td><a href="{r["archivo"]}"><code>{r["archivo"]}</code></a></td>'
            f'<td>{r["paginas"]} págs.</td><td>{r["hojas"]} hojas</td>'
            f'<td><span class="pill {"ok" if r["paridad"] else "no"}">{"PAR OK" if r["paridad"] else "IMPAR"}</span></td>'
            f'<td>{r["size_mb"]:.2f} MB</td></tr>'
        )
    imp_body = f"""
<nav class="migas"><a href="00_EMPEZAR_AQUI.html">Inicio</a><span>›</span><span>Imprenta y PDFs</span></nav>
<h1>Especificación técnica de imprenta y PDFs A4</h1>
<p>Todos los volúmenes fueron compilados en formato <strong>A4 de alto contraste</strong> (código en tinta negra sobre fondo claro para impresión nítida tanto en impresora hogareña como en gráfica profesional) con <strong>paridad par estricta</strong> para impresión a doble faz sin hojas sueltas.</p>
<div class="tabla"><table>
<thead><tr><th>Volumen físico</th><th>Archivo PDF</th><th>Páginas</th><th>Hojas doble faz</th><th>Paridad</th><th>Tamaño</th></tr></thead>
<tbody>{"".join(rows_imp)}
<tr style="font-weight:700;background:#e3f1f2"><td>Total colección física ({len(resultados)} volúmenes)</td><td>—</td><td>{tot_p} págs.</td><td>{tot_h} hojas</td><td><span class="pill ok">100 % PAR</span></td><td>—</td></tr>
</tbody></table></div>
<h2>Edición digital unificada</h2>
<p>Para lectura en tablet, monitor o búsqueda global en PDF con índice de marcadores jerárquicos:</p>
<ul><li><a href="{master_res['archivo']}"><strong><code>{master_res['archivo']}</code></strong></a> — {master_res['paginas']} páginas ({master_res['size_mb']:.2f} MB), unifica los {len(TOMOS_META)} Tomos y la Separata de Escritorio.</li></ul>
"""
    with open(os.path.join(REPO_ROOT, "orden_impresion.html"), "w", encoding="utf-8") as f:
        f.write(page_shell("Imprenta y PDFs", f"Orden técnica de impresión y descarga de los {len(resultados) + 1} PDFs A4.", imp_body, depth=0))

    return resultados, master_res


def auditar_suite(resultados_pdf, master_pdf):
    print("\n[QA] Ejecutando auditoría automática de integridad...")
    errores = []
    html_files = [os.path.join(REPO_ROOT, f) for f in os.listdir(REPO_ROOT) if f.endswith(".html")]
    html_files += [os.path.join(GUIA_DIR, f) for f in os.listdir(GUIA_DIR) if f.endswith(".html")]

    broken_links = []
    raw_markers = []
    for hf in html_files:
        txt = open(hf, "r", encoding="utf-8").read()
        base_dir = os.path.dirname(hf)
        # Strip <script>, <pre>, and <code> blocks before checking HTML links and prose markers
        clean_html = re.sub(r"<script.*?</script>", "", txt, flags=re.S)
        clean_html = re.sub(r"<pre.*?</pre>", "", clean_html, flags=re.S)
        clean_html = re.sub(r"<code.*?</code>", "", clean_html, flags=re.S)
        for m in re.finditer(r'href="([^"]+)"', clean_html):
            href = m.group(1)
            if href.startswith(("http://", "https://", "mailto:", "#", "javascript:")):
                continue
            target = href.split("#")[0]
            if not target:
                continue
            full = os.path.normpath(os.path.join(base_dir, target))
            if not os.path.exists(full):
                broken_links.append((os.path.relpath(hf, REPO_ROOT), href))
        if ":::" in clean_html:
            raw_markers.append((os.path.relpath(hf, REPO_ROOT), ":::"))
        if "$$" in clean_html or "\\frac{" in clean_html:
            raw_markers.append((os.path.relpath(hf, REPO_ROOT), "LaTeX"))
        if "<li>[ ]" in clean_html or "<li>[x]" in clean_html:
            raw_markers.append((os.path.relpath(hf, REPO_ROOT), "[ ]"))

    for r in resultados_pdf + [master_pdf]:
        if not r["paridad"]:
            errores.append(f"PDF impar: {r['archivo']} ({r['paginas']} págs)")

    if broken_links:
        errores.append(f"{len(broken_links)} enlaces internos rotos: {broken_links[:5]}")
    if raw_markers:
        errores.append(f"{len(raw_markers)} marcas crudas detectadas: {raw_markers[:5]}")

    print(f"  HTML inspeccionados: {len(html_files)}")
    print(f"  Enlaces internos rotos: {len(broken_links)}")
    print(f"  Marcas crudas (::: / LaTeX): {len(raw_markers)}")
    print(f"  PDFs con paridad par: {sum(1 for r in resultados_pdf + [master_pdf] if r['paridad'])}/{len(resultados_pdf) + 1}")
    if errores:
        print("  [!] ERRORES DETECTADOS:")
        for e in errores:
            print("     -", e)
        return False
    print("  [OK] AUDITORÍA 100 % LIMPIA.")
    return True


def main():
    data = json.load(open(os.path.join(DATOS_DIR, "catalogo_htb_publico.json"), "r", encoding="utf-8"))
    rendered = construir_sitio_html(data)
    res_pdfs, master_pdf = compilar_todos_los_pdfs(data, rendered)
    ok = auditar_suite(res_pdfs, master_pdf)
    shutil.rmtree(BUILD_TMP, ignore_errors=True)
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
