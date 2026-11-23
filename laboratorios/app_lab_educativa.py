#!/usr/bin/env python3
"""Aplicación didáctica Purple Team (SOLO 127.0.0.1) con endpoints gemelos
`-vulnerable` frente a `-seguro` para practicar el ciclo:
  Ataca (-vulnerable) -> Detecta (telemetría / tráfico) -> Corrige y verifica (-seguro).

ADVERTENCIA: Contiene fallos intencionales (SQLi, XSS reflejado/almacenado, IDOR,
JWT débil, SSRF simulado, SSTI y upload inseguro) exclusivamente para laboratorio
educativo local aislado. NUNCA exponer en redes públicas ni producción.
"""
import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import socket
import sqlite3
import tempfile
import uuid
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template_string, request
from markupsafe import escape

app = Flask(__name__)

# Claves didácticas para comparar JWT inseguro vs. seguro
JWT_SECRETO_DEBIL = "secreto123"
JWT_SECRETO_SEGURO = hashlib.sha256(os.urandom(32)).hexdigest()
EVENTOS_TELEMETRIA = []
COMENTARIOS_VULNERABLES = ["Bienvenidos al tablero de pruebas."]
COMENTARIOS_SEGUROS = ["Bienvenidos al tablero seguro."]
DIRECTORIO_UPLOADS = Path(tempfile.gettempdir()) / "lab_uploads_seguro"
DIRECTORIO_UPLOADS.mkdir(parents=True, exist_ok=True)


def emitir_telemetria(vector: str, endpoint: str, detalle: str, severidad: str = "ALTA"):
    evento = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "severidad": severidad,
        "vector": vector,
        "endpoint": endpoint,
        "origen": request.remote_addr,
        "detalle": detalle[:160],
    }
    EVENTOS_TELEMETRIA.append(evento)
    if len(EVENTOS_TELEMETRIA) > 200:
        EVENTOS_TELEMETRIA.pop(0)
    print(f"[PURPLE-TELEMETRY] {json.dumps(evento, ensure_ascii=False)}", flush=True)


def init_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cur = conn.cursor()
    cur.execute("CREATE TABLE productos (id INTEGER PRIMARY KEY, nombre TEXT, categoria TEXT, precio REAL)")
    cur.executemany(
        "INSERT INTO productos (nombre, categoria, precio) VALUES (?, ?, ?)",
        [
            ("Router Lab A1", "redes", 120.0),
            ("Switch L2 Educativo", "redes", 240.0),
            ("Sensor Sysmon Node", "defensa", 85.0),
            ("Manual Hardening Linux", "libros", 35.0),
        ],
    )
    cur.execute("CREATE TABLE tickets (id INTEGER PRIMARY KEY, owner TEXT, titulo TEXT, detalle TEXT)")
    cur.executemany(
        "INSERT INTO tickets (owner, titulo, detalle) VALUES (?, ?, ?)",
        [
            ("ana", "Revisión firewall", "Reglas de salida verificadas"),
            ("carlos", "Auditoría DNS", "Registro SPF/DMARC pendiente — secreto_lab_carlos"),
        ],
    )
    conn.commit()
    return conn


DB = init_db()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(txt: str) -> bytes:
    pad = "=" * (-len(txt) % 4)
    return base64.urlsafe_b64decode(txt + pad)


def _crear_jwt(payload: dict, secreto: str, alg: str = "HS256") -> str:
    hdr = _b64url_encode(json.dumps({"typ": "JWT", "alg": alg}, separators=(",", ":")).encode())
    pld = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    firma = hmac.new(secreto.encode(), f"{hdr}.{pld}".encode(), hashlib.sha256).digest()
    return f"{hdr}.{pld}.{_b64url_encode(firma)}"


@app.route("/")
def index():
    return render_template_string(
        """<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Lab Web Purple Team</title></head>
        <body style="font-family:sans-serif;max-width:860px;margin:2rem auto;line-height:1.5">
        <h1>Laboratorio Web Purple Team (Solo 127.0.0.1)</h1>
        <p><strong>Uso exclusivo educativo local.</strong> Cada categoría ofrece un endpoint <code>-vulnerable</code> y su gemelo corregido <code>-seguro</code>:</p>
        <ul>
          <li><strong>SQLi:</strong> <code>/buscar-vulnerable?q=redes</code> &harr; <code>/buscar-seguro?q=redes</code></li>
          <li><strong>XSS Reflejado:</strong> <code>/saludo-vulnerable?nombre=Lab</code> &harr; <code>/saludo-seguro?nombre=Lab</code></li>
          <li><strong>XSS Almacenado:</strong> <code>/comentarios-vulnerable</code> &harr; <code>/comentarios-seguro</code></li>
          <li><strong>IDOR / BOLA:</strong> <code>/ticket-vulnerable/2?user=ana</code> &harr; <code>/ticket-seguro/1?user=ana</code></li>
          <li><strong>JWT Débil:</strong> <code>/jwt-login?user=ana</code> &rarr; <code>/jwt-vulnerable</code> &harr; <code>/jwt-seguro</code></li>
          <li><strong>SSRF:</strong> <code>/fetch-vulnerable?url=http://169.254.169.254/latest/meta-data/</code> &harr; <code>/fetch-seguro?url=...</code></li>
          <li><strong>SSTI:</strong> <code>/plantilla-vulnerable?nombre=Lab</code> &harr; <code>/plantilla-seguro?nombre=Lab</code></li>
          <li><strong>Upload:</strong> <code>POST /upload-vulnerable</code> &harr; <code>POST /upload-seguro</code></li>
          <li><strong>Telemetría SOC:</strong> <code>GET /telemetria-lab</code> (últimas detecciones registradas)</li>
        </ul>
        </body></html>"""
    )


@app.route("/telemetria-lab")
def telemetria_lab():
    return jsonify({"total_eventos": len(EVENTOS_TELEMETRIA), "eventos": EVENTOS_TELEMETRIA[-30:]})


# --- 1. SQL Injection (Cap. 2.3) ---

@app.route("/buscar-vulnerable")
def buscar_vulnerable():
    q = request.args.get("q", "")
    if any(tok in q.upper() for tok in ("'", "UNION", "SELECT", "OR ", "--")):
        emitir_telemetria("SQLi_Attempt", "/buscar-vulnerable", f"Payload sospechoso en q={q}")
    cur = DB.cursor()
    try:
        # PATRÓN VULNERABLE INTENCIONAL (CWE-89): concatenación directa sin parametrizar
        cur.execute(f"SELECT id, nombre, categoria, precio FROM productos WHERE categoria = '{q}' OR nombre LIKE '%{q}%'")
        filas = [{"id": r[0], "nombre": r[1], "categoria": r[2], "precio": r[3]} for r in cur.fetchall()]
        return jsonify({"modo": "vulnerable_concatenado", "consulta": q, "resultados": filas})
    except sqlite3.Error as err:
        emitir_telemetria("SQLi_Syntax_Error", "/buscar-vulnerable", str(err))
        return jsonify({"modo": "vulnerable_concatenado", "error_sql": str(err)}), 500


@app.route("/buscar-seguro")
def buscar_seguro():
    q = request.args.get("q", "").strip()[:60]
    cur = DB.cursor()
    # PATRÓN SEGURO: consulta parametrizada (previene SQL Injection)
    cur.execute("SELECT id, nombre, categoria, precio FROM productos WHERE categoria = ? OR nombre LIKE ?", (q, f"%{q}%"))
    filas = [{"id": r[0], "nombre": r[1], "categoria": r[2], "precio": r[3]} for r in cur.fetchall()]
    return jsonify({"modo": "seguro_parametrizado", "consulta": q, "resultados": filas})


# --- 2. XSS Reflejado y Almacenado (Cap. 2.4) ---

@app.route("/saludo-vulnerable")
def saludo_vulnerable():
    nombre = request.args.get("nombre", "Estudiante")
    if "<" in nombre or "script" in nombre.lower() or "onerror" in nombre.lower():
        emitir_telemetria("XSS_Reflejado", "/saludo-vulnerable", f"nombre={nombre}")
    # PATRÓN VULNERABLE INTENCIONAL (CWE-79): reflexión HTML sin escape ni CSP
    return f"<h1>Hola, {nombre}</h1><p>Vista sin escape HTML ni Content-Security-Policy.</p>"


@app.route("/saludo-seguro")
def saludo_seguro():
    nombre = escape(request.args.get("nombre", "Estudiante")[:50])
    resp = app.make_response(f"<h1>Hola, {nombre}</h1><p>Salida codificada con escape HTML y CSP activa.</p>")
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.route("/comentarios-vulnerable", methods=["GET", "POST"])
def comentarios_vulnerable():
    if request.method == "POST":
        texto = request.form.get("texto", "") or (request.get_json(silent=True) or {}).get("texto", "")
        if texto:
            if "<" in texto or "onerror" in texto.lower():
                emitir_telemetria("XSS_Almacenado", "/comentarios-vulnerable", f"texto={texto}")
            COMENTARIOS_VULNERABLES.append(texto)
    items = "".join(f"<li>{c}</li>" for c in COMENTARIOS_VULNERABLES[-20:])
    return f"<h2>Comentarios (Modo Vulnerable)</h2><ul>{items}</ul>"


@app.route("/comentarios-seguro", methods=["GET", "POST"])
def comentarios_seguro():
    if request.method == "POST":
        texto = request.form.get("texto", "") or (request.get_json(silent=True) or {}).get("texto", "")
        if texto:
            COMENTARIOS_SEGUROS.append(texto[:300])
    html_out = render_template_string(
        "<h2>Comentarios (Modo Seguro)</h2><ul>{% for c in items %}<li>{{ c }}</li>{% endfor %}</ul>",
        items=COMENTARIOS_SEGUROS[-20:],
    )
    resp = app.make_response(html_out)
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


# --- 3. IDOR / BOLA + JWT Débil (Cap. 2.5) ---

@app.route("/ticket-vulnerable/<int:ticket_id>")
def ticket_vulnerable(ticket_id):
    usuario_actual = request.args.get("user", "").strip().lower()
    if not usuario_actual:
        return jsonify({"error": "Falta parámetro user"}), 401
    cur = DB.cursor()
    # PATRÓN VULNERABLE INTENCIONAL (CWE-639): consulta solo por id sin validar propietario
    cur.execute("SELECT id, owner, titulo, detalle FROM tickets WHERE id = ?", (ticket_id,))
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "No encontrado"}), 404
    if row[1] != usuario_actual:
        emitir_telemetria("IDOR_Access", f"/ticket-vulnerable/{ticket_id}", f"user={usuario_actual} accedio a owner={row[1]}")
    return jsonify({"modo": "vulnerable_idor", "id": row[0], "owner": row[1], "titulo": row[2], "detalle": row[3]})


@app.route("/ticket-seguro/<int:ticket_id>")
def ticket_seguro(ticket_id):
    usuario_actual = request.args.get("user", "").strip().lower()
    cur = DB.cursor()
    # PATRÓN SEGURO: verifica propiedad en la misma consulta (anti-IDOR / anti-BOLA)
    cur.execute("SELECT id, owner, titulo, detalle FROM tickets WHERE id = ? AND owner = ?", (ticket_id, usuario_actual))
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "Acceso denegado o recurso inexistente"}), 403
    return jsonify({"id": row[0], "owner": row[1], "titulo": row[2], "detalle": row[3]})


@app.route("/jwt-login")
def jwt_login():
    user = request.args.get("user", "ana").strip().lower()
    modo = request.args.get("modo", "debil").strip().lower()
    exp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600
    payload = {"sub": user, "role": "analista", "iss": "lab-local", "aud": "api-lab", "exp": exp}
    secreto = JWT_SECRETO_SEGURO if modo == "seguro" else JWT_SECRETO_DEBIL
    return jsonify({"modo": modo, "token": _crear_jwt(payload, secreto, "HS256")})


@app.route("/jwt-vulnerable")
def jwt_vulnerable():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip() or request.args.get("token", "").strip()
    partes = token.split(".")
    if len(partes) != 3:
        return jsonify({"error": "Token malformado"}), 400
    try:
        hdr = json.loads(_b64url_decode(partes[0]).decode())
        pld = json.loads(_b64url_decode(partes[1]).decode())
    except Exception:
        return jsonify({"error": "Decodificación fallida"}), 400

    # PATRÓN VULNERABLE INTENCIONAL (CWE-347): acepta alg=none o firma débil sin exigir exp/aud
    if str(hdr.get("alg", "")).lower() == "none":
        emitir_telemetria("JWT_Alg_None", "/jwt-vulnerable", f"alg=none para sub={pld.get('sub')} role={pld.get('role')}")
        return jsonify({"modo": "vulnerable_alg_none", "acceso": True, "claims": pld})

    esperada = _b64url_encode(hmac.new(JWT_SECRETO_DEBIL.encode(), f"{partes[0]}.{partes[1]}".encode(), hashlib.sha256).digest())
    if hmac.compare_digest(partes[2], esperada):
        return jsonify({"modo": "vulnerable_secreto_debil", "acceso": True, "claims": pld})
    return jsonify({"error": "Firma inválida"}), 401


@app.route("/jwt-seguro")
def jwt_seguro():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip() or request.args.get("token", "").strip()
    partes = token.split(".")
    if len(partes) != 3:
        return jsonify({"error": "Token ausente o malformado"}), 401
    try:
        hdr = json.loads(_b64url_decode(partes[0]).decode())
        if hdr.get("alg") != "HS256":
            emitir_telemetria("JWT_Alg_Rechazado", "/jwt-seguro", f"alg={hdr.get('alg')}", severidad="MEDIA")
            return jsonify({"error": "Algoritmo no permitido"}), 401
        esperada = _b64url_encode(hmac.new(JWT_SECRETO_SEGURO.encode(), f"{partes[0]}.{partes[1]}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(partes[2], esperada):
            return jsonify({"error": "Firma inválida"}), 401
        pld = json.loads(_b64url_decode(partes[1]).decode())
        ahora = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        if int(pld.get("exp", 0)) <= ahora or pld.get("iss") != "lab-local" or pld.get("aud") != "api-lab":
            return jsonify({"error": "Claims inválidos o expirados"}), 401
        return jsonify({"modo": "seguro", "acceso": True, "claims": pld})
    except Exception:
        return jsonify({"error": "Token inválido"}), 401


# --- 4. SSRF, SSTI y Upload Inseguro (Cap. 2.6) ---

@app.route("/interno-metadata")
def interno_metadata():
    return jsonify({"nota": "Servicio simulado interno solo loopback", "iam_role": "rol-lab-simulado"})


@app.route("/fetch-vulnerable")
def fetch_vulnerable():
    url = request.args.get("url", "").strip()
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host in ("169.254.169.254", "127.0.0.1", "localhost", "::1") or host.startswith(("10.", "192.168.", "172.16.")):
        emitir_telemetria("SSRF_Internal_Target", "/fetch-vulnerable", f"url={url}")
        return jsonify({
            "modo": "vulnerable_ssrf_simulado",
            "destino_alcanzado": url,
            "respuesta_interna": {"meta_data_simulada": "ami-lab-001", "role": "lab-metadata-demo"},
        })
    return jsonify({"modo": "vulnerable_ssrf_simulado", "destino": url, "estado": "Simulación offline sin tráfico externo"})


@app.route("/fetch-seguro")
def fetch_seguro():
    url = request.args.get("url", "").strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return jsonify({"error": "Solo se permiten URLs https válidas"}), 400
    try:
        for info in socket.getaddrinfo(parsed.hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local:
                emitir_telemetria("SSRF_Bloqueado", "/fetch-seguro", f"host={parsed.hostname} ip={ip}", severidad="MEDIA")
                return jsonify({"error": f"Destino interno bloqueado por política anti-SSRF ({ip})"}), 403
    except socket.gaierror:
        return jsonify({"error": "No se pudo resolver el host en modo local"}), 400
    return jsonify({"modo": "seguro_anti_ssrf", "url_validada": url, "estado": "Aprobado por política (sin petición externa en lab offline)"})


@app.route("/plantilla-vulnerable")
def plantilla_vulnerable():
    nombre = request.args.get("nombre", "Analista")
    if "{{" in nombre or "${" in nombre:
        emitir_telemetria("SSTI_Probe", "/plantilla-vulnerable", f"nombre={nombre}")
    # PATRÓN VULNERABLE INTENCIONAL (CWE-1336): interpolación previa en plantilla Jinja2
    return render_template_string(f"<h2>Perfil (Vulnerable): {nombre}</h2>")


@app.route("/plantilla-seguro")
def plantilla_seguro():
    nombre = request.args.get("nombre", "Analista")[:60]
    resp = app.make_response(render_template_string("<h2>Perfil (Seguro): {{ nombre }}</h2>", nombre=nombre))
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none'"
    return resp


@app.route("/upload-vulnerable", methods=["POST"])
def upload_vulnerable():
    f = request.files.get("archivo")
    if not f:
        return jsonify({"error": "Falta campo multipart 'archivo'"}), 400
    nombre_cliente = f.filename or "sin_nombre"
    if ".." in nombre_cliente or "/" in nombre_cliente or "\\" in nombre_cliente or nombre_cliente.endswith((".php", ".py", ".sh", ".jsp")):
        emitir_telemetria("Upload_Peligroso", "/upload-vulnerable", f"filename={nombre_cliente} ct={f.content_type}")
    return jsonify({
        "modo": "vulnerable_upload",
        "filename_confiado_cliente": nombre_cliente,
        "content_type_cliente": f.content_type,
        "riesgo": "Aceptó nombre original y MIME declarado sin validar magic bytes ni renombrar con UUID",
    })


@app.route("/upload-seguro", methods=["POST"])
def upload_seguro():
    f = request.files.get("archivo")
    if not f:
        return jsonify({"error": "Falta campo multipart 'archivo'"}), 400
    contenido = f.read(1024 * 256)
    # Solo PNG o PDF según magic bytes reales (no Content-Type)
    es_png = contenido.startswith(b"\x89PNG\r\n\x1a\n")
    es_pdf = contenido.startswith(b"%PDF-")
    if not (es_png or es_pdf):
        emitir_telemetria("Upload_Rechazado_Magic", "/upload-seguro", f"filename={f.filename}", severidad="MEDIA")
        return jsonify({"error": "Tipo de archivo rechazado por validación de magic bytes (solo PNG/PDF)"}), 400
    ext = ".png" if es_png else ".pdf"
    nombre_uuid = f"{uuid.uuid4().hex}{ext}"
    destino = (DIRECTORIO_UPLOADS / nombre_uuid).resolve()
    if not destino.is_relative_to(DIRECTORIO_UPLOADS.resolve()):
        return jsonify({"error": "Ruta inválida"}), 400
    destino.write_bytes(contenido)
    return jsonify({"modo": "seguro_upload", "archivo_uuid": nombre_uuid, "bytes": len(contenido)})


if __name__ == "__main__":
    host = os.environ.get("LAB_HOST", "127.0.0.1")
    print("[AVISO] lab_local_web con endpoints -vulnerable y -seguro exclusivamente para laboratorio local.", flush=True)
    app.run(host=host, port=5050, debug=False)
