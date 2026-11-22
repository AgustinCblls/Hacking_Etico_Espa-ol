#!/usr/bin/env python3
"""Aplicación didáctica local (SOLO 127.0.0.1) para comparar patrones inseguros vs. seguros.
Uso exclusivo en laboratorio propio (Tomo II).
"""
import sqlite3
from flask import Flask, request, jsonify, render_template_string
from markupsafe import escape

app = Flask(__name__)

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
            ("carlos", "Auditoría DNS", "Registro SPF/DMARC pendiente"),
        ],
    )
    conn.commit()
    return conn

DB = init_db()

@app.route("/")
def index():
    return render_template_string(
        """<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Lab Web Local</title></head>
        <body style="font-family:sans-serif;max-width:760px;margin:2rem auto;line-height:1.5">
        <h1>Laboratorio Web Educativo (127.0.0.1)</h1>
        <p>Compará el comportamiento entre endpoints con validación segura y ejemplos didácticos.</p>
        <ul>
          <li><code>/buscar-seguro?q=redes</code> — Consulta SQL parametrizada (patrón recomendado).</li>
          <li><code>/saludo-seguro?nombre=Estudiante</code> — Salida escapada automáticamente con Jinja2/MarkupSafe.</li>
          <li><code>/ticket-seguro/1?user=ana</code> — Control de acceso con verificación estricta de propietario (anti-IDOR).</li>
        </ul>
        </body></html>"""
    )

@app.route("/buscar-seguro")
def buscar_seguro():
    q = request.args.get("q", "").strip()[:60]
    cur = DB.cursor()
    # Patrón seguro: consulta parametrizada (previene SQL Injection)
    cur.execute("SELECT id, nombre, categoria, precio FROM productos WHERE categoria = ? OR nombre LIKE ?", (q, f"%{q}%"))
    filas = [{"id": r[0], "nombre": r[1], "categoria": r[2], "precio": r[3]} for r in cur.fetchall()]
    return jsonify({"modo": "seguro_parametrizado", "consulta": q, "resultados": filas})

@app.route("/saludo-seguro")
def saludo_seguro():
    nombre = escape(request.args.get("nombre", "Estudiante")[:50])
    resp = app.make_response(f"<h1>Hola, {nombre}</h1><p>Salida codificada con escape HTML y CSP activa.</p>")
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp

@app.route("/ticket-seguro/<int:ticket_id>")
def ticket_seguro(ticket_id):
    usuario_actual = request.args.get("user", "").strip().lower()
    cur = DB.cursor()
    # Patrón seguro: verifica propiedad en la misma consulta (anti-IDOR / anti-BOLA)
    cur.execute("SELECT id, owner, titulo, detalle FROM tickets WHERE id = ? AND owner = ?", (ticket_id, usuario_actual))
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "Acceso denegado o recurso inexistente"}), 403
    return jsonify({"id": row[0], "owner": row[1], "titulo": row[2], "detalle": row[3]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
