#!/usr/bin/env python3
"""Auditor educativo White-Box (SAST básico) para prácticas de Secure Code Review (Cap. 2.7 y 6.4).
Busca patrones peligrosos (Source -> Sink) en archivos Python dentro de un directorio local.
Uso: python auditor_whitebox_codereview.py [ruta_objetivo]
"""
import ast
import os
import sys

SINKS_PELIGROSOS = {
    "eval": "Ejecución dinámica de expresiones arbitrarias (CWE-95)",
    "exec": "Ejecución dinámica de código Python arbitrario (CWE-95)",
    "pickle.loads": "Deserialización insegura capaz de ejecutar código al cargar objetos (CWE-502)",
    "yaml.load": "Deserialización YAML potencialmente insegura si no usa SafeLoader (CWE-502)",
    "os.system": "Invocación de shell del sistema propensa a Command Injection (CWE-78)",
}


def inspeccionar_archivo(ruta: str) -> list[dict]:
    hallazgos = []
    try:
        src = open(ruta, "r", encoding="utf-8", errors="replace").read()
        arbol = ast.parse(src, filename=ruta)
    except SyntaxError:
        return hallazgos

    for nodo in ast.walk(arbol):
        if isinstance(nodo, ast.Call):
            nombre = ""
            if isinstance(nodo.func, ast.Name):
                nombre = nodo.func.id
            elif isinstance(nodo.func, ast.Attribute) and isinstance(nodo.func.value, ast.Name):
                nombre = f"{nodo.func.value.id}.{nodo.func.attr}"

            if nombre in SINKS_PELIGROSOS:
                hallazgos.append({
                    "archivo": ruta,
                    "linea": nodo.lineno,
                    "patron": nombre,
                    "detalle": SINKS_PELIGROSOS[nombre],
                })

            if nombre in ("subprocess.run", "subprocess.Popen", "subprocess.call"):
                for kw in nodo.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        hallazgos.append({
                            "archivo": ruta,
                            "linea": nodo.lineno,
                            "patron": f"{nombre}(shell=True)",
                            "detalle": "Subproceso con intérprete shell activado; preferir lista de argumentos con shell=False (CWE-78)",
                        })

            if isinstance(nodo.func, ast.Attribute) and nodo.func.attr == "execute" and nodo.args:
                arg0 = nodo.args[0]
                if isinstance(arg0, (ast.JoinedStr, ast.BinOp)):
                    hallazgos.append({
                        "archivo": ruta,
                        "linea": nodo.lineno,
                        "patron": "cursor.execute(<dinámico>)",
                        "detalle": "Posible concatenación o f-string en consulta SQL; verificar consultas parametrizadas (CWE-89)",
                    })
    return hallazgos


def main():
    objetivo = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    total = []
    for root, _, files in os.walk(objetivo):
        for fn in sorted(files):
            if fn.endswith(".py") and fn != os.path.basename(__file__):
                total.extend(inspeccionar_archivo(os.path.join(root, fn)))

    print(f"=== Auditoría White-Box AST sobre: {objetivo} ===")
    print(f"Hallazgos candidatos para revisión manual: {len(total)}")
    for h in total:
        print(f"- {h['archivo']}:{h['linea']} [{h['patron']}] -> {h['detalle']}")


if __name__ == "__main__":
    main()
