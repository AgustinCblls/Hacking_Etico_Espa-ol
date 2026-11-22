::: nota Objetivo de la lección
Escribir herramientas propias y auditables en **Python 3** para automatización defensiva, verificación de red local, análisis de registros y comprobación de integridad. Al finalizar vas a dominar sockets TCP, peticiones HTTP seguras, parsing con expresiones regulares/JSON/CSV, hashing con `hashlib`, ejecución controlada mediante `subprocess` y el funcionamiento interno de `laboratorios/auditor_red_local.py` y `laboratorios/analizador_logs_soc.py`.
:::

**Prerrequisitos:** Manejo fluido de terminal y lógica básica de scripting (Capítulo 1.5), además de fundamentos TCP/IP (Capítulo 1.2). **Duración sugerida:** 3 a 4 horas (incluyendo ejecución y extensión de los scripts del laboratorio).

## 1. Python 3 limpio para tareas de seguridad y comparativa con Go

Cuando una tarea supera la complejidad de una tubería de shell —por ejemplo, mantener estado entre múltiples archivos, correlacionar alertas en JSON, consultar una API REST o hablar directamente sobre TCP—, **Python 3** ofrece el mejor equilibrio entre velocidad de desarrollo, legibilidad y biblioteca estándar. Su ecosistema cubre desde prototipado rápido en auditorías autorizadas hasta automatización de respuestas en un SOC.

### 1.1 Entornos aislados, tipado y gestión de recursos

Un script de seguridad descuidado suele fallar por dependencias rotas, sockets sin cerrar o excepciones silenciosas. Aplicá cuatro hábitos desde el primer día:

- **Entornos virtuales (`venv`):** aislá librerías externas como `requests` con `python3 -m venv .venv` para no contaminar el Python del sistema operativo.
- **Manejadores de contexto (`with`):** garantizan el cierre automático de archivos y sockets incluso cuando ocurre una excepción.
- **Anotaciones de tipo (*type hints*):** documentan qué entra y qué sale de cada función (`def verificar_puerto(host: str, puerto: int) -> tuple[bool, str]:`), reduciendo errores en tiempo de mantenimiento.
- **Tiempos de espera explícitos (`timeout`):** ninguna llamada de red o subproceso debe quedar bloqueada indefinidamente.

### 1.2 Criterio de elección: Shell, Python 3 y Go

En equipos de seguridad modernos suele combinarse el scripting de sistema con Python 3 y, para utilidades compiladas de alto rendimiento, **Go (Golang)**. Conviene entender cuándo elegir cada herramienta:

| Criterio | Bash / PowerShell | Python 3 | Go (Golang) |
| :--- | :--- | :--- | :--- |
| Velocidad de prototipado | Muy alta (línea única) | Alta (biblioteca estándar extensa) | Media (tipado estático estricto) |
| Distribución en hosts | Depende del SO y versión | Requiere intérprete y dependencias | Binario estático único sin runtime externo |
| Concurrencia nativa | Limitada (subprocesos) | `asyncio` / `concurrent.futures` | Muy alta (*goroutines* y canales) |
| Caso de uso ideal | Triaje inmediato y administración | Parsing SOC, clientes HTTP/API, automatización | Colectores de telemetría, proxies y agentes portables |

## 2. Programación de red con sockets TCP y clientes HTTP

### 2.1 Sockets TCP defensivos y control de alcance

El módulo estándar `socket` expone la interfaz BSD de comunicaciones de red. Para verificar si un puerto TCP acepta conexiones sin generar ruido innecesario, `connect_ex()` resulta más limpio que `connect()` porque devuelve `0` en caso de éxito o un código de error numérico del sistema operativo sin lanzar excepciones por cada puerto cerrado.

Además, toda herramienta educativa o de inventario interno debe incorporar **guardarraíles de alcance** usando el módulo `ipaddress`, restringiendo las conexiones únicamente a direcciones de laboratorio (`127.0.0.0/8` o rangos privados RFC 1918):

```python
import ipaddress
import socket


def validar_destino_laboratorio(host: str) -> str:
    ip_str = socket.gethostbyname(host)
    ip_obj = ipaddress.ip_address(ip_str)
    if not (ip_obj.is_private or ip_obj.is_loopback):
        raise ValueError(f"Destino fuera de laboratorio autorizado: {ip_str}")
    return ip_str


def probar_tcp(host: str, puerto: int, timeout: float = 0.8) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, puerto)) == 0
```

### 2.2 Peticiones HTTP reproducibles con `urllib` y `requests`

Para auditar cabeceras de seguridad, consultar APIs de inteligencia de amenazas o verificar endpoints de una aplicación local, Python ofrece `urllib.request` en su biblioteca estándar (cero dependencias externas) y la librería `requests` como estándar de facto por su ergonomía. En ambos casos, **nunca deshabilites la verificación de certificados TLS** (`verify=False`) en producción ni omitas `timeout`:

```python
import urllib.request
import urllib.error

CABECERAS_ESPERADAS = (
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
)


def auditar_cabeceras_http(url: str, timeout: float = 3.0) -> dict[str, str]:
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "Lab-Auditor/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {h: resp.headers.get(h, "AUSENTE") for h in CABECERAS_ESPERADAS}
    except urllib.error.URLError as exc:
        return {"error": str(exc)}
```

Si necesitás mantener cookies entre múltiples solicitudes o reutilizar conexiones TCP persistentes (*keep-alive*), usá `requests.Session()` dentro de un bloque `with` y comprobá siempre `resp.status_code` antes de decodificar el cuerpo con `resp.json()`.

## 3. Parsing estructurado (JSON, CSV, Regex) e integridad con `hashlib`

### 3.1 Expresiones regulares compiladas, JSON y CSV

Los registros heterogéneos rara vez llegan en un único formato: un firewall puede exportar CSV, una API devuelve JSON y `sshd` escribe texto semiestructurado. En Python conviene compilar previamente las expresiones regulares con `re.compile()` y usar **grupos con nombre** (`(?P<campo>...)`) para que el código siga siendo legible meses después:

```python
import csv
import json
import re
from pathlib import Path

PATRON_ACCESO = re.compile(
    r'^(?P<ip>\S+) .* "(?P<metodo>GET|POST|PUT|DELETE|HEAD) (?P<ruta>\S+) HTTP/.*" (?P<codigo>\d{3}) '
)


def exportar_resumen_csv_a_json(ruta_csv: Path, ruta_json: Path) -> int:
    filas_filtradas = []
    with ruta_csv.open("r", encoding="utf-8", newline="") as f:
        for fila in csv.DictReader(f):
            if fila.get("estado", "").lower() == "alerta":
                filas_filtradas.append(fila)

    ruta_json.write_text(
        json.dumps(filas_filtradas, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return len(filas_filtradas)
```

### 3.2 Verificación de integridad con `hashlib` y comparación segura

En respuesta a incidentes, forense y verificación de artefactos descargados, el módulo `hashlib` calcula resúmenes criptográficos sin cargar archivos grandes completos en RAM. Usá **SHA-256** (o SHA-512) para integridad, evitando MD5 y SHA-1 debido a colisiones conocidas. Además, al comparar dos resúmenes o tokens sensibles, utilizá `hmac.compare_digest()` para prevenir filtraciones por tiempo de ejecución (*timing attacks*):

```python
import hashlib
import hmac
from pathlib import Path


def sha256_archivo(ruta: Path, bloque: int = 65536) -> str:
    h = hashlib.sha256()
    with ruta.open("rb") as f:
        while fragmento := f.read(bloque):
            h.update(fragmento)
    return h.hexdigest()


def verificar_integridad(ruta: Path, hash_esperado: str) -> bool:
    calculado = sha256_archivo(ruta)
    return hmac.compare_digest(calculado.lower(), hash_esperado.strip().lower())
```

## 4. Automatización segura del sistema con `subprocess`

En ocasiones un script Python necesita invocar binarios del sistema operativo (`ss`, `openssl`, `git`, `ip`). La regla de oro en Python moderno es usar `subprocess.run()` pasando el comando como **lista de argumentos** y manteniendo `shell=False` (el valor por defecto).

| Práctica | Ejemplo | Riesgo / Beneficio |
| :--- | :--- | :--- |
| Insegura (prohibida) | `subprocess.run(f"ping -c 1 {host}", shell=True)` | Inyección de comandos si `host` contiene `;`, `&&` o `$(...)` |
| Segura (recomendada) | `subprocess.run(["ping", "-c", "1", "--", host], capture_output=True, text=True, timeout=5)` | El sistema ejecuta el binario directo sin invocar `/bin/sh` ni interpretar metacaracteres |

El separador `--` indica a muchas utilidades POSIX que los argumentos posteriores son datos y no opciones adicionales (mitigando inyección de flags). Siempre capturá `subprocess.TimeoutExpired` y validá previamente la entrada (por ejemplo, comprobando que `host` sea una IP válida con `ipaddress.ip_address()`).

```python
import ipaddress
import subprocess


def inspeccionar_ruta_local(ip_texto: str) -> str:
    ip_validada = str(ipaddress.ip_address(ip_texto))
    resultado = subprocess.run(
        ["ip", "route", "get", ip_validada],
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    if resultado.returncode != 0:
        return f"Error al consultar ruta: {resultado.stderr.strip()}"
    return resultado.stdout.strip()
```

::: peligro Nunca uses `os.system()` ni `eval()` sobre datos externos
Tanto `os.system()` como `subprocess.run(..., shell=True)` pasan la cadena completa al intérprete de comandos del sistema. De forma análoga, `eval()` y `pickle.loads()` sobre datos no confiables ejecutan código arbitrario. Para deserializar datos externos, restringite siempre a formatos declarativos seguros como `json.loads()` o `yaml.safe_load()`.
:::

## 5. Recorrido práctico por los scripts de `laboratorios/`

El repositorio del manual incluye dos utilidades educativas en Python 3 diseñadas para consolidar los conceptos de este capítulo sin dependencias externas.

### 5.1 Anatomía de `laboratorios/auditor_red_local.py`

Este script realiza un inventario rápido de superficie expuesta sobre un host local o de laboratorio:

1. **Lista acotada de puertos (`PUERTOS_COMUNES`):** verifica 14 puertos representativos (`22, 53, 80, 135, 139, 389, 443, 445, 3306, 3389, 5050, 5432, 8080, 8443`), incluyendo el puerto `5050` de nuestra aplicación educativa web.
2. **Guardarraíl de alcance (`es_destino_privado`):** resuelve el host con `socket.gethostbyname()` y exige que `ip.is_private or ip.is_loopback` sea verdadero; ante cualquier dirección pública aborta con código `1` y el mensaje `[BLOQUEADO]`.
3. **Verificación y captura pasiva/mínima de banner (`verificar_puerto`):** abre un socket TCP con `timeout=0.6` segundos y usa `connect_ex()`. Si el puerto responde y pertenece al conjunto HTTP local (`80`, `5050`, `8080`), envía `HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n` para leer la primera línea de respuesta (`recv(120)`), decodificando con `errors="replace"` para no fallar ante bytes no UTF-8.

### 5.2 Anatomía de `laboratorios/analizador_logs_soc.py`

Este script ilustra cómo estructurar un detector ligero de anomalías de autenticación y sondeo web para un flujo SOC:

1. **Dos patrones compilados:** `PATRON_SSH_FAIL` extrae `user` e `ip` de líneas `Failed password for` de OpenSSH; `PATRON_HTTP_4XX` captura `ip`, `metodo`, `ruta` y `codigo` (`401`, `403`, `404`) en registros de acceso web.
2. **Estructuras de acumulación eficientes:** emplea `collections.Counter()` para contabilizar eventos por IP y `collections.defaultdict(set)` para registrar qué usuarios distintos intentó cada origen sin duplicados.
3. **Emisión de alertas en JSON estructurado:** genera la regla `SOC-AUTH-001` cuando una IP alcanza o supera `umbral` fallos SSH (severidad `media` si es `< 20`, `alta` si es `>= 20`, acotando `usuarios_distintos` a 10 elementos) y la regla `SOC-WEB-002` cuando las respuestas `4xx` alcanzan `umbral * 3`. La salida JSON facilita la integración directa con dashboards, scripts posteriores o sistemas SIEM.

## 6. Panorama complementario: Go (Golang) y C# (.NET) en ciberseguridad

Aunque Python es el lenguaje principal para automatización ágil, muchas herramientas de auditoría, agentes defensivos y aplicaciones empresariales están escritas en **Go** o **C#**, por lo que conviene reconocer ambos ecosistemas desde el inicio:

| Lenguaje | Dónde aparece en ciberseguridad | Por qué importa saber leerlo | Ejemplo mínimo representativo |
|---|---|---|---|
| **Go (Golang)** | Herramientas CLI de red y defensa (`ffuf`, `nuclei`, `ligolo-ng`, sensores eBPF/telemetría y parsers concurrentes de PCAP/logs). | Compila a un **único binario estático** sin dependencias externas en Linux/Windows y maneja alta concurrencia mediante *goroutines*. | `h := sha256.Sum256(data)` y `net.DialTimeout("tcp", addr, time.Second)` |
| **C# (.NET)** | Utilidades corporativas de administración Windows, APIs internas y herramientas de auditoría AD (`SharpView`, `SharpHound`, `Rubeus`). | Se integra nativamente con la API Win32, WMI y `System.DirectoryServices` en Windows, y puede inspeccionarse en claro con **ILSpy / dnSpyEx** (ver Etapa 3 del Curso de Reversing). | `DirectorySearcher` en LDAP y `WindowsIdentity.GetCurrent()` |

## Ejemplo paso a paso: Ejecución de los scripts del laboratorio

Ejecutá ambos scripts en tu entorno local contra `127.0.0.1` y un archivo de registros sintético para observar su comportamiento real.

**Paso 1:** probá el inventario local y comprobá además que el bloqueo de seguridad rechaza direcciones externas:

```bash
python3 laboratorios/auditor_red_local.py 127.0.0.1
python3 laboratorios/auditor_red_local.py 8.8.8.8
```

Salida esperada comentada:

```text
=== Inventario local de puertos en 127.0.0.1 (2026-11-22T20:10:05+00:00) ===
  [ABIERTO] TCP/22    | SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13  # Banner devuelto al conectar
  [ABIERTO] TCP/5050  | HTTP/1.1 200 OK                         # Respuesta tras enviar HEAD /
Total de puertos detectados: 2/14

[BLOQUEADO] Este script educativo solo permite direcciones loopback (127.0.0.0/8) o privadas RFC 1918.
```

**Paso 2:** generá un archivo de muestra combinado y procesalo con `analizador_logs_soc.py` usando un umbral de `3`:

```bash
cat <<'EOF' > /tmp/soc_muestra.log
Nov 22 11:00:01 srv sshd[101]: Failed password for invalid user test from 192.168.56.50 port 41001 ssh2
Nov 22 11:00:03 srv sshd[101]: Failed password for root from 192.168.56.50 port 41002 ssh2
Nov 22 11:00:05 srv sshd[101]: Failed password for admin from 192.168.56.50 port 41003 ssh2
192.168.56.50 - - [22/Nov/2026:11:01:00 +0000] "GET /admin HTTP/1.1" 404 162
EOF

python3 laboratorios/analizador_logs_soc.py /tmp/soc_muestra.log 3
```

Salida esperada comentada:

```json
{
  "archivo": "/tmp/soc_muestra.log",
  "total_alertas": 1,
  "alertas": [
    {
      "regla": "SOC-AUTH-001",
      "severidad": "media",
      "tactica_mitre": "Credential Access",
      "ip_origen": "192.168.56.50",
      "intentos_fallidos": 3,
      "usuarios_distintos": [
        "admin",
        "root",
        "test"
      ]
    }
  ]
}
```

Notá que la línea HTTP `404` no disparó `SOC-WEB-002` porque solo hubo `1` evento y el umbral efectivo para esa regla es `umbral * 3` (`9` respuestas `4xx`).

::: defensa Perspectiva defensiva y mitigación
Escribir scripts seguros es tan importante como analizar vulnerabilidades en sistemas ajenos:
- **Cadena de suministro en Python:** fijá versiones exactas de dependencias en `requirements.txt` (idealmente con hashes mediante `pip install --require-hashes`) y revisá paquetes con herramientas de auditoría como `pip-audit` antes de usarlos en un entorno operativo.
- **Prevención de ReDoS:** al diseñar expresiones regulares para analizar logs no confiables, evitá cuantificadores anidados ambiguos (como `(a+)+`) que pueden causar retroceso exponencial y bloquear un analizador SOC con una sola línea malformada.
- **Límites defensivos en herramientas propias:** incorporá siempre validación de alcance (`ipaddress`), `timeout` en red y subprocesos, lectura por bloques en archivos grandes y sanitización de rutas (`Path.resolve()`) para evitar recorridos inesperados.
- **Análisis estático continuo:** ejecutá `bandit` sobre tus propios scripts Python para detectar de forma temprana usos accidentales de `shell=True`, hashes débiles (`md5`/`sha1`), deserialización insegura o credenciales hardcodeadas.
:::

## Práctica en laboratorio local

Extendé en una copia local los conceptos vistos sobre los scripts de `laboratorios/`:

1. Creá una copia llamada `mi_auditor_local.py` basada en `laboratorios/auditor_red_local.py` que además calcule y muestre el hash **SHA-256** de su propio archivo fuente al inicio del reporte (para trazabilidad de evidencia) y acepte una opción `--json` con `argparse` para emitir el inventario de puertos en formato JSON.
2. Creá una copia llamada `mi_analizador_soc.py` basada en `laboratorios/analizador_logs_soc.py` que agregue una tercera regla `SOC-WEB-003` cuando una misma IP genere `>= 5` respuestas `401` (posible prueba repetida de credenciales HTTP), conservando el formato JSON de salida.
3. Probá ambos scripts sobre `127.0.0.1` y un log de prueba local, y verificá que no haya llamadas a `shell=True` ni manejo inseguro de archivos.

::: practica Entregable mínimo
Los dos scripts extendidos (`mi_auditor_local.py` y `mi_analizador_soc.py`), el archivo JSON de inventario generado contra `127.0.0.1` y la salida JSON de `mi_analizador_soc.py` disparando al menos dos reglas distintas sobre un log de prueba.
:::

## Preguntas de repaso

**1. ¿Por qué `laboratorios/auditor_red_local.py` utiliza `socket.connect_ex()` junto con `settimeout()` y un bloque `with`?** Porque `connect_ex()` devuelve un entero (`0` si conecta o el código `errno` si falla) sin lanzar excepciones en cada puerto cerrado, `settimeout()` impide que un puerto filtrado con paquetes descartados bloquee el script indefinidamente y el bloque `with` asegura que el descriptor del socket se libere de inmediato al terminar cada verificación.

**2. ¿Cuál es el riesgo concreto de ejecutar `subprocess.run(comando, shell=True)` cuando `comando` incluye datos externos?** Al activar `shell=True`, Python delega la interpretación de la cadena a `/bin/sh` o `cmd.exe`. Si la entrada contiene metacaracteres de shell (`;`, `|`, `&&`, `` ` `` o `$(...)`), el intérprete ejecuta comandos arbitrarios adicionales fuera de la intención del programa. Pasar una lista de argumentos con `shell=False` elimina esa superficie.

**3. ¿Por qué conviene calcular el SHA-256 de un archivo leyéndolo por bloques (por ejemplo, 64 KiB) en lugar de usar `Path.read_bytes()`?** Porque `read_bytes()` carga el archivo completo en memoria RAM de una sola vez, lo que puede agotar la memoria del equipo al verificar imágenes de disco, volcados de memoria o registros de varios gigabytes. Leer en bloques iterativos y llamar a `h.update(fragmento)` mantiene el consumo de RAM constante.

**4. ¿Qué ventaja ofrece usar grupos con nombre (`(?P<ip>...)`) en `re.compile()` dentro de `analizador_logs_soc.py`?** Hace que el código acceda a los campos por nombre semántico (`m.group("ip")`) en lugar de índices numéricos frágiles (`m.group(2)`). Si más adelante se añade un grupo de captura anterior en la expresión regular, el resto de la lógica no se rompe silenciosamente, y compilar el patrón una sola vez mejora el rendimiento al procesar miles de líneas.

**5. ¿En qué escenario profesional elegirías Go por encima de Python 3 para una utilidad de seguridad?** Cuando necesitás distribuir un binario estático único en sistemas donde no existe intérprete Python ni permiso para instalar dependencias, o cuando la herramienta requiere alta concurrencia real y bajo consumo de memoria (como un colector de telemetría o un proxy ligero de red).

## Antes de avanzar

- [ ] Sabés crear sockets TCP con `timeout` y validar direcciones privadas/loopback con `ipaddress`.
- [ ] Entendés cómo emitir peticiones HTTP seguras sin desactivar la verificación TLS y cómo parsear JSON, CSV y expresiones regulares compiladas.
- [ ] Podés calcular y comparar hashes SHA-256 por bloques usando `hashlib` y `hmac.compare_digest`.
- [ ] Comprendés el funcionamiento completo de `laboratorios/auditor_red_local.py` y `laboratorios/analizador_logs_soc.py`, y evitás siempre `subprocess(..., shell=True)`.

::: nota Puerta de salida
Con Bash, PowerShell y Python 3 dominados para automatizar inspecciones y analizar registros, ya tenés la caja de herramientas lista. En el Capítulo 1.7 vas a profundizar en los protocolos y servicios de red reales que aparecen detrás de cada puerto TCP/UDP descubierto.
:::

## Referencias y estándares abiertos

- Python Software Foundation — *Python 3 Standard Library Documentation (`socket`, `ipaddress`, `hashlib`, `subprocess`, `re`, `urllib`)*: https://docs.python.org/3/library/
- OWASP Foundation — *Command Injection Prevention Cheat Sheet*: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- NIST FIPS 180-4 — *Secure Hash Standard (SHS — familia SHA-2)*: https://csrc.nist.gov/publications/detail/fips/180/4/final
- IETF RFC 1918 — *Address Allocation for Private Internets*: https://datatracker.ietf.org/doc/html/rfc1918
- PyCQA — *Bandit: Security Linter for Python Code*: https://bandit.readthedocs.io/
