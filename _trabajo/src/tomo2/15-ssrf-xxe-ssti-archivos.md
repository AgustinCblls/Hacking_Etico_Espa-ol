::: nota Objetivo de la lección
Al finalizar este capítulo vas a comprender el funcionamiento interno y la remediación arquitectónica de seis familias críticas de vulnerabilidades del lado del servidor: salto de directorios (*Path Traversal / LFI*), carga insegura de archivos (*Unrestricted File Upload*), falsificación de peticiones del lado del servidor (*SSRF*), entidades externas XML (*XXE*), inyección de plantillas en servidor (*SSTI*) y deserialización insegura de objetos.
:::

**Prerrequisitos:** Capítulo 1.8 (HTTP), Capítulo 2.3 (Inyecciones en servidor) y Capítulo 2.5 (Control de acceso). **Duración sugerida:** 8 a 10 horas.

## 1. Path Traversal y Local File Inclusion (LFI)

Muchas aplicaciones web necesitan leer o servir archivos almacenados en el disco del servidor (por ejemplo, descargar un comprobante en PDF o cargar una plantilla regional). El fallo de **Path Traversal** ocurre cuando la aplicación toma un nombre de archivo enviado por el usuario y lo concatena directamente en una ruta del sistema de archivos (`os.path.join("/var/app/reportes", nombre_usuario)`).

Si la entrada contiene secuencias de navegación hacia el directorio padre (`../` en Linux o `..\` en Windows) o una ruta absoluta (`/etc/passwd`), el sistema operativo resuelve la ruta final **fuera del directorio previsto**. Cuando además el lenguaje del backend (como PHP con `include` o `require`) evalúa el archivo leído como código ejecutable, el fallo se denomina **Local File Inclusion (LFI)**.

### Por qué borrar `"../"` con `replace()` no funciona

Intentar limpiar la cadena haciendo `nombre.replace("../", "")` falla cuando el usuario envía secuencias anidadas o cuando `os.path.join("/base", "/etc/hosts")` descarta directamente `/base` porque el segundo argumento empieza con `/`.

### Solución canónica en ingeniería de software (`realpath` + verificación de prefijo)

La forma segura y definitiva en cualquier lenguaje consta de tres pasos:
1. Quedarse únicamente con el nombre base del archivo (`Path(entrada).name`) o mejor aún, usar un identificador interno en base de datos en lugar de recibir nombres de archivo desde el cliente.
2. Resolver la ruta canónica real en disco (eliminando enlaces simbólicos y referencias relativas) con `Path.resolve()`.
3. Comprobar matemáticamente que la ruta resuelta esté contenida dentro del directorio base autorizado usando `.is_relative_to()`.

```python
from pathlib import Path

DIRECTORIO_REPORTES = Path("/var/app/reportes").resolve()

def obtener_ruta_segura(nombre_solicitado: str) -> Path:
    # 1. Extraer solo el nombre base y construir ruta candidata
    candidata = (DIRECTORIO_REPORTES / Path(nombre_solicitado).name).resolve()
    # 2. Verificar que la ruta final resuelta permanezca dentro del directorio base
    if not candidata.is_relative_to(DIRECTORIO_REPORTES):
        raise PermissionError("Ruta fuera del directorio autorizado")
    return candidata
```

## 2. Carga segura de archivos (File Upload Hardening)

Permitir que los usuarios suban archivos (avatares, documentos PDF, planillas CSV) introduce riesgos graves si el servidor confía en los metadatos declarados por el navegador:
- La cabecera `Content-Type: image/png` del bloque `multipart/form-data` la escribe el cliente y puede falsificarse trivialmente.
- Si el archivo se guarda con el nombre original enviado por el usuario dentro de una carpeta pública del servidor web (*webroot*) donde el servidor ejecuta scripts (`.php`, `.aspx`, `.jsp`) o sirve `.html`/`.svg` (que pueden contener `<script>` activos en el mismo origen), la carga de archivos se transforma en ejecución de código en servidor o XSS almacenado.

### Lista de control arquitectónica para subida de archivos (OWASP File Upload Cheat Sheet)

| Control defensivo | Cómo implementarlo | Qué riesgo elimina |
|---|---|---|
| **Renombrado con UUID aleatorio** | Generar el nombre en el servidor (`f"{uuid.uuid4()}.pdf"`), descartando el `filename` del cliente. | Elimina Path Traversal, sobreescritura de archivos y dobles extensiones (`archivo.php.jpg`). |
| **Validación de contenido real (*Magic Bytes*)** | Inspeccionar los primeros bytes del archivo (`%PDF-`, `\x89PNG\r\n\x1a\n`) o recodificar la imagen con una biblioteca como Pillow. | Impide disfrazar un script o HTML bajo una cabecera `Content-Type: image/png`. |
| **Almacenamiento fuera del *webroot*** | Guardar los archivos en un directorio sin permisos de ejecución (o en almacenamiento de objetos separado) fuera de la carpeta pública del servidor web. | Impide que el servidor web interprete el archivo subido como un script ejecutable. |
| **Descarga con cabeceras de aislamiento** | Servir descargas desde un dominio estático separado (`cdn-archivos.ejemplo.local`) con `Content-Disposition: attachment` y `X-Content-Type-Options: nosniff`. | Impide que un SVG o HTML subido ejecute JavaScript dentro del origen principal de la aplicación. |

<!-- salto -->

## 3. Server-Side Request Forgery (SSRF)

**SSRF (incorporado en `A01:2025 – Broken Access Control` del OWASP Top 10:2025)** ocurre cuando una funcionalidad de la aplicación (por ejemplo "Importar imagen desde URL", "Previsualizar enlace" o "Probar webhook") acepta una URL proporcionada por el usuario y **el propio servidor backend realiza la petición de red hacia ese destino**.

¿Por qué es tan crítico aunque el servidor no muestre la respuesta completa?
Porque el servidor backend se encuentra **dentro de la red interna**:
- Puede conectarse a servicios que escuchan exclusivamente en loopback (`http://127.0.0.1:8080`, bases de datos locales, paneles de administración internos).
- Puede alcanzar otros servidores de la subred privada (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) que están protegidos desde internet por el firewall perimetral.

```text
[Cliente Externo] ──(URL: http://127.0.0.1:9000/admin)──► [Servidor Web Público]
                                                                  │
                                           (Petición originada desde 127.0.0.1)
                                                                  ▼
                                                   [Servicio Interno en Loopback]
```

### Cómo mitigar SSRF de forma robusta

Validar la URL solo con una expresión regular no basta (porque un nombre de dominio externo puede resolver en DNS a `127.0.0.1` o redirigir con un código `302 Found` hacia una IP interna). La defensa completa requiere:

1. **Lista blanca de dominios y esquemas:** permitir únicamente `https://` (y `http://` si es indispensable) hacia una lista cerrada de dominios confiables si el negocio lo permite.
2. **Resolución DNS y bloqueo de rangos privados antes de conectar:** resolver la dirección IP del host destino y verificar con el módulo `ipaddress` que sea una IP global pública (`ip.is_global`), rechazando cualquier dirección loopback (`127.0.0.0/8`, `::1`), privada (RFC 1918) o de enlace local (`169.254.0.0/16`).
3. **Desactivar redirecciones HTTP automáticas:** configurar el cliente HTTP con `allow_redirects=False` para que un servidor externo no pueda redirigir al backend hacia una IP interna en el segundo salto.

```python
import ipaddress
import socket
from urllib.parse import urlparse

def validar_url_anti_ssrf(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Esquema o host inválido")
    # Resolver todas las IPs asociadas al hostname y bloquear cualquier IP no global
    for info in socket.getaddrinfo(parsed.hostname, None):
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local:
            raise PermissionError(f"Destino interno bloqueado por política anti-SSRF: {ip}")
    return url
```

## 4. XML External Entities (XXE)

El estándar XML permite definir una **Declaración de Tipo de Documento (`<!DOCTYPE ...>`)** con entidades (`<!ENTITY nombre SYSTEM "file:///...">` o `"http://..."`). Cuando un parser XML antiguo o mal configurado procesa un documento XML enviado por el usuario con la resolución de entidades externas habilitada, el parser reemplaza la entidad por el contenido del archivo local o realiza una petición de red (SSRF).

### Mitigación en Python y otros entornos

- **En Python:** la biblioteca estándar `xml.etree.ElementTree` es segura frente a entidades externas de archivos por defecto en versiones modernas, pero para proteger también frente a expansiones exponenciales de entidades en memoria (*Billion Laughs / XML Bomb*), utilizá siempre el paquete **`defusedxml`** o desactivá explícitamente `resolve_entities=False` y `no_network=True` en `lxml.etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)`.
- **En Java / .NET:** deshabilitar por completo las declaraciones `DOCTYPE` (`http://apache.org/xml/features/disallow-doctype-decl` = `true`).

## 5. Server-Side Template Injection (SSTI) y Deserialización Insegura

### SSTI: nunca compilar datos del usuario como plantilla

Los motores de plantillas del lado del servidor (como **Jinja2** en Python, **Twig** en PHP o **Freemarker** en Java) son muy seguros cuando se usan correctamente: la plantilla es un archivo estático escrito por el desarrollador y los datos del usuario se pasan como **variables de contexto**.

El fallo **SSTI** ocurre cuando el desarrollador concatena la entrada del usuario **dentro de la cadena de la plantilla antes de renderizarla**:

```python
from flask import render_template_string

# PATRÓN VULNERABLE A SSTI (PROHIBIDO):
# La entrada del usuario forma parte del código fuente de la plantilla Jinja2.
# Si el usuario envía expresiones entre {{ ... }}, Jinja2 las evalúa en el servidor.
def render_inseguro(nombre_usuario):
    return render_template_string(f"<h1>Hola, {nombre_usuario}</h1>")

# PATRÓN SEGURO:
# La cadena de plantilla es fija y estática; el dato viaja como variable de contexto.
def render_seguro(nombre_usuario):
    return render_template_string("<h1>Hola, {{ nombre }}</h1>", nombre=nombre_usuario)
```

#### Identificación segura de motores de plantillas en SSTI (sondas aritméticas inocuas)

Para confirmar si un parámetro es vulnerable a SSTI durante una auditoría autorizada **no se deben usar payloads destructivos ni llamadas a clases del sistema operativo**; basta con una secuencia breve de expresiones aritméticas inocuas:

1. **Detectar evaluación:** enviá primero una expresión matemática simple como `{{7*7}}` o `${7*7}`. Si la aplicación devuelve `49` en lugar del texto literal, la entrada fue compilada como código de plantilla (causa raíz: concatenación previa al renderizado).
2. **Diferenciar sintaxis y motor:** si `{{7*7}}` evaluó a `49`, distinguí entre motores como **Jinja2** y **Twig** con `{{7*'7'}}` (sin invocar módulos ni archivos). Si evaluó `${7*7}`, comprobá variantes específicas de **Freemarker** o **Thymeleaf**.
3. **Documentar y remediar:** verificá que en alertas de WAF/logs queden bloqueadas estas expresiones en parámetros de texto y corregí el código pasando el dato dentro del diccionario de contexto de una plantilla estática.

| Motor de plantillas | Sonda aritmética inocua | Resultado si es vulnerable | Comportamiento en patrón seguro |
|---|---|---|---|
| **Jinja2 (Python)** | `{{7*7}}` y luego `{{7*'7'}}` | `49` y `7777777` (repetición de cadena) | Se renderiza literal `{{7*'7'}}` (escapado en HTML) |
| **Twig (PHP)** | `{{7*7}}` y luego `{{7*'7'}}` | `49` y `49` (coerción numérica) | Se renderiza literal `{{7*'7'}}` |
| **Freemarker (Java)** | `${7*7}` | `49` | Se renderiza literal `${7*7}` |
| **Thymeleaf (Java/Spring)** | `[[${7*7}]]` o `__${7*7}__` | `49` | Se renderiza literal o se rechaza en validación |

### Deserialización insegura de objetos

La **serialización** convierte un objeto en memoria en una secuencia de bytes o texto para guardarlo o transmitirlo; la **deserialización** reconstruye el objeto original. Formatos nativos de objetos de lenguaje como **`pickle` y `yaml.load()` en Python**, `ObjectInputStream` en Java, `BinaryFormatter` en .NET o `unserialize()` en PHP pueden instanciar clases arbitrarias y ejecutar métodos especiales (`__reduce__` en Python, `readObject` en Java) durante el mismo acto de deserializar.

- **Regla estricta de ingeniería:** **jamás deserialices datos provenientes de un cliente o red no confiable con `pickle.loads()` ni con `yaml.load()` sin `SafeLoader`**, ni uses deserializadores nativos inseguros de PHP (`unserialize()`, cadenas `phar://` en LFI) o .NET (`BinaryFormatter`, `ObjectDataProvider`, `NetDataContractSerializer`).
- **Alternativa segura:** usar formatos de datos puros sin ejecución de constructores arbitrarios (**JSON** con `json.loads()` o `yaml.safe_load()`) validados contra un esquema tipado (como `Pydantic` o `System.Text.Json`).

### Wrappers PHP en LFI y casos críticos recientes para SOC y Defensa (Log4Shell, Spring4Shell, Text4Shell)

- **LFI con wrappers y *Log Poisoning*:** en aplicaciones heredadas PHP, la inclusión insegura de archivos combinada con wrappers (`php://filter/convert.base64-encode/resource=...`) o con escritura controlada en logs locales (`User-Agent` registrado en `access.log`) permite leer código fuente o elevar LFI a ejecución de código. Por ello la remediación obliga a usar mapas de rutas fijas (`switch`/diccionario) y configurar `allow_url_include = Off`.
- **Log4Shell (`CVE-2021-44228`), Spring4Shell (`CVE-2022-22965`) y Text4Shell (`CVE-2022-42889`):** tres fallos emblemáticos del ecosistema Java donde cadenas no confiables (en cabeceras HTTP como `User-Agent`, parámetros de enlace de propiedades en Spring MVC o `StringSubstitutor` en Apache Commons Text) dispararon evaluaciones JNDI/LDAP remotas o alteración de propiedades del contenedor Tomcat. **Respuesta defensiva:** actualizar las bibliotecas críticas, deshabilitar resoluciones JNDI remotas (`log4j2.formatMsgNoLookups=true` en mitigación temporal + parche definitivo) y monitorear en el SIEM/WAF peticiones entrantes con marcadores `jndi:` o conexiones salientes anómalas originadas por el proceso Java hacia puertos LDAP/RMI externos.

### Metodología OAST / OOB en laboratorio (*Blind SSRF*, *Blind XXE* y Log4Shell)

Cuando el servidor procesa URLs, documentos XML o cadenas registradas en logs sin devolver el resultado de esa operación en la respuesta HTTP, la verificación controlada en un laboratorio aislado se apoya en pruebas **Out-of-Band (OAST / OOB)** contra un servidor de escucha local (como `interactsh` en red privada o un listener DNS/HTTP/LDAP propio en `127.0.0.1`):

| Escenario ciego (*Blind*) | Causa raíz | Confirmación OAST inocua en laboratorio | Telemetría y mitigación (Purple Team) |
|---|---|---|---|
| **Blind SSRF** | El backend realiza peticiones HTTP salientes hacia URLs del cliente sin validar IP/dominio. | Apuntar el parámetro a `http://127.0.0.1:9090/ssrf-<id>` (o subdominio DNS de escucha local) y confirmar la llegada del *hit* con `User-Agent` del backend. | Registrar conexiones salientes del servidor web; validar con `ip.is_global`, desactivar redirecciones (`allow_redirects=False`) y aplicar *egress filtering*. |
| **Blind XXE** | El parser XML tiene `DOCTYPE` y resolución de entidades externas habilitadas aunque no refleje el XML en la respuesta. | Enviar una declaración `<!DOCTYPE ...>` de prueba que referencie un recurso HTTP/DNS único del listener OAST del laboratorio, sin solicitar archivos locales reales. | Auditar configuraciones del parser (`defusedxml` en Python, `disallow-doctype-decl=true` en Java/.NET) y alertar resoluciones DNS/HTTP originadas por parsers XML. |
| **Log4Shell (`CVE-2021-44228`)** | Log4j2 vulnerable evalúa búsquedas `${jndi:...}` dentro de cadenas registradas en logs (como `User-Agent` o parámetros). | Enviar una sonda benigna con token identificador (`${jndi:ldap://127.0.0.1:1389/probe-<id>}`) hacia un listener pasivo de laboratorio (sin entregar carga ejecutable) para verificar si el proceso Java intenta conectar. | Actualizar Log4j2 a versión parcheada, verificar `log4j2.formatMsgNoLookups=true`, monitorear en WAF/SIEM patrones `jndi:` y bloquear tráfico saliente LDAP/RMI/DNS no autorizado desde contenedores Java. |

## 6. Ejemplo paso a paso: ciclo Purple Team de SSRF, SSTI y Upload en `app_lab_educativa.py`

Ejecutá el ciclo **Ataca → Detecta → Corrige y verifica** contra los pares SSRF, SSTI y Upload de `laboratorios/app_lab_educativa.py`:

```bash
# 1. SSRF: ATACA (/fetch-vulnerable) -> CORRIGE (/fetch-seguro devuelve 403)
curl -s "http://127.0.0.1:5050/fetch-vulnerable?url=http://169.254.169.254/latest/meta-data/"
curl -i "http://127.0.0.1:5050/fetch-seguro?url=https://127.0.0.1:5050/interno-metadata"

# 2. SSTI: ATACA (/plantilla-vulnerable evalúa 49) -> CORRIGE (/plantilla-seguro imprime literal)
curl -s "http://127.0.0.1:5050/plantilla-vulnerable?nombre=%7B%7B7*7%7D%7D"
curl -s "http://127.0.0.1:5050/plantilla-seguro?nombre=%7B%7B7*7%7D%7D"

# 3. DETECTA: inspeccioná los eventos SSRF_Internal_Target, SSRF_Bloqueado y SSTI_Probe
curl -s "http://127.0.0.1:5050/telemetria-lab"
```

Salida verificada:

```text
// /plantilla-vulnerable?nombre={{7*7}} -> evalúa Jinja2:
<h2>Perfil (Vulnerable): 49</h2>

// /plantilla-seguro?nombre={{7*7}} -> pasa como variable de contexto escapada:
<h2>Perfil (Seguro): {{7*7}}</h2>

// /fetch-seguro frente a loopback -> HTTP 403:
{"error":"Destino interno bloqueado por política anti-SSRF (127.0.0.1)"}
```

En paralelo, para contención de rutas en disco (`Upload`), extraer primero `Path(entrada).name` y comprobar `ruta.is_relative_to(base)` impide que un parámetro como `../../etc/passwd` escape de `./reportes_lab`, y `/upload-seguro` solo guarda tras validar magic bytes reales (`PNG`/`%PDF-`) bajo nombre `UUID`.

### Descompresión segura frente a **Zip Slip** (Path Traversal en archivos `.zip`/`.tar`)

Cuando una aplicación extrae archivos comprimidos cargados por usuarios sin inspeccionar el nombre de cada entrada interna (`zipinfo.filename` o `tarinfo.name`), un archivo malicioso puede incluir entradas con secuencias `../../` (por ejemplo `../../../../var/www/html/shell.py` o enlaces simbólicos en `.tar`) y sobrescribir archivos críticos fuera de la carpeta de extracción (*Zip Slip*).
- **Detección (Blue Team):** alertas de FIM/Sysmon (`Event ID 11` / `auditd`) ante creación o modificación de ejecutables, plantillas o crons originada por el proceso web durante operaciones de descompresión.
- **Mitigación:** jamás uses `zipfile.extractall()` ni `tarfile.extractall()` ciegos sobre entradas no confiables; antes de escribir cada miembro, resolvé `destino = (base_dir / miembro).resolve()`, exigí `destino.is_relative_to(base_dir.resolve())` y rechazá enlaces simbólicos o rutas absolutas.

::: defensa Perspectiva defensiva y mitigación
1. **Confinamiento de archivos (`Path.resolve()` + `.is_relative_to()`):** preferí siempre referenciar archivos por un ID numérico o UUID en base de datos en lugar de recibir rutas o nombres de archivo en parámetros HTTP.
2. **Aislamiento de red de salida (*Egress Filtering*):** un servidor web que no necesita iniciar conexiones hacia otros hosts internos debe tener restringido el tráfico saliente a nivel de firewall/red de contenedores, además de validar las URLs con `ipaddress.is_global`.
3. **Formatos de intercambio de datos seguros:** estandarizá `json.loads()` y `yaml.safe_load()`, prohibiendo `pickle` para cualquier dato que cruce una frontera de confianza.
:::

## Práctica en laboratorio local

1. **SSRF, SSTI y Upload en `app_lab_educativa.py`:** compará `/fetch-vulnerable` vs `/fetch-seguro`, `/plantilla-vulnerable` vs `/plantilla-seguro`, y probá enviar un archivo de texto renombrado `.png` a `POST /upload-vulnerable` frente a `POST /upload-seguro`, observando las alertas en `/telemetria-lab`.
2. **OWASP Juice Shop (`127.0.0.1:3000`):** completá los retos de **subida de archivos sin restricción de tipo/tamaño** o **XXE / SSRF** en la instancia local, verificando en logs del contenedor qué petición los disparó.
3. **Práctica unitaria y recursos externos:** escribí `test_defensas_servidor.py` validando `validar_url_anti_ssrf` contra `127.0.0.1`, `192.168.1.1` y `file:///`. Reforzá con los laboratorios de SSRF, XXE y SSTI de **PortSwigger Web Security Academy** y **DVWA** (*File Upload / File Inclusion*).

::: practica Entregable mínimo
Evidencia de ejecución **Ataca → Detecta → Corrige** sobre SSRF, SSTI y Upload en `app_lab_educativa.py`, reporte del reto resuelto en OWASP Juice Shop y `test_defensas_servidor.py` pasando al 100 %.
:::

## Preguntas de repaso

**1. ¿Por qué eliminar la subcadena `"../"` con `replace("../", "")` no es un control suficiente contra Path Traversal?** Porque pueden emplearse variaciones como barras invertidas en Windows (`..\`), secuencias anidadas (`....//` que al quitar `../` reconstruyen `../`) o rutas absolutas (`/etc/passwd`). La solución correcta es tomar solo el nombre base o un ID en base de datos, resolver la ruta canónica real con `Path.resolve()` y verificar que esté contenida en el directorio base con `.is_relative_to()`.

**2. ¿Por qué no basta con verificar la cabecera `Content-Type: image/png` ni la extensión `.png` al recibir un archivo subido por un usuario?** Porque tanto la cabecera `Content-Type` de la petición multipart como el nombre del archivo son cadenas de texto controladas por el cliente. Es obligatorio validar los *magic bytes* o decodificar la imagen en el servidor, renombrar el archivo con un UUID generado internamente y almacenarlo fuera del directorio de ejecución del servidor web.

**3. ¿Qué riesgo específico introduce una vulnerabilidad SSRF aunque el servidor web no devuelva el cuerpo de la respuesta HTTP al cliente?** Aunque sea un SSRF ciego (*Blind SSRF*), el servidor backend sigue enviando peticiones de red desde adentro del perímetro interno, lo que permite interactuar con servicios que escuchan en `127.0.0.1` o en subredes privadas RFC 1918 que estaban bloqueados desde internet por el firewall perimetral.

**4. ¿Cuál es la causa exacta de una vulnerabilidad de Server-Side Template Injection (SSTI) en motores como Jinja2 o Twig?** Ocurre cuando los datos enviados por el usuario se concatenan directamente dentro de la cadena de código fuente de la plantilla antes de compilarla, en lugar de pasarlos como variables dentro del diccionario de contexto de una plantilla estática.

**5. ¿Por qué es peligroso utilizar `pickle.loads()` o `yaml.load()` sobre datos enviados por un cliente en una cookie o petición HTTP?** Porque `pickle` y el cargador completo de PyYAML permiten instanciar clases arbitrarias de Python e invocar métodos como `__reduce__` durante el proceso mismo de deserialización, permitiendo ejecutar código arbitrario en el servidor. Para datos externos debe usarse siempre `json.loads()` o `yaml.safe_load()`.

## Antes de avanzar

Verificá que podés:
- Implementar contención canónica de rutas con `Path.resolve()` e `is_relative_to()`.
- Diseñar un flujo de subida de archivos con UUID, validación de contenido y almacenamiento fuera de webroot.
- Bloquear destinos internos y redirecciones en clientes HTTP del backend para prevenir SSRF.
- Distinguir entre pasar variables de contexto a una plantilla y concatenar cadenas en la plantilla.

::: nota Puerta de salida
Con estas seis familias de fallos de servidor dominadas, estamos listos para abordar la seguridad de arquitecturas modernas de APIs (REST y GraphQL), anomalías del protocolo HTTP y auditoría de código fuente: avanzá al **Capítulo 2.7 · Seguridad de APIs (REST/GraphQL), HTTP avanzado y revisión Whitebox**.
:::

## Referencias y estándares abiertos

- **OWASP Top 10:2025 (`A01:2025 – Broken Access Control [incl. SSRF]`, `A03:2025 – Software Supply Chain Failures`, `A08:2025 – Software or Data Integrity Failures` y `A10:2025 – Mishandling of Exceptional Conditions`) y OWASP ASVS 5.0 (Capítulo V5 — *File Handling*).**
- **OWASP File Upload Cheat Sheet, Server-Side Request Forgery Prevention Cheat Sheet, XML External Entity (XXE) Prevention Cheat Sheet & Deserialization Cheat Sheet.**
- **Documentación oficial de Python (`pathlib.Path.is_relative_to`, `ipaddress` y `defusedxml`).**
