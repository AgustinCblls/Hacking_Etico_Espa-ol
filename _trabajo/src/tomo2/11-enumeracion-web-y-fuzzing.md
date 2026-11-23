::: nota Objetivo de la lección
Al terminar este capítulo vas a saber realizar un inventario completo de la superficie expuesta de una aplicación web en tu laboratorio local: identificar tecnologías del stack (*fingerprinting*), inspeccionar archivos de metadatos (`robots.txt`, `sitemap.xml`, `security.txt`), descubrir rutas, parámetros y *virtual hosts* con `ffuf` aplicando filtros precisos para eliminar ruido, y analizar archivos JavaScript del lado cliente para mapear endpoints de API y lógica expuesta.
:::

**Prerrequisitos:** Capítulo 1.8 (Fundamentos Web y HTTP) y Capítulo 2.1 (Reconocimiento y Nmap). **Duración sugerida:** 5 a 7 horas.

## 1. Metodología de inventario de superficie web

Cuando auditás una aplicación web autorizada, lo que ves en la página principal rara vez representa el 100 % del sistema. Detrás de la interfaz principal suelen coexistir paneles administrativos, versiones anteriores de APIs (`/api/v1/`, `/api/v2/`), archivos de configuración o endpoints de diagnóstico que quedaron habilitados tras el despliegue.

De acuerdo con la guía **OWASP Web Security Testing Guide (WSTG-INFO)**, el relevamiento técnico de una aplicación web se divide en cuatro fases ordenadas de menor a mayor interacción:

1. **Inspección pasiva de respuestas y cabeceras:** análisis de encabezados HTTP, cookies, códigos de estado y certificados TLS devueltos en una navegación normal.
2. **Revisión de archivos estándar y metadatos:** lectura de `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/crossdomain.xml` y manifiestos de aplicación (`manifest.json`).
3. **Análisis estático del código entregado al cliente:** inspección del HTML, comentarios de desarrollo, mapas de código (*source maps* `.js.map`) y paquetes JavaScript (*bundles*) donde se definen las rutas hacia el backend.
4. **Descubrimiento activo controlado (*Fuzzing* de contenido):** sondeo metódico de rutas, extensiones, parámetros y nombres de host virtuales (*vhosts*) mediante diccionarios adaptados a la tecnología detectada.

## 2. Identificación del stack tecnológico (Fingerprinting)

Antes de lanzar cualquier diccionario de rutas conviene saber qué tecnología ejecuta el servidor. No tiene sentido buscar rutas `.aspx` en un servidor que corre Python/Flask sobre Linux, ni buscar endpoints de Spring Boot en una aplicación PHP.

### Pistas observables en una petición estándar

| Fuente de observación | Ejemplo de evidencia | Tecnología revelada |
|---|---|---|
| Cabeceras `Server` / `X-Powered-By` | `Server: Werkzeug/3.0.3 Python/3.12` o `X-Powered-By: Express` | Lenguaje, framework y versión exacta del motor HTTP. |
| Nombre de la cookie de sesión | `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `connect.sid`, `session` | PHP, Java/Servlet, ASP.NET, Node.js/Express, Python/Flask. |
| Estructura de rutas y activos | `/_next/static/`, `/wp-content/`, `/static/admin/css/` | Next.js, WordPress, Django Admin. |
| Páginas de error por defecto | Traza de error con formato específico ante un `404` o `400` | Servidor web (Nginx, Apache, IIS, Tomcat) o framework subyacente. |

```bash
# Inspección rápida de cabeceras y archivos de metadatos en el laboratorio local
curl -sI http://127.0.0.1:5050/
curl -i http://127.0.0.1:8080/robots.txt
curl -i http://127.0.0.1:8080/sitemap.xml
```

::: nota Por qué ocultar la versión no reemplaza el parcheo
Desactivar la versión en la cabecera `Server` (por ejemplo con `server_tokens off;` en Nginx) es una buena práctica de higiene para dificultar el inventario automatizado, pero un analista siempre puede deducir el stack por el comportamiento de las cookies, el orden de las cabeceras o las respuestas ante peticiones malformadas. La seguridad real depende de mantener las dependencias actualizadas y bien configuradas.
:::

<!-- salto -->

## 3. Descubrimiento controlado con `ffuf` y filtrado de ruido

**`ffuf` (Fuzz Faster U Fool)** es una herramienta escrita en Go diseñada para realizar descubrimiento de contenido web reemplazando la palabra clave `FUZZ` en la URL, en las cabeceras o en el cuerpo de una petición por cada línea de un diccionario (*wordlist*).

La habilidad que distingue a un profesional de alguien que ejecuta herramientas a ciegas es **la calibración y el filtrado**. Muchas aplicaciones modernas (especialmente las *Single-Page Applications* en React, Vue o Angular) devuelven código `200 OK` con la misma plantilla HTML de inicio para cualquier ruta inexistente (*soft 404*). Si no filtrás por tamaño, palabras o líneas, obtendrás miles de falsos positivos.

### Opciones esenciales de `ffuf`

| Opción | Función técnica | Cuándo usarla |
|---|---|---|
| `-u URL` | Define la URL objetivo incluyendo el marcador `FUZZ`. | Siempre (`http://127.0.0.1:5050/FUZZ`). |
| `-w ruta` | Especifica la lista de palabras (*wordlist*) a utilizar. | Siempre (elegir listas específicas y acotadas según el stack). |
| `-mc` / `-fc` | Incluye (*match*) o excluye (*filter*) códigos de estado HTTP. | `-fc 404` para ocultar recursos no encontrados. |
| `-fs N` | Excluye respuestas con un tamaño exacto de `N` bytes. | Cuando el servidor devuelve un *soft 404* con `200 OK` de tamaño fijo. |
| `-fw N` / `-fl N` | Excluye respuestas con `N` palabras o `N` líneas. | Cuando el *soft 404* refleja la ruta buscada (cambiando el tamaño en bytes, pero manteniendo constante el número de palabras). |
| `-ac` | Calibración automática (*auto-calibrate*): prueba rutas aleatorias inexistentes al inicio y configura los filtros sola. | Muy recomendable al empezar contra un servicio desconocido en el lab. |
| `-rate N` / `-t N` | Limita la tasa de peticiones por segundo y el número de hilos concurrentes. | Obligatorio en auditorías reales para no degradar el servicio (`-rate 30 -t 10`). |
| `-H "Cabecera: Valor"` | Añade una cabecera HTTP personalizada (útil para descubrir *Virtual Hosts* con `Host: FUZZ.lab.local`). | En auditoría de múltiples subdominios alojados en una misma IP. |

### Casos de uso prácticos en laboratorio

```bash
# 1. Descubrimiento de rutas en la aplicación local con calibración automática y límite de tasa
ffuf -u http://127.0.0.1:5050/FUZZ -w diccionarios/rutas_web.txt -ac -rate 50 -t 10

# 2. Descubrimiento de parámetros GET aceptados por un endpoint conocido
ffuf -u "http://127.0.0.1:5050/buscar-seguro?FUZZ=redes" -w diccionarios/parametros.txt -ac

# 3. Descubrimiento de Virtual Hosts (vhosts) enviando la cabecera Host contra el proxy local
ffuf -u http://127.0.0.1:8080/ -H "Host: FUZZ.lab.local" -w diccionarios/subdominios.txt -ac
```

::: nota Alternativas habituales en laboratorio (`gobuster`, `feroxbuster` y `Caido`)
Además de `ffuf`, en auditorías modernas vas a ver **`gobuster`** (`gobuster dir -u http://127.0.0.1:5050 -w ...`) y **`feroxbuster`** (escrito en Rust, ideal para descubrimiento **recursivo automático** de subdirectorios con autocalibración). Para inspección manual e intercepción de peticiones HTTP/S junto a Burp Suite Community u OWASP ZAP, **`Caido`** ofrece una arquitectura cliente-servidor ligera en Rust orientada a flujos repetibles y filtros rápidos.
:::

## 4. Análisis y desofuscación de JavaScript del lado cliente

En aplicaciones modernas basadas en APIs REST o GraphQL, el navegador descarga archivos `.js` que contienen toda la tabla de enrutamiento del frontend, los nombres exactos de los endpoints del backend, los parámetros esperados y comentarios o constantes olvidados.

### Qué buscar al auditar archivos JavaScript

1. **Rutas de API y endpoints internos:** cadenas que comienzan con `/api/`, `/v1/`, `/internal/`, `/admin/`, `/graphql` o llamadas a `fetch()`, `axios.get()`, `axios.post()` y `XMLHttpRequest`.
2. **Archivos `.js.map` (Source Maps):** si el servidor publica el archivo `main.bundle.js.map` en producción, las herramientas de desarrollador del navegador reconstruyen el árbol completo del código fuente original en TypeScript/React con sus nombres de variables y comentarios intactos.
3. **Validaciones o controles de interfaz en el cliente:** condiciones como `if (user.role === 'admin') { mostrarBotonPanel(); }` revelan qué rutas administrativas existen en el backend para verificar luego si el servidor valida realmente el rol o solo ocultaba el botón.

### Desofuscación y lectura de código minificado

Existe una diferencia fundamental entre **minificación** y **ofuscación**:
- **Minificación (Webpack, Vite, Esbuild, Terser):** elimina espacios, saltos de línea y acorta nombres de variables locales para reducir el peso del archivo. Se revierte en un clic con el botón **Pretty Print (`{}`)** de las DevTools del navegador o con herramientas como `js-beautify`.
- **Ofuscación (codificación en arreglos hexadecimales, `eval`, `atob`, rotación de tablas de strings):** busca dificultar la lectura estática, pero como el navegador necesita ejecutar las instrucciones reales, siempre se puede analizar de forma segura sin ejecutar código desconocido o inspeccionando las funciones decodificadoras en un entorno aislado.

```python
# Ejemplo didáctico en Python para extraer rutas tipo /api/... de un bundle JS descargado en el lab
import re, sys

texto_js = open(sys.argv[1], "r", encoding="utf-8", errors="replace").read()
rutas = sorted(set(re.findall(r'["\'](/[a-zA-Z0-9_\-/]+)["\']', texto_js)))
for r in rutas:
    print("  Ruta detectada:", r)
```

## 5. Auditoría de aplicaciones comunes y CMS (WordPress, Joomla y Drupal)

En evaluaciones reales es habitual encontrarse con **Sistemas de Gestión de Contenidos (CMS)** como **WordPress**, **Joomla** o **Drupal**, así como aplicaciones estándar (GitLab, Jenkins, paneles internos) que exponen rutas predecibles y suelen fallar por **plugins desactualizados** o **configuraciones por defecto** más que por el núcleo del CMS.

### Superficie crítica al auditar WordPress en laboratorio autorizado

| Vector / Ruta en WordPress | Qué revisar en auditoría | Mitigación recomendada |
|---|---|---|
| `/wp-content/plugins/` y `/wp-content/themes/` | Versiones exactas de plugins y temas (`readme.txt`) que pueden contener CVEs públicos conocidos; listado de directorios abierto. | Mantener actualizaciones automáticas del núcleo y plugins, eliminar plugins sin uso y desactivar *Directory Indexing*. |
| `/wp-json/wp/v2/users` y `/?author=1` | **Enumeración pública de nombres de usuario** vía REST API o redirección por ID de autor. | Restringir la exposición del endpoint `/wp/v2/users` a usuarios autenticados. |
| `/xmlrpc.php` | Interfaz XML-RPC heredada que permite realizar múltiples intentos de autenticación dentro de una única petición HTTP (`system.multicall`) y amplificación SSRF/pingback. | Bloquear completamente el acceso a `xmlrpc.php` en Nginx/Apache si no se usa activamente. |
| `/wp-login.php` y `wp-config.php~` | Falta de límite de tasa o MFA en el login, y copias de respaldo olvidadas (`wp-config.php.bak`) accesibles por HTTP. | Activar 2FA, limitar tasa de peticiones y mover/denegar copias temporales fuera del webroot. |

En un entorno autorizado, herramientas especializadas como **`wpscan`** (o enumeración dirigida con `ffuf`) agilizan la correlación de versiones de plugins contra bases de CVEs, siempre limitando la tasa de peticiones para no saturar el servidor.

<!-- salto -->

## 6. Ejemplo paso a paso: mapeo completo de nuestra app de laboratorio

Veamos cómo combinar la inspección manual, un micro-diccionario y el análisis de respuestas sobre `http://127.0.0.1:5050`:

```bash
# Paso 1: Crear un diccionario mínimo de prueba en el laboratorio
cat << 'EOF' > /tmp/wordlist_lab.txt
admin
login
buscar-seguro
saludo-seguro
ticket-seguro/1
status
health
EOF

# Paso 2: Probar cada ruta con curl mostrando código HTTP y tamaño en bytes
while read -r ruta; do
  curl -s -o /dev/null -w "Ruta: /%-18s -> HTTP %{http_code} (%{size_download} bytes)\n" "http://127.0.0.1:5050/$ruta"
done < /tmp/wordlist_lab.txt
```

Salida comentada del laboratorio:

```text
Ruta: /admin              -> HTTP 404 (207 bytes)
Ruta: /login              -> HTTP 404 (207 bytes)
Ruta: /buscar-seguro      -> HTTP 200 (283 bytes)
Ruta: /saludo-seguro      -> HTTP 200 (88 bytes)
Ruta: /ticket-seguro/1    -> HTTP 403 (51 bytes)
Ruta: /status             -> HTTP 404 (207 bytes)
Ruta: /health             -> HTTP 404 (207 bytes)
```

Observá tres hallazgos inmediatos a partir de una tabla tan simple:
1. Todas las rutas inexistentes devuelven `404` con un tamaño exacto de `207 bytes` (nuestro valor de referencia para filtrar ruido con `-fc 404` o `-fs 207`).
2. `/buscar-seguro` y `/saludo-seguro` responden `200 OK` con longitudes distintas.
3. `/ticket-seguro/1` devuelve `403 Forbidden` (51 bytes): ¡eso confirma que el recurso existe y está protegido por una validación de acceso que acepta un parámetro de usuario!

::: defensa Perspectiva defensiva y mitigación
1. **No publicar artefactos de compilación ni `.git` en el webroot:** bloqueá explícitamente en Nginx/Apache el acceso a directorios ocultos (`location ~ /\. { deny all; }`) y excluí los archivos `*.js.map` del paquete de producción.
2. **No confiar en rutas "secretas" (seguridad por oscuridad):** cualquier endpoint administrativo o interno debe exigir autenticación fuerte y control de acceso en el servidor, además de restringirse a la red de administración o VPN interna.
3. **Monitoreo y limitación de tasa (*Rate Limiting*):** un pico repentino de respuestas `404`/`403` desde una misma IP es la huella clásica del fuzzing de directorios (detectable con `laboratorios/analizador_logs_soc.py` bajo la regla `SOC-WEB-002`).
:::

## Práctica en laboratorio local

1. Levantá el entorno local con `python laboratorios/app_lab_educativa.py`.
2. Creá un diccionario de 20 rutas en tu carpeta temporal que incluya las rutas válidas de la aplicación y 15 rutas inexistentes.
3. Ejecutá el bucle de inventario (o `ffuf` con `-fc 404`) contra `http://127.0.0.1:5050/FUZZ` y documentá todas las rutas que devuelven códigos `200` o `403`.
4. Guardá los logs generados por la aplicación o por Nginx en un archivo `acceso_lab.log` y pasalos por `python laboratorios/analizador_logs_soc.py acceso_lab.log 3` para observar cómo el SOC detecta el barrido de rutas `404`.

::: practica Entregable mínimo
Tabla comparativa en tu bitácora con las rutas descubiertas, sus códigos HTTP y tamaños en bytes, junto con la salida JSON de `analizador_logs_soc.py` detectando el patrón de enumeración.
:::

## Preguntas de repaso

**1. ¿Qué es un "soft 404" y cómo se filtra correctamente al usar `ffuf`?** Un *soft 404* ocurre cuando una aplicación web devuelve el código de estado `200 OK` (en lugar de `404 Not Found`) junto con una plantilla genérica para cualquier ruta que no existe. Para filtrarlo en `ffuf`, se utiliza `-fs <bytes>` (si el tamaño de la página genérica es fijo), `-fw <palabras>` (si el tamaño varía porque refleja el nombre de la ruta pero la cantidad de palabras es constante) o la opción `-ac` de calibración automática.

**2. ¿Por qué es un riesgo dejar archivos `.js.map` (Source Maps) accesibles públicamente en un entorno de producción?** Porque los *source maps* contienen el mapeo completo y a menudo el código fuente original sin minificar (TypeScript/JavaScript), exponiendo comentarios internos, nombres de funciones, estructura de carpetas del proyecto y rutas de API que no estaban destinadas a ser documentadas públicamente.

**3. ¿Cómo permite la cabecera HTTP `Host` descubrir múltiples sitios o aplicaciones alojados en una misma dirección IP?** Un servidor web como Nginx o Apache utiliza el valor de la cabecera `Host` de la petición HTTP para decidir a qué bloque `server` (*Virtual Host*) debe entregar la solicitud. Al variar la cabecera `Host: subdominio.ejemplo.local` apuntando a la misma IP del servidor en un entorno autorizado, es posible identificar aplicaciones secundarias que no estaban listadas en el DNS público.

**4. ¿Por qué la presencia de una ruta en `Disallow:` dentro de `/robots.txt` no protege ese directorio?** Porque `robots.txt` es únicamente una indicación voluntaria para buscadores indexadores bien comportados. No aplica ningún control de acceso: por el contrario, publicar rutas administrativas o privadas en `robots.txt` le informa a cualquier visitante exactamente dónde se encuentran.

**5. ¿Qué señal en los logs del servidor web permite al equipo defensivo (SOC) detectar un escaneo de directorios en curso?** Una ráfaga de peticiones HTTP desde una misma dirección IP en un intervalo corto de tiempo que genera una proporción elevada de respuestas `404 Not Found` o `403 Forbidden` sobre rutas secuenciales.

## Antes de avanzar

Verificá que podés:
- Identificar tecnologías de un servicio web a partir de sus cabeceras, cookies y estructura de respuestas.
- Filtrar respuestas repetitivas por código, tamaño o cantidad de palabras durante un descubrimiento de rutas en laboratorio.
- Extraer endpoints de API leyendo el código JavaScript entregado al navegador.

::: nota Puerta de salida
Una vez que tenés el mapa completo de rutas y parámetros de la aplicación de laboratorio, el siguiente paso es analizar cómo procesa el servidor las entradas recibidas en cada parámetro: avanzá al **Capítulo 2.3 · Inyecciones en servidor**.
:::

## Referencias y estándares abiertos

- **OWASP Web Security Testing Guide (WSTG v4.2) — Secciones 4.1 (Information Gathering) y 4.2 (Configuration and Deployment Management Testing):** metodología estándar de inventario web.
- **RFC 9309 (Robots Exclusion Protocol):** especificación oficial del estándar `robots.txt` y sus alcances.
- **RFC 9116 (`security.txt`):** estándar para la publicación de contactos y políticas de reporte responsable de vulnerabilidades.
- **Documentación oficial de `ffuf` (GitHub / Open Source):** guía de filtros, calibración automática y control de tasa.
