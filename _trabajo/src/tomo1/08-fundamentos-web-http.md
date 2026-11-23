::: nota Objetivo de la lección
Al finalizar este capítulo vas a comprender en profundidad la arquitectura del protocolo HTTP (versiones 1.1, 2 y 3), el ciclo completo de una petición y respuesta web, la negociación criptográfica en TLS 1.3, la gestión del estado mediante cookies y sesiones, las políticas de aislamiento del navegador (Same-Origin Policy y CORS) y el uso de un proxy de inspección local para auditar el tráfico de aplicaciones propias en `127.0.0.1:5050`.
:::

**Prerrequisitos:** Capítulo 1.2 (Redes TCP/IP y DNS) y Capítulo 1.6 (Python 3 aplicado a seguridad). **Duración sugerida:** 5 a 7 horas (teoría y laboratorio local con Docker).

## 1. Arquitectura de las aplicaciones web modernas

Una aplicación web no es un bloque monolítico: es un sistema distribuido donde intervienen al menos cuatro componentes que conversan mediante protocolos estandarizados (RFC 9110 y RFC 9112):

1. **Agente de usuario (Navegador o cliente HTTP):** interpreta HTML, aplica hojas de estilo CSS, ejecuta JavaScript en un entorno aislado (*sandbox*), almacena cookies según directivas estrictas y aplica la política del mismo origen (*Same-Origin Policy*, SOP).
2. **Proxy inverso o balanceador (Nginx, Envoy, HAProxy):** recibe la conexión TLS externa, normaliza rutas, aplica límites de tasa (*rate limiting*), añade cabeceras de seguridad y reenvía la petición al servidor de aplicaciones interno.
3. **Servidor de aplicaciones (Backend en Python/Flask, Node.js, Go, .NET o Java):** ejecuta la lógica de negocio, valida la identidad del usuario, verifica permisos de autorización por recurso y serializa la respuesta en HTML o JSON.
4. **Capa de persistencia y servicios internos:** bases de datos relacionales (PostgreSQL, MySQL, SQLite), almacenes clave-valor para sesiones (Redis) y colas de mensajería.

```text
[Navegador / curl]
       │  HTTPS (TLS 1.3 sobre TCP/443)
       ▼
[Proxy Inverso: Nginx (127.0.0.1:8080)]
       │  HTTP interno
       ▼
[Backend: Flask app_lab_educativa.py (127.0.0.1:5050)]
       │  Consultas parametrizadas
       ▼
[Base de Datos SQLite / PostgreSQL]
```

Comprender qué valida cada capa es la base de toda auditoría web. Un error habitual de diseño consiste en delegar validaciones de seguridad al navegador o a clientes locales (como aplicaciones de escritorio, móviles o videojuegos): en cualquier arquitectura cliente-servidor, todo dato o control que viva exclusivamente del lado cliente puede ser inspeccionado o alterado enviando peticiones directas con `curl`, un script en Python o un proxy local. De ahí nace una regla universal de seguridad: **nunca confíes en validaciones ejecutadas solo del lado del cliente**.

## 2. Anatomía de una petición y respuesta HTTP

HTTP es un protocolo de capa de aplicación **sin estado inherente** (*stateless*): cada par petición/respuesta es independiente del anterior a menos que el servidor y el cliente intercambien un identificador explícito (cookie o token).

### Estructura de la petición (Request)

Una petición HTTP/1.1 se compone de cuatro partes separadas por saltos de línea `CRLF` (`\r\n`):

1. **Línea de petición:** método (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`), ruta del recurso (incluyendo *query string*) y versión del protocolo.
2. **Cabeceras (*Headers*):** pares `Nombre: Valor` con metadatos de host, tipo de contenido, autenticación y preferencias del cliente.
3. **Línea en blanco (`\r\n\r\n`):** delimita el fin de las cabeceras.
4. **Cuerpo (*Body*):** opcional; presente en peticiones `POST`, `PUT` o `PATCH` para transportar formularios, JSON o archivos.

```http
GET /buscar-seguro?q=redes HTTP/1.1
Host: 127.0.0.1:5050
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: application/json
Connection: close

```

### Semántica de los métodos y códigos de estado

| Método HTTP | Propósito arquitectónico | ¿Idempotente? | ¿Seguro (sin efectos secundarios)? |
|---|---|---|---|
| `GET` | Obtener la representación de un recurso sin modificar estado en servidor | Sí | Sí |
| `HEAD` | Igual que `GET`, pero el servidor devuelve solo las cabeceras sin cuerpo | Sí | Sí |
| `POST` | Procesar datos, crear un recurso subordinado o ejecutar una acción de negocio | No | No |
| `PUT` | Reemplazar de forma completa la representación de un recurso conocido | Sí | No |
| `PATCH` | Aplicar una modificación parcial sobre un recurso existente | No | No |
| `DELETE` | Eliminar un recurso específico previa verificación de permisos | Sí | No |
| `OPTIONS` | Consultar capacidades del servidor o realizar verificación previa (*preflight*) CORS | Sí | Sí |

Los **códigos de estado** en la respuesta se agrupan en cinco familias:
- **`1xx` (Informativos):** `101 Switching Protocols` (usado al actualizar una conexión HTTP a WebSockets).
- **`2xx` (Éxito):** `200 OK` (operación correcta), `201 Created` (recurso creado), `204 No Content` (éxito sin cuerpo).
- **`3xx` (Redirección):** `301 Moved Permanently`, `302 Found` (redirección temporal, frecuente tras iniciar sesión), `304 Not Modified` (uso de caché).
- **`4xx` (Error del cliente):** `400 Bad Request` (sintaxis inválida), `401 Unauthorized` (falta autenticación válida), `403 Forbidden` (autenticado pero sin permisos sobre el recurso), `404 Not Found`, `405 Method Not Allowed`, `429 Too Many Requests` (control de tasa activo).
- **`5xx` (Error del servidor):** `500 Internal Server Error` (excepción no controlada en el backend), `502 Bad Gateway`, `503 Service Unavailable`.

### Evolución: HTTP/1.1 vs. HTTP/2 vs. HTTP/3

| Característica | HTTP/1.1 (RFC 9112) | HTTP/2 (RFC 9113) | HTTP/3 (RFC 9114) |
|---|---|---|---|
| **Formato en cable** | Texto plano delimitado por `CRLF` | Binario dividido en tramas (*frames*) | Binario sobre tramas QUIC |
| **Transporte subyacente** | TCP (1 petición activa por conexión o pipelining limitado) | TCP con multiplexación de múltiples *streams* en 1 conexión | UDP + QUIC con multiplexación sin bloqueo TCP |
| **Cabeceras** | Texto repetido en cada petición | Comprimidas con HPACK | Comprimidas con QPACK |

Aunque HTTP/2 y HTTP/3 viajen en binario, los proxies de diagnóstico y las herramientas de desarrollador reconstruyen la vista semántica (`:method`, `:path`, `:authority`, cabeceras y cuerpo) para que puedas auditarlos con la misma claridad que HTTP/1.1.

## 3. Estado, cookies y cabeceras de seguridad

Como HTTP no guarda memoria entre peticiones, las aplicaciones mantienen sesiones emitiendo una cookie mediante la cabecera `Set-Cookie`. La seguridad de esa cookie depende de tres atributos críticos que siempre debés auditar:

```http
Set-Cookie: id_sesion=9f8e7d6c5b4a3210...; Path=/; Secure; HttpOnly; SameSite=Lax
```

| Atributo de Cookie | Qué protege | Riesgo si falta |
|---|---|---|
| `HttpOnly` | Impide que el motor JavaScript del navegador lea la cookie mediante `document.cookie`. | Si ocurre un fallo de inyección de scripts en el cliente, el script podría leer el identificador de sesión. |
| `Secure` | Obliga al navegador a transmitir la cookie únicamente sobre canales cifrados HTTPS (salvo `localhost` de desarrollo). | Exposición de la cookie si el usuario realiza una petición en texto claro HTTP. |
| `SameSite=Lax` o `Strict` | Controla si la cookie se adjunta en peticiones originadas desde otros sitios web. | Peticiones cruzadas no deseadas desde páginas externas (CSRF). |

### Cabeceras HTTP de endurecimiento defensivo

Todo servicio web moderno debe responder con un conjunto base de cabeceras defensivas verificables con `curl -I`:

| Cabecera HTTP | Valor recomendado de referencia | Función defensiva |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'` | Restringe desde qué orígenes el navegador puede cargar scripts, objetos o incrustar la página. |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Ordena al navegador conectarse exclusivamente por HTTPS durante los próximos 2 años. |
| `X-Content-Type-Options` | `nosniff` | Impide que el navegador adivine (*MIME sniffing*) el tipo de un archivo ignorando el `Content-Type` declarado. |
| `X-Frame-Options` | `DENY` (o `SAMEORIGIN`) | Bloquea la carga de la página dentro de un `<iframe>` externo (defensa contra *Clickjacking*). |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Evita filtrar rutas o parámetros sensibles en la cabecera `Referer` al navegar hacia otros dominios. |

## 4. Same-Origin Policy (SOP), CORS y TLS 1.3

La **Política del Mismo Origen (SOP)** es el pilar de aislamiento de los navegadores web. Dos URLs comparten el mismo origen **solo si coinciden exactamente en tres elementos**: esquema (`https`), host (`app.ejemplo.local`) y puerto (`443`).

Si un script cargado desde `https://sitio-a.local` intenta leer mediante `fetch()` una respuesta de `https://api.sitio-b.local`, el navegador bloquea la lectura a menos que `api.sitio-b.local` autorice explícitamente a ese origen mediante cabeceras **CORS (Cross-Origin Resource Sharing)**:

- `Access-Control-Allow-Origin: https://sitio-a.local` (lista blanca explícita del origen confiable).
- `Access-Control-Allow-Credentials: true` (si se requiere envío de cookies o cabeceras de autorización; **nunca** debe combinarse con orígenes comodín o reflejados sin validación).

Por debajo de HTTP, **TLS 1.3 (RFC 8446)** protege la confidencialidad e integridad del canal en un solo viaje de ida y vuelta (*1-RTT handshake*), eliminando algoritmos antiguos (como RC4, DES, 3DES, MD5, SHA-1 e intercambio RSA estático) y garantizando **Secreto Perfecto hacia Adelante (*Forward Secrecy*)** mediante Diffie-Hellman efímero sobre curvas elípticas (`ECDHE`).

## 5. Ejemplo paso a paso: inspección del laboratorio local con `curl` y Python

Vamos a levantar nuestra aplicación educativa de `laboratorios/` y verificar sus cabeceras y comportamiento HTTP sobre `127.0.0.1:5050`.

```bash
# 1. Iniciar la aplicación educativa local (o con docker compose up -d)
python laboratorios/app_lab_educativa.py &

# 2. Consultar cabeceras y cuerpo del endpoint /saludo-seguro
curl -i "http://127.0.0.1:5050/saludo-seguro?nombre=Agustin"
```

Salida real esperada:

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.12
Date: Sun, 22 Nov 2026 20:15:00 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 88
Content-Security-Policy: default-src 'self'; script-src 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Connection: close

<h1>Hola, Agustin</h1><p>Salida codificada con escape HTML y CSP activa.</p>
```

Observá cómo el servidor declara explícitamente `Content-Security-Policy`, `X-Content-Type-Options: nosniff` y `X-Frame-Options: DENY`. Si ahora consultamos el endpoint JSON parametrizado:

```bash
curl -s "http://127.0.0.1:5050/buscar-seguro?q=redes" | python -m json.tool
```

```json
{
  "consulta": "redes",
  "modo": "seguro_parametrizado",
  "resultados": [
    {
      "categoria": "redes",
      "id": 1,
      "nombre": "Router Lab A1",
      "precio": 120.0
    },
    {
      "categoria": "redes",
      "id": 2,
      "nombre": "Switch L2 Educativo",
      "precio": 240.0
    }
  ]
}
```

### Configuración de un proxy de inspección local (OWASP ZAP / Burp Suite Community)

Un proxy de inspección HTTP se sitúa en tu propia máquina (por ejemplo en `127.0.0.1:8080`) entre el navegador de pruebas y la aplicación local (`127.0.0.1:5050`):
1. En el proxy local, verificá que el listener escuche **únicamente en `127.0.0.1`** (nunca en `0.0.0.0`) para evitar que otros equipos de la red usen tu proxy.
2. Usá el navegador integrado del proxy (o un perfil de Firefox exclusivo de laboratorio con la extensión FoxyProxy apuntando a `127.0.0.1:8080`).
3. En la pestaña **HTTP History**, revisá cada petición y respuesta sin necesidad de pausar el tráfico; cuando quieras probar cómo reacciona el backend ante distintos encabezados o métodos HTTP, enviá la petición al módulo **Repeater / Manual Request Editor**.

::: defensa Perspectiva defensiva y mitigación
1. **Validación en el servidor como única fuente de verdad:** toda regla de longitud, tipo de dato, autenticación y autorización debe ejecutarse en el backend; el código en el navegador solo mejora la experiencia de usuario.
2. **Plantilla de cabeceras en el proxy inverso:** centralizá `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` y `Content-Security-Policy` en la configuración de Nginx o del framework web para que ningún endpoint quede desprotegido por olvido.
3. **Cookies endurecidas por defecto:** configurá el motor de sesiones del framework con `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SECURE = True` y `SESSION_COOKIE_SAMESITE = 'Lax'`.
:::

## Práctica en laboratorio local

1. Levantá el entorno local ejecutando `python laboratorios/app_lab_educativa.py` (o `docker compose up -d` dentro de `laboratorios/`).
2. Ejecutá `curl -i` contra los tres endpoints (`/`, `/buscar-seguro?q=defensa` y `/saludo-seguro?nombre=Prueba`) y guardá las respuestas completas.
3. Probá el endpoint `/ticket-seguro/1?user=ana` y luego `/ticket-seguro/1?user=carlos`. Observá el cambio de código de estado HTTP (`200 OK` frente a `403 Forbidden`) y registrá por qué ocurre al leer el código fuente de `laboratorios/app_lab_educativa.py`.
4. Escribí un pequeño script en Python 3 con `urllib.request` o `requests` que consulte `http://127.0.0.1:5050/saludo-seguro` y verifique automáticamente si están presentes las tres cabeceras `Content-Security-Policy`, `X-Content-Type-Options` y `X-Frame-Options`.

::: practica Entregable mínimo
Un archivo `bitacora_cap1_8.md` con las salidas HTTP capturadas de los tres endpoints, la comparación entre el código `200` y `403` de `/ticket-seguro/1`, y el script en Python de auditoría de cabeceras de seguridad.
:::

## Preguntas de repaso

**1. ¿Por qué decimos que una validación escrita solo en el JavaScript del navegador o en un atributo HTML `maxlength` no constituye un control de seguridad?** Porque el cliente está bajo control total del usuario. Cualquier herramienta como `curl`, un script en Python o un proxy local envía peticiones HTTP directamente al servidor sin pasar por el DOM ni ejecutar el JavaScript del navegador; por lo tanto, toda validación de seguridad debe aplicarse obligatoriamente en el servidor.

**2. ¿Cuál es la diferencia técnica entre los códigos de estado HTTP `401 Unauthorized` y `403 Forbidden`?** El código `401` indica que la petición carece de credenciales de autenticación válidas (el servidor no sabe quién sos o tu token expiró). El código `403` indica que el servidor comprendió la petición y conoce tu identidad, pero tu cuenta no tiene permisos de autorización para acceder a ese recurso específico.

**3. ¿Qué función cumple cada uno de los tres atributos `HttpOnly`, `Secure` y `SameSite=Lax` en una cookie de sesión?** `HttpOnly` prohíbe el acceso a la cookie desde JavaScript (`document.cookie`), protegiéndola frente a robo mediante scripts en el cliente. `Secure` garantiza que la cookie solo viaje sobre conexiones cifradas HTTPS. `SameSite=Lax` impide que la cookie se envíe automáticamente en peticiones subyacentes originadas desde sitios externos (como formularios `POST` o llamadas `fetch` cruzadas), mitigando ataques CSRF.

**4. ¿Qué tres componentes definen un "origen" en la política Same-Origin Policy (SOP)?** El esquema o protocolo (por ejemplo `https`), el nombre de host completo (`app.ejemplo.local`) y el puerto TCP (`443`). Si cualquiera de los tres cambia, el navegador los considera orígenes distintos y aísla el acceso al DOM y a las lecturas de red entre ambos.

**5. ¿Por qué un proxy de inspección local como Burp Suite o OWASP ZAP debe configurarse para escuchar únicamente en `127.0.0.1` y no en `0.0.0.0`?** Porque escuchar en `0.0.0.0` expone el puerto del proxy en todas las interfaces de red de la máquina, permitiendo que otros dispositivos de la red local enruten tráfico a través de tu estación de trabajo o inspeccionen sesiones activas del proxy.

## Antes de avanzar

Verificá que podés:
- Leer una petición y una respuesta HTTP cruda identificando método, código de estado, cabeceras y cuerpo.
- Explicar para qué sirven `CSP`, `HSTS`, `X-Content-Type-Options`, `X-Frame-Options` y los atributos de cookies.
- Auditar localmente `laboratorios/app_lab_educativa.py` con `curl` y con un script en Python.

::: nota Puerta de salida
Si ya inspeccionaste peticiones y cabeceras HTTP en `127.0.0.1:5050` y comprendés cómo operan cookies, SOP y CORS, estás listo para cerrar el **Tomo I** estudiando la base criptográfica que protege HTTPS/TLS y los certificados digitales: avanzá al **Capítulo 1.9 · Criptografía aplicada, certificados X.509, PKI y seguridad TLS**.
:::

## Referencias y estándares abiertos

- **RFC 9110 (HTTP Semantics) y RFC 9112 (HTTP/1.1):** especificaciones oficiales del IETF sobre métodos, cabeceras y códigos de estado.
- **RFC 8446 (The Transport Layer Security Protocol Version 1.3):** arquitectura del handshake TLS 1.3 y suites criptográficas con Forward Secrecy.
- **OWASP Secure Headers Project:** guía abierta de configuración y verificación de cabeceras HTTP defensivas.
- **MDN Web Docs — Same-Origin Policy & HTTP Cookies:** documentación técnica sobre aislamiento de orígenes y ciclo de vida de cookies en navegadores modernos.
