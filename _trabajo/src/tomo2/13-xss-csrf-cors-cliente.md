::: nota Objetivo de la lección
Al finalizar este capítulo vas a comprender cómo procesa el navegador el árbol DOM, por qué ocurren las vulnerabilidades del lado del cliente —Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), Clickjacking y configuraciones permisivas de CORS—, cómo distinguir entre XSS Reflejado, Almacenado y basado en DOM, y cómo implementar una defensa en profundidad sólida combinando codificación contextual de salida, Content Security Policy (CSP), cookies `SameSite`/`HttpOnly` y tokens sincronizados.
:::

**Prerrequisitos:** Capítulo 1.8 (HTTP, cookies y SOP) y Capítulo 2.3 (Separación entre código y datos). **Duración sugerida:** 6 a 8 horas.

## 1. Seguridad en el navegador y el modelo de confianza del origen

En el capítulo anterior vimos qué ocurre cuando el servidor mezcla datos del usuario con instrucciones SQL o de consola. Del lado del cliente ocurre un fenómeno análogo: **el navegador recibe un documento HTML y no tiene forma nativa de distinguir si una etiqueta o atributo de script fue escrito por el desarrollador del sitio o proviene de un dato no escapado**.

Si un dato no confiable logra interpretarse como código JavaScript activo dentro de la página, ese script se ejecuta **bajo el mismo origen (SOP)** de la aplicación. En consecuencia, hereda los permisos que el navegador le otorga a ese origen:
- Puede leer y modificar el árbol DOM de la página actual.
- Puede enviar peticiones HTTP (`fetch` / `XMLHttpRequest`) hacia el backend adjuntando las credenciales de la sesión activa.
- Puede acceder a `localStorage`, `sessionStorage` y a cualquier cookie que no tenga activado el atributo `HttpOnly`.

## 2. Cross-Site Scripting (XSS): clasificación y contextos de salida

El estándar **OWASP** clasifica los fallos de Cross-Site Scripting en tres categorías según dónde se origina y dónde se inserta el dato no confiable:

| Tipo de XSS | Dónde se procesa el dato sin escapar | Flujo técnico |
|---|---|---|
| **Reflejado (*Reflected XSS*)** | En el **servidor** (respuesta inmediata). | El servidor toma un parámetro de la petición HTTP (por ejemplo `?nombre=...`) y lo inserta directamente en el HTML devuelto sin codificar entidades. |
| **Almacenado (*Stored / Persistent XSS*)** | En el **servidor** (tras leerse de la base de datos). | La aplicación guarda un dato (comentario, perfil, nombre de ticket) en la base de datos y luego lo renderiza sin escape cada vez que otros usuarios o administradores visualizan esa página. |
| **Basado en el DOM (*DOM-based XSS*)** | En el **cliente** (JavaScript en el navegador). | El HTML del servidor es estático y seguro, pero un script del frontend lee una **fuente (*source*)** controlable (`location.search`, `location.hash`, `postMessage`) y la escribe en un **sumidero (*sink*)** que interpreta HTML o código (`innerHTML`, `document.write`, `eval`). |

### Por qué el escape debe ser contextual

Codificar entidades HTML (`<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`, `"` → `&quot;`, `'` → `&#x27;`) es la defensa principal cuando insertás datos dentro del **cuerpo de una etiqueta HTML** (`<p>Hola, {{ nombre }}</p>`) o dentro de un **atributo entrecomillado** (`value="{{ valor }}"`). Sin embargo, existen contextos donde el simple escape HTML no alcanza:

1. **Contexto de cuerpo o atributo HTML común:** usar escape de entidades HTML automático del motor de plantillas (Jinja2, MarkupSafe, React JSX).
2. **Contexto de atributo de URL (`href` o `src`):** si una plantilla permite `<a href="{{ url_usuario }}">`, un valor que empiece por `javascript:` no contiene `<` ni `>`, por lo que el escape HTML no lo neutraliza. **Solución:** validar primero que el esquema de la URL sea estrictamente `https://` o `http://` mediante un parser de URLs (`urllib.parse.urlparse`).
3. **Contexto de datos pasados a JavaScript:** nunca interpolar cadenas directamente dentro de un bloque `<script>var usuario = "{{ nombre }}";</script>`. **Solución:** serializar con `tojson` o colocar los datos en un atributo `data-usuario="..."` de un elemento HTML y leerlo desde un archivo `.js` externo con `elemento.dataset.usuario`.
4. **Sumideros del DOM en el navegador:** reemplazar siempre `elemento.innerHTML = dato` por **`elemento.textContent = dato`** (que inserta texto puro sin crear nodos HTML).

### Comparación práctica en nuestro laboratorio (`laboratorios/app_lab_educativa.py`)

```python
from markupsafe import escape

# PATRÓN SEGURO implementado en /saludo-seguro:
# 1. Codifica caracteres especiales HTML (&, <, >, ", ') con MarkupSafe.
# 2. Aplica una cabecera Content-Security-Policy que bloquea scripts no autorizados.
@app.route("/saludo-seguro")
def saludo_seguro():
    nombre = escape(request.args.get("nombre", "Estudiante")[:50])
    resp = app.make_response(f"<h1>Hola, {nombre}</h1><p>Salida codificada con escape HTML y CSP activa.</p>")
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp
```

## 3. Content Security Policy (CSP) como segunda línea de defensa

Aunque apliques escape contextual en todas tus plantillas, la arquitectura defensiva moderna exige una segunda barrera: la cabecera **`Content-Security-Policy` (CSP)**.

CSP le indica al navegador qué fuentes de contenido están autorizadas. Incluso si un desarrollador cometiera un error y olvidara escapar una variable en una página, una política CSP bien diseñada impide que el navegador ejecute scripts inline (`<script>...</script>` o manejadores `onload=`, `onerror=`) y prohíbe enviar datos hacia dominios externos desconocidos (`connect-src 'self'`).

| Directiva CSP | Valor seguro recomendado | Qué restringe en el navegador |
|---|---|---|
| `default-src 'self'` | Solo el propio origen por defecto | Política base para cualquier recurso no especificado por separado. |
| `script-src 'self'` (o `'nonce-...'`) | Prohíbe scripts inline arbitrarios y dominios terceros | Solo ejecuta archivos `.js` del propio origen o bloques con el *nonce* criptográfico generado por petición. |
| `object-src 'none'` | Desactiva plugins heredados | Bloquea elementos `<object>`, `<embed>` y `<applet>`. |
| `base-uri 'self'` | Fija la etiqueta `<base>` al propio origen | Evita que una inyección HTML altere la ruta base de los scripts relativos. |
| `frame-ancestors 'none'` | Prohíbe incrustar la página en marcos | Reemplazo moderno y más flexible de `X-Frame-Options: DENY`. |
| `require-trusted-types-for 'script'` | Exige políticas **Trusted Types** en *sinks* DOM peligrosos | Bloquea asignaciones de cadenas crudas a `innerHTML`/`document.write`, mitigando **DOM XSS** en SPAs modernas. |

## 4. Cross-Site Request Forgery (CSRF) y Clickjacking

A diferencia de XSS (donde se intenta ejecutar código dentro del origen de la aplicación), **CSRF** abusa de un comportamiento histórico de los navegadores: cuando una página externa (`https://otro-sitio.ejemplo`) envía un formulario o carga un recurso hacia `https://mi-banco.local/cambiar-correo`, el navegador **adjunta automáticamente las cookies de `mi-banco.local`** si no tienen una política restrictiva.

Si el servidor solo verifica la cookie de sesión para autorizar una acción que modifica estado (`POST`, `PUT`, `DELETE`), no puede distinguir si la acción fue iniciada conscientemente por el usuario dentro de la aplicación o disparada en segundo plano desde otra pestaña.

### Las tres capas que eliminan CSRF

1. **Respetar la semántica HTTP:** ninguna petición `GET` debe modificar datos ni cambiar estado en el servidor.
2. **Cookies con `SameSite=Lax` o `SameSite=Strict`:** con `SameSite=Lax`, el navegador no envía la cookie en peticiones `POST` ni llamadas `fetch` originadas desde otro sitio; con `SameSite=Strict`, no la envía ni siquiera al seguir un enlace externo.
3. **Tokens anti-CSRF criptográficos (*Synchronizer Token Pattern*):** el servidor genera un valor aleatorio único por sesión (o por formulario), lo inserta como campo oculto o cabecera personalizada (`X-CSRF-Token`) y verifica su coincidencia exacta al recibir cualquier petición que modifique estado. Como un sitio externo no puede leer el token debido a la *Same-Origin Policy*, no puede falsificar la petición.

Por su parte, el **Clickjacking (Rediseño de Interfaz)** consiste en cargar una página legítima dentro de un `<iframe>` transparente superpuesto sobre botones engañosos para que el usuario haga clic sin saberlo. Se erradica enviando las cabeceras **`Content-Security-Policy: frame-ancestors 'none'`** (o `'self'`) y **`X-Frame-Options: DENY`**.

## 5. Configuraciones inseguras de CORS

Como vimos en el Capítulo 1.8, **CORS** permite relajar de forma controlada la *Same-Origin Policy* para que un frontend autorizado (por ejemplo `https://portal.empresa.local`) consuma una API en `https://api.empresa.local`.

Los dos errores críticos de configuración que debés buscar en toda auditoría de cabeceras CORS son:
1. **Reflejar automáticamente cualquier cabecera `Origin` de la petición dentro de `Access-Control-Allow-Origin` junto con `Access-Control-Allow-Credentials: true`:** esto equivale a desactivar la *Same-Origin Policy* para todos los sitios de internet manteniendo las cookies activas.
2. **Permitir `Access-Control-Allow-Origin: null` con credenciales:** el origen `null` puede ser generado por documentos dentro de un `<iframe sandbox>` desde cualquier sitio externo.

**Configuración correcta:** validar el valor de `Origin` contra un conjunto cerrado e inmutable de dominios propios antes de emitir la cabecera `Access-Control-Allow-Origin`.

### Redirecciones abiertas (*Open Redirect*)

Una redirección abierta ocurre cuando el backend acepta un parámetro de URL destino (por ejemplo `/login?next=https://sitio-externo.invalid`) y responde `HTTP 302 Found` con `Location: <valor_usuario>` sin validar el dominio. Aunque por sí sola no ejecuta JavaScript, suele usarse para aumentar la credibilidad de enlaces de phishing bajo un dominio corporativo legítimo o como eslabón en flujos OAuth.
**Mitigación:** aceptar únicamente **rutas relativas internas** verificando que comiencen con `/` (y nunca con `//`) o validar el hostname contra una lista blanca cerrada en el servidor.

## 6. Ejemplo paso a paso: Purple Team (`Ataca → Detecta → Corrige`) en XSS reflejado y almacenado

En `laboratorios/app_lab_educativa.py` podés comparar directamente la salida sin escape (`/saludo-vulnerable` y `/comentarios-vulnerable`) frente a los gemelos con codificación contextual y CSP (`/saludo-seguro` y `/comentarios-seguro`):

```bash
# 1. ATACA (XSS reflejado y almacenado en modo vulnerable)
curl -s "http://127.0.0.1:5050/saludo-vulnerable?nombre=%3Cb%3EAnalista%3C/b%3E"
curl -s -X POST http://127.0.0.1:5050/comentarios-vulnerable -d "texto=<img src=x onerror=alert(1)>"

# 2. DETECTA (revisar alerta generada en el registro del laboratorio)
curl -s "http://127.0.0.1:5050/telemetria-lab"

# 3. CORRIGE Y VERIFICA (escape HTML con MarkupSafe/Jinja2 + cabeceras CSP/nosniff)
curl -i "http://127.0.0.1:5050/saludo-seguro?nombre=%3Cb%3EAnalista%3C/b%3E"
```

Respuesta verificada del endpoint corregido `/saludo-seguro`:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Security-Policy: default-src 'self'; script-src 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

<h1>Hola, &lt;b&gt;Analista&lt;/b&gt;</h1><p>Salida codificada con escape HTML y CSP activa.</p>
```

Observá las tres defensas activas al mismo tiempo:
1. Los caracteres `<` y `>` fueron transformados en `&lt;` y `&gt;`, por lo que el parser HTML del navegador los muestra como texto plano en pantalla sin crear ninguna etiqueta.
2. La cabecera `X-Content-Type-Options: nosniff` obliga al navegador a respetar `text/html; charset=utf-8`.
3. La cabecera `Content-Security-Policy: default-src 'self'; script-src 'none'` deshabilita la ejecución de cualquier script en esa vista, y `X-Frame-Options: DENY` impide que sea incrustada en un `<iframe>`.

::: defensa Perspectiva defensiva y mitigación
1. **Usar motores de plantillas con auto-escape activado por defecto:** Jinja2 (Flask), Django Templates y React JSX escapan automáticamente las variables en contexto HTML. Auditá con herramientas de análisis estático cualquier uso de filtros que desactiven el escape (`|safe` en Jinja2, `Markup()`, `dangerouslySetInnerHTML` en React o `v-html` en Vue).
2. **Prohibir `innerHTML` para datos dinámicos:** en el JavaScript del frontend, estandarizá el uso de `textContent` o `innerText`. Si genuinamente se requiere renderizar HTML enriquecido escrito por el usuario (por ejemplo desde un editor Markdown), pasalo primero por un sanitizador basado en DOM con lista blanca de etiquetas como **DOMPurify**.
3. **Defensa en profundidad para sesiones:** combiná siempre `HttpOnly` + `Secure` + `SameSite=Lax` en cookies de sesión con tokens anti-CSRF en operaciones de cambio de estado.
:::

## Práctica en laboratorio local

1. **Ciclo completo en `app_lab_educativa.py`:** probá payloads inocuos (`<b>Lab</b>` y `<img src=x onerror=console.log(1)>`) sobre `/saludo-vulnerable` y `POST /comentarios-vulnerable`, confirmá las detecciones `XSS_Reflejado` y `XSS_Almacenado` en `/telemetria-lab`, y validá la codificación y cabeceras CSP en `/saludo-seguro` y `/comentarios-seguro`.
2. **Práctica interactiva en OWASP Juice Shop (`127.0.0.1:3000`):** completá un reto de **XSS basado en DOM** en la barra de búsqueda y analizá el archivo JS del cliente para identificar la fuente y el sumidero del DOM.
3. **CORS seguro y práctica adicional:** escribí una función `validar_origen_cors(origin)` que solo acepte `ORIGENES_PERMITIDOS = ("http://127.0.0.1:5050", "http://localhost:5050")`. Podés reforzar esta unidad con los módulos XSS/CSRF/CORS de **PortSwigger Web Security Academy** y **DVWA**.

::: practica Entregable mínimo
Evidencia del ciclo **Ataca → Detecta → Corrige** sobre XSS reflejado/almacenado, resumen del DOM XSS resuelto en OWASP Juice Shop y la función `validar_origen_cors()` probada.
:::

## Preguntas de repaso

**1. ¿Cuál es la diferencia fundamental entre un XSS Almacenado y un XSS basado en el DOM?** En un XSS Almacenado, el dato no confiable se guarda en el servidor (base de datos) y es el backend quien construye y devuelve un documento HTML con el dato sin escapar. En un XSS basado en el DOM, el servidor puede devolver una página estática completamente segura, pero el propio código JavaScript del cliente lee un dato de una fuente controlable (como `location.search`) y lo inserta de forma insegura en un sumidero del DOM (como `innerHTML`).

**2. ¿Por qué reemplazar `elemento.innerHTML = entrada` por `elemento.textContent = entrada` previene el XSS basado en el DOM?** Porque `innerHTML` invoca al analizador sintáctico HTML del navegador, creando nuevos nodos de etiquetas y atributos si la cadena contiene `<` o `>`. En cambio, `textContent` crea únicamente un nodo de texto literal (`TextNode`) en el árbol DOM, por lo que cualquier carácter especial se muestra en pantalla sin ser interpretado nunca como marcado ni código.

**3. ¿Por qué el simple escape de entidades HTML (`<` → `&lt;`) no basta para asegurar un atributo `<a href="{{ url_usuario }}">`?** Porque un enlace puede contener el pseudoprotocolo `javascript:...`, el cual no requiere utilizar caracteres `<`, `>` ni comillas para ejecutar código cuando el usuario hace clic. En contextos de URL es obligatorio validar primero que el esquema sea estrictamente `http://` o `https://`.

**4. ¿Cómo se complementan el atributo de cookie `SameSite=Lax` y un token anti-CSRF sincronizado?** `SameSite=Lax` actúa a nivel del navegador impidiendo que la cookie de sesión se adjunte en peticiones `POST` o llamadas `fetch` iniciadas desde sitios externos. El token anti-CSRF añade una verificación explícita en el servidor: exige un secreto aleatorio por sesión enviado en el cuerpo o en una cabecera personalizada que ningún origen externo puede conocer debido a la *Same-Origin Policy*.

**5. ¿Por qué es peligrosa la combinación de cabeceras `Access-Control-Allow-Origin: <origen reflejado sin validar>` junto con `Access-Control-Allow-Credentials: true`?** Porque le ordena al navegador adjuntar las cookies de sesión del usuario en peticiones iniciadas desde cualquier sitio web externo y, además, le autoriza a ese sitio externo a leer el contenido completo de la respuesta privada devuelta por la API.

## Antes de avanzar

Verificá que podés:
- Distinguir los tres tipos de XSS y elegir la técnica de codificación o validación correcta para cada contexto del documento.
- Configurar una política `Content-Security-Policy` restrictiva y cabeceras anti-Clickjacking.
- Explicar el mecanismo de CSRF, las reglas de `SameSite` y la validación por lista blanca de orígenes en CORS.

::: nota Puerta de salida
Una vez asegurada la frontera del navegador, el siguiente paso es proteger la identidad del usuario y los permisos sobre cada recurso en el servidor: avanzá al **Capítulo 2.5 · Autenticación, sesiones, JWT, OAuth y control de acceso (IDOR/BOLA)**.
:::

## Referencias y estándares abiertos

- **OWASP Cross-Site Scripting Prevention Cheat Sheet & DOM-based XSS Prevention Cheat Sheet:** reglas de escape por contexto y uso seguro de APIs del DOM.
- **OWASP Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet:** arquitectura de tokens sincronizados y defensa en profundidad con `SameSite`.
- **W3C Content Security Policy Level 3:** especificación oficial de directivas CSP, nonces y hashes.
- **RFC 6454 (The Web Origin Concept):** definición formal del modelo de seguridad de orígenes en navegadores web.
