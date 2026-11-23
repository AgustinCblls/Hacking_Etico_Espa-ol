::: nota Objetivo de la lección
Dominar la auditoría y la remediación de vulnerabilidades web de alta complejidad temporal y arquitectónica: condiciones de carrera sincronizadas mediante HTTP/2, envenenamiento y engaño de cachés intermedias, fallas en canales bidireccionales WebSocket y colisiones en el DOM o rutas relativas del navegador. Al finalizar, vas a saber diagnosticar la causa raíz en arquitectura distribuida y aplicar controles atómicos, cabeceras estrictas y saneamiento seguro.
:::

Las vulnerabilidades web clásicas suelen manifestarse en una única petición HTTP aislada: enviás un parámetro mal formado y el servidor responde con un error o un comportamiento inesperado. En aplicaciones modernas basadas en microservicios, balanceadores, CDN y clientes *Single Page Application* (SPA), las fallas más críticas emergen de la **interacción entre componentes** y de las **ventanas temporales** entre validación y ejecución.

Este capítulo aborda cinco superficies avanzadas siguiendo el criterio técnico de *PortSwigger Web Security Academy* y la guía *OWASP Web Security Testing Guide* (WSTG), priorizando el entendimiento profundo del protocolo y las defensas estructurales.

---

## 1. Race Conditions avanzadas

Una condición de carrera (*race condition*) ocurre cuando múltiples hilos, procesos o peticiones concurrentes acceden y modifican un recurso compartido sin una sincronización adecuada. En aplicaciones web, el patrón clásico se conoce como **TOCTOU** (*Time-of-Check to Time-of-Use*): el servidor verifica una precondición (por ejemplo, si hay saldo suficiente o si un cupón no fue usado) y, milisegundos después, ejecuta la acción (descontar saldo o marcar el cupón). Si dos peticiones atraviesan la etapa de verificación antes de que la primera complete la escritura, ambas resultan aprobadas.

### 1.1 Limit Overrun y ventanas de concurrencia

El escenario más frecuente es el *Limit Overrun*: superar un límite de negocio diseñado para aplicarse una sola vez (canje de créditos promocionales, votación única, retiro de fondos o creación duplicada de registros únicos).

Considerá un endpoint típico de canje de saldo promocional implementado sin control de concurrencia:

```python
# Código vulnerable (patrón TOCTOU)
@app.post("/api/v1/promos/redeem")
def redeem_promo(user_id: int, code: str):
    promo = db.query("SELECT id, amount, redeemed FROM promos WHERE code = %s", (code,))
    if not promo or promo.redeemed:
        return {"error": "Cupón inválido o ya utilizado"}, 400

    # Ventana de carrera: entre la lectura y las escrituras siguientes,
    # múltiples peticiones simultáneas ven promo.redeemed == False.
    db.execute("UPDATE wallets SET balance = balance + %s WHERE user_id = %s", (promo.amount, user_id))
    db.execute("UPDATE promos SET redeemed = TRUE WHERE id = %s", (promo.id,))
    db.commit()
    return {"status": "ok"}
```

En una prueba tradicional con peticiones HTTP/1.1 enviadas secuencialmente o en conexiones TCP separadas, la latencia de red (el *jitter* entre paquetes) suele dispersar la llegada al servidor a lo largo de decenas de milisegundos, lo que hace difícil reproducir ventanas sub-milisegundo.

### 1.2 Single-Packet Attack sobre HTTP/2

La investigación moderna sobre concurrencia web (popularizada por James Kettle en PortSwigger) demostró que **HTTP/2** elimina prácticamente todo el *jitter* de red mediante la multiplexación de *streams* dentro de una única conexión TCP/TLS.

En lugar de abrir veinte conexiones TCP independientes —donde cada una sufre distintas colas en el sistema operativo, handshakes TLS y congestión—, un cliente de auditoría puede agrupar múltiples peticiones lógicas en la misma conexión HTTP/2 utilizando una técnica de sincronización en dos fases:

1. **Pre-envío incompleto**: el cliente envía las cabeceras (`HEADERS`) y la mayor parte del cuerpo (`DATA`) de N peticiones en paralelo en distintos *streams* HTTP/2, pero **retiene el flag `END_STREAM`** (o deja pendiente el último byte de cada stream). El servidor o proxy inverso recibe los datos parciales y los mantiene en el buffer esperando el cierre de cada stream, sin despachar todavía la petición a la lógica de negocio.
2. **Disparo en un único paquete TCP**: tras una breve pausa para vaciar buffers y estabilizar la ventana TCP, el cliente envía los frames finales con `END_STREAM` de todos los streams dentro de **un único segmento TCP** (hasta ~1460 bytes de payload MSS).

```text
Cliente HTTP/2                         Proxy / Servidor Web
  |                                             |
  |--- Stream 1: HEADERS + DATA (sin END) ----->| [En buffer]
  |--- Stream 3: HEADERS + DATA (sin END) ----->| [En buffer]
  |--- Stream 5: HEADERS + DATA (sin END) ----->| [En buffer]
  |                                             |
  |=== 1 Paquete TCP: END_STREAM (1, 3, 5) ====>| ¡Despacho simultáneo (< 100 µs)!
```

Como el kernel del servidor procesa ese último paquete TCP en una sola interrupción de red, el servidor web despacha los N hilos trabajadores casi en el mismo microsegundo. Incluso servidores en Node.js o Python con código asíncrono (`async/await`) quedan expuestos si ceden el *event loop* durante una consulta `await db.fetch(...)` antes de escribir.

### 1.3 Hidden Multi-Step Sequences

No todas las condiciones de carrera involucran dos llamadas al mismo endpoint. Muchas ocurren dentro de **una sola petición HTTP** que internamente ejecuta varios pasos, o entre **dos endpoints distintos** que comparten un estado intermedio transitorio (*sub-state*).

Ejemplos reales observados en auditorías:

- **Inicialización de sesión con privilegios temporales**: un flujo de login crea primero el registro de sesión en Redis con estado predeterminado y luego consulta el rol o bloquea la cuenta si falló el MFA. Durante unos milisegundos existe una sesión válida previa a la verificación secundaria.
- **Restablecimiento de contraseña y cambio de correo**: si un endpoint genera un token de recuperación y tarda algunos milisegundos en asociarlo al usuario correcto en una tabla auxiliar, una petición paralela de actualización de perfil puede alterar el destinatario antes de que se envíe la notificación.
- **Carga y validación de archivos**: guardar un archivo en el directorio público temporal y ejecutar el análisis antivirus o la verificación de formato después, borrándolo solo si falla.

### 1.4 Mitigación transaccional y atómica

Deshabilitar HTTP/2 no soluciona una condición de carrera: solo dificulta ligeramente la sincronización externa, mientras que el problema sigue presente bajo tráfico legítimo concurrente. La remediación debe ocurrir en la capa de datos y coordinación.

| Mecanismo defensivo | Cómo funciona | Cuándo aplicarlo |
| :--- | :--- | :--- |
| **`SELECT ... FOR UPDATE`** | Bloquea la fila leída dentro de una transacción ACID hasta el `COMMIT` o `ROLLBACK`. | Operaciones financieras, inventario o cupones en SQL relacional. |
| **Actualización condicional atómica** | `UPDATE promos SET redeemed = TRUE WHERE id = %s AND redeemed = FALSE` verificando `rowcount == 1`. | Cambios de estado simples sin lectura previa compleja. |
| **Restricciones `UNIQUE` y `CHECK`** | Delega al motor SQL la imposibilidad de duplicados (`UNIQUE(user_id, promo_id)`) o saldos negativos (`CHECK (balance >= 0)`). | Reglas de unicidad y límites numéricos invariantes. |
| **Locks distribuidos (Redis)** | Usa `SET lock_key token NX PX 5000` y liberación atómica mediante script Lua comparando el token dueño. | Microservicios sin base relacional compartida o acceso a APIs externas. |
| **Idempotency Keys** | El cliente envía `Idempotency-Key: <UUID>`; el servidor guarda la clave en un índice único y devuelve la respuesta cacheada ante reintentos paralelos. | Pasarelas de pago, creación de órdenes y webhooks. |

Ejemplo de remediación segura en Python/PostgreSQL combinando bloqueo pesimista y verificación de integridad:

```python
# Código remediado con transacción atómica y bloqueo de fila
@app.post("/api/v1/promos/redeem")
def redeem_promo_safe(user_id: int, code: str):
    with db.transaction():
        # Bloquea la fila específica hasta finalizar la transacción
        promo = db.query_one(
            "SELECT id, amount, redeemed FROM promos WHERE code = %s FOR UPDATE",
            (code,),
        )
        if not promo or promo.redeemed:
            return {"error": "Cupón inválido o ya utilizado"}, 400

        updated = db.execute(
            "UPDATE promos SET redeemed = TRUE, redeemed_by = %s WHERE id = %s AND redeemed = FALSE",
            (user_id, promo.id),
        )
        if updated.rowcount != 1:
            raise ConcurrencyConflictError("Estado modificado concurrentemente")

        db.execute(
            "UPDATE wallets SET balance = balance + %s WHERE user_id = %s",
            (promo.amount, user_id),
        )
    return {"status": "ok"}
```

::: aviso Evitá los sleeps artificiales como defensa
Introducir retardos aleatorios o bloqueos exclusivos en memoria local del proceso web (como `threading.Lock()` en Python) **no protege** despliegues con múltiples *workers* (Gunicorn, PM2) ni múltiples réplicas en Kubernetes. El bloqueo siempre debe residir en un almacén centralizado (base de datos transaccional o coordinador distribuido).
:::

---

## 2. Web Cache Poisoning y Web Cache Deception

Las cachés intermedias (CDN como Cloudflare/Fastly, Varnish o Nginx en modo *reverse proxy cache*) almacenan respuestas generadas por el origen para acelerar la entrega a futuros usuarios. Aunque ambas familias de ataques abusan de esta capa, sus objetivos y mecanismos son inversos:

- **Web Cache Poisoning (envenenamiento)**: el atacante fuerza al servidor de origen a generar una respuesta maliciosa (por ejemplo, con un enlace `<script>` alterado) y logra que el caché la guarde bajo una clave normal para servirla a **otros usuarios**.
- **Web Cache Deception (engaño)**: el atacante engaña al caché para que almacene una respuesta **privada y legítima** de una víctima autenticada (por ejemplo, su perfil o token CSRF) bajo una URL aparentemente estática, y luego la lee directamente.

### 2.1 Cache Keys vs Unkeyed Inputs

Para decidir si dos peticiones merecen la misma respuesta guardada, la caché calcula una **Cache Key** (clave de caché) usando normalmente el método HTTP, el esquema, el `Host` y la ruta con ciertos parámetros de consulta. Todo componente de la petición HTTP que **no forma parte de la clave** se denomina **Unkeyed Input**.

Si el servidor de origen lee un *Unkeyed Input* para construir la respuesta HTML o los encabezados, surge una brecha arquitectónica:

1. **Cabeceras de reenvío (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Scheme`)**: muchos frameworks generan URLs absolutas para cargar scripts o redirecciones leyendo estas cabeceras cuando confían ciegamente en cualquier proxy. Si el caché indexa solo por la URL `/inicio` e ignora `X-Forwarded-Host`, una respuesta que refleje ese host queda almacenada para todos los visitantes de `/inicio`.
2. **Parámetros excluidos (UTM / analytics)** y **cabeceras `Vary`**: algunas CDN descartan parámetros de seguimiento como `utm_source` de la clave de caché. Si la aplicación refleja un parámetro descartado en el DOM o en una redirección, la respuesta envenenada se sirve a quienes visiten la URL limpia. Por otro lado, si una respuesta varía según una cabecera (como `Origin` en CORS o `Accept-Encoding`), debe declararse explícitamente en la cabecera de respuesta `Vary`.

### 2.2 Fat GET Requests

En el estándar HTTP, una petición `GET` puede transportar un cuerpo (*body*), aunque la mayoría de los proxies y cachés ignoran el cuerpo al calcular la *Cache Key*. Sin embargo, algunos frameworks backend (o configuraciones con `X-HTTP-Method-Override`) parsean parámetros tanto de la *query string* como del cuerpo JSON o *form-urlencoded* en rutas `GET`, dando prioridad al cuerpo.

```http
GET /api/config?lang=es HTTP/1.1
Host: app.ejemplo.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 19

callback=validarCfg
```

Si la caché ignora el cuerpo y guarda la respuesta bajo la clave `GET /api/config?lang=es`, cualquier usuario que solicite esa ruta recibirá la respuesta alterada por el parámetro oculto en el cuerpo. La solución es rechazar peticiones `GET` o `HEAD` con `Content-Length > 0` o `Transfer-Encoding` en el proxy inverso, y no mezclar parsers de body en manejadores `GET`.

### 2.3 Web Cache Deception y normalización de rutas

En el *Web Cache Deception*, el problema radica en una **discrepancia de interpretación de rutas** entre el CDN/proxy y el servidor de origen.

Imaginá que el servidor de origen usa un framework tolerante con sufijos o segmentos extra (como ciertos enrutadores PHP, Spring o Express mal configurados) donde `/cuenta/perfil/inexistente.css` resuelve al mismo controlador autenticado que `/cuenta/perfil`. Mientras tanto, el CDN aplica una regla simple basada en extensión: *"cachear cualquier ruta terminada en `.css`, `.js` o `.png` por 10 minutos, ignorando las cabeceras de sesión"*.

```text
Víctima (autenticada) ---> GET /cuenta/perfil/estilo.css ---> CDN (regla: .css es público/cacheable)
                                                               |
                                                               v (miss de caché)
                                                        Servidor Origen
                                                               |
                                                               v (normaliza/ignora sufijo)
                                                        Responde HTML privado de /cuenta/perfil
                                                               |
                                                               v
CDN guarda el HTML privado bajo la clave "/cuenta/perfil/estilo.css"
Auditor / Tercero ---> GET /cuenta/perfil/estilo.css ---> CDN devuelve HIT con datos privados
```

Variantes modernas explotan diferencias en la decodificación de delimitadores (`;`, `%2f`, `%3b`, `%23`) o normalización de barras (`..%2f`) entre el proxy de borde y el servidor de aplicaciones.

### 2.4 Controles de caché y validación estricta

Para erradicar ambas clases de fallas:

- **Contenido autenticado o dinámico**: emití siempre `Cache-Control: private, no-store, max-age=0` y configurá el CDN para **respetar las directivas del origen** (*Honor Origin Cache-Control*), nunca sobrescribirlas por extensión de archivo.
- **Rutas estrictas en origen**: deshabilitá el *trailing path info* o coincidencia por prefijo tolerante. Si `/cuenta/perfil` recibe `/cuenta/perfil/algo.css`, debe responder `404 Not Found` y no renderizar el perfil.
- **Sanitización de cabeceras de borde**: el proxy inverso confiable debe sobrescribir o eliminar `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL` y `X-HTTP-Method-Override` procedentes de Internet antes de reenviar al backend.
- **Validación de `Vary`**: incluí en `Vary` toda cabecera que influya en la respuesta (por ejemplo `Vary: Origin, Accept-Encoding`), evitando incluir cabeceras de alta entropía como `User-Agent` o `Cookie` si se busca eficiencia de caché.

---

## 3. Seguridad en WebSockets

HTTP sigue un modelo estricto de petición-respuesta iniciado por el cliente. Cuando una aplicación necesita comunicación bidireccional de baja latencia (chats en vivo, cotizaciones, notificaciones o consolas interactivas), utiliza **WebSockets** (RFC 6455).

### 3.1 El Handshake `Upgrade: websocket`

Toda conexión WebSocket comienza como una petición HTTP/1.1 estándar con cabeceras de negociación de protocolo:

```http
GET /ws/notificaciones HTTP/1.1
Host: app.ejemplo.com
Upgrade: websocket
Connection: Upgrade
Origin: https://app.ejemplo.com
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Cookie: session_id=eyJhbGciOi...
```

Si el servidor acepta, responde `101 Switching Protocols` con `Sec-WebSocket-Accept` calculado a partir de la clave del cliente. A partir de ese instante, el socket TCP deja de hablar HTTP y pasa a intercambiar **frames binarios o de texto** de forma asíncrona en ambas direcciones.

### 3.2 Cross-Site WebSocket Hijacking (CSWSH)

El navegador adjunta automáticamente las cookies de sesión (`Cookie: session_id=...`) en el handshake `Upgrade: websocket` hacia un dominio, exactamente igual que en una petición HTTP tradicional. Además, **el protocolo WebSocket no aplica la Same-Origin Policy (SOP)** para bloquear la apertura de conexiones desde un origen externo; la responsabilidad de decidir si un sitio tercero puede abrir el túnel recae por completo en el servidor durante el handshake.

Si el servidor WebSocket cumple estas dos condiciones inseguras:
1. Autentica al usuario únicamente mediante cookies (especialmente si tienen `SameSite=None` o en escenarios donde el navegador permite el envío en navegación/subrecursos compatibles).
2. **No valida la cabecera `Origin`** ni exige un token anti-CSRF único vinculado a la sesión dentro del mensaje de apertura o query parameter seguro.

Entonces, un sitio externo malicioso visitado por la víctima puede abrir un objeto `new WebSocket("wss://app.ejemplo.com/ws/notificaciones")` en JavaScript, recibir datos confidenciales emitidos por el servidor o enviar comandos privilegiados actuando con la identidad de la víctima.

**Remediación del handshake:**

```javascript
// Verificación estricta de Origin y token efímero en servidor WebSocket (Node.js 'ws')
const ALLOWED_ORIGINS = new Set(["https://app.ejemplo.com"]);

wss.on("connection", async (ws, req) => {
  const origin = req.headers.origin;
  if (!origin || !ALLOWED_ORIGINS.has(origin)) {
    ws.close(1008, "Origin no autorizado");
    return;
  }

  // Además del Origin, exigí un ticket efímero de un solo uso generado vía API autenticada con CSRF protection
  const url = new URL(req.url, "https://app.ejemplo.com");
  const ticket = url.searchParams.get("ticket");
  const userSession = await consumeOneTimeWsTicket(ticket, req);
  if (!userSession) {
    ws.close(1008, "Ticket de sesión inválido");
    return;
  }

  ws.user = userSession;
});
```

### 3.3 Manipulación de mensajes y sanitización bidireccional

Una vez establecido el túnel, muchos equipos de desarrollo cometen el error de asumir que los datos que llegan por WebSocket son "seguros" porque el cliente JS oficial los serializó correctamente, o porque existe un WAF perimetral HTTP. Sin embargo:

- Muchos WAF tradicionales inspeccionan el handshake `101` pero **no analizan los frames posteriores** enviados sobre el socket abierto.
- Cualquier cliente puede interceptar el tráfico o abrir el socket directamente enviando JSON manipulado, tipos inesperados (por ejemplo enviar un objeto en lugar de un string) o mensajes binarios malformados.

Por lo tanto, **cada mensaje entrante** en el manejador `onmessage` del servidor debe tratarse con el mismo rigor que un endpoint REST:
1. **Validación de esquema estricto** (con *Zod*, *Pydantic* o *JSON Schema*): verificar tipos, longitudes máximas y rechazo de propiedades extra (`additionalProperties: false`).
2. **Autorización por mensaje**: nunca confíes en un campo `userId` o `role` dentro del payload JSON del mensaje; usá siempre el contexto autenticado en el handshake (`ws.user.id`).
3. **Consultas parametrizadas y escape contextual**: si un mensaje de WebSocket se guarda en SQL o se reenvía a otros participantes del chat, deben aplicarse consultas preparadas en backend y renderizado seguro (`textContent` en lugar de `innerHTML`) en todos los clientes receptores para prevenir Stored XSS a través del canal en tiempo real.

---

## 4. DOM Clobbering y Client-Side Path Traversal (CSPT)

A medida que la lógica se desplaza al navegador, surgen vulnerabilidades puramente de cliente que pueden escalar a ejecución de scripts (XSS) o abuso de APIs autenticadas sin necesidad de tocar el backend inicialmente.

### 4.1 DOM Clobbering

Los navegadores mantienen por compatibilidad histórica una característica peligrosa llamada *named access on the Window object*: cuando un elemento HTML tiene un atributo `id` o `name`, el navegador puede crear automáticamente una propiedad en `window` o `document` con ese mismo nombre.

Si la aplicación permite insertar HTML controlado (incluso HTML **sin** etiquetas `<script>` ni manejadores `onerror`, filtrado por un sanitizador permisivo que conserva `id` o `name`), un atacante puede provocar una **colisión sobre variables globales** no inicializadas o propiedades del DOM.

```html
<!-- HTML inyectado sin JavaScript explícito (solo atributos id/name) -->
<a id="appConfig" href="https://cdn-externo.ejemplo/malicioso.js"></a>

<!-- O un árbol de dos niveles usando form/input o dos anchors con el mismo id -->
<a id="appConfig"></a>
<a id="appConfig" name="scriptUrl" href="https://cdn-externo.ejemplo/app.js"></a>
```

Cuando el código JavaScript de la página evalúa una referencia global por defecto usando el patrón `||`:

```javascript
// Patrón JavaScript vulnerable a DOM Clobbering
const config = window.appConfig || { scriptUrl: "/static/app.js" };
const script = document.createElement("script");
// Al acceder a config.scriptUrl, obtiene el href del segundo <a>
script.src = config.scriptUrl;
document.head.appendChild(script);
```

El navegador resuelve `window.appConfig` a una `HTMLCollection` con los dos enlaces; dentro de esa colección, la propiedad `.scriptUrl` apunta al segundo `<a>`, y al convertir un `HTMLAnchorElement` a string (al asignarlo a `script.src`), JavaScript devuelve su atributo `href`. Resultado: carga de un script externo arbitrario sin haber inyectado ninguna etiqueta `<script>`.

Un caso similar ocurre sobre propiedades del propio `document` o elementos `<form>`: un `<input name="action">` dentro de un `<form>` sobrescribe `form.action`, rompiendo validaciones que verifican `if (form.action.startsWith(...))`.

### 4.2 Client-Side Path Traversal (CSPT)

El *Client-Side Path Traversal* ocurre cuando el código JavaScript del navegador construye dinámicamente la ruta de una petición `fetch()` o `XMLHttpRequest` concatenando un parámetro controlado por el usuario (por ejemplo, extraído de `location.search`, `location.hash` o un parámetro de ruta SPA) **sin codificación ni validación**, permitiendo navegar hacia arriba en la jerarquía de rutas del servidor (`../`).

```javascript
// Código cliente vulnerable a CSPT
const params = new URLSearchParams(window.location.search);
const itemId = params.get("id"); // Si alguien pasa "123/../../admin/export-tokens"

fetch(`/api/v1/items/${itemId}/details`, {
  credentials: "include", // Envía cookies de sesión automáticamente
})
  .then((r) => r.json())
  .then((data) => renderItem(data));
```

Cuando el navegador ejecuta `fetch("/api/v1/items/123/../../admin/export-tokens/details")`, **normaliza automáticamente** los segmentos `..` antes de enviar la petición HTTP al servidor, convirtiéndola en `GET /api/v1/admin/export-tokens/details`. Si ese otro endpoint responde datos sensibles que el cliente luego renderiza en pantalla o envía a un *sink* secundario (como un *webhook* o parámetro `redirect`), el flujo del cliente queda desviado hacia acciones no previstas.

### 4.3 Mitigaciones en el Frontend

| Riesgo | Estrategia de mitigación | Implementación recomendada |
| :--- | :--- | :--- |
| **DOM Clobbering** | Evitar depender de variables globales implícitas en `window`. | Encapsular estado en módulos ES (`import`/`export`), declarar con `const`/`let` antes de usar, y evitar `window.miVar \|\| default`. |
| **DOM Clobbering** | Proteger objetos de configuración y formularios. | Aplicar `Object.freeze(window.APP_CONFIG)` al inicio del `<head>`, usar `Object.getOwnPropertyDescriptor` o `FormData` en lugar de `form.campo`. |
| **DOM Clobbering** | Sanitización estricta de HTML de usuario. | Usar **DOMPurify** con `SANITIZE_DOM: true` (activo por defecto, prefija/bloquea colisiones `id`/`name`) y habilitar CSP estricta (`script-src 'self'`). |
| **CSPT** | Codificación de segmentos individuales y validación de formato. | Aplicar `encodeURIComponent(itemId)` y validar con regex estricta (`/^[a-zA-Z0-9_-]{1,64}$/`) antes de construir la URL. |
| **CSPT** | Construcción segura con objeto `URL` y verificación de prefijo post-normalización. | Construir `const url = new URL(...)` y validar `url.pathname.startsWith("/api/v1/items/")` luego de normalizar. |

Ejemplo de cliente blindado frente a ambos vectores:

```javascript
// Configuración inmutable en módulo ES
const CONFIG = Object.freeze({
  apiBase: "https://app.ejemplo.com/api/v1/items/",
});

export async function loadItemDetails(rawId) {
  // 1. Validar formato estricto de identificador (previene CSPT)
  if (typeof rawId !== "string" || !/^[0-9a-fA-F-]{36}$/.test(rawId)) {
    throw new Error("Identificador de ítem inválido");
  }

  // 2. Construir y verificar ruta normalizada
  const targetUrl = new URL(`${encodeURIComponent(rawId)}/details`, CONFIG.apiBase);
  if (targetUrl.origin !== "https://app.ejemplo.com" || !targetUrl.pathname.startsWith("/api/v1/items/")) {
    throw new Error("Ruta de API fuera del alcance permitido");
  }

  const response = await fetch(targetUrl.toString(), { credentials: "include" });
  return response.json();
}
```

### 4.4 Seguridad en `window.postMessage` y *XS-Leaks*

Cuando una aplicación web integra *iframes*, ventanas emergentes (`window.open`) o pasarelas externas de autenticación, suele intercambiar datos entre distintos orígenes mediante `window.postMessage()`. Aunque el método está diseñado para comunicación *cross-origin* segura, su uso descuidado introduce dos fallas frecuentes:

- **Receptor sin validar `event.origin`:** si el manejador `window.addEventListener("message", (event) => ...)` procesa `event.data` y lo inyecta en el DOM (`innerHTML`) o altera el estado de la sesión sin comprobar estrictamente la identidad del remitente, cualquier sitio externo que abra la ventana puede enviar mensajes maliciosos y desencadenar un **DOM-based XSS** o robo de acciones.
- **Emisor con comodín `"*"`:** invocar `targetWindow.postMessage(payload, "*")` entrega el mensaje sin importar qué origen esté cargado actualmente en la ventana destino. Si el contenido incluye un token OAuth o datos sensibles y el atacante navegó la ventana hacia su dominio, captura el secreto al instante.

```javascript
// Patrón seguro de emisión y recepción con validación estricta de origen
const TRUSTED_ORIGIN = "https://app.ejemplo.com";

// Emisor: especificar siempre el origen exacto en lugar de "*"
popupWindow.postMessage({ type: "AUTH_STATUS", ready: true }, TRUSTED_ORIGIN);

// Receptor: validar event.origin ANTES de leer o procesar event.data
window.addEventListener("message", (event) => {
  if (event.origin !== TRUSTED_ORIGIN) {
    return;
  }
  if (typeof event.data?.message === "string") {
    statusBanner.textContent = event.data.message; // Evitar innerHTML
  }
});
```

En paralelo, las técnicas de ***Cross-Site Leaks* (XS-Leaks)** aprovechan señales laterales observables entre orígenes para inferir si un usuario está autenticado o si una búsqueda privada arrojó resultados, sin leer directamente el cuerpo de la respuesta bloqueado por la *Same-Origin Policy*:

- **Tamaño de respuesta y caché / eventos de error:** detectar mediante eventos `onload` / `onerror` o `PerformanceResourceTiming` si un recurso protegido devuelve `200 OK` frente a `404`/`403`, o inferir volumen de datos por tiempo de descarga y estado en caché.
- **Conteo de *frames* e historial:** inspeccionar propiedades expuestas como `windowReference.length` (cantidad de `<iframe>` internos tras una consulta) o cambios en `history.length` tras redirecciones condicionales.

**Mitigación *Purple Team*:** combiná validación estricta de `event.origin` con cabeceras defensivas que aíslan ventanas y bloquean solicitudes cruzadas no previstas: **`Cross-Origin-Opener-Policy: same-origin` (`COOP`)** rompe la referencia `window.opener` y el acceso a `window.length` entre orígenes distintos, **`Cross-Origin-Resource-Policy: same-origin` (`CORP`)** restringe la carga de subrecursos, y las cabeceras **`Fetch Metadata`** (`Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`) permiten al backend rechazar peticiones `cross-site` hacia endpoints privados internos.

### 4.5 SSRF y LFI en generadores de PDF y navegadores *headless*

Muchas plataformas generan facturas, reportes o certificados convirtiendo HTML dinámico a PDF en el servidor mediante motores como **`wkhtmltopdf`**, **Puppeteer** o **Playwright/Chromium** en modo *headless*. El error crítico consiste en interpolar entradas controladas por el usuario (nombre de cliente, dirección, notas en Markdown o SVG) dentro de la plantilla HTML que renderiza el proceso del servidor.

A diferencia de un XSS clásico que se ejecuta en el navegador de la víctima, el payload inyectado aquí se interpreta **en el navegador interno o motor WebKit/Chromium que corre dentro de la red corporativa o instancia cloud del backend**:

- **SSRF hacia metadatos cloud e intranet:** etiquetas como `<iframe src="http://169.254.169.254/latest/meta-data/">`, `<img>` hacia puertos internos o scripts `fetch("http://127.0.0.1:8080/admin")` permiten exfiltrar credenciales IAM del servicio de metadatos o enumerar microservicios internos directamente impresos dentro del PDF descargado.
- **LFI (*Local File Inclusion*) mediante esquema `file://`:** motores permisivos o mal configurados resuelven `<iframe src="file:///etc/passwd">` o `<object data="file:///app/.env">`, incrustando el contenido de archivos locales del servidor en el documento generado.

::: defensa Aislamiento obligatorio para renderizado HTML-a-PDF
Para blindar generadores de PDF y navegadores *headless* en producción:
1. **Sanitización previa y plantillas seguras:** escapá todas las variables dinámicas antes de armar el HTML y rechazá etiquetas activas (`<script>`, `<iframe>`, `<object>`, `<embed>`, `<svg>` con referencias externas).
2. **Desactivar JavaScript y acceso local:** en Puppeteer/Playwright, deshabilitá capacidades innecesarias, interceptá las peticiones de red (`page.setRequestInterception(true)`) bloqueando cualquier esquema distinto de `https:` o recursos en lista blanca, y en `wkhtmltopdf` evitá habilitar `--enable-local-file-access` (desactivado por defecto en versiones modernas).
3. **Aislamiento de red y sandbox de contenedor:** ejecutá el renderizador en un contenedor dedicado sin privilegios, sin volúmenes sensibles montados y con todo tráfico saliente forzado a través de un **proxy de salida aislado** que bloquee rangos privados RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), `127.0.0.0/8` y enlaces locales de metadatos (`169.254.169.254`, `fd00:ec2::254`).
:::

---

## 5. HTTP Request Smuggling

El **HTTP Request Smuggling** (contrabando de peticiones HTTP) explota discrepancias en cómo dos servidores encadenados —un *Front-End* (CDN, WAF o balanceador Nginx/HAProxy) y un *Back-End* (servidor de aplicación)— determinan **dónde termina una petición HTTP y empieza la siguiente** dentro de una misma conexión TCP persistente (`Keep-Alive`). Como el *Front-End* suele multiplexar conexiones de distintos usuarios hacia un mismo socket backend, cualquier byte sobrante envenena la petición del próximo usuario legítimo.

### 5.1 Desincronización clásica en HTTP/1.1 (`CL.TE` y `TE.CL`)

| Variante | Regla del *Front-End* | Regla del *Back-End* | Impacto y detección en laboratorio |
| :--- | :--- | :--- | :--- |
| **`CL.TE`** | Usa `Content-Length` | Usa `Transfer-Encoding: chunked` | El *Front-End* reenvía todo el bloque `Content-Length`; el *Back-End* se detiene al leer `0\r\n\r\n` y deja el prefijo restante encolado como inicio de la siguiente petición en el socket. |
| **`TE.CL`** | Usa `Transfer-Encoding: chunked` | Usa `Content-Length` | El *Front-End* reenvía hasta el cierre `0\r\n\r\n`; el *Back-End* solo lee los primeros bytes indicados por `Content-Length` e interpreta la parte chunked restante como una nueva petición completa. |
| **`TE.TE`** | Ambigüedad por ofuscación | Ambigüedad por ofuscación | Cabeceras malformadas (ej. `Transfer-Encoding: xchunked` o duplicadas) hacen que solo una capa ignore `TE` y caiga en `CL`, reproduciendo `CL.TE` o `TE.CL`. |

```http
POST / HTTP/1.1
Host: app-lab.local
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### 5.2 Downgrade `HTTP/2 → HTTP/1.1` y *Client-Side Desync* (CSD)

1. **Downgrade `HTTP/2 → HTTP/1.1` (`H2.CL` / `H2.TE` / CRLF en cabeceras H2):** en HTTP/2 la longitud de cada mensaje es binaria a nivel de frame (`DATA`). Sin embargo, si un proxy recibe HTTP/2 del cliente y traduce la petición a **HTTP/1.1** hacia el backend sin validar cabeceras, puede inyectar una `Transfer-Encoding: chunked` prohibida por RFC 9113, reenviar un `Content-Length` distinto al tamaño real del frame o permitir `\r\n` dentro del valor de una cabecera para contrabandear una segunda petición al serializar en texto HTTP/1.1.
2. ***Client-Side Desync* (CSD):** no requiere un proxy intermedio. Ocurre cuando un servidor acepta HTTP/1.1 *Keep-Alive* pero **ignora el `Content-Length` de una petición `POST` hacia ciertas rutas** (por ejemplo respuestas `302` o estáticos) devolviendo la respuesta sin consumir el cuerpo. Un sitio externo puede inducir al navegador de la víctima (vía `fetch(..., { method: "POST", mode: "no-cors", credentials: "include" })`) a enviar una petición con cuerpo remanente que envenena la **propia conexión persistente del navegador** para la siguiente solicitud autenticada del usuario.

### 5.3 Detección (*Blue Team*) y mitigación estructural

- **Detección en proxy/WAF/Suricata:** alertar ante toda petición que incluya simultáneamente `Content-Length` y `Transfer-Encoding`, múltiples cabeceras `Content-Length`, espacios/tabulaciones anómalas antes de `:` o nombres de cabecera prohibidos en HTTP/2; correlacionar picos de errores `400`/`408`/`502` o rutas internas inesperadas asociadas a sockets persistentes de un mismo balanceador.
- **Mitigación obligatoria:**
  1. **HTTP/2 de extremo a extremo (*Front-End* ↔ *Back-End*)** siempre que sea posible, evitando la traducción a HTTP/1.1 con conexiones compartidas.
  2. **Normalización estricta RFC 9112 / RFC 9113:** rechazar con `400 Bad Request` y cerrar inmediatamente el socket ante ambigüedades `CL`+`TE`, `Transfer-Encoding` no estándar o caracteres `\r`/`\n` en cabeceras HTTP/2.
  3. **Drenado completo o cierre de socket frente a CSD:** todo servidor HTTP/1.1 debe consumir completamente el cuerpo indicado por `Content-Length` antes de reutilizar la conexión persistente (o enviar `Connection: close`).

---

## Práctica guiada en laboratorio

En tu entorno de laboratorio local (por ejemplo, una instancia controlada de Docker con una aplicación de pruebas propia o laboratorios locales educativos), diseñá una verificación reproducible para validar la resistencia ante concurrencia y engaño de caché:

1. **Prueba de concurrencia con bloqueo SQL**: levantá un servicio local simple con dos rutas de canje de cupón: una sin transacción (`v1`) y otra con `SELECT ... FOR UPDATE` (`v2`). Enviá 15 peticiones concurrentes usando multiplexación HTTP/2 (por ejemplo, mediante el módulo `h2` o `httpx` en un entorno local controlado) sobre ambas rutas y compará cuántas veces se acredita el saldo en la base de datos.
2. **Auditoría de discrepancia proxy-origen**: colocá un Nginx delante de tu aplicación de laboratorio con una regla simulada de caché estática para `*.css` y verificá que una petición a `/perfil/test.css` devuelva explícitamente `404 Not Found` y que toda respuesta autenticada incluya `Cache-Control: private, no-store`.
3. **Inspección de handshake WebSocket**: comprobá que el servidor rechace con código `1008` cualquier intento de conexión donde la cabecera `Origin` no coincida con tu dominio local permitido.

::: practica Entregable mínimo
Documentá en un informe breve de laboratorio: (a) el fragmento de código SQL/transaccional antes y después de aplicar `FOR UPDATE` junto con la evidencia de las filas afectadas en la prueba concurrente, (b) los encabezados HTTP de respuesta que garantizan la no-cacheabilidad de rutas privadas, y (c) el resultado de validación de `Origin` y `DOMPurify` en tus componentes WebSocket y frontend.
:::

::: defensa Perspectiva defensiva y remediación
Los cinco vectores de este capítulo comparten un principio común: **nunca confíes en las suposiciones de orden temporal o de interpretación uniforme entre capas**. El backend no puede asumir que dos peticiones llegan una después de otra, el proxy no puede asumir que el origen interpreta idénticamente `Content-Length` y `Transfer-Encoding`, la caché debe reflejar parámetros clave explícitos, el servidor WebSocket no puede asumir que el navegador aplica Same-Origin Policy, y el JavaScript del navegador no puede asumir que `window` o las rutas relativas están libres de colisiones. Blindar estas fronteras requiere atomicidad en base de datos, contratos HTTP explícitos (`RFC 9112/9113`, `Cache-Control`, `Vary`, validación de `Origin`) y validación de esquema tanto en mensajes bidireccionales como en parámetros del cliente.
:::

## Preguntas de repaso

**1. ¿Por qué el ataque de paquete único (*Single-Packet Attack*) sobre HTTP/2 es significativamente más efectivo que enviar peticiones concurrentes en múltiples conexiones HTTP/1.1?**
Porque HTTP/2 multiplexa múltiples *streams* dentro de una única conexión TCP/TLS y permite retener el flag `END_STREAM` hasta el último momento; al enviar todos los cierres de stream dentro de un único paquete TCP, se elimina el *jitter* de red y el servidor despacha los hilos prácticamente en el mismo microsegundo.

**2. ¿Cuál es la diferencia fundamental entre *Web Cache Poisoning* y *Web Cache Deception*?**
En *Web Cache Poisoning* el objetivo es forzar al origen a generar una respuesta alterada (usando *Unkeyed Inputs*) para que la caché la almacene y la sirva a otros usuarios; en *Web Cache Deception* el objetivo es engañar a la caché para que guarde una respuesta privada y legítima de una víctima (aprovechando diferencias de normalización de rutas) y luego leerla como un tercero.

**3. ¿Por qué validar únicamente la cookie de sesión en un handshake WebSocket expone a la aplicación a *Cross-Site WebSocket Hijacking*?**
Porque los navegadores adjuntan cookies automáticamente en las solicitudes `Upgrade: websocket` sin aplicar la *Same-Origin Policy* para bloquear la conexión desde dominios terceros; si el servidor no verifica la cabecera `Origin` ni exige un token anti-CSRF vinculado a la sesión, un sitio externo puede abrir un túnel autenticado en nombre de la víctima.

**4. ¿Cómo puede derivar una inyección HTML sin etiquetas `<script>` en ejecución de código arbitrario mediante *DOM Clobbering*?**
Al inyectar elementos con atributos `id` o `name` coincidentes con variables globales no declaradas o propiedades del DOM, el navegador expone esas referencias en `window` o `document`; si la aplicación lee esas variables para construir URLs de scripts o destinos dinámicos, termina cargando recursos controlados por el atacante.

**5. ¿Qué combinación de controles previene de forma robusta el *Client-Side Path Traversal (CSPT)* en llamadas `fetch()` del navegador?**
Validar el parámetro de entrada con una lista blanca o expresión regular estricta (por ejemplo, solo caracteres alfanuméricos o UUID), codificar cada segmento con `encodeURIComponent()` y verificar tras construir un objeto `URL` que tanto el `origin` como el `pathname` normalizado permanezcan dentro del prefijo de API esperado.

## Antes de avanzar

::: nota Puerta de salida
Antes de pasar al capítulo sobre OAuth 2.0, OIDC y lógica de negocio, asegurate de poder explicar con tus propias palabras la diferencia entre un *Unkeyed Input* y una discrepancia de normalización de rutas, y de haber verificado al menos una transacción SQL con bloqueo pesimista (`FOR UPDATE`) o clave de idempotencia frente a peticiones paralelas.
:::

## Referencias y estándares abiertos

- **OWASP Web Security Testing Guide (WSTG v4.2)** — Secciones de *Testing for Race Conditions*, *Testing for Web Cache Poisoning* y *Testing WebSockets* (`WSTG-CLNT-10`).
- **RFC 9113 (HTTP/2)** — Especificación oficial de multiplexación de *streams* y framing.
- **RFC 6455 (The WebSocket Protocol)** — Sección 10: Consideraciones de seguridad, validación de `Origin` y protección del handshake.
- **RFC 9111 (HTTP Caching)** — Semántica de *Cache Keys*, directivas `Cache-Control` y cabecera `Vary`.
- **PortSwigger Research** — Documentación técnica sobre *Smashing the State Machine: The True Potential of Web Race Conditions* y *Practical Web Cache Poisoning*.
