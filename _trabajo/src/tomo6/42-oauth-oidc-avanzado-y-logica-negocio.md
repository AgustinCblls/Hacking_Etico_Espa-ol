::: nota Objetivo de la lección
Comprender en profundidad los flujos modernos de autenticación delegada (OAuth 2.0 y OpenID Connect), identificar sus errores de implementación más críticos y dominar la detección y remediación de vulnerabilidades de lógica de negocio mediante checklists estructuradas del estándar OWASP WSTG. Al terminar, vas a poder auditar flujos de autorización complejos y diseñar máquinas de estado resilientes en el servidor.
:::

Las fallas de inyección tradicionales suelen detectarse mediante analizadores sintácticos o escáneres automáticos porque violan la gramática esperada por un intérprete (SQL, HTML o shell). En cambio, las vulnerabilidades en protocolos de federación como **OAuth 2.0 / OIDC** y los defectos de **lógica de negocio** operan con peticiones completamente válidas desde el punto de vista sintáctico: el servidor no lanza errores de parseo, sino que ejecuta reglas de confianza o de negocio diseñadas de forma incompleta.

Auditar estas capas exige entender el protocolo completo de punta a punta y trazar los invariantes que la aplicación debería sostener en todo momento.

---

## 1. OAuth 2.0 y OpenID Connect (OIDC) avanzado

**OAuth 2.0** (RFC 6749) es un marco de **autorización delegada**, no un protocolo de autenticación. Permite que una aplicación cliente (*Client*) obtenga acceso limitado a recursos protegidos de un usuario (*Resource Owner*) alojados en un servidor de recursos, mediante tokens emitidos por un servidor de autorización (*Authorization Server*). **OpenID Connect (OIDC)** extiende OAuth 2.0 agregando una capa de **autenticación** estandarizada a través de un `id_token` en formato JWT y el endpoint `/userinfo`.

### 1.1 Authorization Code Flow + PKCE vs Implicit Flow

Históricamente, aplicaciones móviles y SPAs en navegador utilizaron el **Implicit Flow** (`response_type=token` o `id_token token`), donde el servidor de autorización devuelve el *access token* directamente en el fragmento de la URL de redirección (`https://app.ejemplo.com/cb#access_token=...`). Este flujo está **formalmente deprecado** en OAuth 2.1 y en las mejores prácticas actuales (RFC 9700) por múltiples riesgos:

- El token queda expuesto en el historial del navegador, logs de extensiones o scripts de terceros en la página de destino.
- No permite autenticar al cliente al intercambiar credenciales ni usar *Refresh Tokens* seguros.
- Amplía la superficie de inyección o sustitución de tokens en el navegador.

El estándar moderno obligatorio para todo cliente (incluyendo SPAs y apps móviles) es **Authorization Code Flow con PKCE** (*Proof Key for Code Exchange*, RFC 7636):

```text
Cliente (SPA/Backend)                              Authorization Server
  | 1. Genera code_verifier aleatorio (256 bits)         |
  | 2. Calcula code_challenge = BASE64URL(SHA256(verif)) |
  |                                                      |
  |--- GET /authorize?response_type=code                 |
  |    &client_id=...&redirect_uri=...                   |
  |    &code_challenge=...&code_challenge_method=S256 -->|
  |                                                      |
  |<-- 302 Redirect ?code=AUTH_CODE&state=... -----------|
  |                                                      |
  |--- POST /token (code + code_verifier) -------------->| Verifica SHA256(code_verifier)
  |<-- 200 { access_token, id_token } -------------------| == code_challenge almacenado
```

Con PKCE (`S256`, nunca `plain`), incluso si un atacante lograra interceptar el parámetro `code` en tránsito o en el dispositivo, **no puede canjearlo** en `/token` sin poseer el `code_verifier` original guardado únicamente en la memoria o sesión del cliente legítimo.

### 1.2 CSRF en OAuth por omisión o previsibilidad de `state`

El parámetro `state` en la solicitud `/authorize` cumple el rol de **token anti-CSRF**. El cliente genera un valor criptográficamente aleatorio antes de redirigir al usuario al proveedor de identidad (IdP), lo vincula a la sesión actual (por ejemplo, en una cookie `HttpOnly`, `SameSite=Lax` o en `sessionStorage` con firma) y lo valida estrictamente cuando el IdP redirige de vuelta al `redirect_uri`.

Si la aplicación **omite `state`** o acepta un `state` vacío/predecible en el callback:

- Un atacante puede iniciar un flujo OAuth en su propio navegador con su propia cuenta, detener la redirección justo antes de consumir `/callback?code=ATACANTE_CODE` y forzar al navegador de la víctima (mediante un enlace o iframe oculto) a visitar ese callback.
- La víctima queda autenticada dentro de la **cuenta del atacante** (*Login CSRF*). Si la aplicación además permite vincular métodos de pago o realizar acciones sensibles creyendo que está en su sesión, o si el flujo es de **vinculación de cuentas** (*account linking*), la víctima termina conectando su identidad externa al perfil del atacante, otorgándole acceso permanente a su cuenta.

### 1.3 Abuso de `redirect_uri` y encadenamiento con Open Redirect

El servidor de autorización solo debe enviar el `code` de autorización a URLs previamente registradas (*allowlist* exacta). Sin embargo, errores comunes en la lógica de comparación de `redirect_uri` en el IdP permiten redirigir el código hacia dominios o rutas controladas:

1. **Coincidencia por prefijo o subcadena**: validar `redirect_uri.startsWith("https://app.ejemplo.com")` permite registrar `https://app.ejemplo.com.atacante.invalid/cb`. Validar `.endsWith("ejemplo.com")` permite subdominios ajenos o dominios con prefijos similares (`malicioso-ejemplo.com`).
2. **Normalización y Path Traversal**: si el IdP permite `https://app.ejemplo.com/oauth/cb` y valida solo el prefijo `/oauth/cb`, una ruta como `https://app.ejemplo.com/oauth/cb/../../redir?url=https://externo.invalid` puede ser normalizada por el servidor web de la aplicación hacia otro endpoint antes de responder.
3. **Encadenamiento con Open Redirect**: aunque el IdP exija coincidencia exacta de esquema, host y ruta de `redirect_uri` (o permita cualquier ruta dentro de `https://app.ejemplo.com/*`), si existe una vulnerabilidad de **Open Redirect** en `https://app.ejemplo.com/logout?next=...`, el atacante puede usarla como `redirect_uri`. El navegador recibe el `code` en la URL de `/logout` y el servidor redirige inmediatamente hacia `next`, transfiriendo el `code` (o el fragmento `#access_token` en flujos implícitos, ya que los navegadores modernos preservan el fragmento URL a través de redirecciones `302`) al destino externo.

```python
# Validación estricta de redirect_uri en el Authorization Server (sin prefijos ni regex laxas)
from urllib.parse import urlparse

def validate_redirect_uri(registered_uris: set[str], requested_uri: str) -> bool:
    if not requested_uri or "#" in requested_uri:
        return False  # RFC 6749 prohíbe fragmentos en redirect_uri

    parsed = urlparse(requested_uri)
    if parsed.scheme != "https" or not parsed.netloc:
        return False

    # Comparación exacta carácter por carácter contra la allowlist registrada para ese client_id
    return requested_uri in registered_uris
```

::: aviso Validación doble en /authorize y /token
Según RFC 6749 (sección 4.1.3), el servidor de autorización no solo debe validar `redirect_uri` de forma exacta en `/authorize`, sino también verificar en `POST /token` que el `redirect_uri` enviado al canjear el código coincida exactamente con el usado en la solicitud de autorización inicial.
:::

### 1.4 Fuga de tokens por `Referer` e historial

Cuando un código de autorización (`?code=...`) o token llega en la URL de callback, cualquier recurso externo incrustado en esa misma página (una imagen de analítica, una fuente externa, un botón social o un enlace saliente) hace que el navegador envíe la URL completa —incluyendo el `code`— en la cabecera HTTP `Referer`, salvo que se configure explícitamente la política de referencia.

Controles obligatorios en la página de callback:
- Enviar `Referrer-Policy: no-referrer` en la respuesta HTTP del callback.
- Limpiar la barra de direcciones inmediatamente con `history.replaceState({}, document.title, "/callback")` o responder con una redirección `302` inmediata tras canjear el código en el servidor, evitando renderizar contenido HTML complejo o recursos externos en esa ruta.

### 1.5 Vinculación de cuentas y validación estricta de `id_token` en OIDC

Dos errores recurrentes de implementación en OIDC comprometen la identidad del usuario:

1. **Account Linking sin re-autenticación ni verificación de correo**: muchas plataformas permiten iniciar sesión con email/contraseña y también con "Continuar con Google/GitHub". Si el backend vincula automáticamente la identidad OIDC a una cuenta existente basándose únicamente en el claim `email` recibido del IdP **sin verificar** `email_verified === true` (algunos proveedores permiten correos sin verificar o cambiables), un tercero puede apropiarse de cuentas locales registrando ese correo en un proveedor permisivo. Del mismo modo, agregar un proveedor secundario desde la configuración del perfil siempre debe exigir **re-autenticación reciente** y confirmación CSRF.
2. **Validación incompleta del `id_token` (JWT)**: en OIDC, el `id_token` es un JWT firmado que certifica la identidad. El cliente (Relying Party) debe verificar obligatoriamente cada uno de estos campos antes de crear la sesión:

```python
# Validación robusta de id_token OIDC en backend (ejemplo conceptual con PyJWT)
import jwt

def verify_oidc_id_token(id_token: str, jwks_client, expected_nonce: str) -> dict:
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256", "ES256"],  # Lista blanca explícita; jamás aceptar 'none' ni HS256 con clave pública
        audience="mi-client-id-oficial", # Valida 'aud'
        issuer="https://idp.ejemplo.com",# Valida 'iss' exacto
        options={
            "require": ["exp", "iat", "iss", "aud", "sub", "nonce"],
            "verify_exp": True,
        },
    )

    # Validar nonce vinculado a la sesión previa al flujo (previene replay de id_token)
    if not constant_time_compare(claims["nonce"], expected_nonce):
        raise ValueError("Nonce OIDC inválido")

    if not claims.get("email_verified", False):
        raise ValueError("El correo del proveedor no está verificado")

    return claims
```

---

## 2. Ataques de Lógica de Negocio

Las vulnerabilidades de lógica de negocio (*Business Logic Flaws*) nacen cuando los desarrolladores codifican el "camino feliz" (*happy path*) asumiendo que los usuarios interactuarán con la aplicación exclusivamente a través de la interfaz gráfica diseñada, respetando el orden de pantallas, los límites de formularios y las reglas implícitas del dominio.

### 2.1 Saltos de pasos en flujos multi-etapa (*Workflow Bypass*)

Procesos críticos como *checkouts* de comercio electrónico, verificaciones KYC, activación de 2FA o aprobaciones financieras suelen dividirse en pasos (`/paso-1-carrito`, `/paso-2-pago`, `/paso-3-confirmacion`). Si el servidor no mantiene una **máquina de estados estricta** en la sesión o base de datos y confía en un campo oculto (`step=3`) o permite invocar directamente `/paso-3-confirmacion` sin verificar que `/paso-2-pago` haya transicionado al estado `PAID`, el flujo completo queda eludido.

```python
# Ejemplo vulnerable: asume que el cliente solo llega aquí tras pagar
@app.post("/checkout/confirm")
def confirm_order(order_id: int):
    order = db.get_order(order_id)
    # Falta validar order.status == "PAYMENT_CONFIRMED"
    db.mark_order_fulfilled(order_id)
    return {"message": "Pedido confirmado"}
```

**Remediación**: modelar las transiciones permitidas explícitamente en el servidor mediante un grafo de estados (`ALLOWED_TRANSITIONS = {"PENDING_PAYMENT": {"PAID", "CANCELLED"}, "PAID": {"FULFILLED"}}`), validando el estado previo dentro de una transacción antes de ejecutar la siguiente acción:

```python
# Implementación segura de máquina de estados y cálculo exacto en servidor
from decimal import Decimal, ROUND_HALF_EVEN

ALLOWED_TRANSITIONS = {
    "CART": {"PENDING_PAYMENT", "CANCELLED"},
    "PENDING_PAYMENT": {"PAID", "CANCELLED"},
    "PAID": {"FULFILLED", "REFUNDED"},
}

def transition_order_and_calculate(order_id: int, user_id: int, target_state: str) -> Decimal:
    with db.transaction():
        order = db.query_one(
            "SELECT id, user_id, status, coupon_code FROM orders WHERE id = %s FOR UPDATE",
            (order_id,),
        )
        if not order or order.user_id != user_id:
            raise PermissionError("Orden inexistente o no pertenece al usuario")

        if target_state not in ALLOWED_TRANSITIONS.get(order.status, set()):
            raise ValueError(f"Transición inválida: {order.status} -> {target_state}")

        # Recálculo autoritativo en backend usando Decimal exacto (nunca confiar en precios del cliente)
        items = db.query_all(
            "SELECT oi.quantity, p.unit_price_cents FROM order_items oi "
            "JOIN products p ON p.id = oi.product_id WHERE oi.order_id = %s",
            (order_id,),
        )
        subtotal_cents = sum(item.quantity * item.unit_price_cents for item in items if item.quantity > 0)
        total = (Decimal(subtotal_cents) / Decimal(100)).quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)

        db.execute(
            "UPDATE orders SET status = %s, total_amount = %s WHERE id = %s AND status = %s",
            (target_state, total, order_id, order.status),
        )
        return total
```

Fijate que este patrón combina tres defensas simultáneas: validación de propiedad (`order.user_id == user_id` contra IDOR), verificación estricta de transición en una máquina de estados bajo `FOR UPDATE`, y recálculo monetario autoritativo con `Decimal` a partir de centavos del catálogo en base de datos.

### 2.2 Manipulación de cantidades, precios negativos y precisión decimal

Cuando los cálculos monetarios o de inventario aceptan entradas numéricas sin invariantes estrictos en el backend, aparecen anomalías graves:

- **Cantidades o montos negativos**: en un carrito con dos productos, enviar `quantity = -2` para un artículo puede restar saldo del total a pagar o generar un crédito positivo en la billetera del usuario.
- **Confianza en precios enviados por el cliente**: incluir `price: 10.00` en el payload JSON del carrito en lugar de consultar el precio vigente desde el catálogo en servidor.
- **Errores de precisión decimal y punto flotante**: usar `float` (`IEEE 754`) para dinero o tasas de conversión introduce errores de representación (`0.1 + 0.2 = 0.30000000000000004`). Si un endpoint trunca o redondea hacia abajo (`int(monto)` o `floor`) para validar si hay saldo suficiente o calcular comisiones, transferencias fraccionarias repetidas (por ejemplo `0.004` unidades cuando se redondea a dos decimales) pueden generar acreditaciones sin débito equivalente o viceversa.

**Reglas de oro en lógica financiera:**
- Nunca usar `float` ni `double` para dinero. Utilizar enteros en la unidad mínima indivisible (centavos) o tipos `Decimal` con precisión exacta y política explícita de redondeo (`ROUND_HALF_EVEN` o a favor del sistema en comisiones).
- Validar estrictamente rangos en el servidor: `1 <= quantity <= MAX_ORDER_QTY` y `amount > 0`.
- Calcular precios, impuestos y descuentos **exclusivamente en el servidor** a partir de los IDs de catálogo y las reglas vigentes.

### 2.3 Abuso de cupones, descuentos acumulables y límites de dominio

Incluso cuando los montos son positivos, las combinaciones de reglas de negocio suelen crear brechas:

- **Acumulación no prevista**: aplicar el mismo cupón dos veces si no se verifica unicidad por orden/usuario, o combinar dos cupones incompatibles cambiando el orden de aplicación (`CUPON_50_PORCIENTO` + `CUPON_FIJO_100`).
- **Desbordamiento de límites de dominio**:
  - Cambiar la moneda del pedido entre la cotización y la pasarela de pago (pagar en moneda de menor valor nominal manteniendo el número de monto).
  - Dividir una transferencia en múltiples transacciones pequeñas para evadir un límite por operación cuando el sistema no acumula un tope diario/mensual.
  - Abusar de la lógica de reembolso parcial tras haber aplicado un descuento por volumen: comprás 10 artículos con 30% de descuento, devolvés 9 al precio unitario lleno y conservás el restante por debajo del costo.

| Defecto de lógica | Causa raíz típica | Control estructural de remediación |
| :--- | :--- | :--- |
| **Workflow bypass** | Ausencia de máquina de estados persistida en servidor. | Validar estado actual en DB (`status = 'PAID'`) en cada transición. |
| **Montos negativos / cero** | Validación realizada solo con atributos HTML (`min="1"`). | Validar tipos enteros positivos (`amount > 0`) en esquema backend y `CHECK` SQL. |
| **Arbitraje de redondeo** | Uso de `float` y redondeo inconsistente entre débito y crédito. | Operar en centavos enteros o `Decimal` con verificación `debito == credito`. |
| **Abuso de cupones** | Lógica de carrito mutable sin recálculo atómico final. | Recalcular subtotal, descuentos e impuestos en servidor al cerrar la orden bajo lock. |
| **Límites evadidos** | Verificación por petición aislada sin agregación temporal. | Contadores atómicos por ventana (`user_id + fecha`) en DB o Redis. |

---

<!-- salto -->

## 3. Checklists prácticas OWASP WSTG

Para evitar auditorías improvisadas que solo buscan payloads obvios, el **OWASP Web Security Testing Guide (WSTG)** provee códigos de prueba estandarizados. A continuación tenés una matriz operativa enfocada en autorización (`WSTG-ATHZ`), gestión de sesiones/federación (`WSTG-SESS`) y lógica de negocio (`WSTG-BUSL`) para aplicar en cualquier flujo web completo.

| Código WSTG | Nombre de la prueba | Qué verificar concretamente en auditoría |
| :--- | :--- | :--- |
| **`WSTG-ATHZ-01`** | *Directory Traversal / File Include* | Confirmar que parámetros de ruta o descarga no escapan del directorio base y no existen discrepancias proxy-origen. |
| **`WSTG-ATHZ-02`** | *Bypassing Authorization Schema* | Probar acceso directo a endpoints internos/administrativos saltando pantallas de UI o alterando métodos HTTP (`GET`/`POST`/`HEAD`). |
| **`WSTG-ATHZ-03`** | *Privilege Escalation* | Verificar que un usuario de rol estándar no pueda asignarse roles elevados (`role: admin` en *mass assignment*) ni ejecutar acciones de otro tenant. |
| **`WSTG-ATHZ-04`** | *Insecure Direct Object References (IDOR)* | Reemplazar IDs numéricos o UUIDs de órdenes, facturas o perfiles para confirmar que el servidor valida propiedad (`owner_id == session.user_id`). |
| **`WSTG-SESS-01`** | *Session Management Schema* | Revisar entropía, flags `HttpOnly`/`Secure`/`SameSite`, expiración real en servidor al cerrar sesión y uso obligatorio de PKCE (`S256`) en OAuth. |
| **`WSTG-SESS-05`** | *Cross Site Request Forgery (CSRF)* | Confirmar presencia, aleatoriedad y verificación estricta del parámetro `state` en callbacks OAuth y tokens CSRF en cambios de estado. |
| **`WSTG-BUSL-01`** | *Test Business Logic Data Validation* | Probar valores negativos, cero, decimales extremos (`0.0001`), tipos inesperados y longitudes límites en montos y cantidades. |
| **`WSTG-BUSL-03`** | *Test Integrity Checks* | Verificar si campos calculados (totales, descuentos, roles, timestamps) son modificables al interceptar el cuerpo antes de enviarlo al backend. |
| **`WSTG-BUSL-06`** | *Test Circumvention of Work Flows* | Intentar invocar el paso final de un flujo multi-etapa directamente, repetir un paso ya completado o invertir el orden de pasos. |
| **`WSTG-BUSL-07`** | *Test Defenses Against Application Misuse* | Evaluar límites de tasa, abuso de cupones acumulables, reintentos de verificación y reglas de devolución/reembolso. |
| **`WSTG-BUSL-09`** | *Test Upload of Unexpected File Types* | Comprobar validación de *magic bytes*, extensión en lista blanca, renombrado seguro y almacenamiento fuera de la raíz ejecutable web. |

### Metodología de auditoría paso a paso sobre un flujo completo

Al auditar una aplicación web moderna (por ejemplo, un portal de pagos con login OIDC), seguí esta secuencia sistemática:

1. **Mapeo completo del flujo legítimo**: capturá todas las peticiones desde el clic en "Iniciar sesión con OIDC" hasta la confirmación final de una operación de negocio. Identificá cada redirección, cookie emitida, token JWT y parámetro enviado.
2. **Auditoría de identidad federada**: inspeccioná la petición `/authorize` (presencia de `code_challenge_method=S256`, `state`, `nonce`), verificá en el callback si el servidor valida `state`, probá cómo responde el backend ante un `id_token` con otro `aud`, sin `nonce` o con `email_verified: false`.
3. **Extracción de máquina de estados e invariantes**: listá en una tabla los estados válidos de la entidad principal (ej. `Carrito -> Pendiente -> Pagado -> Enviado`) y los invariantes matemáticos (`total == suma(precio_catalogo * cantidad) - descuento`, `saldo >= 0`).
4. **Pruebas de violación de invariantes y WSTG**: aplicá sistemáticamente cada fila de la tabla `WSTG-ATHZ`, `WSTG-SESS` y `WSTG-BUSL` sobre las transiciones identificadas, documentando evidencia de código y respuesta HTTP.

---

## Práctica guiada en laboratorio

Configurá un entorno de laboratorio local con un cliente OIDC de prueba (por ejemplo, un servidor local con *Keycloak* o un mock OIDC en Python/Node.js) y una API sencilla de tienda online con carrito, cupón y checkout en tres pasos:

1. **Verificación de PKCE y `state`**: configurá el cliente para usar `Authorization Code + PKCE (S256)` y `state` aleatorio guardado en sesión. Realizá dos pruebas controladas en tu laboratorio: enviá un callback con `state` modificado y verificá que el cliente lo rechace con HTTP `400/403`; luego intentá canjear un `code` válido en `/token` omitiendo o alterando `code_verifier` para confirmar que el Authorization Server lo rechaza.
2. **Validación de `id_token`**: implementá el verificador JWT de tu backend local y comprobalo frente a tres casos negativos de prueba unitaria: firma inválida, `aud` perteneciente a otra aplicación cliente y ausencia de `nonce`.
3. **Auditoría `WSTG-BUSL` del checkout**: revisá tu endpoint de confirmación de orden local verificando tres invariantes: rechazo de cantidades negativas/decimales, transición inválida de estado (`PENDING -> FULFILLED` sin pasar por `PAID`) y bloqueo de doble aplicación del mismo cupón.

::: practica Entregable mínimo
Entregá una matriz de auditoría completada con al menos 6 casos de prueba basados en códigos `WSTG-ATHZ`, `WSTG-SESS` y `WSTG-BUSL` ejecutados contra tu aplicación de laboratorio, incluyendo: el código WSTG, la precondición del flujo, la respuesta esperada vs. observada antes de la remediación y el parche implementado en el servidor.
:::

::: defensa Perspectiva defensiva y remediación
La seguridad en OAuth 2.0/OIDC y en la lógica de negocio no se resuelve con filtros perimetrales ni WAFs, porque todas las peticiones involucradas tienen formato HTTP y JSON válido. La defensa efectiva exige dos pilares: adoptar estándares actuales sin atajos (**Authorization Code + PKCE S256**, `state` aleatorio vinculado a sesión, validación estricta de `redirect_uri` exacta y verificación completa de `iss`/`aud`/`nonce`/`exp` en el `id_token`) y trasladar cada regla crítica del negocio a **máquinas de estado explícitas y aritmética exacta en el backend**.
:::

## Preguntas de repaso

**1. ¿Por qué el *Implicit Flow* de OAuth 2.0 fue deprecado en favor de *Authorization Code Flow* con PKCE incluso para SPAs en el navegador?**
Porque el *Implicit Flow* expone los tokens directamente en el fragmento de la URL de redirección (riesgo de fuga vía historial o scripts) y no ofrece prueba criptográfica de posesión del cliente; PKCE (`S256`) vincula el código de autorización a un `code_verifier` secreto generado por la instancia cliente, impidiendo que un código interceptado pueda canjearse en `/token`.

**2. ¿Qué riesgo de seguridad concreto introduce omitir o no validar el parámetro `state` en el callback de OAuth 2.0?**
Expone al flujo a ataques de *Cross-Site Request Forgery* (CSRF) en el inicio de sesión o en la vinculación de cuentas, permitiendo que un tercero fuerce al navegador de la víctima a consumir un código de autorización generado por el atacante y autentique o vincule la sesión de la víctima con la cuenta del atacante.

**3. ¿Cómo se combina una validación exacta de `redirect_uri` a nivel de dominio con un *Open Redirect* para comprometer un flujo OAuth?**
Si el servidor de autorización permite cualquier ruta dentro del dominio confiable (`https://app.ejemplo.com/*`) o si el `redirect_uri` apunta a un endpoint interno que sufre de *Open Redirect* (por ejemplo `/logout?next=...`), el navegador entrega el código o fragmento a ese endpoint y la aplicación redirige inmediatamente al usuario hacia un dominio externo filtrando el parámetro.

**4. ¿Por qué nunca debe usarse aritmética de punto flotante (`float`/`double`) en el cálculo de saldos, precios o comisiones?**
Porque la representación binaria IEEE 754 introduce errores de redondeo exacto (como `0.1 + 0.2 != 0.3`), lo que al combinarse con truncamientos o comparaciones puede provocar discrepancias contables, pérdidas de precisión acumulada o bypass de validaciones de saldo mínimo.

**5. ¿Qué verifica el código `WSTG-BUSL-06` del estándar OWASP WSTG y cómo se remedia la falla asociada?**
Verifica si es posible eludir pasos obligatorios, alterar el orden o repetir etapas dentro de un flujo de trabajo multi-etapa (*workflow bypass*). Se remedia persistiendo una máquina de estados estricta en el servidor y validando en cada endpoint que el estado actual de la entidad permita la transición solicitada dentro de una transacción atómica.

## Antes de avanzar

::: nota Puerta de salida
Antes de continuar al capítulo de *Threat Modeling* y arquitectura segura, verificá que podés dibujar de memoria el flujo completo de **Authorization Code + PKCE + OIDC** indicando exactamente en qué paso se validan `state`, `code_challenge` y `nonce`, y explicar cómo diseñarías una máquina de estados segura para un proceso de pago.
:::

## Referencias y estándares abiertos

- **RFC 6749** — *The OAuth 2.0 Authorization Framework*.
- **RFC 7636** — *Proof Key for Code Exchange by OAuth Public Clients (PKCE)*.
- **RFC 9700** — *Best Current Practice for OAuth 2.0 Security*.
- **OpenID Connect Core 1.0** — Validación de `id_token`, `nonce`, `aud` e `iss`.
- **OWASP Web Security Testing Guide (WSTG)** — Categorías `WSTG-ATHZ`, `WSTG-SESS` y `WSTG-BUSL`.
