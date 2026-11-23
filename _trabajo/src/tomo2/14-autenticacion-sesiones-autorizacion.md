::: nota Objetivo de la lección
Al terminar este capítulo vas a dominar la arquitectura de los sistemas de autenticación y autorización web: diseñar flujos de inicio de sesión resistentes a enumeración y fuerza bruta, gestionar el ciclo de vida seguro de sesiones, auditar la estructura criptográfica y los *claims* de JSON Web Tokens (JWT, RFC 7519), comprender los flujos de delegación OAuth 2.0 / OpenID Connect con PKCE, y erradicar fallos de control de acceso horizontal y vertical (IDOR, BOLA y BFLA) aplicándolos sobre `laboratorios/app_lab_educativa.py`.
:::

**Prerrequisitos:** Capítulo 1.8 (HTTP y cookies) y Capítulo 2.4 (Seguridad del lado del cliente). **Duración sugerida:** 7 a 9 horas.

## 1. Autenticación frente a Autorización

Aunque suelen mencionarse juntos, **autenticación (AuthN)** y **autorización (AuthZ)** resuelven dos problemas completamente distintos y deben evaluarse por separado en toda auditoría:

- **Autenticación (*¿Quién sos?*):** verifica la identidad declarada por un usuario o servicio mediante uno o varios factores (contraseña almacenada con Argon2id, código TOTP/WebAuthn MFA, certificado cliente) y emite una credencial temporal de sesión.
- **Autorización (*¿Qué tenés permiso para hacer y sobre qué datos?*):** verifica en **cada petición posterior** si esa identidad ya autenticada posee permisos para ejecutar la función solicitada (*control vertical*) y para acceder al registro u objeto específico (*control horizontal*).

Un sistema puede tener una autenticación criptográficamente impecable con MFA y, sin embargo, ser totalmente vulnerable si una vez iniciada la sesión un usuario normal puede consultar `/ticket-seguro/2` y leer los datos de otro cliente.

## 2. Seguridad en flujos de autenticación y gestión de sesiones

Al auditar un sistema de inicio de sesión, recuperación de cuenta y manejo de sesiones (**OWASP ASVS 5.0**, Capítulos **V6 — Authentication** y **V7 — Session Management**), existen cuatro debilidades clásicas que debés verificar y corregir:

### 1. Enumeración de usuarios por diferencias en respuestas o tiempos

Si el formulario de login o de recuperación de clave responde `"El usuario no existe"` cuando el correo no está registrado y `"Contraseña incorrecta"` cuando sí existe, regala un oráculo perfecto para listar todas las cuentas válidas del sistema.
- **Mitigación:** devolver siempre un mensaje uniforme (`"Credenciales inválidas"` o `"Si el correo está registrado, recibirás un enlace en los próximos minutos"`) y ejecutar una verificación de hash ficticia de tiempo constante cuando el usuario no exista, evitando también diferencias medibles de tiempo de respuesta (*timing side-channel*).

### 2. Ausencia de límites de tasa (Rate Limiting) y protección ante fuerza bruta

Sin un control de tasa por cuenta y por dirección IP/red, un servicio de autenticación queda expuesto a adivinación automatizada de contraseñas o *password spraying* (probar una misma contraseña común contra cientos de usuarios).
- **Mitigación:** aplicar *rate limiting* progresivo con retroceso exponencial (*exponential backoff*), exigir autenticación multifactor resistente a phishing (FIDO2 / WebAuthn o TOTP) y evitar bloqueos permanentes de cuenta que puedan abusarse para provocar una denegación de servicio contra usuarios legítimos.

### 3. Ciclo de vida inseguro del identificador de sesión

Un identificador de sesión tradicional en cookie debe ser una cadena aleatoria generada con un generador criptográficamente seguro (`secrets.token_urlsafe(32)` en Python, con al menos 128 bits de entropía) cuyo estado real viva en el servidor (base de datos o Redis).
- **Reglas obligatorias del ciclo de vida:**
  1. **Rotar el ID de sesión inmediatamente después del login** (previene *Session Fixation*).
  2. **Invalidar la sesión en el servidor al cerrar sesión (*Logout*)**, no solo borrar la cookie en el navegador.
  3. **Definir tiempos de expiración absolutos y por inactividad** (*idle timeout*).

## 3. Anatomía y auditoría de JSON Web Tokens (JWT — RFC 7519)

En arquitecturas de APIs modernas es habitual reemplazar o complementar las sesiones en memoria del servidor por **JSON Web Tokens (JWT)**. Un JWT es una cadena compuesta por tres bloques codificados en **Base64URL** separados por puntos (`Header.Payload.Signature`):

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbmEiLCJyb2xlIjoiYW5hbGlzdGEiLCJleHAiOjE3OTUzOTAwMDB9.FirmaCriptograficaBase64Url
└────────────── Header ──────────────┘ └─────────────────────── Payload ───────────────────────┘ └─────── Signature ───────┘
```

1. **Header (Cabecera):** declara el tipo de token (`"typ": "JWT"`) y el algoritmo criptográfico empleado para firmarlo (`"alg": "HS256"`, `"RS256"`, `"ES256"`).
2. **Payload (Cuerpo o *Claims*):** contiene las afirmaciones sobre la identidad y validez del token:
   - `sub` (*Subject*): identificador único del usuario.
   - `iss` (*Issuer*): quién emitió el token.
   - `aud` (*Audience*): para qué servicio o API fue emitido.
   - `iat` (*Issued At*) y `exp` (*Expiration Time*): marcas de tiempo Unix de emisión y vencimiento.
3. **Signature (Firma):** garantiza la **integridad y autenticidad** del Header y del Payload.

::: peligro Recordatorio crítico: un JWT firmado (JWS) NO está cifrado
La codificación Base64URL de un JWT estándar es 100 % reversible por cualquiera que vea el token. La firma impide que alguien **modifique** el contenido sin conocer la clave secreta o privada, pero no oculta los datos. Nunca guardes secretos, contraseñas ni datos personales sensibles dentro del payload de un JWT.
:::

### Fallos críticos en implementaciones de JWT y cómo corregirlos

| Defecto de implementación | Por qué ocurre | Mitigación de ingeniería (RFC 8725) |
|---|---|---|
| **Aceptación del algoritmo `none`** | La biblioteca obedece el campo `"alg": "none"` enviado en el header del propio token y da por válida una firma vacía. | Pasar siempre una lista fija y explícita de algoritmos permitidos al verificar: `jwt.decode(token, clave, algorithms=["HS256"])`. |
| **Secretos HMAC (`HS256`) cortos o predecibles** | Firmar con una clave simétrica débil como `"secreto123"` permite que cualquiera que obtenga un token pruebe diccionarios offline hasta hallar la clave. | Generar secretos HMAC con `secrets.token_bytes(32)` (256 bits reales de entropía aleatoria) o usar firma asimétrica (`RS256` / `ES256`). |
| **Confusión de algoritmo (`RS256` → `HS256`)** | El servidor usa par de claves pública/privada RSA, pero acepta `"alg": "HS256"` en el header y usa su propia clave pública RSA como si fuera un secreto simétrico HMAC. | Fijar estrictamente `algorithms=["RS256"]` y usar objetos de clave tipados que prohíban usar una clave pública RSA en una función HMAC. |
| **Falta de validación de `exp`, `iss` o `aud`** | El backend verifica la firma pero no comprueba si el token venció o si fue emitido para otro microservicio. | Exigir `require=["exp", "iss", "aud", "sub"]` en la configuración del validador JWT. |
| **Inyección en cabecera `kid` (*Key ID*)** | El servidor toma el campo `"kid"` del header sin validar y lo concatena en una ruta de archivo (`../`) o consulta SQL para buscar la clave de firma. | Validar `kid` contra un mapa cerrado en memoria de claves activas (nunca construir rutas ni queries SQL desde `kid`). |

## 4. Fundamentos de seguridad en OAuth 2.0, OpenID Connect (OIDC) y SAML 2.0

**OAuth 2.0 (RFC 6749 y RFC 9700)** es un estándar de delegación de autorización, sobre el cual **OpenID Connect (OIDC)** construye una capa de autenticación federada (SSO). En el flujo moderno recomendado (**Authorization Code Flow con PKCE**):

1. La aplicación cliente redirige al usuario al Proveedor de Identidad (IdP) enviando su `client_id`, la `redirect_uri`, un parámetro aleatorio anti-CSRF llamado **`state`** y un desafío criptográfico **`code_challenge` (PKCE, RFC 7636)**.
2. Tras autenticarse el usuario, el IdP redirige el navegador a `redirect_uri` entregando un código efímero de un solo uso (`code`) y devolviendo el mismo `state`.
3. El cliente verifica que `state` coincida con su sesión y canjea el `code` por los tokens enviando el `code_verifier` original.

**Los tres controles obligatorios al auditar OAuth 2.0:**
- **Comparación exacta byte a byte de `redirect_uri`:** nunca permitir comodines ni coincidencias parciales de prefijo en las URLs de retorno registradas, para impedir que el código de autorización sea redirigido a una ruta no confiable.
- **Validación estricta del parámetro `state`:** vinculada a la sesión del navegador para impedir ataques de inicio de sesión forzado (*Login CSRF*).
- **Uso obligatorio de PKCE (`S256`):** incluso en clientes confidenciales, tal como establece las mejores prácticas actuales del IETF (RFC 9700).

### Seguridad de SAML 2.0 (SSO Empresarial en XML)

En entornos corporativos (*Single Sign-On*), **SAML 2.0** transmite aserciones de identidad firmadas en formato XML (`<saml:Assertion>`). Al heredar XML + firma digital, presenta tres riesgos propios que deben auditarse y monitorearse:
- **XXE en el parser SAML:** si el *Service Provider (SP)* procesa la aserción XML sin desactivar entidades DTD antes de validar la firma, queda expuesto a lectura de archivos o SSRF.
- **XML Signature Wrapping (XSW):** ocurre cuando el módulo criptográfico valida una etiqueta `<Signature>` válida colocada en un elemento del documento XML, pero la lógica de negocio lee el usuario (`<NameID>`) de otro bloque XML no firmado añadido en otra rama. **Mitigación:** validar la firma sobre todo el árbol canónico exacto usado posteriormente por la aplicación y rechazar documentos con múltiples aserciones o elementos `ID` duplicados.
- **Autenticación por comentarios en XML / Manipulación de `NameID`:** asegurarse de normalizar nodos de texto completos tras verificar la firma y detectar en el SIEM aserciones SAML con múltiples nodos `<Assertion>` o firmas ausentes.

## 5. Control de acceso: IDOR, BOLA, BFLA y HTTP Verb Tampering

Los fallos de autorización encabezan tanto el **OWASP Top 10:2025 (`A01:2025 – Broken Access Control`, verificable en ASVS 5.0 Cap. V8 — *Authorization*)** como el **OWASP API Security Top 10 (API1:2023 BOLA y API5:2023 BFLA)**:

1. **Control de acceso horizontal — IDOR (*Insecure Direct Object Reference*) / BOLA (*Broken Object Level Authorization*):**
   Ocurre cuando un usuario autenticado `ana` cambia el identificador de un recurso en la URL, en el cuerpo JSON o en una consulta GraphQL (por ejemplo, de `/tickets/1` a `/tickets/2`) y el servidor devuelve o modifica el objeto de `carlos` porque solo verificó que la sesión estuviera iniciada, pero **olvidó comprobar que el objeto solicitado perteneciera a `ana`**.
2. **Control de acceso vertical — BFLA (*Broken Function Level Authorization*) y *HTTP Verb Tampering*:**
   Ocurre cuando un usuario con rol estándar (`analista`) invoca un endpoint administrativo (`POST /api/admin/usuarios/crear` o `DELETE /api/logs`) y el servidor ejecuta la acción porque solo comprobó autenticación general en lugar de verificar el rol específico. Una variante clásica es **HTTP Verb Tampering**: cuando una regla de control de acceso bloquea explícitamente solo `GET` y `POST` hacia `/admin`, pero el servidor procesa igualmente una petición `HEAD`, `PUT` o un método personalizado sin activar el filtro de autorización. **Mitigación:** denegar todo por defecto y definir reglas de autorización independientes del método HTTP.

## 6. Ejemplo paso a paso: ciclo Purple Team de IDOR y JWT débil (`Ataca → Detecta → Corrige`)

En `laboratorios/app_lab_educativa.py` podés reproducir tanto el acceso horizontal indebido (IDOR/BOLA) como la aceptación de tokens JWT con `alg: none`:

```bash
# --- A. IDOR / BOLA ---
# 1. ATACA (/ticket-vulnerable): Ana pide el ticket #2 (propiedad de Carlos)
curl -i "http://127.0.0.1:5050/ticket-vulnerable/2?user=ana"

# 2. DETECTA: evento IDOR_Access registrado en /telemetria-lab
curl -s "http://127.0.0.1:5050/telemetria-lab"

# 3. CORRIGE Y VERIFICA (/ticket-seguro): devuelve 403 Forbidden
curl -i "http://127.0.0.1:5050/ticket-seguro/2?user=ana"

# --- B. JWT débil (alg: none) ---
# Pedir un token de prueba débil y contrastar /jwt-vulnerable vs /jwt-seguro
curl -s "http://127.0.0.1:5050/jwt-login?user=ana&modo=debil"
```

Salida verificada en el laboratorio:

```text
# IDOR vulnerable (/ticket-vulnerable/2?user=ana -> 200 OK exponiendo dato de Carlos):
{"detalle":"Registro SPF/DMARC pendiente — secreto_lab_carlos","id":2,"modo":"vulnerable_idor","owner":"carlos"}

# Control anti-IDOR (/ticket-seguro/2?user=ana -> 403 Forbidden):
HTTP/1.1 403 Forbidden
{"error":"Acceso denegado o recurso inexistente"}
```

Observá dos decisiones clave en `/ticket-seguro` y `/jwt-seguro`:
1. La restricción `AND owner = ?` se aplica directamente en la consulta parametrizada, sin cargar objetos ajenos ni revelar si el `id` existe, y `/jwt-seguro` rechaza explícitamente cualquier header distinto de `alg == "HS256"` validando `exp`, `iss` y `aud` con clave aleatoria segura (`hmac.compare_digest`).

::: defensa Perspectiva defensiva y mitigación
1. **Autorización declarativa y centralizada:** nunca dependas de que cada desarrollador recuerde escribir un `if` manual suelto. Usá decoradores o middlewares de políticas (`@requiere_rol("admin")`) para el control vertical y filtros de ámbito por propietario (`repositorio.obtener_por_id_y_propietario(id, usuario_actual.id)`) para el control horizontal.
2. **Los UUIDs no reemplazan el control de acceso:** cambiar identificadores numéricos (`1, 2, 3`) por UUIDv4 (`8f3c...`) dificulta la enumeración secuencial, pero si el servidor no verifica la propiedad del recurso, sigue existiendo una vulnerabilidad BOLA/IDOR cada vez que un UUID se comparta en logs, URLs o referencias cruzadas.
3. **Pruebas automatizadas de matriz de permisos en CI/CD:** toda suite de tests de una API debe incluir pruebas que ejecuten cada endpoint con tres identidades: anónimo (esperando `401`), usuario estándar accediendo a un recurso de otro usuario (esperando `403`/`404`) y propietario legítimo (esperando `200`).
:::

## Práctica en laboratorio local

1. **IDOR y JWT en `app_lab_educativa.py`:** ejecutá la matriz en un script `auditar_autorizacion.py` sobre `/ticket-vulnerable/2?user=ana` vs. `/ticket-seguro/2?user=ana` y armá un JWT de prueba con `{"typ":"JWT","alg":"none"}` contra `/jwt-vulnerable` (observando `JWT_Alg_None` en `/telemetria-lab`) para confirmar luego su rechazo (`401`) en `/jwt-seguro`.
2. **Práctica en OWASP Juice Shop (`127.0.0.1:3000`):** resolvé un desafío de manipulación de carrito/usuario ajeno (IDOR/BOLA) o de JWT firmado con clave débil/ninguna.
3. **Laboratorios adicionales:** explorá **crAPI** (OWASP *Completely Ridiculous API*) para practicar BOLA/BFLA en APIs modernas y los laboratorios de *Access Control* y *JWT* en **PortSwigger Web Security Academy**.

::: practica Entregable mínimo
El script `auditar_autorizacion.py` con la matriz IDOR + prueba JWT (`alg: none` vs. `/jwt-seguro`) pasando al 100 %, captura de `/telemetria-lab` y ficha corta del reto BOLA/JWT resuelto en OWASP Juice Shop.
:::

## Preguntas de repaso

**1. ¿Por qué es necesario rotar el identificador de sesión (emitir un nuevo ID de cookie) inmediatamente después de que un usuario se autentica con éxito?** Para prevenir ataques de fijación de sesión (*Session Fixation*). Si el servidor reutiliza el mismo ID de sesión que existía antes del login, cualquier actor que hubiera logrado fijar o conocer ese ID previo pasaría a controlar la sesión autenticada del usuario.

**2. Si los datos de un JSON Web Token (JWT) estándar llevan una firma criptográfica válida (`HS256` o `RS256`), ¿es seguro guardar información confidencial dentro de su payload?** No. Un JWT firmado (JWS) garantiza integridad y autenticidad (nadie puede alterarlo sin invalidar la firma), pero su contenido está simplemente codificado en Base64URL, por lo que cualquiera que tenga acceso al token puede decodificarlo y leer el JSON en texto claro.

**3. ¿En qué consiste la vulnerabilidad de confusión de algoritmo (`RS256` a `HS256`) en JWT y cómo se previene en una línea de código?** Ocurre cuando un servidor diseñado para verificar firmas asimétricas `RS256` con su clave pública RSA acepta un token cuyo header declara `"alg": "HS256"` y utiliza esa misma clave pública (conocida por todos) como secreto simétrico HMAC. Se previene especificando de forma explícita y cerrada el algoritmo permitido en el servidor, por ejemplo `algorithms=["RS256"]`.

**4. ¿Por qué reemplazar identificadores numéricos secuenciales (`/factura/104`) por identificadores UUIDv4 (`/factura/a3f1...`) no corrige por sí solo una vulnerabilidad IDOR/BOLA?** Porque un UUID solo hace que el identificador sea difícil de adivinar por fuerza bruta, pero no verifica permisos. Si un UUID queda registrado en la cabecera `Referer`, en logs compartidos o en otra respuesta de la API, cualquier usuario autenticado podría acceder al recurso ajeno si el servidor no comprueba explícitamente la propiedad (`WHERE id = ? AND owner_id = ?`).

**5. ¿Qué función cumplen el parámetro `state` y la extensión `PKCE` en un flujo OAuth 2.0?** El parámetro `state` vincula la petición de autorización inicial con la sesión del navegador del usuario, previniendo ataques de CSRF sobre el inicio de sesión. `PKCE` (*Proof Key for Code Exchange*) vincula criptográficamente el código de autorización (`code`) con el cliente que inició el flujo mediante un `code_verifier`, impidiendo que un código interceptado en la redirección pueda ser canjeado por otro actor.

## Antes de avanzar

Verificá que podés:
- Explicar la diferencia entre autenticación y autorización horizontal (IDOR/BOLA) y vertical (BFLA).
- Auditar un JWT verificando algoritmo, longitud de clave y claims obligatorios (`exp`, `iss`, `aud`, `sub`).
- Implementar consultas de acceso a datos que filtren siempre por la identidad del propietario autenticado.

::: nota Puerta de salida
Con la autenticación y el control de acceso claros, el siguiente paso es dominar las vulnerabilidades de procesamiento de archivos, peticiones salientes del servidor y motores de plantillas: avanzá al **Capítulo 2.6 · LFI/Path Traversal, File Upload, SSRF, XXE, SSTI y deserialización**.
:::

## Referencias y estándares abiertos

- **RFC 7519 (JSON Web Token) y RFC 8725 (JSON Web Token Best Current Practices):** especificación y reglas de validación criptográfica segura para JWT.
- **RFC 6749 (OAuth 2.0), RFC 7636 (PKCE) y RFC 9700 (OAuth 2.0 Security Best Current Practice):** estándares oficiales de delegación y autenticación federada.
- **OWASP Top 10:2025 (`A01:2025 – Broken Access Control` & `A07:2025 – Authentication Failures`) y OWASP ASVS 5.0 (V6 Authentication, V7 Session Management, V8 Authorization, V9 Self-Contained Tokens, V10 OAuth/OIDC).**
- **OWASP API Security Top 10 (2023) — API1:2023 Broken Object Level Authorization (BOLA) & API5:2023 Broken Function Level Authorization (BFLA).**
