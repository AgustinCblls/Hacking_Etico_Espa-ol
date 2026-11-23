::: nota Objetivo de la lección
Al finalizar este capítulo vas a dominar los pilares prácticos de la criptografía moderna aplicada a la seguridad de sistemas y redes: distinguir funciones hash criptográficas (SHA-256), códigos de autenticación de mensajes (HMAC), cifrado simétrico autenticado (AEAD / AES-GCM frente a modos heredados vulnerables como ECB o CBC sin integridad), criptografía asimétrica (RSA, ECDSA y ECDHE), certificados X.509, cadenas de confianza PKI y auditoría de protocolos TLS 1.2/1.3 con `openssl` y Python 3 en laboratorio local.
:::

**Prerrequisitos:** Capítulo 1.6 (Python 3), Capítulo 1.7 (Protocolos de red) y Capítulo 1.8 (HTTP y TLS introductorio). **Duración sugerida:** 6 a 8 horas.

## 1. Tres garantías distintas: Confidencialidad, Integridad y Autenticidad

Uno de los errores de arquitectura más frecuentes al diseñar software seguro consiste en confundir **para qué sirve cada primitiva criptográfica**: aplicar un hash para proteger un secreto, cifrar sin autenticar la integridad del texto cifrado o inventar algoritmos propios en lugar de usar estándares auditados.

| Primitiva criptográfica | Qué garantiza | Qué **NO** garantiza por sí sola | Estándares modernos vigentes |
|---|---|---|---|
| **Codificación** (`Base64`, `Hex`, `URL-encoding`) | Representación portable de bytes en texto ASCII. | **Nada de seguridad:** es 100 % reversible sin clave. | RFC 4648 (no es criptografía). |
| **Hash criptográfico** (`SHA-256`, `SHA-3`) | **Integridad** de datos y detección de alteraciones (cualquier cambio de 1 bit cambia todo el resumen). | Confidencialidad ni almacenamiento seguro de contraseñas sin salt/costo (para claves usar KDF como `Argon2id`). | FIPS 180-4 (`SHA-256`/`512`), FIPS 202 (`SHA-3`). |
| **MAC / HMAC** (`HMAC-SHA256`) | **Integridad + Autenticidad** mediante clave secreta compartida. | Confidencialidad (el mensaje sigue en claro si no se cifra). | RFC 2104 (`HMAC`). |
| **Cifrado Simétrico AEAD** (`AES-GCM`, `ChaCha20-Poly1305`) | **Confidencialidad + Integridad + Autenticidad** simultáneamente usando la misma clave secreta. | No repudio frente a terceros (ambas partes comparten la misma clave). | NIST SP 800-38D (`GCM`), RFC 8439 (`ChaCha20-Poly1305`). |
| **Cifrado y Firma Asimétrica** (`RSA`, `ECDSA`, `Ed25519`, `ECDH`) | Intercambio de claves sin secreto previo, identidad digital y **no repudio** con par clave pública / privada. | Velocidad en grandes volúmenes de datos (por eso se usa solo en el *handshake* inicial). | RFC 8032 (`Ed25519`), FIPS 186-5. |

::: peligro La primera regla de la criptografía aplicada
Nunca implementes primitivas matemáticas criptográficas propias ni combines modos antiguos sin autenticación. Usá bibliotecas estándar mantenidas (`cryptography`, `openssl`, `libsodium`) y seleccioná siempre **cifrado autenticado (AEAD)** como `AES-256-GCM` o `ChaCha20-Poly1305`.
:::

## 2. Cifrado simétrico y errores clásicos de implementación

En el cifrado simétrico, emisor y receptor comparten una misma clave secreta (`K` de 128 o 256 bits en AES). Sin embargo, un cifrador de bloques como AES solo cifra bloques fijos de **16 bytes (128 bits)**. La forma en que se encadenan múltiples bloques se denomina **Modo de Operación**, y elegir un modo incorrecto destruye por completo la seguridad del cifrado:

### Comparativa de modos de operación simétricos

| Modo de operación | Comportamiento técnico | Riesgo o vulnerabilidad conocida | Recomendación actual |
|---|---|---|---|
| **ECB (*Electronic Codebook*)** | Cada bloque de 16 bytes idéntico produce exactamente el mismo bloque cifrado. | Filtra patrones visuales y estructurales del mensaje original sin conocer la clave. | **Prohibido siempre.** |
| **CBC (*Cipher Block Chaining*) sin MAC** | Usa un Vector de Inicialización (`IV`) aleatorio y encadena bloques con XOR. | Sin autenticación (HMAC), permite modificar bits arbitrarios del mensaje o explotar errores de relleno (**Padding Oracle**). | Evitar en código nuevo; nunca usar sin `Encrypt-then-MAC`. |
| **AES-GCM / ChaCha20-Poly1305 (AEAD)** | Cifra en modo flujo autenticado y genera una etiqueta criptográfica (**Tag de autenticación**) de 128 bits. | Si el receptor verifica el Tag antes de descifrar, rechaza cualquier manipulación. **Cuidado crítico:** nunca reutilizar la misma pareja `(Clave, Nonce)` dos veces. | **Estándar obligatorio** en protocolos y aplicaciones nuevas. |

## 3. Criptografía asimétrica, firmas digitales e intercambio de claves

Mientras la criptografía simétrica usa una sola clave compartida, la criptografía asimétrica utiliza un par matemáticamente ligado: una **clave privada** (que el propietario jamás revela) y una **clave pública** (que se distribuye libremente). Cumple dos funciones centrales en las redes modernas:

1. **Firmas digitales (Autenticidad e Integridad pública — `Ed25519`, `ECDSA`, `RSA-PSS`):**
   El emisor calcula el hash del documento o certificado y lo firma usando su **clave privada**. Cualquier receptor verifica esa firma usando la **clave pública** del emisor. Si un solo bit del documento cambió o si la clave privada no corresponde, la verificación falla al instante.
2. **Acuerdo de claves efímero (`ECDHE` — *Elliptic Curve Diffie-Hellman Ephemeral*):**
   Permite que un cliente y un servidor establezcan una clave simétrica secreta de sesión a través de una red pública insegura sin haber compartido nada previamente. Al generar parámetros efímeros nuevos en cada conexión, proporciona **Secreto Perfecto hacia Adelante (*Forward Secrecy*, PFS)**: incluso si años más tarde alguien comprometiera la clave privada del certificado del servidor, no podría descifrar capturas PCAP grabadas en el pasado.

## 4. Infraestructura de Clave Pública (PKI) y certificados X.509

Conocer la clave pública de un servidor plantea un problema de confianza: ¿cómo sabés que la clave pública que recibís al conectarte por HTTPS pertenece realmente a `portal.empresa.local` y no a un intermediario en la red?

La respuesta es la **PKI (*Public Key Infrastructure*)** y los **certificados digitales X.509 v3 (RFC 5280)**: documentos electrónicos firmados digitalmente por una **Autoridad de Certificación (CA)** de confianza que vinculan una identidad (nombre DNS o usuario) con una clave pública.

```text
[Root CA (Raíz, autofirmada, offline en el almacén de confianza del SO/navegador)]
        │  firma el certificado de:
        ▼
[Intermediate CA (CA Intermedia operativa)]
        │  firma el certificado hoja de:
        ▼
[Certificado del Servidor (Leaf): SAN = portal.empresa.local, Valid From/To, Key Usage]
```

### Campos críticos que debés revisar al auditar un certificado X.509

| Campo X.509 | Qué verifica el cliente / auditor | Consecuencia si está mal configurado |
|---|---|---|
| **Subject Alternative Name (`SAN`)** | Lista oficial de nombres DNS (`DNS:portal.empresa.local`) o IPs válidas (hoy tiene prioridad sobre `CN`). | El navegador rechaza la conexión con error de coincidencia de nombre aunque la cadena sea válida. |
| **Validity (`NotBefore` / `NotAfter`)** | Ventana temporal de validez: en web pública, **máximo 200 días desde el 15/03/2026** conforme a la hoja de ruta CA/B Forum **SC-081v3** (bajando a **100 días en 2027** y **47 días en 2029**). | Certificados vencidos o fuera de plazo generan rechazo del cliente/navegador y tentación de forzar automatizaciones inseguras. |
| **Key Usage & Extended Key Usage (`EKU`)** | Define usos permitidos (`Server Authentication 1.3.6.1.5.5.7.3.1`, `Client Authentication`, `Code Signing`). | Un certificado de usuario no debe poder actuar como CA intermedia (`Basic Constraints: CA:FALSE`). |
| **Estado de revocación (`CRL` / `OCSP`)** | Lista de certificados revocados antes de expirar por compromiso de clave o baja de servicio. | Un certificado cuya clave privada se filtró sigue siendo aceptado hasta su fecha de vencimiento. |

::: nota Retirada de OCSP en CAs públicas (Let's Encrypt 2025)
Durante **2025**, **Let's Encrypt** completó su transición de **OCSP** hacia listas **CRL** (suspendió URLs de OCSP y *OCSP Must-Staple* en mayo y apagó definitivamente sus *responders* OCSP el **6 de agosto de 2025**) para eliminar la fuga de privacidad sobre los sitios consultados por cada navegador y reducir infraestructura masiva. En servidores web actuales, evitá forzar *OCSP Stapling* obligatorio si tu CA ya no incluye URL de OCSP y verificá revocación mediante CRL/CRLite en clientes.
:::

## 5. Auditoría práctica de TLS y errores frecuentes en servicios internos

A lo largo de la última década, numerosas vulnerabilidades públicas en TLS obligaron a retirar versiones y algoritmos heredados. Al auditar cualquier servicio HTTPS, LDAPS o SMTP con TLS, el estándar mínimo aceptable (Mozilla SSL Configuration Guidelines / NIST SP 800-52 Rev. 2) exige:
- **Protocolos permitidos:** únicamente **TLS 1.2** (con suites AEAD + ECDHE) y **TLS 1.3**. Deben estar deshabilitados por completo **SSLv2, SSLv3, TLS 1.0 y TLS 1.1**.
- **Suites de cifrado:** solo suites con **Forward Secrecy (`ECDHE`)** y **cifrado autenticado (`AES_128_GCM`, `AES_256_GCM`, `CHACHA20_POLY1305`)**. Prohibir `RC4`, `3DES`, `CBC` heredado cuando haya alternativa GCM, `NULL` y algoritmos `EXPORT`.
- **Verificación de certificados en clientes propios (Python/Go/curl):** nunca dejar `verify=False` en `requests.get()` ni `-k` / `--insecure` en scripts de producción; en laboratorios internos con CA privada, exportá el certificado raíz de tu CA e indicalo explícitamente con `verify="/ruta/ca_lab.pem"`.

### Ataques históricos y debilidades clásicas en TLS que explican la configuración moderna

| Debilidad / Ataque TLS | Qué componente fallaba | Por qué desaparece con TLS 1.2+ moderno y TLS 1.3 |
|---|---|---|
| **POODLE y *Padding Oracles*** | Modo CBC sin autenticación verificada + SSLv3 / mensajes de error distintos al validar padding. | Desactivar SSLv3 y usar cifrado autenticado AEAD (**`AES-GCM`** / **`ChaCha20-Poly1305`**). |
| **BEAST y *RC4 Biases*** | Vector de inicialización (IV) predecible en TLS 1.0 CBC o sesgos estadísticos en el cifrador de flujo `RC4`. | Retirar TLS 1.0/1.1 y prohibir `RC4` en todas las suites del servidor. |
| **CRIME y BREACH** | Compresión TLS o compresión HTTP (`gzip`) combinada con secretos reflejados (cookies/tokens CSRF), filtrando bytes por longitud cifrada. | Compresión TLS eliminada en TLS 1.3 y separación/máscaras en tokens secretos reflejados. |
| **Bleichenbacher y DROWN** | Uso de relleno RSA PKCS#1 v1.5 en el intercambio de claves RSA o soporte simultáneo heredado de **SSLv2**. | Deshabilitar SSLv2 completamente y exigir **ECDHE** con Forward Secrecy en lugar de intercambio estático RSA. |
| **Generadores débiles de números aleatorios (PRNG)** | Uso de `random` estándar en lugar de fuentes criptográficas (`CSPRNG`) para claves, tokens o nonces. | Usar siempre `secrets` en Python, `CryptGenRandom`/`BCryptGenRandom` en Windows o `/dev/urandom` / `getrandom()` en Linux. |

### Criptografía Post-Cuántica (PQC) y *Crypto-Agility* (panorama 2026)

::: nota Bloque actualizado 2026: Transición Post-Cuántica y Agilidad Criptográfica
Aunque las computadoras cuánticas capaces de ejecutar el algoritmo de Shor contra `RSA` y curvas elípticas (`ECDHE`/`ECDSA`) todavía están en desarrollo, la amenaza **HNDL (*Harvest Now, Decrypt Later*)** ya es operativa hoy: un adversario puede capturar y archivar tráfico TLS o backups cifrados actualmente para descifrarlos dentro de unos años cuando disponga de capacidad cuántica. Por eso el foco actual está puesto en el **intercambio de claves** y en la **agilidad criptográfica**.

1. **Estándares NIST vigentes:** tras estandarizar en 2024 sus algoritmos post-cuánticos basados en retículos y hashes, el ecosistema de producción adopta:
   - **ML-KEM (FIPS 203, derivado de *CRYSTALS-Kyber*):** mecanismo de encapsulamiento de claves (*Key Encapsulation Mechanism*) para establecer secretos de sesión resistentes a computación cuántica.
   - **ML-DSA (FIPS 204, derivado de *CRYSTALS-Dilithium*):** estándar principal para firmas digitales post-cuánticas (complementado por `SLH-DSA` / FIPS 205 basado en hashes).
2. **Intercambio de claves híbrido en TLS 1.3 (`X25519MLKEM768`):** en 2026 los navegadores principales, CDNs y pilas TLS modernas (como OpenSSL 3.5+) negocian grupos híbridos como **`X25519MLKEM768`**. En lugar de confiar en un solo esquema, el cliente y el servidor combinan el secreto de curva elíptica clásica (`X25519`) con el de `ML-KEM-768`: si cualquiera de los dos algoritmos resiste, la clave de sesión permanece protegida frente a ataques clásicos y futuros ataques cuánticos (mitigando HNDL sin perder compatibilidad).
3. **Por qué las organizaciones necesitan *Crypto-Agility*:** los estándares, tamaños de clave y bibliotecas cambian con el tiempo. La **agilidad criptográfica** es la capacidad de inventariar qué algoritmos usa cada sistema (inventario CBOM — *Cryptographic Bill of Materials*) y rotar primitivas, certificados o grupos TLS mediante configuración centralizada sin reescribir código fuente ni romper clientes.
   - **Enfoque Purple Team (detección y operación):** al auditar servicios TLS 1.3 podés verificar si negocian grupos híbridos revisando la línea `Server Temp Key` en `openssl s_client -connect 127.0.0.1:8443 -tls1_3`. En red, tené en cuenta que las claves públicas `ML-KEM` aumentan el tamaño del mensaje *ClientHello* por encima de los ~1.500 bytes de un paquete Ethernet estándar (fragmentación TCP), por lo que conviene probar firewalls, balanceadores e IDS/IPS heredados en laboratorio antes de habilitar PQC híbrido en producción.
:::

## 6. Ejemplo paso a paso: inspección de certificados y HMAC/SHA-256 en laboratorio

Podemos generar un par clave/certificado de prueba autofirmado únicamente dentro de `/tmp` (o tu carpeta temporal de VM), inspeccionar todos sus campos X.509 con `openssl` y verificar la integridad de un archivo de evidencia con Python:

```bash
# Paso 1: Generar un certificado X.509 de laboratorio válido por 30 días con SAN explícito
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 \
  -keyout /tmp/lab_clave.pem -out /tmp/lab_cert.pem \
  -subj "/CN=lab-local.invalid/O=Laboratorio Local" \
  -addext "subjectAltName=DNS:lab-local.invalid,IP:127.0.0.1"

# Paso 2: Inspeccionar la huella digital SHA-256, algoritmo de firma, validez y extensiones SAN/EKU
openssl x509 -in /tmp/lab_cert.pem -noout -text -fingerprint -sha256 | head -n 32
```

Fragmento de salida comentada:

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = lab-local.invalid, O = Laboratorio Local
        Validity
            Not Before: Nov 22 18:00:00 2026 GMT
            Not After : Dec 22 18:00:00 2026 GMT
        Subject: CN = lab-local.invalid, O = Laboratorio Local
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:lab-local.invalid, IP Address:127.0.0.1
SHA256 Fingerprint=4A:7C:19:E0:...
```

Y para auditar un puerto TLS local existente (por ejemplo, una instancia Nginx con TLS en tu VM de laboratorio):

```bash
# Probar handshake TLS 1.3 específico e inspeccionar la cadena completa de certificados
openssl s_client -connect 127.0.0.1:8443 -tls1_3 -showcerts </dev/null

# Intentar forzar TLS 1.0 (el servidor endurecido DEBE rechazar la conexión)
openssl s_client -connect 127.0.0.1:8443 -tls1 </dev/null
```

::: defensa Perspectiva defensiva y mitigación
1. **Automatización de certificados y vida útil corta:** en servicios internos y externos, automatizá la emisión y renovación mediante protocolos ACME internos (como `step-ca` o Certbot) y centralizá los almacenes de CA raíz mediante GPO/MDM.
2. **Inventariar criptografía débil de forma continua:** combiná `testssl.sh` o scripts NSE (`nmap --script ssl-enum-ciphers -p 443 <host_lab>`) en tus auditorías periódicas para detectar servicios olvidados que todavía acepten TLS 1.0/1.1 o suites RC4/3DES.
3. **Almacenamiento seguro de claves:** las claves privadas TLS y secretos HMAC jamás se guardan dentro del repositorio Git ni en texto claro con permisos abiertos (`0644`); protegé siempre las claves con permisos `0600` del usuario del servicio o mediante HSM/bóveda de secretos.
:::

## Práctica en laboratorio local

1. Ejecutá los comandos de la sección 6 en tu VM para generar `/tmp/lab_cert.pem` y `/tmp/lab_clave.pem` e inspeccioná la salida completa de `openssl x509 -in /tmp/lab_cert.pem -noout -text`.
2. Escribí un script corto en Python 3 (`demo_hmac_entropia.py`) que:
   - Genere una clave aleatoria de 32 bytes con `secrets.token_bytes(32)`.
   - Calcule un `hmac.new(clave, b"Registro auditado Lab", hashlib.sha256).hexdigest()` y verifique con `hmac.compare_digest()` en tiempo constante que cualquier alteración de 1 bit invalida la firma HMAC.
   - Levante un servidor HTTPS mínimo de prueba en `127.0.0.1:8443` usando `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)` con `minimum_version = ssl.TLSVersion.TLSv1_2` cargando tu certificado temporal de laboratorio y compruebe con `openssl s_client` que TLS 1.0 es rechazado.

::: practica Entregable mínimo
Salida de `openssl x509` comentada señalando emisor, algoritmo de firma, fechas y `SAN`, junto con tu script `demo_hmac_entropia.py` validando verificación HMAC en tiempo constante y rechazo de TLS heredado.
:::

## Preguntas de repaso

**1. ¿Por qué calcular únicamente un hash `SHA-256(mensaje)` no garantiza autenticidad si un intermediario puede interceptar tanto el mensaje como el hash?** Porque `SHA-256` es una función pública sin clave secreta: un intermediario puede modificar el mensaje y recalcular un nuevo hash `SHA-256` válido para el mensaje alterado. Para garantizar autenticidad e integridad hace falta un código con clave secreta (`HMAC-SHA256`) o una firma asimétrica (`Ed25519` / `ECDSA`).

**2. ¿Cuál es el riesgo técnico fundamental del modo simétrico ECB frente a AES-GCM?** En ECB cada bloque idéntico de 16 bytes de texto en claro se cifra exactamente en el mismo bloque de salida, preservando patrones estructurales de los datos; además no incluye detección de manipulación. `AES-GCM`, en cambio, cifra como flujo autenticado usando un *nonce* único y genera un tag de autenticación que detecta cualquier modificación.

**3. ¿Qué ventaja de seguridad aporta usar `ECDHE` (intercambio efímero) en TLS frente al antiguo intercambio de claves estático con RSA?** Proporciona *Forward Secrecy* (Secreto Perfecto hacia Adelante): como los parámetros de sesión son efímeros y se destruyen al terminar la conexión, la eventual filtración futura de la clave privada del certificado del servidor no permite descifrar grabaciones pasadas de tráfico cifrado.

**4. Al validar un certificado X.509 de un servidor HTTPS, ¿por qué se debe desactivar `verify=False` incluso en pruebas con una CA interna?** Porque desactivar la verificación de certificados anula por completo la autenticación del servidor frente a ataques de intermediario (*Man-in-the-Middle*). En entornos internos o de laboratorio con certificados propios se debe especificar la ruta del certificado raíz confiable (`verify="/ruta/ca_lab.pem"`).

**5. ¿Por qué `hmac.compare_digest(a, b)` es obligatorio al comparar firmas HMAC o tokens en Python en lugar del operador estándar `==`?** Porque el operador `==` compara byte a byte y se detiene en el primer byte diferente, introduciendo una pequeña diferencia de tiempo medible (*timing side-channel*). `hmac.compare_digest()` tarda exactamente el mismo tiempo sin importar en qué byte difieren ambas cadenas.

## Antes de avanzar

Verificá que podés:
- Elegir la primitiva criptográfica adecuada (Hash vs HMAC vs AEAD vs Firma Asimétrica vs KDF).
- Explicar por qué evitar ECB, claves/nonces reutilizados, protocolos TLS < 1.2 y comparaciones de firmas no constantes.
- Inspeccionar certificados X.509, extensiones SAN/EKU y suites TLS con `openssl`.

::: nota Puerta de salida
¡Excelente! Con el dominio de la criptografía práctica, PKI y TLS cerrás el **Tomo I (Ruta 1 · Principiante)**. Ya tenés toda la base de sistemas, redes, programación y protocolos para pasar a la auditoría activa y seguridad web en el **Tomo II · Capítulo 2.1 (Reconocimiento, footprinting y Nmap)**.
:::

## Referencias y estándares abiertos

- **RFC 8446 (TLS 1.3) y RFC 5280 (Internet X.509 Public Key Infrastructure Certificate and CRL Profile).**
- **NIST SP 800-52 Rev. 2 (*Guidelines for the Selection, Configuration, and Use of Transport Layer Security Implementations*) & NIST SP 800-38D (AES-GCM).**
- **Mozilla Server Side TLS Guidelines:** perfiles oficiales (*Modern* e *Intermediate*) de versiones y suites recomendadas.
- **Documentación oficial de OpenSSL (`man openssl-x509`, `openssl-s_client`) y Python `cryptography` / `hmac` / `ssl`.**
