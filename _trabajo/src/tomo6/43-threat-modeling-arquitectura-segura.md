::: nota Objetivo de la lección
Aplicar el modelado de amenazas (*Threat Modeling*) de forma sistemática antes de escribir código o desplegar infraestructura. Vas a dominar las cuatro preguntas fundamentales, la construcción de Diagramas de Flujo de Datos (DFD) con fronteras de confianza, las metodologías STRIDE y PASTA, el diseño de Árboles de Ataque (`AND`/`OR`) y el mapeo directo de contramedidas hacia requisitos verificables del estándar OWASP ASVS sobre una API de pagos y autenticación.
:::

Corregir una falla de diseño arquitectónico cuando la aplicación ya está en producción cuesta entre diez y cien veces más que detectarla sobre una pizarra antes de escribir la primera línea de código. Mientras que las pruebas dinámicas (*pentesting*) y la revisión de código detectan errores de implementación, el **Threat Modeling** descubre fallas de diseño estructural: suposiciones falsas de confianza, ausencia de verificación entre microservicios, falta de no-repudio o canales sin cifrar.

---

## 1. Threat Modeling sistemático: las 4 preguntas clave

El *Threat Modeling Manifesto* y el marco de referencia popularizado por Adam Shostack estructuran cualquier sesión de modelado de amenazas alrededor de cuatro preguntas iterativas que todo equipo de ingeniería y seguridad debe responder de manera continua:

| Pregunta | Objetivo operativo | Artefactos resultantes |
| :--- | :--- | :--- |
| **1. ¿Qué estamos construyendo?** | Comprender alcance, activos críticos, arquitectura, actores y flujos de datos. | Diagrama de Flujo de Datos (DFD), inventario de activos y *Trust Boundaries*. |
| **2. ¿Qué puede salir mal?** | Enumerar sistemáticamente amenazas realistas sobre cada componente y frontera. | Matriz STRIDE, análisis PASTA, Árboles de Ataque (`AND`/`OR`). |
| **3. ¿Qué haremos al respecto?** | Decidir para cada amenaza: mitigar, eliminar, transferir o aceptar formalmente. | Requisitos de seguridad en backlog mapeados a **OWASP ASVS**. |
| **4. ¿Hicimos un buen trabajo?** | Validar si el modelo refleja el sistema real y si las mitigaciones fueron efectivas. | Pruebas de integración, revisión de pares y verificación post-despliegue. |

::: nota Momento ideal de ejecución
El modelado no debe ser un evento burocrático único al final del proyecto. Aplicá una sesión corta (45 a 60 minutos) en cada nuevo RFC, historia de usuario con impacto en autenticación/pagos o cambio en fronteras de red.
:::

---

## 2. Diagramas de Flujo de Datos (DFD) y Fronteras de Confianza

Un diagrama de arquitectura de red tradicional muestra servidores, subredes y balanceadores, pero rara vez deja claro **cómo viajan los datos** ni **quién confía en quién**. Para modelar amenazas se utilizan **Diagramas de Flujo de Datos (DFD)** compuestos por cinco elementos estándar:

1. **Entidades Externas** (*External Entities*): actores o sistemas fuera de nuestro control directo (usuarios finales, navegadores, apps móviles, pasarelas de pago externas, IdPs).
2. **Procesos** (*Processes*): unidades de cómputo que reciben, transforman o enrutan datos (API Gateway, servicio de login, worker de facturación).
3. **Almacenes de Datos** (*Data Stores*): repositorios persistentes o temporales (bases PostgreSQL, clúster Redis, buckets S3, archivos de logs).
4. **Flujos de Datos** (*Data Flows*): flechas unidireccionales o bidireccionales que indican el protocolo y el tipo de carga útil que circula entre elementos.
5. **Fronteras de Confianza** (*Trust Boundaries*): líneas punteadas o recuadros que delimitan zonas donde cambia el nivel de privilegio, autenticación o control administrativo. **Toda flecha que cruza una frontera de confianza exige validación, autenticación y autorización.**

### Ejemplo DFD: Plataforma de Login y API de Pagos

Consideremos el diseño previo al desarrollo de un módulo de autenticación y procesamiento de pagos con tarjeta tokenizada:

```text
+-----------------------------------------------------------------------+
| ZONA NO CONFIABLE (Internet / Cliente)                                |
|                                                                       |
|  [Usuario / Navegador SPA]                                            |
+-----------------------------------+-----------------------------------+
                                    | (1) HTTPS / JSON (Credenciales, Token pago)
============ FRONTERA DE CONFIANZA 1: Edge / TLS / Autenticación =======|
                                    v
+-----------------------------------------------------------------------+
| ZONA DMZ / BORDE DE APLICACIÓN                                        |
|                                                                       |
|  (( P1: API Gateway / WAF ))                                          |
+-----------------+---------------------------------+-------------------+
                  | (2) gRPC interno (mTLS)         | (3) HTTP interno
                  v                                 v
====== FRONTERA DE CONFIANZA 2: Segmento de Microservicios =============|
                  |                                 |
    +-------------+-------------+     +-------------+-------------+
    | (( P2: Servicio Auth ))   |     | (( P3: Servicio Pagos ))  |
    +------+-------------+------+     +------+-------------+------+
           |             |                   |             |
    (4) SQL/TLS    (5) RESP/TLS       (6) SQL/TLS    (7) HTTPS + HMAC
           v             v                   v             |
    [ D1: DB Users ] [ D2: Redis ]    [ D3: DB Órdenes ]   |
                                                           v
====== FRONTERA DE CONFIANZA 3: Proveedor Externo =========|============|
                                                           v
                                              [ E2: Pasarela Externa ]
```

Fijate cómo las tres **Fronteras de Confianza** revelan de inmediato puntos de inspección obligatorios:
- **Frontera 1** (Internet hacia API Gateway): cualquier dato entrante es potencialmente malicioso; aquí aplican TLS estricto, limitación de tasa, validación de esquema y autenticación de sesión.
- **Frontera 2** (API Gateway hacia microservicios internos): aunque estén en la misma VPC, si un servicio periférico resulta comprometido no debe poder suplantar identidades hacia `P3: Servicio Pagos`. Por eso se exige `mTLS` y verificación de tokens internos firmados.
- **Frontera 3** (`P3` hacia `E2: Pasarela Externa` y webhooks de retorno): la pasarela externa es otra entidad fuera de nuestro control; las respuestas y webhooks de retorno que cruzan de vuelta esa frontera deben validarse criptográficamente con firma HMAC.

---

## 3. Metodología STRIDE aplicada por elemento

Creada originalmente en Microsoft, **STRIDE** es una mnemotecnia de seis categorías de amenazas que se contraponen directamente a seis propiedades fundamentales de seguridad:

| Letra | Amenaza | Definición técnica | Propiedad violada |
| :--- | :--- | :--- | :--- |
| **S** | *Spoofing* (Suplantación) | Hacerse pasar por otro usuario, servicio o componente legítimo. | **Autenticación** |
| **T** | *Tampering* (Manipulación) | Alterar datos en tránsito, en memoria o almacenados sin autorización. | **Integridad** |
| **R** | *Repudiation* (Repudio) | Negar haber ejecutado una acción por falta de evidencia auditable íntegra. | **No Repudio** |
| **I** | *Information Disclosure* | Exponer información sensible a actores no autorizados (datos, errores, secretos). | **Confidencialidad** |
| **D** | *Denial of Service* | Agotar recursos o bloquear la operación normal del sistema. | **Disponibilidad** |
| **E** | *Elevation of Privilege* | Obtener capacidades o permisos por encima del rol asignado. | **Autorización** |

### STRIDE por elemento (*STRIDE-per-element*)

En lugar de aplicar las seis letras al azar a todo el sistema, la variante profesional **STRIDE-per-element** asocia a cada tipo de elemento del DFD exactamente las amenazas que tienen sentido físico sobre él:

| Elemento del DFD | S | T | R | I | D | E | Foco principal de análisis |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Entidad Externa** | X | | X | | | | ¿Cómo sabemos que el cliente o pasarela externa es quien dice ser? ¿Puede negar una transacción? |
| **Proceso** | X | X | X | X | X | X | Es el único elemento sujeto a las 6 categorías: valida entradas, ejecuta lógica, escribe logs y controla roles. |
| **Almacén de Datos** | | X | X* | X | X | | ¿Quién puede modificar registros (`T`), leer datos en reposo/backups (`I`) o llenar el disco (`D`)? (*`R` aplica si guarda logs de auditoría). |
| **Flujo de Datos** | | X | | X | X | | ¿El canal puede ser interceptado (`I`), alterado en tránsito (`T`) o saturado (`D`)? |

Aplicando **STRIDE-per-element** sobre nuestro DFD de pagos y login obtenemos hallazgos accionables concretos:
- **Flujo (1) Cliente -> P1**: *Tampering* / *Information Disclosure* en tránsito (mitigado con TLS 1.3 y HSTS) y *Denial of Service* por peticiones masivas al login (mitigado con rate limiting y WAF).
- **Proceso P2 (Servicio Auth)**: *Spoofing* mediante robo de credenciales o tokens JWT débiles; *Elevation of Privilege* si un usuario modifica su campo `role` en el perfil; *Repudiation* si los inicios de sesión y cambios de contraseña no registran timestamp, IP, user-agent y resultado en log inmutable.
- **Almacén D3 (DB Órdenes)**: *Information Disclosure* por backups sin cifrar o consultas SQL sin parametrizar; *Tampering* si no hay integridad referencial ni control de acceso mínimo por servicio (`least privilege`).
- **Entidad E2 (Pasarela Externa -> Webhook hacia P3)**: *Spoofing* si cualquiera puede invocar el endpoint de webhook fingiendo una confirmación de pago sin verificar la firma HMAC de la pasarela.

---

## 4. PASTA: 7 etapas orientadas al riesgo del negocio

Mientras STRIDE es ideal para equipos de ingeniería centrados en el diseño de software, **PASTA** (*Process for Attack Simulation and Threat Analysis*) adopta una perspectiva **centrada en el riesgo del negocio y el perfil real del atacante**. Se ejecuta en siete etapas progresivas:

1. **Definir los objetivos del negocio y requisitos de seguridad**: identificar qué activos protegen los ingresos, la continuidad operativa y el cumplimiento regulatorio (por ejemplo, PCI-DSS en pagos o GDPR/Ley de Protección de Datos).
2. **Definir el alcance técnico**: enumerar infraestructura, APIs, librerías, dependencias, contenedores y servicios en la nube incluidos en el límite del análisis.
3. **Descomposición de la aplicación**: construir DFDs, mapear casos de uso, roles, *trust boundaries* y puntos de entrada de datos.
4. **Análisis de amenazas**: correlacionar inteligencia de amenazas reales (tácticas de atacantes relevantes para el sector fintech/SaaS) sobre el sistema descompuesto.
5. **Análisis de vulnerabilidades y debilidades**: cruzar los componentes con debilidades conocidas (CWE, fallas de diseño previas, hallazgos SAST/DAST o reportes pasados).
6. **Modelado de ataques**: construir **Árboles de Ataque** y secuencias encadenadas que muestren cómo un adversario real combinaría fallas menores para lograr el objetivo de negocio adverso.
7. **Análisis de riesgo e impacto**: calcular impacto financiero/reputacional frente a costo de remediación y priorizar las contramedidas con mayor reducción de riesgo.

::: aviso ¿Cuándo usar STRIDE y cuándo PASTA?
Usá **STRIDE** en el día a día de desarrollo (sprints, diseño de nuevas funcionalidades y microservicios) por su rapidez y exhaustividad técnica. Reservá **PASTA** para plataformas críticas de alto impacto financiero o regulatorio donde la gerencia de riesgo necesita priorizar inversiones en base a escenarios adversos concretos.
:::

### Aplicación concreta de PASTA sobre la API de Pagos

Para visualizar cómo PASTA conecta la estrategia del negocio con el detalle técnico, observá los entregables de las siete etapas aplicadas a nuestra plataforma de checkout y pagos:

| Etapa PASTA | Entregable concreto en la API de Pagos |
| :--- | :--- |
| **1. Objetivos de negocio** | Garantizar cero cobros fraudulentos o acreditaciones sin pago real; cumplir PCI-DSS SAQ A evitando tocar PAN en backend. |
| **2. Alcance técnico** | API Gateway (Nginx/Envoy), Servicio Auth (Python), Servicio Pagos (Go), PostgreSQL 16, Redis 7 y pasarela externa vía HTTPS. |
| **3. Descomposición** | El DFD anterior con 3 *Trust Boundaries*, roles (`customer`, `support`, `admin`) y casos de uso críticos (login, pago, webhook). |
| **4. Análisis de amenazas** | Tácticas relevantes para fintech: relleno de credenciales, manipulación de webhooks, condiciones de carrera en cupones y robo de JWT. |
| **5. Debilidades** | Revisión de CWE aplicables (`CWE-362` concurrencia, `CWE-345` firma HMAC ausente, `CWE-639` IDOR en órdenes). |
| **6. Modelado de ataques** | Construcción de Árboles de Ataque (`AND`/`OR`) para demostrar el camino mínimo hacia el objetivo adverso *"Acreditar orden sin pagar"*. |
| **7. Riesgo e impacto** | Priorización cuantitativa: exigir firma HMAC + `FOR UPDATE` + tokenización antes de salir a producción (riesgo crítico residual reducido a bajo). |

---

## 5. Árboles de Ataque (*Attack Trees*) con nodos `AND`/`OR`

Los **Árboles de Ataque**, formalizados por Bruce Schneier, modelan de manera visual y lógica las rutas que debe recorrer un atacante para alcanzar un objetivo prohibido (el **nodo raíz**). Cada nivel inferior descompone el objetivo en sub-metas conectadas mediante dos operadores booleanos:

- **Nodos `OR` (disyunción)**: basta con que se cumpla **cualquiera** de los nodos hijos para satisfacer el nodo padre. Representan caminos alternativos.
- **Nodos `AND` (conjunción)**: deben cumplirse **todos** los nodos hijos simultáneamente para avanzar. Aquí es donde la **defensa en profundidad** tiene mayor impacto, porque bloquear un único hijo `AND` neutraliza toda esa rama.

Ejemplo de Árbol de Ataque para el objetivo raíz: **"Acreditar una orden sin realizar el pago real en la API de Pagos"**:

```text
[RAÍZ] Acreditar orden sin pagar
  |
  +-- (OR) 1. Falsificar confirmación del Webhook de Pasarela
  |     |
  |     +-- (AND) 1a. Endpoint webhook accesible públicamente
  |     +-- (AND) 1b. Ausencia de validación de firma HMAC / secreto filtrado
  |
  +-- (OR) 2. Explotar falla de lógica o concurrencia en Checkout
  |     |
  |     +-- (OR) 2a. Enviar monto total negativo o alterado desde cliente
  |     +-- (OR) 2b. Condición de carrera en aplicación de cupón / saldo
  |
  +-- (OR) 3. Secuestrar sesión de usuario con tarjeta guardada
        |
        +-- (AND) 3a. Obtener cookie/token (XSS o fuga en log)
        +-- (AND) 3b. Compra en 1 clic sin re-autenticación ni CVV/3DS
```

Al anotar cada hoja con atributos como **Costo/Dificultad (Bajo/Medio/Alto)** y **Detectabilidad**, el arquitecto observa de inmediato que las ramas `1a AND 1b` o `2a` son las más baratas para un atacante y requieren contramedidas inmediatas antes del lanzamiento.

---

## 6. Mapeo de mitigaciones a requisitos verificables OWASP ASVS

Un error clásico del modelado de amenazas es terminar con recomendaciones vagas como *"asegurar la API"* o *"agregar monitoreo"*. Todo hallazgo priorizado debe traducirse en un **requisito verificable** que QA o seguridad puedan comprobar objetivamente.

El estándar **OWASP ASVS 5.0 (Application Security Verification Standard, mayo 2025 — 17 capítulos V1–V17)** ofrece el catálogo exacto de controles divididos en niveles (L1 básico, L2 estándar para la mayoría de apps con datos sensibles, L3 crítico como banca/salud).

A continuación tenés el mapeo completo para nuestra **API de Pagos y Login**:

| Componente DFD | Amenaza STRIDE identificada | Mitigación arquitectónica concreta | Requisito OWASP ASVS 5.0 |
| :--- | :--- | :--- | :--- |
| **P2: Servicio Auth** | *Spoofing* por fuerza bruta o credenciales comprometidas | Rate limiting por cuenta/IP, contraseñas con Argon2id y soporte MFA FIDO2/TOTP. | **`V6`** (Authentication: hashing resistente, MFA) y **`V2`** (Anti-automatización). |
| **Flujo (1) -> P1** | *Spoofing* / *Information Disclosure* de tokens de sesión | Emitir tokens opacos o JWT firmados con vida corta; cookies con `HttpOnly`, `Secure`, `SameSite=Lax`. | **`V7`** (Session Management) y **`V9`** (Self-Contained Tokens). |
| **P3: Servicio Pagos** | *Elevation of Privilege* (IDOR sobre órdenes ajenas) | Validar `order.owner_id == auth_context.user_id` en el servicio antes de leer o confirmar orden. | **`V8`** (Authorization: control de acceso a nivel de objeto y rechazo por defecto). |
| **P3: Servicio Pagos** | *Tampering* de precios o cantidades en payload | Ignorar montos enviados por el cliente; recalcular precios desde catálogo DB y usar `Decimal`/centavos. | **`V2`** (Validation and Business Logic) y **`V1`** (Encoding and Sanitization). |
| **P3: Servicio Pagos** | *Tampering* / Race condition en cobros y cupones | Implementar `Idempotency-Key` único y bloqueo pesimista `SELECT ... FOR UPDATE` en base de datos. | **`V2`** (Validation and Business Logic — protección ante abuso concurrente). |
| **P2 & P3 (Logs)** | *Repudiation* en transacciones y cambios de cuenta | Registrar eventos de login, fallos, pagos y cambios de rol en log centralizado inmutable sin guardar secretos/PAN. | **`V16`** (Security Logging and Error Handling). |
| **E2 -> P3 (Webhook)** | *Spoofing* de confirmaciones de la pasarela externa | Verificar firma HMAC-SHA256 sobre payload crudo con `constant_time_compare` y validar timestamp contra replay. | **`V12`** (Secure Communication) y **`V4`** (API and Web Service). |
| **D1 / D3 (Bases)** | *Information Disclosure* de datos en reposo/tránsito | Cifrado TLS hacia DB, tokenización PCI en proveedor externo (nunca persistir PAN/CVV), cuentas DB con mínimos privilegios. | **`V14`** (Data Protection) y **`V11` / `V12`** (Cryptography / Secure Communication). |

### Responder la pregunta 4: verificación continua y antipatrones frecuentes

Un modelo de amenazas queda obsoleto si nadie comprueba que las contramedidas mapeadas a **OWASP ASVS 5.0** realmente existen en el código desplegado. Para cerrar el ciclo con la pregunta *"¿Hicimos un buen trabajo?"*, asociá cada fila de la tabla anterior a una prueba automatizada en integración continua:

- **Pruebas de contrato e integración**: verificar que toda llamada al endpoint de órdenes sin JWT válido devuelva `401`, que intentar leer la orden de otro usuario devuelva `403`/`404` (**`V8`**) y que un webhook con firma HMAC inválida sea rechazado (**`V4` / `V12`**).
- **Pruebas de concurrencia y aritmética**: ejecutar tests paralelos contra `POST /checkout/confirm` verificando que solo una transacción avance y que montos negativos sean rechazados (**`V2`**).
- **Antipatrones que debés evitar**: considerar que "estar dentro de la misma VPC" elimina la necesidad de autenticación entre servicios (ignorando la *Frontera de Confianza 2*), copiar un DFD genérico sin actualizarlo cuando se agrega un nuevo webhook o almacenamiento S3, y redactar amenazas sin asignar un responsable ni un criterio de verificación ASVS.

### Escalar a un programa AppSec medible: `OWASP SAMM`, `BSIMM` y `NIST SSDF`

El *Threat Modeling* rinde su máximo valor cuando forma parte de un **programa formal de Seguridad de Aplicaciones (AppSec)** y no de esfuerzos aislados por proyecto:

| Marco de programa AppSec | Naturaleza y estructura | Cómo se complementan |
|---|---|---|
| **OWASP SAMM** (*Software Assurance Maturity Model*) | Modelo prescriptivo abierto con **5 funciones de negocio** (*Gobernanza, Diseño, Implementación, Verificación y Operaciones*) y 3 niveles de madurez. | Sirve como hoja de ruta accionable paso a paso para medir dónde está el equipo hoy y planificar mejoras semestrales. |
| **BSIMM** (*Building Security In Maturity Model*) | Modelo descriptivo basado en observaciones reales de programas maduros en más de cien organizaciones. | Permite comparar (*benchmarking*) tu inversión en prácticas AppSec frente a pares del mismo sector industrial. |
| **NIST SSDF (`SP 800-218`)** | Marco oficial de prácticas fundamentales de desarrollo seguro exigido en cadenas de suministro y organismos públicos. | Define los controles mínimos obligatorios de ciclo de vida (**`PO`/`PS`/`PW`/`RV`**) alineables con ASVS 5.0, SBOM y CI/CD. |

---

## Práctica guiada en laboratorio

Elegí una arquitectura pequeña que estés construyendo o un escenario de laboratorio estándar (por ejemplo, un sistema de **Transferencias Internas con Autenticación JWT y Notificaciones por Webhook**) y realizá un ejercicio completo de modelado antes de implementar nuevas funcionalidades:

1. **Dibujá el DFD**: representá al menos 2 entidades externas, 3 procesos, 2 almacenes de datos, sus flujos etiquetados con protocolo y al menos 2 **Fronteras de Confianza** claras.
2. **Aplicá STRIDE-per-element**: seleccioná 1 flujo que cruce una frontera de confianza, 1 proceso crítico y 1 almacén de datos; documentá al menos 6 amenazas concretas derivadas de la matriz STRIDE.
3. **Construí un Árbol de Ataque**: modelá un único objetivo adverso (por ejemplo, *"Ejecutar transferencia no autorizada desde cuenta ajena"*) usando al menos un nodo `AND` y un nodo `OR`.
4. **Mapeá a ASVS**: vinculá cada amenaza detectada con una contramedida técnica específica y su capítulo correspondiente de **OWASP ASVS 5.0** (Nivel 2).

::: practica Entregable mínimo
Un documento Markdown de arquitectura segura (`threat-model.md`) que contenga: (a) el diagrama DFD con fronteras de confianza numeradas, (b) la tabla STRIDE-per-element con al menos 6 filas, (c) el árbol de ataque ASCII con nodos `AND`/`OR`, y (d) la tabla de mitigaciones mapeadas a códigos `OWASP ASVS` listos para convertirse en tickets verificables.
:::

::: defensa Perspectiva defensiva y remediación
El *Threat Modeling* transforma la seguridad de un cuello de botella reactivo al final del desarrollo en una disciplina de diseño ingenieril. Su mayor valor no reside en producir un diagrama decorativo, sino en **hacer visibles las fronteras de confianza ocultas** y convertir cada amenaza abstracta (STRIDE) en un requisito verificable (OWASP ASVS) que pueda probarse automáticamente en integración continua. Cuando un equipo se acostumbra a preguntar *"¿qué puede salir mal en esta frontera?"* antes de codificar, elimina familias enteras de vulnerabilidades de diseño por construcción.
:::

## Preguntas de repaso

**1. ¿Cuáles son las cuatro preguntas fundamentales del modelado de amenazas y qué artefacto principal responde a la primera?**
Las cuatro preguntas son: *¿Qué estamos construyendo?*, *¿Qué puede salir mal?*, *¿Qué haremos al respecto?* y *¿Hicimos un buen trabajo?*. La primera pregunta se responde principalmente construyendo un **Diagrama de Flujo de Datos (DFD)** con los activos, actores y fronteras de confianza.

**2. ¿Por qué las Fronteras de Confianza (*Trust Boundaries*) son el elemento más crítico de un DFD desde el punto de vista de la seguridad?**
Porque señalan exactamente los puntos donde los datos cruzan de una zona con menor nivel de confianza o privilegio a otra diferente; toda transición a través de una frontera de confianza requiere validación de entrada, autenticación y verificación de autorización explícitas.

**3. ¿En qué se diferencia aplicar *STRIDE-per-element* respecto a evaluar las seis categorías sobre cada componente de forma genérica?**
*STRIDE-per-element* restringe el análisis en cada elemento del DFD a las categorías físicamente aplicables a su naturaleza (por ejemplo, un flujo de datos sufre *Tampering*, *Information Disclosure* y *Denial of Service*, mientras que un proceso está sujeto a las seis), reduciendo el ruido y acelerando la cobertura sistemática.

**4. ¿Qué ventaja práctica aporta modelar nodos `AND` frente a nodos `OR` en un Árbol de Ataque?**
Un nodo `OR` indica caminos alternativos independientes donde el atacante solo necesita tener éxito en uno, mientras que un nodo `AND` exige cumplir múltiples condiciones simultáneamente; por lo tanto, mitigar cualquiera de los hijos de un nodo `AND` bloquea por completo esa rama de ataque, optimizando la inversión en defensa en profundidad.

**5. ¿Cuál es el principal beneficio de elegir PASTA frente a STRIDE en sistemas críticos de negocio?**
Mientras STRIDE está enfocado en la arquitectura técnica del software, PASTA conecta en siete etapas los objetivos de negocio, el cumplimiento regulatorio, la inteligencia de amenazas reales y el análisis de impacto financiero, permitiendo priorizar controles según el riesgo real para la organización.

## Antes de avanzar

::: nota Puerta de salida
Antes de avanzar hacia el pentesting *White-Box* y la revisión segura de código fuente, asegurate de poder diferenciar cada categoría de STRIDE con un ejemplo propio y de saber traducir al menos tres amenazas arquitectónicas en requisitos concretos de **OWASP ASVS**.
:::

## Referencias y estándares abiertos

- **Threat Modeling Manifesto** (*threatmodelingmanifesto.org*) — Principios, valores y antipatrones del modelado de amenazas.
- **OWASP Application Security Verification Standard (ASVS 5.0, mayo 2025)** — Catálogo completo de requisitos verificables (`V1` a `V17`).
- **OWASP Threat Modeling Cheat Sheet** — Guía práctica de DFD, STRIDE y priorización de contramedidas.
- **Adam Shostack — *Threat Modeling: Designing for Security*** — Referencia fundacional de las 4 preguntas y *STRIDE-per-element*.
- **PASTA (*Process for Attack Simulation and Threat Analysis*)** — Marco de modelado centrado en riesgo de negocio (UcedaVélez & Morana).
