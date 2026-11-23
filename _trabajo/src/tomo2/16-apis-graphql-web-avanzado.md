::: nota Objetivo de la lección
Al finalizar este capítulo vas a dominar la auditoría y el diseño seguro de APIs modernas (REST y GraphQL) conforme al estándar OWASP API Security Top 10, comprender anomalías avanzadas del protocolo HTTP y de concurrencia (asignación masiva, condiciones de carrera TOCTOU, discrepancias de encuadre HTTP entre proxy y backend y envenenamiento de caché), y aplicar una metodología sistemática de revisión de código fuente (*Whitebox Analysis*) trazando fuentes, validadores y sumideros.
:::

**Prerrequisitos:** Capítulo 2.3 a 2.6 (Seguridad Web del lado servidor y cliente). **Duración sugerida:** 8 a 10 horas.

## 1. Arquitectura de APIs REST y OWASP API Security Top 10

Las aplicaciones modernas separan casi toda su lógica de negocio en APIs REST o GraphQL consumidas por clientes web (SPA), aplicaciones móviles y otros microservicios. A diferencia de una aplicación tradicional que renderiza HTML en el servidor, una API expone directamente las estructuras de datos y métodos del dominio.

Además de BOLA (IDOR) y BFLA que estudiamos en el Capítulo 2.5, existen tres riesgos arquitectónicos propios de las APIs que siempre debés auditar:

### 1. Asignación Masiva (*Mass Assignment* / *BOPLA — Broken Object Property Level Authorization*)

Ocurre cuando un endpoint de creación o actualización (`PUT /api/perfil` o `PATCH /api/usuarios/me`) toma todo el diccionario JSON enviado por el cliente y lo vuelca directamente sobre el modelo de base de datos (`usuario.update(**request.json)`).
Si la tabla o modelo interno `Usuario` tiene columnas como `es_admin`, `saldo` o `plan_suscripcion` que no figuraban en el formulario visual, un cliente que agregue `"es_admin": true` en el JSON modificaría propiedades privilegiadas.

**Mitigación:** separar estrictamente el **Modelo de Base de Datos** del **Esquema de Entrada (DTO)** definiendo una lista blanca explícita de campos editables por el usuario:

```python
# PATRÓN SEGURO contra Mass Assignment: esquema cerrado de campos permitidos
CAMPOS_EDITABLES_PERFIL = {"nombre_mostrar", "zona_horaria", "idioma"}

def actualizar_perfil_seguro(datos_json: dict) -> dict:
    # Ignora o rechaza cualquier propiedad no incluida en el conjunto permitido
    campos_invalidos = set(datos_json.keys()) - CAMPOS_EDITABLES_PERFIL
    if campos_invalidos:
        raise ValueError(f"Propiedades no permitidas en la solicitud: {sorted(campos_invalidos)}")
    return {k: datos_json[k] for k in CAMPOS_EDITABLES_PERFIL if k in datos_json}
```

### 2. Exposición excesiva de propiedades en respuestas

Es el problema inverso: el backend serializa el objeto completo de la base de datos (`return jsonify(usuario.__dict__)`) confiando en que el frontend solo mostrará en pantalla el nombre y el avatar, pero enviando en el JSON oculto el hash de contraseña, tokens internos o correos privados.
**Mitigación:** definir siempre un esquema de salida (*Response DTO*) que proyecte únicamente las columnas públicas necesarias para esa vista.

### 3. Consumo irrestricto de recursos (*Unrestricted Resource Consumption* — API4:2023)

Si un endpoint de listado (`GET /api/registros?limite=10000000`) acepta el parámetro `limite` sin tope máximo, una sola petición puede agotar la memoria RAM y la CPU de la base de datos.
**Mitigación:** imponer en el servidor un tope duro (`limite = min(int(request.args.get("limite", 20)), 100)`), limitar el tamaño máximo del cuerpo HTTP (`MAX_CONTENT_LENGTH`) y aplicar *rate limiting* por token y por IP.

## 2. Seguridad en APIs GraphQL

**GraphQL** reemplaza múltiples rutas REST por un único endpoint (usualmente `POST /graphql`) donde el cliente especifica exactamente qué objetos y campos desea consultar (*Queries*) o modificar (*Mutations*). Esta flexibilidad exige cuatro controles defensivos específicos en el servidor GraphQL:

| Riesgo en GraphQL | Por qué ocurre | Control de ingeniería requerido |
|---|---|---|
| **Exposición del esquema completo en producción** | La consulta de **introspección** (`__schema`, `__type`) viene habilitada por defecto en muchos motores. | Desactivar la introspección en entornos de producción para usuarios no administrativos. |
| **Consultas circulares profundas (*Depth DoS*)** | Si `Autor` tiene `libros` y `Libro` tiene `autor`, un cliente puede anidar 30 niveles (`autor { libros { autor { libros ... } } }`) colapsando el servidor. | Configurar un validador de profundidad máxima (`max_depth = 5`) y de complejidad máxima de consulta (*Query Cost Analysis*). |
| **Abuso de *Batching* / *Aliases* para evadir límites de tasa** | Enviar un arreglo de 500 mutaciones o 500 *aliases* dentro de una sola petición HTTP `POST /graphql` evade un *rate limiter* que solo cuente peticiones HTTP. | Limitar la cantidad de operaciones/aliases por petición HTTP y aplicar el *rate limiting* dentro del resolver de autenticación. |
| **Falta de autorización a nivel de *Resolver* o campo** | Proteger solo la ruta HTTP `/graphql` pero olvidar validar permisos en cada nodo del grafo. | Verificar la autorización del usuario autenticado dentro de cada *resolver* de objeto y de campo sensible. |

## 3. Anomalías de protocolo HTTP y concurrencia en servidor

En el nivel avanzado (*Senior Web*), muchos defectos no provienen de un carácter mal escapado sino de discrepancias en el estado temporal o en la interpretación del protocolo HTTP entre capas:

### 1. Condiciones de carrera (*Race Conditions* / TOCTOU)

Un fallo **TOCTOU (*Time-of-Check to Time-of-Use*)** ocurre cuando una aplicación primero comprueba una condición en la base de datos (`SELECT saldo FROM cuentas WHERE id = 1` → verifica `saldo >= 100`) y, milisegundos después, ejecuta la actualización (`UPDATE cuentas SET saldo = saldo - 100`).

Si llegan 10 peticiones concurrentes en el mismo milisegundo (por ejemplo enviadas en paralelo sobre una misma conexión multiplexada HTTP/2), las 10 peticiones leen `saldo = 100` antes de que la primera haya escrito el `UPDATE`, aprobando la operación 10 veces.

```sql
-- PATRÓN SEGURO ATÓMICO EN SQL (elimina la ventana TOCTOU):
-- La verificación y el descuento ocurren en una única sentencia atómica con bloqueo de fila
UPDATE cuentas
SET saldo = saldo - 100
WHERE id = ? AND saldo >= 100;
-- Luego el backend verifica que rowcount == 1; si es 0, el saldo era insuficiente.
```

En operaciones de múltiples pasos, debe usarse una transacción con bloqueo pesimista (`SELECT ... FOR UPDATE`) o una clave de idempotencia única por operación (`Idempotency-Key` en Redis con `SETNX`).

### 2. Discrepancias de encuadre HTTP (*HTTP Request Smuggling*)

En arquitecturas con un proxy inverso delante de un servidor de aplicaciones que reutiliza conexiones HTTP/1.1 persistentes (*keep-alive*), todas las peticiones de distintos usuarios viajan una detrás de otra por el mismo socket TCP interno.
El protocolo HTTP/1.1 (RFC 9112) define dos formas de indicar dónde termina el cuerpo de una petición:
- `Content-Length` (longitud exacta en bytes).
- `Transfer-Encoding: chunked` (bloques terminados en un bloque de tamaño `0`).

Si una petición malformada incluye ambas cabeceras (o una cabecera `Transfer-Encoding` con formato ambiguo) y el proxy frontal calcula el límite usando una cabecera mientras el backend usa la otra, ambos servidores pierden la sincronización sobre dónde termina una petición y dónde empieza la siguiente.

**Mitigación:**
1. Configurar el proxy inverso para que **normalice estrictamente las peticiones** y rechace con `400 Bad Request` cualquier solicitud HTTP/1.1 que contenga simultáneamente `Content-Length` y `Transfer-Encoding`.
2. Utilizar **HTTP/2 de extremo a extremo** (donde la longitud está definida por tramas binarias y no por cabeceras de texto ambiguas).

### 3. Envenenamiento de caché web, *Host Header Attacks*, *HTTP/2 Downgrading* y *Session Puzzling*

- **Web Cache Poisoning:** ocurre cuando una caché intermedia (CDN o Varnish/Nginx) guarda una respuesta basándose solo en la clave de caché (*cache key*: método + ruta + query string), pero el backend modifica la respuesta usando una cabecera no incluida en esa clave (por ejemplo `X-Forwarded-Host`). **Mitigación:** ignorar cabeceras `X-Forwarded-*` que no provengan del balanceador de confianza e incluir en `Vary` cualquier cabecera que modifique la salida.
- **Host Header Attacks:** si la aplicación usa el valor de la cabecera `Host:` directamente para construir enlaces de "Recuperar contraseña" o redirigir tráfico interno, un cliente puede manipular esa cabecera generando enlaces hacia un dominio controlado por él o eludiendo restricciones de acceso local. **Mitigación:** validar el `Host` permitido explícitamente en Nginx (`server_name` estricto sin bloque comodín por defecto) y generar enlaces de recuperación desde una URL base fija de configuración (`BASE_URL`), jamás desde cabeceras de la petición.
- **HTTP/2 Downgrading (`H2.CL` / `H2.TE`):** ocurre cuando el proxy frontal recibe tráfico **HTTP/2** y lo traduce internamente a **HTTP/1.1** hacia el backend introduciendo cabeceras `Content-Length` o `Transfer-Encoding` conflictivas. **Mitigación:** usar HTTP/2 de extremo a extremo o configurar el proxy inverso para rechazar cabeceras prohibidas/redundantes de encuadre durante la traducción.
- **Session Puzzling (*Variable Overloading*):** fallo lógico donde distintas funcionalidades (por ejemplo "Registro incompleto" y "Autenticación") escriben en las mismas claves del almacén de sesión (`session['user_id']`), permitiendo que un flujo incompleto deje una sesión parcialmente autenticada reutilizable en otra ruta. **Mitigación:** usar claves de sesión separadas y con prefijo explícito por módulo o flujo.

### 4. *DNS Rebinding*, *Prototype Pollution* y *Type Juggling*

1. **DNS Rebinding (evasión temporal de filtros SSRF y SOP):** como vimos en el Cap. 2.6, validar la IP del DNS antes de llamar a `requests.get(url)` deja una pequeña ventana temporal (TOCTOU): si un dominio externo responde primero con una IP pública válida y `TTL=0`, y un milisegundo después responde `127.0.0.1` cuando el cliente HTTP vuelve a resolver el nombre, burla la validación previa. **Mitigación:** conectar el socket directamente a la **misma IP pública ya validada** fijando la cabecera `Host`, además de exigir validación estricta del `Host` en servicios internos locales.
2. **Prototype Pollution (JavaScript / Node.js):** cuando funciones inseguras de fusión recursiva de objetos (`merge`/`clone`) copian propiedades con clave `__proto__`, `constructor` o `prototype` desde un JSON de usuario, alterando propiedades heredadas de `Object.prototype` en toda la aplicación (causando escalada de privilegios lógica o ejecución de código en gadgets del backend/DOM). **Mitigación:** usar `Map` o `Object.create(null)`, validar esquemas JSON rechazando claves `__proto__` / `constructor` y congelar prototipos (`Object.freeze(Object.prototype)`).
3. **Type Juggling (comparación débil de tipos en PHP/JS):** ocurre al usar `==` (comparación laxa) en lugar de `===` (identidad estricta de tipo y valor); por ejemplo, en versiones heredadas de PHP cadenas que empiezan con `"0e..."` comparadas con `==` se evaluaban como notación científica igual a cero. **Mitigación:** exigir siempre comparación estricta (`===`) y usar `hash_equals()` en tiempo constante para tokens y firmas.

::: nota Profundización en el Tomo VI (Caps. 6.1 a 6.4)
En este capítulo introducimos los fundamentos y mitigaciones esenciales. El análisis en profundidad de las técnicas avanzadas de explotación, telemetría y defensa se desarrolla en el **Tomo VI (Caps. 6.1 a 6.4)**:
- ***Race Conditions* HTTP/2 (*single-packet attack*):** sincronización de ráfagas sobre multiplexación HTTP/2 y mitigaciones de concurrencia distribuida.
- ***Web Cache Poisoning* y *Web Cache Deception*:** abuso de *unkeyed headers*, normalización de rutas en CDNs y reglas de cacheo seguras.
- **OAuth 2.0 complejo:** validación estricta de `redirect_uri`, PKCE, confusión de `state` / `nonce` y abuso de flujos entre clientes y servidores de autorización.
- ***Prototype Pollution* avanzado:** cadenas de *gadgets* en tiempo de ejecución en Node.js y DOM, junto con detección en análisis dinámico y estático.
:::

## 4. Metodología de auditoría de código fuente (*Whitebox Pentesting*)

Contar con acceso al código fuente de la aplicación transforma la auditoría: en lugar de adivinar desde afuera, podés verificar el 100 % de las rutas y encontrar defectos lógicos en minutos. La metodología profesional combina tres técnicas:

```text
[1. Mapa de Superficie]        [2. Trazado Taint (Source → Sink)]      [3. Revisión de Lógica]
Listar todas las rutas         Seguir cada dato de entrada hasta       Verificar transacciones,
(@app.route, routers,          consultas SQL, plantillas, archivos,    controles de propiedad
resolvers GraphQL)             llamadas HTTP o deserializadores        y estados de negocio
```

### Trazado de flujo de datos (*Taint Analysis*: Fuentes → Sanitizadores → Sumideros)

1. **Identificar las Fuentes (*Sources*):** todos los puntos donde entran datos controlados por el cliente (`request.args`, `request.form`, `request.json`, `request.headers`, `request.cookies`, parámetros de ruta).
2. **Identificar los Sumideros (*Sinks*):** funciones sensibles donde un dato sin validar causa un fallo:
   - Base de datos: `cursor.execute()`, `.raw()`, `text()`.
   - Sistema operativo: `subprocess.run()`, `os.system()`, `os.popen()`.
   - Archivos: `open()`, `Path()`, `send_file()`.
   - Plantillas / HTML: `render_template_string()`, `Markup()`, `|safe`.
   - Red saliente: `requests.get()`, `urllib.request.urlopen()`.
   - Deserialización: `pickle.loads()`, `yaml.load()`.
3. **Verificar el Sanitizador o Parametrización en el camino:** comprobar que entre cada *Source* y cada *Sink* exista parametrización estricta, validación por lista blanca o codificación contextual.

::: nota Profundización en el Tomo VI (Caps. 6.1 a 6.4)
El flujo de análisis estático que aplicamos aquí en Python se amplía en el **Tomo VI (Caps. 6.1 a 6.4)** con metodología sistemática de ***White-Box Code Review* en 5 lenguajes**, cubriendo patrones de fuentes, sanitizadores y sumideros específicos de cada ecosistema junto con reglas SAST reproducibles.
:::

## 5. Ejemplo paso a paso: auditoría Whitebox automatizada con un script en Python

Veamos cómo escribir un auditor estático ligero en Python que inspeccione archivos `.py` buscando patrones de riesgo (como `shell=True`, `pickle.loads`, `yaml.load(` sin `safe_load` o `render_template_string(f"`) y verificar con él nuestro propio laboratorio:

```python
# Auditor estático educativo de sumideros riesgosos en archivos Python
import re, sys

REGLAS_WHITEBOX = [
    ("WB-CMD-01", r"subprocess\.\w+\([^)]*shell\s*=\s*True", "Uso de shell=True en subprocess"),
    ("WB-DES-02", r"\bpickle\.loads?\(", "Deserialización con pickle"),
    ("WB-YML-03", r"\byaml\.load\(", "Uso de yaml.load() (preferir yaml.safe_load)"),
    ("WB-SSTI-04", r"render_template_string\(\s*f[\"']", "Interpolación f-string dentro de plantilla Jinja2"),
]

def auditar_codigo(ruta_archivo: str):
    lineas = open(ruta_archivo, "r", encoding="utf-8").splitlines()
    hallazgos = 0
    for num, texto in enumerate(lineas, 1):
        for cod, patron, desc in REGLAS_WHITEBOX:
            if re.search(patron, texto):
                hallazgos += 1
                print(f"  [ALERTA {cod}] Línea {num}: {desc} -> {texto.strip()}")
    if hallazgos == 0:
        print(f"  [OK] {ruta_archivo}: 0 sumideros inseguros detectados por las reglas base.")
```

Al ejecutar `python laboratorios/auditor_whitebox_codereview.py ./laboratorios/`, el auditor identifica de inmediato el sumidero SQLi intencional del endpoint `/buscar-vulnerable` en `app_lab_educativa.py` (`cursor.execute(<dinámico>)` — `CWE-89`), mientras que ninguno de los endpoints `-seguro` ni los restantes scripts defensivos disparan falsos positivos. Esa detección estática temprana permite interceptar regresiones antes de publicar código.

::: defensa Perspectiva defensiva y mitigación
1. **Esquemas de entrada y salida tipados (DTOs):** utilizá bibliotecas como Pydantic o Marshmallow en cada endpoint de API para rechazar propiedades desconocidas (*extra = "forbid"*), fijar longitudes máximas y validar tipos escalares antes de ejecutar la lógica de negocio.
2. **Operaciones financieras o de inventario siempre atómicas:** nunca separes la lectura de verificación (`SELECT`) de la escritura (`UPDATE`) en peticiones concurrentes sin una transacción con bloqueo de fila o una actualización condicional atómica.
3. **Integrar análisis estático (SAST) en cada commit:** ejecutá Semgrep o Bandit en el pipeline de integración continua para bloquear automáticamente código que introduzca sumideros peligrosos.
:::

## Práctica en laboratorio local

1. **White-Box (`Source → Sink`) en `laboratorios/`:** corré `python laboratorios/auditor_whitebox_codereview.py ./laboratorios/`, verificá qué línea de `buscar_vulnerable()` en `app_lab_educativa.py` dispara `CWE-89`, y añadí en una copia local `auditor_whitebox_lab.py` la regla `WB-SSTI-04` (`render_template_string(f"`) para detectar también `/plantilla-vulnerable` y confirmar cero hallazgos en `/plantilla-seguro`.
2. **Auditoría API en OWASP Juice Shop (`127.0.0.1:3000`):** inspeccioná la API REST/JSON del carrito o perfil en **OWASP Juice Shop** probando un caso de *Mass Assignment* / *Excessive Data Exposure*, y verificá qué propiedades acepta o filtra el backend.
3. **Práctica adicional recomendada:** completá los escenarios de APIs vulnerables (BOLA, BFLA, Mass Assignment y SSRF) en **crAPI** y los laboratorios de *API Testing* y *GraphQL* en **PortSwigger Web Security Academy**.

::: practica Entregable mínimo
Salida comentada de `auditor_whitebox_codereview.py` sobre `app_lab_educativa.py` (diferenciando hallazgos `-vulnerable` de `-seguro`), la regla `WB-SSTI-04` probada y la ficha del ejercicio sobre APIs de OWASP Juice Shop.
:::

## Preguntas de repaso

**1. ¿En qué consiste la vulnerabilidad de Asignación Masiva (*Mass Assignment*) en una API REST y cómo se previene por diseño?** Ocurre cuando el backend vincula automáticamente todos los campos de un cuerpo JSON enviado por el cliente a las columnas de un modelo de base de datos, permitiendo sobrescribir atributos internos como `es_admin` o `rol`. Se previene definiendo un esquema de entrada (DTO) con una lista blanca explícita de las propiedades que el usuario tiene permitido editar.

**2. ¿Por qué una API GraphQL requiere limitar la profundidad de las consultas (*Query Depth*) y validar permisos dentro de cada *resolver*?** Porque en GraphQL las relaciones entre objetos forman un grafo que puede contener ciclos (por ejemplo `usuario → grupo → miembros → grupo`), permitiendo que una sola consulta muy anidada agote la CPU y la memoria del servidor. Además, como todos los datos se consultan a través de un único endpoint `/graphql`, validar permisos solo en la ruta HTTP no impide que un usuario solicite nodos o campos restringidos dentro del grafo.

**3. ¿Qué es una condición de carrera TOCTOU (*Time-of-Check to Time-of-Use*) y cómo se resuelve en una base de datos relacional?** Es un fallo de concurrencia donde el programa comprueba primero una condición (por ejemplo, que el saldo sea suficiente) y luego modifica el estado en un paso separado; si varias peticiones llegan en paralelo durante esa ventana de milisegundos, todas pasan la verificación inicial antes de que se registre el descuento. Se resuelve realizando la verificación y el cambio en una sola sentencia SQL atómica (`UPDATE ... WHERE id = ? AND saldo >= ?`) o usando transacciones con bloqueo de fila (`SELECT ... FOR UPDATE`).

**4. ¿Cuál es la causa técnica del *HTTP Request Smuggling* entre un proxy inverso y un servidor backend?** Se produce cuando una petición HTTP/1.1 malformada presenta ambigüedad en los encabezados que definen la longitud del cuerpo (por ejemplo, combinando `Content-Length` y `Transfer-Encoding: chunked`) y el proxy frontal interpreta un límite distinto al que interpreta el backend sobre la conexión TCP reutilizada, desincronizando la cola de peticiones.

**5. En una revisión de código fuente (*Whitebox*), ¿qué significan los términos *Source* (fuente) y *Sink* (sumidero)?** Un *Source* es cualquier punto de entrada por donde ingresan datos externos no confiables a la aplicación (parámetros GET/POST, cuerpo JSON, cabeceras HTTP, cookies). Un *Sink* es una función o operación sensible (como ejecutar una consulta SQL, abrir una ruta de archivo, renderizar HTML o invocar un subproceso) donde la llegada de un dato procedente de un *Source* sin validación ni parametrización produce una vulnerabilidad.

## Antes de avanzar

Verificá que podés:
- Auditar una API REST y GraphQL frente a BOLA, BFLA, Mass Assignment, exceso de datos y falta de límites de tasa.
- Identificar y corregir ventanas de carrera TOCTOU mediante operaciones atómicas.
- Realizar una revisión Whitebox sistemática siguiendo el recorrido *Source → Sanitizador → Sink*.

::: nota Puerta de salida
Ya tenés las herramientas técnicas para auditar aplicaciones y servicios de principio a fin. Para cerrar el **Tomo II**, queda aprender la habilidad que convierte un hallazgo técnico en valor real para una organización: avanzá al **Capítulo 2.8 · Metodología profesional de pentesting, informes ejecutivos y remediación**.
:::

## Referencias y estándares abiertos

- **OWASP API Security Top 10 (Edición 2023):** catálogo oficial de los diez riesgos críticos en arquitecturas de APIs.
- **OWASP GraphQL Cheat Sheet:** guía de endurecimiento de esquemas, límite de profundidad, complejidad y autorización en GraphQL.
- **RFC 9112 (HTTP/1.1 Message Syntax and Routing — Sección 6: Message Body Length):** reglas estrictas de precedencia y rechazo ante conflicto entre `Transfer-Encoding` y `Content-Length`.
- **OWASP Code Review Guide:** metodología abierta de revisión de código fuente y análisis de flujo de datos.
