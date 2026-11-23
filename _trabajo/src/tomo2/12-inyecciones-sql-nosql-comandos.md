::: nota Objetivo de la lección
Al completar este capítulo vas a comprender la causa raíz arquitectónica de las vulnerabilidades de inyección del lado del servidor —la mezcla de instrucciones y datos no confiables en un mismo canal de texto—, analizar cómo se producen en motores SQL, bases de datos NoSQL e intérpretes del sistema operativo, y aplicar las soluciones de ingeniería definitivas (consultas parametrizadas, validación de tipos estrictos y ejecución de subprocesos sin shell) verificándolas en `laboratorios/app_lab_educativa.py`.
:::

**Prerrequisitos:** Capítulo 1.6 (Python 3), Capítulo 1.8 (HTTP) y Capítulo 2.2 (Enumeración web). **Duración sugerida:** 8 a 10 horas.

## 1. El principio fundamental: separación entre código y datos

Todas las vulnerabilidades de inyección —ya sea en un motor SQL, en una consulta documental NoSQL, en un directorio LDAP o en una llamada al sistema operativo— comparten exactamente el mismo defecto de diseño: **la aplicación construye un comando concatenando texto enviado por el usuario y se lo entrega a un intérprete para que lo analice (*parse*) y lo ejecute**.

Cuando un intérprete recibe una cadena plana ya concatenada, no tiene forma de distinguir qué caracteres escribió el programador original y qué caracteres provinieron de la petición HTTP. Si el dato de entrada contiene delimitadores sintácticos del propio lenguaje (comillas, paréntesis, operadores lógicos o separadores de comandos), esos caracteres modifican el **Árbol de Sintaxis Abstracta (AST)** de la instrucción.

```text
[Patrón Inseguro: Concatenación de cadenas]
Entrada usuario + Plantilla de texto ──► Cadena única ──► Parser del intérprete (AST alterado)

[Patrón Seguro: Parametrización / Separación de canal]
Plantilla fija con marcadores (?)    ──► Compilación del AST fijo en el motor
Entrada usuario                      ──► Vinculación como literal puro (nunca altera el AST)
```

La regla de oro de la ingeniería de software seguro (OWASP ASVS V5) es directa: **nunca se sanea una inyección intentando adivinar o borrar palabras prohibidas; se elimina por diseño separando el canal del código del canal de los datos**.

## 2. Inyección SQL (SQLi): arquitectura del fallo y clasificación

Una inyección SQL ocurre cuando una aplicación incorpora datos externos directamente en la cadena de una sentencia SQL mediante concatenación (`+`), interpolación (`f"..."` en Python, `${...}` en JavaScript) o formato (`%s`).

### Comparación directa en código Python (SQLite / PostgreSQL)

Observá la diferencia entre un bloque vulnerable por concatenación y el patrón seguro implementado en nuestro laboratorio `laboratorios/app_lab_educativa.py`:

```python
# PATRÓN VULNERABLE (PROHIBIDO): interpolación directa con f-string
# El motor SQL compila la cadena DESPUÉS de haber insertado el texto del usuario.
def buscar_inseguro(db, categoria_usuario):
    cur = db.cursor()
    consulta = f"SELECT id, nombre, precio FROM productos WHERE categoria = '{categoria_usuario}'"
    cur.execute(consulta)
    return cur.fetchall()

# PATRÓN SEGURO (implementado en laboratorios/app_lab_educativa.py): consulta parametrizada
# El motor SQL compila primero la estructura fija con marcadores (?) y luego recibe la tupla de valores.
def buscar_seguro(db, q):
    cur = db.cursor()
    cur.execute(
        "SELECT id, nombre, categoria, precio FROM productos WHERE categoria = ? OR nombre LIKE ?",
        (q, f"%{q}%"),
    )
    return cur.fetchall()
```

### Por qué las consultas parametrizadas son inmunes

En una consulta parametrizada (*Prepared Statement*), la comunicación entre el backend y el motor de base de datos ocurre en dos pasos separados a nivel de protocolo:
1. **Preparación (`PREPARE`):** el motor de base de datos recibe `SELECT id, nombre FROM productos WHERE categoria = ?`, analiza la gramática SQL, valida las tablas y construye el árbol de ejecución. En este punto la estructura lógica de la consulta queda **congelada**.
2. **Ejecución (`EXECUTE`):** el backend envía el valor del parámetro en un paquete de datos separado. Aunque el valor contenga comillas simples, palabras como `OR` o `UNION`, el motor lo almacena literalmente dentro del nodo de datos del parámetro `?` sin volver a invocar al parser SQL.

### Clasificación técnica de escenarios SQLi durante una auditoría

Cuando auditás código o probás una aplicación en un entorno autorizado, los fallos de inyección SQL se clasifican según cómo responde la aplicación:

| Clasificación | Comportamiento de la aplicación | Qué observar durante la auditoría |
|---|---|---|
| **In-band (Basada en resultados o errores)** | La respuesta HTTP muestra directamente filas devueltas por la consulta o mensajes de excepción del motor de base de datos (`sqlite3.OperationalError`, `PSQLException`). | Cambios en la estructura de la tabla devuelta o trazas de error detalladas ante una comilla desbalanceada. |
| **Inferencial Booleana (*Boolean-Blind*)** | La aplicación no muestra errores ni datos de la base de datos, pero devuelve una página diferente (p. ej. "Producto disponible" frente a "No encontrado") según si la condición SQL evalúa a verdadero o falso. | Diferencia reproducible en el código de estado, tamaño o contenido ante una condición lógica verdadera (`1=1`) frente a una falsa (`1=2`). |
| **Inferencial Temporal (*Time-Blind*)** | La respuesta visual es idéntica en todos los casos, pero el tiempo de procesamiento de la base de datos varía si se evalúa una condición sincrónica. | Latencia medible en el tiempo de respuesta del servidor asociada a la evaluación condicional de la sentencia. |
| **De Segundo Orden (*Second-Order*)** | El dato se almacena primero de forma segura en la base de datos, pero más tarde otra rutina interna lee ese valor de la tabla y lo concatena sin parametrizar en una segunda consulta. | Rutinas de reportes, exportación o paneles administrativos que confían ciegamente en datos ya guardados en la base. |

::: aviso Cuidado con los lugares donde `?` no puede usarse
Los marcadores de parámetros (`?` o `$1`) solo reemplazan **valores literales** (en cláusulas `WHERE`, `VALUES` o `SET`). No pueden parametrizar nombres de columnas ni el sentido de ordenamiento en un `ORDER BY campo ASC|DESC`. Para esos casos dinámicos, la única solución segura es validar la entrada contra una **lista blanca estricta en código**:
```python
COLUMNAS_PERMITIDAS = {"nombre": "nombre", "precio": "precio", "id": "id"}
col_segura = COLUMNAS_PERMITIDAS.get(param_orden, "id")
```
:::

## 3. Inyección en bases de datos NoSQL (NoSQLi)

Un mito frecuente es creer que al usar bases de datos documentales como MongoDB, CouchDB o Redis "no existen inyecciones porque no hay SQL". Si bien no se usa el lenguaje SQL, los motores NoSQL utilizan estructuras de consulta basadas en objetos JSON o diccionarios que admiten **operadores lógicos de evaluación** (por ejemplo, en MongoDB los operadores que comienzan con `$`, como `$ne`, `$gt`, `$in`, `$regex` o `$where`).

### Cómo ocurre el fallo en APIs que aceptan JSON

Si un backend en Node.js/Express o Python recibe un cuerpo JSON y pasa el campo `req.body.filtro` directamente al método `coleccion.find({ categoria: req.body.filtro })` sin verificar que sea una cadena de texto (`str`), un cliente podría enviar un objeto anidado `{"$ne": ""}` en lugar de un string. Al recibir un diccionario en vez de un string, el driver de la base de datos lo interpreta como un operador de consulta (distinto de vacío) en lugar de una comparación literal.

### Mitigación estricta en NoSQL

1. **Validación rigurosa de tipos y esquemas (Pydantic, Zod, JSON Schema):** antes de tocar la base de datos, forzá que el parámetro sea estrictamente de tipo `str` o `int`. Si se espera una cadena y llega un diccionario o lista, rechazá la petición con `400 Bad Request`.
2. **Deshabilitar evaluación de JavaScript en el motor:** en MongoDB, mantener desactivada la ejecución de scripts del lado servidor (`--noscripting`) y prohibir el uso del operador `$where`.

## 4. Inyección de comandos del sistema operativo (Command Injection)

La inyección de comandos ocurre cuando una aplicación web invoca una utilidad del sistema operativo (como `ping`, `convert`, `tar`, `git` o `openssl`) pasando una cadena construida con datos del usuario a través de un intérprete de comandos (`sh -c` en Linux o `cmd.exe /c` en Windows).

Cuando se invoca una shell, caracteres como `;`, `|`, `&`, `&&`, `||`, `` ` `` o `$(...)` son interpretados por la shell como separadores para encadenar nuevos procesos.

### Cómo eliminar el riesgo por completo en Python

```python
import subprocess
import ipaddress

# PATRÓN VULNERABLE (PROHIBIDO): shell=True con cadena concatenada
# Invoca /bin/sh -c, permitiendo que metacaracteres de shell alteren el comando.
def verificar_host_inseguro(ip_usuario):
    return subprocess.check_output(f"ping -c 1 {ip_usuario}", shell=True, text=True)

# PATRÓN SEGURO (DEFENSA EN PROFUNDIDAD):
# 1. Usar bibliotecas nativas del lenguaje siempre que existan (p. ej. socket o ipaddress).
# 2. Si es imprescindible llamar a un binario externo: validar formato + pasar lista de argumentos con shell=False.
def verificar_host_seguro(ip_usuario: str) -> str:
    # Paso 1: Validación estricta de tipo/formato (solo acepta una IP válida)
    ip_validada = str(ipaddress.ip_address(ip_usuario))
    # Paso 2: Ejecución directa del binario (execve) SIN pasar por /bin/sh (shell=False)
    res = subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip_validada],
        shell=False,
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    return res.stdout
```

Cuando usás `subprocess.run(["comando", "arg1", "arg2"], shell=False)`, el sistema operativo invoca directamente la llamada al sistema `execve()` (o `CreateProcess` en Windows) sin lanzar `/bin/sh` ni `cmd.exe`. Por lo tanto, los elementos de la lista pasan directamente al vector `argv[]` del programa destino como texto plano, haciendo imposible encadenar otros comandos.

## 5. Otras familias de inyección: XPath, LDAP, SSI/ELI y uso metódico de SQLMap

Además de SQL y comandos OS, el principio de **separación código/datos** aplica directamente a tres contextos frecuentes en entornos empresariales:

1. **Inyección LDAP (*LDAP Injection*):** cuando una aplicación web autentica o busca usuarios en Active Directory/OpenLDAP concatenando entrada sin escapar en filtros como `(&(uid={usuario})(userPassword={clave}))`. Si un usuario envía `*` o `)(|(objectClass=*`, altera la lógica booleana del filtro LDAP. **Mitigación:** escapar caracteres reservados LDAP (`\`, `*`, `(`, `)`, NUL según **RFC 4515**) usando funciones oficiales de la librería LDAP antes de interpolar.
2. **Inyección XPath (*XPath Injection*):** análoga a SQLi pero sobre consultas a documentos XML (`//usuario[nombre='...' and clave='...']/rol`). **Mitigación:** usar consultas XPath **parametrizadas** (variables vinculadas por la API XML) o listas blancas estrictas alfanuméricas.
3. **Server-Side Includes (SSI) y Expression Language Injection (ELI):** ocurren cuando un servidor HTML antiguo evalúa directivas `<!--#exec ...-->` o un backend Java/Spring evalúa expresiones `${...}` suministradas por el cliente. **Mitigación:** deshabilitar SSI en el servidor web si no es indispensable y nunca evaluar entrada del cliente como expresión del framework.

### Confirmación controlada de inyecciones ciegas y pruebas Out-of-Band (OAST)

En auditorías reales, muchas inyecciones no devuelven mensajes de error ni muestran datos en la respuesta HTTP (*Blind Injection*). En un laboratorio aislado y autorizado, la confirmación debe hacerse con **pruebas mínimas, reproducibles y no destructivas** que demuestren la causa raíz sin provocar denegación de servicio (DoS) ni alterar registros:

1. **SQLi ciega: inferencia booleana frente a inferencia temporal controlada**
   - **Inferencia booleana (*Boolean-Blind*):** es siempre la primera opción porque no introduce carga ni latencia en el motor de base de datos. Se comparan dos expresiones lógicas inocuas (por ejemplo, una condición que evalúa a verdadero frente a otra que evalúa a falso) y se observa si la respuesta HTTP cambia de forma consistente en código de estado, longitud o texto funcional.
   - **Inferencia temporal controlada (*Time-Blind*):** se usa únicamente cuando la respuesta HTTP es idéntica para verdadero y falso. Debe emplear una pausa **breve y acotada** (típicamente de 2 a 3 segundos, nunca bucles de cómputo pesado ni demoras largas que saturen el *pool* de conexiones de la aplicación) y repetirse con dos valores distintos de retardo (ej. 2 s frente a 4 s) para descartar ruido de red antes de confirmar el hallazgo.

2. **Confirmación fuera de banda (OAST / OOB) para *Blind OS Command Injection***
   - Cuando la aplicación invoca un subproceso del sistema operativo en segundo plano (por ejemplo, mediante `shell=True`) y descarta por completo la salida estándar (`stdout`/`stderr`) o responde de manera asíncrona, ni la respuesta HTTP ni el tiempo de espera confirman con certeza la ejecución.
   - La técnica **OAST (*Out-of-Band Application Security Testing*)** utiliza un servidor de escucha controlado dentro de la red aislada del laboratorio —como una instancia local de **`interactsh`**, *Burp Collaborator* en entorno privado o un receptor HTTP/DNS propio— para detectar si el servidor auditado inicia una conexión saliente al procesar el parámetro.
   - En lugar de ejecutar comandos invasivos o destructivos, se valida el canal con un identificador único de prueba mediante una resolución DNS mínima o una petición HTTP controlada hacia el listener del laboratorio (por ejemplo, `nslookup <token_unico>.oob.lab.local` o `curl -fsS http://127.0.0.1:9090/<token_unico>`). Recibir el registro DNS o HTTP con `<token_unico>` en el servidor de escucha confirma de forma inequívoca la inyección de comandos sin leer ni modificar archivos del servidor.

::: defensa Telemetría y mitigación frente a inyecciones ciegas y canales OOB (Purple Team)
- **Causa raíz:** concatenación de entrada no confiable en consultas SQL o en invocaciones de shell (`shell=True`), combinada con ausencia de restricciones de red saliente en el servidor de aplicaciones.
- **Detección (Blue Team):** en host, correlacionar alertas de **Sysmon (Event ID 1)** o **`auditd`** cuando un proceso web (`gunicorn`, `nginx`, `node`, `java`) genera procesos hijos inesperados (`sh`, `bash`, `nslookup`, `dig`, `curl`); en red y DNS, alertar sobre consultas DNS salientes hacia subdominios de alta entropía o conexiones HTTP originadas por el backend hacia destinos no declarados.
- **Mitigación:** además de aplicar parametrización SQL y `subprocess.run(..., shell=False)`, implementá **políticas estrictas de *egress* (filtrado de salida)** en firewall y Kubernetes/contenedores para bloquear resoluciones DNS externas arbitrarias y tráfico HTTP saliente no autorizado desde los servidores de aplicación.
:::

### Uso metódico y controlado de SQLMap en auditorías autorizadas

Cuando necesitás validar un hallazgo potencial de SQL Injection durante una auditoría autorizada en laboratorio (tras haber entendido el mecanismo manual), **`sqlmap`** automatiza la detección y enumeración controlada siempre que fijes parámetros prudentes:

```bash
# Ejecutar sqlmap a partir de una petición HTTP guardada desde el proxy local (-r peticion.req)
# --batch: no hace preguntas interactivas | --level 1 --risk 1: pruebas conservadoras iniciales
# --technique=BEU: Boolean-blind, Error-based, UNION (evita cargas pesadas por tiempo si no hacen falta)
sqlmap -r /tmp/peticion_lab.req -p q --dbms=sqlite --level=1 --risk=1 --batch --banner
```

*Advertencia operativa:* verificá primero en tu laboratorio que tus propias consultas SQL parametrizadas devuelven un mensaje claro de que el parámetro **`q` no parece ser inyectable** en SQLMap; esa es la prueba automatizada estándar de que la remediación funcionó.

## 6. Ejemplo paso a paso: auditoría de código y verificación en nuestro laboratorio

Vamos a inspeccionar cómo responde el endpoint parametrizado `/buscar-seguro` de `laboratorios/app_lab_educativa.py` cuando recibe caracteres especiales como comillas o paréntesis:

```bash
# 1. Consulta normal por categoría
curl -s "http://127.0.0.1:5050/buscar-seguro?q=redes"

# 2. Consulta enviando comillas simples y operadores SQL como texto de búsqueda
curl -s "http://127.0.0.1:5050/buscar-seguro?q=redes'%20OR%20'1'='1"
```

Salida verificada:

```json
{
  "consulta": "redes' OR '1'='1",
  "modo": "seguro_parametrizado",
  "resultados": []
}
```

¿Por qué devuelve una lista vacía `[]` y código `200 OK` sin ningún error de sintaxis SQL?
Porque en `laboratorios/app_lab_educativa.py`:
```python
cur.execute(
    "SELECT id, nombre, categoria, precio FROM productos WHERE categoria = ? OR nombre LIKE ?",
    (q, f"%{q}%"),
)
```
SQLite buscó literalmente un producto cuya categoría o nombre contuviera los caracteres `redes' OR '1'='1`. Como ningún producto se llama así, devolvió `[]` limpiamente. El árbol sintáctico de la consulta jamás se alteró.

::: defensa Perspectiva defensiva y mitigación
1. **Parametrización al 100 %:** toda consulta SQL debe usar marcadores de parámetros (`?`, `%s`, `:nombre`) o métodos de ORM que parametricen internamente (evitando métodos crudos como `.raw()` o `text()` concatenado).
2. **Principio de mínimo privilegio en la cuenta de base de datos:** la aplicación web nunca debe conectarse al motor de base de datos como `sa`, `postgres` o `root`. Debe usar una cuenta dedicada que solo tenga permisos `SELECT`, `INSERT`, `UPDATE` y `DELETE` sobre las tablas del esquema de la aplicación, sin permisos de lectura de archivos (`pg_read_file`, `LOAD_FILE`) ni ejecución de comandos (`xp_cmdshell`).
3. **Prohibición de `shell=True` en linters de CI/CD:** herramientas de análisis estático como **Bandit** (Python), **Semgrep** o **ESLint Security** detectan automáticamente llamadas a `subprocess` con `shell=True` o cadenas SQL interpoladas con `f"SELECT ..."` antes de que el código llegue a producción.
:::

## Práctica en laboratorio local

1. Abrí `laboratorios/app_lab_educativa.py` y revisá la función `buscar_seguro()`.
2. Escribí en tu carpeta de trabajo un script local `test_parametrizacion.py` que cree una tabla SQLite en memoria con 3 usuarios de prueba y compare dos funciones: una que verifica qué pasa al pasar una comilla simple a una consulta parametrizada (`WHERE usuario = ?`) y otra que valide columnas de ordenamiento mediante un diccionario de lista blanca (`COLUMNAS_PERMITIDAS`).
3. Agregá en el mismo script una función que valide una dirección IP con `ipaddress.ip_address()` antes de pasarla a una lista de argumentos con `shell=False`, comprobando que cualquier cadena que no sea una IP válida lance `ValueError` inmediatamente.

::: practica Entregable mínimo
El script `test_parametrizacion.py` documentado junto con la salida de consola demostrando que las entradas con comillas o caracteres especiales son tratadas como literales inofensivos o rechazadas por validación de tipo.
:::

## Preguntas de repaso

**1. ¿Por qué filtrar o borrar palabras como `SELECT`, `UNION` o `OR` con `replace()` no es una solución segura contra la inyección SQL?** Porque las listas negras de palabras son frágiles: rompen datos legítimos (por ejemplo, un apellido como "O'Reilly" o palabras que contienen "or") y pueden eludirse mediante variaciones de codificación, comentarios o sintaxis alternativa del motor SQL. La única solución definitiva es separar el código de los datos mediante consultas parametrizadas.

**2. ¿Qué ocurre internamente en el motor de base de datos cuando ejecutás una consulta parametrizada (`Prepared Statement`)?** El motor primero compila la plantilla SQL con los marcadores (`?`) y construye el árbol de sintaxis abstracta (AST) y el plan de ejecución de forma inmutable. Luego recibe los valores de los parámetros en un canal de datos separado y los inserta directamente como literales escalares, sin volver a pasar por el analizador sintáctico SQL.

**3. ¿Cómo se debe manejar de forma segura un parámetro que define la columna de un `ORDER BY` si los motores SQL no permiten usar `?` para nombres de columnas?** Mediante una validación por **lista blanca estricta** (*allowlist*) en el servidor: se compara el valor recibido contra un diccionario o conjunto cerrado de nombres de columnas permitidas (por ejemplo `{"precio", "nombre", "fecha"}`) y, si no coincide exactamente, se aplica un valor por defecto fijo o se devuelve un error `400`.

**4. ¿Cómo puede ocurrir una inyección en una base de datos NoSQL como MongoDB si no se utiliza lenguaje SQL?** Ocurre cuando la aplicación deserializa un cuerpo JSON o parámetros de consulta anidados y los entrega directamente al método de búsqueda sin validar que el valor sea un tipo escalar (`string` o `number`). Si el cliente envía un objeto con operadores como `{"$ne": null}`, el motor NoSQL evalúa el operador lógico en lugar de comparar un texto literal.

**5. ¿Cuál es la diferencia de seguridad a nivel del sistema operativo entre `subprocess.run(f"cmd {arg}", shell=True)` y `subprocess.run(["cmd", arg], shell=False)`?** Con `shell=True`, Python invoca primero al intérprete `/bin/sh -c` (o `cmd.exe /c`), el cual interpreta metacaracteres como `;`, `|`, `&&` o `$(...)` y puede lanzar nuevos procesos. Con `shell=False` y una lista de argumentos, el sistema operativo ejecuta directamente el binario mediante `execve()` pasando `arg` como un elemento literal dentro de `argv[]`, sin que intervenga ninguna shell.

## Antes de avanzar

Verificá que podés:
- Explicar por qué la mezcla de código y datos altera el AST de un intérprete.
- Escribir consultas SQL 100 % parametrizadas y listas blancas para cláusulas `ORDER BY`.
- Sustituir cualquier llamada a comandos del sistema con `shell=True` por bibliotecas nativas o listas de argumentos con `shell=False` y validación de tipos.

::: nota Puerta de salida
Ya dominás la seguridad de los intérpretes del lado del servidor. Ahora vamos a cruzar al otro extremo de la comunicación HTTP para analizar cómo proteger el navegador del usuario: avanzá al **Capítulo 2.4 · Seguridad del lado del cliente: XSS, CSRF, CORS y CSP**.
:::

## Referencias y estándares abiertos

- **OWASP Top 10 (A03:2021 Injection) y OWASP ASVS v4.0 (Capítulo V5 — Validation, Sanitization and Encoding):** requisitos estándar de verificación contra inyecciones.
- **OWASP SQL Injection Prevention Cheat Sheet & OS Command Injection Defense Cheat Sheet:** guías de parametrización y ejecución segura de procesos.
- **Documentación oficial de Python (`sqlite3` y `subprocess`):** uso de parámetros DB-API 2.0 (PEP 249) y advertencias de seguridad sobre `shell=True`.
