::: nota Objetivo de la lección
Al finalizar este capítulo vas a distinguir con precisión operativa entre un pentest tradicional y un ejercicio de Red Teaming orientado a objetivos y medición de detección; vas a identificar qué telemetría exacta delata los comandos clásicos de enumeración y los scripts no firmados; vas a comprender el funcionamiento y los artefactos forenses de LOLBAS en Windows y GTFOBins en Linux; y vas a analizar cómo funciona la infraestructura C2 moderna junto con las técnicas matemáticas y conductuales que usa el Blue Team para detectar *beaconing* y anomalías padre-hijo en un laboratorio aislado.
:::

## Pentest tradicional, Red Teaming y enfoque Purple Team

En seguridad ofensiva aplicada a entornos corporativos, confundir un *penetration test* (pentest) con una operación de **Red Teaming** lleva a expectativas equivocadas y mediciones inútiles. Aunque ambos evalúan la resiliencia técnica bajo autorización contractual explícita, sus objetivos, su huella en la telemetría y sus criterios de éxito son opuestos.

Un **pentest tradicional** busca **cobertura total** dentro de un alcance definido (un rango de IPs, una aplicación web o un segmento de Active Directory). El operador prioriza encontrar la mayor cantidad posible de vulnerabilidades en un tiempo acotado: lanza escaneos ruidosos de puertos y servicios, ejecuta enumeraciones masivas, prueba credenciales por diccionario dentro de límites acordados y valida configuraciones inseguras. Que el SOC bloquee al pentester suele ser un obstáculo administrativo (a menudo se pide poner la IP de origen en lista blanca), porque el foco está en el **inventario de fallos técnicos y su remediación**.

Un ejercicio de **Red Teaming**, en cambio, adopta la lógica de emulación de adversarios reales (estilo CRTO/OSEP/RTFM, siempre en entorno autorizado o laboratorio aislado). No busca barrer toda la red ni reportar cada cabecera HTTP faltante. Persigue **objetivos de negocio específicos** (*crown jewels*: acceso a un controlador de dominio, lectura de un repositorio de secretos de CI/CD o acceso a una base de datos financiera) operando con **sigilo y disciplina de OPSEC** (*Operations Security*). El verdadero cliente de un Red Team no es solo infraestructura: es el **Blue Team**. La métrica principal consiste en medir el **Tiempo Medio de Detección (MTTD)**, la calidad de las alertas y el **Tiempo Medio de Respuesta (MTTR)** ante TTPs (*Tactics, Techniques, and Procedures*) alineados a MITRE ATT&CK.

De esa tensión nace el enfoque **Purple Team**: en lugar de mantener una competencia opaca donde el equipo rojo oculta sus pasos hasta el informe final, ambos equipos colaboran en ciclos cortos. El operador rojo ejecuta una técnica controlada en el laboratorio, y el analista azul verifica en tiempo real si el evento llegó al EDR, si Sysmon registró la línea de comandos completa y si la regla de correlación en el SIEM disparó la alerta esperada.

| Dimensión operativa | Pentest tradicional | Red Teaming | Purple Teaming |
| :--- | :--- | :--- | :--- |
| **Propósito central** | Descubrir el máximo de vulnerabilidades en un activo | Emular un adversario hacia objetivos críticos (*flags*) | Validar y afinar capacidades de detección y respuesta |
| **Ruido y visibilidad** | Alto (escaneos exhaustivos, fuzzing, scanners) | Mínimo (evita firmas obvias y respeta OPSEC) | Controlado y transparente por iteración |
| **Relación con el SOC** | Frecuentemente en *allowlist* para no perder tiempo | Sin *allowlist*; se mide si el SOC detecta y contiene | Trabajo conjunto hombro a hombro en el SIEM/EDR |
| **Alcance técnico** | Amplio sobre una superficie acotada | Profundo y oportunista sobre rutas de ataque reales | Basado en matriz ATT&CK y casos de uso prioritarios |
| **Entregable clave** | Listado priorizado de fallos y remediación | Línea de tiempo ataque vs detección (MTTD/MTTR) | Reglas nuevas, telemetría corregida y brechas cerradas |

::: aviso Regla de laboratorio y autorización
Todas las técnicas analizadas en este capítulo se estudian para comprender la cadena causal entre ejecución y telemetría. En cualquier evaluación real, la emulación de TTPs fuera de un laboratorio propio exige reglas de enfrentamiento (RoE) firmadas, ventanas horarias definidas y canales de desescalamiento inmediato con el SOC.
:::

## OPSEC operativo y telemetría que delata

El **OPSEC operativo** es la disciplina de evaluar cada acción antes de ejecutarla según la huella que deja en disco, en memoria, en la red y en los registros de auditoría del sistema operativo. En redes modernas con EDR y recolección centralizada de eventos, el mayor delator de un operador novato no es una vulnerabilidad compleja, sino el reflejo automático de tipear comandos administrativos heredados de guías antiguas.

Considerá lo que sucede apenas alguien obtiene una shell interactiva en Windows y ejecuta la secuencia clásica de reconocimiento:

```text
whoami /all
net user /domain
net group "Domain Admins" /domain
ipconfig /all
nltest /dclist:corp.local
```

Cada uno de esos comandos genera una cascada de telemetría de altísima fidelidad para el Blue Team:

1. **Windows Security Event ID `4688`** (*A new process has been created*): si la política *Include command line in process creation events* está activa, registra el proceso padre (`cmd.exe`, `powershell.exe` o un binario inusual), el ejecutable hijo (`whoami.exe`, `net.exe`, `nltest.exe`) y los argumentos literales.
2. **Sysmon Event ID `1`** (*Process Creation*): agrega contexto crítico como el hash del binario, el usuario, el *Integrity Level*, `ParentImage`, `ParentCommandLine` y el `ProcessGuid` único para reconstruir todo el árbol de ejecución.
3. **PowerShell Event ID `4104`** (*Script Block Logging*): captura el contenido completo del bloque de script en memoria. Incluso si un operador ejecuta `powershell.exe -EncodedCommand <base64>` o concatena cadenas para ocultar un `Invoke-WebRequest`, el motor de PowerShell registra el código **ya decodificado** en el log `Microsoft-Windows-PowerShell/Operational` antes de ejecutarlo.
4. **PowerShell Event ID `4103`** (*Module Logging*) y **`400`/`600`**: registran la carga de módulos, el inicio del motor de PowerShell y el cambio de estado de proveedores, delatando sesiones interactivas o *downgrade attacks* hacia PowerShell v2.
5. **Tráfico RPC/LDAP y Event ID `4662` / consultas SAMR**: comandos como `net user /domain` realizan llamadas SAMR/LDAP predecibles hacia el controlador de dominio, fácilmente correlacionables con herramientas de detección de anomalías de identidad.

En un ejercicio Purple Team, la pregunta clave no es "cómo escondo `whoami`", sino "qué información ya existe en el contexto del proceso o en el token sin necesidad de lanzar subprocesos ruidosos, y qué señales debe priorizar el SOC para no ahogarse en falsos positivos". Por ejemplo, un script de administración legítimo rara vez lanza `whoami /all` seguido de `nltest /dclist` y `net group "Domain Admins" /domain` en menos de diez segundos desde `winword.exe` o `wmiprvse.exe`. La correlación temporal (*burst* de comandos de descubrimiento en un mismo `ProcessGuid` padre) convierte comandos individualmente benignos en alertas de severidad alta.

| Acción o comando clásico | Proceso y evento principal | Telemetría específica generada | Señal que alerta al SOC |
| :--- | :--- | :--- | :--- |
| `whoami /all` o `whoami /priv` | `whoami.exe` (Sec `4688`, Sysmon `1`) | Argumentos `/all` o `/priv`; `ParentImage` atípico | Ejecución desde procesos no interactivos (`w3wp.exe`, `sqlservr.exe`) |
| `net user /domain` / `net group` | `net.exe` y `net1.exe` (Sysmon `1`, `3`) | Línea de comandos con `/domain`; consulta LDAP/SMB | Ráfaga de enumeración de cuentas privilegiadas desde una estación |
| `powershell -nop -w hidden -enc ...` | `powershell.exe` (Sysmon `1`, PS `4104`) | Flags de ocultamiento + bloque decodificado en `4104` | Combinación de `-w hidden` / `-enc` y uso de `Net.WebClient` o `IEX` |
| Scripts PowerShell no firmados | `powershell.exe` (PS `4104`, `4103`, AppLocker `8004`) | Ruta en `%TEMP%` o `C:\Users\Public`, estado de firma | Bypass de `ExecutionPolicy` o scripts desde directorios escribibles |
| `ipconfig /all` + `arp -a` + `route print` | Múltiples binarios nativos (Sysmon `1`) | Secuencia rápida bajo el mismo árbol de proceso | Patrón automatizado de reconocimiento inicial post-explotación |

## Uso y abuso de LOLBAS en Windows y GTFOBins en Linux

El término **LOLBAS** (*Living Off the Land Binaries, Scripts and Libraries*) describe binarios, scripts y bibliotecas legítimas, preinstaladas y **firmadas digitalmente por el fabricante del sistema operativo** (Microsoft en Windows) o por software corporativo de confianza, que pueden reutilizarse fuera de su propósito original para descargar archivos, compilar código, evadir restricciones simples de ejecución o lanzar procesos de forma indirecta. En entornos POSIX/Linux, el catálogo equivalente se conoce como **GTFOBins** (o *LoLBins*).

El atractivo conceptual de estas herramientas radica en que no requieren subir binarios propios a disco inicialmente y aprovechan la confianza implícita de reglas de control de aplicaciones mal diseñadas (como permitir todo lo firmado por Microsoft). Sin embargo, desde el punto de vista de OPSEC y defensa moderna, **usar un LOLBin no vuelve invisible a la operación**: al contrario, muchos LOLBins tienen patrones de uso tan anómalos fuera de tareas específicas de administración que generan alertas inmediatas de alta prioridad.

### LOLBAS críticos en Windows y su huella forense

1. **`certutil.exe`**: herramienta administrativa para gestionar certificados, CA y listas de revocación (CRL). Su abuso clásico consiste en descargar archivos remotos o decodificar bloques Base64 en disco.
   - *Huella defensiva*: Sysmon ID `1` con parámetros como `-urlcache`, `-split`, `-f` o `-decode`; Sysmon ID `3` (conexión saliente de red desde `certutil.exe` hacia una IP externa o dominio no PKI); creación de artefactos de caché en `%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content` y `MetaData`; y Event ID `11` (*FileCreate*).
2. **`mshta.exe`**: intérprete legítimo de aplicaciones HTML (`.hta`) que ejecuta JScript o VBScript mediante el motor de Internet Explorer/MSHTML.
   - *Huella defensiva*: hoy prácticamente no existe uso corporativo legítimo de `mshta.exe` conectándose a internet o ejecutándose desde `cmd.exe` / documentos de Office. Deja Sysmon ID `1` con URLs en la línea de comandos o scripts inline (`javascript:` / `vbscript:`), Sysmon ID `3` hacia servidores externos y carga de DLLs de scripting (`jscript.dll`, `vbscript.dll`, Sysmon ID `7`).
3. **`rundll32.exe`**: cargador nativo diseñado para invocar funciones exportadas de DLLs mediante una firma específica (`EntryPoint`).
   - *Huella defensiva*: es un blanco clásico de abuso para proxy execution (por ejemplo, invocando DLLs de JavaScript/COM o bibliotecas propias). El Blue Team monitorea `rundll32.exe` ejecutando DLLs desde rutas de usuario (`AppData`, `Temp`, `ProgramData`), sin argumentos válidos, invocando funciones por ordinal (`#1`) o generando conexiones de red (Sysmon ID `3`) y procesos hijos inesperados.
4. **`regsvr32.exe`**: utilidad para registrar y desregistrar controles COM/DLL en el Registro de Windows. Su abuso conocido como *Squiblydoo* emplea el flag `/i:` apuntando a un scriptlet `.sct` local o remoto junto con `scrobj.dll`.
   - *Huella defensiva*: Sysmon ID `1` combinando `/s /n /u /i:http...` y `scrobj.dll`; Sysmon ID `7` mostrando la carga de `scrobj.dll` y motores de scripting dentro de `regsvr32.exe`; y tráfico HTTP/S saliente originado en un binario de registro del sistema.
5. **`bitsadmin.exe`**: herramienta heredada (reemplazada operativamente por los cmdlets de PowerShell de BITS) para administrar trabajos de transferencia en segundo plano (*Background Intelligent Transfer Service*).
   - *Huella defensiva*: además de Sysmon ID `1` con argumentos `/transfer`, `/create` o `/addfile`, el propio servicio BITS registra eventos dedicados en `Microsoft-Windows-Bits-Client/Operational` (Event ID `3`, `4`, `59`, `60`) con la URL exacta, el archivo destino y el usuario solicitante, además de persistir metadatos en la base `qmgr.db`.
6. **`msbuild.exe`**: motor de compilación de Microsoft Build Engine incluido en .NET Framework. Permite definir tareas inline en C# dentro de archivos `.csproj` o `.xml`, lo que posibilita compilar y ejecutar código en memoria desde un archivo de texto XML sin invocar `csc.exe` directamente de forma visible para reglas simples.
   - *Huella defensiva*: fuera de estaciones de desarrollo o servidores de CI/CD, la ejecución de `msbuild.exe` es altamente sospechosa. Aún más delator es verlo lanzado por un padre no vinculado a Visual Studio (`cmd.exe`, `wmiprvse.exe`, `explorer.exe`) o leyendo archivos XML desde carpetas temporales, sumado a la telemetría de carga de ensamblados .NET (ETW `Microsoft-Windows-DotNETRuntime`).
7. **`forfiles.exe`**: utilidad de línea de comandos para iterar sobre archivos y ejecutar un comando por cada coincidencia. En ejercicios ofensivos suele analizarse como método de ejecución indirecta (*parent-child spoofing* básico o evasión de firmas de cadena simple) para lanzar un segundo binario.
   - *Huella defensiva*: argumentos `/p`, `/m`, `/c` invocando `cmd /c`, `powershell` o `mshta` en rutas del sistema como `C:\Windows\System32` con una máscara fija para forzar una única iteración.

### GTFOBins / LoLBins en Linux y su detección

En sistemas Linux (servidores de aplicaciones, contenedores, nodos Kubernetes o bastiones), la ausencia de binarios adicionales no impide acciones posteriores al acceso inicial si las políticas de `sudoers`, los permisos SUID o las capacidades POSIX están mal configuradas:

- **`curl` y `wget`**: transferencia de artefactos, exfiltración vía POST/headers y sondeo interno (*SSRF* local o enumeración de metadatos cloud). Su ejecución desde cuentas de servicio web (`www-data`, `nginx`) hacia destinos externos genera eventos `execve` en `auditd` y conexiones salientes detectables por `netfilter`/eBPF.
- **`python` / `python3`**: presente en casi toda distribución moderna. Permite abrir sockets, interactuar con APIs o lanzar subshells interactivas (`pty.spawn`) desde una shell restringida.
- **`tar`**: si un usuario tiene permisos `sudo` para ejecutar `tar` (por ejemplo, en un script de respaldo), flags legítimos como `--checkpoint=1 --checkpoint-action=exec=...` permiten ejecutar comandos arbitrarios con el privilegio del proceso `tar`.
- **`awk` y `find`**: herramientas estándar de procesamiento de texto y búsqueda que incorporan primitivas de ejecución (`BEGIN { system(...) }` en `awk`, o `-exec ... \;` en `find`). Si se habilitan en reglas `sudo` sin el parámetro `NOEXEC`, rompen cualquier restricción de shell.

Para el Blue Team en Linux, la defensa no pasa por borrar `tar` o `python3` (lo cual rompería el sistema operativo), sino por:
- Auditar `sudo -l` y agregar la etiqueta `NOEXEC:` en `/etc/sudoers` cuando un operador solo deba leer o empaquetar sin lanzar subprocesos.
- Recolectar eventos `execve` (syscall `59` en x86_64) mediante **`auditd`** o sensores **eBPF** (como Falco o Tetragon), alertando cuando un daemon de red (`nginx`, `postgres`, `java`) genera hijos como `curl`, `python3`, `bash` o `sh`.

| Binario | Plataforma | Uso legítimo | Señal clave de abuso en telemetría |
| :--- | :--- | :--- | :--- |
| `certutil.exe` | Windows | Gestión de certificados y CRL | Flags `-urlcache` / `-decode` + conexión red saliente (Sysmon `1`, `3`) |
| `mshta.exe` | Windows | Ejecución de aplicaciones `.hta` | URL remota o inline script en CLI + carga de `vbscript.dll` / `jscript.dll` |
| `rundll32.exe` | Windows | Invocación de exports en DLL | Ruta DLL en `%TEMP%`/`AppData`, ordinales o conexiones salientes |
| `regsvr32.exe` | Windows | Registro de componentes COM | Flags `/s /n /u /i:` con `scrobj.dll` y URL externa |
| `bitsadmin.exe` | Windows | Transferencias BITS heredadas | Logs `Bits-Client` IDs `3`/`59` con URLs externas no corporativas |
| `msbuild.exe` | Windows | Compilación de proyectos .NET | Ejecución fuera de equipos dev o desde rutas temporales |
| `forfiles.exe` | Windows | Procesamiento por lotes de archivos | Uso de `/c` invocando intérpretes sin iteración real de negocio |
| `tar` / `find` / `awk` | Linux | Archivo, búsqueda y texto | Invocación con `sudo` sin `NOEXEC` usando `-exec` o `--checkpoint-action` |

## Infraestructura C2 moderna: canales, *jitter*, perfiles y redirectores

En una operación de Red Teaming madura, el agente desplegado en el laboratorio nunca se conecta directamente a la IP administrativa del **Team Server** (el servidor central de Comando y Control). Exponer el servidor C2 en primera línea permitiría que un analista bloquee una única IP, analice el certificado TLS del panel administrativo o identifique la huella del framework con escáneres públicos como Shodan o Censys.

Por ese motivo, la infraestructura C2 moderna se diseña en capas:

1. **Redirectores HTTP/S**: servidores intermedios desechables (implementados con Nginx, Apache `mod_rewrite`, Caddy o detrás de redes CDN legítimas en simulaciones autorizadas) que reciben el tráfico del perímetro. Solo reenvían al Team Server las peticiones que cumplen criterios estrictos (ruta URI válida, cabecera personalizada, *User-Agent* esperado o rango de IP del objetivo). Cualquier otro visitante —como un analista haciendo `curl` manual o un *crawler* de sandbox— recibe una redirección a un sitio benigno o un error `404` genérico.
2. **Canales HTTP/S**: se prefiere HTTPS sobre puertos estándar (`443`) para integrarse con el tráfico cifrado corporativo y atravesar proxies salientes. Cuando existe inspección TLS (*SSL Bump*) en el proxy corporativo, el canal queda expuesto a análisis de cabeceras y contenido en capa 7.
3. ***Sleep* y *Jitter***: el agente no mantiene una conexión TCP abierta permanente ni consulta cada `5.000` segundos exactos. Combina un intervalo base (*sleep*, por ejemplo `60` segundos) con un porcentaje de variación aleatoria (*jitter*, por ejemplo `25%`), de modo que cada consulta ocurre en una ventana variable entre `45` y `75` segundos para dificultar reglas ingenuas de periodicidad fija.
4. **Perfiles maleables (*Malleable C2 profiles*)**: definen la "forma" del tráfico HTTP en tránsito. Permiten mapear el identificador de sesión dentro de una cookie estándar, codificar comandos dentro de respuestas JSON o bloques HTML simulando telemetría de un servicio SaaS, y ajustar cabeceras `Server`, `Cache-Control` y `Content-Type` para evitar firmas por defecto de frameworks C2.

### Cómo detecta el Blue Team anomalías padre-hijo y *beaconing*

Incluso con redirectores, HTTPS, *jitter* y perfiles maleables, la combinación de telemetría de endpoint y red deja rastros claros:

- **Anomalías en el árbol de procesos (*parent-child*)**: un navegador (`chrome.exe`, `msedge.exe`) iniciando tráfico HTTPS hacia `443` es normal; `rundll32.exe`, `regsvr32.exe`, `notepad.exe` o `svchost.exe` sin servicio asociado abriendo sockets hacia internet (Sysmon ID `3`) es una anomalía crítica. Asimismo, procesos de ofimática (`winword.exe`, `excel.exe`) generando hijos como `cmd.exe`, `powershell.exe`, `mshta.exe` o `wmic.exe` activan detecciones inmediatas.
- **Análisis estadístico de *beaconing***: aunque el *jitter* rompe el intervalo exacto, las distribuciones de intervalos (`delta_t`) entre un proceso y un mismo dominio externo mantienen una media acotada y un **coeficiente de variación (CV)** relativamente bajo en comparación con la navegación humana, que alterna ráfagas de cientos de peticiones por segundo con largos períodos de inactividad. Herramientas como Zeek + RITA analizan:
  - Histogramas de intervalos `delta_t` y simetría alrededor del *sleep* configurado.
  - Baja entropía en el tamaño de las respuestas HTTP cuando el C2 está en reposo (respuestas vacías o de tamaño casi constante como "no hay tareas").
  - **Huellas TLS (JA3/JA4)** inconsistentes con el `User-Agent` declarado (por ejemplo, declarar ser Chrome en Windows pero presentar una negociación TLS propia de `WinHTTP` o `curl`).
  - Dominios recién registrados, certificados TLS de corta duración con historial nulo en la organización y ausencia de consultas DNS previas coherentes (Sysmon ID `22`).

## Detección y verificación defensiva en laboratorio

En un entorno Purple Team, podés validar la capacidad de detección tanto en red (analizando registros de conexiones salientes para encontrar *beaconing* incluso con *jitter*) como en endpoint (auditando eventos Sysmon).

El siguiente script en **Python** implementa un detector estadístico defensivo de *beaconing*. Procesa marcas de tiempo y tamaños de respuesta simulados de un log de proxy/Zeek, calcula el coeficiente de variación de los intervalos y señala destinos sospechosos:

```python
import statistics
from collections import defaultdict
from datetime import datetime


def analizar_beaconing(registros, min_conexiones=6, cv_umbral=0.35):
    """
    Analiza registros (origen, destino, timestamp_iso, bytes_resp)
    para identificar patrones compatibles con beaconing HTTP/S con jitter.
    """
    agrupado = defaultdict(list)
    for origen, destino, ts, tam in registros:
        agrupado[(origen, destino)].append((datetime.fromisoformat(ts), tam))

    hallazgos = []
    for (origen, destino), eventos in agrupado.items():
        if len(eventos) < min_conexiones:
            continue

        eventos.sort(key=lambda x: x[0])
        deltas = [
            (eventos[i][0] - eventos[i - 1][0]).total_seconds()
            for i in range(1, len(eventos))
        ]
        tamanos = [e[1] for e in eventos]

        media_dt = statistics.mean(deltas)
        if media_dt <= 0:
            continue

        stdev_dt = statistics.pstdev(deltas)
        cv_dt = stdev_dt / media_dt
        stdev_bytes = statistics.pstdev(tamanos)

        # Un CV bajo en deltas indica periodicidad acotada incluso con jitter
        if cv_dt <= cv_umbral:
            hallazgos.append({
                "origen": origen,
                "destino": destino,
                "muestras": len(eventos),
                "sleep_estimado_s": round(media_dt, 2),
                "cv_intervalo": round(cv_dt, 3),
                "desv_bytes": round(stdev_bytes, 2),
            })

    return hallazgos


if __name__ == "__main__":
    # Simulacion controlada de trafico en laboratorio:
    # 10.10.20.15 -> cdn-telemetry-lab.example con ~60s y jitter ~20%
    # 10.10.20.15 -> portal-noticias.example con navegacion humana irregular
    logs_lab = [
        ("10.10.20.15", "cdn-telemetry-lab.example", "2026-11-22T10:00:00", 248),
        ("10.10.20.15", "cdn-telemetry-lab.example", "2026-11-22T10:00:52", 248),
        ("10.10.20.15", "cdn-telemetry-lab.example", "2026-11-22T10:02:01", 252),
        ("10.10.20.15", "cdn-telemetry-lab.example", "2026-11-22T10:02:58", 248),
        ("10.10.20.15", "cdn-telemetry-lab.example", "2026-11-22T10:04:09", 248),
        ("10.10.20.15", "cdn-telemetry-lab.example", "2026-11-22T10:05:03", 250),
        ("10.10.20.15", "portal-noticias.example", "2026-11-22T10:00:05", 14200),
        ("10.10.20.15", "portal-noticias.example", "2026-11-22T10:00:07", 890),
        ("10.10.20.15", "portal-noticias.example", "2026-11-22T10:03:40", 53200),
        ("10.10.20.15", "portal-noticias.example", "2026-11-22T10:03:42", 1200),
        ("10.10.20.15", "portal-noticias.example", "2026-11-22T10:15:10", 4100),
        ("10.10.20.15", "portal-noticias.example", "2026-11-22T10:15:11", 650),
    ]
    for alerta in analizar_beaconing(logs_lab):
        print("[ALERTA BEACONING]", alerta)
```

En el endpoint Windows, podés auditar ejecuciones sospechosas de LOLBAS en tu máquina de laboratorio mediante **PowerShell** consultando el canal de Sysmon y cruzando proceso padre con línea de comandos:

```powershell
# Auditoria defensiva en laboratorio sobre Sysmon Event ID 1 (ultimas 24 horas)
$inicio = (Get-Date).AddHours(-24)
$lolbas = @('certutil.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'bitsadmin.exe', 'msbuild.exe', 'forfiles.exe')

Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = 1
    StartTime = $inicio
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $datos = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $datos[$d.Name] = $d.'#text'
    }
    $img = Split-Path $datos['Image'] -Leaf
    if ($lolbas -contains $img.ToLower()) {
        [PSCustomObject]@{
            Hora        = $_.TimeCreated
            Proceso     = $img
            Padre       = Split-Path $datos['ParentImage'] -Leaf
            Usuario     = $datos['User']
            CommandLine = $datos['CommandLine']
        }
    }
} | Format-Table -AutoSize
```

Para estandarizar esta visibilidad en un SIEM, una regla **Sigma** conceptual para detectar el abuso de `certutil.exe` o `mshta.exe` con tráfico/URLs y padres inusuales se estructura de la siguiente forma:

```yaml
title: Ejecucion Sospechosa de LOLBAS con Indicadores de Descarga o Scripting
status: experimental
description: Detecta argumentos de descarga o ejecucion remota en binarios firmados de Windows.
logsource:
  category: process_creation
  product: windows
detection:
  sel_certutil:
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - 'urlcache'
      - '-decode'
      - 'verifyctl'
  sel_mshta:
    Image|endswith: '\mshta.exe'
    CommandLine|contains:
      - 'http://'
      - 'https://'
      - 'javascript:'
      - 'vbscript:'
  condition: sel_certutil or sel_mshta
level: high
tags:
  - attack.defense_evasion
  - attack.t1218
```

## Práctica guiada en laboratorio

En tu laboratorio aislado (una VM Windows con Sysmon configurado con un esquema comunitario como SwiftOnSecurity o Olaf Hartong, y una VM Linux con `auditd`), ejecutá un ciclo Purple Team controlado:

1. **Verificá la telemetría base de Windows**: habilitá *Command Line Process Auditing* (Directiva de grupo para Event ID `4688`) y *PowerShell Script Block Logging* (Event ID `4104`).
2. **Generá eventos benignos de prueba**: en una consola PowerShell de prueba ejecutá `whoami /all` y un bloque de script inocuo (`Write-Output "Prueba Purple Team"`), y luego ejecutá `certutil.exe -?` y una consulta controlada en `forfiles.exe /p C:\Windows\System32 /m notepad.exe /c "cmd /c echo test_lab"`.
3. **Inspeccioná los logs**: ejecutá el script de auditoría PowerShell visto en el capítulo y confirmá que podés reconstruir `ParentImage`, `CommandLine` y `ScriptBlockText` en el Visor de Eventos.
4. **Probá el detector de *beaconing***: corré el script Python sobre el dataset de laboratorio, modificá el *jitter* simulado entre `5%` y `40%` y observá cómo cambia el coeficiente de variación (`cv_intervalo`).

::: practica Entregable mínimo
Documentá una tabla de validación Purple Team con al menos **4 pruebas** ejecutadas en tu laboratorio (comando benigno de prueba, Event ID capturado en Windows o `auditd` en Linux, campos críticos visibles como `ParentImage` y `CommandLine`, y la regla o consulta exacta con la que el Blue Team lo detectaría). Adjuntá la salida del script Python mostrando cómo varía `cv_intervalo` al incrementar el *jitter*.
:::

::: defensa Perspectiva defensiva y mitigación
La mitigación efectiva frente al abuso de LOLBAS e infraestructura C2 requiere defensa en profundidad: aplicar políticas de **Control de Aplicaciones (WDAC / AppLocker)** que bloqueen explícitamente binarios innecesarios para usuarios estándar (`mshta.exe`, `msbuild.exe` en equipos no dev, `wscript.exe`); habilitar **ASR (Attack Surface Reduction)** para impedir que aplicaciones de Office creen procesos hijos o realicen llamadas ejecutables sospechosas; exigir inspección de salida HTTP/S con análisis de **JA3/JA4** y *beaconing*; activar **PowerShell Constrained Language Mode** junto con `4104`; y en Linux aplicar `NOEXEC` en `sudoers` junto con monitoreo eBPF/`auditd` sobre `execve`.
:::

## Preguntas de repaso

**1. ¿Cuál es la diferencia fundamental entre el éxito de un pentest tradicional y el de una operación de Red Teaming?** Un pentest busca cobertura exhaustiva para inventariar y remediar la mayor cantidad posible de vulnerabilidades en un alcance fijado, mientras que el Red Teaming emula un adversario enfocado en objetivos críticos con sigilo (OPSEC) para medir la capacidad real de detección y respuesta (MTTD/MTTR) del Blue Team.

**2. ¿Por qué codificar un comando de PowerShell en Base64 con `-EncodedCommand` ya no oculta la intención frente a un entorno bien configurado?** Porque el Event ID `4104` (*Script Block Logging*) captura el bloque de código dentro del motor de PowerShell una vez decodificado en memoria antes de su ejecución, dejando el texto plano completo registrado en el log `Microsoft-Windows-PowerShell/Operational`.

**3. ¿Qué diferencia operativa existe en la telemetría entre ejecutar `certutil.exe` para verificar un certificado corporativo y abusarlo para transferir un archivo?** El abuso con fines de descarga deja argumentos específicos en Sysmon ID `1` (`-urlcache`, `-split`, `-f`), una conexión de red saliente anómala en Sysmon ID `3` desde `certutil.exe` hacia dominios no PKI, creación de archivos en disco (ID `11`) y artefactos persistentes en `CryptnetUrlCache`.

**4. ¿Para qué sirven los redirectores y el *jitter* en una arquitectura C2 moderna?** Los redirectores protegen la IP y la identidad del Team Server filtrando peticiones que no corresponden al perfil esperado hacia sitios benignos o errores 404, mientras que el *jitter* introduce variación pseudoaleatoria en el intervalo *sleep* del agente para evitar que los sistemas de monitoreo detecten callbacks con periodicidad matemática exacta.

**5. ¿Cómo puede un analista Blue Team detectar un canal C2 que utiliza HTTPS y *jitter* del 20%?** Correlacionando telemetría de red y endpoint: analizando el coeficiente de variación de los intervalos `delta_t` y la baja variación de tamaños de respuesta HTTP (detección estadística de *beaconing*), revisando discrepancias entre huellas TLS (JA3/JA4) y el `User-Agent` declarado, y verificando mediante Sysmon ID `3` y ID `1` si procesos que no son navegadores o tienen relaciones padre-hijo anómalas están iniciando conexiones externas.

## Antes de avanzar

::: nota Puerta de salida
Antes de pasar al capítulo 6.6 sobre arquitectura interna de AV/EDR y señales de evasión en memoria y kernel, asegurate de poder responder sin dudas:
- Qué eventos de Windows Security (`4688`), PowerShell (`4104`) y Sysmon (`1`, `3`, `7`, `11`, `22`) registran la ejecución de comandos y LOLBAS.
- Cómo distinguir un proceso hijo legítimo de una anomalía padre-hijo en Windows y Linux.
- Por qué la estadística de intervalos y las huellas TLS complementan la detección basada en firmas.
:::

## Referencias y estándares abiertos

- MITRE ATT&CK Framework — Enterprise Tactics & Techniques (`T1059` Command and Scripting Interpreter, `T1218` System Binary Proxy Execution, `T1071` Application Layer Protocol).
- Proyecto **LOLBAS** (*Living Off The Land Binaries, Scripts and Libraries*): catálogo abierto de binarios Windows y reglas de detección asociadas.
- Proyecto **GTFOBins**: lista curada de binarios Unix/Linux y restricciones de `sudoers` / `NOEXEC`.
- Microsoft Learn — *Sysmon (System Monitor)* y *PowerShell Security Logging* (Event IDs `4103` y `4104`).
- SigmaHQ — Repositorio abierto de reglas de detección genéricas para SIEM.
- Active Countermeasures — *RITA (Real Intelligence Threat Analytics)*: documentación abierta sobre detección estadística de *beaconing*.
