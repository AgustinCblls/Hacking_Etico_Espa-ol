::: nota Objetivo de la lección
Dominar la automatización y el análisis operativo con **Bash** en sistemas Linux y **PowerShell** en entornos Windows. Al finalizar vas a poder construir tuberías de filtrado reproducibles, escribir scripts seguros de auditoría de registros, consultar eventos estructurados con `Get-WinEvent` y `Get-CimInstance`, y aplicar controles defensivos sobre la ejecución de scripts.
:::

**Prerrequisitos:** Conocimientos básicos de línea de comandos Linux (Capítulo 1.3) y fundamentos de Windows (Capítulo 1.4). **Duración sugerida:** 3 a 4 horas (incluyendo laboratorio práctico).

## 1. Flujo de datos en Bash: descriptores, redirecciones y tuberías

En entornos Unix y Linux, casi toda la telemetría de seguridad —registros de autenticación, trazas de servicios web, listas de sockets abiertos o volcados de configuración— se representa como **flujos de texto plano**. La potencia de Bash reside en encadenar utilidades pequeñas y especializadas mediante descriptores de archivo y tuberías (`|`), sin necesidad de escribir programas complejos para tareas de triaje diario.

### 1.1 Descriptores estándar y control de salida

Todo proceso en Linux inicia con tres descriptores de archivo abiertos: entrada estándar (`stdin`, descriptor `0`), salida estándar (`stdout`, descriptor `1`) y salida de error estándar (`stderr`, descriptor `2`). Separar los datos útiles (`stdout`) de los avisos o permisos denegados (`stderr`) evita contaminar reportes automatizados o romper tuberías posteriores.

| Operador | Descriptor afectado | Comportamiento técnico | Uso típico en auditoría |
| :--- | :--- | :--- | :--- |
| `>` / `>>` | `1` (`stdout`) | Sobrescribe o agrega al archivo destino | Guardar inventario de puertos o procesos |
| `2>` | `2` (`stderr`) | Redirige solo errores a un archivo o `/dev/null` | Silenciar avisos de `Permission denied` en `find` |
| `2>&1` | `2` → `1` | Fusiona errores en la misma salida estándar | Capturar salida completa de un comando en un log |
| `\|` | `1` → `0` | Conecta la salida de un comando a la entrada del siguiente | Filtrar, ordenar y contar eventos en cadena |
| `tee -a` | `1` → pantalla y archivo | Duplica el flujo hacia un archivo y hacia `stdout` | Conservar evidencia mientras se sigue procesando |

### 1.2 Modo estricto y escritura defensiva de scripts

Un script de auditoría mal escrito puede fallar en silencio, operar sobre rutas vacías o interpretar nombres de archivo con espacios como múltiples argumentos. Al comienzo de cualquier script de producción o laboratorio, definí siempre un encabezado defensivo:

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
```

- `set -e` detiene la ejecución ante cualquier comando con código de salida distinto de `0`.
- `set -u` trata las variables no definidas como un error inmediato, previniendo rutas truncadas como `rm -rf "/tmp/${VAR_VACIA}"`.
- `set -o pipefail` hace que una tubería devuelva error si falla cualquiera de sus etapas, no solo el último comando.
- Comillar siempre las expansiones (`"${archivo}"`) protege contra división de palabras y expansión inesperada de comodines (`*`, `?`).

::: aviso Validación previa de scripts Bash
Antes de ejecutar un script de automatización en un servidor o en tu VM, pasalo por `bash -n script.sh` para comprobar sintaxis y, si tenés `shellcheck` instalado, ejecutá `shellcheck script.sh` para detectar comillas faltantes, redirecciones defectuosas y posibles inyecciones de argumentos.
:::

## 2. Filtrado y transformación de texto para análisis de seguridad

Durante una investigación de incidentes o una revisión de superficie expuesta, raramente vas a leer un archivo de registro línea por línea. Necesitás extraer campos precisos, normalizar formatos y agregar frecuencias en segundos.

### 2.1 Expresiones regulares y búsqueda con `grep`

`grep` filtra líneas que coinciden con un patrón. Usar `-E` activa expresiones regulares extendidas (ERE), evitando escapar metacaracteres como `+`, `?`, `|` o `()`. Conviene conocer los modificadores esenciales: `-i` (insensible a mayúsculas), `-v` (invierte la coincidencia para excluir ruido conocido), `-o` (imprime solo la subcadena coincidente, útil para extraer direcciones IP) y `-n` (muestra el número de línea).

| Herramienta | Especialidad principal | Cuándo elegirla en análisis de seguridad |
| :--- | :--- | :--- |
| `grep -E` | Filtrado rápido por patrón | Aislar fallos de autenticación, códigos HTTP `4xx`/`5xx` o IOCs |
| `cut` | Corte por delimitador simple o posición | Extraer columnas fijas en archivos CSV o `/etc/passwd` |
| `awk` | Procesamiento por columnas, condiciones y sumatorias | Correlacionar campos variables, filtrar por umbral y formatear tablas |
| `sed` | Sustitución y edición en flujo | Sanitizar direcciones IP, limpiar encabezados o extraer rangos de líneas |
| `sort \| uniq -c` | Ordenamiento y conteo de frecuencias | Identificar los orígenes más ruidosos o rutas más solicitadas |

### 2.2 Extracción estructurada con `awk`, `sed`, `sort` y `uniq`

Mientras `cut` falla cuando los campos están separados por múltiples espacios consecutivos, `awk` divide automáticamente por secuencias de espacios en blanco (`$1`, `$2`, ..., `$NF` para el último campo) y permite lógica condicional en una sola pasada:

```bash
# Extraer direcciones IP con fallos SSH en auth.log y listar el Top 5
grep -E "Failed password for" /var/log/auth.log \
  | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
  | sort | uniq -c | sort -rn | head -n 5

# Contar respuestas HTTP 401/403/404 por IP en un access.log en formato Combined
awk '$9 ~ /^(401|403|404)$/ { conteo[$1]++ }
     END { for (ip in conteo) if (conteo[ip] >= 10) printf "%6d  %s\n", conteo[ip], ip }' \
  /var/log/nginx/access.log | sort -rn

# Anonimizar los últimos dos octetos de direcciones IPv4 antes de compartir evidencia
sed -E 's/([0-9]{1,3}\.[0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}/\1.x.x/g' muestra_log.txt
```

Observá que en el segundo ejemplo `awk` realiza el filtrado, la agrupación y el corte por umbral (`>= 10`) en memoria sin necesidad de abrir subprocesos intermedios de `grep`, `sort` y `uniq`, lo que marca una diferencia notable en archivos de cientos de megabytes.

## 3. Estructuras de control y scripts defensivos en Bash

Cuando un análisis deja de ser puntual y necesita repetirse de forma periódica (por ejemplo, una comprobación diaria de línea base en servidores del laboratorio), conviene empaquetarlo en un script modular con funciones, verificación de argumentos y salida determinista.

### 3.1 Bucles seguros y lectura línea por línea

Para iterar sobre líneas de un archivo o resultados de búsqueda sin corromper espacios ni caracteres especiales, evitá el antipatrón `for linea in $(cat archivo)`. Usá siempre `while IFS= read -r linea`:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Script defensivo de línea base local: sockets en escucha y fallos SSH recientes
REPORTE="/tmp/auditoria_local_$(date +%Y%m%d_%H%M%S).txt"
LOG_AUTH="${1:-/var/log/auth.log}"
UMBRAL="${2:-5}"

verificar_archivo() {
  local ruta="$1"
  if [[ ! -r "${ruta}" ]]; then
    echo "[ERROR] No se puede leer el archivo: ${ruta}" >&2
    exit 1
  fi
}

verificar_archivo "${LOG_AUTH}"

{
  echo "=== Auditoría rápida de host ($(hostname)) - $(date -u +%FT%TZ) ==="
  echo
  echo "[1] Puertos TCP/UDP en escucha (ss -tuln):"
  ss -tuln | awk 'NR==1 || /LISTEN|UNCONN/ { printf "%-6s %-24s %s\n", $1, $5, $2 }'
  echo
  echo "[2] IPs con >= ${UMBRAL} fallos de contraseña en ${LOG_AUTH}:"
  awk -v lim="${UMBRAL}" '
    /Failed password for/ {
      for (i = 1; i <= NF; i++) {
        if ($i == "from" && (i + 1) <= NF) { cuentas[$(i+1)]++ }
      }
    }
    END {
      encontrados = 0
      for (ip in cuentas) {
        if (cuentas[ip] >= lim) {
          printf "  ALERTA  %-18s intentos=%d\n", ip, cuentas[ip]
          encontrados++
        }
      }
      if (encontrados == 0) print "  Sin orígenes por encima del umbral."
    }
  ' "${LOG_AUTH}"
} | tee "${REPORTE}"

echo "Reporte guardado en: ${REPORTE}"
```

Este patrón encapsula el bloque completo entre llaves `{ ... } | tee "${REPORTE}"` para escribir la evidencia una sola vez, usa variables locales (`local`) dentro de funciones y pasa el umbral a `awk` de forma segura con `-v lim="${UMBRAL}"` en lugar de interpolar variables sin sanitizar dentro del código de `awk`.

## 4. PowerShell moderno: arquitectura orientada a objetos

A diferencia de Bash, donde cada herramienta debe volver a interpretar texto plano según separadores o posiciones de columna, **PowerShell** (tanto Windows PowerShell 5.1 como PowerShell 7+ multiplataforma) transporta **objetos .NET tipados** a través de la tubería. Cada objeto conserva sus propiedades y métodos originales hasta el instante en que se renderiza en consola o se serializa a JSON o CSV.

### 4.1 Comparativa operativa: Bash frente a PowerShell

| Capacidad | Enfoque en Bash (Linux) | Enfoque en PowerShell (Windows / Multiplataforma) |
| :--- | :--- | :--- |
| Unidad de pipeline | Líneas de texto plano | Objetos .NET con propiedades tipadas |
| Nomenclatura | Comandos breves (`ps`, `ss`, `grep`) | Convención `Verbo-Sustantivo` (`Get-Process`, `Get-NetTCPConnection`) |
| Filtrado | `grep`, `awk` | `Where-Object` (alias `?`) |
| Selección de campos | `cut`, `awk '{print $1,$5}'` | `Select-Object` (alias `select`) |
| Agrupación y conteo | `sort \| uniq -c` | `Group-Object` (alias `group`) |
| Descubrimiento de esquema | `man comando` | `Get-Help`, `Get-Command`, `Get-Member` |

Cuando trabajes con un cmdlet nuevo en PowerShell, enviá un único elemento a `Get-Member` (por ejemplo, `Get-Process | Select-Object -First 1 | Get-Member`) para inspeccionar los nombres exactos y tipos de datos de todas sus propiedades antes de construir filtros.

### 4.2 Filtrado, proyección y agrupación en el pipeline

En análisis de seguridad sobre Windows, la combinación de `Where-Object`, `Select-Object`, `Group-Object` y `Sort-Object` permite auditar procesos activos, conexiones de red y servicios sin depender de expresiones regulares frágiles:

```powershell
# Listar conexiones TCP establecidas agrupadas por proceso propietario
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
    @{ Name = 'Proceso'; Expression = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } } |
  Sort-Object Proceso, RemotePort |
  Format-Table -AutoSize

# Detectar procesos en ejecución desde rutas de usuario (AppData o Temp) para revisión de triaje
Get-CimInstance Win32_Process |
  Where-Object { $_.ExecutablePath -match '\\(AppData|Temp)\\' } |
  Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
  Export-Csv -Path ".\procesos_rutas_usuario.csv" -NoTypeInformation -Encoding UTF8
```

El uso de propiedades calculadas (`@{ Name = '...'; Expression = { ... } }`) enriquece el objeto original al vuelo y facilita la exportación directa a CSV o JSON (`ConvertTo-Json -Depth 4`) para su ingestión en herramientas de análisis posteriores.

## 5. Análisis de eventos, CIM/WMI y gobierno de ejecución en Windows

### 5.1 Consulta eficiente de registros con `Get-WinEvent`

El cmdlet heredado `Get-EventLog` solo lee los canales clásicos y está deprecado en PowerShell moderno. `Get-WinEvent` accede tanto a los registros clásicos (`Security`, `System`, `Application`) como a los canales modernos de aplicaciones y servicios (por ejemplo, `Microsoft-Windows-PowerShell/Operational`).

La regla de rendimiento fundamental es **filtrar a la izquierda**: pasá `-FilterHashtable` al motor de eventos de Windows para que descarte registros antes de instanciar objetos en memoria, en lugar de traer decenas de miles de eventos y filtrarlos tarde con `Where-Object`:

```powershell
# Consultar eventos recientes de inicio de sesión fallido en el registro Security (requiere elevación)
$inicio = (Get-Date).AddHours(-24)

$eventos = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $inicio
} -ErrorAction SilentlyContinue

$eventos | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $datos = @{}
    foreach ($nodo in $xml.Event.EventData.Data) {
        $datos[$nodo.Name] = $nodo.'#text'
    }
    [PSCustomObject]@{
        Fecha       = $_.TimeCreated.ToString('s')
        Usuario     = $datos['TargetUserName']
        Dominio     = $datos['TargetDomainName']
        IpOrigen    = $datos['IpAddress']
        TipoLogon   = $datos['LogonType']
        EstadoHex   = $datos['Status']
    }
} | Group-Object IpOrigen, Usuario | Sort-Object Count -Descending | Format-Table Count, Name -AutoSize
```

Parsear la estructura XML interna (`$_.ToXml()`) con `[xml]` evita depender del idioma del sistema operativo en la cadena `Message` (español vs. inglés), garantizando que el script funcione de manera idéntica en cualquier Windows.

### 5.2 Inventario con CIM/WMI y políticas de ejecución

**CIM (Common Information Model)** mediante `Get-CimInstance` reemplaza al antiguo `Get-WmiObject`: usa protocolos estándar sobre WS-Man/WinRM en lugar de DCOM/RPC heredado y devuelve objetos más livianos. Permite inventariar hardware, servicios (`Win32_Service`), tareas programadas, cuentas locales (`Win32_UserAccount`) y parches instalados (`Win32_QuickFixEngineering`).

Respecto a las **políticas de ejecución** (`Get-ExecutionPolicy -List`), conviene aclarar un error muy extendido: la `ExecutionPolicy` (`Restricted`, `AllSigned`, `RemoteSigned`, `Bypass`) es una **red de seguridad operativa** para evitar la ejecución accidental de scripts no revisados, **no un límite de seguridad hermético**, ya que un usuario con acceso a la consola puede ejecutar código desde entrada estándar o especificar parámetros por sesión. El control real se logra combinando firma digital de scripts, **Constrained Language Mode (CLM)** junto con **AppLocker / Windows Defender Application Control (WDAC)**, y telemetría reforzada (**Script Block Logging** y **Module Logging**).

## Ejemplo paso a paso: Triaje cruzado de registros en laboratorio local

En este recorrido vas a generar un pequeño archivo de registro sintético en Linux y ejecutar sobre él una tubería de agregación, para luego replicar el mismo enfoque sobre un inventario local en PowerShell.

**Paso 1 (Linux / WSL / VM):** creá un archivo de muestra en `/tmp/auth_lab.log` y extraé las IPs sospechosas ordenadas por volumen:

```bash
cat <<'EOF' > /tmp/auth_lab.log
Nov 22 10:01:12 lab-srv sshd[2104]: Failed password for invalid user admin from 192.168.56.20 port 51422 ssh2
Nov 22 10:01:14 lab-srv sshd[2104]: Failed password for invalid user admin from 192.168.56.20 port 51423 ssh2
Nov 22 10:01:16 lab-srv sshd[2104]: Failed password for root from 192.168.56.20 port 51424 ssh2
Nov 22 10:02:01 lab-srv sshd[2118]: Accepted publickey for analyst from 192.168.56.1 port 53001 ssh2
Nov 22 10:03:09 lab-srv sshd[2130]: Failed password for operator from 10.10.0.15 port 49811 ssh2
EOF

awk '/Failed password/ {
  for (i=1; i<=NF; i++) if ($i=="from") ip=$(i+1)
  fallos[ip]++
}
END {
  for (ip in fallos) printf "%-16s %d fallos\n", ip, fallos[ip]
}' /tmp/auth_lab.log | sort -k2 -rn
```

Salida esperada comentada:

```text
192.168.56.20    3 fallos   # Agrupa intentos sobre usuarios válidos e inexistentes
10.10.0.15       1 fallos   # Evento aislado; útil para comparar contra umbral definido
```

**Paso 2 (Windows PowerShell):** verificá el estado de seguridad de los servicios en ejecución automática que corren fuera de `C:\Windows\System32` y las políticas activas de ejecución:

```powershell
Get-ExecutionPolicy -List

Get-CimInstance Win32_Service |
  Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -notmatch 'C:\\Windows\\system32' } |
  Select-Object Name, State, StartName, PathName |
  Format-Table -AutoSize
```

Salida esperada comentada:

```text
        Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
   UserPolicy       Undefined
      Process       Undefined
  CurrentUser    RemoteSigned   # Requiere firma solo para scripts descargados de Internet
 LocalMachine       Undefined

Name        State   StartName     PathName
----        -----   ---------     --------
OpenSSHd    Running LocalSystem   "C:\Program Files\OpenSSH\sshd.exe"  # Ruta entrecomillada correctamente
```

Comprobá siempre si `PathName` contiene espacios sin comillas en servicios que ejecutan con privilegios elevados (`LocalSystem`), ya que constituye un patrón clásico de mala configuración en inventarios Windows.

::: defensa Perspectiva defensiva y mitigación
Tanto Bash como PowerShell son herramientas administrativas legítimas que también resultan atractivas para actores maliciosos porque ya vienen instaladas en el sistema (*living off the land*). Para reducir su abuso sin frenar la operación:
- **Auditoría de comandos en Linux:** habilitá reglas de `auditd` para ejecuciones privilegiadas y protegé el historial con archivos inmutables o envío inmediato a un colector centralizado (`rsyslog` / `journald`).
- **Telemetría de PowerShell en Windows:** activá **Script Block Logging** (canal `Microsoft-Windows-PowerShell/Operational`), **Module Logging** y **Transcription** mediante GPO, y deshabilitá el motor heredado PowerShell v2 (`Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`) para evitar degradaciones sin registro.
- **Restricción de ejecución:** combiná **WDAC / AppLocker** con **Constrained Language Mode** en estaciones de trabajo de usuarios finales y exigí firma de código (`AllSigned`) para scripts de automatización compartidos.
- **Higiene de scripts propios:** nunca incrustes contraseñas en texto plano en archivos `.sh` o `.ps1`; usá variables de entorno protegidas, permisos `chmod 600` o el almacén seguro de credenciales del sistema.
:::

## Práctica en laboratorio local

Realizá esta práctica en tu máquina virtual Linux y tu estación o VM Windows aislada:

1. En Linux, escribí un script llamado `resumen_sistema.sh` con `set -euo pipefail` que reciba como parámetro la ruta de un archivo de log de autenticación, valide su existencia y genere un reporte con: fecha UTC, lista de usuarios con shell interactiva en `/etc/passwd` (excluyendo `nologin` y `false`), puertos TCP en escucha y ranking de IPs con más de 3 intentos fallidos.
2. En Windows PowerShell, escribí un script llamado `Auditoria-HostLocal.ps1` que consulte con `Get-CimInstance` los últimos 5 parches instalados (`Win32_QuickFixEngineering`), liste las conexiones TCP activas en estado `Listen` junto al nombre del proceso propietario y exporte los resultados a un archivo JSON estructurado con `ConvertTo-Json`.
3. Probá ambos scripts validando el manejo de errores (por ejemplo, pasarle una ruta inexistente a `resumen_sistema.sh` y verificar que retorne un código de salida distinto de `0`).

::: practica Entregable mínimo
Dos scripts funcionales y comentados (`resumen_sistema.sh` y `Auditoria-HostLocal.ps1`), la salida de `bash -n resumen_sistema.sh` sin errores y el archivo JSON generado por PowerShell en tu entorno local.
:::

## Preguntas de repaso

**1. ¿Por qué conviene incluir `set -euo pipefail` al inicio de un script de auditoría en Bash?** Porque fuerza al script a fallar rápido y de manera visible: `-e` detiene la ejecución si un comando retorna error, `-u` impide expandir variables no declaradas (evitando rutas vacías peligrosas) y `-o pipefail` asegura que un fallo en etapas intermedias de una tubería no quede oculto por el código de salida `0` del último comando.

**2. ¿Cuál es la diferencia técnica más relevante entre `awk` y `cut` al analizar logs del sistema?** `cut` solo divide líneas usando un delimitador de un único carácter o posiciones fijas de bytes, por lo que falla cuando los campos están alineados con cantidades variables de espacios. `awk` trata secuencias de espacios y tabulaciones como un único separador por defecto, soporta condicionales, arreglos asociativos para contar frecuencias y formateo estructurado en una sola lectura del archivo.

**3. ¿En qué se diferencia fundamentalmente el pipeline de PowerShell del pipeline de Bash?** En Bash los comandos intercambian flujos de texto plano que cada herramienta debe volver a analizar. En PowerShell el pipeline transfiere objetos .NET con propiedades y métodos tipados, lo que permite filtrar (`Where-Object`), proyectar (`Select-Object`) y agrupar (`Group-Object`) directamente por atributo sin depender del formato visual de columnas ni del idioma de salida.

**4. ¿Por qué `Get-WinEvent -FilterHashtable` es preferible a `Get-WinEvent | Where-Object` en investigaciones defensivas?** Porque `-FilterHashtable` delega el filtrado al motor de eventos de Windows antes de construir objetos .NET en PowerShell. Esto reduce drásticamente el consumo de CPU, memoria y tiempo de respuesta cuando se consultan registros voluminosos como `Security` o `Microsoft-Windows-PowerShell/Operational`.

**5. ¿Alcanza configurar `ExecutionPolicy` en `Restricted` para impedir la ejecución maliciosa de código PowerShell?** No. La `ExecutionPolicy` es una medida preventiva contra ejecuciones accidentales, no una frontera de seguridad estricta, ya que puede eludirse pasando comandos codificados o ejecutando bloques por entrada estándar. La mitigación real requiere control de aplicaciones (WDAC/AppLocker), Constrained Language Mode, deshabilitar PowerShell v2 y habilitar Script Block Logging.

## Antes de avanzar

- [ ] Podés redirigir `stdout` y `stderr` de forma independiente y explicar el efecto de `2>&1` y `pipefail`.
- [ ] Sabés construir una tubería con `grep`, `awk`, `sort` y `uniq` para resumir intentos de autenticación en un archivo de log.
- [ ] Entendés cómo inspeccionar propiedades de objetos PowerShell con `Get-Member` y filtrar eventos con `Get-WinEvent -FilterHashtable`.
- [ ] Comprendés la diferencia entre `Get-CimInstance` y el antiguo WMI, así como las limitaciones reales de `ExecutionPolicy`.

::: nota Puerta de salida
Antes de pasar al Capítulo 1.6, asegurate de haber ejecutado y verificado tus dos scripts de triaje (`resumen_sistema.sh` y `Auditoria-HostLocal.ps1`) en tu laboratorio local. Esa base te va a permitir decidir cuándo alcanza una tubería de shell y cuándo conviene dar el salto a Python 3 para lógica de red o correlación más compleja.
:::

## Referencias y estándares abiertos

- GNU Project — *Bash Reference Manual* (redirecciones, shell parameters y modo estricto): https://www.gnu.org/software/bash/manual/
- IEEE / The Open Group — *POSIX.1-2017 Shell Command Language y utilidades `awk`, `sed`, `grep`*: https://pubs.opengroup.org/onlinepubs/9699919799/
- Microsoft Learn — *PowerShell Documentation: About Pipelines, Get-WinEvent y About Execution Policies*: https://learn.microsoft.com/en-us/powershell/
- Microsoft Learn — *PowerShell Security Features (Script Block Logging y Constrained Language Mode)*: https://learn.microsoft.com/en-us/powershell/scripting/security/
- NIST SP 800-92 — *Guide to Computer Security Log Management*: https://csrc.nist.gov/publications/detail/sp/800-92/final
