::: nota Objetivo de la lección
Al finalizar este capítulo vas a comprender cómo Windows separa privilegios entre modo usuario y modo kernel, cómo evalúa permisos mediante SIDs, tokens y listas de control de acceso (ACLs) en NTFS, dónde se concentran los vectores de configuración y persistencia en el Registro, servicios y tareas programadas, y cómo auditar el estado vivo de una estación Windows con comandos nativos, WMI/CIM y Sysinternals.
:::

**Prerrequisitos:** Manejo básico de consola y conceptos de sistemas operativos (Capítulos 1.1 a 1.3), más una VM Windows 10/11 o Server aislada en red Host-Only. **Duración sugerida:** 2 horas y media.

## Arquitectura de Windows: modos, sesiones, SIDs y tokens de acceso

El diseño de seguridad de Windows NT se apoya en dos planos protegidos por hardware (anillos x86-64): **modo usuario** (Ring 3), donde corren aplicaciones y servicios, y **modo kernel** (Ring 0), donde operan `ntoskrnl.exe`, el HAL y los controladores. Ningún proceso de usuario puede leer memoria del kernel ni tocar el hardware directamente; debe invocar llamadas al sistema mediante `ntdll.dll`. Desde Windows Vista rige además el **aislamiento de Sesión 0**: todos los servicios corren en la Sesión 0 sin escritorio interactivo, mientras las sesiones humanas comienzan en la Sesión 1, bloqueando inyecciones clásicas de mensajes entre ventanas (*shatter attacks*).

### SIDs, cuentas integradas y anatomía del token

Windows identifica cada entidad de seguridad mediante un **Security Identifier (SID)** inmutable con formato `S-1-5-21-<dominio>-<RID>`. Al iniciar sesión vía LSASS (`lsass.exe`), se crea un **token de acceso** heredado por cada proceso hijo que almacena: SID del usuario, SIDs de grupos, lista de **privilegios** (`SeImpersonatePrivilege`, `SeDebugPrivilege`, `SeBackupPrivilege`) y el **Nivel de Integridad** (*Mandatory Integrity Control*, MIC: Untrusted, Low, Medium, High o System). Con **UAC** activo, un miembro de `Administrators` recibe un token filtrado *Medium* hasta aprobar una elevación explícita a *High*.

| Cuenta o entidad | SID característico | Identidad en red | Privilegio local y exposición |
| --- | --- | --- | --- |
| `NT AUTHORITY\SYSTEM` | `S-1-5-18` | Cuenta de equipo (`EQUIPO$`) | Control total local; equivalente a `root` en Linux. |
| `NT AUTHORITY\LocalService` | `S-1-5-19` | Sesión anónima | Privilegios locales mínimos; pensado para servicios aislados. |
| `NT AUTHORITY\NetworkService` | `S-1-5-20` | Cuenta de equipo (`EQUIPO$`) | Privilegios locales mínimos, pero autentica en red como el host. |
| Administrador integrado | `S-1-5-21-...-500` | Usuario local / dominio | Control administrativo total; RID fijo `500`. |
| Usuario estándar | `S-1-5-21-...-1001+` | Usuario local / dominio | Integridad *Medium*; sin escritura en `C:\Windows`. |

Para inspeccionar tu token activo en CMD o PowerShell, ejecutá `whoami /all`:

```text
C:\Users\auditor> whoami /all
USER INFORMATION
User Name       SID
lab-win\auditor S-1-5-21-3819201411-942108732-119402819-1002

GROUP INFORMATION
Group Name                             Type  SID          Attributes
BUILTIN\Users                          Alias S-1-5-32-545 Mandatory group, Enabled
Mandatory Label\Medium Mandatory Level Label S-1-16-8192  ... # Integridad Medium (sin UAC elevado)

PRIVILEGES INFORMATION
Privilege Name                Description                     State
SeShutdownPrivilege           Shut down the system            Disabled
SeChangeNotifyPrivilege       Bypass traverse checking        Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set  Disabled
```

::: aviso Privilegios peligrosos en cuentas de servicio
Si detectás `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeDebugPrivilege` o `SeBackupPrivilege` en un token de servicio (incluso en estado `Disabled`, porque el proceso puede habilitarlos con `AdjustTokenPrivileges`), tenés un hallazgo de alta prioridad: permiten escalar hacia `SYSTEM` o leer colmenas protegidas del sistema.
:::

## Sistema de archivos NTFS y control de acceso (ACLs)

A diferencia del esquema POSIX `rwx`, NTFS asigna a cada archivo y carpeta un **Descriptor de Seguridad** con propietario (*Owner*), una **DACL** (*Discretionary Access Control List*, qué SIDs pueden acceder y con qué permisos) y una **SACL** (*System Access Control List*, qué eventos se auditan). Cada lista agrupa entradas **ACE** (*Access Control Entry*). El Monitor de Referencia de Seguridad (SRM, en kernel) evalúa la DACL de arriba hacia abajo: cualquier **Deny explícito** prevalece sobre un **Allow**, y si ninguna ACE coincide con el token, el acceso se deniega por defecto.

### Inspección práctica con icacls y PowerShell

NTFS soporta además flujos alternativos de datos (**ADS**, visibles con `dir /R` o `Get-Item -Stream *`), como `Zone.Identifier` para marcar archivos descargados de internet. Sin embargo, el vector más habitual en auditoría local son permisos NTFS demasiado permisivos sobre carpetas de aplicaciones o binarios de servicios.

| Código `icacls` | Significado técnico | Impacto en seguridad |
| --- | --- | --- |
| `F` | Control total (*Full Control*) | Permite modificar, borrar y alterar permisos o propietario. |
| `M` | Modificar (*Modify*) | Permite sobrescribir binarios o scripts ejecutados por terceros. |
| `RX` | Lectura y ejecución (*Read & Execute*) | Permiso seguro estándar para ejecutables en `Program Files`. |
| `W` | Escritura (*Write*) | Permite crear archivos en la carpeta (riesgo de *DLL hijacking*). |
| `(OI)(CI)` | *Object Inherit* / *Container Inherit* | Propaga la ACE a archivos y subcarpetas hijas. |
| `(I)` | Permiso heredado | Indica herencia activa desde el directorio padre. |

```powershell
# Revisar ACLs de una carpeta de aplicación
icacls "C:\Program Files\LabApp"
# Salida comentada:
# C:\Program Files\LabApp NT AUTHORITY\SYSTEM:(OI)(CI)(F)
#                         BUILTIN\Administrators:(OI)(CI)(F)
#                         BUILTIN\Users:(OI)(CI)(RX)        # Seguro: solo lectura/ejecución
#                         BUILTIN\Authenticated Users:(M)   # HALLAZGO: escritura para cualquier usuario

# Buscar archivos escribibles por Users o Everyone en un árbol
Get-ChildItem "C:\Program Files\LabApp" -Recurse | ForEach-Object {
    (Get-Acl $_.FullName).Access | Where-Object {
        $_.IdentityReference -match "Users|Everyone" -and $_.FileSystemRights -match "Write|Modify|FullControl"
    } | Select-Object @{N='Ruta';E={$_.PSPath}}, IdentityReference, FileSystemRights
}
```

## El Registro de Windows como mapa de configuración y persistencia

El **Registro** es una base de datos jerárquica que centraliza parámetros del kernel, controladores, políticas, servicios y perfiles de usuario. Presenta cinco colmenas raíz (*hives*), de las cuales solo `HKLM` y `HKU` corresponden a almacenamiento físico directo; el resto son enlaces simbólicos dinámicos.

| Colmena raíz | Alcance | Archivo físico en disco (`C:\Windows\System32\config\` o perfil) |
| --- | --- | --- |
| `HKEY_LOCAL_MACHINE` (`HKLM`) | Configuración global del host | `SAM`, `SECURITY`, `SOFTWARE`, `SYSTEM` |
| `HKEY_USERS` (`HKU`) | Perfiles cargados por SID | `NTUSER.DAT` y `UsrClass.dat` por usuario |
| `HKEY_CURRENT_USER` (`HKCU`) | Enlace a `HKU\<SID_actual>` | `%USERPROFILE%\NTUSER.DAT` |
| `HKEY_CLASSES_ROOT` (`HKCR`) | Asociaciones y objetos COM | Fusión de `HKLM\SOFTWARE\Classes` y `HKCU\SOFTWARE\Classes` |
| `HKEY_CURRENT_CONFIG` (`HKCC`) | Perfil de hardware activo | Enlace a `HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current` |

### Claves críticas: Run, RunOnce y Services

En auditorías de configuración y análisis de persistencia, tres ramas requieren inspección sistemática:

- **Inicio por usuario (sin elevación):** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` y `RunOnce`.
- **Inicio global (requiere privilegios administrativos):** `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce` y su rama de 32 bits bajo `WOW6432Node`.
- **Servicios y drivers:** `HKLM\SYSTEM\CurrentControlSet\Services\<Servicio>`, cuyos valores clave son `ImagePath` (ruta del ejecutable), `ObjectName` (cuenta de ejecución) y `Start` (`2` = automático, `3` = manual, `4` = deshabilitado).

```powershell
# Consultar entradas de inicio automático globales y del usuario actual
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Leer configuración de un servicio directamente desde el Registro
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" |
    Select-Object DisplayName, ImagePath, ObjectName, Start
```

## Servicios, tareas programadas, WMI/CIM y Sysinternals

El **Service Control Manager (`services.exe`)** controla el ciclo de vida de los servicios. Dos fallos frecuentes en software de terceros son permisos NTFS débiles sobre el ejecutable en `ImagePath` y **rutas sin comillas con espacios** (*Unquoted Service Paths*) fuera de `C:\Windows`, que llevan a Windows a probar rutas intermedias en orden. Las **Tareas Programadas** guardan sus definiciones XML en `C:\Windows\System32\Tasks` y ejecutan scripts o binarios por horario o evento, a menudo como `SYSTEM`.

### Inspección con sc, Get-Service, schtasks y CIM

Para enumerar el sistema sin depender del deprecado `wmic`, utilizá `sc.exe`, `Get-Service`, `schtasks` y los cmdlets **CIM** (`Get-CimInstance`), que consultan el espacio de nombres `root\cimv2` sobre el estándar WS-Man.

```powershell
# Estado rápido y configuración detallada de un servicio
Get-Service -Name wuauserv | Format-List Name, Status, StartType
sc.exe qc wuauserv

# Servicios no nativos con ruta, cuenta y estado vía WMI/CIM
Get-CimInstance -ClassName Win32_Service |
    Where-Object { $_.PathName -and $_.PathName -notmatch '^"?C:\\Windows\\' } |
    Select-Object Name, StartMode, State, StartName, PathName | Format-Table -AutoSize

# Tareas programadas en CMD y filtradas en PowerShell
schtasks /query /fo TABLE /nh
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled" } |
    Select-Object TaskName, TaskPath, @{N='Usuario';E={$_.Principal.UserId}}
```

### CMD esencial y suite Sysinternals para visibilidad en vivo

Comandos nativos como `systeminfo`, `net user`, `net localgroup Administrators`, `tasklist /svc` y `netstat -ano` brindan contexto inmediato. La suite oficial **Microsoft Sysinternals** profundiza esa visibilidad en tiempo real y reduce falsos positivos mediante verificación de firmas digitales.

| Herramienta Sysinternals | Equivalente nativo | Aporte concreto en auditoría de seguridad |
| --- | --- | --- |
| **Process Explorer** (`procexp64.exe`) | `tasklist /svc` | Árbol padre-hijo, argumentos, DLLs cargadas, verificación de firma y pestaña *Security* con tokens/privilegios. |
| **Autoruns** (`autoruns64.exe`) | `reg query` + `schtasks` + `sc` | Inventario unificado de más de 100 ubicaciones de inicio (Run, servicios, tareas, WMI) filtrando entradas firmadas por Microsoft. |
| **TCPView** (`tcpview64.exe`) | `netstat -anob` | Mapa vivo de sockets TCP/UDP locales y remotos vinculados al PID y ruta exacta del ejecutable. |
| **AccessChk** (`accesschk64.exe`) | `icacls` + `sc sdshow` | Evalúa permisos efectivos sobre archivos, claves del Registro y servicios para un usuario o grupo específico. |

## Ejemplo paso a paso: auditoría de superficie local en una VM Windows aislada

Supongamos que auditás una estación Windows 11 en tu laboratorio local (`127.0.0.1` / VM Host-Only) donde corre un servicio interno llamado `LabMonitorSvc`. Seguí esta secuencia reproducible:

**Paso 1 — Verificar contexto de identidad y puertos abiertos:**
```powershell
whoami /groups | findstr /I "Administrators Users Mandatory"
netstat -ano | findstr "LISTENING"
# BUILTIN\Users                          Alias  S-1-5-32-545  Mandatory group, Enabled
# Mandatory Label\Medium Mandatory Level Label  S-1-16-8192   # Sesión sin elevación UAC
#   TCP    127.0.0.1:8443         0.0.0.0:0              LISTENING       4120
```

**Paso 2 — Correlacionar el PID `4120` con su servicio vía CIM:**
```powershell
Get-CimInstance Win32_Service -Filter "ProcessId = 4120" |
    Select-Object Name, DisplayName, StartName, PathName
# Name      : LabMonitorSvc
# StartName : LocalSystem                                      # Privilegios máximos (SYSTEM)
# PathName  : C:\LabTools\Monitor App\agent.exe --port 8443    # Ruta con espacio sin comillas
```

**Paso 3 — Auditar permisos NTFS del ejecutable y su directorio:**
```powershell
icacls "C:\LabTools\Monitor App\agent.exe"
# C:\LabTools\Monitor App\agent.exe NT AUTHORITY\SYSTEM:(I)(F)
#                                   BUILTIN\Administrators:(I)(F)
#                                   BUILTIN\Users:(I)(M)   # RIESGO CRÍTICO: sobrescribible por usuario estándar
```

**Paso 4 — Corroborar persistencia y comportamiento con Sysinternals:**
Abrís `autoruns64.exe`, activás *Options → Hide Microsoft Entries* y confirmás que `LabMonitorSvc` figura sin firma digital verificada. En `tcpview64.exe` comprobás que `agent.exe` escucha solo en `127.0.0.1:8443`, y en `procexp64.exe` validás que su token pertenece a `NT AUTHORITY\SYSTEM`. El hallazgo queda documentado con evidencia verificable: binario no firmado, ruta sin comillas, permiso `M` para `BUILTIN\Users` y cuenta excesivamente privilegiada.

::: defensa Perspectiva defensiva y mitigación
Aplicá controles complementarios sobre cada capa revisada:
1. **Mínimo privilegio en servicios:** ejecutá servicios de terceros con cuentas dedicadas sin privilegios administrativos o `NT AUTHORITY\LocalService`, reservando `SYSTEM` solo para componentes esenciales del SO.
2. **Endurecimiento de ACLs NTFS:** instalá ejecutables de servicios bajo `C:\Program Files`, cortá herencias inseguras (`icacls <ruta> /inheritance:r`), limitá `BUILTIN\Users` a `RX` (nunca `W`, `M` ni `F`) y encerrá `ImagePath` entre comillas dobles si contiene espacios.
3. **UAC y control de ejecución:** mantené UAC habilitado y restringí la ejecución de binarios no firmados fuera de directorios autorizados mediante **AppLocker** o **WDAC**.
4. **Detección y auditoría:** habilitá creación de procesos con línea de comandos (**Event ID 4688** o **Sysmon Event ID 1**), instalación de servicios (**Event ID 7045**) y alta de tareas programadas (**Event ID 4698**).
:::

## Práctica en laboratorio local

Realizá esta práctica únicamente en tu VM Windows aislada (Host-Only):

1. Desde una consola sin elevar ejecutá `whoami /all` y `net localgroup Administrators`. Anotá tu SID, tu nivel de integridad y los privilegios presentes.
2. Creá `C:\LabAuditoria\prueba.txt`, inspeccioná sus permisos con `icacls C:\LabAuditoria` y endurecelos para que solo `SYSTEM`, `Administrators` y tu usuario conserven acceso.
3. Consultá las claves `Run` de `HKLM` y `HKCU`, enumerá servicios fuera de `C:\Windows` con `Get-CimInstance Win32_Service` y listá tareas activas con `schtasks` y `Get-ScheduledTask`.
4. Ejecutá `procexp64.exe`, `autoruns64.exe` y `tcpview64.exe` de Sysinternals en la VM y contrastá un servicio activo con lo relevado por consola.

::: practica Entregable mínimo
Un informe corto (`auditoria-windows-local.md`) que incluya: (a) tu SID y nivel de integridad obtenidos con `whoami /all`; (b) salida de `icacls` antes y después de endurecer `C:\LabAuditoria`; (c) tabla con 3 servicios de tu VM detallando `Name`, `StartName` y `PathName`; y (d) una entrada detectada en **Autoruns** con su clave de Registro o tarea asociada.
:::

## Preguntas de repaso

**1. ¿Por qué un usuario perteneciente a `Administrators` no puede modificar `C:\Windows\System32` desde una consola estándar con UAC activo?** Porque UAC entrega al iniciar sesión un token filtrado de integridad *Medium* con los privilegios administrativos deshabilitados; hasta aprobar una elevación explícita a integridad *High*, el acceso se evalúa como el de un usuario sin privilegios.

**2. ¿Qué diferencia operativa existe entre `NT AUTHORITY\LocalService` y `NT AUTHORITY\NetworkService`?** Ambas disponen de privilegios locales mínimos en el equipo, pero `LocalService` accede a la red de forma anónima, mientras que `NetworkService` autentica frente a recursos remotos usando las credenciales de la cuenta de equipo (`EQUIPO$`).

**3. En una DACL de NTFS, ¿qué sucede si un usuario recibe `Allow (F)` por un grupo y `Deny (W)` explícito por otro sobre el mismo archivo?** La escritura queda bloqueada, ya que el Monitor de Referencia de Seguridad evalúa todas las entradas explícitas de denegación antes que las de permiso.

**4. ¿Por qué son críticas una ruta de servicio sin comillas con espacios y un permiso `Modify` para `BUILTIN\Users` sobre `ImagePath`?** La ruta sin comillas puede llevar al Service Control Manager a ejecutar un binario plantado en un directorio intermedio escribible; el permiso `Modify` permite sobrescribir directamente el ejecutable para correr código bajo la cuenta del servicio (a menudo `SYSTEM`).

**5. ¿Qué ventaja ofrece combinar consultas CIM/PowerShell con Autoruns y Process Explorer durante una auditoría?** PowerShell y CIM permiten automatizar filtros y generar evidencia reproducible en texto, mientras Autoruns unifica más de cien puntos de persistencia con verificación de firmas y Process Explorer muestra en vivo el árbol de procesos, DLLs cargadas y tokens activos.

## Antes de avanzar

::: nota Puerta de salida
Avanzá al próximo capítulo cuando puedas explicar qué información contiene un token de acceso de Windows, leer una salida de `icacls` detectando permisos de riesgo, enumerar servicios y tareas con `sc.exe`, `Get-CimInstance` y `schtasks`, y validar un proceso junto con su persistencia usando Process Explorer y Autoruns en tu VM local.
:::

## Referencias y estándares abiertos

- Microsoft Learn — *Access Control Overview, SIDs and Access Tokens*: https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-overview
- Microsoft Learn — *Windows Registry Information for Advanced Users*: https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users
- Microsoft Learn — *icacls, sc.exe and schtasks Command-Line References*: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
- Microsoft Learn — *Sysinternals Utilities Index (Process Explorer, Autoruns, TCPView, AccessChk)*: https://learn.microsoft.com/en-us/sysinternals/
- CIS Benchmarks — *Microsoft Windows Desktop & Server Hardening*: https://www.cisecurity.org/cis-benchmarks
