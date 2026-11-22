::: nota Objetivo de la lección
Al finalizar este capítulo vas a comprender la arquitectura interna de los sistemas AV y EDR modernos en Windows —desde *mini-filter drivers* y callbacks en kernel hasta *hooks* en `ntdll.dll`, AMSI y ETW-TI—; vas a entender a nivel técnico-conceptual cómo operan técnicas avanzadas discutidas en evaluaciones Red Team (cifrado de cargas, *unhooking*, syscalls directas e indirectas, *PPID Spoofing*, `BlockDLLs` y ejecución *in-memory*); y vas a saber exactamente qué señales de hardware, kernel y telemetría permiten al Blue Team detectarlas hoy en laboratorio.
:::

## Arquitectura interna de AV y EDR modernos

Para analizar por qué ciertas técnicas existen y por qué hoy resultan mucho más detectables que hace algunos años, primero tenés que entender cómo observa un sistema operativo una solución de seguridad moderna. Un antivirus clásico de primera generación se limitaba casi exclusivamente a calcular hashes y buscar firmas estáticas sobre archivos en disco. Un **EDR (Endpoint Detection and Response)** moderno, en cambio, opera como una red distribuida de sensores tanto en **espacio de usuario (user-land)** como en **modo kernel (kernel-land)**.

```text
+-----------------------------------------------------------------------+
| ESPACIO DE USUARIO (Ring 3)                                           |
|  [Aplicacion / PowerShell / .NET]                                     |
|       |---> AMSI (AmsiScanBuffer) ---> Proveedor AV/EDR               |
|       |---> Win32 API (kernel32 / kernelbase)                         |
|       |---> ntdll.dll [User-land API Hooks del EDR]                   |
|       |---> ETW User Providers (DotNETRuntime, PowerShell, etc.)      |
+-----------------------------------+-----------------------------------+
                                    | Transicion syscall
+-----------------------------------v-----------------------------------+
| MODO KERNEL (Ring 0)                                                  |
|  [Mini-filter Driver (fltmgr.sys)]  --> E/S de archivos en disco      |
|  [Kernel Callbacks]                 --> PsSetCreateProcessNotify...   |
|                                     --> PsSetCreateThreadNotify...    |
|                                     --> PsSetLoadImageNotify...       |
|                                     --> ObRegisterCallbacks (Handles) |
|  [ETW-TI (Threat Intelligence)]     --> Servicio PPL del EDR (ELAM)   |
+-----------------------------------------------------------------------+
```

::: nota Profundización en internos y kernel de Windows
El análisis detallado de la transición Ring 3 a Ring 0, las estructuras del kernel (`EPROCESS`, `ETHREAD`, `PEB`), los descriptores de servicio y el ciclo completo de llamadas del sistema en Windows se desarrolla en el material de referencia del proyecto: [Guía de internos y kernel de Windows](../../CLS_Guia/2d.html). Te conviene consultarlo antes de diseñar pruebas de telemetría en kernel en tu laboratorio.
:::

Los cinco pilares arquitectónicos que debés conocer son:

1. ***Mini-filter drivers* en kernel (`fltmgr.sys`)**: el EDR registra un controlador *mini-filter* con una altitud asignada por Microsoft dentro de la pila del sistema de archivos. Cada vez que un proceso intenta crear, escribir, leer o ejecutar un archivo (`IRP_MJ_CREATE`, `IRP_MJ_WRITE`), el controlador intercepta la operación antes de que se complete, inspecciona el contenido y puede bloquear el acceso en tiempo real.
2. **Callbacks nativos del kernel**: Windows expone interfaces oficiales y documentadas para que los controladores de seguridad reciban notificaciones síncronas o asíncronas desde Ring 0:
   - `PsSetCreateProcessNotifyRoutine` (y su variante extendida `Ex`): notifica la creación y terminación de todo proceso, entregando el PID real del creador, la línea de comandos y el objeto `EPROCESS`.
   - `PsSetCreateThreadNotifyRoutine`: alerta cuando se crea un hilo nuevo, especialmente crítico para distinguir hilos locales de hilos creados en un proceso ajeno.
   - `PsSetLoadImageNotifyRoutine`: registra cada ejecutable o DLL mapeado en memoria por cualquier proceso.
   - `ObRegisterCallbacks`: intercepta solicitudes de apertura o duplicación de *handles* (`NtOpenProcess`, `NtDuplicateObject`). Así es como el EDR protege a `lsass.exe` y a sus propios procesos quitando permisos como `PROCESS_VM_READ` o `PROCESS_TERMINATE` a solicitantes no autorizados.
3. **API Hooking en user-land dentro de `ntdll.dll`**: aunque el kernel ve el nacimiento del proceso y la carga de módulos, inspeccionar cada argumento de memoria en cada llamada desde Ring 0 tendría un costo de rendimiento alto. Por eso, muchos EDR inyectan su propia DLL de monitoreo dentro de cada proceso nuevo y sobrescriben los primeros bytes (el prólogo) de funciones nativas sensibles en `ntdll.dll` —como `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` o `NtQueueApcThread`— con un salto (`JMP`) hacia código de inspección en su DLL antes de ejecutar la instrucción `syscall`.
4. **Proveedores AMSI (*Antimalware Scan Interface*)**: interfaz estándar de Windows integrada en intérpretes dinámicos como PowerShell, Windows Script Host (`cscript`/`wscript`), VBA de Office y el *Common Language Runtime* (.NET 4.8+). Justo antes de compilar o evaluar un script o ensamblado en memoria, el intérprete invoca `AmsiScanBuffer`, permitiendo al motor AV/EDR inspeccionar el código ya desencriptado y desofuscado en tiempo de ejecución.
5. **ETW y ETW-TI (*Event Tracing for Windows - Threat Intelligence*)**:
   - El **ETW tradicional** emite eventos desde componentes de usuario y kernel (por ejemplo, `Microsoft-Windows-DotNETRuntime`, que registra qué ensamblados y métodos .NET se cargan en un proceso).
   - **ETW-TI** (`Microsoft-Windows-Threat-Intelligence`) es un proveedor especial **generado íntegramente en el kernel** y protegido: solo puede consumirlo un proceso ejecutándose como **PPL (*Protected Process Light*)** con firma de controlador ELAM (*Early Launch Anti-Malware*), exactamente el nivel de privilegio que posee el servicio del EDR. Como se origina en Ring 0, los parches en memoria de usuario no lo ciegan.

::: peligro Alcance educativo y prohibición de uso malicioso
En este módulo analizamos las técnicas de evasión únicamente a nivel **conceptual y arquitectónico**, sin incluir código malicioso, shellcode ni implementaciones funcionales contra controles de terceros. El objetivo es entender las primitivas del sistema operativo para diseñar mejores detecciones Purple Team en laboratorio aislado.
:::

## Comprensión técnica de técnicas avanzadas en evaluaciones Red Team

En evaluaciones avanzadas (tipo CRTO/OSEP), los equipos rojos estudian cómo interactúan los artefactos de prueba con los cinco pilares descriptos. Comprender la mecánica teórica detrás de cada técnica es indispensable para que el Blue Team no confíe en detecciones obsoletas.

### Cifrado y ofuscación en reposo vs memoria

En disco ("en reposo"), un binario con cadenas en texto claro o secuencias de bytes conocidas cae de inmediato ante reglas YARA o firmas estáticas. Al cifrar o comprimir una carga en reposo, la firma estática desaparece, pero se introduce una anomalía medible: **alta entropía de Shannon** en la sección que contiene los datos cifrados (valores cercanos a `7.2`–`8.0` bits por byte en comparación con código compilado normal de `5.5`–`6.5`).

Además, ocultar el binario en disco no resuelve el problema en tiempo de ejecución: apenas el programa descifra su contenido en memoria para ejecutarlo, los escáneres de memoria del EDR (activados al crear hilos o ante eventos ETW-TI) inspeccionan las regiones recién asignadas. Esto motivó el concepto de *sleep obfuscation* (ofuscación en reposo en memoria): cifrar las regiones de datos y código propias del agente y retirar permisos de ejecución (`PAGE_EXECUTE_READ` -> `PAGE_READWRITE`) mientras el agente duerme entre *beacons*, restaurándolos brevemente solo al despertar.

### *Unhooking* de `ntdll.dll` y syscalls directas e indirectas

Dado que el *API Hooking* en user-land modifica los bytes de `ntdll.dll` cargada en la memoria del proceso, existen tres enfoques conceptuales ampliamente documentados en la literatura técnica:

- ***Unhooking* de `ntdll.dll`**: el proceso abre una copia limpia y sin modificar de `ntdll.dll` (desde `\KnownDlls\ntdll.dll`, desde el disco `C:\Windows\System32\ntdll.dll` o leyendo la sección `.text` de un proceso secundario creado en estado suspendido) y sobrescribe la sección `.text` en memoria propia para restaurar los prólogos originales, eliminando los `JMP` colocados por el EDR.
- **Syscalls directas (*Direct Syscalls*)**: cada función `Nt*` en `ntdll.dll` simplemente carga en el registro `EAX` su número de servicio del sistema (**SSN**, *System Service Number*) y ejecuta la instrucción de CPU `syscall`. Una implementación de syscall directa resuelve dinámicamente el SSN correspondiente a la versión exacta de Windows y ejecuta la instrucción `syscall` directamente desde su propio código en memoria, **evitando pasar por `ntdll.dll`**.
- **Syscalls indirectas (*Indirect Syscalls*)**: debido a que ejecutar `syscall` fuera de `ntdll.dll` deja un rastro evidente en la pila de llamadas (*call stack*), la variante indirecta prepara los argumentos y el SSN en los registros, pero en lugar de ejecutar `syscall` en su propia región de memoria, realiza un salto hacia la dirección de una instrucción `syscall; ret` legítima dentro de `ntdll.dll`.

### *PPID Spoofing* y política `BlockDLLs`

Muchas reglas iniciales de SIEM y EDR dependían casi exclusivamente del árbol padre-hijo (`ParentImage` -> `Image`). Dos atributos documentados de la API `CreateProcessW` (mediante `STARTUPINFOEX` y `UpdateProcThreadAttribute`) ilustran los límites de esa detección ingenua:

- ***PPID Spoofing*** (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`): permite especificar un proceso padre arbitrario al crear un proceso hijo (por ejemplo, simular que un nuevo proceso nació de `explorer.exe` o `svchost.exe` en lugar de una macro de `winword.exe`). El nuevo proceso hereda el entorno y aparece visualmente bajo ese padre falso en herramientas basadas solo en `CreateToolhelp32Snapshot` o el campo padre del PEB.
- **Política `BlockDLLs`** (`PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`): es una mitigación legítima de Windows diseñada para impedir la inyección de DLLs no firmadas por Microsoft (como adware o hooks de terceros). Cuando un proceso se crea con esta política, el cargador de Windows rechaza DLLs de terceros en user-land. Como efecto secundario conceptual, si la DLL de *hooking* de un EDR no cuenta con firma Microsoft/WHQL compatible con esa política, no logra cargarse en ese proceso hijo. (Sin embargo, esto no detiene en absoluto los callbacks en kernel ni ETW-TI).

### Ejecución *in-memory* vs disco

Mientras que el lanzamiento tradicional escribe un ejecutable en disco y llama a `CreateProcess`, la ejecución *in-memory* busca evitar el *mini-filter driver* de archivos cargando lógica directamente en memoria virtual: carga reflectiva de DLLs (mapear manualmente cabeceras PE y resolver importaciones sin usar `LoadLibrary`), ejecución de ensamblados .NET en memoria mediante `System.Reflection.Assembly.Load`, o *Module Stomping* (cargar una DLL legítima poco usada desde disco y sobrescribir su sección de código para que la memoria ejecutada figure respaldada por un archivo firmado en lugar de ser memoria privada anónima).

## Señales defensivas que hoy los detectan

Lejos de ser "indetectables", las técnicas anteriores desplazan el punto de observación desde firmas estáticas en disco hacia **anomalías estructurales de memoria, pila de llamadas y telemetría de kernel** mucho más difíciles de falsificar.

| Técnica conceptual | Lo que intenta evitar | Señal defensiva moderna que la detecta |
| :--- | :--- | :--- |
| **Cifrado de payload en reposo** | Firmas YARA y escaneo estático en disco | Entropía de Shannon elevada (> 7.2) en secciones PE; detección en memoria al descifrar |
| ***Unhooking* de `ntdll.dll`** | Hooks de monitoreo en Ring 3 | Evento de cambio de permisos (`PAGE_EXECUTE_READWRITE` sobre `ntdll.dll` vía ETW-TI `PROTECTVM_LOCAL`) y verificación de integridad de `.text` |
| **Syscalls directas** | Hooks de user-land en `ntdll.dll` | **Call Stack Inspection**: la dirección de retorno (`RIP`) tras `syscall` apunta a memoria privada no respaldada (*unbacked memory*), no a `ntdll.dll` |
| **Syscalls indirectas** | Validación simple de RIP en `ntdll.dll` | **Deep Call Stack Walking**: la pila de retorno debajo de `ntdll.dll` no atraviesa `kernelbase.dll` ni el marco de llamada esperado |
| ***PPID Spoofing*** | Reglas simples de `ParentImage` | Discrepancia entre el creador real en `ETW Kernel-Process` / `Sysmon ID 10` (handle `PROCESS_CREATE_PROCESS` hacia el padre falso) y el padre declarado |
| **Política `BlockDLLs`** | Inyección de DLL de hooking en user-land | Telemetría íntegra en kernel (`PsSetCreateProcessNotifyRoutine`, ETW-TI) + flag anómalo de mitigación en procesos comunes |
| **Ejecución *in-memory*** | Mini-filter de archivos en disco | Regiones `MEM_PRIVATE` con permisos `RWX`/`RX` sin respaldo en disco (*unbacked executable memory*) y eventos ETW de .NET |

### Profundización en los cuatro detectores modernos clave

1. **Inspección de la pila de llamadas (*Call Stack Inspection*)**: cuando el kernel captura un evento crítico mediante ETW-TI (como asignar memoria ejecutable remota o abrir un handle a otro proceso), recorre hacia atrás los marcos de pila (*stack unwinding*) tanto en kernel como en usuario. En una llamada legítima, el flujo desciende ordenadamente desde la aplicación -> `kernelbase.dll` -> `ntdll.dll` -> kernel. Si la pila muestra un salto abrupto desde una región `MEM_PRIVATE` sin DLL asociada, o marcos de retorno inconsistentes propios de syscalls indirectas o *ROP/call-stack spoofing* rudimentario, el EDR genera una alerta de alta confianza.
2. **Discrepancias de páginas privadas ejecutables (`MEM_PRIVATE` + `RX`/`RWX`)**: el código legítimo en Windows se mapea como `MEM_IMAGE` respaldado por un archivo PE en disco (`.exe` o `.dll`). Cuando una herramienta inyecta código en memoria o hace carga reflectiva, aparecen páginas de tipo `MEM_PRIVATE` con permisos de ejecución (`PAGE_EXECUTE_READ` o `PAGE_EXECUTE_READWRITE`) sin archivo asociado. Motores como *Moneta* o los escáneres de memoria de los EDR señalan de inmediato memoria privada ejecutable o hilos cuyo `StartAddress` cae fuera de módulos mapeados. En *Module Stomping*, la memoria figura como `MEM_IMAGE`, pero sus páginas fueron modificadas (*Copy-on-Write* / páginas privadas sucias respecto al archivo original en disco), lo cual también es detectable comparando hashes de páginas en memoria contra disco.
3. **Telemetría ETW-TI desde kernel**: aunque un proceso modifique en su propia memoria la función `EtwEventWrite` de `ntdll.dll` para silenciar proveedores de usuario, el proveedor **ETW-TI** corre dentro del núcleo del sistema operativo y emite eventos como `THREATINT_ALLOCVM_REMOTE`, `THREATINT_PROTECTVM_REMOTE` y `THREATINT_WRITEVM_REMOTE` directamente al servicio protegido (PPL) del EDR.
4. **Sysmon Event IDs `8`, `10` y `25`**:
   - **Sysmon ID `8` (*CreateRemoteThread*)**: registra el proceso origen (`SourceImage`), el proceso destino (`TargetImage`) y la dirección inicial (`StartAddress` y módulo) cuando un proceso crea un hilo dentro de otro.
   - **Sysmon ID `10` (*ProcessAccess*)**: captura el acceso entre procesos (`GrantedAccess` y `CallTrace`). Es fundamental tanto para detectar intentos de volcado de credenciales sobre `lsass.exe` (`0x1010`, `0x1410`, `0x1fffff`) como para detectar ***PPID Spoofing***, porque el proceso creador debe pedir un *handle* con permiso `PROCESS_CREATE_PROCESS` (`0x0080`) o `PROCESS_ALL_ACCESS` sobre el proceso padre que intenta suplantar, dejando expuesto el `SourceImage` verdadero junto al `CallTrace`.
   - **Sysmon ID `25` (*ProcessTampering*)**: introducido específicamente para detectar manipulación de la imagen de un proceso en memoria respecto al archivo en disco, cubriendo técnicas como *Process Hollowing*, *Process Herpaderping* y *Process Ghosting*.

## Metodología práctica frente a Antivirus en laboratorio aislado (enfoque PEN-200)

En evaluaciones prácticas como **PEN-200 (OSCP)** no basta con conocer la teoría del kernel: las máquinas de laboratorio cuentan habitualmente con **Windows Defender** activo, y los auditores necesitan diagnosticar por qué una herramienta o binario de prueba es bloqueado antes de validar controles defensivos:

1. **Por qué caen al instante los binarios estándar (`msfvenom` sin modificar):** los generadores automáticos utilizan plantillas PE fijas, secciones predecibles y secuencias de bytes ampliamente indexadas en las bases de firmas de todo antivirus. Además, cuando el archivo se escribe en disco o se ejecuta, el emulador integrado de Windows Defender corre los primeros ciclos en una mini-sandbox interna buscando llamadas API típicas (`VirtualAlloc` → `RtlMoveMemory` → `CreateThread`) y patrones de alta entropía.
2. **Aislamiento de firmas offline (*Signature Identification*):** frente a un falso o verdadero positivo en un ejecutable compilado de laboratorio, herramientas analíticas como **`DefenderCheck`** o **`ThreatCheck`** automatizan una búsqueda por bisección binaria invocando localmente el motor del antivirus sobre fragmentos crecientes del archivo (`MpCmdRun.exe -Scan -ScanType 3`) hasta señalar el *offset* exacto o cadena de texto que dispara la detección (tanto estática como en `AMSITrigger` para scripts PowerShell). Toda esta prueba se realiza **100 % offline en la VM de laboratorio**, jamás subiendo artefactos internos a plataformas públicas como VirusTotal.
3. **Cargadores gestionados (C# / .NET) vs visibilidad AMSI/ETW:** frente a ejecutables nativos fáciles de firmar, las evaluaciones modernas comparan el comportamiento de ensamblados C#/.NET o scripts en memoria. Sin embargo, desde .NET 4.8 todos los ensamblados cargados dinámicamente (`Assembly.Load`) pasan automáticamente por **`AmsiScanBuffer`** y emiten eventos en el proveedor **ETW `Microsoft-Windows-DotNETRuntime`**, por lo que en entornos modernos la validación Purple Team siempre verifica la correlación en SIEM (`4104`, `Sysmon ID 1/8/10`) más allá de que el antivirus de disco no haya detenido un archivo estático.

## Verificación defensiva y auditoría en laboratorio

Podés comprobar estas señales defensivas de forma totalmente segura en tu laboratorio usando herramientas de análisis estático y consultas a eventos reales del sistema.

El siguiente script en **Python** calcula la entropía de Shannon por ventana o por secciones básicas de un archivo PE de prueba (sin ejecutar el binario), ayudando al Blue Team a identificar artefactos empaquetados o con bloques cifrados sospechosos:

```python
import math
import sys
from collections import Counter


def entropia_shannon(datos: bytes) -> float:
    """Calcula la entropia de Shannon (0.0 a 8.0 bits por byte)."""
    if not datos:
        return 0.0
    total = len(datos)
    conteo = Counter(datos)
    entropia = 0.0
    for frecuencia in conteo.values():
        prob = frecuencia / total
        entropia -= prob * math.log2(prob)
    return entropia


def auditar_bloques_archivo(ruta: str, tamano_bloque: int = 4096):
    """Analiza un binario de laboratorio por bloques para detectar zonas de alta entropia."""
    with open(ruta, "rb") as f:
        contenido = f.read()

    entropia_global = entropia_shannon(contenido)
    print(f"Archivo: {ruta} | Tamano: {len(contenido)} bytes | Entropia global: {entropia_global:.3f}")

    bloques_altos = 0
    for offset in range(0, len(contenido), tamano_bloque):
        bloque = contenido[offset : offset + tamano_bloque]
        ent = entropia_shannon(bloque)
        if ent >= 7.20:
            bloques_altos += 1
            print(f"  [!] Bloque 0x{offset:08X} con entropia alta: {ent:.3f} bits/byte")

    if bloques_altos == 0:
        print("  [OK] No se observaron bloques con entropia >= 7.20 bits/byte.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python analizar_entropia.py <ruta_archivo_laboratorio>")
        sys.exit(1)
    auditar_bloques_archivo(sys.argv[1])
```

En Windows, el siguiente script defensivo en **PowerShell** inspecciona los **Sysmon IDs `8`, `10` y `25`** de las últimas 24 horas y verifica qué políticas de mitigación (incluida la restricción de DLLs no firmadas por Microsoft) están activas sobre procesos en ejecución:

```powershell
# Auditoria defensiva en laboratorio: Sysmon IDs 8, 10 y 25 + Politicas de Mitigacion
$inicio = (Get-Date).AddHours(-24)

Write-Host "=== Eventos Sysmon 8 (CreateRemoteThread), 10 (ProcessAccess sospechoso) y 25 (ProcessTampering) ===" -ForegroundColor Cyan
$eventos = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = @(8, 10, 25)
    StartTime = $inicio
} -ErrorAction SilentlyContinue

foreach ($ev in $eventos) {
    $xml = [xml]$ev.ToXml()
    $d = @{}
    foreach ($campo in $xml.Event.EventData.Data) {
        $d[$campo.Name] = $campo.'#text'
    }
    [PSCustomObject]@{
        EventID      = $ev.Id
        Hora         = $ev.TimeCreated
        Origen       = $d['SourceImage']
        Destino      = if ($d['TargetImage']) { $d['TargetImage'] } else { $d['Image'] }
        AccesoOTipo  = if ($d['GrantedAccess']) { $d['GrantedAccess'] } else { $d['Type'] }
        CallTrace    = $d['CallTrace']
    }
} | Format-List

Write-Host "=== Verificacion de politicas de mitigacion en procesos activos (ej. msedge / powershell) ===" -ForegroundColor Cyan
Get-ProcessMitigation -Name powershell.exe -ErrorAction SilentlyContinue |
    Select-Object ProcessName, @{Name='BlockNonMSBinaries';Expression={$_.BinarySignature.BlockNonMicrosoftBinaries}}
```

## Práctica guiada en laboratorio

En tu máquina virtual de laboratorio Windows (con Sysmon habilitado usando configuración de visibilidad para IDs `8`, `10` y `25`), realizá la siguiente verificación estrictamente defensiva y sin herramientas ofensivas externas:

1. **Medí entropía de referencia**: ejecutá el script `analizar_entropia.py` sobre una copia de `C:\Windows\System32\notepad.exe` (entropía típica de código nativo) y luego sobre un archivo `.zip` o `.7z` de prueba (entropía cercana a `7.9` bits/byte) para calibrar visualmente cómo luce un bloque comprimido/cifrado frente a una sección `.text` legítima.
2. **Inspeccioná `CallTrace` en Sysmon ID `10`**: abrí el Administrador de tareas o Process Explorer en tu laboratorio (herramientas administrativas legítimas que leen información de otros procesos) y filtrá en PowerShell los eventos `Sysmon ID 10` generados. Observá el formato del campo `CallTrace` y verificá cómo las direcciones resuelven a `ntdll.dll` y `kernelbase.dll`, contrastándolo con lo que ocurriría si apareciera una dirección `UNKNOWN` sin módulo respaldado.
3. **Auditá mitigaciones de procesos**: ejecutá `Get-ProcessMitigation -System` y `Get-ProcessMitigation -Name msedge.exe` (o un navegador instalado en la VM) para ver en la práctica cómo Windows aplica *CFG*, *DEP* y políticas de firma binaria (`BlockNonMicrosoftBinaries`).

::: practica Entregable mínimo
Entregá un breve reporte de laboratorio que contenga: (a) la salida comparativa de `analizar_entropia.py` entre un binario nativo de Windows y un archivo comprimido de prueba; (b) una captura o transcripción anonimizada de un evento `Sysmon ID 10` de tu VM mostrando `SourceImage`, `TargetImage`, `GrantedAccess` y un fragmento del `CallTrace` legítimo; y (c) el detalle de tres mitigaciones verificadas con `Get-ProcessMitigation`.
:::

::: defensa Perspectiva defensiva y mitigación
La defensa moderna contra técnicas de evasión en memoria no depende de un solo gancho en user-land. Se apoya en habilitar **EDR con sensor kernel y consumidor PPL de ETW-TI**, activar **HVCI / Integridad de Memoria** (VBS) para blindar el kernel y los controladores, exigir **Credential Guard** (aislando secretos de `lsass.exe` en VTL1), configurar **Sysmon** capturando IDs `1`, `7`, `8`, `10` (con `CallTrace`) y `25`, y correlacionar la presencia de memoria `MEM_PRIVATE` ejecutable con anomalías en el *call stack*.
:::

## Preguntas de repaso

**1. ¿Por qué un *unhooking* de `ntdll.dll` en user-land no logra cegar la visibilidad completa de un EDR moderno?** Porque los EDR modernos operan principalmente mediante callbacks registrados en Ring 0 (`PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`, *mini-filters*) y consumen **ETW-TI** desde el kernel mediante un servicio protegido (PPL), canales que no dependen de los *hooks* en `ntdll.dll` ni pueden desactivarse desde la memoria de usuario del proceso.

**2. ¿Cuál es la diferencia técnica entre una syscall directa y una syscall indirecta, y qué delata a cada una ante el análisis de pila?** Una syscall directa ejecuta la instrucción `syscall` desde la memoria del propio programa fuera de `ntdll.dll`, dejando un `RIP` de retorno en memoria privada no respaldada; una syscall indirecta salta a una instrucción `syscall; ret` dentro de `ntdll.dll` para aparentar legitimidad, pero sigue siendo detectable mediante *deep call stack inspection* cuando los marcos inferiores de la pila no corresponden al flujo normal de `kernelbase.dll` y las APIs de usuario.

**3. ¿Qué ventaja aporta Sysmon Event ID `10` (*ProcessAccess*) para detectar *PPID Spoofing*?** Para suplantar a un proceso padre benigno mediante `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, el proceso atacante debe abrir un *handle* hacia ese padre falso con derechos de creación de procesos (`PROCESS_CREATE_PROCESS`), lo que genera un evento Sysmon ID `10` donde queda registrado el `SourceImage` real junto con su `CallTrace`.

**4. ¿Qué indica la presencia de páginas `MEM_PRIVATE` con permisos `PAGE_EXECUTE_READWRITE` o `RX` en un proceso estándar?** Indica código ejecutable alojado en memoria dinámica sin un archivo PE legítimo respaldado en disco (`MEM_IMAGE`), un patrón característico de cargas reflectivas, inyección de memoria o intérpretes JIT no esperados en binarios nativos.

**5. ¿Qué tipo de anomalías busca detectar específicamente Sysmon Event ID `25` (*ProcessTampering*)?** Detecta discrepancias entre la imagen del ejecutable mapeada en la memoria de un proceso y el archivo original en disco, cubriendo técnicas de manipulación como *Process Hollowing*, *Process Herpaderping* y *Process Ghosting*.

## Antes de avanzar

::: nota Puerta de salida
Antes de pasar al capítulo 6.7 sobre Ingeniería Social y acceso inicial, confirmá que podés explicar con claridad:
- La diferencia entre telemetría en Ring 3 (`ntdll.dll`, AMSI) y telemetría protegida en Ring 0 (callbacks, *mini-filters*, ETW-TI).
- Por qué el *Call Stack Inspection* y la detección de memoria `MEM_PRIVATE` ejecutable cerraron la brecha de las syscalls directas y la carga reflectiva.
- Qué registra específicamente cada uno de los eventos Sysmon `8`, `10` y `25`.
:::

## Referencias y estándares abiertos

- Microsoft Learn — *Antimalware Scan Interface (AMSI)*, *Process Mitigation Policies* y documentación de kernel callbacks (`PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks`).
- Microsoft Learn — *Sysmon v15+ Documentation* (Event ID `8`, `10` y `25`).
- MITRE ATT&CK — `T1055` (*Process Injection*), `T1134.004` (*Parent PID Spoofing*), `T1562.001` (*Impair Defenses*), `T1620` (*Reflective Code Loading*).
- Proyecto abierto **Moneta** y **Hunt-Sleeping-Beacons** — Referencias educativas sobre detección de memoria privada ejecutable y *call stack anomalies*.
- Material interno de arquitectura: [Guía de internos y kernel de Windows](../../CLS_Guia/2d.html).
