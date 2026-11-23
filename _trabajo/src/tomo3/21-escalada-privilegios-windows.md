::: nota Objetivo de la lección
Al finalizar este capítulo vas a comprender la arquitectura del modelo de seguridad de Windows (tokens de acceso, niveles de integridad, UAC y privilegios sensibles), auditar configuraciones inseguras en servicios, tareas programadas, resolución de DLLs y almacenamiento de credenciales en tu laboratorio local, y aplicar medidas concretas de endurecimiento como LAPS, Credential Guard, protección LSA (`RunAsPPL`) y monitoreo con Sysmon.
:::

**Prerrequisitos:** Manejo básico de PowerShell, nociones de administración Windows y una VM Windows propia en red aislada. **Duración sugerida:** 90 a 120 minutos.

## 1. Modelo de seguridad de Windows: tokens, integridad y UAC

Windows controla el acceso a objetos del sistema (archivos, claves del Registro, procesos y servicios) comparando el **token de acceso** de un proceso contra el descriptor de seguridad (DACL) del recurso solicitado.

### Componentes clave del contexto de seguridad

- **Identificadores de seguridad (SID):** Representan de forma única al usuario y a los grupos a los que pertenece.
- **Niveles de integridad (Mandatory Integrity Control):** Clasifican procesos y objetos en niveles (*Untrusted*, *Low*, *Medium*, *High* y *System*). Un proceso con integridad *Medium* no puede escribir sobre objetos marcados como *High* aunque comparta el mismo usuario.
- **Control de Cuentas de Usuario (UAC):** Divide el token de los administradores locales en un token filtrado (*Medium*) para tareas cotidianas y un token elevado (*High*) que requiere consentimiento explícito. Es fundamental recordar que UAC es una barrera de conveniencia operativa y no un límite de seguridad absoluto cuando el usuario ya pertenece al grupo de administradores.
- **Privilegios asignados al token:** Permisos globales otorgados al proceso más allá de las ACL individuales. Entre los más sensibles a auditar figuran:
  - `SeImpersonatePrivilege`: permite a una cuenta de servicio adoptar el contexto de seguridad de un cliente conectado; si se asigna a cuentas no confiables o servicios expuestos, puede derivar en elevación hacia `SYSTEM`.
  - `SeBackupPrivilege`: otorga lectura de archivos omitiendo restricciones DACL estándar, pensado exclusivamente para cuentas de respaldo estrictamente controladas.
  - `SeDebugPrivilege`: habilita la inspección y depuración de procesos de otros usuarios; nunca debe concederse a cuentas estándar.

```powershell
# Auditar contexto actual, grupos, nivel de integridad y privilegios del token
whoami /all
```

## 2. Auditoría de servicios, tareas programadas y orden de búsqueda de DLLs

Gran parte de las debilidades locales en endpoints Windows surgen de software de terceros instalado con permisos heredados inseguros o rutas mal definidas.

### Superficies principales y su causa raíz

| Superficie | Causa técnica de la vulnerabilidad | Verificación en laboratorio (solo lectura) | Remediación |
| --- | --- | --- | --- |
| **Permisos débiles en servicios o binarios** | Usuarios estándar poseen permisos de escritura sobre el ejecutable o la configuración del servicio | `icacls` sobre el binario y `sc.exe sdshow <servicio>` | Restringir escritura solo a `SYSTEM` y `Administrators` |
| **Rutas de servicio sin comillas** | Rutas con espacios sin comillas hacen que Windows pruebe prefijos sucesivos al iniciar el servicio | Consulta WMI/CIM de `PathName` en `Win32_Service` | Encerrar siempre la ruta completa entre comillas dobles |
| **Tareas programadas privilegiadas** | Tareas que corren como `SYSTEM` ejecutando scripts almacenados en carpetas modificables | `Get-ScheduledTask` + revisión de ACL del script | Mover scripts a rutas protegidas y validar ACL |
| **Orden de búsqueda de DLLs** | Una aplicación carga una DLL sin ruta absoluta y busca en directorios escribibles del `PATH` | Revisión de `SafeDllSearchMode` y permisos en `%PATH%` | Usar rutas absolutas, firmas digitales y carpetas protegidas |
| **Credenciales en texto claro** | Archivos de despliegue desatendido, scripts o claves del Registro conservan contraseñas | Revisión de políticas de configuración y archivos de instalación | Eliminar archivos de instalación y usar gestión centralizada |

### Mecánica conceptual de rutas sin comillas y DLL hijacking

Cuando un servicio se registra con una ruta como `C:\Program Files\App Interna\servicio.exe` sin comillas dobles, el administrador de servicios interpreta los espacios de forma ambigua y evalúa rutas intermedias antes de alcanzar el binario real. Si algún directorio intermedio otorga permisos de escritura a usuarios no privilegiados, un archivo colocado allí podría ejecutarse con los privilegios del servicio.

De manera similar, el **secuestro de DLL (DLL hijacking)** aprovecha el orden de búsqueda de bibliotecas dinámicas de Windows cuando una aplicación solicita una DLL por nombre simple sin especificar la ruta completa y la biblioteca no reside en el directorio protegido de la aplicación ni en `System32`. Si el proceso continúa buscando en directorios incluidos en la variable `PATH` donde un usuario común puede escribir, la integridad del proceso queda comprometida.

### Vectores críticos adicionales: `AlwaysInstallElevated` y BYOVD (visión defensiva)

| Vector / Superficie | Mecanismo técnico | Telemetría (Event IDs + Sigma) | Mitigación obligatoria |
|---|---|---|---|
| **`AlwaysInstallElevated`** | Si tanto `HKCU\...\Installer\AlwaysInstallElevated` como `HKLM\...\Installer\AlwaysInstallElevated` valen `1`, cualquier usuario estándar puede ejecutar un instalador `.msi` (`msiexec /quiet /qn /i lab.msi`) con privilegios `NT AUTHORITY\SYSTEM`. | **Sysmon Event ID `1`** / **Security `4688`** (`msiexec.exe /quiet` iniciado por usuario estándar desde `%TEMP%` o `Users\Public`) + **Application `11707`/`1033`** (`MsiInstaller`). **Criterio Sigma:** `Image\|endswith: '\msiexec.exe'` con `/q` y padre no administrativo desde ruta escribible. | Mantener **`AlwaysInstallElevated = 0`** en GPO (`Computer` y `User Configuration`), bloquear `.msi` no firmados mediante AppLocker/WDAC. |
| **BYOVD** (*Bring Your Own Vulnerable Driver*) | Un actor con privilegios administrativos locales carga un controlador legítimo firmado pero con vulnerabilidades de lectura/escritura en núcleo para terminar procesos EDR o alterar tokens del kernel. | **Sysmon Event ID `6`** (*Driver Loaded*), **System `7045`** (`Type: Kernel Driver`) y **CodeIntegrity `3076`/`3077`** por bloqueo WDAC/Blocklist. **Criterio Sigma:** carga de `.sys` desde `Users\`/`Temp\` o coincidencia de hash con listas *LOLDrivers*. | Habilitar **Microsoft Vulnerable Driver Blocklist** y **HVCI (*Memory Integrity*)** sobre VBS. Para el análisis técnico de drivers y firmas en núcleo, consultá [Curso de Reversing en Windows · Etapa 6](../../CLS_Guia/guia/etapa-6.html). |

## 3. Medidas de endurecimiento para endpoints Windows

El hardening efectivo en Windows reduce drásticamente el impacto de credenciales expuestas y corta las vías habituales de elevación local.

### Controles prioritarios recomendados por Microsoft y CIS

1. **Principio de mínimo privilegio:** Retirar a los usuarios cotidianos del grupo `Administrators` local y separar las tareas administrativas en cuentas dedicadas.
2. **Windows LAPS (*Local Administrator Password Solution*):** Genera, rota automáticamente y almacena de forma cifrada contraseñas únicas para la cuenta administrativa local de cada equipo, eliminando el riesgo de reutilización lateral.
3. **LSA Protection (`RunAsPPL`):** Configura el proceso de autoridad de seguridad local (`lsass.exe`) como proceso protegido (*Protected Process Light*), bloqueando la lectura o inyección de memoria desde procesos no firmados adecuadamente.
4. **Windows Defender Credential Guard:** Utiliza seguridad basada en virtualización (VBS) para aislar secretos derivados de autenticación en un contenedor protegido por hipervisor, inaccesible incluso para procesos con privilegios elevados en el sistema operativo principal.
5. **Control de aplicaciones (WDAC / AppLocker):** Restringe la ejecución a binarios firmados o ubicados en rutas aprobadas, mitigando la ejecución de ejecutables y DLLs no autorizados.

| Control defensivo | Riesgo principal mitigado | Requisito técnico clave |
| --- | --- | --- |
| **Windows LAPS** | Reutilización de contraseñas de administrador local | Active Directory o Microsoft Entra ID |
| **LSA Protection (`RunAsPPL`)** | Acceso no autorizado a la memoria de `lsass.exe` | Arranque seguro (UEFI/Secure Boot) recomendado |
| **Credential Guard** | Extracción de credenciales en memoria | Hardware con virtualización (VBS / TPM 2.0) |
| **WDAC / AppLocker** | Ejecución de binarios y DLLs no confiables | Política de inventario y firma de código |

### Protección de almacenes de credenciales locales (DPAPI, Credential Manager y navegadores)

Windows protege secretos guardados por el usuario (contraseñas de Wi-Fi, certificados personales, credenciales del **Windows Credential Manager**, perfiles de Outlook y bases locales de navegadores) mediante **DPAPI (*Data Protection API*)**, que deriva claves maestras vinculadas a las credenciales del usuario y, en sistemas modernos de navegadores, refuerza el aislamiento mediante **App-Bound Encryption** ligada a un servicio de sistema privilegiado.
- **Riesgo en auditoría:** si una cuenta de usuario queda comprometida en un endpoint compartido o deja claves maestras accesibles en sesiones persistentes, cualquier proceso en el contexto de ese usuario puede descifrar sus propios secretos DPAPI (o acceder a claves de aplicaciones que no restringen su ámbito).
- **Defensa operativa:** utilizar **Windows Hello for Business / TPM** para proteger claves privadas, evitar almacenar credenciales administrativas estáticas en scripts o archivos XML de instalación (`Unattend.xml`) y auditar con **Credential Guard + WDAC**.

### Técnicas de evasión de controles y su detección defensiva (UAC, Defender, AMSI)

En evaluaciones avanzadas de endpoints Windows conviene conocer cómo operan las barreras locales para verificar por qué nunca reemplazan el **principio de mínimo privilegio**:
- **Auto-elevación de UAC (*UAC Bypasses*):** binarios firmados por Microsoft configurados para auto-elevarse consultando rutas de registro bajo `HKCU\Software\Classes` (por ejemplo `ms-settings\Shell\Open\command` asociada a `fodhelper.exe` o interfaces COM privilegiadas) permiten a una cuenta que ya es miembro de `Administrators` abrir un proceso elevado sin cuadro de diálogo. **Detección SOC:** monitorear creaciones de subclaves bajo `HKCU\Software\Classes\ms-settings` (Sysmon Event ID `12/13`) y procesos `cmd.exe`/`powershell.exe` nacidos con nivel *High* directamente desde `fodhelper.exe` o `computerdefaults.exe` (Sysmon `1`). **Mitigación real:** usar cuentas estándar sin derechos administrativos en el uso diario.
- **Verificación de AMSI y Microsoft Defender:** toda política de endurecimiento debe exigir protección contra alteraciones (**Tamper Protection**) en Defender, **Controlled Folder Access** y bloqueo de modificaciones en exclusiones del antivirus, registrando cambios de exclusiones en Event Log `Microsoft-Windows-Windows Defender/Operational` (Event ID **`5007`**).

## 4. Monitoreo de endpoints con Sysmon

Sysmon (*System Monitor*, parte de Microsoft Sysinternals) complementa el registro nativo de Windows proporcionando telemetría estructurada sobre eventos de alto valor analítico: creación de procesos con línea de comandos completa y hashes, carga de imágenes y DLLs, cambios en el estado de servicios y accesos anómalos entre procesos. Integrar Sysmon con una configuración curada y reenviar los registros a un SIEM permite detectar comportamientos anómalos sin saturar el almacenamiento.

## Ejemplo paso a paso: auditoría de solo lectura de servicios y protecciones en PowerShell

En este procedimiento revisamos en nuestra VM Windows de laboratorio si existen servicios con rutas potencialmente ambiguas, inspeccionamos los permisos de un directorio de aplicación y verificamos el estado de las protecciones de memoria y credenciales.

```powershell
# 1. Identificar servicios de terceros con espacios en la ruta y sin comillas dobles
Get-CimInstance -ClassName Win32_Service |
    Where-Object {
        $_.PathName -and
        $_.PathName -notmatch '^"' -and
        $_.PathName -notmatch 'C:\\Windows\\' -and
        $_.PathName -match ' '
    } |
    Select-Object Name, StartName, State, PathName
# Salida esperada en un equipo endurecido: sin resultados.
# Si aparece algún servicio, debe corregirse citando la ruta ejecutable.

# 2. Verificar permisos efectivos de la variable PATH del sistema
($env:Path -split ';') | Where-Object { $_ -ne '' } | ForEach-Object {
    if (Test-Path $_) {
        Write-Host "`n--- Directorio: $_ ---"
        icacls $_
    }
}
# Revisá que usuarios estándar (Users / Everyone / Authenticated Users)
# NO tengan permisos (M) Modify, (W) Write ni (F) Full Control.

# 3. Comprobar estado de seguridad basada en virtualización (VBS) y Credential Guard
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning
# Salida comentada:
# VirtualizationBasedSecurityStatus = 2 indica VBS activo.
# SecurityServicesRunning contiene 1 cuando Credential Guard está en ejecución.
```

### Triaje automatizado en laboratorio (`WinPEAS`) y correlación Sigma

En VMs de laboratorio aisladas, `WinPEAS` acelera el inventario de servicios sin comillas, permisos de carpetas en `PATH`, `AlwaysInstallElevated` y credenciales en caché:

```powershell
# Triaje enfocado en servicios e información del sistema dentro de VM aislada de laboratorio
.\winPEASx64.exe quiet servicesinfo systeminfo
```

- **Telemetría Blue Team:** **Sysmon Event ID `1`** / **Security `4688`** (ejecución de `winPEAS*.exe` desde `Users\Public` o `%TEMP%` seguida de ráfagas de `reg query`, `sc qc` e `icacls`), **Sysmon Event ID `11`** (*FileCreate* del binario) y **PowerShell `4104`** si se ejecuta vía script en memoria.
- **Criterio Sigma:** `ProcessCreate` con `OriginalFileName` o `CommandLine` conteniendo `winPEAS` / `servicesinfo` o correlación en ventana < 15 s de múltiples consultas `reg query` sobre `Run`, `Installer\AlwaysInstallElevated` y `Services` bajo usuario estándar.

::: defensa Perspectiva defensiva, detección y mitigación
Bajo la óptica Blue Team (tácticas de alto nivel de MITRE ATT&CK como **Privilege Escalation**, **Credential Access** y **Defense Evasion**), la protección de endpoints Windows se apoya en dos pilares:
- **Telemetría de alta señal:** Monitorear mediante Sysmon y los registros de seguridad la creación o modificación de servicios y tareas programadas, cargas de DLLs desde carpetas de usuario o temporales, y procesos no esperados que intenten abrir manejadores hacia procesos críticos del sistema.
- **Endurecimiento preventivo:** Habilitar Windows LAPS, Credential Guard y LSA Protection (`RunAsPPL`), depurar privilegios sensibles en cuentas de servicio, aplicar políticas CIS Benchmark mediante GPO/Intune y garantizar que ningún directorio del `PATH` ni ningún binario de servicio sea modificable por usuarios estándar.
:::

## Práctica en laboratorio local

En tu VM Windows de laboratorio (aislada en red Host-Only):

1. Ejecutá `whoami /all` desde una consola estándar y luego desde una consola elevada, comparando el nivel de integridad (*Medium* vs. *High*) y la lista de privilegios habilitados.
2. Corré los comandos PowerShell de auditoría de servicios sin comillas y revisión de permisos `icacls` sobre los directorios del `PATH`, registrando cualquier desviación.
3. Inspeccioná las tareas programadas no pertenecientes a Microsoft (`Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' }`) y verificá con qué cuenta se ejecutan.
4. Comprobá el estado actual de VBS/Credential Guard y documentá qué controles de endurecimiento recomendarías habilitar en ese equipo.

::: practica Entregable mínimo
Un informe breve con: la comparativa de salida de `whoami /all` (estándar vs. elevada), el resultado de la auditoría de servicios y `PATH`, el inventario de tareas programadas de terceros y una lista priorizada de acciones de hardening para la VM evaluada.
:::

## Preguntas de repaso

**1. ¿Por qué UAC no debe considerarse un límite de seguridad infalible frente a un proceso ejecutado bajo una cuenta con membresía administrativa?** Porque UAC está diseñado como un control de conveniencia para evitar elevaciones accidentales en cuentas que ya poseen derechos administrativos; la verdadera separación exige operar diariamente con una cuenta estándar sin pertenencia al grupo `Administrators`.

**2. ¿Cuál es el riesgo técnico de otorgar `SeImpersonatePrivilege` o `SeDebugPrivilege` a cuentas que no los necesitan estrictamente?** `SeImpersonatePrivilege` permite asumir identidades de clientes privilegiados que se conecten al servicio, mientras que `SeDebugPrivilege` habilita la inspección y manipulación de otros procesos del sistema; ambos privilegios pueden derivar en control total del host si la cuenta se ve comprometida.

**3. ¿Cómo se origina el problema de una ruta de servicio sin comillas y cuál es su corrección definitiva?** Se origina cuando el campo `ImagePath` de un servicio contiene espacios sin comillas dobles, induciendo a Windows a probar rutas parciales previas; la corrección consiste en encerrar la ruta del ejecutable entre comillas dobles y restringir los permisos de escritura en los directorios contenedores.

**4. ¿Qué ventaja operativa y de seguridad ofrece Windows LAPS en una red corporativa?** Automatiza la generación y rotación de contraseñas únicas por equipo para la cuenta de administrador local, impidiendo que el compromiso de un endpoint facilite el movimiento lateral hacia otros equipos mediante contraseñas compartidas.

**5. ¿Cómo se complementan LSA Protection (`RunAsPPL`) y Credential Guard para proteger credenciales en memoria?** `RunAsPPL` restringe el acceso de procesos no protegidos al espacio de memoria de `lsass.exe`, mientras que Credential Guard aísla los secretos de autenticación mediante virtualización por hardware (VBS) para que no queden expuestos al sistema operativo principal.

## Antes de avanzar

- [ ] Distinguís con claridad los niveles de integridad, SIDs y privilegios del token en Windows.
- [ ] Sabés auditar permisos de servicios, rutas sin comillas y tareas programadas mediante PowerShell e `icacls`.
- [ ] Comprendés el mecanismo del orden de búsqueda de DLLs y cómo prevenirlo con ACLs y rutas seguras.
- [ ] Conocés el propósito y los requisitos de Windows LAPS, `RunAsPPL` y Credential Guard.
- [ ] Comprendés qué valor aporta Sysmon al monitoreo defensivo de endpoints Windows.

::: nota Puerta de salida
Con los Capítulos 3.1 a 3.4 completos consolidaste las bases operativas y defensivas de sesiones, contraseñas y escalada local tanto en Linux como en Windows. Asegurate de respaldar tus notas y políticas de hardening antes de iniciar la Parte B del Tomo III.
:::

## Referencias y estándares abiertos

- Microsoft Learn: *Access Control Overview, Integrity Levels y User Account Control* (https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/access-control)
- Microsoft Learn: *Windows LAPS Overview* y *Configure Additional LSA Protection* (https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- Microsoft Learn: *Windows Defender Credential Guard Overview* (https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- Microsoft Sysinternals: *Sysmon Documentation* (https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- CIS Benchmarks: *CIS Microsoft Windows Enterprise Benchmarks* y MITRE ATT&CK Enterprise Matrix (https://www.cisecurity.org/cis-benchmarks y https://attack.mitre.org/)
