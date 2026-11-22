::: nota Objetivo de la lección
Al terminar este capítulo vas a saber habilitar telemetría de seguridad de alto valor en endpoints Windows (Audit Policy, PowerShell Script Block Logging y Sysmon) y Linux (`auditd` y `journald`), entendiendo cómo esta base alimenta soluciones EDR/XDR y endurecimiento defensivo en tu laboratorio local.
:::

**Prerrequisitos:** Conocimientos básicos de administración de Windows (PowerShell, visores de eventos) y Linux (`systemd`, permisos y consola). **Duración sugerida:** 2 a 3 horas de práctica en VMs aisladas.

## 1. Fundamentos de telemetría de endpoints y arquitectura EDR/XDR

Sin registros estructurados en los sistemas finales, un equipo defensivo opera a ciegas. Los sistemas operativos traen auditoría mínima por defecto para ahorrar disco y CPU, pero esa configuración omite datos esenciales como argumentos de línea de comandos, relaciones padre-hijo entre procesos o consultas DNS por proceso.

Las plataformas **EDR** (*Endpoint Detection and Response*) recopilan telemetría del kernel y del espacio de usuario en cada host para detectar comportamientos anómalos y aislar equipos. **XDR** (*Extended Detection and Response*) amplía esa correlación uniendo señales del endpoint con red, identidad y correo bajo una misma línea de tiempo. En un laboratorio propio, combinar la auditoría nativa de Windows/Linux con **Sysmon** reproduce gran parte de la visibilidad base de un agente EDR moderno.

## 2. Auditoría avanzada en Windows y registros nativos

Windows organiza sus eventos en canales (como `Security`, `System` y `Microsoft-Windows-PowerShell/Operational`). Para evitar volúmenes inmanejables de ruido, conviene agrupar la visibilidad en **tres dominios padre** prioritarios:

| Dominio de telemetría | Qué permite detectar | Eventos representativos clave |
| --- | --- | --- |
| **Identidad y Acceso** | Inicios de sesión interactivos/remotos, fallos reiterados, uso de privilegios elevados y tickets de dominio | Logons exitosos y fallidos (`4624` con tipo de logon, `4625`), privilegios especiales (`4672`), gestión de cuentas y tickets Kerberos/NTLM (`4720`, `4768`, `4769`, `4776`). |
| **Ejecución y Scripts** | Lanzamiento de procesos con argumentos completos y ejecución de bloques de código en memoria | Creación de procesos con línea de comandos (`4688`) y PowerShell Script Block Logging (`4104`). |
| **Persistencia y Servicios** | Instalación de nuevos servicios del sistema que puedan ejecutarse con privilegios altos | Instalación de un nuevo servicio (`7045` en el canal `System`). |

### Activación de Audit Policy y Script Block Logging

En una VM Windows de laboratorio (PowerShell como Administrador), habilitá la auditoría avanzada de procesos y la captura de línea de comandos:

```powershell
# Habilitar auditoría de creación de procesos y eventos de inicio de sesión
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Incluir argumentos de línea de comandos en el evento 4688
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force

# Verificar política activa
auditpol /get /category:"Detailed Tracking"
```

Para auditar scripts ofuscados o ejecutados directamente en memoria, habilitá **PowerShell Script Block Logging** (`4104`) mediante GPO o clave de política en el laboratorio:

```powershell
# Activar Script Block Logging para PowerShell en laboratorio
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
```

::: aviso Gestión del volumen de logs
Habilitar auditoría avanzada incrementa el consumo de disco. Ajustá el tamaño máximo del canal `Security` (por ejemplo, ≥ 256 MB en laboratorio) con `wevtutil sl Security /ms:268435456` para evitar que los eventos recientes sobrescriban evidencias críticas.
:::

## 3. Sysmon: arquitectura, instalación y filtrado XML

**Sysmon** (System Monitor, de Microsoft Sysinternals) corre como un servicio y controlador de sistema que registra actividad detallada en `Microsoft-Windows-Sysmon/Operational`. A diferencia de los logs nativos, añade hashes criptográficos, árbol de procesos padre-hijo, GUID único por proceso y asociación directa entre conexiones de red y el ejecutable que las originó.

Al igual que los logs nativos, sus eventos se agrupan en las mismas categorías de análisis:

- **Procesos e integridad:** Creación de procesos con hashes (`ID 1`), carga de bibliotecas (`ID 7`), hilos remotos (`ID 8`) y acceso entre procesos (`ID 10`).
- **Red y resolución de nombres:** Conexiones TCP/UDP salientes o entrantes (`ID 3`) y consultas DNS asociadas al proceso origen (`ID 22`).
- **Sistema de archivos y configuración:** Creación de archivos (`ID 11`) y cambios en valores de configuración del sistema (`ID 13`).

### Diseño de una configuración XML mantenible

El principio clave de Sysmon es filtrar ruido benigno (*exclusions*) mientras se capturan comportamientos relevantes (*inclusions*). Usar reglas vacías o capturar todo sin filtro satura el SIEM.

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <!-- Capturar creación de procesos excluyendo telemetría ruidosa del propio sistema -->
    <RuleGroup name="Procesos" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\conhost.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Registrar conexiones de red y DNS originadas por intérpretes o rutas temporales -->
    <RuleGroup name="Red_y_DNS" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image condition="contains any">powershell.exe;cmd.exe;python.exe</Image>
      </NetworkConnect>
      <DnsQuery onmatch="exclude">
        <QueryName condition="end with">.local</QueryName>
      </DnsQuery>
    </RuleGroup>

    <!-- Monitorear creación de ejecutables o scripts en directorios temporales -->
    <RuleGroup name="Archivos" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\Temp\</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Para instalar o actualizar la configuración en tu VM Windows de pruebas:

```powershell
# Instalación inicial con aceptación de licencia y archivo XML
.\Sysmon64.exe -accepteula -i .\sysmon-lab.xml

# Recargar configuración tras ajustes sin reiniciar el host
.\Sysmon64.exe -c .\sysmon-lab.xml
```

## 4. Telemetría equivalente en Linux: auditd y journald

En sistemas Linux, la visibilidad equivalente se logra combinando **journald** (registros de servicios y autenticación del sistema) con el subsistema de auditoría del kernel **auditd**.

| Componente | Rol principal | Herramienta de consulta |
| --- | --- | --- |
| **auditd** | Registra llamadas al sistema (`execve`), acceso a archivos críticos y cambios de privilegios en el kernel | `ausearch` y `aureport` |
| **journald** | Centraliza logs estructurados de unidades `systemd`, kernel y demonios como `sshd` o `sudo` | `journalctl` |

### Reglas básicas de auditd para laboratorio

Podés cargar reglas temporales con `auditctl` o hacerlas persistentes en `/etc/audit/rules.d/soc-lab.rules`:

```bash
# Vigilar cambios en identidad y configuración de privilegios
sudo auditctl -w /etc/passwd -p wa -k identidad_cambios
sudo auditctl -w /etc/sudoers -p wa -k privilegios_sudo

# Auditar ejecución de comandos en arquitectura de 64 bits
sudo auditctl -a always,exit -F arch=b64 -S execve -k ejecucion_procesos

# Listar reglas activas
sudo auditctl -l
```

## 5. Plataforma unificada open-source: Wazuh (SIEM + XDR) en laboratorio

Para practicar telemetría de endpoints a escala sin depender de licencias comerciales, **`Wazuh`** reúne capacidades de agente HIDS/EDR y análisis centralizado tipo SIEM en una sola arquitectura de código abierto:

- **Agente Wazuh (`wazuh-agent`):** corre en Windows, Linux y macOS; lee Windows Event Log + **Sysmon** (ver nuestro archivo listo para laboratorio `laboratorios/sysmon_config_lab.xml`), monitorea integridad de archivos (**FIM**, *File Integrity Monitoring*), detecta cambios de configuración contra **CIS Benchmarks (SCA)** y reenvía eventos cifrados al servidor central.
- **Manager e Indexer:** normaliza eventos mediante **decoders** y los evalúa contra **reglas XML jerárquicas** con niveles de severidad (`local_rules.xml`), pudiendo disparar respuestas activas controladas (*Active Response*) o alertas en **Wazuh Dashboard**.

## Ejemplo paso a paso: Correlación de telemetría en Windows y Linux

En este ejercicio verificamos cómo queda registrada una ejecución controlada en ambos sistemas operativos dentro de tu laboratorio aislado.

**Paso 1 (Windows):** Ejecutar un comando inofensivo y consultar el evento en Sysmon y PowerShell.

```powershell
# Generar evento controlado en laboratorio
powershell.exe -NoProfile -Command "Write-Output 'Prueba de telemetria Lab'"

# Consultar el último evento de creación de proceso en Sysmon (ID 1)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 1 |
  Format-List TimeCreated, Message
```

```text
# Salida comentada (resumida)
TimeCreated : 22/11/2026 15:20:11
Message     : Process Create:
              Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
              CommandLine: powershell.exe -NoProfile -Command "Write-Output 'Prueba de telemetria Lab'"
              ParentImage: C:\Windows\System32\cmd.exe
              Hashes: SHA256=D94F...
# Confirmamos ruta exacta, argumentos completos, proceso padre y hash SHA256.
```

**Paso 2 (Linux):** Consultar ejecuciones y autenticación reciente con `ausearch` y `journalctl`.

```bash
# Buscar eventos etiquetados con la clave ejecucion_procesos en los últimos 10 minutos
sudo ausearch -k ejecucion_procesos -ts recent | tail -n 12

# Revisar autenticaciones SSH recientes en journald
sudo journalctl -u ssh --since "30 minutes ago" --no-pager | tail -n 10
```

```text
# Salida comentada (auditd)
type=SYSCALL msg=audit(1795371615.204:412): arch=c000003e syscall=59 success=yes uid=1000 comm="whoami" exe="/usr/bin/whoami" key="ejecucion_procesos"
# syscall=59 corresponde a execve; uid=1000 identifica al usuario ejecutor y exe confirma el binario real.
```

::: defensa Perspectiva defensiva, detección y mitigación
La telemetría solo protege si se combina con endurecimiento y resguardo de registros:
- **Endurecimiento preventivo:** Aplicá el principio de mínimo privilegio, restringí PowerShell con *Constrained Language Mode* para usuarios estándar y deshabilitá servicios innecesarios para reducir superficie de ataque.
- **Protección de logs:** Reenviá eventos en tiempo real a un servidor central (SIEM) para evitar que un atacante borre evidencia local; monitoreá también la limpieza inesperada del registro de eventos o la detención del servicio Sysmon/`auditd`.
- **Cobertura por táctica:** Con esta configuración cubrís de base las tácticas padre de **Ejecución**, **Persistencia** y **Acceso Inicial** en endpoints.
:::

## Práctica en laboratorio local

En tus VMs aisladas (Windows y Linux), aplicá las políticas de auditoría vistas en este capítulo: instalá Sysmon con el archivo `sysmon-lab.xml`, activá Script Block Logging y cargá las tres reglas de `auditctl` en Linux. Luego ejecutá tres acciones benignas (una consulta DNS, creación de un archivo en `\Temp\` y un comando `sudo -l`) y verificá que cada una quede registrada.

::: practica Entregable mínimo
Guardá un documento `evidencia_telemetria.md` que incluya:
1. Salida de `auditpol /get /category:"Detailed Tracking"` y versión activa de Sysmon en tu VM Windows.
2. Un fragmento real de un evento `ID 1` (Sysmon) y un evento `4104` (PowerShell) de tu prueba benigna.
3. Salida de `sudo auditctl -l` y un registro filtrado con `ausearch -k` de tu VM Linux.
4. Dos propuestas concretas de exclusión para reducir ruido que observaste durante la práctica.
:::

## Preguntas de repaso

**1. ¿Por qué no alcanza con activar el evento 4688 en Windows sin habilitar la captura de línea de comandos?** Porque sin los argumentos de ejecución solo sabrás que se lanzó un binario genérico como `powershell.exe` o `cmd.exe`, perdiendo la visibilidad sobre qué script, parámetro o acción se invocó realmente.

**2. ¿Qué ventaja central aporta Sysmon frente a los registros nativos de Windows?** Sysmon enriquece cada evento con hashes criptográficos, identificadores únicos de proceso (ProcessGuid) y correlación directa entre procesos, conexiones de red y consultas DNS mediante una configuración XML flexible.

**3. ¿Cuál es la diferencia operativa entre `auditd` y `journald` en Linux?** `auditd` captura eventos a nivel de kernel (como llamadas al sistema `execve` y accesos a archivos sensibles) con foco forense y de cumplimiento, mientras que `journald` centraliza los logs operativos de servicios `systemd` y demonios del sistema.

**4. ¿Por qué se recomienda reenviar la telemetría de endpoints hacia un repositorio central externo?** Porque un atacante con privilegios locales puede detener el agente o limpiar los registros en el equipo comprometido; el reenvío inmediato preserva la evidencia fuera de su alcance.

**5. ¿Cómo se diferencia una solución XDR de un EDR tradicional?** Un EDR concentra detección y respuesta sobre la telemetría de endpoints, mientras que XDR integra y correlaciona señales de múltiples capas (endpoints, red, identidad y nube) para contextualizar incidentes completos.

## Antes de avanzar

- [ ] Habilitaste auditoría de procesos con línea de comandos y Script Block Logging en tu VM Windows.
- [ ] Instalaste Sysmon con una configuración XML filtrada y validaste eventos locales.
- [ ] Configuraste reglas en `auditd` y consultaste registros con `ausearch` y `journalctl`.
- [ ] Comprendés cómo balancear visibilidad y ruido para no saturar almacenamiento ni analistas.

::: nota Puerta de salida
Ya generás telemetría rica y estructurada en Windows y Linux. En el próximo capítulo vas a centralizar estos registros en un SIEM y escribir búsquedas y correlaciones prácticas en Splunk (SPL) y Elastic (KQL).
:::

## Referencias y estándares abiertos

- Microsoft Learn — *Sysmon (Sysinternals)*: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Microsoft Learn — *Advanced Security Audit Policy Settings*: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings
- CIS Benchmarks (Microsoft Windows & Linux Distribution Benchmarks): https://www.cisecurity.org/cis-benchmarks
- Linux Audit Project (`auditd` / `auditctl` documentation): https://github.com/linux-audit/audit-documentation
