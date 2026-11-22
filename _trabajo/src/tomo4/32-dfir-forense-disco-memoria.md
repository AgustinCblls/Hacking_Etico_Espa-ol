::: nota Objetivo de la lección
Al finalizar este capítulo vas a saber planificar una adquisición forense digital íntegra siguiendo el orden de volatilidad (RFC 3227) y la cadena de custodia, interpretar los artefactos clave de evidencia de ejecución, archivos, red y persistencia en Windows (`$MFT`, Prefetch, ShimCache, AmCache, SRUM, Registro y EVTX) y Linux (`ext4`, `wtmp/btmp`, `cron/systemd` y MACB), usar herramientas de triage a escala (KAPE / Velociraptor) y correlacionar memoria RAM con **Volatility 3** (conectando además con el curso hermano **Curso de Reversing en Windows** para análisis profundo de estructuras internas de Windows).
:::

**Prerrequisitos:** Capítulos 1.3–1.4 (Sistemas Linux y Windows), 4.2 (Telemetría Sysmon/auditd) y 4.6 (Threat Hunting). **Duración sugerida:** 9 a 11 horas.

## 1. Principios de informática forense: orden de volatilidad y cadena de custodia

La disciplina **DFIR (*Digital Forensics and Incident Response*)** persigue dos metas que deben equilibrarse bajo presión operativa: **contener la intrusión rápido** y **preservar la evidencia digital sin alterarla** para reconstruir con certeza qué pasó, cuándo entró, qué cuentas o datos tocó y cómo erradicar la causa raíz.

### Orden de volatilidad (RFC 3227)

Al recolectar evidencia de un equipo comprometido, siempre se avanza desde los datos más efímeros hacia los más persistentes (si apagás un servidor por pánico antes de capturar su RAM o sus conexiones activas, perdés evidencia irrecuperable):

1. **Registros de CPU, caché y memoria RAM:** procesos ocultos o sin archivo en disco (*fileless*), claves de cifrado en memoria, líneas de comando completas y sockets abiertos.
2. **Estado volátil del sistema y red:** tabla ARP, conexiones activas, rutas, sesiones abiertas e interfaces.
3. **Sistemas de archivos en disco local:** artefactos de NTFS/ext4, logs locales EVTX/`/var/log`, archivos temporales y volcados previos.
4. **Logs remotos archivados y copias de seguridad:** telemetría ya enviada al SIEM y backups offline.

### Cadena de custodia e integridad probatoria

Toda evidencia recolectada (imagen de RAM, disco o paquete de triage) debe ir acompañada de su **Acta de Cadena de Custodia** registrando: identificador del equipo, fecha y hora exacta en **UTC**, persona que adquirió la muestra, herramienta utilizada y **hash criptográfico SHA-256** calculado en el instante de la adquisición. Nunca trabajes sobre el disco original ni montes imágenes de disco en modo lectura-escritura: analizá siempre copias verificadas montadas como solo lectura (`-o ro`).

## 2. Mapa completo de artefactos forenses en Windows

Incluso si alguien borra un archivo ejecutable o limpia parte de los logs visibles, Windows conserva decenas de huellas cruzadas en el sistema de archivos NTFS y en los ficheros de colmena (*hives*) del Registro:

| Pregunta forense | Artefacto clave de Windows | Ubicación en disco / Registro | Qué evidencia concreta aporta |
|---|---|---|---|
| **¿Qué archivos existieron y cuándo se crearon/modificaron?** | **`$MFT` y `$UsnJrnl`** | Raíz del volumen NTFS (`\$MFT`, `\$Extend\$UsnJrnl:$J`) | Registro maestro de todos los archivos, tamaños, permisos y **dos conjuntos de timestamps** (`$STANDARD_INFORMATION` modificable vs `$FILE_NAME` actualizado por el kernel, útil para detectar *timestomping*). |
| **¿Qué programas se ejecutaron en el equipo?** | **Windows Prefetch (`.pf`)** | `C:\Windows\Prefetch\<BINARIO>-<HASH>.pf` | Confirma hasta las últimas 8 fechas/horas de ejecución, el contador total de ejecuciones y archivos/DLLs cargados durante los primeros 10 segundos. |
| **¿Qué binarios existieron o corrieron aunque luego se borraran?** | **ShimCache (`AppCompatCache`) y AmCache** | `SYSTEM\...\AppCompatCache` y `C:\Windows\AppCompat\Programs\Amcache.hve` | Lista histórica de ejecutables vistos por Windows, incluyendo en **AmCache** el **hash SHA-1**, tamaño y metadatos de versión PE. |
| **¿Qué ejecutó manualmente el usuario o qué estuvo en segundo plano?** | **UserAssist, BAM/DAM y MuiCache** | `NTUSER.DAT\...\UserAssist` y `SYSTEM\...\Services\bam\State` | Programas lanzados desde el Explorador gráfico (`UserAssist`, codificado en ROT-13), fecha exacta de última ejecución y ruta completa (`BAM`). |
| **¿Qué carpetas y archivos abrió el usuario?** | **ShellBags, LNK y JumpLists** | `UsrClass.dat\...\BagMRU` y `%APPDATA%\Microsoft\Windows\Recent\` | Demuestra acceso a carpetas locales, unidades USB o recursos compartidos `\\servidor\carpeta` incluso después de desconectarlos o borrarlos. |
| **¿Cuánto tráfico de red y CPU consumió cada binario?** | **SRUM (*System Resource Usage Monitor*)** | `C:\Windows\System32\sru\SRUDB.dat` (ESE DB) | Registra por hora el binario exacto, usuario (`SID`), bytes enviados/recibidos por interfaz de red y ciclos de CPU durante los últimos 30–60 días. |
| **¿Qué dispositivos USB se conectaron?** | **USBSTOR y `setupapi.dev.log`** | `SYSTEM\...\Enum\USBSTOR` y `C:\Windows\inf\setupapi.dev.log` | Número de serie del dispositivo USB, marca/modelo, primera y última fecha de conexión y letra de unidad montada. |

::: aviso Cómo detectar manipulación de fechas (*Timestomping*)
En NTFS cada archivo posee marcas MACB en el atributo `$STANDARD_INFORMATION` (que herramientas de usuario pueden alterar) y un segundo juego en `$FILE_NAME` (gestionado por el núcleo de NTFS). Si un binario presenta en `$STANDARD_INFORMATION` una fecha de creación de hace cinco años (ej. 2021) pero su `$FILE_NAME` o su entrada en `$UsnJrnl` y Prefetch datan de hoy, quedás frente a una señal inequívoca de alteración temporal.
:::

## 3. Artefactos forenses en Linux y paralelismos en macOS

En servidores Linux (`ext4` / `xfs`), la investigación se concentra en registros de texto, archivos binarios de sesión, tareas programadas y metadatos del sistema de archivos:

- **Sesiones e historial:** `/var/log/wtmp` (accesos exitosos leídos con `last`), `/var/log/btmp` (intentos fallidos leídos con `lastb`), `/var/log/lastlog`, `/var/log/auth.log` o `/var/log/secure` y historiales `~/.bash_history` / `~/.zsh_history`.
- **Mecanismos de persistencia:** unidades de servicio en `/etc/systemd/system/` y `/lib/systemd/system/`, tareas cron en `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/crontabs/`, claves autorizadas en `~/.ssh/authorized_keys` y scripts de perfil (`/etc/profile.d/`).
- **Marcas temporales MACB en inodos (`stat`):** *Modified* (contenido), *Accessed* (última lectura), *Changed* (cambio de metadatos/permisos del inodo) y *Birth* (creación en `ext4` moderno).

En entornos **macOS**, la estructura equivalente combina los **Unified Logs** (`log show`), **FSEvents** (historial de cambios del sistema de archivos APFS), **`LaunchAgents` / `LaunchDaemons`** (`.plist` de persistencia), cuarentena (`com.apple.quarantine` / base SQLite de descargas) y bases SQLite de navegadores y TCC.

## 4. Triage a escala (KAPE / Velociraptor) y memoria RAM con Volatility 3

Cuando un incidente involucra decenas de equipos (por ejemplo, contención de ransomware o movimiento lateral en Active Directory), clonar discos de 1 TB por la red tardaría horas o días. Por eso los equipos DFIR modernos usan **triage dirigido a escala** y **análisis de memoria RAM**:

- **KAPE (*Kroll Artifact Parser and Extractor*):** recolecta y analiza selectivamente en menos de 3 minutos los artefactos críticos (`$MFT`, hives del Registro, Prefetch, EVTX, SRUM, LNK), reduciendo 1 TB de disco a un paquete de triage de ~300 MB.
- **Velociraptor:** plataforma cliente-servidor de código abierto que permite lanzar consultas **VQL (*Velociraptor Query Language*)** en tiempo real sobre toda la flota para recolectar artefactos, inspeccionar procesos y cazar indicadores simultáneamente en Windows, Linux y macOS.

### Plugins esenciales de Volatility 3 para memoria RAM

Un volcado de memoria (`.raw`, `.dmp`, `.vmem`) conserva estado vivo que nunca existió en disco o que ya fue eliminado:

| Plugin de Volatility 3 | Qué extrae de la RAM | Señal típica de alerta |
|---|---|---|
| `windows.info` / `banners` | Perfil del kernel, versión exacta del SO y fecha/hora de captura de la imagen. | Base obligatoria para ubicar símbolos (PDB/DWARF). |
| `windows.pslist` / `windows.pstree` | Procesos activos y árbol padre-hijo (*PPID → PID*). | Procesos anómalos bajo `winword.exe`, `w3wp.exe` o `services.exe`; nombres mal escritos (`svch0st.exe`). |
| `windows.psscan` | Busca estructuras `_EPROCESS` directamente en memoria física. | Descubre procesos ocultos o ya terminados poco antes del volcado (*unlinked processes*). |
| `windows.cmdline` | Argumentos exactos de línea de comando con los que arrancó cada proceso. | Comandos codificados, cargas desde `C:\Users\Public` o `AppData`. |
| `windows.netscan` | Sockets TCP/UDP abiertos, puertos locales y direcciones remotas por PID. | Sesiones `ESTABLISHED` desde procesos sin función de red (`notepad.exe`, `regsvr32.exe`). |
| `windows.malfind` | Regiones de memoria privada con permisos `PAGE_EXECUTE_READWRITE` sin archivo PE respaldado en disco. | Indicios de inyección de código en memoria o desensamblado no respaldado por módulo legítimo. |

*(Puente con la obra hermana: si querés profundizar en cómo Windows representa internamente los objetos `_EPROCESS`, el VAD (*Virtual Address Descriptor*), las colmenas del Registro, servicios, COM/RPC y ETW en el kernel, consultá la **Rama 2D · Windows Internals y Virtualización** de [Curso de Reversing en Windows](../../CLS_Guia/2d.html) dentro del paquete hermano).*

### Adquisición forense, artefactos de navegador y detección de antiforense

Una investigación DFIR robusta no solo analiza una instantánea aislada de memoria; también garantiza la preservación física del almacenamiento, reconstruye la actividad inicial del usuario en navegadores y detecta intentos del atacante por borrar sus huellas:

- **Adquisición de disco y RAM (`FTK Imager`, `LiME`, `dd`, `Autopsy` y efecto `TRIM` en SSD):** Siguiendo el orden de volatilidad, la memoria RAM se adquiere primero en vivo (`DumpIt`/`WinPmem` en Windows; el módulo de kernel **LiME** en Linux para volcar páginas físicas a un formato `.lime` analizable en Volatility 3) antes de desmontar o clonar el almacenamiento mediante herramientas de solo lectura (`dd` con bloqueadores de escritura o formatos forenses `E01` con `FTK Imager`) y correlacionarlo en suites como `Autopsy`. Conviene considerar una diferencia crítica de hardware: en discos mecánicos HDD los archivos eliminados suelen recuperarse por *data carving* mientras no se sobrescriban, mientras que en unidades **SSD/NVMe** el comando **`TRIM`** y la recolección interna de bloques (*garbage collection*) pueden poner a cero las páginas liberadas en cuestión de segundos o minutos, haciendo indispensable la adquisición rápida del volumen completo y el examen de `$MFT` / `$UsnJrnl`.
- **Forense de navegadores web (SQLite y *Hindsight*):** Muchos compromisos iniciales comienzan en el navegador. Los perfiles Chromium/Edge y Firefox almacenan su actividad en bases SQLite locales (`History`, `Downloads`, `Cookies`, `Login Data` en Chromium; `places.sqlite` en Firefox). Copiar el perfil en modo solo lectura y procesarlo con herramientas dedicadas como **`Hindsight`** permite reconstruir cadenas completas de URL visitadas, descargas originales, redirecciones HTTP, *Cache* y marcas de tiempo en formato WebKit/PRTime para responder cómo llegó el archivo al equipo.
- **Técnicas antiforense y su detección (*ADS*, borrado de eventos y *Timestomping*):** Cuando un operador intenta ocultar binarios o limpiar evidencia deja artefactos secundarios detectables:
  - **Borrado de registros de eventos:** Limpiar *Security* (`Event ID 1102`) o *System* (`Event ID 104`) en Windows destruye eventos previos, pero el propio borrado genera de inmediato un evento de auditoría de limpieza, al igual que las brechas temporales abruptas en la secuencia de `RecordNumber` o en `/var/log/` truncado en Linux.
  - **Alternate Data Streams (`ADS`) en NTFS:** Permiten adjuntar contenido oculto detrás del flujo principal (`archivo.txt:oculto`), incluyendo el indicador legítimo `Zone.Identifier` que registra desde qué URL fue descargado un archivo. Se auditan con `dir /r` o `Get-Item -Path <ruta> -Stream *` en PowerShell.
  - **Timestomping:** Alterar fechas de modificación visibles no siempre actualiza simultáneamente ambos conjuntos de metadatos en NTFS; comparar las marcas de `$STANDARD_INFORMATION` frente a `$FILE_NAME` dentro de la `$MFT` suele delatar la discrepancia cronológica, al igual que rastrear remanentes en `$UsnJrnl` de utilidades de *artifact wiping*.

## 5. Ejemplo paso a paso: cadena de custodia, línea temporal MACB y Volatility 3

Veamos un flujo completo y reproducible en laboratorio Linux para verificar integridad SHA-256 de una imagen de disco o memoria de práctica, construir una micro-timeline ordenada en **UTC** y correlacionar salidas de Volatility 3:

```bash
# 1. Registrar hash criptográfico de la evidencia recibida ANTES de abrirla
sha256sum evidencia_lab.raw > evidencia_lab.sha256
sha256sum -c evidencia_lab.sha256

# 2. Extraer marcas temporales MACB en UTC de un directorio o volumen montado en solo lectura (-o ro)
TZ=UTC find /mnt/evidencia_ro -printf "%TY-%Tm-%TdT%TH:%TM:%TSZ | M | %u:%g | %s | %p\n" 2>/dev/null | sort

# 3. Correlacionar procesos, argumentos y red en un volcado de memoria Windows con Volatility 3
vol -f evidencia_lab.raw windows.pstree
vol -f evidencia_lab.raw windows.cmdline --pid 4512
vol -f evidencia_lab.raw windows.netscan
```

Salida comentada de la correlación (todo expresado en UTC):

```text
# Verificacion de integridad:
evidencia_lab.raw: OK

# Extracto windows.pstree:
PID   PPID  ImageFileName   CreateTime (UTC)
1048  612   services.exe    2026-11-22 14:01:02Z
4410  3120  winword.exe     2026-11-22 14:22:18Z
4512  4410  cmd.exe         2026-11-22 14:22:21Z  <-- Hijo anomalo tras abrir documento

# Extracto windows.netscan para PID 4512:
Proto  LocalAddr       ForeignAddr        State        PID   Owner
TCPv4  192.168.56.20   198.51.100.88:443  ESTABLISHED  4512  cmd.exe
```

Al alinear los eventos del `$MFT`, Prefetch, EVTX y `windows.pstree`/`netscan` sobre un único reloj en **UTC**, se construye una **Supertimeline** (frecuentemente generada con **Plaso / `log2timeline`**) que responde de punta a punta qué ocurrió minuto a minuto.

::: defensa Perspectiva defensiva y mitigación
1. **Preparación antes del incidente (*DFIR Readiness*):** sincronizá relojes con NTP hacia servidores internos fiables y centralizá registros (EVTX, Sysmon, `auditd`, DNS, proxy) fuera de los hosts para que un borrado local no borre la historia completa.
2. **No apagar antes de aislar:** ante un incidente activo, aislá primero el host a nivel de red (vía EDR o VLAN de cuarentena) conservando la memoria RAM encendida para capturar procesos volátiles antes de reiniciar.
:::

## Práctica en laboratorio local

En tu VM Linux de laboratorio (red aislada Host-Only):

1. Creá un volumen pequeño de práctica de 16 MB (`dd if=/dev/zero of=/tmp/disco_dfir.img bs=1M count=16 && mkfs.ext4 /tmp/disco_dfir.img`), montalo temporalmente para crear 3 archivos (`nota.txt`, `script_prueba.sh`, `temporal.log`), modificá uno, borrá `temporal.log` y desmontalo.
2. Calculá el **SHA-256** de `/tmp/disco_dfir.img` **antes** y **después** de volver a montarlo estrictamente en modo solo lectura (`sudo mount -o ro,noloop /tmp/disco_dfir.img /mnt/dfir_ro`) para verificar que el montaje forense en solo lectura conserva idéntico el hash bit a bit.
3. Generá una línea temporal ordenada en UTC de `/mnt/dfir_ro` con `TZ=UTC stat` o `find -printf` y exportala a `timeline_lab.csv`.

::: practica Entregable mínimo
Acta breve de cadena de custodia con los hashes SHA-256 idénticos antes y después del montaje `-o ro`, tabla MACB en UTC (`timeline_lab.csv`) y matriz resumen de qué cinco artefactos Windows (de `$MFT`, Prefetch, AmCache, SRUM, EVTX) recolectarías primero ante un incidente en tu laboratorio.
:::

## Preguntas de repaso

**1. ¿Por qué el RFC 3227 exige recolectar el contenido de la memoria RAM antes que clonar el disco duro?** Porque la memoria RAM es volátil: contiene procesos en ejecución, sockets abiertos, argumentos en memoria e incluso código inyectado sin respaldo en disco que se destruye irreversiblemente si se apaga o reinicia el equipo.

**2. ¿Qué diferencia forense existe entre los timestamps de `$STANDARD_INFORMATION` y `$FILE_NAME` dentro del `$MFT` de NTFS?** `$STANDARD_INFORMATION` almacena las fechas visibles normalmente en el sistema y puede modificarse desde herramientas en modo usuario (*timestomping*); `$FILE_NAME` es mantenido internamente por el kernel de NTFS al crear o renombrar el archivo, por lo que una discrepancia marcada entre ambos revela manipulación temporal.

**3. ¿Qué evidencia específica aportan `Prefetch` y `AmCache` en Windows que no ofrece un listado simple de archivos del volumen?** `Prefetch` confirma que el ejecutable fue realmente lanzado (con hasta las últimas 8 marcas temporales de ejecución, conteo y DLLs cargadas), mientras que `AmCache` conserva el hash SHA-1 y metadatos PE del ejecutable incluso si el archivo ya fue eliminado del disco.

**4. ¿Cuándo conviene usar KAPE o Velociraptor en lugar de adquirir imágenes bit a bit de discos completos?** En incidentes con múltiples equipos o contención urgente donde clonar terabytes completos tomaría horas o días; el triage dirigido extrae en pocos minutos los artefactos clave de ejecución, persistencia y logs de toda la flota.

**5. ¿Por qué todas las líneas de tiempo forenses (*supertimelines*) deben normalizarse obligatoriamente a UTC?** Para correlacionar con precisión eventos generados por servidores, estaciones, firewalls, proxies y registros en distintos husos horarios o cambios de horario de verano sin introducir desfases artificiales de horas en la cronología.

## Antes de avanzar

Verificá que podés:
- Explicar el orden de volatilidad (RFC 3227) y aplicar cadena de custodia con SHA-256 y montaje solo lectura.
- Asociar cada pregunta de investigación (archivos, ejecución, red, USB, carpetas) con su artefacto Windows/Linux exacto.
- Interpretar salidas básicas de Volatility 3 (`pstree`, `psscan`, `cmdline`, `netscan`, `malfind`) y alinear eventos en UTC.

::: nota Puerta de salida
Avanzá al último capítulo de la obra (**Capítulo 4.8 · Triage estático de malware, desofuscación y telemetría de bajo nivel**) para integrar inspección estática segura, sensores ETW/AMSI, el puente completo con **Curso de Reversing en Windows** y el reporte ejecutivo/técnico de incidentes.
:::

## Referencias y estándares abiertos

- **RFC 3227 (*Guidelines for Evidence Collection and Archiving*):** orden de volatilidad y preservación de evidencia digital.
- **NIST SP 800-86 (*Guide to Integrating Forensic Techniques into Incident Response*).**
- **Volatility Foundation — Documentación oficial de Volatility 3** y **Velociraptor VQL Docs.**
- **Obra hermana [`Curso de Reversing en Windows`](../../CLS_Guia/2d.html):** Rama 2D de *Windows Internals* (VAD, Registro, Servicios, Objetos y ETW).
