::: nota Objetivo de la lección
Al completar este capítulo vas a poder navegar y auditar la jerarquía FHS de Linux, interpretar cuentas y privilegios en `/etc/passwd`, `/etc/shadow` y `/etc/sudoers`, calcular y revisar permisos octales, bits especiales (SUID, SGID, Sticky Bit) y ACLs POSIX, inspeccionar procesos en `/proc`, administrar servicios `systemd`, revisar sockets locales con `ss` y analizar registros con `journalctl` y `/var/log/auth.log`.
:::

**Prerrequisitos:** Capítulo 1.2 completado y una máquina virtual Linux de laboratorio (Debian o Ubuntu LTS recomendada) en red aislada. **Duración sugerida:** 2,5 horas.

## Jerarquía del sistema de archivos (FHS) con foco de seguridad

En Linux, todo recurso (archivos, directorios, discos, sockets y datos del kernel) se representa bajo un único árbol que comienza en `/`. El estándar **FHS (Filesystem Hierarchy Standard)** organiza cada ruta con un propósito definido; conocerlo acelera tanto la auditoría de configuración como la respuesta ante incidentes.

| Ruta FHS | Contenido habitual | Interés en auditoría y defensa |
| :--- | :--- | :--- |
| `/etc` | Archivos de configuración globales del sistema y servicios. | Verificar permisos de escritura restrictivos (`root:root`), `sudoers`, `sshd_config` y tareas `cron`. |
| `/var/log` | Registros persistentes del kernel, autenticación y demonios. | Fuente primaria de evidencia (`auth.log`, `syslog`, `nginx/access.log`). |
| `/proc` | Pseudosistema de archivos en memoria expuesto por el kernel. | Inspección viva de procesos (`/proc/<pid>`), sockets y parámetros de red (`/proc/sys`). |
| `/tmp` y `/dev/shm` | Directorios temporales escribibles por cualquier usuario. | Puntos frecuentes para binarios temporales o scripts; deben montarse con `noexec,nosuid,nodev`. |
| `/usr/bin`, `/usr/sbin` | Binarios estándar de usuario y administración del sistema. | Controlar integridad y auditar ejecutables con bit SUID/SGID habilitado. |
| `/opt` y `/srv` | Software de terceros y datos servidos por aplicaciones. | Suelen albergar servicios personalizados fuera del gestor de paquetes oficial. |
| `/home` y `/root` | Directorios personales de usuarios y del superusuario (`UID 0`). | Almacenan claves `~/.ssh`, historiales de shell y configuraciones sensibles. |

## Usuarios, grupos y delegación de privilegios

Linux controla la identidad mediante identificadores numéricos: **UID** (usuario) y **GID** (grupo). El usuario `root` posee siempre `UID 0`.

### Estructura de `/etc/passwd`, `/etc/shadow` y `/etc/sudoers`

- **`/etc/passwd`** (legible por todos los usuarios, `0644`): lista las cuentas del sistema en siete campos separados por dos puntos (`usuario:x:UID:GID:comentario:home:shell`). La `x` en el segundo campo indica que el hash de contraseña se almacena en `/etc/shadow`. Las cuentas de servicio deben llevar shell no interactiva como `/usr/sbin/nologin` o `/bin/false`.
- **`/etc/shadow`** (legible solo por `root` y el grupo `shadow`, `0640`): almacena los hashes criptográficos junto con el algoritmo usado (campo con identificador `6` para SHA-512 o `y` para yescrypt), la sal aleatoria y las políticas de expiración. Un campo con `!` o `*` indica cuenta bloqueada sin contraseña directa.
- **`/etc/group`**: define los grupos secundarios que otorgan privilegios clave (por ejemplo `sudo`, `wheel`, `adm`, `docker`). Pertenecer al grupo `docker` equivale funcionalmente a privilegios de `root` sobre el host porque permite montar `/` dentro de un contenedor.
- **`/etc/sudoers`** y **`/etc/sudoers.d/`**: definen qué usuarios pueden ejecutar comandos como otro usuario mediante `sudo`. Deben editarse únicamente con `visudo` para validar sintaxis antes de guardar.

::: peligro Riesgo de reglas permisivas en `sudoers`
Otorgar `NOPASSWD` sobre editores, paginadores o intérpretes (`vim`, `less`, `find`, `python3`, `tar`) permite abrir una shell con privilegios elevados mediante funciones legítimas del propio binario. Concedé `sudo` solo a comandos acotados, con ruta absoluta y argumentos explícitos.
:::

## Permisos DAC, bits especiales y ACLs POSIX

El control de acceso discrecional (**DAC**) asigna tres clases de sujeto —propietario (`u`), grupo (`g`) y otros (`o`)— y tres permisos básicos: lectura (`r = 4`), escritura (`w = 2`) y ejecución/travesía (`x = 1`). Al sumar los pesos se obtiene la notación octal: por ejemplo, `0750` equivale a `rwxr-x---` (el propietario lee, escribe y ejecuta; el grupo lee y ejecuta; otros no tienen acceso). La máscara `umask` (usualmente `0022` o `0027` en entornos endurecidos) resta permisos por defecto al crear archivos nuevos.

### Bits especiales: SUID, SGID y Sticky Bit

Un cuarto dígito octal a la izquierda activa comportamientos especiales críticos para la seguridad del sistema:

| Bit especial | Valor octal | Letra en `ls -l` | Efecto sobre archivos ejecutables | Efecto sobre directorios |
| :--- | :---: | :---: | :--- | :--- |
| **SUID** | `4000` | `s` / `S` en propietario | Ejecuta el proceso con el **EUID del propietario** (ej. `/usr/bin/passwd`). | Sin efecto estándar en Linux. |
| **SGID** | `2000` | `s` / `S` en grupo | Ejecuta el proceso con el **EGID del grupo** del archivo. | Los archivos creados heredan el grupo del directorio padre. |
| **Sticky Bit** | `1000` | `t` / `T` en otros | Obsoleto en archivos regulares. | Solo el propietario del archivo, el del directorio o `root` puede borrarlo (ej. `/tmp` con `1777`). |

Cuando aparece una letra mayúscula (`S` o `T`), significa que el bit especial está activo pero falta el permiso de ejecución (`x`) subyacente.

### ACLs POSIX extendidas

Cuando el modelo propietario/grupo/otros resulta insuficiente, Linux soporta listas de control de acceso granulares mediante `getfacl` y `setfacl`. Un archivo con ACL extendida muestra un signo `+` al final de la cadena de permisos en `ls -la` (por ejemplo `-rw-r-----+`).

```bash
# Consultar ACLs efectivas de un directorio de aplicación
getfacl /var/log/mi_app

# Conceder lectura puntual al usuario auditor sin incluirlo en el grupo adm
sudo setfacl -m u:auditor:r-- /var/log/mi_app/eventos.log
```

## Gestión de procesos, señales y el pseudosistema `/proc`

Todo comando ejecutado en Linux crea un proceso identificado por un **PID** y vinculado a un proceso padre (**PPID**). Cada proceso transita por estados visibles en `ps` y `top`: `R` (en ejecución), `S` (esperando evento), `D` (espera ininterrumpida de E/S), `T` (detenido) y `Z` (zombi, finalizado pero aún sin ser recogido por su padre).

Para controlar procesos se envían **señales** con `kill`:

- `SIGHUP` (`1`): solicita a muchos demonios recargar su configuración sin reiniciar el servicio.
- `SIGTERM` (`15`, predeterminada): pide cierre ordenado para liberar memoria y cerrar archivos limpiamente.
- `SIGKILL` (`9`): finalización inmediata impuesta por el kernel; el proceso no puede interceptarla ni ignorarla.

Cuando auditás un proceso sospechoso o desconocido, el directorio `/proc/<pid>/` ofrece visibilidad directa desde el kernel, incluso si el binario fue borrado del disco después de arrancar:

- `/proc/<pid>/cmdline`: línea de comandos exacta con la que inició el proceso.
- `/proc/<pid>/exe`: enlace simbólico al binario real ejecutado (marca `(deleted)` si se borró en disco).
- `/proc/<pid>/fd/`: descriptores de archivo abiertos (archivos locales, tuberías y sockets).
- `/proc/<pid>/status`: UIDs/GIDs reales y efectivos (`Uid`, `Gid`) y capacidades Linux (`CapEff`).

## Servicios `systemd`, red local y análisis de logs

En distribuciones modernas, **`systemd`** (PID 1) gestiona el arranque, los servicios (`.service`), las tareas periódicas (`.timer`) y los sockets. Los archivos de unidad distribuidos por paquetes residen en `/usr/lib/systemd/system/`, mientras que las personalizaciones locales del administrador se ubican en `/etc/systemd/system/` y tienen prioridad.

Para inspeccionar la superficie de red local y los controles de filtrado:

- **`ip a`** y **`ip r`**: muestran interfaces, direcciones CIDR y tabla de enrutamiento (reemplazan a los obsoletos `ifconfig` y `route`).
- **`ss -tulnap`**: lista sockets TCP (`-t`) y UDP (`-u`) en estado de escucha (`-l`), sin resolver nombres (`-n`), mostrando direcciones (`-a`) y el proceso propietario (`-p`).
- **`ufw status verbose`** o **`sudo nft list ruleset`**: muestran las reglas activas del firewall local basadas en el subsistema `netfilter`/`nftables` del kernel.

Finalmente, la telemetría del sistema se consulta por dos vías complementarias: el diario binario estructurado mediante **`journalctl`** (`-u servicio`, `-p err`, `--since "1 hour ago"`) y los archivos de texto rotados en `/var/log/` —especialmente `/var/log/auth.log` en Debian/Ubuntu (o `/var/log/secure` en RHEL/Rocky) para inicios de sesión SSH, invocaciones de `sudo` y fallos de PAM.

## Ejemplo paso a paso: Auditoría rápida de permisos, procesos, sockets y logs en Linux

Ejecutá esta secuencia de solo lectura en tu VM Linux de laboratorio para construir una línea base de seguridad en menos de tres minutos.

### Paso 1: Identidad actual, grupos y privilegios `sudo`

```bash
id
sudo -l
```

Salida real comentada:

```text
uid=1000(analista) gid=1000(analista) groups=1000(analista),27(sudo),108(adm)
# El grupo adm permite leer la mayoría de los archivos en /var/log sin usar root.

User analista may run the following commands on lab-ubuntu:
    (ALL : ALL) ALL
```

### Paso 2: Inventario de binarios SUID y verificación de permisos en `/tmp`

```bash
# Buscar binarios SUID silenciando errores de lectura sobre rutas sin permiso
find /usr/bin /usr/sbin -type f -perm -4000 -ls 2>/dev/null | head -n 5

# Verificar Sticky Bit (t) en /tmp
ls -ld /tmp
```

```text
  134521   64 -rwsr-xr-x 1 root root   63960 Feb  6  2024 /usr/bin/passwd
  134802  232 -rwsr-xr-x 1 root root  232416 Apr  8  2024 /usr/bin/sudo
# Ambos binarios son SUID legítimos de la distribución; cualquier binario
# no estándar o en /opt o /usr/local/bin amerita revisión inmediata.

drwxrwxrwt 12 root root 4096 Nov 22 19:40 /tmp
# La "t" final confirma Sticky Bit activo (1777).
```

### Paso 3: Inspeccionar sockets en escucha y correlacionar con `/proc` y `systemd`

```bash
sudo ss -tulnap
```

```text
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
udp   UNCONN 0      0      127.0.0.53%lo:53    0.0.0.0:*         users:(("systemd-resolve",pid=612,fd=13))
tcp   LISTEN 0      128    127.0.0.1:8080      0.0.0.0:*         users:(("docker-proxy",pid=1482,fd=4))
tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*         users:(("sshd",pid=841,fd=3))
# Clave de lectura: 127.0.0.1:8080 solo acepta conexiones locales;
# 0.0.0.0:22 expone SSH en todas las interfaces activas de la VM.
```

Ahora inspeccionamos el proceso `sshd` (PID `841`) en `/proc` y su unidad `systemd`:

```bash
sudo ls -l /proc/841/exe
tr '\0' ' ' < /proc/841/cmdline; echo
systemctl status ssh --no-pager | head -n 8
```

```text
lrwxrwxrwx 1 root root 0 Nov 22 19:01 /proc/841/exe -> /usr/sbin/sshd
sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups

● ssh.service - OpenBSD Secure Shell server
     Loaded: loaded (/usr/lib/systemd/system/ssh.service; enabled; preset: enabled)
     Active: active (running) since Sun 2026-11-22 19:01:08 -03; 41min ago
   Main PID: 841 (sshd)
```

### Paso 4: Revisar eventos de autenticación con `journalctl` y `auth.log`

```bash
sudo journalctl -u ssh --since "1 hour ago" -n 5 --no-pager
sudo grep -E "Accepted|Failed|sudo:" /var/log/auth.log | tail -n 5
```

```text
Nov 22 19:15:42 lab-ubuntu sshd[1204]: Accepted publickey for analista from 192.168.56.1 port 53118 ssh2
Nov 22 19:22:10 lab-ubuntu sudo[1390]: analista : TTY=pts/0 ; PWD=/home/analista ; USER=root ; COMMAND=/usr/bin/ss -tulnap
# Cada acceso SSH y comando elevado queda trazado con marca temporal, origen, usuario y binario exacto.
```

::: defensa Perspectiva defensiva y mitigación
Endurecer un servidor Linux se basa en reducir superficie y aumentar trazabilidad antes de exponer cualquier servicio:
1. **Aislamiento en unidades `systemd`:** en servicios propios añadí directivas de sandboxing como `User=servicio_no_priv`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes` y `ProtectHome=yes`. Verificá el puntaje de exposición con `systemd-analyze security`.
2. **Montaje seguro de particiones:** configurá `/tmp` y `/dev/shm` en `/etc/fstab` con `nodev,nosuid,noexec` para frenar la ejecución directa de artefactos dejados en rutas temporales.
3. **Auditoría del kernel con `auditd` y logs centralizados:** registrá cambios en `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` y ejecuciones privilegiadas mediante reglas de `auditd`, y reenviá logs en tiempo real a un servidor externo (`rsyslog`/SIEM) para impedir que un atacante borre sus huellas localmente.
:::

### Endurecimiento esencial en macOS (entornos corporativos híbridos)

En flotas de desarrollo o estaciones ejecutivas, **macOS** comparte raíces POSIX/UNIX con Linux (kernel híbrido XNU y herramientas CLI similares), pero implementa controles propios que un auditor debe verificar:

| Control nativo macOS | Propósito de seguridad | Verificación rápida / Endurecimiento |
|---|---|---|
| **SIP (*System Integrity Protection*)** | Impide incluso a `root` modificar rutas protegidas (`/System`, `/usr`, `/sbin`) o inyectar librerías en binarios del sistema. | Verificar con `csrutil status` (`enabled` obligatorio fuera de entornos de investigación kernel dedicados). |
| **Gatekeeper, Notarización y XProtect** | Valida firmas de desarrollador, notarización ante Apple y firmas de malware antes de ejecutar binarios descargados (`com.apple.quarantine`). | Confirmar `spctl --status` (`assessments enabled`) y mantener XProtect/MRT actualizados automáticamente. |
| **FileVault 2** | Cifrado completo de volumen APFS ligado al enclave seguro (*Secure Enclave*) frente a robo físico o acceso offline al disco. | Comprobar con `fdesetup status` (`FileVault is On`) y custodiar la clave de recuperación institucional vía MDM. |
| **TCC (*Transparency, Consent, and Control*)** | Regula permisos granulares de privacidad (*Full Disk Access*, cámara, micrófono, automatización AppleEvents y grabación de pantalla). | Auditar excepciones otorgadas en `System Settings` o vía perfiles **PPPC** gestionados por MDM para evitar abusos de accesibilidad o captura. |

## Práctica en laboratorio local

1. En tu VM Linux aislada, creá un directorio de pruebas `/tmp/lab_permisos` y un archivo interno `secreto.txt`. Aplicá permisos `0640`, probá asignarle una ACL puntual con `setfacl` y verificá el resultado con `ls -la` y `getfacl`.
2. Ejecutá un inventario completo de sockets locales (`sudo ss -tulnap`), interfaces (`ip -br a`) y reglas de firewall (`sudo ufw status verbose` o `sudo nft list ruleset`), guardando la salida en `evidencias/cap1_3/red_local.txt`.
3. Elegí un servicio activo (como `ssh` o `cron`), inspeccioná su archivo de unidad con `systemctl cat <servicio>`, verificá su PID en `/proc/<pid>/exe` y revisá sus últimas 10 líneas de registro con `journalctl -u <servicio> -n 10`.
4. Generá el inventario de binarios SUID de tu VM (`evidencias/cap1_3/suid_baseline.txt`) y sellá todos los entregables con `sha256sum`.

::: practica Entregable mínimo
En `evidencias/cap1_3/` debés almacenar:
- `red_local.txt`: salida de `ip -br a`, `ss -tulnap` y estado del firewall.
- `suid_baseline.txt`: listado base de binarios SUID en `/usr/bin` y `/usr/sbin`.
- `auditoria_servicio.txt`: análisis de una unidad `systemd`, su entrada en `/proc/<pid>` y sus últimos logs en `journalctl`.
- `manifest.sha256`: hashes verificados con `sha256sum -c`.
:::

## Preguntas de repaso

**1. ¿Por qué separar `/etc/passwd` de `/etc/shadow` mejora la seguridad frente al diseño clásico de UNIX?** Porque numerosos programas del sistema necesitan resolver nombres de usuario, UIDs y directorios personales leyendo `/etc/passwd`, por lo que ese archivo debe ser legible por todos (`0644`). Al trasladar los hashes de contraseña a `/etc/shadow` con permisos restringidos (`0640`, solo `root` y grupo `shadow`), los usuarios sin privilegios no pueden leer los hashes ni intentar crackearlos fuera de línea.

**2. ¿Qué ocurre exactamente cuando un usuario normal ejecuta un binario con permiso `4755` (`-rwsr-xr-x`) cuyo propietario es `root`?** El kernel asigna al nuevo proceso un identificador de usuario efectivo (**EUID**) igual a `0` (`root`) en lugar del UID del usuario que lo invocó, permitiendo realizar operaciones privilegiadas específicas (como modificar `/etc/shadow` mediante `passwd`). Si ese binario tiene fallas de diseño o permite ejecutar comandos arbitrarios, se convierte en un vector directo de escalamiento de privilegios.

**3. ¿Cuál es la función del Sticky Bit (`1777`) en el directorio `/tmp`?** Permite que cualquier usuario cree y modifique sus propios archivos dentro de `/tmp`, pero impide que un usuario elimine o renombre archivos pertenecientes a otros usuarios. Sin este bit, cualquier cuenta local podría borrar o reemplazar archivos temporales ajenos dentro de `/tmp`.

**4. ¿Qué ventaja ofrece inspeccionar `/proc/<pid>/exe` y `/proc/<pid>/cmdline` respecto a mirar únicamente el nombre del proceso en `ps`?** Un proceso puede alterar su cadena `argv[0]` para disfrazar su nombre en listados simples de `ps`. En cambio, `/proc/<pid>/exe` es un enlace simbólico gestionado directamente por el kernel hacia el inodo real del ejecutable en disco (e incluso señala `(deleted)` si el archivo fue borrado tras iniciarse), proporcionando evidencia mucho más confiable.

**5. ¿Qué diferencia hay en `ss -tulnap` entre un servicio escuchando en `127.0.0.1:8080` y otro escuchando en `0.0.0.0:8080`?** Un socket ligado a `127.0.0.1:8080` solo acepta conexiones originadas dentro del mismo host a través de la interfaz loopback. Un socket ligado a `0.0.0.0:8080` escucha en todas las interfaces IPv4 activas del equipo, exponiendo el servicio a cualquier host de la red que alcance esas interfaces si no existe una regla de firewall que lo bloquee.

## Antes de avanzar

- [ ] Identificás sin dudar el rol de `/etc`, `/var/log`, `/proc`, `/tmp` y las diferencias entre `/etc/passwd` y `/etc/shadow`.
- [ ] Calculás permisos octales de cuatro dígitos (incluyendo SUID, SGID y Sticky Bit) y sabés detectar ACLs extendidas con `getfacl`.
- [ ] Correlacionás un puerto abierto en `ss -tulnap` con su PID en `/proc`, su unidad `systemd` y sus registros en `journalctl`.
- [ ] Tenés la línea base de SUID y red local sellada con `SHA-256`.

::: nota Puerta de salida
Antes de avanzar al Capítulo 1.4, asegurate de poder rastrear un servicio Linux de punta a punta: desde el puerto abierto en `ss` hasta el archivo de unidad `systemd`, el ejecutable en `/proc/<pid>/exe` y sus eventos en `journalctl`. En el próximo capítulo trasladarás exactamente esa misma disciplina de inspección a Windows.
:::

## Referencias y estándares abiertos

- Linux Foundation: *Filesystem Hierarchy Standard (FHS) 3.0* — https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html
- Linux man-pages project: `passwd(5)`, `shadow(5)`, `proc(5)`, `chmod(1)`, `ss(8)` — https://man7.org/linux/man-pages/
- Documentación oficial de `systemd`: `systemd.service(5)` y `systemd.exec(5)` — https://www.freedesktop.org/software/systemd/man/
- NIST Special Publication 800-123: *Guide to General Server Security* — https://csrc.nist.gov/publications/detail/sp/800-123/final
- CIS Benchmarks: *Distribution Independent Linux Benchmark* — https://www.cisecurity.org/cis-benchmarks
