::: nota Objetivo de la lección
Al completar este capítulo vas a ejecutar una auditoría estructurada de configuraciones locales en servidores Linux, comprender técnicamente por qué determinados permisos, bits SUID/SGID, capacidades POSIX, tareas programadas y membresías de grupo permiten elevar privilegios, y diseñar un plan práctico de detección y endurecimiento basado en CIS Benchmarks, `auditd` y controles obligatorios de acceso (AppArmor/SELinux).
:::

**Prerrequisitos:** Administración básica de sistemas Linux, permisos POSIX (`rwx`, propietario/grupo) y máquina virtual Linux propia en laboratorio aislado. **Duración sugerida:** 90 a 120 minutos.

## 1. Modelo de privilegios en Linux y principio de enumeración metódica

En Linux, la autorización del núcleo se basa principalmente en identificadores de usuario (`UID`), grupo (`GID`), grupos suplementarios y capacidades POSIX (*Linux Capabilities*). El usuario `root` (`UID 0`) posee control irrestricto sobre el sistema, aunque el modelo moderno permite delegar fracciones específicas de privilegio sin otorgar control total.

Una auditoría rigurosa de escalada local no consiste en ejecutar scripts a ciegas, sino en relevar sistemáticamente la superficie de privilegios del host mediante comandos nativos de solo lectura.

```bash
# 1. Contexto de identidad y pertenencia a grupos
id
groups

# 2. Privilegios delegados mediante sudo (si el usuario tiene permisos de consulta)
sudo -l

# 3. Información del núcleo, distribución y estado de servicios locales
uname -a
cat /etc/os-release
ss -tulpn
```

## 2. Vectores frecuentes de mala configuración y su mecanismo técnico

Cada vector de elevación local responde a una ruptura del principio de mínimo privilegio o a una falta de aislamiento entre cuentas de servicio y administrativas.

### Resumen de superficies de auditoría

| Vector | Mecanismo técnico de riesgo | Comando de auditoría (solo lectura) | Corrección recomendada |
| --- | --- | --- | --- |
| **Reglas `sudoers` laxas** | Permitir ejecutar intérpretes, editores o binarios con escape a shell como `root` | `sudo -l` / `visudo -c` | Rutas absolutas, argumentos exactos, etiqueta `NOEXEC` |
| **Bits SUID/SGID indebidos** | El binario corre con el EUID/EGID del propietario (`root`), heredando privilegios | `find / -perm /6000 -type f 2>/dev/null` | Retirar bits innecesarios con `chmod u-s` o `g-s` |
| **Capabilities excesivas** | Permiten operaciones privilegiadas (p. ej. cambio de UID o acceso arbitrario a archivos) | `getcap -r / 2>/dev/null` | Eliminar capacidades no justificadas con `setcap -r` |
| **Tareas programadas y `PATH`** | Scripts ejecutados por `cron` o `systemd` modificables por usuarios sin privilegios | `ls -la /etc/cron*` / `systemctl list-timers` | Propiedad `root:root`, permisos `0750` o `0700`, `PATH` fijo |
| **Grupos privilegiados** | Pertenencia a `docker`, `lxd` o `adm` otorga acceso equivalente a `root` o logs sensibles | `getent group docker lxd adm` | Retirar usuarios no administrativos; usar Docker rootless |

### Profundización técnica en tres riesgos críticos

1. **SUID/SGID, *GTFOBins* y capacidades POSIX:** Un binario con bit SUID activado y propietario `root` cambia el `EUID` efectivo del proceso a `0` durante su ejecución. El proyecto comunitario **GTFOBins** cataloga exactamente qué utilidades legítimas de Unix/Linux (`vim`, `find`, `tar`, `less`, `awk`, `python3`, `env`) incluyen funciones nativas para lanzar subshells o leer/escribir archivos arbitrarios si un administrador comete el error de marcarles el bit SUID, delegarlas por `sudo` sin `NOEXEC`, o asignarles capacidades como `cap_setuid` o `cap_dac_read_search`.
2. **Abuso de `PATH`, comodines (`*`) y escape de shells restringidas (`rbash`):** Un script ejecutado por `cron` o `root` que invoca comandos sin ruta absoluta (`tar cf ...` en lugar de `/usr/bin/tar`) o utiliza comodines expansivos (`tar cf /backup/b.tar *`) en directorios escribibles por usuarios permite alterar el flujo de argumentos mediante nombres de archivo que imitan opciones de CLI (`--checkpoint-action=...`), o escapar de shells restringidas (`rbash`) cuando no se bloquea el cambio de variables de entorno o binarios con escape a subproceso.
3. **Servicios internos en `127.0.0.1` y grupos administrativos implícitos (`docker`, `lxd`, `adm`):** Muchos administradores relajan la autenticación en servicios ligados a `localhost` asumiendo aislamiento. De forma similar, pertenecer al grupo `docker` permite montar `/` del anfitrión dentro de un contenedor privilegiado, y el grupo `adm` otorga lectura directa sobre registros donde aplicaciones mal configuradas pueden haber volcado secretos.

## 3. Hardening sistemático alineado con CIS Benchmarks

Cerrar la superficie de escalada local requiere combinar limpieza de permisos, configuración mínima de `sudo` y confinamiento obligatorio a nivel de núcleo.

### Endurecimiento de `sudoers` y permisos de archivos

- Editá siempre `/etc/sudoers` o archivos en `/etc/sudoers.d/` mediante `visudo` para validar sintaxis antes de guardar.
- Evitá comodines amplios (`*`) y especificá siempre la ruta absoluta y los argumentos permitidos.
- Usá `NOEXEC` cuando un comando autorizado no necesite generar procesos hijos, y activá `use_pty` y registro de entrada/salida (`log_output`) para máxima trazabilidad.

```text
# Ejemplo de política restrictiva en /etc/sudoers.d/auditoria-servicios
Defaults use_pty
Defaults logfile="/var/log/sudo.log"

# Delegación granular: solo reiniciar un servicio específico sin escape a subprocesos
operador_web ALL=(root) NOEXEC: /usr/bin/systemctl restart nginx
```

### Confinamiento con AppArmor y SELinux

Mientras que los permisos POSIX constituyen un Control de Acceso Discrecional (DAC), **AppArmor** (Debian/Ubuntu) y **SELinux** (RHEL/Rocky/Fedora) aplican Control de Acceso Obligatorio (MAC). Incluso si un servicio es comprometido o mal configurado, el perfil MAC restringe exactamente qué archivos, sockets y capacidades puede invocar ese proceso.

```bash
# Verificar estado de AppArmor en sistemas basados en Debian/Ubuntu
sudo aa-status

# Verificar estado de SELinux en sistemas basados en RHEL/Fedora
getenforce
sestatus
```

### Auditoría de NFS (`no_root_squash`) y gestión defensiva del kernel

- **Exportaciones NFS sin `root_squash` (`/etc/exports`):** por diseño seguro, la opción predeterminada `root_squash` en un servidor NFS mapea las peticiones de un cliente remoto con `UID 0` (`root`) hacia una cuenta local sin privilegios (`nobody` o `nfsnobody`), evitando que un cliente modifique permisos privilegiados en el recurso compartido. Cuando un directorio se exporta con **`no_root_squash`** hacia subredes amplias o equipos sin aislamiento, quien posea privilegios de `root` en el cliente montado puede crear un binario propiedad de `root` con el bit SUID activado dentro del recurso compartido y luego ejecutarlo localmente en el servidor NFS para elevar a `UID 0`. Auditá siempre `/etc/exports` y `exportfs -v`, eliminá `no_root_squash` (usá `root_squash` o `all_squash`), restringí las IPs autorizadas y montá recursos NFS en clientes con `nosuid,nodev`.
- **Gestión defensiva de superficie del kernel Linux:** además de aplicar actualizaciones periódicas o *livepatching* (como `kpatch` o *Canonical Livepatch*) para corregir vulnerabilidades locales de privilegio sin esperar reinicios prolongados, reducí la superficie de ataque del núcleo vía `sysctl` en `/etc/sysctl.d/99-hardening-kernel.conf`:

```bash
# Auditar exportaciones NFS activas buscando no_root_squash
cat /etc/exports
sudo exportfs -v

# Parámetros recomendados en /etc/sysctl.d/99-hardening-kernel.conf
# Restringir namespaces de usuario sin privilegios (donde contenedores/sandboxes no lo requieran)
kernel.unprivileged_userns_clone = 0
# Ocultar direcciones de punteros del núcleo en /proc/kallsyms (dificulta evadir KASLR)
kernel.kptr_restrict = 2
# Limitar lectura del ring buffer del núcleo (dmesg) a usuarios con CAP_SYSLOG / root
kernel.dmesg_restrict = 1
```

Aplicá los cambios con `sudo sysctl --system` y verificá que sigan vigentes ante reinicios.

## 4. Detección de actividad privilegiada con `auditd`

El subsistema de auditoría del núcleo Linux (`auditd`) permite registrar eventos críticos de seguridad de manera inmutable para análisis posterior o envío hacia un SIEM.

```bash
# Consultar reglas activas de auditd en el servidor de laboratorio
sudo auditctl -l

# Ejemplo de archivo de reglas persistentes (/etc/audit/rules.d/hardening.rules)
# Supervisar modificaciones en identidad, sudoers y tareas programadas
-w /etc/passwd -p wa -k cambios_identidad
-w /etc/shadow -p wa -k cambios_identidad
-w /etc/sudoers -p wa -k cambios_sudoers
-w /etc/sudoers.d/ -p wa -k cambios_sudoers
-w /etc/crontab -p wa -k tareas_programadas
```

## Ejemplo paso a paso: auditoría y remediación de permisos en un servidor Linux de laboratorio

En este recorrido auditamos una VM Linux propia para detectar binarios SUID no estándar, scripts de cron con permisos excesivos y capacidades POSIX inesperadas, y luego aplicamos la corrección.

```bash
# 1. Inventariar binarios SUID y comparar contra una línea base limpia
find /usr/bin /usr/local/bin -perm -4000 -type f -ls 2>/dev/null
# Salida esperada: lista acotada (passwd, sudo, su, mount, etc.)
# Cualquier script propio o intérprete en esta lista constituye un hallazgo crítico.

# 2. Auditar capacidades POSIX asignadas en el sistema
getcap -r /usr /bin /sbin 2>/dev/null
# Salida esperada: solo utilidades esperadas como ping (cap_net_raw) o similares.

# 3. Revisar permisos de tareas programadas y timers de systemd
ls -la /etc/crontab /etc/cron.d/
systemctl list-timers --all

# 4. Remediación ejemplo: asegurar un script administrativo mal configurado
sudo chown root:root /usr/local/sbin/respaldo_lab.sh
sudo chmod 0750 /usr/local/sbin/respaldo_lab.sh

# 5. Validar que los permisos quedaron endurecidos y registrar el cambio
stat -c '%U:%G %a %n' /usr/local/sbin/respaldo_lab.sh
# Salida comentada:
# root:root 750 /usr/local/sbin/respaldo_lab.sh (solo root puede modificarlo)
```

::: defensa Perspectiva defensiva, detección y mitigación
Desde la perspectiva de monitoreo Blue Team (tácticas de alto nivel de MITRE ATT&CK como **Privilege Escalation** y **Persistence**), la defensa efectiva en Linux combina prevención y telemetría centralizada:
- **Detección prioritaria:** Alertar ante cambios en archivos de cuentas o `sudoers`, creación de nuevos binarios SUID/capabilities, incorporación de usuarios a grupos privilegiados y registros de nuevas tareas en `cron` o `systemd`.
- **Hardening estructural:** Aplicar líneas base del CIS Benchmark para la distribución en uso, mantener AppArmor/SELinux en modo *enforcing*, montar particiones temporales (`/tmp`, `/var/tmp`) con `noexec,nosuid,nodev` y reenviar logs de `auditd` y `auth.log` a un servidor central de solo anexado.
:::

## Práctica en laboratorio local

En tu VM Linux de laboratorio (red Host-Only):

1. Ejecutá una línea base de solo lectura relevando `id`, `sudo -l`, binarios SUID, capacidades POSIX (`getcap`), servicios en escucha (`ss -tulpn`) y timers de `systemd`.
2. Creá un archivo de prueba `/usr/local/sbin/tarea_prueba.sh` propiedad de `root`, verificá qué ocurre al auditarlo si tiene permisos excesivos (`0777`) y luego aplicá la remediación correcta (`root:root` y `0750`).
3. Instalá o verificá `auditd`, agregá una regla de vigilancia sobre `/etc/sudoers` y comprobá en `/var/log/audit/audit.log` que los accesos administrativos quedan registrados.

::: practica Entregable mínimo
Un reporte de auditoría local que incluya: tabla de hallazgos de la línea base (SUID, capabilities, grupos y timers), comandos de remediación ejecutados y evidencia de al menos un evento capturado por `auditd`.
:::

## Preguntas de repaso

**1. ¿Por qué asignar el bit SUID a un intérprete o editor de texto representa un riesgo crítico de escalada de privilegios?** Porque el proceso se ejecuta con el identificador efectivo (`EUID`) del propietario del archivo (`root`), permitiendo que cualquier usuario utilice las funciones legítimas del programa para leer o modificar archivos restringidos del sistema.

**2. ¿Qué diferencia existe entre una política DAC tradicional y un sistema MAC como AppArmor o SELinux?** El control DAC depende de propietarios y permisos de archivos (`rwx`), mientras que MAC impone políticas obligatorias definidas por el administrador del núcleo que restringen las acciones permitidas a cada proceso incluso si este cuenta con privilegios elevados.

**3. ¿Por qué pertenecer al grupo `docker` se considera operativamente equivalente a tener privilegios administrativos en el host?** Porque permite comunicarse con el demonio privilegiado de Docker y montar directorios sensibles del sistema anfitrión dentro de un contenedor, eludiendo los controles de permisos locales del usuario.

**4. ¿Qué medidas deben aplicarse al delegar un comando puntual mediante `sudoers`?** Utilizar siempre `visudo`, especificar rutas absolutas y argumentos exactos, evitar comodines amplios, habilitar `NOEXEC` cuando corresponda y activar el registro de auditoría de sesiones `sudo`.

**5. ¿Cómo ayudan las opciones de montaje `nosuid`, `nodev` y `noexec` en particiones como `/tmp`?** Impiden que binarios depositados en directorios escribibles por cualquier usuario puedan ejecutarse directamente, aprovechar bits SUID o interactuar con archivos especiales de dispositivo.

## Antes de avanzar

- [ ] Realizaste una enumeración metódica de permisos, SUID, capabilities y tareas programadas en tu VM Linux.
- [ ] Entendés por qué grupos como `docker` o `lxd` amplían la superficie de privilegios.
- [ ] Configuraste al menos una regla básica de vigilancia en `auditd`.
- [ ] Verificaste el estado de AppArmor o SELinux en tu servidor de laboratorio.
- [ ] Sabés redactar reglas restrictivas en `sudoers` sin comodines riesgosos.

::: nota Puerta de salida
Verificá que el script de prueba creado en `/usr/local/sbin/` haya quedado con permisos seguros (`0750`) o eliminado tras documentar tu práctica, antes de pasar al entorno Windows en el Capítulo 3.4.
:::

## Referencias y estándares abiertos

- CIS Benchmarks: *CIS Distribution Independent Linux Benchmark* (https://www.cisecurity.org/cis-benchmarks)
- Linux man-pages: `capabilities(7)`, `sudoers(5)`, `auditctl(8)`, `systemd.timer(5)` (https://man7.org/linux/man-pages/)
- MITRE ATT&CK Enterprise Matrix: tácticas *Privilege Escalation* y *Persistence* (https://attack.mitre.org/)
- Documentación oficial de AppArmor y SELinux Project (https://gitlab.com/apparmor/apparmor/-/wikis/home y https://selinuxproject.org/)
- NIST SP 800-123: *Guide to General Server Security* (https://csrc.nist.gov/publications/detail/sp/800-123/final)
