::: nota Objetivo de la lección
Comprender el funcionamiento interno, los mecanismos de autenticación, los banners y las malas configuraciones más frecuentes de los doce servicios de red críticos en infraestructuras modernas: **SSH, FTP, DNS, SMTP, SMB, SNMP, LDAP/LDAPS, RDP, WinRM, MySQL, PostgreSQL y MSSQL**. Al finalizar vas a poder auditar la postura de cada servicio en tu laboratorio y aplicar un checklist de hardening verificable.
:::

**Prerrequisitos:** Dominio del modelo TCP/IP, puertos y sockets (Capítulo 1.2) y manejo de herramientas de inspección en Linux/Windows (Capítulos 1.3 a 1.5). **Duración sugerida:** 3 a 4 horas.

## 1. Mapa de protocolos clave: puertos, transporte y autenticación

Un puerto abierto por sí solo no constituye una vulnerabilidad: el riesgo nace de **qué servicio escucha detrás**, **qué versión o dialecto negocia**, **cómo autentica** y **si cifra el tráfico en tránsito**. Antes de auditar cualquier entorno autorizado conviene dominar la arquitectura base de los servicios más comunes en redes corporativas y servidores Linux/Windows.

| Servicio | Puerto y transporte | Rol principal | Autenticación habitual | Cifrado en tránsito |
| :--- | :--- | :--- | :--- | :--- |
| **SSH** | TCP `22` | Administración remota y SFTP | Clave pública / contraseña | Nativo (SSHv2) |
| **FTP** | TCP `21` (control) | Transferencia de archivos | Usuario/contraseña o `anonymous` | Texto plano (salvo FTPS) |
| **DNS** | UDP/TCP `53` | Resolución de nombres | TSIG (zonas) / sin auth en consultas | Texto plano (salvo DoT/DoH) |
| **SMTP** | TCP `25`, `587` | Envío y enrutamiento de correo | Ninguna (puerto 25) / AUTH (`587`) | Opcional (`STARTTLS`) |
| **SMB** | TCP `445` | Archivos e impresoras en red | Kerberos / NTLMv2 | Opcional (cifrado en SMB 3.x) |
| **SNMP** | UDP `161` | Monitoreo y gestión de red | Community string (`v1`/`v2c`) / USM (`v3`) | Solo en SNMPv3 (`authPriv`) |
| **LDAP / LDAPS** | TCP `389` / `636` | Directorio de identidades | Simple Bind / SASL (Kerberos) | Texto plano (`389`) / TLS (`636`) |
| **RDP** | TCP `3389` | Escritorio remoto Windows | CredSSP / NLA (Kerberos/NTLM) | TLS + NLA |
| **WinRM** | TCP `5985` / `5986` | Gestión remota PowerShell/WS-Man | Kerberos / Negotiate / Basic | Texto plano (`5985` HTTP) / TLS (`5986`) |
| **MySQL** | TCP `3306` | Base de datos relacional | `caching_sha2_password` | Opcional / exigible por TLS |
| **PostgreSQL** | TCP `5432` | Base de datos relacional | `scram-sha-256` / certificados | Opcional / exigible (`hostssl`) |
| **MSSQL** | TCP `1433` | Base de datos relacional | Windows Auth / SQL Auth | TLS (recomendado `Force Encryption`) |

### 1.1 Banners de protocolo y negociación inicial

Muchos protocolos orientados a conexión (SSH, FTP, SMTP, MySQL) envían un **banner inicial** apenas se completa el *three-way handshake* TCP para acordar compatibilidad de versiones y capacidades. Por ejemplo, `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13` informa al cliente la versión de protocolo (`2.0`) y, como efecto colateral, la distribución del servidor. Aunque ocultar banners nunca reemplaza mantener el software parcheado, reducir la divulgación innecesaria de versiones y deshabilitar dialectos obsoletos disminuye la superficie de información expuesta.

## 2. Servicios de acceso, transferencia e infraestructura: SSH, FTP, DNS, SMTP y SNMP

### 2.1 SSH (TCP/22) y FTP (TCP/21)

**SSHv2 (RFC 4251–4254)** separa la capa de transporte cifrada, la autenticación de usuario y la multiplexación de canales (terminal interactivo, reenvío de puertos y SFTP). Las malas configuraciones habituales en `/etc/ssh/sshd_config` incluyen habilitar `PermitRootLogin yes`, mantener `PasswordAuthentication yes` expuesto a Internet sin limitación de intentos, o conservar algoritmos criptográficos heredados (`diffie-hellman-group1-sha1`, `ssh-rsa` con SHA-1).

**FTP (RFC 959)** utiliza dos canales separados (control en `21` y datos en modo activo o pasivo) y transmite credenciales y archivos **en texto plano**. Sus fallos clásicos son permitir acceso anónimo (`anonymous`) con permisos de escritura o exponer credenciales en redes compartidas. En sistemas modernos, FTP debe reemplazarse por **SFTP** (sobre SSH) o, si un sistema legado lo exige, restringirse a **FTPS** (FTP sobre TLS explícito) con aislamiento `chroot`.

### 2.2 DNS (UDP/TCP 53), SMTP (TCP 25/587) y SNMP (UDP 161)

- **DNS (RFC 1035):** usa UDP `53` para consultas estándar y TCP `53` para respuestas grandes y transferencias de zona (`AXFR`/`IXFR`). Dos errores críticos son permitir transferencias de zona sin restricción de IP ni clave **TSIG** (exponiendo todo el inventario interno de registros) y dejar un servidor autoritativo configurado como **recursivo abierto** hacia Internet (abusable en ataques de amplificación DDoS).
- **SMTP (RFC 5321):** el puerto `25` atiende intercambio servidor-a-servidor y el `587` (*Submission*) la entrega autenticada de clientes con `STARTTLS`. Los riesgos principales son el **Open Relay** (aceptar reenvío de correo a dominios externos sin autenticación), la exposición de comandos `VRFY` y `EXPN` que facilitan enumerar buzones, y la ausencia de registros **SPF**, **DKIM** y **DMARC** para mitigar suplantación de remitente.
- **SNMP (RFC 3411–3418):** permite consultar árboles MIB de enrutadores, switches y servidores por UDP `161`. **SNMPv1 y SNMPv2c** autentican mediante una cadena compartida en texto plano (*community string*), frecuentemente dejada en valores predeterminados (`public` lectura, `private` escritura). La mitigación estándar es migrar a **SNMPv3** en modo `authPriv` (autenticación SHA-2 y cifrado AES) restringido por listas de acceso (ACL) a la red de gestión.

## 3. Protocolos de entorno corporativo y Windows: SMB, LDAP/LDAPS, RDP y WinRM

### 3.1 SMB (TCP/445) y LDAP/LDAPS (TCP 389/636)

**SMB (Server Message Block)** opera hoy directamente sobre TCP `445` (sin depender del antiguo NetBIOS sobre `139`). Sus principales vectores de mala configuración son:

1. **Dialectos obsoletos (SMBv1):** carentes de cifrado moderno y asociados históricamente a vulnerabilidades críticas de ejecución remota; SMBv1 debe estar deshabilitado en todos los equipos.
2. **Ausencia de firma SMB (*SMB Signing*):** si el servidor no exige firma criptográfica por paquete, las conexiones autenticadas quedan expuestas a manipulación en tránsito o retransmisión de credenciales (*relay*).
3. **Recursos compartidos permisivos o sesiones nulas/invitado:** carpetas con permisos excesivos (`Everyone` / `Authenticated Users` con escritura) o acceso de invitado habilitado filtran backups, scripts y configuraciones sensibles.

**LDAP (RFC 4511)** consulta y modifica directorios jerárquicos (como Active Directory u OpenLDAP) en TCP `389`, mientras **LDAPS** envuelve la conexión en TLS sobre TCP `636`. Las debilidades críticas son permitir **Anonymous Bind** (lectura sin credenciales de usuarios, grupos y descripciones), aceptar **Simple Bind en texto plano** por `389` sin `StartTLS`, y omitir **LDAP Signing** y **Channel Binding** en controladores de dominio.

### 3.2 Administración remota Windows: RDP (TCP/3389) y WinRM (TCP 5985/5986)

**RDP (Remote Desktop Protocol)** brinda acceso gráfico completo a hosts Windows. Exponer el puerto `3389` directamente a Internet sin pasarela ni VPN es uno de los vectores iniciales más explotados en incidentes corporativos. A nivel de protocolo, es indispensable exigir **NLA (Network Level Authentication)** para autenticar al usuario antes de asignar recursos de sesión gráfica, aplicar cifrado TLS con certificado válido y restringir el grupo `Remote Desktop Users` al mínimo privilegio.

**WinRM (Windows Remote Management)** implementa el protocolo WS-Management sobre HTTP (`5985`) y HTTPS (`5986`) para administración remota con PowerShell (`Enter-PSSession`, `Invoke-Command`). Aunque sobre Kerberos el cuerpo de los mensajes en `5985` se cifra a nivel de protocolo, habilitar `AllowUnencrypted = true` o autenticación `Basic` sin TLS expone credenciales en claro. En entornos reforzados se deshabilita el listener HTTP, se usa **HTTPS en `5986`** con certificado de la PKI interna y se restringe el acceso por firewall de host a la subred de administración (*bastion / jump host*).

## 4. Servicios de bases de datos: MySQL, PostgreSQL y MSSQL

Las bases de datos rara vez necesitan escuchar en interfaces públicas. Su exposición directa a redes de usuarios o a Internet amplifica cualquier credencial débil o permiso excesivo en impacto inmediato sobre la confidencialidad e integridad de los datos.

### 4.1 Comparativa de riesgos de configuración en motores relacionales

| Motor (Puerto) | Error de red común | Riesgo de autenticación | Funcionalidad peligrosa mal configurada |
| :--- | :--- | :--- | :--- |
| **MySQL / MariaDB** (`3306`) | `bind-address = 0.0.0.0` sin firewall | Cuenta `root@'%'` remota o plugin `mysql_native_password` heredado | `secure_file_priv` vacío o `local_infile = ON` (lectura/escritura de archivos) |
| **PostgreSQL** (`5432`) | `listen_addresses = '*'` en red no aislada | Regla `trust` o `md5` en `pg_hba.conf` | Roles de aplicación con atributo `SUPERUSER` o uso libre de `COPY ... PROGRAM` |
| **Microsoft SQL Server** (`1433`) | Instancia expuesta + SQL Browser UDP `1434` abierto | Cuenta `sa` habilitada con contraseña débil en modo Mixto | `xp_cmdshell` habilitado o enlaces entre servidores (*linked servers*) sobreprivilegiados |

### 4.2 Patrones de configuración segura en MySQL y PostgreSQL

En PostgreSQL, el control de acceso por origen, base, rol y método reside en `pg_hba.conf`. Reemplazar `trust` y `md5` por `scram-sha-256` sobre conexiones `hostssl` cierra la autenticación sin cifrar:

```text
# /etc/postgresql/16/main/pg_hba.conf (fragmento endurecido)
# TYPE   DATABASE   USER         ADDRESS           METHOD
local    all        postgres                       peer
hostssl  app_db     app_usuario  10.10.20.0/24     scram-sha-256
host     all        all          0.0.0.0/0         reject
```

En MySQL 8+, restringir el enlace a `127.0.0.1` (o a la IP interna de la VLAN de datos) y exigir TLS evita intercepción lateral:

```text
# /etc/mysql/mysql.conf.d/mysqld.cnf (fragmento endurecido)
[mysqld]
bind-address             = 127.0.0.1
require_secure_transport = ON
local_infile             = OFF
secure_file_priv         = /var/lib/mysql-files
```

## 5. Checklist de hardening por servicio

| Servicio | Controles prioritarios de endurecimiento verificables |
| :--- | :--- |
| **SSH (`22`)** | `PermitRootLogin no`, `PasswordAuthentication no`, claves Ed25519, `AllowUsers`/`AllowGroups`, limitación de tasa o VPN. |
| **FTP (`21`)** | Reemplazar por SFTP; si es imprescindible, exigir FTPS (TLS 1.2+), deshabilitar `anonymous` y aplicar `chroot`. |
| **DNS (`53`)** | Restringir `allow-transfer` a secundarios con TSIG, deshabilitar recursión externa en autoritativos, implementar DNSSEC. |
| **SMTP (`25`/`587`)** | Bloquear Open Relay, exigir `STARTTLS` y AUTH en `587`, deshabilitar `VRFY`/`EXPN`, publicar SPF, DKIM y DMARC (`p=reject`). |
| **SMB (`445`)** | Deshabilitar SMBv1, exigir SMB Signing y cifrado SMB 3.x, bloquear sesiones anónimas/invitado, filtrar `445` en perímetro. |
| **SNMP (`161`)** | Deshabilitar v1/v2c, migrar a SNMPv3 `authPriv` (SHA-256 + AES), restringir origen por ACL a servidores de monitoreo. |
| **LDAP/LDAPS (`389`/`636`)** | Deshabilitar Anonymous Bind, exigir LDAPS (`636`) o `StartTLS`, activar LDAP Signing y Channel Binding. |
| **RDP (`3389`)** | Nunca exponer directo a Internet; exigir VPN/RD Gateway + MFA, activar NLA y cifrado TLS, auditar fallos de logon. |
| **WinRM (`5985`/`5986`)** | Deshabilitar `AllowUnencrypted` y `Basic`, configurar listener HTTPS (`5986`), permitir solo subred de administración. |
| **MySQL / PostgreSQL / MSSQL** | Escuchar solo en loopback/VLAN privada, exigir TLS, usar `scram-sha-256`/`caching_sha2_password`/Windows Auth, cuentas de mínimo privilegio y desactivar `xp_cmdshell`/`local_infile`. |

## Ejemplo paso a paso: Inspección defensiva de servicios locales

En tu laboratorio local (VM Linux o WSL + equipo Windows aislado), ejecutá verificaciones no intrusivas sobre la configuración efectiva de servicios activos.

**Paso 1 (Linux):** auditá la configuración efectiva de OpenSSH (`sshd -T`) y verificá políticas de DNS locales:

```bash
# Inspeccionar directivas críticas efectivas del demonio SSH (requiere sudo)
sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|x11forwarding|maxauthtries) '

# Verificar si un servidor DNS local responde a consulta de versión o registros SPF/DMARC
dig @127.0.0.53 +short TXT localhost
```

Salida esperada comentada:

```text
permitrootlogin no                # Correcto: impide acceso directo como root
passwordauthentication no         # Correcto: exige autenticación por clave pública
pubkeyauthentication yes          # Habilitado para llaves Ed25519/RSA modernas
x11forwarding no                  # Reduce superficie de reenvío gráfico innecesario
maxauthtries 3                    # Limita intentos por conexión TCP
```

**Paso 2 (Windows PowerShell):** verificá el estado de SMBv1, la exigencia de SMB Signing y la configuración del servicio WinRM en tu máquina local:

```powershell
# Comprobar configuración del servidor SMB local
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EncryptData

# Revisar estado de NLA en Terminal Services (1 = NLA obligatorio)
(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
```

Salida esperada comentada:

```text
EnableSMB1Protocol       : False  # Correcto: protocolo legado desactivado
EnableSMB2Protocol       : True   # Habilita familia moderna SMB 2/3
RequireSecuritySignature : True   # Exige firma criptográfica en cada trama SMB
EncryptData              : True   # Protege la confidencialidad de archivos en tránsito

1                                 # NLA activo: autentica antes de abrir sesión gráfica
```

::: defensa Perspectiva defensiva y mitigación
La defensa más eficaz sobre protocolos de red combina **segmentación** con **endurecimiento de capa de aplicación**:
- **Zero Exposure para gestión y datos:** ningún puerto administrativo (`22`, `3389`, `5985/5986`, `161`) ni de bases de datos (`3306`, `5432`, `1433`) ni `SMB` (`445`) o `LDAP` (`389`) debe exponerse directamente a Internet; colocá siempre una VPN con MFA o un *bastion host* auditado delante.
- **Principio de mínimo servicio:** desinstalá o detené cualquier demonio que no cumpla una función documentada; un servicio detenido no puede ser mal configurado ni explotado.
- **Cifrado y firma obligatorios:** eliminá progresivamente variantes en texto plano (FTP, Telnet, SNMPv1/v2c, LDAP sin TLS, HTTP WinRM) y exigí firma criptográfica en SMB y LDAP para frustrar ataques de intermediario (*MitM*) y retransmisión en la LAN.
- **Inventario continuo de línea base:** compará periódicamente la salida de `ss -tulnp` o `Get-NetTCPConnection -State Listen` contra un inventario aprobado para detectar servicios abiertos sin autorización.
:::

## Práctica en laboratorio local

Ejecutá una auditoría defensiva de servicios sobre tus máquinas virtuales de laboratorio:

1. Inventariá todos los puertos TCP y UDP en escucha en tu VM Linux (`ss -tulnp`) y en tu entorno Windows (`Get-NetTCPConnection -State Listen`), identificando el proceso binario y el usuario de ejecución de cada servicio.
2. En tu VM Linux, revisá `/etc/ssh/sshd_config` (o `sshd -T`) y corregí al menos tres parámetros según el checklist del Capítulo (por ejemplo, `PermitRootLogin no`, `X11Forwarding no`, `MaxAuthTries 3`), validando la sintaxis con `sudo sshd -t` antes de recargar el servicio.
3. Si desplegás un contenedor local de PostgreSQL o MySQL en `127.0.0.1`, comprobá con `laboratorios/auditor_red_local.py 127.0.0.1` que el puerto responda solo en loopback y revisá sus parámetros de autenticación y TLS.

::: practica Entregable mínimo
Una tabla de inventario de servicios activos en tu laboratorio (puerto, protocolo, proceso, interfaz de enlace), el resultado de `sshd -t` sin errores tras endurecer SSH y la captura de `Get-SmbServerConfiguration` verificando `EnableSMB1Protocol : False`.
:::

## Preguntas de repaso

**1. ¿Por qué deshabilitar SMBv1 y activar `RequireSecuritySignature` (SMB Signing) son dos controles complementarios y no redundantes?** Deshabilitar SMBv1 elimina un protocolo heredado con múltiples vulnerabilidades históricas y falta de cifrado moderno. Sin embargo, incluso usando SMBv2/v3, si la firma SMB no es obligatoria, un atacante en la red local puede interceptar y retransmitir autenticaciones NTLM (*SMB Relay*) hacia otros hosts; exigir SMB Signing garantiza integridad y autenticidad por mensaje.

**2. ¿Qué riesgo implica dejar habilitadas transferencias de zona (`AXFR`) sin restricciones en un servidor DNS autoritativo?** Permite que cualquier host no autorizado solicite por TCP `53` una copia completa de los registros de la zona DNS (`A`, `AAAA`, `MX`, `TXT`, `SRV`, subdominios internos), entregando un mapa detallado de la infraestructura y los servicios de la organización sin necesidad de fuerza bruta de nombres.

**3. ¿Por qué `SNMPv2c` sigue siendo inseguro aun cuando se cambia la cadena `public` por una palabra más larga?** Porque tanto SNMPv1 como SNMPv2c transmiten la *community string* y el contenido de los paquetes **en texto plano** sobre UDP `161`. Cualquier observador en la red puede capturarla pasivamente; además no ofrece cifrado ni autenticación criptográfica por usuario, capacidades que recién introduce SNMPv3 en modo `authPriv`.

**4. ¿Qué aporta NLA (Network Level Authentication) en conexiones RDP (`TCP/3389`)?** Obliga al cliente a completar la autenticación de usuario mediante CredSSP antes de que el servidor establezca una sesión gráfica completa de escritorio remoto. Esto protege contra ataques previos a la autenticación en la pila gráfica de RDP y reduce el consumo de recursos frente a conexiones masivas no autenticadas.

**5. ¿Cuál es el impacto de configurar `trust` en `pg_hba.conf` (PostgreSQL) o dejar `local_infile = ON` y `root@'%'` en MySQL?** En PostgreSQL, `trust` concede acceso sin solicitar contraseña a cualquier conexión que coincida con esa regla de origen. En MySQL, exponer `root@'%'` amplía el acceso administrativo a toda la red, y `local_infile = ON` junto a privilegios excesivos facilita la lectura no autorizada de archivos del sistema desde consultas SQL.

## Antes de avanzar

- [ ] Reconocés de memoria los puertos estándar y mecanismos de autenticación de SSH, FTP, DNS, SMTP, SMB, SNMP, LDAP/LDAPS, RDP, WinRM y las tres bases de datos principales.
- [ ] Sabés distinguir qué servicios operan en texto plano por defecto y cuál es su alternativa cifrada estándar.
- [ ] Podés verificar la configuración efectiva de OpenSSH (`sshd -T`) y de SMB/RDP en PowerShell sin herramientas externas.
- [ ] Tenés claro cómo aplicar segmentación y mínimo privilegio sobre servicios administrativos y motores SQL.

::: nota Puerta de salida
Con los servicios de red de infraestructura bajo control, el siguiente paso cierra el Tomo I enfocándose en la superficie más expuesta en Internet: las aplicaciones web, HTTP/TLS y los proxies locales de inspección (Capítulo 1.8).
:::

## Referencias y estándares abiertos

- IETF RFC 4251 — *The Secure Shell (SSH) Protocol Architecture*: https://datatracker.ietf.org/doc/html/rfc4251
- IETF RFC 4511 — *Lightweight Directory Access Protocol (LDAP): The Protocol*: https://datatracker.ietf.org/doc/html/rfc4511
- IETF RFC 5321 — *Simple Mail Transfer Protocol (SMTP)* y RFC 7489 (*DMARC*): https://datatracker.ietf.org/doc/html/rfc5321
- Microsoft Learn — *SMB Security Enhancements y Configure WinRM for HTTPS*: https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security
- NIST SP 800-123 — *Guide to General Server Security*: https://csrc.nist.gov/publications/detail/sp/800-123/final
