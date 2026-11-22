::: nota Objetivo de la lección
Al finalizar este capítulo vas a comprender cómo se diseñan y auditan redes corporativas segmentadas, cómo funcionan los túneles de capa de aplicación y transporte (reenvío de puertos local `-L`, remoto `-R` y proxy dinámico SOCKS5 `-D` sobre SSH, así como `netsh interface portproxy` en Windows) para administrar o evaluar subredes internas en un laboratorio multirred, cómo operan los protocolos de administración remota corporativa (SMB, WinRM, WMI, MMC/DCOM y RDP) y cómo implementar una arquitectura defensiva de **microsegmentación** y detección de túneles en el SOC.
:::

**Prerrequisitos:** Capítulo 1.2 (Redes TCP/IP), Capítulo 1.7 (Protocolos de red) y Capítulos 3.3–3.4 (Seguridad en Linux y Windows). **Duración sugerida:** 8 a 10 horas.

## 1. Arquitectura de redes segmentadas y el concepto de salto (Pivoting)

En cualquier organización medianamente madura —y en todo laboratorio realista de infraestructura— las redes no son planas. Los activos se dividen en zonas o subredes aisladas por firewalls internos y listas de control de acceso (ACLs) según su función y nivel de criticidad:

```text
[Estación de Auditoría / Admin] (192.168.56.10)
             │
             │  Subred A (192.168.56.0/24 - Zona de Acceso / Bastión)
             ▼
[Servidor Bastión Dual-Homed]
  • eth0: 192.168.56.20
  • eth1: 10.10.20.20
             │
             │  Subred B (10.10.20.0/24 - Red Interna de Aplicación / Dominio)
             ▼
[Servidor Interno de Base de Datos / DC] (10.10.20.50 — No enrutable directo desde Subred A)
```

Un equipo **dual-homed** (como un servidor bastión, un salto de administración o un contenedor conectado a dos redes virtuales en Docker/VirtualBox) posee interfaces en dos subredes distintas.

Desde la perspectiva de la administración de sistemas y de las pruebas de penetración autorizadas en entornos segmentados, el **reenvío de puertos (*Port Forwarding*)** y el **encapsulamiento (*Tunneling / Pivoting*)** permiten encaminar conexiones técnicas a través de un host intermedio autorizado hacia una subred interna que no tiene ruta directa desde el exterior. Desde la perspectiva de la defensa (**Blue Team / Arquitectura de Red**), comprender exactamente cómo funcionan estos túneles es indispensable para diseñar reglas de microsegmentación y detectar flujos laterales anómalos.

## 2. Reenvío de puertos y túneles con OpenSSH

El cliente y servidor **OpenSSH** (presente de forma nativa tanto en Linux como en Windows 10/11 y Windows Server modernos) incluye tres modos de reenvío cifrado sobre una única conexión TCP/22 autenticada:

| Modo OpenSSH | Sintaxis del comando | Dónde abre el puerto de escucha | Caso de uso en laboratorio o administración |
|---|---|---|---|
| **Local Port Forwarding (`-L`)** | `ssh -N -L 127.0.0.1:8445:10.10.20.50:445 usuario@192.168.56.20` | En tu **máquina local** (`127.0.0.1:8445`). | Acceder desde tu estación local a un único puerto específico (`10.10.20.50:445`) de la subred interna a través del bastión `192.168.56.20`. |
| **Dynamic Port Forwarding (`-D`)** | `ssh -N -D 127.0.0.1:1080 usuario@192.168.56.20` | En tu **máquina local** como proxy **SOCKS4/SOCKS5** (`127.0.0.1:1080`). | Enrutar cualquier herramienta compatible con SOCKS5 (navegador, `curl --socks5`, scripts Python) hacia múltiples hosts y puertos de la Subred B. |
| **Remote Port Forwarding (`-R`)** | `ssh -N -R 127.0.0.1:9000:10.10.20.50:80 usuario@192.168.56.10` | En el **servidor SSH destino** al que se conecta el comando. | Cuando las reglas de firewall solo permiten iniciar conexiones SSH salientes desde el bastión hacia la estación de administración. |

### Reglas de higiene al usar túneles SSH en laboratorio

1. **Vincular siempre el puerto reenviado a `127.0.0.1`:** escribí explícitamente `-L 127.0.0.1:8080:...` o `-D 127.0.0.1:1080`. Así garantizás que solo tu propia estación de trabajo pueda usar el túnel local.
2. **Usar `-N` (no ejecutar comando remoto):** cuando solo necesitás el túnel de red, la bandera `-N` abre el canal cifrado sin reservar una shell interactiva innecesaria en el bastión.
3. **Salto nativo con `ProxyJump` (`-J`):** para administrar un servidor Linux interno a través de un bastión SSH oficial, OpenSSH ofrece el flag `-J` que encadena la autenticación de extremo a extremo sin copiar claves privadas al bastión intermedio:

```bash
# Conexión SSH directa al host interno 10.10.20.50 saltando por el bastión 192.168.56.20
ssh -J admin_lab@192.168.56.20 admin_interno@10.10.20.50
```

### Uso de un proxy SOCKS5 local con herramientas de consola

Cuando levantás un proxy SOCKS5 local en `127.0.0.1:1080` con `ssh -N -D 127.0.0.1:1080`:
- **`curl` nativo:** `curl --socks5-hostname 127.0.0.1:1080 http://10.10.20.50:8080/` (la variante `--socks5-hostname` resuelve también los nombres DNS a través del túnel en el extremo remoto).
- **`proxychains4` en Linux:** intercepta las llamadas a la biblioteca estándar de sockets (`connect()`) de programas TCP para redirigirlos por el puerto SOCKS configurado en `/etc/proxychains4.conf` (`socks5 127.0.0.1 1080`). Recordá que un proxy SOCKS transporta conexiones **TCP** completas (por eso con Nmap a través de SOCKS solo funcionan conexiones TCP completas `-sT -Pn`, nunca paquetes crudos ICMP ni SYN scan `-sS`).

## 3. Reenvío de puertos en Windows y túneles de capa de transporte/red

En entornos Windows, el subsistema de red nativo permite inspeccionar y configurar reglas de reenvío TCP IPv4/IPv6 mediante la utilidad administrativa **`netsh interface portproxy`**:

```powershell
# Listar todas las reglas de reenvío de puertos configuradas en un host Windows (clave en auditorías y DFIR)
netsh interface portproxy show all

# Ejemplo en laboratorio: reenviar tráfico del puerto local 8080 hacia 10.10.20.50:80
netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=8080 connectaddress=10.10.20.50 connectport=80

# Eliminar la regla al finalizar la prueba de laboratorio
netsh interface portproxy delete v4tov4 listenaddress=127.0.0.1 listenport=8080
```

::: nota Rastro en el Registro de Windows de `netsh portproxy`
Toda regla creada con `netsh interface portproxy` queda almacenada de forma persistente en la clave del Registro:
`HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp`
y es ejecutada por el servicio `iphlpsvc` (*IP Helper*). En una investigación SOC/DFIR (Tomo IV), auditar esta clave del Registro y el Event ID `5156` de Windows Filtering Platform permite detectar de inmediato si alguien configuró un reenvío de puertos interno en un servidor Windows.
:::

Además de SSH y `netsh`, en laboratorios de infraestructura se estudian tres herramientas y arquitecturas adicionales:
1. **Túneles TCP/UDP encapsulados sobre HTTP/WebSockets (como *Chisel*, `socat` y `plink.exe` en Windows):** útiles en laboratorios para comprender cómo redirigir puertos o cómo una conexión WebSocket persistente (`HTTP/1.1 101 Switching Protocols`) puede multiplexar un canal SOCKS5, y por qué los proxies corporativos deben inspeccionar conexiones WebSockets de larga duración.
2. **Túneles basados en interfaz virtual TUN/TAP (como *Ligolo-ng* o WireGuard/OpenVPN):** en lugar de usar un proxy SOCKS en capa de aplicación con `proxychains`, crean una interfaz de red virtual `tun0` en el sistema operativo local y agregan una ruta (`ip route add 10.10.20.0/24 dev tun0`), permitiendo que el kernel enrute paquetes de forma nativa.
3. **Frameworks de Comando y Control modulares (ej. *Sliver C2*) y detección de *beaconing* con `RITA`:** en ejercicios de Red Team autorizados, los operadores estudian canales cifrados (HTTPS/mTLS/DNS) con intervalos de comunicación (*jitter*) para validar si los controles NSM los detectan. Desde el lado defensivo (**Blue Team**), herramientas abiertas como **`RITA` (*Real Intelligence Threat Analysis*)** ingieren logs de **Zeek** (`conn.log`, `dns.log`) para identificar automáticamente conexiones periódicas (*beaconing*) y canales DNS encubiertos.

## 4. Protocolos de administración remota y movimiento lateral en redes corporativas

En una red empresarial Windows/Linux, los administradores —y los auditores durante ejercicios autorizados— interactúan entre equipos utilizando cinco protocolos estándar que debés conocer tanto en su operación legítima como en su telemetría defensiva:

| Protocolo / Servicio | Puertos estándar | Mecanismo técnico | Telemetría de detección en el host destino |
|---|---|---|---|
| **SSH (OpenSSH)** | `TCP/22` | Sesión de consola cifrada, ejecución remota de comandos y transferencia SFTP/SCP. | `/var/log/auth.log` o `journalctl -u ssh` (Linux); Event Log `OpenSSH/Operational` Event ID `4` (Windows). |
| **SMB y Recursos Administrativos (`ADMIN$`, `C$`, `IPC$`)** | `TCP/445` | Acceso a archivos y RPC sobre *Named Pipes* (`svcctl` para crear/iniciar servicios remotos). | Event ID `4624` (Logon Type `3` — Network), Event ID `5140`/`5145` (acceso a recurso compartido), Event ID `7045` (nuevo servicio instalado). |
| **WinRM / PowerShell Remoting** | `TCP/5985` (HTTP cifrado con Kerberos/NTLM) y `TCP/5986` (HTTPS) | Protocolo WS-Management (`Enter-PSSession`, `Invoke-Command`); lanza el proceso hijo `wsmprovhost.exe` en el destino. | Event ID `4624` (Logon Type `3`), `Microsoft-Windows-WinRM/Operational` (ID `6`, `91`) y `PowerShell/Operational` (`4104`) bajo `wsmprovhost.exe`. |
| **WMI / CIM Remoto** | `TCP/135` (RPC Endpoint Mapper) + puertos dinámicos altos (`49152–65535`) | Invocación de métodos de gestión remota; el comando ejecutado nace como proceso hijo de **`WmiPrvSE.exe`**. | Sysmon Event ID `1` / Security `4688` mostrando `ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe`. |
| **RDP (Remote Desktop Protocol)** | `TCP/3389` | Sesión gráfica interactiva remota en Windows. | Event ID `4624` (**Logon Type `10`** — RemoteInteractive) y `TerminalServices-LocalSessionManager/Operational` (ID `21`, `24`, `25`). |

### Suite `Impacket` y huella operativa en movimiento lateral

En evaluaciones prácticas de infraestructura y Active Directory (como **PEN-200 / OSCP**), la suite en Python **Impacket** permite probar movimiento lateral desde una estación Linux utilizando contraseñas, hashes NT (**Pass-the-Hash** con `-hashes LM:NT`) o tickets Kerberos en caché (`-k -no-pass` con `KRB5CCNAME`):

| Herramienta Impacket | Canal utilizado | Huella y artefacto generado en el destino | Impacto en ruido / OPSEC |
| :--- | :--- | :--- | :--- |
| **`psexec.py`** | SMB (`445`) + SCM (`svcctl`) | Sube un binario aleatorio a `ADMIN$`, crea e inicia un servicio nuevo (**Event ID `7045`** + `Sysmon ID 11`). | **Muy ruidoso**; dispara alertas inmediatas de servicio nuevo y AV sobre el ejecutable temporal. |
| **`smbexec.py`** | SMB (`445`) + SCM sin binario propio | Crea un servicio efímero que invoca `cmd.exe /Q /c ...` redirigiendo la salida a un archivo en `C$\__output`. | **Alto ruido** (`7045` + creación de `cmd.exe` bajo `services.exe`). |
| **`wmiexec.py`** | RPC (`135`) + WMI (`49152+`) + SMB | Ejecuta comandos vía WMI sin crear servicio; procesos nacen bajo **`WmiPrvSE.exe`** y escribe salida temporal en `ADMIN$`. | **Moderado**; evita `7045`, preferido en evaluaciones frente a `psexec.py`. |
| **`atexec.py`** | RPC (`135`) + Task Scheduler (`atsvc`) | Crea y ejecuta una tarea programada única (`Event ID 4698`) bajo `svchost.exe` (`Schedule`). | **Moderado**; deja traza clara de creación de tarea programada. |

```bash
# Ejemplo en laboratorio autorizado: sesión semi-interactiva vía WMI pasando hash NT (sin contraseña en claro)
impacket-wmiexec DOMINIO/admin_lab@10.10.20.30 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0

# Alternativa por Kerberos usando un ticket .ccache obtenido previamente en laboratorio
export KRB5CCNAME=/tmp/admin_lab.ccache
impacket-wmiexec -k -no-pass DOMINIO/admin_lab@srv02.lab.local
```

### Metodología *Assumed Breach* en cadenas multi-salto

A diferencia del pentest perimetral tradicional donde se empieza desde Internet sin credenciales, el enfoque ***Assumed Breach*** (muy común en PEN-200 y auditorías internas) parte suponiendo que un adversario ya obtuvo acceso inicial en una estación de usuario o un par usuario/contraseña de dominio, y mide hasta dónde logra avanzar mediante movimiento lateral y escalada:

1. **Triage inicial del primer nodo:** recolectar interfaces de red (`ipconfig /all`, `arp -a`), sesiones activas, variables de entorno y archivos de configuración en busca de nuevas subredes internas y credenciales locales o de dominio.
2. **Despliegue de túnel hacia la red interna:** levantar un pivote nativo (**`Ligolo-ng`** mediante interfaz `tun0` o **`Chisel`** SOCKS5 sobre `proxychains4`) para que las herramientas en la estación del auditor alcancen la segunda subred sin necesidad de instalar todo en la víctima.
3. **Enumeración de Active Directory a través del túnel:** lanzar recolectores de **`BloodHound`** y comprobaciones puntuales con **`NetExec` (`nxc smb`)** para identificar en qué servidores tiene permisos administrativos locales la cuenta comprometida (`(Pwn3d!)`) y qué rutas llevan hacia usuarios con mayor privilegio.
4. **Salto lateral y cosecha incremental:** conectarse al siguiente servidor mediante `wmiexec.py`, `Evil-WinRM` o RDP (con credenciales válidas o Pass-the-Hash), analizar qué nuevas credenciales o tickets de otras cuentas residen en ese servidor y repetir el ciclo hasta validar la ruta completa al Tier 0.

## 5. Ejemplo paso a paso: laboratorio de dos subredes con Docker y túnel local

Podemos simular una arquitectura de dos subredes aisladas en nuestra propia máquina en menos de dos minutos usando redes bridge de Docker o el reenvío local de SSH/Python:

```bash
# 1. Verificar qué puertos escuchan solo en loopback (127.0.0.1) dentro de un servidor Linux del lab
ss -tulnp | grep "127.0.0.1"
```

Salida típica cuando un servicio interno (como una consola de administración o base de datos PostgreSQL/Redis) solo escucha localmente dentro del servidor bastión:

```text
tcp   LISTEN 0   128   127.0.0.1:5432   0.0.0.0:*   users:(("postgres",pid=1142,fd=6))
tcp   LISTEN 0   128   127.0.0.1:9000   0.0.0.0:*   users:(("python3",pid=1380,fd=4))
```

Si desde un escaneo externo con Nmap sobre la IP `192.168.56.20` del servidor bastión solo se veía abierto `TCP/22`, al autenticarnos por SSH y consultar `ss -tulnp` descubrimos el servicio interno en `127.0.0.1:9000`. Para inspeccionarlo desde el navegador de nuestra estación de trabajo sin exponer el puerto `9000` a toda la red LAN:

```bash
# 2. Abrir un túnel SSH local desde nuestra estación hacia el loopback del servidor de laboratorio
ssh -N -L 127.0.0.1:9000:127.0.0.1:9000 usuario_lab@192.168.56.20

# 3. En otra terminal local, consultar el servicio a través del túnel cifrado
curl -i http://127.0.0.1:9000/
```

::: defensa Perspectiva defensiva, detección y mitigación (Microsegmentación)
1. **Bloquear la comunicación horizontal entre estaciones de trabajo (*Workstation-to-Workstation Blocking*):** en una red corporativa ninguna PC de usuario final tiene motivo para conectarse por SMB (`445`), WinRM (`5985`), RPC (`135`) o RDP (`3389`) a la PC de otro usuario final. Configurar el Firewall de Windows mediante GPO para permitir esos puertos **únicamente desde la subred dedicada de servidores de administración (PAW / Jump Hosts)** corta de raíz el 90 % del movimiento lateral.
2. **Restringir el reenvío de puertos en servidores SSH bastión:** en `/etc/ssh/sshd_config`, si un servidor SSH no actúa oficialmente como bastión de salto, configurá `AllowTcpForwarding no`, `GatewayPorts no` y `PermitTunnel no`, o limitá los destinos permitidos con la directiva `PermitOpen 10.10.20.50:443`.
3. **Auditar reglas `portproxy` y conexiones de larga duración en NSM:** monitoreá cambios en `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy` y configurá Zeek/Suricata para alertar sobre sesiones SSH o WebSockets internas de larga duración con alto volumen de bytes entre zonas de distinta criticidad.
:::

## Práctica en laboratorio local

1. En tu VM de laboratorio o entorno local, ejecutá `ss -tulnp` (Linux) o `Get-NetTCPConnection -State Listen` (Windows PowerShell) y clasificá todos los puertos en escucha en dos columnas: los que escuchan únicamente en `127.0.0.1` / `::1` (solo accesibles localmente o mediante reenvío local) y los que escuchan en `0.0.0.0` / `::` (expuestos a la red).
2. En una VM Windows de laboratorio, ejecutá `netsh interface portproxy show all` y consultá con PowerShell la clave `Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp" -ErrorAction SilentlyContinue` para verificar que no existan reenvíos ocultos.
3. Redactá una política de firewall de host (en sintaxis `nftables`/`ufw` para Linux y `New-NetFirewallRule` para Windows) que permita la administración remota (`22`, `445`, `5985`, `3389`) exclusivamente desde una subred de administración `10.10.99.0/24`.

::: practica Entregable mínimo
Tabla de inventario de servicios en escucha (`127.0.0.1` vs `0.0.0.0`), salida de verificación de `portproxy` y los comandos de microsegmentación para firewall de Linux y Windows.
:::

## Preguntas de repaso

**1. ¿Cuál es la diferencia práctica entre un reenvío de puerto local SSH (`ssh -L`) y un reenvío dinámico SOCKS5 (`ssh -D`)?** El reenvío local `-L` mapea un puerto local hacia un **único host y puerto destino fijo** (por ejemplo `10.10.20.50:445`). En cambio, el reenvío dinámico `-D` levanta un servidor proxy **SOCKS5** local que permite que las aplicaciones clientes elijan dinámicamente a qué dirección IP y puerto de la red remota desean conectarse en cada petición.

**2. ¿Por qué al usar Nmap a través de un proxy SOCKS5 (con `proxychains`) es necesario utilizar escaneo de conexión TCP completa (`-sT -Pn`) en lugar de escaneo SYN (`-sS`) o ping ICMP?** Porque el protocolo SOCKS5 opera en la capa de sesión/transporte estableciendo conexiones TCP completas mediante la llamada al sistema `connect()` desde el extremo remoto del túnel; no transporta paquetes IP crudos (*raw sockets*) ni paquetes ICMP ni medios handshakes SYN.

**3. Si un servidor de aplicaciones interno escucha únicamente en `127.0.0.1:9000`, ¿por qué no aparece al escanear la IP de red del servidor desde otra máquina, y cómo puede un administrador acceder a él de forma segura?** No aparece desde afuera porque el socket está vinculado exclusivamente a la interfaz loopback (`127.0.0.1`), por lo que el kernel descarta cualquier paquete dirigido a ese puerto que entre por la tarjeta de red física (`eth0`). Un administrador autenticado por SSH puede acceder de forma cifrada mediante `ssh -N -L 127.0.0.1:9000:127.0.0.1:9000 usuario@servidor`.

**4. ¿Qué procesos padre en Windows revelan en los logs de creación de procesos (Event ID `4688` o Sysmon Event ID `1`) que un comando fue ejecutado remotamente mediante WinRM frente a WMI?** Una ejecución remota por **WinRM / PowerShell Remoting** crea los procesos hijos bajo **`wsmprovhost.exe`**, mientras que una ejecución remota invocada a través de **WMI** crea los procesos hijos bajo **`WmiPrvSE.exe`**.

**5. ¿Cómo reduce la microsegmentación de estaciones de trabajo (*Workstation-to-Workstation Blocking*) el impacto de una intrusión en una red corporativa?** Al bloquear en el firewall local de cada estación de trabajo las conexiones entrantes SMB (`445`), WinRM (`5985/5986`), RPC (`135`) y RDP (`3389`) provenientes de otras estaciones de usuario final (permitiéndolas solo desde la subred de administración), un equipo comprometido no puede propagarse horizontalmente hacia las computadoras de otros empleados aunque disponga de credenciales locales compartidas.

## Antes de avanzar

Verificá que podés:
- Distinguir cuándo usar `ssh -L`, `ssh -R`, `ssh -D` y `ssh -J` (`ProxyJump`).
- Identificar puertos internos vinculados a `127.0.0.1` frente a `0.0.0.0`.
- Reconocer la huella en red y en procesos locales de SSH, SMB, WinRM, WMI y RDP, y diseñar reglas de microsegmentación.

::: nota Puerta de salida
Con el dominio de redes segmentadas y protocolos de administración remota, estás listo para entrar al corazón de las redes corporativas empresariales: avanzá al **Capítulo 3.6 · Active Directory: arquitectura, LDAP, PowerView y BloodHound**.
:::

## Referencias y estándares abiertos

- **Manual oficial de OpenSSH (`man ssh` y `man sshd_config`):** documentación de `-L`, `-R`, `-D`, `-J` (`ProxyJump`) y directivas `AllowTcpForwarding` / `PermitOpen`.
- **RFC 1928 (SOCKS Protocol Version 5):** especificación del protocolo de proxy SOCKS5.
- **Microsoft Learn — Netsh Interface Portproxy & Windows Filtering Platform:** administración y auditoría de reglas de reenvío TCP en Windows.
- **NSA / CISA — Network Segmentation and Zero Trust Architecture Guidance:** principios de microsegmentación y aislamiento de redes de administración.
