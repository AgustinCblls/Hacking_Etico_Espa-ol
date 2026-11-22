::: nota Objetivo de la lección
Al terminar este capítulo vas a poder mapear tráfico real sobre los modelos OSI y TCP/IP, calcular subredes IPv4 en notación CIDR sin herramientas automáticas, interpretar el intercambio TCP (3-way handshake y banderas), distinguir ARP, ICMP, UDP y DNS, y capturar e inspeccionar paquetes locales con `tcpdump` y Wireshark.
:::

**Prerrequisitos:** Capítulo 1.1 completado y contenedor de laboratorio `lab_web` accesible en `127.0.0.1:8080`. **Duración sugerida:** 2,5 horas.

## Modelo OSI frente a TCP/IP y proceso de encapsulación

Cada mensaje que atraviesa una red viaja envuelto en capas sucesivas de encabezados (encapsulación en origen) que el destino retira en orden inverso (desencapsulación). El modelo **OSI** (7 capas) sirve como lenguaje común para diagnosticar fallas y ubicar controles de seguridad, mientras que la pila **TCP/IP** (4 capas) describe la arquitectura efectivamente implementada en Internet y en redes locales.

| Capa OSI | Equivalente TCP/IP | PDU (Unidad) | Protocolos representativos | Dispositivo / Control típico |
| :--- | :--- | :--- | :--- | :--- |
| **7. Aplicación** | Aplicación | Datos | HTTP/HTTPS, DNS, SSH, SMB | WAF, proxy inverso, IDS de capa 7 |
| **6. Presentación** | Aplicación | Datos | TLS/SSL, codificación UTF-8, JSON | Inspección TLS, validación de certificados |
| **5. Sesión** | Aplicación | Datos | NetBIOS, RPC, sesiones HTTP | Gestión de tokens y tiempos de expiración |
| **4. Transporte** | Transporte | Segmento (TCP) / Datagrama (UDP) | TCP, UDP, SCTP | Firewall stateful, balanceador L4 |
| **3. Red** | Internet | Paquete | IPv4, IPv6, ICMP, IPsec | Router, firewall L3, ACLs de red |
| **2. Enlace de datos** | Acceso a red | Trama (Frame) | Ethernet (802.3), ARP, Wi-Fi (802.11), VLAN (802.1Q) | Switch gestionable, Port Security, DAI |
| **1. Física** | Acceso a red | Bits | Par trenzado, fibra óptica, radiofrecuencia | Seguridad física de racks y puertos |

Comprender en qué capa ocurre un evento evita errores frecuentes: por ejemplo, el filtrado por dirección MAC opera en Capa 2 (solo dentro del dominio de difusión local), mientras que el enrutamiento entre subredes opera en Capa 3 mediante direcciones IP.

## Direccionamiento IPv4 y cálculo práctico de subredes CIDR

Una dirección IPv4 tiene **32 bits** divididos en cuatro octetos de 8 bits expresados en decimal (`0` a `255`). La notación **CIDR** (*Classless Inter-Domain Routing*) añade un sufijo `/N` que indica cuántos bits consecutivos desde la izquierda identifican la **porción de red**; los `32 - N` bits restantes identifican al **host**.

### Rangos reservados clave

- **Redes privadas (RFC 1918):** `10.0.0.0/8`, `172.16.0.0/12` (`172.16.0.0` → `172.31.255.255`) y `192.168.0.0/16`. No son enrutables en Internet público y son la base de toda LAN y laboratorio local.
- **Loopback:** `127.0.0.0/8` (usualmente `127.0.0.1`), tráfico que nunca abandona el host local.
- **Link-Local (APIPA):** `169.254.0.0/16`, asignado automáticamente cuando falla DHCP.

### Tabla de referencia rápida CIDR

| Prefijo | Máscara decimal | Salto en el octeto crítico | Direcciones totales | Hosts utilizables (`2^(32 - N) - 2`) |
| :---: | :---: | :---: | :---: | :---: |
| `/24` | `255.255.255.0` | 1 (4.º octeto: 256) | 256 | 254 |
| `/25` | `255.255.255.128` | 128 | 128 | 126 |
| `/26` | `255.255.255.192` | 64 | 64 | 62 |
| `/27` | `255.255.255.224` | 32 | 32 | 30 |
| `/28` | `255.255.255.240` | 16 | 16 | 14 |
| `/29` | `255.255.255.248` | 8 | 8 | 6 |
| `/30` | `255.255.255.252` | 4 | 4 | 2 (enlaces punto a punto) |

### Método manual en cuatro pasos

Tomemos el host `10.10.20.135/27` para determinar su subred exacta:

1. **Identificá el octeto crítico y el tamaño de bloque:** `/27` ocupa 24 bits en los tres primeros octetos y 3 bits en el cuarto (`27 - 24 = 3`). Quedan `8 - 3 = 5` bits para hosts → tamaño de bloque `2^5 = 32` (máscara `255.255.255.224`).
2. **Ubicá el múltiplo de 32 inmediatamente menor o igual a `135`:** los bloques son `0, 32, 64, 96, 128, 160...`. Por lo tanto, la **dirección de red** es `10.10.20.128`.
3. **Calculá el broadcast:** es una dirección menos que el siguiente bloque (`160 - 1 = 159`) → `10.10.20.159`.
4. **Determiná el rango útil de hosts:** desde `red + 1` hasta `broadcast - 1` → `10.10.20.129` a `10.10.20.158` (30 hosts utilizables).

::: aviso Verificación mental obligatoria
Antes de definir un objetivo en una herramienta de red o en un archivo de firewall, calculá siempre qué direcciones quedan dentro del prefijo CIDR. Confundir `/24` con `/16` multiplica el alcance por `256` (de 254 a 65.534 hosts) y puede violar las Reglas de Enfrentamiento.
:::

## Protocolos centrales: ARP, ICMP, TCP, UDP y DNS

### ARP e ICMP (Capa 2 y Capa 3)

- **ARP (Address Resolution Protocol):** traduce una dirección IPv4 a una dirección física MAC dentro del mismo segmento Ethernet mediante una trama broadcast (`Who has 192.168.56.1? Tell 192.168.56.10`) y una respuesta unicast. Porque ARP carece de autenticación nativa, los segmentos sin protección son vulnerables a **ARP Spoofing** (envenenamiento de caché ARP para interceptar tráfico en la LAN).
- **ICMP (Internet Control Message Protocol):** transporta mensajes de diagnóstico y error encapsulados directamente sobre IP (sin puertos). Los tipos esenciales en análisis son **Type 8 / Code 0** (*Echo Request*), **Type 0 / Code 0** (*Echo Reply*), **Type 3** (*Destination Unreachable*, indicando red, host o puerto inalcanzable) y **Type 11** (*Time Exceeded*, base del funcionamiento de `traceroute`).

### TCP: 3-way handshake, cierre y banderas

TCP (RFC 9293) es un protocolo **orientado a conexión** y confiable. Antes de intercambiar datos de aplicación, cliente y servidor sincronizan sus números de secuencia iniciales (**ISN**) mediante el **3-way handshake**:

1. **Cliente → Servidor (`SYN`):** propone su número de secuencia inicial `SEQ = x`.
2. **Servidor → Cliente (`SYN, ACK`):** acepta la conexión, envía su propio `SEQ = y` y confirma el del cliente con `ACK = x + 1`.
3. **Cliente → Servidor (`ACK`):** confirma el `SEQ` del servidor con `ACK = y + 1`. La sesión queda en estado `ESTABLISHED`.

El cierre ordenado usa un intercambio de 4 pasos con paquetes `FIN` y `ACK`, mientras que un cierre abrupto o el rechazo de un puerto cerrado se señala con `RST`.

| Bandera TCP | Notación en `tcpdump` | Función técnica | Significado habitual en auditoría |
| :--- | :---: | :--- | :--- |
| **SYN** | `[S]` | Inicia conexión y sincroniza números de secuencia. | Inicio normal o sondeo de puertos abiertos (SYN scan). |
| **ACK** | `[.]` | Confirma recepción de bytes hasta `ACK - 1`. | Presente en casi todo paquete tras el primer `SYN`. |
| **PSH** | `[P.]` | Indica al receptor entregar los datos al proceso sin esperar llenado de búfer. | Marca tráfico interactivo o solicitudes HTTP/SSH con carga útil. |
| **FIN** | `[F.]` | Cierre ordenado de envío de datos en un sentido. | Fin normal de sesión o sondeos sigilosos contra firewalls antiguos. |
| **RST** | `[R]` o `[R.]` | Reinicia y aborta inmediatamente la conexión. | Puerto cerrado (`RST,ACK`) o corte forzado por firewall/IPS. |
| **URG** | `[U]` | Marca puntero de datos urgentes (en desuso en protocolos modernos). | Raro en tráfico legítimo; suele delatar paquetes artesanales o anomalías. |

### UDP y resolución DNS

- **UDP (User Datagram Protocol):** protocolo sin conexión con una cabecera minimalista de solo **8 bytes** (puerto origen, puerto destino, longitud, checksum). No garantiza orden ni retransmisión, lo que reduce latencia para **DNS**, **DHCP**, **NTP**, **SNMP** y **QUIC (HTTP/3)**. Al no tener handshake, un puerto UDP abierto a menudo no responde nada ante una sonda genérica, mientras que un puerto cerrado devuelve `ICMP Type 3 Code 3 (Port Unreachable)`.
- **DNS (Domain Name System, RFC 1035):** opera normalmente sobre **UDP/53** para consultas estándar y sobre **TCP/53** para transferencias de zona (`AXFR`) o respuestas grandes (y TCP/853 en DNS over TLS). Un cliente envía una consulta recursiva a su resolvedor local, que recorre de forma iterativa los servidores raíz (`.`), el TLD (`.com`, `.org`) y el servidor autoritativo del dominio. Los registros más relevantes son `A` (IPv4), `AAAA` (IPv6), `CNAME` (alias), `NS` (servidores de nombres), `MX` (correo), `TXT` (políticas SPF/DMARC y verificación) y `PTR` (resolución inversa IP → nombre).

## Captura y análisis con `tcpdump` y Wireshark

Capturar paquetes permite ver la verdad exacta de la red sin depender de lo que afirme una aplicación. Es fundamental distinguir dos lenguajes de filtrado distintos:

- **Filtros de captura BPF (*Berkeley Packet Filter*):** usados por `tcpdump` y por el cuadro *Capture Filter* de Wireshark. Se ejecutan en el kernel **antes** de escribir a disco para no saturar almacenamiento ni CPU.
- **Filtros de visualización (*Display Filters*):** usados por Wireshark y `tshark -Y` para inspeccionar paquetes ya capturados con granularidad de capa 7.

| Objetivo de filtrado | Filtro de captura BPF (`tcpdump`) | Filtro de visualización (Wireshark / `tshark -Y`) |
| :--- | :--- | :--- |
| Tráfico de un host exacto | `host 127.0.0.1` | `ip.addr == 127.0.0.1` |
| Solo tráfico TCP al puerto 8080 | `tcp port 8080` | `tcp.port == 8080` |
| Solo paquetes `SYN` iniciales (sin `ACK`) | `tcp[tcpflags] & (tcp-syn\|tcp-ack) == tcp-syn` | `tcp.flags.syn == 1 and tcp.flags.ack == 0` |
| Tráfico DNS (UDP o TCP 53) | `port 53` | `dns` |
| Peticiones HTTP GET | No filtra semántica HTTP nativa | `http.request.method == "GET"` |
| Paquetes ICMP de error o ping | `icmp` | `icmp.type == 8 or icmp.type == 0` |

## 5. Conmutación (VLANs), Enrutamiento, NAT e IPv6 en redes modernas

Las redes corporativas raramente funcionan como una única red plana: combinan conmutación de Capa 2 segmentada mediante VLANs, enrutamiento dinámico/estático en Capa 3, traducción de direcciones NAT y convivencia *dual-stack* con IPv6.

| Tecnología / Protocolo | Función en la red | Implicación de seguridad y auditoría |
|---|---|---|
| **Switches y VLANs (802.1Q)** | Separan dominios de difusión (*broadcast*) lógicos sobre switches físicos mediante etiquetas de 12 bits (`VLAN ID`). | Configurar puertos de usuario en modo acceso fijo (`switchport mode access`), deshabilitar DTP y separar las VLANs de servidores, invitados, VoIP y gestión (*out-of-band*). |
| **Enrutamiento (Estático, OSPF, BGP) y NAT** | Intercambian rutas entre subredes/sistemas autónomos (`OSPF` en LAN/WAN corporativa, `BGP` entre proveedores) y traducen direcciones privadas RFC 1918 (`NAT`) al salir a internet. | Exigir autenticación criptográfica en vecinos `OSPF`/`BGP` y recordar que **NAT no es un firewall**: solo traduce IPs/puertos; la seguridad real depende de reglas de filtrado con estado (*stateful*). |
| **IPv6 y NDP (*Neighbor Discovery*)** | Direcciones de 128 bits (`fe80::/10` link-local, `fc00::/7` únicas locales, `2000::/3` globales) que reemplazan ARP por ICMPv6 **NDP** y usan **SLAAC** o DHCPv6. | Incluso en redes "solo IPv4", la pila IPv6 suele venir habilitada por defecto en Windows y Linux. Auditar siempre reglas de firewall IPv6 (`ip6tables`/`nftables`) y activar **RA Guard** en switches. |

## Ejemplo paso a paso: Captura de un 3-way handshake HTTP y consulta DNS en loopback

En esta práctica vas a capturar tráfico real contra el contenedor `lab_web` del Capítulo 1.1 (`127.0.0.1:8080`) usando dos terminales en tu máquina Linux de laboratorio.

### Paso 1: Iniciar la captura dirigida en loopback (Terminal 1)

```bash
mkdir -p evidencias/cap1_2
# -i lo: interfaz loopback | -nn: sin resolución DNS ni nombres de puerto
# -S: números de secuencia absolutos | -w: guardar en archivo pcap
sudo tcpdump -i lo -nn -S -w evidencias/cap1_2/http_local.pcap "tcp port 8080"
```

### Paso 2: Generar una petición HTTP mínima (Terminal 2)

```bash
curl -s -o /dev/null -w "HTTP %{http_code} | Tiempo total: %{time_total}s\n" http://127.0.0.1:8080/
```

Salida esperada:

```text
HTTP 200 | Tiempo total: 0.004120s
```

Detené `tcpdump` en Terminal 1 con `Ctrl+C`.

### Paso 3: Leer y diseccionar cada paquete del archivo `.pcap`

```bash
tcpdump -r evidencias/cap1_2/http_local.pcap -nn
```

Salida real comentada (los números de puerto efímero y secuencia varían por ejecución):

```text
# 1) Handshake paso 1: cliente (puerto efímero 51422) envía SYN al puerto 8080
18:12:04.101102 IP 127.0.0.1.51422 > 127.0.0.1.8080: Flags [S], seq 2948102011, win 65495, length 0

# 2) Handshake paso 2: servidor responde SYN+ACK confirmando ack=1 (relativo)
18:12:04.101129 IP 127.0.0.1.8080 > 127.0.0.1.51422: Flags [S.], seq 1084729104, ack 2948102012, win 65483, length 0

# 3) Handshake paso 3: cliente confirma con ACK puro; conexión ESTABLISHED
18:12:04.101144 IP 127.0.0.1.51422 > 127.0.0.1.8080: Flags [.], ack 1, win 512, length 0

# 4) Datos de aplicación: cliente envía solicitud HTTP GET (78 bytes) con bandera PSH+ACK
18:12:04.101210 IP 127.0.0.1.51422 > 127.0.0.1.8080: Flags [P.], seq 1:79, ack 1, win 512, length 78: HTTP: GET / HTTP/1.1

# 5) Respuesta HTTP 200 OK del servidor Nginx y cierre ordenado posterior
18:12:04.101502 IP 127.0.0.1.8080 > 127.0.0.1.51422: Flags [P.], seq 1:239, ack 79, win 512, length 238: HTTP: HTTP/1.1 200 OK
18:12:04.101811 IP 127.0.0.1.51422 > 127.0.0.1.8080: Flags [F.], seq 79, ack 854, win 512, length 0
18:12:04.101845 IP 127.0.0.1.8080 > 127.0.0.1.51422: Flags [F.], seq 854, ack 80, win 512, length 0
18:12:04.101860 IP 127.0.0.1.51422 > 127.0.0.1.8080: Flags [.], ack 855, win 512, length 0
```

### Paso 4: Inspeccionar cabeceras de aplicación y DNS con `tshark` / `dig`

```bash
# Extraer campos específicos del pcap con tshark (CLI de Wireshark)
tshark -r evidencias/cap1_2/http_local.pcap -Y "http" \
  -T fields -e frame.number -e ip.src -e tcp.srcport -e http.request.method -e http.response.code

# Consultar el resolvedor local (127.0.0.53 en systemd-resolved) con dig
dig +noall +answer +stats localhost A
```

```text
4   127.0.0.1   51422   GET
5   127.0.0.1   8080            200

localhost.              0       IN      A       127.0.0.1
;; Query time: 0 msec
;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)
```

::: defensa Perspectiva defensiva y mitigación
La pila TCP/IP original fue diseñada para interoperabilidad, no para entornos hostiles. Para endurecer una red frente a abusos de capas 2, 3 y 4 aplicá estas medidas concretas:
1. **Mitigación de inundaciones SYN (SYN Flood):** habilitá `net.ipv4.tcp_syncookies = 1` en hosts Linux para no agotar la cola de conexiones semiabiertas (`SYN_RECV`).
2. **Protección de Capa 2 en switches:** activá **DHCP Snooping** junto con **Dynamic ARP Inspection (DAI)** y **Port Security** para bloquear ARP Spoofing y servidores DHCP falsos en la LAN.
3. **Cifrado obligatorio en tránsito:** sustituí protocolos en claro (HTTP, Telnet, FTP, DNS plano) por TLS 1.3 (HTTPS, SSH, DoT/DoH) y validá registros con **DNSSEC** cuando corresponda.
4. **Segmentación y filtrado de egreso:** dividí servidores, estaciones de trabajo y administración en VLANs/subredes separadas con listas de control de acceso que restrinjan tanto el tráfico entrante como el saliente innecesario (por ejemplo, bloqueando salida directa al puerto UDP/TCP 53 desde servidores que solo deben consultar el DNS interno).
:::

## Práctica en laboratorio local

1. Calculá manualmente, sin calculadoras online, la dirección de red, el broadcast, la máscara decimal y el rango de hosts utilizables para estas tres redes: `192.168.56.64/26`, `172.16.40.200/28` y `10.20.30.13/30`.
2. Capturá con `tcpdump` dos escenarios separados en tu interfaz loopback o Host-Only:
   - Una petición HTTP exitosa contra `127.0.0.1:8080` (`evidencias/cap1_2/puerto_abierto.pcap`).
   - Un intento de conexión contra un puerto cerrado local como `127.0.0.1:9999` (`evidencias/cap1_2/puerto_cerrado.pcap`).
3. Abrí ambos archivos `.pcap` en Wireshark (o inspeccionalos con `tshark`) y compará las banderas TCP que devolvió el kernel en el puerto abierto (`SYN,ACK`) frente al puerto cerrado (`RST,ACK`).
4. Generá el resumen `SHA-256` de tus capturas y notas en `evidencias/cap1_2/manifest.sha256`.

::: practica Entregable mínimo
Guardá en `evidencias/cap1_2/`:
- `calculo_cidr.md`: desarrollo paso a paso de las tres subredes indicadas.
- `puerto_abierto.pcap` y `puerto_cerrado.pcap`: capturas filtradas en tu entorno local.
- `analisis_paquetes.txt`: salida comentada de `tcpdump -r` o `tshark` explicando el 3-way handshake y el paquete `RST,ACK`.
- `manifest.sha256`: verificación de integridad de los tres archivos anteriores.
:::

## Preguntas de repaso

**1. ¿Cuántas direcciones IP utilizables para hosts existen en una subred `/26` y por qué se restan dos direcciones al total del bloque?** Existen `62` direcciones utilizables. Un prefijo `/26` deja `32 - 26 = 6` bits de host, lo que produce `2^6 = 64` direcciones totales; se restan siempre 2 porque la primera identifica a la dirección de red y la última corresponde a la dirección de broadcast del segmento.

**2. ¿Qué diferencia existe en la respuesta TCP cuando un cliente envía un paquete `SYN` a un puerto abierto frente a un puerto cerrado sin firewall descartando paquetes?** Un puerto abierto con un servicio escuchando responde con las banderas `SYN,ACK` (`[S.]`) para continuar el 3-way handshake. Un puerto cerrado en un host alcanzable responde inmediatamente con `RST,ACK` (`[R.]`), indicando que no hay ningún proceso aceptando conexiones en ese puerto.

**3. ¿Por qué el protocolo ARP solo funciona dentro de la misma subred local y qué riesgo de seguridad introduce?** ARP utiliza tramas broadcast de Capa 2 (`ff:ff:ff:ff:ff:ff`) que los routers no reenvían hacia otras redes, limitándolo al dominio de difusión local. Como carece de mecanismo criptográfico de autenticación, cualquier host en ese segmento puede enviar respuestas ARP falsas (*ARP Spoofing*) para asociar su MAC con la IP del gateway e interceptar tráfico.

**4. ¿Cuándo debés usar un filtro BPF frente a un filtro de visualización de Wireshark?** El filtro BPF se aplica durante la captura en el kernel (`tcpdump` o captura de Wireshark) para descartar tráfico irrelevante antes de escribirlo en disco y ahorrar memoria/CPU. El filtro de visualización se aplica sobre paquetes ya capturados para analizar campos profundos de protocolos de aplicación como `http.request.method` o `dns.qry.name`.

**5. ¿En qué casos el protocolo DNS utiliza TCP puerto 53 en lugar de UDP puerto 53?** Aunque las consultas comunes usan UDP/53 por baja latencia, DNS emplea TCP/53 cuando una respuesta excede el límite de tamaño de datagrama UDP (marcada con el bit truncado `TC`), para transferencias de zona entre servidores (`AXFR`/`IXFR`) y cuando se requiere transporte confiable orientado a conexión.

## Antes de avanzar

- [ ] Podés identificar en qué capa OSI/TCP-IP actúan ARP, IP, ICMP, TCP, UDP, TLS y HTTP.
- [ ] Resolvés subredes CIDR comunes (`/24` a `/30`) manualmente sin cometer errores en red, broadcast ni rango útil.
- [ ] Distinguís a simple vista `[S]`, `[S.]`, `[.]`, `[P.]`, `[F.]` y `[R.]` en una traza de `tcpdump`.
- [ ] Sabés aplicar filtros BPF en captura y filtros de visualización en Wireshark/`tshark`.

::: nota Puerta de salida
Antes de avanzar al Capítulo 1.3, confirmá que sabés distinguir en una captura propia un handshake completo (`SYN` → `SYN,ACK` → `ACK`) de un rechazo inmediato (`RST,ACK`). Esa lectura será clave cuando analices sockets y servicios activos en Linux y Windows.
:::

## Referencias y estándares abiertos

- RFC 791: *Internet Protocol (IPv4)* — https://datatracker.ietf.org/doc/html/rfc791
- RFC 9293: *Transmission Control Protocol (TCP)* — https://datatracker.ietf.org/doc/html/rfc9293
- RFC 1035: *Domain Names - Implementation and Specification (DNS)* — https://datatracker.ietf.org/doc/html/rfc1035
- RFC 4632: *Classless Inter-Domain Routing (CIDR)* — https://datatracker.ietf.org/doc/html/rfc4632
- Documentación oficial de `tcpdump` y filtros BPF (`pcap-filter(7)`) / Wireshark Display Filter Reference — https://www.tcpdump.org/manpages/pcap-filter.7.html y https://www.wireshark.org/docs/dfref/
