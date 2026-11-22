::: nota Objetivo de la lección
Analizar la arquitectura de autenticación **WPA2/WPA3-Enterprise (IEEE 802.1X / EAP / RADIUS)** y comparar la seguridad de sus métodos EAP principales, evaluar en laboratorio aislado el riesgo de ataques **Evil Twin** frente a clientes mal configurados y mecanismos de **portales cautivos**, comprender las mejoras criptográficas de **WPA3-Personal (SAE)** junto con las vulnerabilidades históricas *Dragonblood*, y diseñar una estrategia integral de defensa inalámbrica corporativa con **WIDS/WIPS**.
:::

::: peligro Alcance estrictamente autorizado y controlado
Los experimentos con puntos de acceso simulados (*Evil Twin*), servidores RADIUS de prueba o verificación de portales cautivos deben realizarse únicamente dentro de tu red de laboratorio aislada (o mediante radios virtuales `mac80211_hwsim` / jaula de RF) y con cuentas ficticias creadas para la práctica. Desplegar un SSID corporativo falso o interceptar identidades fuera de un entorno autorizado y delimitado es ilegal y puede provocar denegación de servicio en la red real.
:::

Cuando una organización supera unas pocas decenas de usuarios, compartir una única contraseña precompartida (PSK) se vuelve ingobernable: cada baja de personal obligaría a rotar la clave en cientos de dispositivos, y cualquier usuario con acceso podría descifrar el tráfico de sus compañeros si captura el *4-Way Handshake*. Para resolverlo, las redes corporativas utilizan **WPA2/WPA3-Enterprise**, mientras que los entornos modernos adoptan **WPA3-Personal** para eliminar el crackeo offline de frases de paso.

## Arquitectura WPA2/WPA3-Enterprise: IEEE 802.1X, EAP y RADIUS

El estándar **IEEE 802.1X** implementa control de acceso a nivel de puerto mediante tres actores diferenciados que separan el transporte inalámbrico de la decisión de identidad:

1. **Supplicant (Cliente)**: la estación inalámbrica (notebook, teléfono) con un cliente 802.1X (`wpa_supplicant` en Linux, perfil MDM en Windows/macOS/iOS/Android) que presenta credenciales o certificados.
2. **Authenticator (Punto de Acceso / Controladora WLC)**: actúa como guardia intermedio. Mantiene el puerto lógico bloqueado para tráfico de datos IP (permitiendo únicamente tramas **EAPOL** / 802.1X) hasta que el servidor central apruebe la autenticación. Encapsula los mensajes **EAP** (*Extensible Authentication Protocol*) recibidos por aire dentro de paquetes **RADIUS** (o Diameter) sobre IP hacia el backend.
3. **Authentication Server (Servidor RADIUS / NAC)**: típicamente FreeRADIUS, Microsoft NPS o Cisco ISE, conectado al directorio corporativo (Active Directory / LDAP / PKI). Verifica la identidad del usuario o dispositivo y devuelve al Authenticator un mensaje `Access-Accept` (junto con la clave maestra derivada para cifrar la sesión Wi-Fi y atributos opcionales de VLAN dinámica) o `Access-Reject`.

### Comparativa de seguridad entre métodos EAP

EAP es un marco extensible que soporta múltiples mecanismos de autenticación dentro de un túnel TLS o directamente sobre el enlace:

| Método EAP | Autenticación del servidor | Autenticación del cliente | Riesgo principal ante mala configuración |
| :--- | :--- | :--- | :--- |
| **EAP-PEAP (con MSCHAPv2)** | Certificado TLS del servidor RADIUS | Usuario + contraseña vía **MSCHAPv2** dentro del túnel TLS | Si el endpoint no valida el certificado del servidor, un *Evil Twin* obtiene el desafío/respuesta NetNTLMv1 (MSCHAPv2) crackeable |
| **EAP-TTLS (PAP / MSCHAPv2)** | Certificado TLS del servidor RADIUS | Credenciales (PAP, CHAP o MSCHAPv2) dentro del túnel TLS | Igual que PEAP: si el cliente omite verificar la CA y el *SAN/CN* del RADIUS, expone credenciales al AP falso |
| **EAP-PWD** | Basado en contraseña compartida (PAKE) | Contraseña compartida sin certificados | Históricamente afectado por fallas *Dragonblood* en implementaciones antiguas; sin autenticación mutua por PKI |
| **EAP-TLS** | Certificado X.509 del servidor RADIUS | **Certificado X.509 único por dispositivo/usuario** | Es el estándar de oro corporativo: no transmite contraseñas ni hashes MSCHAPv2; resiste Evil Twin incluso ante descuidos del usuario |

¿Por qué **EAP-TLS** supera ampliamente a **EAP-PEAP**? En PEAP-MSCHAPv2, el túnel TLS protege el intercambio siempre y cuando el usuario o el sistema operativo valide estrictamente qué servidor está al otro lado. Si el cliente acepta cualquier certificado autofirmado o no verifica el nombre del servidor RADIUS, el atacante termina negociando un túnel TLS falso con la víctima y recibiendo el intercambio **MSCHAPv2** (que equivale criptográficamente a un desafío/respuesta NetNTLMv1 basado en el hash NT del usuario, sin sal y fácilmente auditable offline). En cambio, con **EAP-TLS** existe **autenticación mutua por certificado**: ni hay contraseña que capturar ni el cliente completará la sesión sin validar la cadena de confianza PKI.

## Ataques Evil Twin y captura controlada en laboratorio

Un ataque **Evil Twin** consiste en desplegar un punto de acceso controlado por el auditor que anuncia el mismo **SSID** (y opcionalmente simula la misma configuración RSN) que una red legítima, aprovechando que los clientes Wi-Fi suelen conectarse automáticamente al AP que ofrezca mayor intensidad de señal o mediante respuestas dirigidas a tramas *Probe Request*.

### Riesgo en WPA2-Enterprise: `hostapd-wpe` y validación de certificados RADIUS

En auditorías de redes corporativas basadas en `EAP-PEAP` o `EAP-TTLS`, la herramienta de referencia en laboratorio para evaluar si los endpoints corporativos validan correctamente el certificado del servidor RADIUS es **`hostapd-wpe`** (Wireless Pwnage Edition). A diferencia de un AP legítimo que reenvía los mensajes EAP hacia un servidor FreeRADIUS real, `hostapd-wpe` termina la negociación EAP-TLS/PEAP localmente presentando un certificado autofirmado o generado al vuelo y registra las identidades o intercambios MSCHAPv2 que los clientes mal configurados acepten enviarle.

En un laboratorio aislado (por ejemplo, usando radios virtuales `mac80211_hwsim` o un entorno de RF cerrado), una configuración básica de prueba de `hostapd-wpe.conf` define el SSID objetivo, soporte 802.1X/EAP y la ruta a los certificados de prueba:

```ini
interface=wlan0
ssid=CorpLab-WiFi
channel=6
hw_mode=g
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
```

Al iniciar `sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf` frente a un cliente de prueba configurado con *"No validar certificado del servidor"* (un error sorprendentemente común en configuraciones manuales de Windows, macOS o Linux), el usuario acepta implícitamente la identidad del AP falso y `hostapd-wpe` imprime el `username`, el `challenge` y la `response` de MSCHAPv2 en formato listo para evaluar la robustez de la contraseña con **`asleap`** o **`hashcat -m 5500`** (NetNTLMv1). Por el contrario, si el equipo cliente fue aprovisionado correctamente mediante **MDM/GPO** fijando la CA raíz interna y el nombre exacto del servidor RADIUS (`radius.corplab.local`), el cliente abortará el handshake TLS de inmediato ante la discrepancia del certificado y jamás enviará credenciales.

### Evil Twin en redes PSK y portales cautivos falsos

En redes **WPA2-Personal**, como el atacante no conoce la PSK, un Evil Twin puro no puede completar el *4-Way Handshake* ni entregar acceso real. Sin embargo, combinando un AP abierto o clonado con un servidor DHCP/DNS (`dnsmasq`) y un portal web simulado (como el patrón conceptual de herramientas tipo `wifiphisher` o `airgeddon` en laboratorio), se evalúa el factor humano (*phishing inalámbrico*): ante una desconexión repentina de su red, un usuario desprevenido puede conectarse al SSID gemelo abierto y entregar la clave Wi-Fi en un portal web falso que simule una actualización de firmware del router.

La defensa técnica frente a este escenario combina capacitación de usuarios, **802.11w (PMF)** para dificultar desconexiones forzadas y monitoreo WIDS/WIPS de SSIDs duplicados con BSSIDs no autorizados.

## Mecánica y auditoría de portales cautivos

Los **portales cautivos** (*Captive Portals*) son habituales en hoteles, aeropuertos, campus universitarios y redes de invitados corporativas. A diferencia de WPA2/WPA3, el portal cautivo no cifra ni autentica el enlace Wi-Fi en capa 2 por usuario (salvo que use OWE / Enhanced Open); su control opera en capa 3/4 en el *gateway* de red (usando reglas de firewall como `iptables`/`nftables` o listas ACL en el controlador inalámbrico).

El flujo estándar funciona así:
1. El cliente se asocia a un SSID abierto (o con PSK pública compartida) y recibe una dirección IP vía **DHCP**.
2. El firewall del gateway bloquea todo tráfico saliente hacia Internet excepto **DNS (UDP/TCP 53)**, DHCP y tráfico HTTP/HTTPS hacia la IP del propio portal cautivo.
3. Cuando el dispositivo intenta consultar su URL de detección de portal cautivo (por ejemplo, `captive.apple.com` o `connectivitycheck.gstatic.com`), el gateway intercepta HTTP o devuelve una redirección hacia la página de inicio de sesión.
4. Tras autenticarse con éxito, el controlador agrega la **dirección MAC** y la **IP** del cliente a una tabla de permitidos (*whitelist*) durante un tiempo de sesión determinado.

### Errores de implementación comunes y cómo evitar la evasión

Durante auditorías de seguridad sobre portales cautivos propios o de clientes, suelen detectarse tres debilidades clásicas de aislamiento:

- **Falta de *Client Isolation* y autorización solo por MAC**: si el AP no aísla los clientes entre sí en capa 2 y el portal únicamente autoriza direcciones MAC en su firewall, un auditor en laboratorio puede observar tráfico de otro cliente ya autenticado en el mismo segmento y verificar si el controlador permite reutilizar esa MAC (*MAC spoofing*) tras desconectarse el equipo original.
- **Permisividad excesiva en DNS (UDP/TCP 53) o ICMP**: muchos portales permiten consultas DNS arbitrarias hacia servidores externos en lugar de forzar el uso del resolvedor DNS interno. Cuando el puerto UDP 53 o los paquetes ICMP Echo llegan sin restricción hasta Internet antes de autenticarse, se abre la puerta a **túneles DNS** (`iodine`, `dnscat2`) o túneles ICMP que exfiltran tráfico saltándose la pasarela de pago o autenticación.
- **Reglas de puertos mal filtradas**: en ocasiones el administrador bloquea únicamente los puertos `80` y `443` hacia el exterior olvidando restringir otros puertos TCP/UDP (como `22`, `53` TCP, `1194` o puertos altos), o deja accesibles subredes corporativas internas RFC 1918 por falta de reglas de firewall inter-VLAN.

Un portal cautivo bien diseñado aísla la red de invitados en una **VLAN dedicada sin enrutamiento hacia la red interna**, activa **Client Isolation** (bloqueando comunicación directa STA-a-STA), intercepta obligatoriamente todo el DNS hacia su propio servidor interno (bloqueando UDP/TCP 53 externo y DoH/DoT hasta completar la autenticación) y vincula la sesión a un túnel o token controlado por un NAC robusto.

## WPA3-Personal (SAE) y vulnerabilidades Dragonblood

Para corregir la debilidad estructural de WPA2-PSK —donde capturar un único *4-Way Handshake* o *PMKID* permite probar millones de contraseñas offline sin límite de velocidad—, la Wi-Fi Alliance introdujo **WPA3** en 2018.

### Simultaneous Authentication of Equals (SAE)

**WPA3-Personal** reemplaza el intercambio PSK tradicional por **SAE** (*Simultaneous Authentication of Equals*), basado en el protocolo **Dragonfly** (un intercambio de claves autenticado por contraseña o **PAKE** sobre curvas elípticas o grupos finitos).

Sus propiedades de seguridad transforman el panorama defensivo:
- **Resistencia al diccionario offline**: en SAE, cada intento de autenticación requiere una interacción en vivo con el punto de acceso utilizando elementos derivados de la contraseña y valores efímeros únicos por sesión. Capturar pasivamente la negociación SAE por el aire no sirve para lanzar Hashcat offline sobre la contraseña.
- **Forward Secrecy (Secreto hacia adelante)**: incluso si un atacante llegara a obtener la frase de paso semanas después, no podrá descifrar el tráfico WPA3 capturado previamente en el aire porque las claves de sesión derivadas son efímeras.
- **PMF obligatorio (`802.11w`)**: WPA3 exige *Protected Management Frames* en todos los dispositivos certificados, mitigando ataques triviales de desautenticación.

### Nociones sobre Dragonblood (downgrade y side-channel)

En 2019, Mathy Vanhoef y Eyal Ronen publicaron una serie de vulnerabilidades de diseño e implementación en el estándar inicial de WPA3 bajo el nombre **Dragonblood**:

1. **Ataques de degradación (*Downgrade Attacks*) en modo transición**: muchas redes despliegan el modo mixto **WPA3/WPA2 Transition Mode** para no dejar fuera a dispositivos antiguos. Un atacante puede montar un AP falso anunciando únicamente soporte **WPA2-PSK** para el mismo SSID; cuando un cliente compatible intenta conectarse, degrada a WPA2 permitiendo capturar un *4-Way Handshake* tradicional crackeable offline. (En WPA3 puro sin transición y con la extensión *Transition Disable*, los clientes memorizan que la red exige SAE y rechazan degradaciones).
2. **Canales laterales de tiempo y caché (*Timing / Cache Side-Channels*)**: el algoritmo *hunting-and-pecking* original de Dragonfly para mapear la contraseña a un punto de la curva elíptica ejecutaba un número de iteraciones dependiente de la contraseña, filtrando bits mediante variaciones sutiles de tiempo o accesos a caché en ciertas implementaciones, permitiendo reconstruir información de contraseñas débiles.
3. **Agotamiento de recursos (DoS)**: enviar ráfagas masivas de tramas SAE `Commit` con MACs aleatorias podía saturar la CPU del AP calculando operaciones de curva elíptica antes de que existieran mecanismos de *anti-clogging tokens*.

Para corregir estas fallas, la Wi-Fi Alliance actualizó la especificación de WPA3 introduciendo el método constante en tiempo **Hash-to-Element (H2E)** en reemplazo de *hunting-and-pecking* (obligatorio en la banda de 6 GHz / Wi-Fi 6E).

## Defensa inalámbrica corporativa: WIDS/WIPS y endurecimiento

Proteger una infraestructura Wi-Fi empresarial exige visibilidad continua del espectro electromagnético y políticas estrictas tanto en los puntos de acceso como en los dispositivos finales:

- **WIDS y WIPS (*Wireless Intrusion Detection / Prevention Systems*)**: sensores dedicados (o radios secundarias de monitoreo en APs empresariales) escanean continuamente los canales 2.4, 5 y 6 GHz para detectar **Rogue APs** (puntos de acceso no autorizados conectados por empleados a la red cableada corporativa), **Evil Twins** (APs externos emitiendo el SSID corporativo desde un BSSID desconocido), inundaciones de tramas `Deauthentication`/`Disassociation` y anomalías de asociaciones SAE. Cuando opera en modo prevención (**WIPS**), el sistema correlaciona puertos de switch (mediante LLDP/CDP/MAC tables) para bloquear administrativamente el puerto físico de un Rogue AP conectado a la LAN y alerta al SOC en tiempo real.
- **Migración a WPA3-Enterprise con EAP-TLS**: eliminá el uso de PSK y PEAP-MSCHAPv2 en redes corporativas sensibles. Distribuí certificados de cliente X.509 únicos y certificados de CA raíz de confianza mediante un sistema **MDM** (*Mobile Device Management*) o **GPO**, deshabilitando explícitamente la opción de que el usuario ignore advertencias de certificado del servidor RADIUS.
- **Segmentación de red y NAC**: asigná VLANs dinámicas desde RADIUS según el perfil del equipo (corporativo, BYOD, IoT, invitados) aplicando listas de control de acceso estrictas entre segmentos.
- **802.11w (PMF) obligatorio**: habilitá PMF en modo *Required* en todos los SSIDs compatibles y deshabilitá el modo transición WPA2/WPA3 en segmentos críticos tan pronto el inventario de endpoints lo permita.

## Práctica guiada en laboratorio

En un entorno virtualizado aislado (por ejemplo, utilizando el módulo del kernel Linux `mac80211_hwsim` con dos o tres radios virtuales `wlan0`, `wlan1`, `wlan2` para evitar emitir radiofrecuencia real):

1. Configurá en `wlan0` un punto de acceso corporativo simulado con `hostapd-wpe` anunciando el SSID `LabCorp-8021X` bajo esquema `WPA2-EAP` (`CCMP`).
2. Creá un perfil de cliente de prueba en `wlan1` con `wpa_supplicant`: primero sin especificar `ca_cert` ni `altsubject_match` (configuración vulnerable) y observá cómo `hostapd-wpe` captura el desafío/respuesta MSCHAPv2 al conectar el cliente ficticio.
3. Luego, endurecé la configuración del cliente añadiendo la CA de confianza y la validación estricta del nombre del certificado del servidor RADIUS legítimo; intentá nuevamente la conexión contra `hostapd-wpe` y verificá en los logs que el cliente rechaza el certificado no confiable sin entregar credenciales.
4. Adicionalmente, verificá en `hostapd` la configuración de `ieee80211w=2` (PMF obligatorio) y `wpa_key_mgmt=SAE` para observar las capacidades RSN anunciadas en las tramas Beacon mediante `tshark` o `airodump-ng`.

::: practica Entregable mínimo
Un documento técnico de laboratorio que incluya: (a) archivo de configuración del cliente `wpa_supplicant` vulnerable vs endurecido demostrando la validación de CA y nombre del servidor RADIUS; (b) log de rechazo TLS del cliente endurecido frente al AP simulado de `hostapd-wpe` comprobando la mitigación del ataque Evil Twin; y (c) inspección con `tshark` de una trama *Beacon* verificando los indicadores RSN correspondientes a **SAE (WPA3)** y **PMF Required (`802.11w`)**.
:::

::: defensa Perspectiva defensiva y mitigación
La defensa inalámbrica moderna en organizaciones se sostiene sobre cuatro pilares concretos:
- **EAP-TLS y aprovisionamiento centralizado (MDM/GPO)**: sustituí métodos basados en contraseña (`EAP-PEAP/MSCHAPv2`, `PSK`) por **EAP-TLS** con certificados mutuos. En los equipos que aún requieran PEAP/TTLS durante una transición, forzará por política MDM la validación estricta de la CA raíz corporativa y del *Subject Alternative Name (SAN)* del servidor RADIUS, bloqueando al usuario la opción de aceptar certificados desconocidos.
- **WPA3 con H2E y PMF obligatorio**: en redes personales o de dispositivos sin soporte 802.1X, implementá **WPA3-SAE** con soporte *Hash-to-Element* (actualizando firmware de APs y clientes frente a Dragonblood) y habilitá `802.11w` (PMF) en modo obligatorio.
- **Endurecimiento de portales cautivos**: aislá la red de invitados en una VLAN sin acceso a subredes internas, activá *Client Isolation*, bloqueá tráfico UDP/TCP 53 hacia DNS externos antes de la autenticación (previniendo túneles DNS) y evitá depender únicamente de la dirección MAC como prueba persistente de identidad.
- **Monitoreo continuo WIDS/WIPS**: integrá alertas de puntos de acceso falsos, SSIDs duplicados y ráfagas de desautenticación dentro del SIEM/SOC, vinculando la detección con puertos de switches administrados para aislar Rogue APs conectados internamente.
:::

## Preguntas de repaso

**1. ¿Qué función cumple el Authenticator (AP/WLC) dentro de una arquitectura IEEE 802.1X frente al Supplicant y al Servidor RADIUS?** El Authenticator actúa como intermediario en la frontera de red: mantiene bloqueado el tráfico de datos del Supplicant hasta recibir autorización, traduce las tramas EAPOL recibidas por Wi-Fi (capa 2) hacia mensajes RADIUS sobre IP hacia el Authentication Server, y finalmente aplica la decisión (`Access-Accept`/`Access-Reject`) instalando las claves de cifrado de sesión y asignando la VLAN correspondiente.

**2. ¿Por qué EAP-TLS ofrece una protección muy superior frente a ataques Evil Twin en comparación con EAP-PEAP con MSCHAPv2?** Porque EAP-TLS exige autenticación mutua mediante certificados X.509 tanto del servidor RADIUS como del cliente, eliminando el uso de contraseñas o intercambios MSCHAPv2 por el túnel. En cambio, en EAP-PEAP, si el dispositivo cliente no valida estrictamente la CA y el nombre del certificado del servidor RADIUS, puede entregar un desafío/respuesta MSCHAPv2 al túnel TLS de un AP falso.

**3. ¿Qué controles mínimos impiden la evasión de un portal cautivo mediante *MAC spoofing* o túneles DNS?** Para frenar el *MAC spoofing* entre usuarios es indispensable habilitar *Client Isolation* en el AP (impidiendo que un cliente observe la MAC autenticada de otros pares en capa 2) y no depender de VLANs compartidas; para evitar túneles DNS, el firewall del gateway debe bloquear cualquier consulta UDP/TCP al puerto 53 (así como DoT/DoH conocidos) hacia servidores externos hasta que el usuario complete la autenticación, redirigiendo únicamente hacia el resolvedor DNS interno del portal.

**4. ¿Cómo resuelve WPA3-Personal (SAE) el principal punto débil criptográfico de WPA2-Personal (PSK)?** SAE reemplaza la derivación estática verificable offline del *4-Way Handshake* tradicional por un protocolo PAKE (*Dragonfly*) interactivo sobre curvas elípticas con claves efímeras por sesión. Esto impide verificar candidatos de contraseña offline a partir de una captura pasiva y añade *Forward Secrecy* sobre el tráfico previo.

**5. ¿En qué consiste un ataque de degradación (*downgrade*) en redes WPA3 y cómo se mitiga?** Consiste en operar un AP falso anunciando únicamente WPA2-PSK con el mismo SSID de una red configurada en modo mixto *WPA3/WPA2 Transition*, induciendo a los clientes compatibles a conectarse por WPA2 para capturar un *4-Way Handshake* auditable offline. Se mitiga desplegando **WPA3 puro** sin modo transición y habilitando la indicación *Transition Disable* para que los clientes rechacen degradaciones a WPA2 en ese SSID.

## Antes de avanzar

Con este capítulo cerraste el bloque de seguridad móvil y redes inalámbricas del Tomo VII, abarcando desde la anatomía de un APK y su análisis estático/dinámico/forense hasta la evaluación defensiva y ofensiva controlada de redes Wi-Fi WEP, WPS, WPA2-PSK, WPA2/WPA3-Enterprise y WPA3-SAE:

::: nota Puerta de salida
- Distinguís los roles 802.1X (`Supplicant`, `Authenticator`, `RADIUS`) y comprendés por qué **EAP-TLS** y la validación estricta de certificados RADIUS neutralizan el robo de identidades por Evil Twin.
- Sabés cómo opera un portal cautivo en capa 2/3 y qué reglas evitan su evasión por túneles DNS o suplantación MAC.
- Comprendés las garantías de **WPA3-SAE** (H2E y PMF), los límites históricos de *Dragonblood* y el papel de **WIDS/WIPS** en la defensa inalámbrica corporativa.
:::

## Referencias y estándares abiertos

- **IEEE 802.1X — Port-Based Network Access Control**: https://standards.ieee.org/ieee/802.1X/7345/
- **Wi-Fi Alliance — WPA3 Specification (SAE & H2E)**: https://www.wi-fi.org/discover-wi-fi/security
- **RFC 5216 — The EAP-TLS Authentication Protocol**: https://datatracker.ietf.org/doc/html/rfc5216
- **Dragonblood: Security Analysis of WPA3-SAE (Vanhoef & Ronen)**: https://wpa3.mathyvanhoef.com/
- **FreeRADIUS — Documentación oficial de implementación 802.1X**: https://freeradius.org/documentation/
