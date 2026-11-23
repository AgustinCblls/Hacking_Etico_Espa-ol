::: nota Objetivo de la lección
Comprender la estructura física y de enlace del estándar **IEEE 802.11**, operar tarjetas inalámbricas en modo monitor dentro de un laboratorio propio aislado, analizar las fallas criptográficas y de diseño de **WEP** y **WPS**, capturar material de autenticación **WPA/WPA2-PSK** (*4-Way Handshake* y **PMKID**) y ejecutar auditorías offline de robustez de contraseñas con **Hashcat**.
:::

::: peligro Marco legal y aislamiento físico de laboratorio
Las ondas de radiofrecuencia atraviesan paredes y no respetan límites lógicos de red. Toda prueba de captura, inyección o desautenticación descripta en este capítulo debe ejecutarse **exclusivamente sobre un punto de acceso (AP) y clientes de tu propiedad**, dentro de un entorno controlado (idealmente con potencia de transmisión reducida al mínimo o en jaula/entorno aislado de RF). Emitir tramas de desautenticación o capturar tráfico hacia redes de terceros constituye una interferencia ilegal y una violación grave de seguridad.
:::

A diferencia de una red cableada Ethernet donde el acceso físico requiere conectar un puerto en un switch, las redes inalámbricas **Wi-Fi (IEEE 802.11)** transmiten en un medio compartido y abierto. Cualquier estación dentro del rango de cobertura que opere en el mismo canal puede escuchar las tramas que viajan por el aire e incluso inyectar tramas forjadas si los mecanismos de autenticación y protección de gestión no están adecuadamente implementados.

## Fundamentos de IEEE 802.11 y modo monitor

Una auditoría inalámbrica seria empieza entendiendo el espectro, el lenguaje de las tramas y el comportamiento de la interfaz de red.

### Bandas de frecuencia y canales

El estándar 802.11 opera principalmente en tres bandas sin licencia:
- **2.4 GHz (802.11b/g/n/ax)**: ofrece mayor alcance y penetración en obstáculos, pero sufre alta congestión. En la mayoría de las regiones dispone de canales de 20 MHz superpuestos, siendo **1, 6 y 11** los únicos tres canales que no se solapan entre sí.
- **5 GHz (802.11a/n/ac/ax)**: aporta muchos más canales no superpuestos (con anchos de 20, 40, 80 y 160 MHz) y mayor rendimiento, aunque menor penetración física. Incluye canales **DFS** (*Dynamic Frequency Selection*) sujetos a detección de radares.
- **6 GHz (Wi-Fi 6E / Wi-Fi 7 - 802.11ax/be)**: amplía drásticamente el espectro disponible, elimina protocolos heredados inseguros y exige obligatoriamente **WPA3** y **PMF (802.11w)**.

### Tipos de tramas 802.11: Management, Control y Data

En la capa MAC de 802.11 todas las comunicaciones se clasifican en tres grandes familias:

1. **Tramas de Gestión (*Management Frames*)**: coordinan el descubrimiento y asociación entre estaciones (STA) y puntos de acceso (AP). Entre las más relevantes para auditoría están:
   - **`Beacon`**: anunciadas periódicamente por el AP (típicamente cada 102.4 ms) difundiendo su **SSID**, **BSSID** (dirección MAC de la radio), canal, tasas soportadas y capacidades de cifrado (RSN/WPA2/WPA3).
   - **`Probe Request` y `Probe Response`**: enviadas por clientes buscando redes conocidas previamente (lo que filtra información de SSIDs guardados si no se usa aleatorización MAC) y respondidas por los APs cercanos.
   - **`Authentication` y `Association`**: negocian el vínculo inicial previo al intercambio criptográfico.
   - **`Deauthentication` y `Disassociation`**: notifican la terminación abrupta de la sesión. En redes heredadas sin protección **802.11w**, estas tramas viajan **sin cifrar ni autenticar**, permitiendo que un atacante en el laboratorio falsifique la dirección MAC origen del AP para forzar a un cliente a reconectarse.
2. **Tramas de Control (*Control Frames*)**: regulan el acceso al medio compartido y evitan colisiones (`RTS`, `CTS`, `ACK`).
3. **Tramas de Datos (*Data Frames*)**: transportan la carga útil encapsulada (paquetes IP, ARP, DHCP) y los mensajes de autenticación **EAPOL** durante el establecimiento de sesión.

### Modo monitor e inyección con airmon-ng y airodump-ng

En operación normal (*Managed Mode*), la tarjeta Wi-Fi descarta cualquier trama cuya dirección MAC destino no coincida con la suya o con direcciones de broadcast. Para auditar una red propia necesitamos cambiar la tarjeta a **Modo Monitor (*Monitor Mode*)** usando un chipset compatible con captura cruda e inyección de tramas (por ejemplo, adaptadores basados en Atheros AR9271, Realtek RTL8812AU o MediaTek MT7612U con drivers Linux adecuados).

Prepará la interfaz con la suite **Aircrack-ng** verificando primero procesos conflictivos como `NetworkManager` o `wpa_supplicant` que puedan cambiar de canal automáticamente:

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
iwconfig wlan0mon
```

Para comprobar si tu adaptador de laboratorio soporta inyección de paquetes contra tu AP de pruebas, ejecutá `aireplay-ng`:

```bash
sudo aireplay-ng --test wlan0mon
```

A continuación, iniciá el reconocimiento pasivo en todas las bandas o fijando un canal y BSSID específicos pertenecientes a tu AP de laboratorio:

```bash
sudo airodump-ng wlan0mon --band abg
sudo airodump-ng -c 6 --bssid AA:BB:CC:11:22:33 -w captura_lab wlan0mon
```

En la salida de `airodump-ng`, prestá atención a las columnas `PWR` (intensidad de señal en dBm), `Beacons`, `#Data` (tramas de datos cifradas), `CH` (canal), `ENC` (WEP, WPA, WPA2, WPA3), `CIPHER` (CCMP/AES o TKIP) y `AUTH` (PSK, SAE, MGT), además de la tabla inferior que lista las estaciones (`STATION`) asociadas y los SSIDs que están buscando mediante `Probes`.

## Debilidades criptográficas históricas de WEP

Aunque **WEP** (*Wired Equivalent Privacy*) está oficialmente obsoleto desde 2004, sigue presente ocasionalmente en dispositivos industriales antiguos o impresoras heredadas y constituye la base didáctica para entender por qué la auditoría busca **eliminar cifrados débiles por diseño antes que intentar repararlos**: la reutilización de vectores de inicialización cortos sobre **RC4** degrada por completo la confidencialidad sin importar cuánto se rote la clave manualmente.

WEP utiliza el cifrado de flujo **RC4** combinado con un mecanismo de verificación de integridad llamado **ICV** (*Integrity Check Value*) basado en **CRC-32** (que es lineal y no criptográfico). Para no reutilizar la misma secuencia pseudoaleatoria (*keystream*) de RC4 en cada paquete, WEP concatena un **Vector de Inicialización (IV) de 24 bits** en texto claro con la clave secreta compartida (de 40 o 104 bits).

El problema matemático es fatal por tres motivos simultáneos:
1. **Espacio diminuto del IV**: con apenas 24 bits, solo existen 16.777.216 valores posibles de IV. Por la paradoja del cumpleaños, tras apenas unos miles de paquetes en una red activa comienzan a repetirse IVs con altísima probabilidad, permitiendo recuperar el *keystream* haciendo XOR entre dos tramas con el mismo IV.
2. **Correlación estadística en RC4 (ataques FMS y PTW)**: Fluhrer, Mantin y Shamir (FMS) demostraron que ciertos IVs débiles filtran información directa sobre los bytes de la clave raíz en las primeras salidas de RC4. En 2007, Pyshkin, Tews y Weinmann (**ataque PTW**) optimizaron este análisis estadístico sobre paquetes ARP capturados, permitiendo recuperar una clave WEP de 104 bits en pocos minutos tras recolectar entre 40.000 y 85.000 tramas con IV únicos.
3. **Inyección de paquetes ARP para acelerar la captura**: en un laboratorio con poco tráfico, el auditor envía solicitudes ARP capturadas previamente (`aireplay-ng -3 -b <BSSID> -h <MAC_CLIENTE> wlan0mon`) para que el AP las retransmita generando miles de nuevos IVs por segundo, permitiendo luego que `aircrack-ng captura_lab-01.cap` recupere la clave WEP al instante.

## Fallas de diseño en Wi-Fi Protected Setup (WPS)

Para facilitar la conexión de usuarios domésticos sin tipear contraseñas largas, se introdujo **WPS** (*Wi-Fi Protected Setup*), que permite autenticarse mediante un botón físico (PBC) o un **PIN numérico de 8 dígitos**. Ese PIN de 8 dígitos fue el origen de una vulnerabilidad arquitectónica devastadora descubierta por Stefan Viehböck en 2011.

### Estructura dividida del PIN (4 + 3 + checksum)

El protocolo externo de autenticación WPS no valida los 8 dígitos de una sola vez:
- El octavo dígito es simplemente un **dígito de verificación (*checksum*)** calculado matemáticamente a partir de los siete dígitos anteriores. Esto reduce el espacio real de búsqueda de 100.000.000 de combinaciones a 10.000.000.
- Peor aún: el intercambio de mensajes EAP-WSC verifica **primero la primera mitad del PIN (4 dígitos)** en el mensaje `M4/M5` y **luego la segunda mitad (3 dígitos)** en el mensaje `M6/M7`. Si la primera mitad es incorrecta, el AP devuelve un mensaje `NACK` de inmediato sin evaluar la segunda mitad.

En consecuencia, la complejidad total de fuerza bruta online cae a apenas **10.000 + 1.000 = 11.000 intentos** en el peor caso (y 5.500 en promedio). Herramientas como `reaver` o `bully` podían agotar ese espacio en pocas horas contra routers sin bloqueo.

### Ataque Pixie Dust offline y bloqueo por rate-limiting

En 2014, Dominique Bongard descubrió el ataque **Pixie Dust** (`pixiewps`), explotando que numerosos chips Wi-Fi implementaban generadores de números pseudoaleatorios (PRNG) débiles o predecibles (incluso usando marcas de tiempo UNIX o semillas constantes) al calcular los *nonces* secretos `E-S1` y `E-S2` durante un único intercambio WPS. Como resultado, capturando un solo intento de handshake WPS (`M1` a `M3`), el auditor puede calcular el PIN correcto **completamente offline en cuestión de segundos** sin disparar bloqueos de intentos fallidos:

```bash
sudo reaver -i wlan0mon -b AA:BB:CC:11:22:33 -c 6 -K 1 -vv
```

La bandera `-K 1` ejecuta Pixie Dust automáticamente. Como mitigación parcial, los fabricantes modernos implementaron *rate-limiting* y bloqueo temporal o permanente de WPS tras 3 a 10 intentos fallidos (`AP Rate Limiting` visible con `wash -i wlan0mon`). Sin embargo, la única remediación definitiva sigue siendo **desactivar WPS por completo** en el punto de acceso.

## Ataques a WPA y WPA2-Personal (PSK)

**WPA2-Personal** (definido en IEEE 802.11i) reemplazó a WEP y TKIP incorporando el algoritmo **AES-CCMP**, que garantiza confidencialidad e integridad criptográfica robusta siempre que la clave compartida (*Pre-Shared Key* o PSK) posea suficiente entropía. En modo Personal, no hay servidor de autenticación central: el AP y el cliente derivan una clave maestra por pareja (**PMK**, *Pairwise Master Key*) aplicando **PBKDF2-HMAC-SHA1** durante 4096 iteraciones sobre la frase de paso del usuario y el nombre del SSID como sal.

### Anatomía del 4-Way Handshake (EAPOL)

Para demostrar que ambos conocen la PMK sin enviarla jamás por el aire, y generar claves temporales únicas de sesión (**PTK**, *Pairwise Transient Key*) junto con la clave grupal (**GTK**), el AP y la estación ejecutan el **4-Way Handshake** mediante tramas **EAPOL-Key**:

1. **Mensaje 1 (AP -> STA)**: el AP envía un número aleatorio llamado **`ANonce`** junto con su MAC. Con `PMK`, `ANonce`, su propio `SNonce` y ambas MACs, el cliente ya puede calcular localmente la **PTK**.
2. **Mensaje 2 (STA -> AP)**: el cliente envía su **`SNonce`** protegido con un código de integridad **MIC** (*Message Integrity Code*) calculado con la KCK (*Key Confirmation Key*, primera porción de la PTK). El AP deriva la misma PTK y verifica el MIC.
3. **Mensaje 3 (AP -> STA)**: el AP confirma la autenticidad, entrega la clave grupal **GTK** cifrada y firma el mensaje con su propio MIC.
4. **Mensaje 4 (STA -> AP)**: el cliente confirma la instalación de las claves para iniciar el tráfico cifrado CCMP.

Si en tu laboratorio capturás al menos los mensajes **M1 y M2** (o M2 y M3), disponés de toda la información pública (`SSID`, `MAC_AP`, `MAC_STA`, `ANonce`, `SNonce`) y del `MIC` necesario para verificar candidatos de contraseña offline. En pruebas sobre clientes propios, si ningún dispositivo se asocia naturalmente durante la captura de `airodump-ng`, podés enviar una ráfaga acotada de tramas de desautenticación al cliente de prueba para provocar una reconexión inmediata:

```bash
sudo aireplay-ng -0 3 -a AA:BB:CC:11:22:33 -c DD:EE:FF:44:55:66 wlan0mon
```

### Captura sin clientes vía PMKID

En 2018, Jens Steube (autor de Hashcat) reveló un método que elimina por completo la necesidad de esperar clientes conectados o enviar tramas de desautenticación contra un AP de laboratorio que soporte *roaming* IEEE 802.11i/RSN. En el **primer mensaje (M1)** del 4-Way Handshake, muchos puntos de acceso incluyen opcionalmente dentro del campo *RSN Information Element* el **PMKID** (*Pairwise Master Key Identifier*), calculado directamente como:

`PMKID = HMAC-SHA1-128(PMK, "PMK Name" || MAC_AP || MAC_STA)`

Como `PMKID` depende directamente de la `PMK` (derivada del SSID y la passphrase) y de las dos direcciones MAC ya conocidas, basta con iniciar un intento de asociación hacia el AP objetivo con `hcxdumptool` para recibir el mensaje M1 con el PMKID y someterlo a auditoría offline:

```bash
sudo hcxdumptool -i wlan0mon -o captura_pmkid.pcapng --active_beacon --enable_status=15
```

::: aviso Comportamiento de hcxdumptool y alcance controlado
En versiones modernas de `hcxdumptool`, si no filtrás objetivos mediante un archivo de lista blanca (`--filterlist_ap` con `--filtermode=2`), la herramienta intentará interactuar con todos los APs al alcance. En cualquier laboratorio o auditoría profesional, **restringí siempre la captura al BSSID exacto de tu AP de pruebas** usando filtros explícitos para no emitir tramas hacia redes vecinas.
:::

## Auditoría offline de contraseñas con Hashcat

Una vez capturado un *4-Way Handshake* o un *PMKID* en formato `.cap` o `.pcapng`, la validación de fortaleza de la clave se realiza completamente **offline**, sin emitir un solo paquete adicional hacia la red inalámbrica.

El flujo estándar moderno unifica ambos artefactos (EAPOL y PMKID) mediante `hcxpcapngtool` hacia el formato **`22000`** de Hashcat (que reemplazó al antiguo formato `.hccapx` / modo 2500):

```bash
hcxpcapngtool -o hashes_wifi.hc22000 captura_lab-01.cap
```

Cada línea generada en `hashes_wifi.hc22000` comienza con `WPA*01*` (PMKID) o `WPA*02*` (EAPOL 4-Way Handshake) e incluye en hexadecimal el SSID, las MACs y los nonces necesarios. A continuación, ejecutá la auditoría por diccionario o reglas sobre GPU con `hashcat`:

```bash
hashcat -m 22000 hashes_wifi.hc22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

Si necesitás evaluar contraseñas numéricas o patrones corporativos previsibles (por ejemplo, combinaciones de 8 dígitos), podés usar ataque por máscara:

```bash
hashcat -m 22000 -a 3 hashes_wifi.hc22000 "?d?d?d?d?d?d?d?d"
```

Para auditorías rápidas en CPU con diccionarios pequeños también podés emplear `aircrack-ng -w diccionario.txt -b AA:BB:CC:11:22:33 captura_lab-01.cap`, aunque **Hashcat** aprovecha paralelismo masivo en GPU (alcanzando cientos de miles o millones de hashes PBKDF2 por segundo frente a unos pocos miles en CPU). Recordá que la seguridad de WPA2-PSK reside enteramente en la entropía de la frase de paso: una clave corta o basada en palabras de diccionario cede ante auditoría offline sin importar que utilice AES-CCMP.

## Endurecimiento de redes WPA2-Personal

La defensa efectiva frente a las técnicas analizadas combina higiene criptográfica, reducción de superficie heredada y protección de tramas de gestión:
- **Eliminar protocolos obsoletos**: deshabilitá WEP, WPA1 y el cifrado TKIP por completo; exigí **WPA2-PSK con AES-CCMP** únicamente (o migrá a **WPA3-SAE** si los clientes lo soportan).
- **Desactivar WPS**: apagá WPS (tanto PIN como PBC) en la configuración de todos los APs, eliminando de raíz el riesgo de fuerza bruta 4+3 y Pixie Dust.
- **Frases de paso de alta entropía**: usá contraseñas aleatorias de al menos **16 a 20 caracteres** (o frases largas con múltiples palabras no predecibles) para volver computacionalmente inviable el crackeo offline de PMK/PMKID.
- **Activar 802.11w (PMF - *Protected Management Frames*)**: cifra y autentica tramas de gestión críticas como `Deauthentication` y `Disassociation` tras establecer la sesión, neutralizando ataques de desautenticación falsificada para forzar handshakes.

## Práctica guiada en laboratorio

Configurá un AP de pruebas propio (un router de laboratorio o un entorno virtualizado con `mac80211_hwsim` en Linux que simula radios Wi-Fi virtuales sin emitir RF real) y ejecutá la auditoría completa:

1. Activá el modo monitor sobre tu interfaz de laboratorio (`airmon-ng` o `iw`) e identificá el canal, BSSID, esquema de cifrado y clientes conectados usando `airodump-ng`.
2. Configurá temporalmente el AP de pruebas con **WPA2-PSK (AES-CCMP)** y una frase de paso débil conocida incluida en un diccionario de prueba; verificá con `wash` si WPS está expuesto.
3. Capturá un **4-Way Handshake** durante la reconexión de tu propio cliente de pruebas y, en una segunda prueba sin clientes conectados, intentá extraer el **PMKID** filtrando exclusivamente por el BSSID de tu AP con `hcxdumptool`.
4. Convertí la captura con `hcxpcapngtool` al formato `22000` y verificá la recuperación de la clave con `hashcat -m 22000`.
5. Finalmente, endurecé el AP aplicando una clave aleatoria de 20 caracteres, desactivando WPS y habilitando **802.11w (PMF)**, y confirmá que la inyección de tramas de desautenticación ya no desconecta al cliente.

::: practica Entregable mínimo
Un informe de laboratorio documentando: (a) comandos y captura de `airodump-ng` identificando el AP propio y un cliente de prueba; (b) archivo `.hc22000` generado con `hcxpcapngtool` (indicando si corresponde a `WPA*01*` PMKID o `WPA*02*` EAPOL) y evidencia de verificación exitosa con `hashcat -m 22000`; y (c) verificación posterior al endurecimiento demostrando WPS desactivado y resistencia frente a desautenticación tras habilitar `802.11w`.
:::

::: defensa Perspectiva defensiva y mitigación
La seguridad en redes inalámbricas personales o de pequeñas oficinas requiere controles preventivos claros:
- **Migración y cifrado estricto**: desterrá WEP y WPA/TKIP; configurá exclusivamente **WPA2-AES (CCMP)** o idealmente **WPA3-Personal (SAE)** para eliminar el ataque de diccionario offline sobre handshakes.
- **Desactivación de WPS y servicios auxiliares**: deshabilitá WPS en la interfaz de administración y verificá mediante auditorías periódicas con `wash` que ninguna actualización de firmware lo haya reactivado por defecto.
- **Protección de tramas de gestión (`802.11w` / PMF)**: configurá PMF en modo *Required* (o al menos *Capable* si existen dispositivos heredados) para impedir ataques de desautenticación y denegación de servicio en capa 2.
- **Rotación y separación de segmentos**: nunca reutilices una PSK compartida para invitados o dispositivos IoT en la misma VLAN que estaciones corporativas; aislá SSIDs de invitados con *Client Isolation* y considerá migrar redes de empleados a **WPA2/WPA3-Enterprise (802.1X)**.
:::

## Preguntas de repaso

**1. ¿Por qué las tramas `Deauthentication` en una red WPA2 estándar sin `802.11w` pueden ser falsificadas por un atacante cercano?** Porque en el estándar 802.11 original las tramas de gestión (*Management Frames*) como `Deauthentication` y `Disassociation` se envían sin cifrado ni código de integridad autenticada. Cualquier estación dentro del rango que conozca las direcciones MAC del AP y del cliente puede inyectar una trama falsificando la MAC de origen sin necesidad de conocer la clave de la red.

**2. ¿Qué dos fallas combinadas hacen al protocolo WEP vulnerable a recuperación rápida de clave mediante ataques como PTW?** En primer lugar, utiliza un Vector de Inicialización (IV) de solo 24 bits que se repite rápidamente en redes activas provocando reutilización de *keystreams* RC4; en segundo lugar, la programación de claves de RC4 presenta sesgos estadísticos frente a IVs débiles que permiten reconstruir byte a byte la clave secreta tras capturar decenas de miles de paquetes ARP.

**3. ¿Por qué un PIN de WPS de 8 dígitos solo requiere como máximo 11.000 intentos en lugar de 100 millones?** Porque el octavo dígito es un *checksum* calculado a partir de los siete anteriores (reduciendo el espacio a 10 millones) y porque el protocolo valida de forma independiente primero los 4 primeros dígitos y luego los 3 siguientes (10.000 + 1.000 = 11.000 combinaciones).

**4. ¿Qué ventaja operativa presenta la captura de PMKID frente a la captura tradicional del 4-Way Handshake en WPA2-PSK?** La extracción de PMKID solo requiere enviar una solicitud de asociación al AP para recibir el primer mensaje (M1) del handshake que incluye el identificador derivado de la PMK; por lo tanto, no necesita esperar a que existan clientes legítimos asociados ni inyectar tramas de desautenticación para forzar su reconexión.

**5. ¿Cuál es la función de `hcxpcapngtool` en el flujo de auditoría con `hashcat -m 22000`?** Extrae, limpia y convierte tanto intercambios EAPOL del *4-Way Handshake* (`WPA*02*`) como identificadores *PMKID* (`WPA*01*`) desde archivos de captura `.cap` o `.pcapng` hacia el formato textual unificado `.hc22000` requerido por Hashcat para realizar pruebas offline aceleradas por GPU.

## Antes de avanzar

Ya comprendés la mecánica de capa 2 de 802.11, por qué colapsaron WEP y WPS, y cómo se audita la fortaleza de una clave precompartida en WPA2-Personal. En el próximo capítulo vas a dar el salto hacia entornos corporativos con servidores RADIUS, portales cautivos, ataques Evil Twin y la criptografía moderna de WPA3:

::: nota Puerta de salida
- Podés poner una interfaz compatible en modo monitor, identificar canales/clientes con `airodump-ng` y distinguir tramas Management, Control y Data.
- Entendés la anatomía del *4-Way Handshake* EAPOL y la extracción de PMKID para su evaluación offline con `hcxpcapngtool` y `hashcat -m 22000`.
- Sabés por qué deben desactivarse WEP, TKIP y WPS y cómo protege `802.11w` (PMF) las tramas de gestión.
:::

## Referencias y estándares abiertos

- **IEEE 802.11-2020 Standard (Wireless LAN MAC and PHY Specifications)**: https://standards.ieee.org/ieee/802.11/7028/
- **Wi-Fi Alliance — Security & WPA2 / PMF (802.11w)**: https://www.wi-fi.org/discover-wi-fi/security
- **Aircrack-ng Documentation**: https://www.aircrack-ng.org/doku.php
- **Hashcat — Mode 22000 (WPA-PBKDF2-PMKID+EAPOL)**: https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
- **hcxtools & hcxdumptool (ZerBea)**: https://github.com/ZerBea/hcxdumptool
