::: nota Objetivo de la lección
Al finalizar este capítulo vas a dominar los fundamentos de Network Security Monitoring (NSM), la inspección de capturas PCAP con Wireshark y `tshark`, la lectura de metadatos estructurados de Zeek (`conn.log`, `dns.log`, `http.log`, `ssl.log`) y el diseño y afinado de reglas IDS/IPS en Suricata dentro de un laboratorio aislado.
:::

**Prerrequisitos:** Manejo de TCP/IP, DNS, HTTP y TLS, además de nociones de SIEM y alertas (Capítulos 4.1 a 4.3). **Duración sugerida:** 3 horas de estudio y práctica con capturas PCAP locales.

## 1. Fundamentos de NSM y diseño seguro de red

El **Monitoreo de Seguridad de Red (NSM)** complementa la telemetría de endpoints porque observa todo lo que circula por el cable, incluidos dispositivos sin agente (IoT, impresoras, routers o equipos no administrados). Para que un sensor NSM funcione sin degradar la red, se ubica en puntos estratégicos de la arquitectura —borde perimetral, frontera de **DMZ** y enlaces entre VLANs segmentadas— recibiendo una copia del tráfico mediante un **Network TAP** o puerto espejo (**SPAN**).

### Captura completa (PCAP) frente a metadatos de flujo (NetFlow / Zeek)

| Enfoque de captura | Qué almacena | Ventaja principal | Limitación operativa |
| --- | --- | --- | --- |
| **Full PCAP** | Encabezados y carga útil completa de cada paquete | Máximo detalle forense: permite reconstruir archivos y sesiones exactas. | Consumo muy alto de disco; retención típica de horas o pocos días. |
| **NetFlow / IPFIX** | Resumen de sesiones (IPs, puertos, bytes, paquetes, duración) | Muy liviano; permite retener meses de historial y detectar anomalías de volumen. | No inspecciona capa de aplicación ni nombres de dominio. |
| **Zeek (NSM)** | Metadatos enriquecidos por protocolo (`conn`, `dns`, `http`, `ssl`) | Equilibrio óptimo entre contexto de protocolo, escalabilidad y búsqueda rápida. | No sustituye el PCAP cuando hace falta extraer el binario íntegro. |

En la capa de prevención, un **IDS** (*Intrusion Detection System*) opera de forma pasiva (fuera de banda) generando alertas sin alterar el tráfico, mientras que un **IPS** (*Intrusion Prevention System*) opera en línea (*inline*) con capacidad de descartar paquetes (`drop`) en tiempo real, lo cual exige un afinado riguroso para no interrumpir servicios críticos.

## 2. Investigación intermedia con Wireshark y tshark

**Wireshark** (interfaz gráfica) y **`tshark`** (versión de consola) permiten examinar capturas `.pcap` en profundidad. En análisis real conviene usar `tshark` para resumir miles de paquetes y pasar a Wireshark solo cuando necesitás reconstruir una sesión puntual (*Follow TCP/HTTP Stream*).

### Consultas clave para HTTP, DNS, TLS (SNI / JA3) y beaconing

Aunque gran parte del tráfico moderno viaja cifrado con TLS, los metadatos de negociación siguen aportando visibilidad valiosa: el campo **SNI** (*Server Name Indication*) revela el dominio solicitado en el *Client Hello*, y la huella **JA3** resume la combinación de versión TLS, cifrados y extensiones del cliente para identificar perfiles inusuales.

```bash
# 1. Listar conversaciones TCP principales por volumen
tshark -r captura_lab.pcap -q -z conv,tcp

# 2. Extraer consultas DNS y respuestas para detectar dominios anómalos
tshark -r captura_lab.pcap -Y "dns.flags.response == 0" -T fields -e frame.time_epoch -e ip.src -e dns.qry.name

# 3. Inspeccionar nombres de servidor TLS (SNI) y cabeceras HTTP
tshark -r captura_lab.pcap -Y "tls.handshake.extensions_server_name" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name
tshark -r captura_lab.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri -e http.user_agent

# 4. Exportar objetos HTTP transferidos en claro hacia una carpeta temporal
tshark -r captura_lab.pcap --export-objects http,./objetos_extraidos/
```

### Detección conceptual de beaconing periódico

El *beaconing* ocurre cuando un host comprometido consulta periódicamente a un servidor externo en intervalos regulares (por ejemplo, cada 60 segundos con pequeña variación o *jitter*). Para identificarlo, revisá la diferencia de tiempo (`delta`) entre conexiones repetidas hacia el mismo par `ip.dst:tcp.dstport`: intervalos muy uniformes con transferencias pequeñas y recurrentes merecen investigación prioritaria.

## 3. Interpretación de logs estructurados de Zeek

**Zeek** procesa tráfico en vivo o archivos `.pcap` y genera registros tabulados (o JSON) vinculados entre sí por un identificador único de conexión (`uid`), lo que permite cruzar protocolos en segundos.

| Archivo Zeek | Qué registra | Campos clave para análisis |
| --- | --- | --- |
| `conn.log` | Todas las sesiones TCP, UDP e ICMP | `uid`, `id.orig_h`, `id.resp_h`, `id.resp_p`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state` |
| `dns.log` | Consultas y respuestas DNS | `uid`, `query`, `qtype_name`, `rcode_name`, `answers` |
| `http.log` | Solicitudes y respuestas HTTP | `uid`, `method`, `host`, `uri`, `user_agent`, `status_code` |
| `ssl.log` | Negociaciones TLS/SSL y certificados | `uid`, `version`, `server_name`, `subject`, `issuer`, `validation_status` |

Procesar un PCAP en tu laboratorio con Zeek y consultar columnas con `zeek-cut` toma un único comando:

```bash
# Procesar captura local con Zeek
zeek -C -r captura_lab.pcap

# Consultar conexiones salientes con mayor cantidad de bytes enviados
cat conn.log | zeek-cut uid id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes | sort -k6 -nr | head -n 10

# Cruzar dominios consultados en DNS y SNI observados en TLS
cat dns.log | zeek-cut uid id.orig_h query rcode_name | head -n 10
cat ssl.log | zeek-cut uid id.orig_h id.resp_h server_name validation_status | head -n 10
```

## 4. Anatomía y escritura de reglas IDS/IPS en Suricata

**Suricata** es un motor IDS/IPS de alto rendimiento que inspecciona paquetes y flujos de aplicación usando firmas declarativas. Toda regla se compone de dos partes: **encabezado (header)** y **opciones** entre paréntesis.

```text
[acción] [protocolo] [ip_origen] [puerto_origen] [dirección] [ip_destino] [puerto_destino] (opciones;)
```

Elementos estructurales esenciales de las opciones:
- `msg`: descripción legible de la alerta en el log `eve.json`.
- `flow`: dirección y estado de la sesión (por ejemplo, `established,to_server`), vital para evitar falsos positivos en paquetes sueltos.
- `content`: cadena literal o hexadecimal buscada con gran eficiencia (motor de coincidencia rápida).
- `pcre`: expresión regular compatible con Perl, usada solo después de un `content` para no penalizar rendimiento.
- `sid` y `rev`: identificador numérico único de la regla (rango `>= 1000000` para reglas locales) y número de revisión.

### Ejemplos de reglas locales y afinado

```text
# Regla 1 (IDS - alert): Detectar User-Agent de prueba automatizado hacia un servicio interno HTTP
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"LAB-SEC HTTP User-Agent inusual detectado"; flow:established,to_server; http.user_agent; content:"LabScanner"; nocase; sid:1000001; rev:1;)

# Regla 2 (IDS - alert): Detectar descarga de script por HTTP con patrón de extensión mediante content + pcre
alert http any any -> $HOME_NET any (msg:"LAB-SEC Descarga de script por HTTP sin cifrar"; flow:established,to_client; http.response_body; content:"#!/bin/"; pcre:"/^#!\/bin\/(ba)?sh/m"; sid:1000002; rev:1;)
```

Para validar sintaxis y probar tus reglas sobre un PCAP sin tocar producción:

```bash
# Validar reglas locales y ejecutar Suricata en modo offline sobre un PCAP
sudo suricata -T -c /etc/suricata/suricata.yaml -S ./reglas_lab.rules
suricata -r captura_lab.pcap -S ./reglas_lab.rules -l ./salida_suricata/
```

Para **afinar falsos positivos** sin desactivar una firma entera, utilizá `threshold.config` (por ejemplo, `suppress` por IP de un servidor de monitoreo autorizado o `threshold` por frecuencia) y actualizá el número `rev` en cada cambio documentado.

### Comparativa rápida con Snort, anomalías L2/L3 y correlación perimetral

En entornos reales un analista NSM combina el análisis de paquetes con la telemetría de dispositivos de borde y herramientas complementarias:

- **Sintaxis Snort frente a Suricata:** Ambos motores comparten estructura clásica (`acción proto src_ip src_port -> dst_ip dst_port (opciones)`), pero **Snort 2/3** utiliza inspectores y modificadores clásicos como `uricontent` / `http_uri`, mientras que **Suricata** ofrece *sticky buffers* más expresivos (`http.uri; content:"...";`, `http.user_agent;`, `tls.sni;`), multihilo nativo y registro unificado `eve.json`. El archivo local [`laboratorios/suricata_lab.rules`](../laboratorios/suricata_lab.rules) incluye cuatro reglas listas para estudiar filtros `flow`, `pcre`, firmas `MZ` en transferencia y `threshold`.
- **Anomalías de Capa 2 y Capa 3 (*ARP Spoofing*, *IP Spoofing* y fragmentación):**
  - ***ARP Spoofing* y *ARP Scanning*:** Ráfagas de respuestas *ARP Reply* no solicitadas o cambios súbitos de correspondencia IP→MAC (en especial hacia la puerta de enlace) se observan en Wireshark filtrando `arp.duplicate-address-detected` o `arp.opcode == 2` sin `opcode == 1` previo, y se mitigan con *Dynamic ARP Inspection* (`DAI`) y `DHCP Snooping` en switches gestionados.
  - ***IP Spoofing* y fragmentación evasiva:** Paquetes entrantes en interfaces WAN con direcciones origen RFC 1918 o de la subred interna, o fragmentos IP solapados (*tiny fragments* para dividir cabeceras TCP entre fragmentos), se bloquean mediante filtrado de entrada/salida (*BCP 38 / uRPF*) y reensamblado estricto (`stream` / `frag3`) en el IDS/IPS antes de evaluar firmas.
- **Extracción automática de artefactos con *NetworkMiner*:** Frente a capturas PCAP extensas, herramientas forenses pasivas como `NetworkMiner` reconstruyen automáticamente sesiones por host, archivos transferidos por HTTP/SMB, credenciales en texto claro, certificados TLS y parámetros DNS/OS fingerprinting sin necesidad de extraer flujos manualmente.
- **Correlación con Firewall, VPN, Proxy y WAF:** Un hallazgo de red cobra contexto completo al cruzar los tres niveles temporales: la sesión permitida/bloqueada en el **Firewall** o túnel **VPN** (usuario autenticado y origen externo), la URI completa y el código HTTP registrados por el **Proxy** corporativo o **WAF** (payload bloqueado o permitido en capa 7), y la conversación íntegra preservada en PCAP/Zeek para verificar si hubo respuesta exitosa o exfiltración.

## Ejemplo paso a paso: Correlación PCAP → Zeek → Suricata en laboratorio

En este recorrido analizamos una captura local (`trafico_prueba.pcap`) donde un host de laboratorio realiza consultas periódicas a un servidor web interno de pruebas.

**Paso 1:** Revisar el resumen temporal con `tshark` para detectar periodicidad.

```bash
tshark -r trafico_prueba.pcap -Y "http.request" -T fields -e frame.time_relative -e ip.src -e ip.dst -e http.host -e http.user_agent
```

```text
# Salida comentada en laboratorio
0.000000   192.168.56.20  192.168.56.10  lab-srv.local  LabScanner/1.0
30.012410  192.168.56.20  192.168.56.10  lab-srv.local  LabScanner/1.0
60.004920  192.168.56.20  192.168.56.10  lab-srv.local  LabScanner/1.0
# Intervalo constante de ~30 s entre peticiones: indicador claro de beaconing periódico.
```

**Paso 2:** Procesar con Zeek y verificar la sesión en `http.log` y `conn.log` mediante el mismo `uid`.

```bash
zeek -C -r trafico_prueba.pcap
cat http.log | zeek-cut uid id.orig_h id.resp_h host uri user_agent status_code
```

```text
# Salida comentada (Zeek)
CHhAvVGS1DHFjwGM9  192.168.56.20  192.168.56.10  lab-srv.local  /check  LabScanner/1.0  200
# El uid permite pivotar directamente hacia conn.log para medir bytes transferidos y duración.
```

**Paso 3:** Probar la regla Suricata `sid:1000001` y revisar la alerta estructurada en `eve.json`.

```bash
suricata -r trafico_prueba.pcap -S ./reglas_lab.rules -l ./salida_suricata/
grep '"event_type":"alert"' ./salida_suricata/eve.json | head -n 1
```

```text
# Salida comentada (eve.json resumido)
{"timestamp":"2026-11-22T16:10:01Z","event_type":"alert","src_ip":"192.168.56.20","dest_ip":"192.168.56.10","alert":{"signature_id":1000001,"signature":"LAB-SEC HTTP User-Agent inusual detectado"}}
# La firma coincidió sin falsos positivos y quedó lista para ingerirse en Splunk o Elastic.
```

::: defensa Perspectiva defensiva, detección y mitigación
Una arquitectura NSM eficaz reduce drásticamente el tiempo de exposición frente a tácticas padre como **Comando y Control**, **Exfiltración** y **Descubrimiento**:
- **Segmentación y control de egresos:** Restringí el tráfico saliente desde servidores críticos mediante listas permitidas y proxy autenticado; la visibilidad en egress es tan importante como el perímetro de entrada.
- **Complemento endpoint + red:** Ningún sensor es suficiente solo: TLS moderno oculta el contenido en red, pero la combinación de Zeek (`ssl.log`/`dns.log`), alertas Suricata y telemetría Sysmon cierra el circuito completo.
- **Migración gradual de IDS a IPS:** Validá toda firma nueva en modo `alert` durante un período de observación antes de pasarla a `drop` para prevenir bloqueos de tráfico legítimo.
:::

## Práctica en laboratorio local

En tu red Host-Only, levantá un servidor HTTP local simple (`python3 -m http.server 8080`) en una VM y realizá desde otra VM tres peticiones periódicas separadas por 15 segundos con `curl -A "LabScanner/1.0" http://<IP_SERVIDOR>:8080/` mientras capturás el tráfico con `tcpdump -i <interfaz> -w trafico_prueba.pcap`. Luego analizá el archivo con `tshark`, Zeek y tu regla local en Suricata.

::: practica Entregable mínimo
Generá un informe breve `nsm_laboratorio.md` que incluya:
1. Salida de `tshark` mostrando la periodicidad temporal de las peticiones HTTP.
2. Fragmento de `conn.log` y `http.log` generados por Zeek correlacionados mediante el campo `uid`.
3. Una regla propia de Suricata (`sid >= 1000000`) validada con `suricata -T` y la alerta correspondiente en `eve.json`.
4. Explicación breve de cómo suprimirías un falso positivo de esa regla si un escáner interno autorizado usara el mismo encabezado.
:::

## Preguntas de repaso

**1. ¿Por qué los equipos NSM combinan metadatos de Zeek con captura PCAP de retención corta en lugar de guardar todo en PCAP indefinidamente?** Porque el PCAP completo consume demasiado almacenamiento para retener semanas o meses de tráfico, mientras que los logs estructurados de Zeek ocupan una fracción mínima, permiten búsquedas rápidas en el SIEM y señalan qué ventana puntual revisar en PCAP.

**2. ¿Qué información útil puede extraerse del tráfico TLS sin descifrar el contenido de la sesión?** Se pueden analizar metadatos del *handshake*, como el dominio indicado en SNI, la versión de TLS, los datos del certificado (emisor, vigencia, validez) y huellas de cliente como JA3, además de la cadencia temporal y el volumen de bytes.

**3. ¿Cuál es la función del campo `uid` en los registros de Zeek?** Actúa como clave única de correlación de una conexión específica, permitiendo enlazar en segundos su resumen de red en `conn.log` con sus detalles de aplicación en `dns.log`, `http.log` o `ssl.log`.

**4. ¿Por qué en una regla Suricata conviene combinar `content` antes de aplicar `pcre`?** Porque `content` utiliza el motor de búsqueda rápida de cadenas literales para filtrar la inmensa mayoría de los paquetes con mínimo consumo de CPU, reservando la evaluación costosa de expresiones regulares (`pcre`) solo a los paquetes prefiltrados.

**5. ¿Cuál es el riesgo principal de habilitar reglas nuevas directamente en modo IPS (`drop`) sin fase previa en modo IDS (`alert`)?** Un error en la lógica de la regla o una excepción no contemplada puede bloquear tráfico operativo legítimo y provocar una interrupción autoinducida del servicio (*self-DoS*).

## Antes de avanzar

- [ ] Diferenciás cuándo usar PCAP completo, NetFlow y logs estructurados de Zeek.
- [ ] Ejecutaste filtros en `tshark` para inspeccionar DNS, HTTP, SNI y periodicidad temporal.
- [ ] Procesaste una captura local con Zeek y correlacionaste registros mediante `uid`.
- [ ] Escribiste, validaste (`suricata -T`) y probaste una regla Suricata sobre un archivo PCAP.

::: nota Puerta de salida
Con los cuatro capítulos de esta Parte A completados, ya contás con el ciclo operativo completo de defensa y monitoreo: procesos SOC y respuesta a incidentes, telemetría de endpoints Windows/Linux, correlación SIEM en Splunk/Elastic y análisis de red con Wireshark, Zeek y Suricata.
:::

## Referencias y estándares abiertos

- Zeek Official Documentation — *Log Files & Scripting Reference*: https://docs.zeek.org/
- OISF Suricata User Guide — *Rule Format & Performance Tuning*: https://docs.suricata.io/
- Wireshark User's Guide & `tshark` Manual: https://www.wireshark.org/docs/
- NIST Special Publication 800-94 — *Guide to Intrusion Detection and Prevention Systems (IDPS)*: https://csrc.nist.gov/publications/detail/sp/800-94/final
