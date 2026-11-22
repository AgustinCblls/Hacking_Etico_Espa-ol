::: nota Objetivo de la lección
Al finalizar este capítulo vas a comprender por qué las prioridades de seguridad se invierten en entornos de Tecnología Operativa (OT), identificar los componentes centrales de una arquitectura ICS/SCADA, aplicar el Modelo Purdue (ISA-95 / IEC 62443) con su DMZ Industrial en Nivel 3.5, analizar las debilidades históricas de protocolos industriales como Modbus, DNP3, S7comm y OPC UA, y diseñar controles defensivos basados en segmentación, diodos de datos y monitoreo estrictamente pasivo.
:::

Cuando salís de una red corporativa tradicional (IT) y entrás en una planta industrial, una subestación eléctrica o una planta potabilizadora de agua, las reglas operativas cambian de raíz. En IT, reiniciar un servidor que se colgó durante un escaneo de puertos suele resolverse en minutos. En un entorno **OT (*Operational Technology*)** con sistemas **ICS (*Industrial Control Systems*)** y **SCADA (*Supervisory Control and Data Acquisition*)**, un paquete malformado o una ráfaga agresiva de red puede detener un proceso continuo de manufactura, dañar equipamiento de millones de dólares o poner en riesgo directo la vida de operarios y poblaciones cercanas.

## Inversión de la tríada y fragilidad de los dispositivos de campo

En seguridad informática corporativa (IT), la tríada clásica suele priorizar **Confidencialidad -> Integridad -> Disponibilidad** según el valor de los datos protegidos. En sistemas industriales OT/ICS, esa escala se invierte de forma tajante:

1. **Seguridad física humana y ambiental (*Safety*):** ninguna acción técnica o de respuesta a incidentes puede comprometer la integridad física de las personas, el ambiente o la contención de materiales peligrosos.
2. **Disponibilidad:** los procesos físicos operan en tiempo real determinista, las 24 horas del día durante años sin ventanas de parada. Perder la comunicación durante milisegundos puede disparar paradas de emergencia (*trips*) con daños mecánicos o pérdidas productivas enormes.
3. **Integridad:** asegurar que las mediciones de los sensores y las consignas enviadas hacia válvulas, bombas o disyuntores no sean alteradas ni suplantadas en tránsito.
4. **Confidencialidad:** aunque importa resguardar secretos de fabricación o topologías de planta, en la operación del piso de planta ocupa el último lugar frente a la estabilidad del proceso físico.

| Criterio operativo | Entorno IT corporativo | Entorno OT / ICS / SCADA |
| :--- | :--- | :--- |
| Prioridad principal | Confidencialidad e Integridad | Seguridad humana (*Safety*) y Disponibilidad |
| Ciclo de vida del activo | 3 a 5 años | 15 a 30 años en operación continua |
| Tolerancia a latencia y caídas | Alta (segundos de reintento aceptables) | Muy baja (requiere determinismo en milisegundos) |
| Ventanas de parcheo | Mensuales o semanales automatizadas | Raras (solo en paradas programadas de planta) |
| Impacto de escaneo activo | Degradación leve o alerta en SIEM | Bloqueo del PLC, disparo de protecciones y parada física |

### Por qué un escaneo agresivo tipo Nmap puede tumbar un PLC viejo

En auditorías IT es habitual ejecutar `nmap -sS -sV -T4 -p-`. Trasladar esa misma práctica a una red de control industrial provoca caídas reales por razones técnicas concretas:

- **Pilas TCP/IP embebidas heredadas:** muchos **PLCs**, **RTUs** y variadores de frecuencia diseñados hace 15 o 20 años corren sobre microcontroladores de bajos recursos con sistemas operativos en tiempo real (RTOS) minimalistas y tablas muy reducidas de sockets simultáneos (a veces 8 o 16 conexiones TCP).
- **Agotamiento de buffers y falta de manejo de excepciones:** una ráfaga de paquetes SYN o sondas de banners (`-sV`) que envían cadenas HTTP/TLS/SMB arbitrarias a puertos industriales propietarios puede saturar la cola de recepción o disparar fallos de memoria en la tarjeta de comunicaciones del controlador.
- **Violación del tiempo de ciclo (*Scan Cycle*) y *Watchdog*:** un PLC ejecuta un bucle determinista continuo (leer entradas -> evaluar lógica -> actualizar salidas). Si la CPU dedica ciclos excesivos a procesar interrupciones de red anómalas, el temporizador supervisor (*watchdog timer*) detecta que el ciclo superó el límite máximo y pasa el controlador a modo **FAULT / STOP** por seguridad, deteniendo la maquinaria conectada.

::: peligro Regla de oro en evaluaciones OT
Nunca ejecutes escaneos activos agresivos (`-T4`, `-T5`, `-sV`, `-A`, fuzzers o fuerza bruta) contra subredes de Nivel 0, 1 o 2 sin autorización explícita, validación previa en gemelo de laboratorio (*testbed*) y presencia del ingeniero de automatización de planta. La metodología recomendada parte siempre del **descubrimiento pasivo** mediante capturas de tráfico.
:::

## Arquitectura y componentes de un entorno ICS/SCADA

Para auditar o defender una red industrial necesitás identificar con claridad qué rol cumple cada activo dentro del lazo de control:

- **PLC (*Programmable Logic Controller*):** computadora industrial endurecida que recibe señales de sensores (temperatura, presión, caudal), ejecuta lógica determinista en tiempo real (lenguajes IEC 61131-3 como *Ladder* o *Texto Estructurado*) y acciona actuadores locales (válvulas, motores, relés).
- **RTU (*Remote Terminal Unit*):** dispositivo con propósito equivalente al PLC pero optimizado para emplazamientos geográficamente dispersos (subestaciones eléctricas, estaciones de bombeo, gasoductos), con almacenamiento en búfer local ante cortes y enlaces por radio, satélite, celular o fibra hacia el centro SCADA.
- **HMI (*Human-Machine Interface*):** panel táctil en máquina o estación gráfica de operador que muestra variables de proceso en tiempo real, alarmas activas y controles para ajustar consignas (*setpoints*) o iniciar secuencias.
- **Historian:** servidor especializado en bases de datos de series temporales de alta velocidad que registra miles de mediciones por segundo para trazabilidad regulatoria, calidad y analítica. Suele ser el puente de datos clave entre OT e IT.
- **Engineering Workstation (EWS):** estación de trabajo donde corren los entornos de ingeniería propietarios (como TIA Portal o Studio 5000) usados para programar lógica, actualizar firmware y descargar proyectos hacia los PLCs. Comprometer la EWS equivale a controlar el proceso físico completo.

## El Modelo Purdue (ISA-95 / IEC 62443) y la DMZ Industrial

El **Modelo Purdue (PERA)**, adoptado por **ISA-95** e integrado como referencia de segmentación en **IEC 62443**, organiza la frontera entre el proceso físico y la red corporativa en niveles jerárquicos separados por una zona desmilitarizada intermedia indispensable.

| Nivel Purdue | Denominación | Componentes típicos | Flujo de comunicación permitido |
| :--- | :--- | :--- | :--- |
| **Nivel 0** | Proceso físico | Sensores, transmisores, válvulas, motores | Señales analógicas (4–20 mA), discretas o buses de campo hacia Nivel 1. |
| **Nivel 1** | Control básico | PLCs, RTUs, IEDs, controladores PID, sistemas SIS | Intercambio determinista con Nivel 0 y supervisión con Nivel 2. |
| **Nivel 2** | Control de área | HMIs locales, servidores SCADA de línea/celda | Supervisión de Nivel 1 y reporte hacia Nivel 3. |
| **Nivel 3** | Operaciones de sitio | SCADA maestro de planta, EWS, MES, parches OT, Historian primario | Gestiona Niveles 1–2; único enlace con IT mediante Nivel 3.5. |
| **Nivel 3.5** | **DMZ Industrial (IDMZ)** | *Jump hosts* con MFA, Historian espejo, proxies de parches/AV, Data Diodes | **Aísla OT (<=3) de IT (>=4). Ningún flujo cruza directo.** |
| **Nivel 4** | Redes empresariales IT | ERP, Active Directory corporativo, correo, analítica BI | Consume datos replicados desde Nivel 3.5; jamás conecta a Nivel 1–3. |
| **Nivel 5** | Perímetro / Externo | VPN de proveedores, nube, Internet | Acceso remoto solo hacia IDMZ tras MFA y aprobación por ventana. |

El **Nivel 3.5 (DMZ Industrial o IDMZ)** es la pieza arquitectónica más crítica en seguridad OT. En redes mal segmentadas, un sistema de BI en Nivel 4 consulta directo al Historian de Nivel 3, o un proveedor externo accede por VPN corporativa directo a la IP de un PLC. Ese atajo permite que un *ransomware* originado en una notebook administrativa de Nivel 4 se propague hasta los servidores SCADA y HMIs de Nivel 2/3.

Con una **IDMZ** bien diseñada en Nivel 3.5:

1. Toda sesión entre IT y OT termina y se regenera en un intermediario dentro de la DMZ (por ejemplo, el Historian primario en Nivel 3 empuja datos hacia un Historian espejo en Nivel 3.5, y Nivel 4 lee únicamente esa réplica).
2. El soporte remoto externo ingresa desde Nivel 5 hasta un *jump host* bastión en Nivel 3.5 con MFA, grabación de sesión y habilitación temporal aprobada por Operaciones antes de saltar hacia Nivel 3.
3. Los sistemas instrumentados de seguridad (**SIS**, *Safety Instrumented Systems*) se mantienen aislados del sistema de control básico (BPCS) para que un compromiso del SCADA no anule las paradas de emergencia físicas.

## Protocolos industriales: anatomía y carencias históricas

La mayoría de los protocolos industriales nacieron sobre enlaces seriales RS-232/RS-485 punto a punto, donde el aislamiento físico hacía innecesaria la criptografía. Al encapsularse luego sobre TCP/IP, heredaron confianza implícita hacia cualquier nodo capaz de alcanzar el puerto de red.

### Modbus TCP / RTU (Puerto TCP 502)

Publicado por Modicon en 1979, **Modbus** es el protocolo más difundido en automatización por su simplicidad. Organiza los datos en cuatro tablas: bobinas (*Coils*, 1 bit R/W), entradas discretas (1 bit R), registros de entrada (*Input Registers*, 16 bits R) y registros de retención (*Holding Registers*, 16 bits R/W). El encabezado MBAP en TCP/502 transporta el identificador de unidad y el **Código de Función (*Function Code*)**: por ejemplo `0x01` (leer bobinas), `0x03` (leer registros de retención), `0x05` (escribir una bobina), `0x06` (escribir un registro) y `0x10` (escribir múltiples registros).

**Análisis de seguridad:** Modbus TCP clásico carece por completo de autenticación, autorización y cifrado. Cualquier equipo que alcance el puerto TCP `502` de un PLC puede leer variables o enviar códigos `0x05`/`0x06` para detener maquinaria o alterar consignas. Aunque existe **Modbus/TCP Security** sobre TLS en el puerto `802`, el parque instalado sigue operando mayoritariamente en claro sobre `502`.

### DNP3 (*Distributed Network Protocol 3*, Puerto TCP 20000)

Muy extendido en redes eléctricas y sistemas de agua, DNP3 tolera enlaces ruidosos y transmite eventos con estampa de tiempo entre una estación maestra SCADA y múltiples RTUs o IEDs.

**Análisis de seguridad:** la especificación base no cifra ni autentica mensajes, permitiendo inyección de comandos de apertura o cierre de interruptores (*Direct Operate* / *Select Before Operate*). Si bien existe **DNP3 Secure Authentication (SAv5/SAv6)** con desafío-respuesta HMAC-SHA256 para autenticar comandos críticos, muchas instalaciones heredadas lo mantienen desactivado por compatibilidad.

### S7comm y S7commPlus (Puerto TCP 102)

Protocolo propietario de los controladores Siemens SIMATIC S7 sobre ISO-on-TCP (RFC 1006, puerto `102`). Permite leer/escribir bloques de datos (`DB`), cargar o descargar lógica y ejecutar comandos como `STOP CPU`.

**Análisis de seguridad:** en S7-300/400, **S7comm** clásico viaja sin cifrado y su protección opcional por contraseña resultó vulnerable a captura y repetición (*replay*). Los modelos modernos S7-1200/1500 introdujeron **S7commPlus** con integridad criptográfica y protección *anti-replay*, aunque habilitar modos de compatibilidad heredados (*PUT/GET*) vuelve a exponer el PLC.

### OPC UA (*Unified Architecture*, Puerto TCP 4840)

Sucesor multiplataforma de OPC Classic (que dependía de RPC/DCOM inseguro en Windows), **OPC UA** sí incorpora seguridad robusta nativa: certificados X.509 mutuos, firma y cifrado AES/SHA-256 (`Basic256Sha256`). Su falla frecuente en planta es operativa: por simplicidad de puesta en marcha, muchos integradores lo degradan a `SecurityPolicy: None` y acceso anónimo, anulando el cifrado.

| Protocolo | Puerto típico | Seguridad nativa | Riesgo frecuente en planta | Filtro Wireshark |
| :--- | :--- | :--- | :--- | :--- |
| **Modbus TCP** | TCP 502 (TLS: 802) | Ninguna en versión clásica | Escritura arbitraria de registros/bobinas (`0x05`, `0x06`, `0x10`) | `modbus` o `mbtcp` |
| **DNP3** | TCP/UDP 20000 | Opcional (SAv5/SAv6 HMAC) | Maniobras no autenticadas si SAv5 está inactivo | `dnp3` |
| **S7comm / Plus** | TCP 102 | Solo en S7commPlus moderno | Parada remota de CPU (`STOP`) o alteración de lógica | `s7comm` |
| **OPC UA** | TCP 4840 | Robusta (X.509 + AES/SHA256) | Degradación manual a `SecurityPolicy: None` | `opcua` |

## Segmentación OT, Data Diodes y monitoreo pasivo de tráfico

Como en OT raramente podés parchear PLCs en caliente o instalarles agentes EDR, la defensa se apoya en controlar caminos de red y observar pasivamente lo que circula por el cable.

### Firewalls OT con inspección profunda de protocolos (DPI)

Un firewall L4 tradicional (`Permitir SCADA -> PLC 502`) no distingue lecturas de escrituras. Los **firewalls industriales con DPI** comprenden la gramática de Modbus, DNP3 o S7comm y aplican políticas granulares alineadas a zonas y conductos de **IEC 62443**: por ejemplo, permitir al Historian leer registros con código `0x03` y bloquear códigos de escritura (`0x05`, `0x06`, `0x10`) desde cualquier origen distinto de la HMI o EWS autorizada.

### Data Diodes unidireccionales

En infraestructuras críticas donde solo se necesita exportar telemetría desde Nivel 3 hacia la IDMZ/IT, se instalan **Data Diodes**. A diferencia de un firewall por software, un diodo de datos impone unidireccionalidad física mediante hardware: un transmisor óptico (LED/láser) conectado por una única fibra hacia un receptor (fotodiodo), **sin fibra física de retorno**. Así es físicamente imposible que un paquete de ataque cruce desde IT hacia la red OT. Para transportar protocolos que requieren `ACK`, proxies dedicados convierten el tráfico en tramas UDP unidireccionales con corrección de errores y reconstruyen la sesión en el lado receptor.

### Monitoreo pasivo de tráfico OT

Para obtener visibilidad continua sin inyectar paquetes activos ni agregar latencia en los lazos de control se utiliza **monitoreo pasivo**:

1. **Adquisición fuera de banda:** se conectan **TAPs de red** pasivos o puertos **SPAN / Mirror** hacia sensores en modo solo escucha (sin dirección IP asignada en la subred de control).
2. **Análisis pasivo:** motores abiertos como **Zeek** (analizadores ICS para Modbus, DNP3, S7comm, OPC UA), **Suricata** (reglas de protocolo `modbus`, `dnp3`, `enip`) y plataformas OT especializadas (como Nozomi Networks, Claroty o Dragos a nivel conceptual) construyen pasivamente el **inventario de activos** (modelo de PLC y firmware observados en tráfico legítimo), establecen la **línea base de comunicaciones** (*allowlisting* de pares IP y códigos de función) y alertan ante anomalías como nuevas estaciones conectándose al puerto `102`/`502` o descargas de lógica fuera de ventana.

```text
# Regla Suricata conceptual para alertar escritura Modbus desde origen no autorizado
alert modbus any any -> 10.20.1.0/24 502 (msg:"OT ALERTA - Escritura Modbus FC 06 no autorizada"; \
    modbus: function 6; flow:to_server,established; \
    src_ip: ![10.20.30.10,10.20.30.11]; sid:9000101; rev:1;)
```

## Práctica guiada en laboratorio

En esta práctica vas a analizar de manera estrictamente pasiva una captura de tráfico industrial simulado y diseñar reglas defensivas de segmentación y detección.

1. **Obtención de captura educativa:** descargá en tu VM de análisis una captura `.pcap` pública de tráfico ICS (por ejemplo, muestras Modbus/DNP3/S7comm de *Wireshark SampleCaptures* o repositorios educativos abiertos de *ICS-Security-Tools*).
2. **Inspección pasiva con TShark/Wireshark:** ejecutá análisis en modo solo lectura sobre la captura:
   - Listá conversaciones Modbus con `tshark -r captura.pcap -Y "modbus" -T fields -e ip.src -e ip.dst -e modbus.func_code`.
   - Clasificá los códigos de función observados diferenciando lecturas (`1`, `3`, `4`) de escrituras (`5`, `6`, `15`, `16`).
3. **Diseño Purdue y reglas DPI:** ubicá las IPs observadas en los Niveles 1, 2, 3 y 3.5 del Modelo Purdue, definiendo dónde conectarías el puerto SPAN para monitoreo pasivo y qué reglas DPI permitirían solo lecturas hacia el Historian.

::: practica Entregable mínimo
Entregá un informe breve de análisis pasivo OT con: (a) los comandos `tshark` / filtros Wireshark usados y el inventario de nodos cliente-servidor extraído del `.pcap`; (b) tabla diferenciando códigos de función de lectura y escritura observados; y (c) diagrama textual del Modelo Purdue con Nivel 3.5 (IDMZ), ubicación del sensor pasivo y tres reglas DPI propuestas.
:::

::: defensa Perspectiva defensiva y gobernanza
La seguridad OT requiere alinear ingeniería de planta y ciberseguridad corporativa bajo **IEC 62443** y el **Modelo Purdue**. Eliminá conexiones directas entre Nivel 4 (IT) y Niveles 1–3 imponiendo una **DMZ Industrial (Nivel 3.5)** y **Data Diodes** donde solo exista exportación de telemetría; protegé las **Engineering Workstations** y accesos remotos con MFA y grabación de sesión; implementá **monitoreo pasivo** con TAP/SPAN (Zeek/Suricata o plataformas OT especializadas) para inventariar activos y detectar cambios en PLCs sin riesgo operativo; y prohibí por política todo escaneo activo no validado en redes productivas de control.
:::

## Preguntas de repaso

**1. ¿Por qué se invierte la tríada CIA en entornos OT/ICS respecto de IT y qué implica para un auditor?** Porque en procesos físicos industriales la pérdida de disponibilidad o alteración de comandos puede causar accidentes humanos graves, daños ambientales o paradas costosas, priorizando Seguridad física (*Safety*) y Disponibilidad sobre Integridad y Confidencialidad; esto obliga al auditor a evitar pruebas activas disruptivas y priorizar técnicas pasivas.

**2. ¿Por qué un escaneo agresivo con Nmap (`-T4 -sV`) puede sacar de servicio a un PLC antiguo?** Porque muchos PLCs heredados poseen pilas TCP/IP simples y tablas muy pequeñas de sockets simultáneos; una ráfaga de paquetes o sondeos inesperados satura buffers o alarga el ciclo de escaneo, disparando el temporizador *watchdog* y pasando el controlador a estado de falla o parada (*STOP*).

**3. ¿Qué función cumple el Nivel 3.5 (DMZ Industrial) dentro del Modelo Purdue?** Desacopla obligatoriamente la red OT (Niveles 0–3) de la red IT corporativa (Niveles 4–5), alojando intermediarios como servidores Historian espejo, proxies de parches y *jump hosts* con MFA para evitar que compromisos en IT alcancen directamente los PLCs o servidores SCADA.

**4. ¿Qué debilidad comparten Modbus TCP, DNP3 clásico y S7comm tradicional, y cuál es el riesgo habitual de OPC UA en campo?** Modbus TCP, DNP3 clásico y S7comm tradicional carecen de autenticación mutua y cifrado nativos en sus versiones base; OPC UA sí incluye autenticación X.509 y cifrado AES/SHA-256, pero en campo suele degradarse operativamente a `SecurityPolicy: None` anulando esa protección.

**5. ¿Cómo se logra visibilidad de red y aislamiento unidireccional en OT sin afectar el ciclo de los PLCs?** Mediante **monitoreo estrictamente pasivo** sobre TAPs o puertos SPAN conectados a motores en modo solo escucha (Zeek, Suricata o plataformas OT) junto con **firewalls DPI** y **Data Diodes** unidireccionales por hardware que impiden físicamente el ingreso de tráfico desde IT.

## Antes de avanzar

::: nota Puerta de salida
Antes de avanzar al último capítulo sobre GRC y marco legal, asegurate de saber ubicar PLC, RTU, HMI, Historian y EWS en el Modelo Purdue con su IDMZ en Nivel 3.5, explicar por qué los protocolos industriales clásicos fallan en autenticación y justificar el monitoreo pasivo frente al escaneo activo.
:::

## Referencias y estándares abiertos

- NIST SP 800-82 Rev. 3 (*Guide to Operational Technology Security*).
- Serie normativa internacional **ISA/IEC 62443** y modelo de referencia **ANSI/ISA-95**.
- Especificación técnica **Modbus Application Protocol** y **OPC Foundation OPC UA Security Architecture**.
- Proyectos abiertos **Zeek** y **Suricata** para análisis pasivo de protocolos ICS.
