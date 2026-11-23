::: nota Objetivo de la lección
Al finalizar este capítulo vas a poder evaluar controles de seguridad física en auditorías autorizadas, diferenciar tecnologías RFID/NFC de baja y alta frecuencia frente a ataques de clonación, mitigar vectores en puertos expuestos como BadUSB y ataques DMA, comprender el diseño del cifrado de disco completo frente a ataques en frío y ejecutar un análisis pasivo inicial de hardware y firmware embebido con `binwalk`.
:::

Toda infraestructura lógica descansa sobre un sustrato físico. Si un atacante o un auditor autorizado obtiene acceso directo a un puerto USB desbloqueado, a una placa base con depuración activa o al lector de acceso de un edificio, los controles perimetrales de red quedan soslayados. En este capítulo abordamos la frontera física y de hardware: cómo se evalúan estos controles bajo autorización estricta y cómo se diseña su defensa en profundidad.

## Seguridad física en auditorías autorizadas

Las auditorías de seguridad física forman parte de evaluaciones de *Red Team* o verificación de cumplimiento (como ISO/IEC 27001 o PCI-DSS). Al involucrar interacción humana e infraestructura sensible, nunca se improvisan: exigen un documento de Reglas de Enfrentamiento (*RoE*) que delimite edificios, horarios y áreas excluidas, además de una carta de autorización firmada que el auditor lleva consigo en todo momento.

### Control de accesos, tailgating y piggybacking

El perímetro físico se diseña en anillos concéntricos: perímetro exterior, recepción, oficinas generales y áreas técnicas restringidas. Cada transición requiere controles acordes al riesgo:

- **Barreras físicas y esclusas (*mantraps*):** los molinetes ópticos alertan cuando pasan dos personas con una sola credencial; las esclusas de doble puerta con enclavamiento (*interlock*) impiden abrir la segunda puerta si sensores de peso o volumétricos detectan más de un individuo en cabina.
- ***Tailgating* y *piggybacking*:** el *tailgating* consiste en aprovechar el cierre lento de una puerta para ingresar detrás de un empleado sin su consentimiento; el *piggybacking* utiliza ingeniería social para que el empleado sostenga la puerta voluntariamente (por ejemplo, cargando cajas o mostrando una credencial falsa).
- **Gestión de visitas:** todo tercero debe registrarse con documento de identidad, portar credencial de color diferenciado y circular siempre bajo escolta en áreas operativas.

::: aviso Protocolo ante confrontación en pruebas físicas
Si durante una auditoría autorizada el personal de vigilancia o un empleado te detiene e interroga, detené de inmediato la maniobra, mantené la calma y presentá la carta de autorización según lo acordado en el RoE. Nunca escales una discusión ni fuerces el paso físico.
:::

### Cerraduras, ubicación de racks y videovigilancia

Un lector biométrico o de proximidad pierde efectividad si la mecánica de la puerta o la disposición de salas técnicas presenta fallas elementales:

| Componente | Falla frecuente en auditorías | Medida de mitigación |
| :--- | :--- | :--- |
| Pestillo y marco | Holgura que permite retraer el pestillo con lámina (*latch slipping*) | Instalar placa protectora (*latch guard*) y pestillo con bloqueo muerto (*deadlatch*). |
| Cerradura electrónica | Sensores REX mal orientados que abren al deslizar algo bajo la puerta | Calibrar ángulo del sensor PIR y elegir *fail-secure* o *fail-safe* según norma de evacuación. |
| Bisagras y tabiques | Bisagras con pernos expuestos; paredes falsas hasta el cielorraso | Bisagras con pernos fijos de seguridad y muros extendidos hasta la losa (*slab-to-slab*). |
| Cuartos IDF / MDF y racks | Racks abiertos o con llave universal de fábrica | Cerraduras únicas o electrónicas por gabinete, sensores de puerta y salas IDF dedicadas. |
| Cámaras (CCTV) | Puntos ciegos sobre lectores, retención corta o cámaras en VLAN de oficinas | Cubrir accesos y frentes/dorsos de racks sin enfocar pantallas; aislar en VLAN dedicada con UPS. |

En cuartos de cableado (*IDF/MDF*), cada rack debe mantener cerradas sus puertas frontales y traseras con sensores magnéticos integrados al sistema de monitoreo. Si un puerto Ethernet de acceso queda expuesto en un cuarto sin 802.1X, pocos minutos bastan para conectar un implante de red o un punto de acceso oculto.

## Tarjetas RFID y NFC: del 125 kHz a DESFire con AES

Las credenciales sin contacto dominan el control de acceso físico, pero su resistencia a la clonación cambia por completo según la frecuencia y la arquitectura criptográfica.

### Baja frecuencia (125 kHz): EM410x y HID Prox

Las tarjetas LF (125 kHz) como **EM410x** y **HID Prox** fueron concebidas para identificación básica, sin criptografía. Al acercarse al campo electromagnético de una antena lectora, la tarjeta se energiza por inducción y transmite de forma continua su identificador estático en texto claro.

Esta arquitectura presenta tres debilidades críticas: carece de autenticación mutua (responde a cualquier lector compatible, incluso oculto a corta distancia), viaja sin cifrado ni desafío-respuesta, y puede clonarse en segundos sobre chips regrabables como **T5577**, generando una copia idéntica para el controlador de la puerta.

### Alta frecuencia (13.56 MHz): MIFARE Classic vs MIFARE DESFire EV2/EV3

En 13.56 MHz (ISO/IEC 14443 Tipo A/B, compatible con NFC) existen chips con capacidades criptográficas muy dispares:

- **MIFARE Classic (1K / 4K):** utiliza el cifrado propietario **Crypto-1** con claves de 48 bits y un generador pseudoaleatorio (PRNG) débil. Los ataques criptoanalíticos públicos (*Darkside*, *Nested*, *Hardnested*) recuperan todas las claves de los sectores en segundos o minutos, permitiendo leer la memoria completa y duplicarla en tarjetas *Magic* con bloque 0 (UID) regrabable. Se considera obsoleta.
- **MIFARE DESFire (EV2 / EV3):** implementa un sistema de archivos por aplicaciones con **autenticación mutua basada en AES-128** estándar. La clave secreta nunca sale del chip: lector (mediante módulo SAM) y tarjeta ejecutan un protocolo desafío-respuesta de tres pasos con números aleatorios frescos, derivando una clave de sesión efímera para cifrar y autenticar cada comando con CMAC (*Secure Messaging*).

¿Por qué **DESFire EV2/EV3 con AES** mitiga la clonación? Porque la verificación no depende del UID público: incluso activando **Random UID** (que impide rastrear usuarios por su identificador fijo) o copiando el UID físico, un clon sin la clave AES almacenada en el chip original no puede resolver el desafío criptográfico del lector. Además, soporta **diversificación de claves** (derivando una clave única por tarjeta desde una clave maestra mediante AES-CMAC), de modo que comprometer una credencial individual no compromete al resto del edificio.

| Tecnología | Frecuencia | Cifrado / Estándar | Autenticación mutua | Riesgo de clonación |
| :--- | :--- | :--- | :--- | :--- |
| EM410x / HID Prox | 125 kHz (LF) | Ninguno (UID en claro) | No | Crítico (clonación directa en T5577) |
| MIFARE Classic | 13.56 MHz (HF) | Crypto-1 (48 bits, roto) | Débil | Crítico (recuperación de claves y copia en *Magic UID*) |
| MIFARE DESFire EV2/EV3 | 13.56 MHz (HF) | AES-128 + Secure Messaging | Sí (3-pass + CMAC) | Muy bajo / Nulo con AES diversificado |

::: peligro El error del modo CSN-only
Adquirir tarjetas DESFire EV3 no protege la instalación si los lectores están configurados para leer únicamente el UID/CSN externo de capa ISO 14443A por compatibilidad heredada. Verificá siempre que los lectores usen módulos SAM y autenticación AES completa.
:::

## Puertos físicos expuestos: BadUSB, políticas USB y ataques DMA

Un equipo desatendido en una sala de reuniones o un puerto expuesto en un tótem de recepción aprovecha la confianza implícita del sistema operativo hacia el hardware conectado localmente.

### BadUSB e inyección HID

Un dispositivo **BadUSB** modifica el firmware de un microcontrolador para declararse como un teclado **HID** (*Human Interface Device*), a veces combinado con un adaptador de red USB (RNDIS/ECM). Dado que los sistemas operativos confían automáticamente en teclados nuevos sin pedir confirmación, el dispositivo inyecta secuencias de comandos en milisegundos para abrir terminales, descargar cargas útiles o capturar hashes Net-NTLMv2 si el equipo está desbloqueado o permite interfaces de red en pantalla de bloqueo.

### Bloqueo de puertos USB por política, Udev e Intune

La mitigación combina bloqueo físico de puertos innecesarios, deshabilitación en UEFI y listas blancas en el sistema operativo:

- **Linux (`udev` / `USBGuard`):** permite fijar `authorized_default=0` y autorizar dispositivos únicamente por `idVendor`, `idProduct` y número de serie. **USBGuard** añade control por clase de interfaz para bloquear dispositivos compuestos que combinen almacenamiento y teclado.
- **Windows (GPO / Microsoft Intune):** las directivas de *Device Control* y *Restricción de instalación de dispositivos* en Intune permiten bloquear almacenamiento extraíble, impedir nuevos adaptadores de red USB y restringir nuevos teclados HID en quioscos o estaciones críticas mediante listas de *Hardware IDs* aprobados.

```ini
# /etc/udev/rules.d/99-usb-restrict.rules
# Bloquea por defecto nuevos dispositivos USB y autoriza un teclado corporativo específico
ACTION=="add", SUBSYSTEM=="usb", TEST=="authorized_default", ATTR{authorized_default}="0"
ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="046d", ATTR{idProduct}=="c31c", ATTR{authorized}="1"
```

### Ataques DMA vía Thunderbolt/PCIe y mitigación IOMMU

Los puertos **Thunderbolt 3/4**, **USB4** (con túnel PCIe) y ranuras **M.2 / PCIe** permiten **Acceso Directo a Memoria (DMA)**, transfiriendo datos hacia y desde la RAM sin intervención de la CPU ni controles del sistema operativo. Un atacante con hardware FPGA (como placas de prueba tipo *PCILeech*) conectado brevemente a un puerto Thunderbolt sin protección puede volcar la RAM para extraer claves de cifrado activas o inyectar código en el kernel y sortear la pantalla de bloqueo.

La defensa estructural reside en la **IOMMU** (**Intel VT-d** / **AMD-Vi**), que interpone tablas de traducción de direcciones entre dispositivos PCIe externos y la RAM física, restringiendo cada periférico únicamente a sus páginas asignadas.

| Capa | Control defensivo contra DMA | Efecto práctico |
| :--- | :--- | :--- |
| Firmware UEFI | Activar **Intel VT-d / AMD-Vi** y *Pre-boot DMA Protection* | Impide lecturas DMA antes de cargar el sistema operativo. |
| Windows / Intune | Verificar **Kernel DMA Protection** (`msinfo32`) y bloquear periféricos no compatibles | Bloquea o aísla dispositivos Thunderbolt/PCIe mientras el equipo está bloqueado. |
| Linux | Parámetros de kernel `intel_iommu=on iommu=force` y demonio `boltd` | Exige remapeo estricto IOMMU y autorización explícita de túneles Thunderbolt. |

## Cifrado completo de disco: BitLocker y LUKS2 frente a ataques en frío

El cifrado completo de disco (*FDE*) protege los datos en reposo ante robo de portátiles, pero la forma de custodiar la clave maestra durante el arranque define su resistencia ante un atacante físico.

### BitLocker con TPM + PIN frente a TPM sniffing en frío

En modo *TPM-only* (solo TPM), al encender el equipo el chip **TPM** valida la integridad del arranque y entrega automáticamente la **VMK (*Volume Master Key*)** sin intervención del usuario. Cuando el equipo emplea un **dTPM** discreto soldado en la placa madre, la VMK suele viajar sin cifrar por el bus **LPC** o **SPI** hacia la CPU. Mediante **TPM sniffing**, un atacante con acceso físico breve conecta un analizador lógico a esas pistas expuestas durante el encendido y captura la VMK en claro, descifrando luego el disco entero fuera del equipo.

Exigir **BitLocker con TPM + PIN de pre-arranque** (mejorado mediante directiva `AllowEnhancedPin`) neutraliza este ataque: el TPM no libera la VMK hasta recibir el secreto ingresado por el usuario, el cual no reside en la placa madre. Complementariamente, evitar la suspensión S3 tradicional (usando hibernación S4 o apagado fuera de oficina) mitiga ataques *cold boot* sobre RAM residual.

### LUKS2 en Linux

En Linux, **LUKS2** (gestionado con `cryptsetup`) emplea cabeceras resilientes, cifrado `aes-xts-plain64` de 512 bits y la función de derivación **Argon2id**, resistente a fuerza bruta acelerada por GPU/ASIC. Para combinar usabilidad y resistencia contra *TPM sniffing*, se vincula el *keyslot* al chip TPM2 exigiendo PIN de arranque:

```bash
# Inspección de cabecera LUKS2 y parámetros KDF (solo lectura)
sudo cryptsetup luksDump /dev/nvme0n1p3

# Enrolamiento TPM2 con PIN obligatorio en LUKS2
sudo systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes /dev/nvme0n1p3
```

## Análisis básico de hardware, IoT y firmware

La evaluación autorizada de dispositivos embebidos e IoT requiere identificar las interfaces de depuración en la placa (*PCB*) y analizar de forma pasiva la imagen de firmware.

### Buses UART, depuración JTAG/SWD y memorias SPI

1. **UART (*Universal Asynchronous Receiver-Transmitter*):** bus serie asíncrono (`VCC`, `GND`, `TX`, `RX` a 3.3 V o 1.8 V). Tras medir voltajes con multímetro y determinar la velocidad en baudios (habitualmente `115200 8N1`), un adaptador USB-UART suele exponer la consola del *bootloader* (U-Boot) o una shell `root` embebida sin autenticación.
2. **JTAG y SWD:** puertos de depuración en chip (`TDI`, `TDO`, `TCK`, `TMS` en JTAG; `SWDIO`, `SWCLK` en ARM SWD). Si no fueron bloqueados en fábrica mediante fusibles (*eFuses* o niveles de protección de lectura), permiten pausar la CPU, volcar memoria flash protegida y leer secretos en RAM.
3. **Memorias SPI Flash:** chips externos de 8 pines (SOIC-8) que almacenan *bootloader*, kernel y sistema de archivos. Cuando UART y JTAG están cerrados pero la flash no está cifrada, en laboratorio autorizado se lee la memoria con pinza SOIC-8 y programador SPI.

### Extracción y análisis pasivo de firmware con `binwalk`

Con el volcado del chip o una actualización pública del fabricante, el análisis pasivo inicial se realiza en una estación aislada con **`binwalk`**, que detecta firmas de compresión, kernels y sistemas de archivos embebidos (SquashFS, JFFS2, CramFS):

```bash
# 1. Mapear firmas y desplazamientos (offsets) sin extraer
binwalk firmware_router.bin

# 2. Analizar entropía para identificar zonas comprimidas o cifradas
binwalk -E firmware_router.bin

# 3. Extraer de forma recursiva en un directorio de trabajo sin privilegios de root
binwalk -eM firmware_router.bin
```

Sobre el sistema de archivos extraído (`squashfs-root/`), la inspección pasiva busca hallazgos de alto impacto: **credenciales hardcodeadas** en `/etc/shadow`, scripts de inicio `/etc/init.d/*` o archivos de configuración; **claves privadas TLS/SSH** compartidas por toda la línea de producto; y **servicios expuestos** al arranque como `telnetd`, servidores web obsoletos o scripts CGI que invoquen `system()` con entradas no sanitizadas.

| Comando de inspección pasiva | Objetivo dentro de `squashfs-root/` |
| :--- | :--- |
| `grep -rnE "password\|passwd\|secret\|api_key" etc/` | Detectar credenciales o secretos en texto claro. |
| `find . -name "*.pem" -o -name "*.key"` | Localizar llaves privadas embebidas de fábrica. |
| `cat etc/inittab && ls -la etc/init.d/` | Verificar servicios peligrosos al inicio (ej. Telnet). |
| `strings usr/bin/httpd \| grep -E "system\|/bin/sh"` | Buscar posibles inyecciones de comandos en binarios web. |

### Bluetooth Low Energy (BLE): arquitectura GAP/GATT y auditoría ética

Muchos dispositivos médicos, cerraduras inteligentes y sensores IoT emplean **Bluetooth Low Energy (BLE)** en la banda de 2.4 GHz. Su modelo operativo se divide en dos capas esenciales para el auditor:

- **GAP (*Generic Access Profile*):** gobierna el descubrimiento y la publicidad (*advertising*). Un dispositivo *Peripheral* emite paquetes periódicos anunciando su nombre, dirección MAC (fija o aleatoria rotativa) y servicios disponibles para que un *Central* (teléfono o gateway) inicie la conexión.
- **GATT (*Generic Attribute Profile*):** una vez establecida la conexión, expone los datos en una jerarquía de **Servicios** y **Características** identificadas por UUIDs. Cada característica define permisos como **`Read`** (lectura), **`Write`** / **`Write Without Response`** (escritura de comandos o configuración) y **`Notify`** (suscripción a cambios en tiempo real).

El fallo más frecuente en auditorías IoT ocurre al usar el modo de emparejamiento débil ***Just Works*** (o *LE Legacy Pairing* sin código PIN), que no ofrece verificación frente a intercepción *Man-in-the-Middle*, combinado con características `Write` críticas expuestas sin exigir enlace cifrado previo (*Encryption / Authentication Required*). En laboratorio sobre **hardware propio**, podés relevar dispositivos cercanos con `hcitool lescan` o `bluetoothctl`, inspeccionar tráfico capturado en **Wireshark** (disector BLE) y auditar conexiones propias de forma pasiva con **`btlejack`** usando dongles dedicados para confirmar si los comandos de control viajan cifrados mediante *LE Secure Connections* (ECDH + *Numeric Comparison* o *Passkey*).

### Bluetooth Clásico (`BR/EDR`) y panorama del bus CAN automotriz

- **Bluetooth Clásico (`BR/EDR`) frente a BLE:** utilizado en audio, manos libres, teclados/ratones HID y perfiles serie (`RFCOMM`/`SPP`), implementa pilas más pesadas que BLE y acumuló fallos graves como **BlueBorne** (ejecución remota o fuga de memoria por desbordamientos en pilas sin emparejamiento previo) y **KNOB** (*Key Negotiation of Bluetooth*, reducción forzada de la entropía de cifrado durante la negociación). **Mitigación:** mantener el adaptador en modo **no-descubrible** cuando no se empareja, exigir longitudes mínimas de clave (*Secure Connections Only*), deshabilitar perfiles innecesarios y aplicar parches de firmware/SO.
- **Bus CAN (*Controller Area Network*) automotriz (panorama):** los vehículos modernos interconectan decenas de unidades electrónicas (**ECUs**: motor, ABS, dirección, tablero e infoentretenimiento) sobre el **bus CAN** (accesible físicamente por el puerto diagnóstico **OBD-II**). Por diseño original de resiliencia en tiempo real, las tramas CAN viajan en **broadcast sin cifrado ni autenticación de emisor**, arbitrando prioridad por su identificador (`Arbitration ID`: valores menores como `0x000` ganan prioridad siempre). En bancos de prueba aislados (usando interfaz SocketCAN virtual `vcan0` y `can-utils` con `candump`/`cansend`) se analiza cómo la inyección arbitraria de tramas o inundación de alta prioridad alteraría sensores sin validación; en vehículos actuales, la defensa arquitectónica exige **Central Gateways con listas de filtrado** que aíslen por completo los buses multimedia/telemáticos (Wi-Fi, LTE, Bluetooth) del dominio crítico de tren motriz/frenos y la adopción progresiva de **SecOC** (*Secure Onboard Communication*, autenticación MAC por trama).

### Radiofrecuencia Sub-GHz: código fijo frente a *rolling codes*

Controles remotos de portones, alarmas inalámbricas, sensores industriales y sistemas de apertura vehicular operan habitualmente en bandas ISM **Sub-GHz** (**315 MHz**, **433.92 MHz**, **868 MHz** o **915 MHz**) utilizando modulaciones simples como **ASK/OOK** o **FSK**:

- **Código fijo (*Fixed Code*):** el control transmite siempre exactamente la misma secuencia binaria estática al presionar el botón. Cualquier transceptor en alcance puede grabar esa señal y retransmitirla literalmente (*replay attack*) para abrir el acceso sin conocer clave alguna.
- ***Rolling codes* modernos (como KeeLoq o esquemas cifrados AES):** cada transmisión combina un identificador del transmisor con un **contador incremental sincronizado** cifrado mediante una clave secreta compartida con el receptor. El receptor valida que el contador sea estrictamente mayor que el último aceptado dentro de una ventana válida, invalidando automáticamente cualquier captura repetida (aunque implementaciones heredadas de KeeLoq con claves de fabricante débiles o ataques de bloqueo + captura secuencial refuerzan la necesidad de usar protocolos bidireccionales modernos con AES-128).

En una auditoría ética de laboratorio, la verificación inicial se limita a **recepción pasiva** sobre dispositivos propios usando un receptor **SDR (*Software Defined Radio*)** económico (por ejemplo, un *RTL-SDR* en modo solo escucha) junto a herramientas como `rtl_433` o **Universal Radio Hacker (URH)** para inspeccionar el espectrograma, demodular la trama y confirmar que el sistema no transmita identificadores de código fijo en claro.

## Práctica guiada en laboratorio

En esta práctica vas a inspeccionar de forma pasiva un firmware abierto en entorno aislado y auditar los controles locales de USB e IOMMU en tu máquina virtual Linux.

1. **Preparación aislada:** creá una VM Linux de laboratorio sin acceso a red corporativa, instalá `binwalk`, `squashfs-tools` y `cryptsetup`, y descargá una imagen de firmware abierta educativa (por ejemplo, una imagen oficial de OpenWrt para arquitectura virtual o una imagen pública de práctica como DVRF).
2. **Mapeo y extracción con `binwalk`:** ejecutá `binwalk <imagen.bin>` y `binwalk -E <imagen.bin>` para registrar los offsets de kernel/sistema de archivos y verificar la entropía. Luego extraé el contenido con `binwalk -e <imagen.bin>` usando un usuario sin privilegios.
3. **Búsqueda pasiva de riesgos:** dentro del directorio `squashfs-root` extraído, relevá `/etc/passwd`, `/etc/shadow`, `/etc/init.d/` y archivos de configuración en busca de servicios de red activos, usuarios administrativos y posibles claves o tokens hardcodeados.
4. **Verificación de endurecimiento local:** en tu Linux de pruebas, revisá el estado de IOMMU (`dmesg | grep -iE "iommu|dmar|vt-d"`) y listá reglas activas de `udev` o `usbguard` (`usbguard list-rules`) para comprobar cómo restringir nuevos dispositivos HID o de red USB.

::: practica Entregable mínimo
Presentá un informe técnico breve (1 a 2 páginas) con: (a) la salida resumida de `binwalk` indicando offsets y entropía; (b) una tabla con al menos tres servicios o archivos relevantes inspeccionados en `squashfs-root/` y su nivel de riesgo; y (c) una regla `udev` o política `USBGuard` comentada que bloquee dispositivos USB no autorizados.
:::

::: defensa Perspectiva defensiva y gobernanza
La seguridad física, de hardware y de firmware exige controles preventivos desde la arquitectura y las compras. En instalaciones físicas, implementá defensa por anillos con esclusas, cerraduras únicas por rack, CCTV aislado y credenciales **DESFire EV2/EV3 con AES diversificado** eliminando lectores de 125 kHz. En estaciones corporativas, desplegá políticas mediante **Intune** o **USBGuard** que bloqueen dispositivos USB no aprobados, activá **IOMMU (VT-d / AMD-Vi) y Kernel DMA Protection**, y exigí **BitLocker con TPM + PIN** o **LUKS2 con TPM2 + PIN**. En compras de dispositivos IoT, imponé contractualmente el bloqueo de JTAG/UART en producción, arranque seguro y ausencia de credenciales por defecto o servicios heredados como Telnet.
:::

## Preguntas de repaso

**1. ¿Por qué las tarjetas MIFARE DESFire EV2/EV3 con AES mitigan los ataques de clonación que afectan a EM410x y MIFARE Classic?** Porque EM410x transmite su identificador estático en claro sin autenticación y MIFARE Classic usa el cifrado roto Crypto-1 cuyas claves se recuperan en segundos, mientras que DESFire EV2/EV3 ejecuta autenticación mutua desafío-respuesta basada en AES-128 con claves diversificadas y mensajería segura CMAC donde la clave secreta jamás abandona el chip.

**2. ¿Qué diferencia existe entre un ataque BadUSB y un ataque DMA por Thunderbolt/PCIe, y cómo se mitiga cada uno?** BadUSB abusa de la confianza del sistema operativo en periféricos HID/red USB para inyectar comandos o capturar tráfico, mitigándose con políticas de control de dispositivos (`udev`, `USBGuard`, Intune); en cambio, un ataque DMA accede directamente a la memoria RAM física saltándose el sistema operativo, por lo que requiere aislar direcciones mediante hardware y kernel con IOMMU (Intel VT-d / AMD-Vi) y Kernel DMA Protection.

**3. ¿Por qué BitLocker configurado solo con TPM (TPM-only) es vulnerable ante un atacante con acceso físico y cómo lo resuelve TPM + PIN?** En equipos con TPM discreto (dTPM), la clave maestra VMK viaja sin cifrar por el bus LPC o SPI durante el arranque automático y puede capturarse mediante *TPM sniffing* con un analizador lógico; agregar un PIN de pre-arranque impide que el TPM libere la VMK hasta ingresar el secreto que no reside en la placa madre.

**4. ¿Qué hallazgos busca un auditor al extraer pasivamente un firmware embebido con `binwalk`?** Busca credenciales o hashes débiles hardcodeados en `/etc/shadow` o scripts de inicio, claves privadas TLS/SSH reutilizadas en toda la flota de dispositivos, servicios riesgosos habilitados al arranque (como `telnetd`) y fallas evidentes de sanitización en interfaces web CGI o binarios embebidos.

**5. ¿Qué riesgo implica dejar interfaces UART o JTAG/SWD habilitadas en dispositivos IoT comerciales?** UART expuesto suele brindar acceso directo al *bootloader* o a una consola `root` sin contraseña para manipular el sistema, mientras que JTAG o SWD activos sin fusibles de bloqueo permiten depurar la CPU en tiempo real, volcar la memoria flash protegida y extraer claves criptográficas desde la RAM.

## Antes de avanzar

::: nota Puerta de salida
Antes de continuar hacia redes industriales OT/ICS, verificá que puedas distinguir los riesgos de RFID LF/HF, explicar el rol de la IOMMU frente a ataques DMA, justificar el uso de TPM + PIN frente a *TPM sniffing* y describir el flujo de extracción pasiva con `binwalk`.
:::

## Referencias y estándares abiertos

- NIST SP 800-111 (*Guide to Storage Encryption Technologies for End User Devices*) y NIST SP 800-193 (*Platform Firmware Resiliency Guidelines*).
- Estándar ISO/IEC 14443 y arquitectura pública de seguridad MIFARE DESFire EV2/EV3 (NXP).
- OWASP IoT Security Verification Standard (ISVS) y Firmware Security Testing Methodology (FSTM).
- Documentación del kernel Linux sobre IOMMU/`udev`, proyecto `USBGuard` y guías Microsoft Learn sobre BitLocker y Kernel DMA Protection.
