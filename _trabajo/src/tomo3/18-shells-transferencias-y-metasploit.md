::: nota Objetivo de la lección
Al finalizar este capítulo vas a comprender el funcionamiento interno de las sesiones interactivas (TTY/PTY) frente a las no interactivas, la diferencia arquitectónica entre sesiones bind y reverse en redes segmentadas, los métodos verificables para transferir archivos en un laboratorio controlado, los fundamentos de memoria y arquitectura x86 detrás de las corrupciones de pila y el uso metódico de Metasploit como plataforma de auditoría documentada.
:::

**Prerrequisitos:** Conocimientos básicos de redes TCP/IP, línea de comandos en Linux y PowerShell, y laboratorio local aislado con máquinas virtuales propias (red Host-Only). **Duración sugerida:** 90 a 120 minutos.

## 1. Shells interactivas, no interactivas y asignación de PTY/TTY

En sistemas tipo Unix, una shell es un intérprete de comandos que se comunica con el núcleo mediante descriptores de archivo estándar: `stdin` (0), `stdout` (1) y `stderr` (2). La experiencia operativa y el comportamiento de los programas cambian según exista o no una terminal virtual asociada.

### Diferencias entre sesiones con y sin PTY

Cuando te conectás por SSH o abrís una consola local, el sistema asigna una pseudoterminal (PTY), compuesta por un extremo maestro y uno esclavo (`/dev/pts/N`). Esto habilita el control de trabajos (`Ctrl+C`, `Ctrl+Z`), el historial, el autocompletado y programas que requieren lectura directa de terminal como `sudo`, `su` o `less`. En contraste, una sesión canalizada únicamente por tuberías (pipes) o sockets sin PTY carece de disciplina de línea: las señales no se enrutan al proceso hijo y las utilidades interactivas fallan o exponen comportamiento errático.

| Característica | Shell no interactiva (pipe/socket) | Shell interactiva con PTY/TTY |
| --- | --- | --- |
| Dispositivo asociado | Ninguno (`not a tty`) | `/dev/pts/N` o `/dev/ttyN` |
| Manejo de señales (`SIGINT`) | Suele cerrar la sesión completa | Se entrega al proceso en primer plano |
| Programas como `sudo` o `vim` | Rechazan entrada o fallan al dibujar | Funcionan con control de eco y cursor |
| Trazabilidad en auditoría | Menor contexto de sesión interactiva | Registrada en `utmp`/`wtmp` y auditoría TTY |

Para inspeccionar el estado de tu terminal actual en una máquina Linux del laboratorio, ejecutá:

```bash
# Verificar si la sesión posee un dispositivo TTY asignado
tty

# Inspeccionar los parámetros de disciplina de línea (tamaño, señales, eco)
stty -a | head -n 3

# Confirmar la relación entre la terminal y el proceso actual
ps -o pid,ppid,tty,cmd -p $$
```

## 2. Arquitectura de sesiones bind vs. reverse en redes con firewall y NAT

En auditorías de laboratorio sobre topologías segmentadas, el sentido de inicio de la conexión TCP determina cómo interactúa la sesión con reglas de filtrado perimetral y traducción de direcciones (NAT).

### Comparativa arquitectónica

En un modelo **bind**, el sistema objetivo abre un puerto TCP en escucha y espera una conexión entrante desde la estación de administración. En un modelo **reverse**, el flujo se invierte: la conexión TCP se inicia desde el segmento interno hacia un puerto de escucha en la estación de control. Desde el punto de vista de ingeniería de redes, esta diferencia es crítica porque los firewalls corporativos suelen bloquear conexiones entrantes no solicitadas hacia subredes internas, mientras que el tráfico saliente (egress) suele estar menos restringido si no existe filtrado estricto por proxy o lista de permitidos.

| Dimensión | Sesión Bind (entrante) | Sesión Reverse (saliente) |
| --- | --- | --- |
| Quién inicia el handshake TCP | Estación de auditoría → objetivo | Objetivo → estación de auditoría |
| Impacto de firewall perimetral | Bloqueada por políticas default-deny entrantes | Depende del control de egress y proxy |
| Comportamiento tras NAT | Requiere reenvío de puertos explícito | Atraviesa NAT saliente como tráfico estándar |
| Superficie expuesta en el host | Deja un socket en estado `LISTEN` visible | Genera una conexión `ESTABLISHED` saliente |

::: aviso Uso exclusivo en redes aisladas
El análisis de conectividad saliente debe realizarse únicamente dentro de redes Host-Only o laboratorios propios sin salida a Internet. En entornos productivos, restringir el tráfico saliente (egress filtering) es uno de los controles más eficaces contra comunicaciones no autorizadas.
:::

## 3. Transferencias de archivos trazables e íntegras en laboratorio

Durante una auditoría técnica o una respuesta ante incidentes, suele ser necesario mover herramientas de diagnóstico, scripts de verificación o evidencias entre máquinas del laboratorio. Toda transferencia profesional debe ser **predecible, acotada en tiempo y verificada criptográficamente** mediante SHA-256.

### Métodos recomendados en Linux y Windows

1. **SCP sobre SSH:** Cifra el canal de extremo a extremo y reutiliza autenticación estándar, ideal entre nodos Linux y servidores Windows con OpenSSH.
2. **Servidor HTTP efímero local:** Útil en redes Host-Only para servir archivos de solo lectura durante pocos segundos, restringido a la interfaz del laboratorio.
3. **Codificación Base64 + verificación de hash:** Adecuada para archivos pequeños de texto o configuración cuando solo disponés de una consola interactiva.

| Método | Cifrado nativo | Requisito principal | Verificación recomendada |
| --- | --- | --- | --- |
| `scp` / `sftp` | Sí (SSH) | Servicio SSH activo | `sha256sum` / `Get-FileHash` |
| `python3 -m http.server` | No (HTTP plano) | Python 3 en origen y red local | Validar hash SHA-256 en destino |
| `base64` por consola | Depende del canal | Utilidad `base64` o PowerShell | Comparar digest origen vs. destino |

```bash
# Origen (Linux): calcular huella SHA-256 antes de transferir
sha256sum reporte_auditoria.txt

# Transferencia cifrada por SCP hacia un host del laboratorio
scp reporte_auditoria.txt auditor@192.168.56.20:/tmp/reporte_auditoria.txt

# Alternativa efímera acotada a la interfaz Host-Only (cerrar con Ctrl+C al terminar)
python3 -m http.server 8080 --bind 192.168.56.10
```

```powershell
# Destino (Windows PowerShell): descarga en red de laboratorio y control de integridad
Invoke-WebRequest -Uri "http://192.168.56.10:8080/reporte_auditoria.txt" -OutFile "C:\Lab\reporte_auditoria.txt"
Get-FileHash -Path "C:\Lab\reporte_auditoria.txt" -Algorithm SHA256
```

## 4. Fundamentos de ensamblador x86 y corrupciones de pila

Comprender cómo la CPU organiza la memoria permite entender por qué existen vulnerabilidades de corrupción de memoria tanto en Linux como en Windows x86 y cómo las mitigan los sistemas operativos modernos.

### Registros clave y marco de pila (Stack Frame)

En arquitectura x86 de 32 bits, la ejecución secuencial depende de registros de propósito general (`EAX`, `EBX`, `ECX`, `EDX`) y de control de pila:

- `ESP` (*Stack Pointer*): apunta a la cima actual de la pila (crece hacia direcciones menores).
- `EBP` (*Base Pointer*): marca la base del marco de la función en ejecución para referenciar variables locales y parámetros.
- `EIP` (*Instruction Pointer*): contiene la dirección de la próxima instrucción que ejecutará el procesador.

Cuando un programa en C/C++ copia datos de entrada a un búfer de tamaño fijo en la pila sin validar la longitud (por ejemplo, usando funciones inseguras en lugar de variantes acotadas), la escritura desborda el espacio reservado para variables locales y puede sobrescribir el `EBP` guardado y la dirección de retorno. Al ejecutarse la instrucción `RET`, el procesador carga esa dirección corrupta en `EIP`, provocando una caída del proceso o una alteración del flujo de control.

### Protecciones modernas contra corrupción de memoria

Los compiladores y sistemas operativos contemporáneos implementan defensas en profundidad que elevan drásticamente el costo de explotar errores de memoria:

| Mecanismo | Plataforma | Función protectora |
| --- | --- | --- |
| **Stack Canaries** (`-fstack-protector`, `/GS`) | Linux y Windows | Inserta un valor aleatorio antes de la dirección de retorno y aborta si se modifica |
| **NX / DEP** | Linux y Windows | Marca la pila y el heap como memoria no ejecutable |
| **ASLR** | Linux y Windows | Aleatoriza las direcciones base de pila, bibliotecas y ejecutables en cada ejecución |
| **SafeSEH / SEHOP** | Windows x86 | Verifica la integridad de los manejadores estructurados de excepciones |

## 5. Uso metódico y documentado de Metasploit Framework

Metasploit no debe utilizarse como una caja negra automatizada, sino como un entorno modular para validar configuraciones, ejecutar reconocimientos reproducibles y mantener trazabilidad completa de cada prueba autorizada.

### Arquitectura modular y disciplina de evidencia

- **Workspaces:** Aíslan resultados, hosts y servicios por proyecto o subred dentro de la base de datos PostgreSQL.
- **Módulos `auxiliary` y `scanner`:** Permiten verificar versiones, banners y configuraciones expuestas sin alterar la estabilidad del servicio.
- **Módulos `post`:** Orientados a inventario estructurado y recolección de evidencias dentro de sesiones autorizadas.
- **Registro con `spool`:** Guarda la salida íntegra de consola en un archivo de auditoría con marca temporal para respaldar el informe técnico.

```text
msf6 > workspace -a lab_tomo3
[*] Added workspace: lab_tomo3

msf6 > spool /home/auditor/evidencias/sesion_lab_tomo3.log
[*] Spooling to file /home/auditor/evidencias/sesion_lab_tomo3.log...

msf6 > search type:auxiliary name:ssh_version
msf6 > use auxiliary/scanner/ssh/ssh_version
msf6 auxiliary(scanner/ssh/ssh_version) > set RHOSTS 192.168.56.20
msf6 auxiliary(scanner/ssh/ssh_version) > show options
msf6 auxiliary(scanner/ssh/ssh_version) > run
```

## 6. Búsqueda, lectura crítica y adaptación de exploits públicos (`searchsploit` y compilación cruzada)

En certificaciones prácticas como **PEN-200 (OSCP)** —donde el uso de explotación automatizada con Metasploit suele restringirse— y en auditorías reales sobre software legado, no basta con lanzar módulos prefabricados: necesitás encontrar pruebas de concepto (**PoCs**) públicas, verificar que sean seguras antes de ejecutarlas y adaptarlas a la arquitectura real del objetivo en laboratorio.

### Búsqueda metódica con `searchsploit` y lectura crítica de PoCs

La base local de **Exploit-DB** se consulta offline con `searchsploit` cruzando producto y versión exacta obtenida durante la enumeración (Cap. 2.1):

```bash
# Buscar por nombre de servicio y versión (sin ruido externo)
searchsploit -t "Apache 2.4"

# Inspeccionar el código fuente completo de un PoC antes de copiarlo (ejemplo ID 12345)
searchsploit -x 12345

# Copiar el archivo al directorio de trabajo del laboratorio para revisarlo y adaptarlo
searchsploit -m 12345
```

::: peligro Regla de seguridad obligatoria antes de ejecutar un PoC público
Nunca compiles ni ejecutes a ciegas un script descargado de GitHub, blogs o Exploit-DB sin **leer línea por línea todo su código fuente**: han existido PoCs falsos con *backdoors* o comandos destructivos ocultos en llamadas `curl`, cadenas Base64 o funciones auxiliares. Verificá siempre qué IP contacta, qué archivos modifica y qué payload contiene, ejecutándolo únicamente en tu VM aislada con snapshot previo.
:::

### Adaptación de exploits públicos (*Fixing Exploits*) y compilación cruzada

Los scripts históricos rara vez funcionan a la primera sobre sistemas modernos o redes de laboratorio distintas a la del autor original. Los cuatro ajustes habituales en laboratorio son:

1. **Migración de Python 2 a Python 3:** muchos PoCs antiguos importan `urllib2` (reemplazar por `urllib.request`) o envían cadenas `str` directas por sockets (`sock.send("...")`), lo cual falla en Python 3 por exigir `bytes` (`b"..."` o `.encode("utf-8")`) y `requests` moderno.
2. **Parámetros hardcodeados de red y ruta:** revisar direcciones `127.0.0.1` o `10.10.x.x` escritas dentro del código, puertos HTTP frente a HTTPS (deshabilitar verificación de certificado autofirmado en lab cuando aplica o ajustar el esquema) y prefijos de directorio (`/app/` vs `/`).
3. **Ajuste de payload o comando de verificación:** reemplazar cualquier comando intrusivo del autor original por una prueba inocua y verificable en tu laboratorio (por ejemplo `id`, `whoami` o un ping/petición HTTP hacia tu propia interfaz Host-Only) para confirmar ejecución sin dañar el servicio.
4. **Compilación cruzada (*Cross-Compilation*) desde Linux hacia Windows o Linux x86:** si el PoC está escrito en C/C++, debés compilarlo apuntando a la arquitectura exacta del sistema destino (`file` / `uname -m` / `systeminfo`):

```bash
# Compilar en Linux un PoC en C para Windows 64 bits (enlazando sockets Winsock con -lws2_32)
x86_64-w64-mingw32-gcc poc_lab.c -o poc_win64.exe -lws2_32

# Compilar para Windows 32 bits en sistemas legados
i686-w64-mingw32-gcc poc_lab.c -o poc_win32.exe -lws2_32

# Compilar para Linux 32 bits o con bibliotecas estáticas (evita errores de GLIBC en hosts antiguos)
gcc -m32 -static poc_linux.c -o poc_linux32
```

## Ejemplo paso a paso: auditoría reproducible con verificación de integridad y registro

En este recorrido verificamos la conectividad de un servicio SSH local, transferimos un archivo de inventario entre dos VMs del laboratorio comprobando su integridad SHA-256 y documentamos la sesión.

```bash
# 1. Crear un archivo de inventario local en la VM origen (192.168.56.10)
uname -a > /tmp/inventario_vm.txt
sha256sum /tmp/inventario_vm.txt
# Salida esperada:
# 9c4b8e2f...  /tmp/inventario_vm.txt

# 2. Codificar a Base64 si se necesita auditar transferencia por texto plano
base64 /tmp/inventario_vm.txt > /tmp/inventario_vm.b64

# 3. Transferir por SCP hacia la VM destino (192.168.56.20)
scp /tmp/inventario_vm.b64 auditor@192.168.56.20:/tmp/

# 4. En la VM destino: decodificar y validar que el hash coincida exactamente
base64 -d /tmp/inventario_vm.b64 > /tmp/inventario_vm.txt
sha256sum /tmp/inventario_vm.txt
# Salida comentada: si el digest coincide carácter a carácter, no hubo corrupción ni alteración.
```

::: defensa Perspectiva defensiva, detección y mitigación
Desde la óptica de defensa y monitoreo (tácticas de alto nivel de MITRE ATT&CK como **Execution** y **Command and Control**), las sesiones anómalas, transferencias no autorizadas y escaneos modulares dejan rastros claros en los registros del host y de red:
- **Árbol de procesos anómalo:** Intérpretes de comandos o motores de scripting iniciados desde servicios de red o aplicaciones que normalmente no generan consolas interactivas.
- **Conexiones salientes inusuales:** Tráfico TCP desde servidores internos hacia puertos no estándar o estaciones fuera de la lista de destinos aprobados.
- **Mitigación directa:** Aplicar filtrado estricto de salida (egress), compilar binarios propios con ASLR, NX/DEP y stack canaries habilitados, y restringir herramientas de transferencia en servidores productivos a canales autenticados y auditados.
:::

## Práctica en laboratorio local

Configurá dos máquinas virtuales en una red Host-Only aislada (una estación de auditoría Linux y un servidor Linux o Windows de prueba):

1. Verificá tu entorno de terminal con `tty`, `stty -a` y `ps` dentro de una sesión SSH y comparalo con la salida obtenida al ejecutar un comando no interactivo por SSH (`ssh usuario@host tty`).
2. Transferí un archivo de prueba usando `scp` y luego mediante `python3 -m http.server` restringido a la IP de la red Host-Only, comprobando en ambos casos el hash SHA-256.
3. Inicializá un workspace dedicado en `msfconsole`, activá `spool` y ejecutá un módulo auxiliar de identificación de versión (`ssh_version` o `http_version`) únicamente contra tu VM de laboratorio.

::: practica Entregable mínimo
Un archivo de evidencia que incluya: captura de la salida de `tty` (interactiva vs. no interactiva), los digests SHA-256 coincidentes en origen y destino, y el extracto del log generado con `spool` mostrando el workspace utilizado.
:::

## Preguntas de repaso

**1. ¿Por qué ciertos comandos administrativos como `sudo` o editores de pantalla completa requieren una PTY para operar normalmente?** Porque dependen de la disciplina de línea y las llamadas de control de terminal que provee el dispositivo PTY para desactivar el eco de contraseñas, gestionar señales como `SIGINT` y conocer las dimensiones de la ventana.

**2. ¿Cuál es la diferencia fundamental entre una sesión bind y una sesión reverse frente a un firewall perimetral con NAT?** En una sesión bind el cliente inicia la conexión hacia un puerto abierto en el destino, lo cual suele ser bloqueado por políticas entrantes y NAT; en una sesión reverse el host interno origina la conexión saliente, atravesando NAT salvo que exista filtrado estricto de tráfico de salida.

**3. ¿Por qué es obligatorio verificar el hash SHA-256 tras transferir un archivo en una auditoría?** Porque garantiza integridad criptográfica, confirmando que el archivo recibido es idéntico bit a bit al original y no sufrió truncamientos, errores de codificación o alteraciones durante el tránsito.

**4. ¿Qué papel cumplen los mecanismos ASLR, DEP/NX y Stack Canaries frente a una corrupción de pila x86?** Actúan como defensas en profundidad: los canaries detectan la sobrescritura antes de retornar de la función, DEP/NX impide ejecutar instrucciones desde regiones de datos y ASLR dificulta predecir direcciones válidas en memoria.

**5. ¿Qué valor aporta trabajar con workspaces y `spool` dentro de Metasploit?** Permite segregar los hallazgos de distintos entornos evaluados y conservar una bitácora íntegra y auditable de cada módulo ejecutado, evitando mezclar evidencias y facilitando la reproducibilidad técnica.

## Antes de avanzar

- [ ] Diferenciás el comportamiento de una shell con PTY frente a una sesión sin terminal asignada.
- [ ] Comprendés cómo las políticas de firewall y NAT afectan el sentido de conexión TCP.
- [ ] Sabés transferir archivos de forma controlada en laboratorio y verificar su integridad con SHA-256.
- [ ] Identificás los registros básicos x86 y las principales defensas contra corrupción de memoria.
- [ ] Usás workspaces y registro de evidencias al ejecutar módulos auxiliares en Metasploit.

::: nota Puerta de salida
Antes de pasar al Capítulo 3.2, asegurate de haber cerrado cualquier servidor HTTP temporal que hayas levantado en tu laboratorio y de conservar tus evidencias organizadas por fecha y host.
:::

## Referencias y estándares abiertos

- NIST SP 800-115: *Technical Guide to Information Security Testing and Assessment* (https://csrc.nist.gov/publications/detail/sp/800-115/final)
- MITRE ATT&CK Enterprise Matrix: tácticas *Execution* y *Command and Control* (https://attack.mitre.org/)
- Linux man-pages: `pty(7)`, `stty(1)`, `scp(1)`, `sha256sum(1)` (https://man7.org/linux/man-pages/)
- Microsoft Learn: *Data Execution Prevention (DEP) y mitigaciones de memoria en Windows* (https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention)
- Rapid7 Metasploit Framework Documentation: *Managing Workspaces and Auxiliary Modules* (https://docs.metasploit.com/)
