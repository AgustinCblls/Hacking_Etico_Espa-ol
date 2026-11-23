::: nota Objetivo de la lección
Al completar este capítulo vas a poder diseñar y desplegar un laboratorio local completamente aislado mediante máquinas virtuales y contenedores Docker, redactar y verificar un marco de autorización legal (RoE), aplicar las fases de PTES y NIST SP 800-115 con enfoque colaborativo (Purple Team) y mantener una bitácora técnica reproducible respaldada por hashes `SHA-256`.
:::

**Prerrequisitos:** Conocimientos básicos de uso de sistema operativo (Windows, Linux o macOS) y familiaridad mínima con la terminal. **Duración sugerida:** 2 horas.

## Fundamentos de seguridad de la información y enfoque integral

La seguridad de la información protege activos digitales y procesos de negocio frente a accesos no autorizados, alteraciones indebidas o interrupciones de servicio. Todo análisis técnico riguroso parte de la **tríada CIA** y de una ecuación práctica de riesgo: un riesgo se materializa cuando una amenaza explota una vulnerabilidad sobre un activo con impacto medible.

| Propiedad | Definición operativa | Ejemplo de falla técnica | Control defensivo primario |
| :--- | :--- | :--- | :--- |
| **Confidencialidad** | Garantizar que solo entidades autorizadas lean la información. | Exposición de copias de seguridad o credenciales en texto claro. | Cifrado en tránsito (TLS), cifrado en reposo y control de acceso mínimo. |
| **Integridad** | Asegurar que datos, configuraciones y binarios no se modifiquen sin autorización. | Alteración de un script de despliegue o manipulación de registros de auditoría. | Firmas criptográficas, hashes `SHA-256` y registros inmutables. |
| **Disponibilidad** | Mantener sistemas y servicios operativos dentro de los acuerdos de nivel de servicio. | Agotamiento de descriptores de archivo o saturación de ancho de banda. | Redundancia, limitación de tasa (rate limiting) y respaldos verificados. |

En la práctica profesional, el trabajo se organiza en tres funciones complementarias:

- **Red Team (ofensivo):** simula adversarios realistas bajo alcance aprobado para descubrir rutas de ataque reales y medir la resiliencia organizacional.
- **Blue Team (defensivo):** diseña arquitectura segura, opera controles preventivos, analiza telemetría (logs, red, endpoints) y responde ante incidentes.
- **Purple Team (colaborativo):** integra ambos mundos en ciclos cortos. Cada técnica ejecutada por el lado ofensivo se valida de inmediato contra las alertas, reglas y registros del lado defensivo para cerrar brechas de visibilidad en lugar de entregar un informe estático semanas después.

::: aviso Mentalidad de ingeniería, no de recetas
Ejecutar herramientas sin entender qué paquetes salen por la red ni qué rastro dejan en el sistema destino produce falsos positivos y errores peligrosos. En este manual cada técnica ofensiva viene acompañada de su lectura defensiva y su verificación de telemetría.
:::

## Arquitectura del laboratorio local aislado

Toda práctica de hacking ético exige un entorno controlado donde un error de configuración nunca afecte redes domésticas, corporativas ni terceros en Internet. Un laboratorio bien diseñado separa el **host físico** (tu equipo principal), la **capa de virtualización o contenedores** y las **redes virtuales aisladas**.

### Hipervisores y snapshots

Un hipervisor **Tipo 1** (*bare-metal*, como **Hyper-V**, KVM/QEMU o VMware ESXi) se ejecuta directamente sobre el hardware físico o mediante un núcleo de hipervisión propio, mientras que un hipervisor **Tipo 2** (*hosted*, como VirtualBox o VMware Workstation Pro) corre como aplicación sobre tu sistema operativo anfitrión. Antes de instalar herramientas o modificar configuraciones críticas en una máquina virtual (VM), creá siempre un **snapshot limpio** (estado base): esto te permite revertir cualquier experimento fallido en segundos sin reinstalar el sistema.

### Topologías de red en hipervisores

La elección del adaptador de red virtual determina si tus máquinas vulnerables quedan expuestas a tu red local (LAN) o contenidas en un segmento privado.

| Modo de red | Acceso VM → VM | Acceso Host → VM | Acceso VM → Internet | Uso recomendado en laboratorio |
| :--- | :---: | :---: | :---: | :--- |
| **Host-Only** | Sí | Sí | No | Ideal para máquinas vulnerables y pruebas ofensivas controladas. |
| **Red Interna (Internal)** | Sí | No (requiere VM puente) | No | Máximo aislamiento para simular segmentos corporativos cerrados. |
| **NAT Network** | Sí | Solo con port-forwarding | Sí (saliente) | Apto para actualizar paquetes de una VM atacante; desactivar antes de probar objetivos vulnerables. |
| **Bridged (Puente)** | Sí | Sí | Sí (IP directa en LAN) | **Evitar** con sistemas vulnerables: expone la VM a toda la red física. |

::: peligro Regla de oro de aislamiento
Nunca conectes una máquina intencionalmente vulnerable en modo **Bridged** dentro de una red compartida, universitaria o corporativa. Usá exclusivamente redes **Host-Only**, redes internas o contenedores Docker ligados a `127.0.0.1`.
:::

### Contenedores locales con Docker

Para servicios web, bases de datos y microservicios de práctica, Docker consume una fracción de la memoria RAM que exige una VM completa. La seguridad de un entorno Docker local descansa en dos reglas de diseño:

1. Publicar puertos exclusivamente en la interfaz de loopback (`127.0.0.1:8080:80` y nunca `8080:80`, que escucha en `0.0.0.0`).
2. Declarar redes de puente internas (`internal: true`) cuando los contenedores no necesiten salida a Internet.

### VM atacante recomendada (Kali / Parrot), hardware y Git mínimo

Para la estación de trabajo ofensiva dentro del laboratorio aislado se suele usar **Kali Linux** o **Parrot Security OS** (edición Security). Requisitos orientativos para ejecutar cómodamente una VM atacante junto con 1 o 2 objetivos locales: **16 GB de RAM** (mínimo funcional 8 GB cerrando aplicaciones del host), **4 núcleos de CPU** y **50–60 GB de disco libre** con *snapshots* antes de cada laboratorio.

Asimismo, mantené tus scripts y notas bajo control de versiones con **Git mínimo** (excluyendo en `.gitignore` archivos `.pcap`, `.env`, claves privadas y volcados): `git status` (revisar cambios), `git add ruta/archivo` (preparar) y `git commit -m "nota técnica"` (registrar hito reproducible).

### Entornos heterogéneos y superficie física

Aunque la mayor parte del curso utiliza Linux y Windows, en evaluaciones reales vas a encontrar otros dos planos relevantes:

- **Estaciones macOS:** basadas en el núcleo Darwin (BSD/Mach), comparten herramientas POSIX (`zsh`, `ssh`, `lsof`, `pf` como firewall) pero incorporan controles propios como **System Integrity Protection (SIP)**, **Gatekeeper** (verificación de firma y notarización de aplicaciones), **TCC** (permisos granulares de privacidad) y el **Keychain** para credenciales. Si tu host físico es macOS, aplican las mismas reglas de aislamiento de red con UTM, VMware Fusion o Docker Desktop/Colima.
- **Superficie de hardware:** en auditorías de dispositivos embebidos o IoT con autorización explícita, el alcance puede incluir interfaces físicas de depuración como **UART** (consola serie), **SPI/I2C** (lectura de memoria flash externa), **JTAG/SWD** (depuración a nivel de CPU) o riesgos de periféricos USB no confiables (emulación de teclado HID y acceso directo a memoria DMA). En este tomo trabajamos exclusivamente sobre software y redes virtuales locales; la seguridad física y de hardware requiere equipamiento dedicado y permisos específicos.

## Marco legal, autorización y metodologías abiertas

La única línea que separa una auditoría profesional de un delito informático es la **autorización previa, explícita y por escrito** del titular legítimo de los activos. Ningún escaneo activo, prueba de credenciales ni explotación sobre sistemas ajenos está permitido sin contrato vigente.

### Reglas de Enfrentamiento (RoE)

Antes de enviar el primer paquete en un compromiso real, ambas partes firman un documento de **Rules of Engagement (RoE)** que fija:

- **Alcance estricto (In-Scope / Out-of-Scope):** rangos CIDR exactos, dominios, aplicaciones y exclusiones explícitas (por ejemplo, sistemas críticos de soporte vital o proveedores externos de terceros).
- **Ventanas horarias y restricciones técnicas:** horarios aprobados, límite de concurrencia para evitar denegación de servicio involuntaria y técnicas prohibidas (como ingeniería social o pruebas de estrés).
- **Contactos de emergencia y escalamiento:** canal seguro para reportar de inmediato hallazgos críticos o evidencia de una intrusión real ya existente.
- **Manejo de evidencias y confidencialidad:** cifrado de reportes, período de retención y destrucción segura tras el cierre.

### PTES y NIST SP 800-115

Las pruebas profesionales siguen estándares abiertos verificables para garantizar cobertura consistente y repetibilidad:

| Fase lógica | Estándar PTES | Estándar NIST SP 800-115 | Validación Purple Team asociada |
| :--- | :--- | :--- | :--- |
| **1. Preparación** | Interacciones previas al compromiso | Planificación | Definir hipótesis de ataque y fuentes de logs esperadas. |
| **2. Reconocimiento** | Recolección de inteligencia y modelado de amenazas | Descubrimiento (información) | Verificar si el perímetro detecta enumeración anómala. |
| **3. Análisis** | Análisis de vulnerabilidades | Descubrimiento (vulnerabilidades) | Contrastar hallazgos con el inventario real de parches. |
| **4. Validación** | Explotación y post-explotación | Ataque (acceso, escalamiento, pivote) | Comprobar alertas en SIEM/EDR y tiempos de detección. |
| **5. Cierre** | Reporte técnico y ejecutivo | Reporte y remediación | Entregar remediación priorizada y reglas de detección probadas. |

## Método de estudio activo y bitácora reproducible

Leer documentación sin ejecutar pruebas genera una falsa sensación de dominio. Para consolidar habilidades técnicas duraderas aplicá un ciclo de cuatro pasos por cada tema:

1. **Hipótesis previa:** antes de correr un comando, anticipá qué protocolo, archivo o proceso va a intervenir.
2. **Ejecución controlada:** corré el comando en tu laboratorio local y observá la salida completa (incluyendo códigos de retorno y errores).
3. **Verificación de rastro:** revisá los logs o paquetes capturados para confirmar qué quedó registrado.
4. **Registro en bitácora:** documentá fecha UTC, comando exacto, resultado resumido y hash criptográfico de cada evidencia guardada.

Preservar evidencias con `SHA-256` garantiza **integridad** y cadena de custodia: si un archivo de captura (`.pcap`), un log o una salida de escaneo se altera un solo bit, su resumen criptográfico cambia por completo.

## Ejemplo paso a paso: Laboratorio Docker aislado, consulta DNS local y bitácora SHA-256

En este ejemplo vas a trabajar con el archivo real [`laboratorios/docker-compose.yml`](../laboratorios/docker-compose.yml), verificar que los contenedores (`lab_local_web` y `lab_local_nginx` en la red `red_aislada_lab`) queden atados exclusivamente a `127.0.0.1`, ejecutar `laboratorios/dns_check_local.py` y sellar la evidencia con `SHA-256`.

### Paso 1: Revisar el laboratorio aislado (`laboratorios/docker-compose.yml`)

En `laboratorios/docker-compose.yml` definimos la red `red_aislada_lab` con `internal: false` (necesario en Docker bridge cuando se publican puertos locales en el host, ya que `internal: true` impide exponer puertos hacia loopback) combinada con **enlace estricto a `127.0.0.1`** (`127.0.0.1:8080:80` para `lab_local_nginx` y `127.0.0.1:5050:5050` para `lab_local_web`) para impedir cualquier acceso desde la LAN:

```yaml
services:
  app-educativa:
    image: python:3.12-slim
    container_name: lab_local_web
    working_dir: /app
    volumes:
      - ./app_lab_educativa.py:/app/app_lab_educativa.py:ro
    command: ["sh", "-c", "pip install --no-cache-dir flask && python /app/app_lab_educativa.py"]
    ports:
      - "127.0.0.1:5050:5050"
    networks:
      - red_aislada_lab
    restart: unless-stopped

  servidor-nginx:
    image: nginx:alpine
    container_name: lab_local_nginx
    ports:
      - "127.0.0.1:8080:80"
    networks:
      - red_aislada_lab
    restart: unless-stopped

networks:
  red_aislada_lab:
    driver: bridge
    internal: false
```

### Paso 2: Levantar los servicios y validar el aislamiento de red

```bash
# Levantamos los contenedores base en segundo plano
docker compose -f laboratorios/docker-compose.yml up -d

# Verificamos qué direcciones quedaron asociadas a los puertos publicados
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

Salida esperada comentada:

```text
NAMES             STATUS         PORTS
lab_local_web     Up 6 seconds   127.0.0.1:5050->5050/tcp
lab_local_nginx   Up 6 seconds   127.0.0.1:8080->80/tcp
# Confirmación crítica: el prefijo 127.0.0.1 garantiza que ningún equipo
# externo de tu LAN pueda alcanzar los puertos 5050 u 8080 de estos contenedores.
```

Comprobá además desde tu estación host que el puerto responde en loopback (`127.0.0.1:8080`) y verificá con `ss` / `netstat` que NO escucha en `0.0.0.0`:

```bash
curl -sI http://127.0.0.1:8080 | head -n 3
ss -tln | grep -E "5050|8080" || netstat -an | findstr "8080"
```

```text
HTTP/1.1 200 OK
Server: nginx/1.27.x
LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*
```

### Paso 3: Automatizar una consulta DNS controlada en laboratorio con Python

Para entender cómo funcionan los protocolos sin depender de cajas negras, escribí un script mínimo (`laboratorios/dns_check_local.py`) que resuelva únicamente nombres locales configurados en tu sistema o zona interna de laboratorio y registre la salida con marca temporal UTC:

```python
#!/usr/bin/env python3
"""Verificador básico de resolución de nombres para entorno de laboratorio local."""
import datetime
import socket

OBJETIVOS_LOCALES = ["localhost", "web-lab.local"]

ahora_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
print(f"[INFO] Inicio de prueba UTC: {ahora_utc}")

for nombre in OBJETIVOS_LOCALES:
    try:
        # getaddrinfo usa el resolvedor del SO (incluyendo /etc/hosts o DNS local)
        registros = socket.getaddrinfo(nombre, None, proto=socket.IPPROTO_TCP)
        ips = sorted({item[4][0] for item in registros})
        print(f"[OK]   {nombre} -> {', '.join(ips)}")
    except socket.gaierror as err:
        print(f"[MISS] {nombre} -> sin resolución ({err})")
```

### Paso 4: Ejecutar el script y sellar la evidencia con SHA-256

En Linux o macOS:

```bash
mkdir -p evidencias/cap1_1
python3 laboratorios/dns_check_local.py | tee evidencias/cap1_1/dns_local.log
sha256sum evidencias/cap1_1/dns_local.log > evidencias/cap1_1/manifest.sha256
sha256sum -c evidencias/cap1_1/manifest.sha256
```

Salida esperada comentada:

```text
[INFO] Inicio de prueba UTC: 2026-11-22T20:05:11.402198+00:00
[OK]   localhost -> 127.0.0.1, ::1
[MISS] web-lab.local -> sin resolución ([Errno -2] Name or service not known)
evidencias/cap1_1/dns_local.log: OK
# El estado "OK" prueba que el archivo no sufrió alteraciones desde su generación.
```

En Windows PowerShell podés generar exactamente el mismo sello de integridad con `Get-FileHash`:

```powershell
Get-FileHash -Path ".\evidencias\cap1_1\dns_local.log" -Algorithm SHA256 | Format-List
```

::: defensa Perspectiva defensiva y mitigación
Incluso en tu propia estación de trabajo, el laboratorio debe tratarse como una **zona no confiable**. Aplicá tres controles inmediatos:
1. **Aislamiento de red estricto:** mantené el firewall del host activo (`ufw`/`nftables` en Linux, Windows Defender Firewall en Windows, `pf` en macOS) y bloqueá tráfico entrante desde interfaces de laboratorio hacia servicios locales del host (SMB, RDP, SSH).
2. **Mínimo privilegio en contenedores y VMs:** evitá `--privileged`, usá `read_only: true` cuando sea viable y desactivá carpetas compartidas bidireccionales o portapapeles compartido cuando analices binarios desconocidos.
3. **Verificación Purple Team:** cada vez que corras una prueba en el laboratorio, revisá qué evento generó el servidor (`docker logs lab_local_nginx` / `docker logs lab_local_web`) para entrenar el ojo en la lectura de telemetría real desde el primer día.
:::

## Práctica en laboratorio local

1. Verificá que tenés instalado al menos un hipervisor (VirtualBox, VMware o Hyper-V) o Docker Engine funcional.
2. Creá la estructura de carpetas `laboratorios/` y `evidencias/cap1_1/` en tu directorio de estudio.
3. Desplegá `laboratorios/docker-compose.yml`, validá que el contenedor escucha únicamente en `127.0.0.1:8080` y confirmá la respuesta HTTP con `curl -I http://127.0.0.1:8080`.
4. Redactá una plantilla breve de **Rules of Engagement** ficticia (`evidencias/cap1_1/roe_laboratorio.md`) que defina tu rango de laboratorio local (por ejemplo `192.168.56.0/24` y `127.0.0.1`), exclusiones y formato de bitácora.
5. Ejecutá `dns_check_local.py`, generá el manifiesto `manifest.sha256` con todos los archivos creados y verificá la integridad con `sha256sum -c` o `Get-FileHash`.

::: practica Entregable mínimo
Al finalizar debés contar en `evidencias/cap1_1/` con:
- `roe_laboratorio.md`: documento de alcance y reglas de tu propio laboratorio local.
- `verificacion_red.txt`: salida de `docker ps` y `curl -I http://127.0.0.1:8080`.
- `dns_local.log`: salida del script de resolución local en Python.
- `manifest.sha256`: listado de hashes `SHA-256` verificado sin errores.
:::

## Preguntas de repaso

**1. ¿Por qué no se debe configurar una máquina virtual vulnerable en modo Bridged dentro de una red doméstica o corporativa?** Porque el modo Bridged asigna a la VM una dirección IP directamente en la misma subred física que el resto de los dispositivos de la LAN. Cualquier servicio vulnerable queda accesible para otros equipos de esa red y, si la VM resultara comprometida, serviría como punto de pivote directo contra la red anfitriona.

**2. ¿Qué diferencia operativa existe entre un ejercicio Red Team tradicional y un ciclo Purple Team?** En un ejercicio Red Team tradicional el equipo ofensivo opera de forma separada del defensivo y entrega sus hallazgos al finalizar el compromiso. En un ciclo Purple Team ambos equipos colaboran en tiempo real: cada técnica ejecutada se contrasta inmediatamente contra logs, alertas y reglas de detección para validar y mejorar la visibilidad defensiva sobre la marcha.

**3. ¿Cuál es la función de las opciones `127.0.0.1:8080:80` e `internal: true` en un archivo `docker-compose.yml` de laboratorio?** El mapeo `127.0.0.1:8080:80` restringe el puerto publicado exclusivamente a la interfaz loopback del host, impidiendo conexiones entrantes desde otras máquinas de la red. La directiva `internal: true` suprime la puerta de enlace por defecto del puente Docker para que el contenedor no pueda iniciar tráfico hacia Internet.

**4. ¿Qué elementos mínimos debe contener un documento de Rules of Engagement (RoE) antes de iniciar una prueba autorizada?** Debe incluir el alcance exacto de activos autorizados y excluidos (IPs, rangos CIDR, dominios), ventanas horarias permitidas, técnicas habilitadas y prohibidas, canales de escalamiento ante incidentes críticos, y criterios de confidencialidad y destrucción de evidencias, todo respaldado por firma de un representante legal autorizado.

**5. ¿Para qué sirve generar un archivo `manifest.sha256` al cerrar una sesión de laboratorio o auditoría?** Permite demostrar la integridad de las evidencias recolectadas (logs, capturas de red, salidas de comandos). Si un archivo se modifica accidental o maliciosamente después de la prueba, su hash `SHA-256` dejará de coincidir con el manifiesto original, preservando la trazabilidad y la cadena de custodia.

## Antes de avanzar

- [ ] Entendés la diferencia entre confidencialidad, integridad y disponibilidad, y el rol del enfoque Purple Team.
- [ ] Tenés un entorno aislado funcional (hipervisor con red Host-Only o Docker ligado a `127.0.0.1`) verificado sin exposición externa.
- [ ] Comprendés qué requisitos legales y de alcance (RoE) habilitan una prueba técnica legítima.
- [ ] Armaste tu estructura de bitácora y validaste la integridad de evidencias mediante `SHA-256`.

::: nota Puerta de salida
No pases al Capítulo 1.2 hasta haber levantado el contenedor aislado, comprobado el enlace exclusivo en `127.0.0.1` y verificado tu primer manifiesto `SHA-256`. Toda la práctica de redes que sigue se apoyará directamente sobre este laboratorio.
:::

## Referencias y estándares abiertos

- NIST Special Publication 800-115: *Technical Guide to Information Security Testing and Assessment* — https://csrc.nist.gov/publications/detail/sp/800-115/final
- PTES (Penetration Testing Execution Standard): *Technical Guidelines* — http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines
- RFC 1918: *Address Allocation for Private Internets* — https://datatracker.ietf.org/doc/html/rfc1918
- OWASP Web Security Testing Guide (WSTG v4.2): *Introduction and Testing Framework* — https://owasp.org/www-project-web-security-testing-guide/
- Docker Engine Documentation: *Networking overview and internal networks* — https://docs.docker.com/engine/network/
