::: nota Objetivo de la lección
Al completar este capítulo vas a poder planificar una fase de reconocimiento autorizada, diferenciar técnicas pasivas de activas, inventariar servicios en un laboratorio local con Nmap de forma controlada y priorizar hallazgos combinando criterios de severidad, probabilidad y causa raíz.
:::

**Prerrequisitos:** Manejo básico de terminal Linux/PowerShell, modelo TCP/IP (puertos, handshake de tres vías y DNS) y laboratorio local aislado en funcionamiento. **Duración sugerida:** 2 a 3 horas.

## Metodología de pruebas autorizadas y mentalidad analítica

Toda evaluación técnica seria comienza con un alcance formalmente autorizado (*Rules of Engagement*). El marco **NIST SP 800-115** divide el proceso en cuatro etapas: planificación, descubrimiento, validación controlada e informe de remediación. Antes de ejecutar cualquier comando, definí qué activos están dentro del alcance, qué ventanas horarias rigen y qué acciones están expresamente excluidas para evitar interrupciones operativas.

Adoptar una mentalidad orientada a amenazas (*threat-informed*) implica ir más allá de tildar listas de control: buscás entender cómo interactúan los activos expuestos, los controles preventivos y la telemetría defensiva. En una planificación moderna de superficie de ataque, conviene contemplar tanto los servicios de red tradicionales como vectores adyacentes que suelen quedar fuera de foco:

- **Cadena de suministro de software (*Supply Chain*):** dependencias externas, imágenes base de contenedores y paquetes de terceros pueden introducir debilidades sin modificar una sola línea de código propio. Mantener un inventario SBOM (*Software Bill of Materials*) y verificar firmas criptográficas es parte del reconocimiento defensivo.
- **Equipos de borde y *Shadow IT* expuesto:** concentradores VPN, gateways, servidores de correo y subdominios olvidados (*dangling DNS*) suelen constituir la primera superficie real detectada desde el exterior antes de alcanzar la red interna.

## Reconocimiento pasivo y footprinting corporativo

El reconocimiento pasivo recopila información pública y registros abiertos sin enviar paquetes exploratorios directos hacia los sistemas objetivo. Su propósito es mapear la huella externa de una organización (*footprinting*) y detectar activos olvidados, configuraciones DNS incompletas o exposición innecesaria de infraestructura.

| Fuente pasiva | Protocolo o registro | Qué revela en una auditoría | Utilidad defensiva |
| :--- | :--- | :--- | :--- |
| **DNS público y subdominios pasivos** | A, AAAA, MX, NS, TXT + fuentes pasivas (`subfinder`, `amass -passive`) | Servidores de correo, proveedores cloud y subdominios conocidos sin tocar el objetivo | Detectar registros huérfanos (*dangling DNS*) y activos sombra |
| **Transparencia de Certificados (CT)** | Logs públicos RFC 6962 (`crt.sh`) | Subdominios con certificados TLS emitidos históricamente | Descubrir entornos de pruebas expuestos por error |
| **Buscadores de activos expuestos** | Indexadores pasivos (**Shodan**, **Censys**, **FOFA**) | Puertos abiertos, banners, versiones, certificados SSL y paneles expuestos a Internet | Auditar qué ve Internet de tu perímetro antes de que un atacante lo aproveche |
| **Archivos históricos web** | **Wayback Machine** / **Common Crawl** (`waybackurls`, `gau`) | Endpoints retirados, rutas administrativas olvidadas, `.bak` y parámetros legados | Retirar de producción rutas antiguas y rotar secretos expuestos históricamente |
| **RDAP / WHOIS** | HTTP/JSON (RFC 7480) | Bloques ASN, rangos IP asignados y fechas de vencimiento | Validar propiedad de activos y contactos de abuso |
| **Autenticación de correo** | Registros TXT (SPF, DMARC, DKIM) | Política frente a suplantación de dominio y terceros autorizados | Endurecer entregas y reducir riesgo de *phishing* |

*(Nota: en el Capítulo 2.8 integraremos estas fuentes pasivas dentro del flujo estructurado de *Bug Bounty* y validación de alcance continuo).*

### Consultas DNS y verificación de postura de correo

Podés inspeccionar registros DNS y políticas SPF/DMARC con herramientas estándar como `dig` sin interactuar con los puertos de aplicación del objetivo:

```bash
# Consultar registros de intercambio de correo y políticas TXT de un dominio de ejemplo
dig +short MX example.com
dig +short TXT example.com
dig +short TXT _dmarc.example.com
```

Un registro SPF terminado en `-all` indica rechazo estricto de emisores no listados, mientras que una política DMARC en `p=reject` (o `p=quarantine` durante la transición) protege la reputación del dominio. Documentar hallazgos pasivos permite construir un inventario inicial antes de pasar al entorno de laboratorio.

::: aviso Límite legal y ético
Ejecutá únicamente consultas pasivas sobre dominios autorizados o dominios reservados para documentación (`example.com`, RFC 2606). Todo escaneo activo de puertos y servicios debe realizarse estrictamente contra tu propio laboratorio local (`127.0.0.1` o red privada aislada de VMs).
:::

## Enumeración activa en laboratorio con Nmap

Cuando ya contás con autorización explícita en tu red de pruebas, **Nmap** permite descubrir equipos activos, identificar puertos abiertos, inferir versiones de servicios y validar configuraciones mediante scripts del motor NSE (*Nmap Scripting Engine*).

### Tipos de escaneo, temporización y formatos de salida

Elegir la técnica adecuada reduce el ruido en la red y mejora la precisión de los resultados:

| Opción Nmap | Mecanismo técnico | Privilegios | Uso recomendado en laboratorio |
| :--- | :--- | :--- | :--- |
| `-sn` | Descubrimiento de hosts sin escaneo de puertos | Usuario / Root | Mapear VMs activas en la subred local |
| `-sS` | Escaneo TCP SYN (*half-open*, no completa handshake) | Root / Admin | Rápido y limpio para inventariar puertos TCP |
| `-sT` | Escaneo TCP Connect (usa syscall `connect()` del SO) | Usuario normal | Alternativa sin privilegios elevados |
| `-sU` | Escaneo UDP (evalúa respuestas ICMP *port unreachable*) | Root / Admin | Verificar DNS (53), NTP (123) o SNMP (161) en rangos acotados |
| `-sV` | Sondas de protocolo para identificar servicio y versión | Usuario / Root | Correlacionar banners con versiones instaladas |
| `-sC` | Ejecuta scripts NSE de la categoría `default` (seguros) | Usuario / Root | Obtener metadatos TLS, cabeceras HTTP o banners estándar |
| `-O` | Huella de pila TCP/IP para estimar sistema operativo | Root / Admin | Validar homogeneidad del parque de VMs |
| `-Pn` | Omite el descubrimiento previo (*host discovery* / ping) y asume el host vivo | Usuario / Root | Indispensable cuando un firewall filtra ICMP/sondas iniciales |
| `-p-` | Escanea el rango completo de los `65.535` puertos TCP (`1-65535`) | Usuario / Root | Inventario real: evita omitir servicios en puertos altos (`8080`, `9200`, etc.) |
| `--open` | Filtra la salida para mostrar solo puertos `open` | Usuario / Root | Reduce ruido en reportes sobre segmentos con miles de puertos |
| `-oA base` | Guarda simultáneamente `.nmap`, `.xml` y `.gnmap` | Usuario / Root | Preservar evidencia reproducible para informes |

**Control de velocidad y precisión en inventario real:** las plantillas de temporización van de `-T0` (muy lento/evasivo) a `-T5` (agresivo). En producción o laboratorio realista, combiná `-Pn -p-` con `-T3` o `-T4` y parámetros explícitos de ritmo como `--min-rate 300 --max-retries 2` (o `--scan-delay` en equipos sensibles OT/legacy) para completar inventarios extensos sin saturar enlaces ni provocar pérdida de respuestas (*drops*). Recordá que las tasas altas aumentan la visibilidad inmediata en alertas IDS/IPS y firewalls perimetrales.

### Uso responsable del motor NSE

Los scripts NSE se agrupan por categorías como `safe`, `discovery`, `version`, `vuln` e `intrusive`. Para evaluaciones iniciales y verificaciones defensivas, limitate a `safe` y `default`, revisando previamente qué hace cada script con `--script-help`:

```bash
# Inspeccionar la documentación de un script NSE antes de ejecutarlo
nmap --script-help http-headers,ssl-cert

# Ejecutar únicamente scripts informativos y seguros contra un servicio local
nmap -sT -sV --script="http-headers,http-title" -p 5050 127.0.0.1
```

## Evaluación y priorización de vulnerabilidades

Identificar un servicio expuesto o una versión desactualizada no alcanza: necesitás priorizar qué corregir primero. Para evitar decisiones basadas solo en intuición, combiná cuatro piezas complementarias:

1. **CVSS (v3.1 y v4.0):** estima la severidad técnica según la facilidad de acceso, los privilegios requeridos y el impacto sobre confidencialidad, integridad y disponibilidad. La versión 4.0 incorpora métricas suplementarias y una mejor contextualización ambiental, pero sigue siendo una medida de severidad teórica, no de probabilidad real.
2. **EPSS (*Exploit Prediction Scoring System*):** estima la probabilidad porcentual de que una vulnerabilidad catalogada sea observada en actividad hostil durante los próximos 30 días. Permite diferenciar fallos críticos con alta exposición real de fallos severos en papel pero raramente abusados.
3. **CISA KEV y árbol SSVC:** el catálogo **CISA KEV (*Known Exploited Vulnerabilities*)** confirma si un CVE ya tiene explotación activa observada en el mundo real; combinado con **SSVC (*Stakeholder-Specific Vulnerability Categorization*)**, permite decidir objetivamente entre **Act** (parcheo urgente inmediato), **Attend**, **Track\*** o **Track**.
4. **CWE (*Common Weakness Enumeration*):** clasifica la causa raíz del defecto en familias estructurales —como *Validación de Entrada* o *Exposición de Información Sensible*— para corregir patrones arquitectónicos completos y no solo síntomas aislados.

| Prioridad | Severidad (CVSS) | Probabilidad (EPSS) / KEV | Exposición del activo | Acción recomendada (SSVC) |
| :--- | :--- | :--- | :--- | :--- |
| **Crítica (P1)** | Alta / Crítica | Elevada o presente en **CISA KEV** | Expuesto a red externa (o *edge device*) | **Act:** remediación inmediata y verificación |
| **Alta (P2)** | Alta / Crítica | Baja (sin KEV) | Red interna segmentada | **Attend:** planificar parcheo en el ciclo corto |
| **Media (P3)** | Media | Moderada | Servicio interno autenticado | **Track\*:** mitigar por configuración y monitorear |
| **Baja (P4)** | Baja / Informativa | Muy baja | Laboratorio o entorno aislado | **Track:** documentar en inventario de deuda técnica |

::: aviso Superficie crítica 2024–2026: dispositivos perimetrales (*Edge Devices*)
En incidentes reales de 2024–2026, los **dispositivos de borde (*edge devices*)** —firewalls SSL-VPN, gateways de acceso remoto y balanceadores de fabricantes como **Fortinet, Ivanti, Citrix y Palo Alto**— concentraron el vector principal de acceso inicial corporativo. Al operar expuestos 24/7 sin agentes EDR tradicionales dentro del firmware, cualquier CVE incluido en **CISA KEV** sobre estos equipos debe tratarse con prioridad **Act (P1)** y aislamiento inmediato de interfaces de gestión.
:::

## 4. OSINT corporativo y seguridad de la Cadena de Suministro (*Supply Chain*)

En una auditoría realista o ejercicio de Red Team autorizado, la superficie de una organización supera sus servidores web directos: abarca **registros públicos (OSINT)** y **dependencias externas (*Supply Chain*)**:

- **OSINT Corporativo estructurado:**
  - *Infraestructura pública:* bloques ASN/BGP, registros WHOIS, registros DNS (`MX`, `TXT` SPF que revelan proveedores SaaS), y logs públicos de **Certificate Transparency (CT)** (`crt.sh`) para descubrir subdominios emitidos.
  - *Registros organizacionales y exposición inadvertida:* metadatos olvidados en documentos públicos (autoría, rutas internas), repositorios públicos de código de empleados (donde jamás deben subirse claves API ni archivos `.env`) y exposición involuntaria de detalles tecnológicos en ofertas laborales.
- **Ataques y riesgos en la Cadena de Suministro (*Supply Chain Attacks*):**
  - *Dependencias de software:* paquetes comprometidos en registros públicos (`npm`, `PyPI`), *typosquatting* de librerías y **confusión de dependencias** (*Dependency Confusion*: cuando un gestor instala un paquete público homónimo en lugar del paquete interno privado).
  - *Actualizaciones firmadas y CI/CD:* el incidente de SolarWinds mostró cómo comprometer el servidor de compilación permite distribuir código malicioso firmado legítimamente. **Mitigación:** fijar hashes criptográficos en *lockfiles* (`requirements.txt --require-hashes`, `package-lock.json`), generar **SBOM** (*Software Bill of Materials*), verificar firmas digitales con **Sigstore/Cosign** y aislar corredores de CI/CD.

## Ejemplo paso a paso: inventario controlado en laboratorio local

En este recorrido vas a iniciar la aplicación educativa local incluida en `laboratorios/app_lab_educativa.py` (puerto `5050` en `127.0.0.1`) y levantar un inventario técnico reproducible con Nmap.

### Paso 1: levantar el servicio de laboratorio

En una terminal aislada, ejecutá la aplicación didáctica:

```bash
python3 laboratorios/app_lab_educativa.py
```

```text
 * Serving Flask app 'app_lab_educativa'
 * Debug mode: off
 * Running on http://127.0.0.1:5050
```

### Paso 2: escaneo focalizado con detección de versión y registro en archivo

Desde una segunda terminal, ejecutá un escaneo TCP Connect (`-sT`) sin privilegios, solicitando identificación de versión (`-sV`), cabeceras HTTP seguras y guardado en los tres formatos (`-oA`):

```bash
nmap -sT -sV -T4 --script="http-title,http-headers" -p 5050,8000 -oA evidencia_lab_local 127.0.0.1
```

Salida esperada comentada:

```text
Starting Nmap 7.95 ( https://nmap.org )
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00018s latency).

PORT     STATE  SERVICE VERSION
5050/tcp open   http    Werkzeug httpd 3.0.x (Python 3.12)
|_http-title: Lab Web Local
| http-headers:
|   Server: Werkzeug/3.0.x Python/3.12
|   Content-Type: text/html; charset=utf-8
|_  Connection: close
8000/tcp closed http-alt

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 6.42 seconds
```

### Paso 3: análisis técnico del hallazgo

Observá tres detalles clave en la salida:

- El puerto `5050/tcp` figura `open` y expone la cabecera `Server: Werkzeug/3.0.x Python/3.12`. En producción, un servidor de desarrollo como Werkzeug nunca debe exponerse directamente; se despliega detrás de un servidor WSGI (como Gunicorn) y un proxy inverso que oculte detalles internos.
- El puerto `8000/tcp` aparece `closed`, lo cual confirma conectividad TCP (el host respondió `RST`) sin servicio escuchando.
- Los archivos `evidencia_lab_local.nmap`, `evidencia_lab_local.xml` y `evidencia_lab_local.gnmap` quedan listos para auditar cambios futuros mediante `ndiff`.

::: defensa Perspectiva defensiva y mitigación
Para reducir la superficie descubrible en entornos reales, aplicá estas medidas estructurales:
- **Principio de mínima exposición:** cerrá puertos administrativos en interfaces públicas y aislá servicios internos mediante firewall basado en listas blancas.
- **Higiene de metadatos:** deshabilitá banners detallados en proxies inversos, revisá registros DNS periódicamente y aplicá SPF/DMARC estrictos.
- **Gestión continua de activos y dependencias:** contrastá escaneos internos autorizados contra tu inventario oficial y mantené un SBOM actualizado para detectar componentes vulnerables de terceros antes de su explotación.
- **Detección en red:** monitoreá patrones anómalos de conexión secuencial hacia múltiples puertos desde un mismo origen en logs de firewall o sistemas IDS/IPS para identificar actividad de reconocimiento no autorizada.
:::

## Práctica en laboratorio local

Ejecutá `laboratorios/app_lab_educativa.py` en tu entorno local y realizá un inventario estructurado de tus servicios de prueba siguiendo buenas prácticas de evidencia:

1. Verificá con `ss -tulpn` (Linux) o `Get-NetTCPConnection -State Listen` (PowerShell) qué puertos locales están escuchando realmente en `127.0.0.1`.
2. Corré un escaneo Nmap controlado sobre `127.0.0.1` en el rango `5000-5100` con `-sT -sV -oA lab_inventario`.
3. Compará la salida de Nmap contra la lista obtenida desde el sistema operativo y clasificá cada hallazgo usando la matriz de priorización (severidad, exposición y causa raíz CWE).

::: practica Entregable mínimo
Un archivo `reporte_recon_lab.md` de una página que contenga:
1. Tabla con los servicios detectados en `127.0.0.1` (puerto, estado, versión observada y proceso real asociado).
2. Diferencia entre dos hallazgos priorizados (por ejemplo, exposición de banner de servidor de desarrollo vs. puerto cerrado esperado).
3. Tres recomendaciones concretas de endurecimiento aplicables antes de pasar el servicio a producción.
:::

## Preguntas de repaso

**1. ¿Por qué el reconocimiento pasivo precede siempre al escaneo activo en una auditoría profesional?** Porque permite mapear la huella pública, los rangos autorizados y los servicios expuestos sin generar tráfico exploratorio ni riesgo operativo sobre la infraestructura objetivo, mejorando la precisión del alcance antes de cualquier prueba activa.

**2. ¿Qué diferencia técnica existe entre un escaneo Nmap `-sS` y un escaneo `-sT`?** El escaneo `-sS` envía paquetes SYN y analiza respuestas SYN-ACK o RST sin completar el handshake TCP de tres vías (requiere privilegios elevados para paquetes crudos), mientras que `-sT` utiliza la llamada estándar `connect()` del sistema operativo completando la conexión y funciona sin privilegios de administrador.

**3. ¿Por qué no conviene priorizar vulnerabilidades basándose únicamente en la puntuación CVSS base?** Porque CVSS base mide severidad técnica en abstracto, sin reflejar si el activo está expuesto en red ni qué probabilidad real existe de explotación activa; combinarlo con EPSS, contexto ambiental y causa raíz CWE evita desperdiciar esfuerzo en hallazgos de bajo riesgo efectivo.

**4. ¿Qué aporta el formato `-oA` al ejecutar Nmap en una evaluación formal?** Genera simultáneamente salida legible para revisión humana (`.nmap`), salida estructurada para herramientas o comparación diferencial con `ndiff` (`.xml`) y salida apta para filtrado rápido en consola (`.gnmap`), asegurando trazabilidad y reproducibilidad.

**5. ¿Qué enseñanza arquitectónica comparten el fallo histórico de WEP y la manipulación de memoria en clientes locales?** Ambos demuestran que la seguridad nunca puede descansar en suposiciones frágiles ni en controles exclusivos del extremo no confiable: los protocolos criptográficos deben cumplir garantías modernas probadas y toda regla de negocio crítica debe validarse siempre en el servidor.

## Antes de avanzar

- [ ] Diferencio con claridad reconocimiento pasivo (DNS, CT, RDAP, SPF/DMARC) de enumeración activa en laboratorio.
- [ ] Sé seleccionar opciones seguras de Nmap (`-sT`, `-sS`, `-sV`, `-sC`, `-oA`) e interpretar estados `open`, `closed` y `filtered`.
- [ ] Puedo justificar la prioridad de un hallazgo combinando CVSS, EPSS, exposición real y categoría CWE.
- [ ] Generé y verifiqué el entregable local sobre `127.0.0.1` sin ejecutar escaneos contra terceros.

::: nota Puerta de salida
Cuando puedas inventariar tu servicio local en `127.0.0.1`, explicar cada línea de la salida de Nmap y clasificar tus hallazgos con criterios reproducibles, estás listo para pasar al **Capítulo 2.2: Enumeración web, fuzzing con ffuf y análisis de JavaScript**.
:::

## Referencias y estándares abiertos

- NIST Special Publication 800-115: *Technical Guide to Information Security Testing and Assessment* (https://csrc.nist.gov/pubs/sp/800/115/final)
- Nmap Reference Guide — *Port Scanning Techniques & Nmap Scripting Engine* (https://nmap.org/book/man.html)
- FIRST — *Common Vulnerability Scoring System (CVSS v3.1 / v4.0)* y *Exploit Prediction Scoring System (EPSS)* (https://www.first.org/cvss/ y https://www.first.org/epss/)
- IETF RFC 7208 (*Sender Policy Framework*), RFC 7489 (*DMARC*) y RFC 6962 (*Certificate Transparency*)
- MITRE CWE — *Common Weakness Enumeration* (https://cwe.mitre.org/)
