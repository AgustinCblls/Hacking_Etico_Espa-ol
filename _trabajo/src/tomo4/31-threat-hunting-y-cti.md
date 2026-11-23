::: nota Objetivo de la lección
Al finalizar este capítulo vas a saber diseñar y ejecutar sesiones completas de **Threat Hunting proactivo** guiado por hipótesis (apilamiento estadístico de frecuencias, caza de LOLBins, detección de anomalías en redes, web y Active Directory), operacionalizar la inteligencia de amenazas (**CTI**) con estándares abiertos STIX/TAXII y la Pirámide del Dolor, y realizar el análisis técnico seguro de correos de **phishing** (`Received`, SPF, DKIM, DMARC y adjuntos) utilizando las muestras incluidas en `laboratorios/muestras/`.
:::

**Prerrequisitos:** Capítulos 4.1 a 4.5 (Operaciones SOC, Telemetría Sysmon/auditd, SIEM, NSM y reglas Sigma/YARA). **Duración sugerida:** 8 a 10 horas.

## 1. Threat Hunting proactivo guiado por hipótesis

Mientras el monitoreo tradicional L1/L2 reacciona a alertas conocidas generadas por reglas estáticas del SIEM o IDS, el **Threat Hunting** parte de la premisa operativa de que una técnica nueva o un uso sigiloso de herramientas legítimas del sistema puede estar ocurriendo sin haber disparado alertas previas.

Para evitar búsquedas improvisadas sin rumbo, toda campaña de caza sigue un ciclo estructurado en cuatro pasos:

```text
[1. Formulación de Hipótesis]  ──►  [2. Recolección y Análisis (SIEM/EDR/NSM)]
            ▲                                        │
            │                                        ▼
[4. Regla Permanente (Sigma/SPL)] ◄── [3. Hallazgo y Validación / Patrón]
```

### De dónde nacen las hipótesis de caza

Una hipótesis verificable combina tres fuentes:
1. **Inteligencia sobre amenazas (CTI):** TTPs observados en campañas recientes contra el sector (por ejemplo, ejecución de utilidades administrativas para descarga o abuso de herramientas remotas legítimas).
2. **Conocimiento de la propia arquitectura:** qué activos críticos existen (Controladores de Dominio en Tier 0, servidores expuestos, portales web) y qué actividad es normal en ellos (*baseline*).
3. **Anomalías estadísticas en telemetría:** eventos de muy baja frecuencia o combinaciones atípicas de proceso padre → hijo.

### Tres técnicas fundamentales de hunting

1. **Apilamiento de frecuencias (*Stacking / Least Frequency of Occurrence*):** agrupar eventos por campo (`ParentImage` + `Image`, `User-Agent`, dominio DNS consultado, puerto destino) y ordenarlos **de menor a mayor ocurrencia**. En una flota de 500 estaciones, lo legítimo ocurre miles de veces al día; lo anómalo suele aparecer con frecuencia `1`, `2` o `3`.
2. **Detección de LOLBins (*Living-off-the-Land Binaries*):** buscar ejecuciones de binarios firmados del sistema operativo (`certutil.exe`, `mshta.exe`, `rundll32.exe`, `bitsadmin.exe`, `curl`, `python`) con parámetros de red o lanzados desde rutas no habituales (`C:\Users\Public\`, `%TEMP%`, `/tmp/`).
3. **Caza de persistencia y movimientos atípicos:** revisar periódicamente tareas programadas fuera de ventanas de mantenimiento, servicios nuevos (`7045` / Sysmon `1`), claves `Run` (Sysmon `13`) y consultas DNS o conexiones HTTP periódicas (*beaconing*).

### Matriz de caza transversal: Endpoint, Web, Red y Active Directory

| Superficie monitoreada | Hipótesis concreta de hunting | Consulta o señal clave a buscar |
|---|---|---|
| **Servidores Web y APIs** | *"Un proceso del servidor web generó una shell hija o consultó recursos internos."* | Sysmon `1` / `auditd` buscando `w3wp.exe`, `nginx`, `apache2`, `gunicorn` o `node` como `ParentImage` lanzando `sh`, `bash`, `cmd.exe` o `powershell.exe`. |
| **Active Directory (Tier 0)** | *"Una estación de usuario estándar está realizando enumeración LDAP masiva o solicitando múltiples TGS en segundos."* | Controlador de Dominio Event ID `4769` con cifrado RC4 (`0x17`), Event ID `1644` (consultas LDAP costosas) o acceso no habitual de soporte a servidores críticos. |
| **Red y DNS (NSM)** | *"Un equipo interno mantiene comunicación periódica con dominios recién registrados o realiza túneles DNS."* | Zeek `dns.log` ordenando dominios por longitud máxima de subdominio y cantidad de consultas `TXT` o `NULL`, y `conn.log` buscando intervalos constantes entre paquetes. |
| **Estaciones de trabajo** | *"Un documento ofimático o cliente de correo lanzó un intérprete de comandos."* | Sysmon `1` donde `ParentImage` sea `winword.exe`, `excel.exe`, `outlook.exe` o `acrord32.exe` con hijo `cmd.exe`, `powershell.exe` o `wscript.exe`. |

## 2. Inteligencia de amenazas (CTI), Pirámide del Dolor y STIX/TAXII

La **Inteligencia de Amenazas (*Cyber Threat Intelligence*, CTI)** contextualiza qué amenazas son relevantes para la organización, evitando perseguir listas genéricas de miles de direcciones IP caducadas.

| Nivel de CTI | Audiencia principal | Qué responde | Horizonte de vida |
|---|---|---|---|
| **Estratégico** | CISO, Dirección y Comité de Riesgo | Tendencias geopolíticas/sectoriales, riesgos de negocio e impacto financiero para priorizar presupuesto. | Meses a años |
| **Operacional** | Responsables de SOC, IR y Defensa | Campañas activas, vectores iniciales más usados y capacidades reales de grupos que apuntan al sector. | Semanas a meses |
| **Táctico y Técnico** | Analistas SOC, Hunters y Detection Engineers | TTPs mapeados a MITRE ATT&CK, reglas Sigma/YARA y artefactos observables (hashes, dominios, rutas). | Horas a semanas |

### Prioridad de detección, plataformas CTI (`MISP` / `OpenCTI`) y protocolo `TLP 2.0`

Recordá siempre la **Pirámide del Dolor** (Cap. 4.5): bloquear un hash SHA-256 o una IP es sencillo pero efímero; cazar **TTPs** (comportamientos padre-hijo y abusos de protocolo) tiene impacto duradero. Para intercambiar y operacionalizar inteligencia de forma estructurada se utilizan los estándares abiertos de OASIS junto con plataformas abiertas de referencia:
- **STIX 2.1 (*Structured Threat Information Expression*):** formato JSON estandarizado que describe objetos (`indicator`, `threat-actor`, `malware`, `attack-pattern`) y sus relaciones.
- **TAXII 2.1 (*Trusted Automated Exchange of Intelligence Information*):** protocolo REST sobre HTTPS para publicar y consumir colecciones STIX automáticamente.
- **MISP (*Malware Information Sharing Platform*):** plataforma colaborativa centrada en compartir **eventos e indicadores (IOCs)**, correlacionar atributos repetidos entre incidentes de distintas organizaciones, enriquecer con taxonomías y exportar automáticamente listas hacia Suricata, Zeek, SIEM o firewalls.
- **OpenCTI:** plataforma basada en grafo de conocimiento **STIX 2.1** orientada a conectar **amenazas estratégicas/operacionales con TTPs de MITRE ATT&CK**, campañas, herramientas y fuentes externas (incluyendo conectores con MISP y feeds abiertos).

Para intercambiar inteligencia sin exponer investigaciones confidenciales, toda pieza compartida en MISP, OpenCTI o TheHive debe etiquetarse con **TLP 2.0 (*Traffic Light Protocol*, estándar FIRST)**:

| Etiqueta TLP 2.0 | Alcance de distribución permitido | Uso típico en SOC / CTI |
|---|---|---|
| **`TLP:RED`** | Estrictamente restringido a los participantes de la reunión/caso puntual (no reenviar). | Detalles de intrusión activa o identidad de víctima antes de contener. |
| **`TLP:AMBER+STRICT`** | Solo dentro de la **propia organización** (sin compartir con proveedores ni clientes). | Telemetría interna sensible, hallazgos internos Tier 0. |
| **`TLP:AMBER`** | Dentro de la organización y clientes/socios que necesiten actuar para protegerse. | IOCs observados en una campaña dirigida contra proveedores del sector. |
| **`TLP:GREEN`** | Comunidad sectorial / pares de ciberseguridad (no publicar en web abierta ni redes). | Reglas Sigma/YARA compartidas entre equipos Blue Team de un ISAC. |
| **`TLP:CLEAR`** | Sin restricción de divulgación pública (sujeto a atribución estándar). | Boletines públicos, hashes de malware ya divulgados, avisos CVE. |

### Regla innegociable de higiene: *Defanging*

Antes de pegar cualquier URL, dominio, IP o correo sospechoso en un informe, ticket, correo o chat interno, neutralizalo (*defanging*) para impedir clics accidentales o previsualizaciones automáticas:
- `https://login-verificacion.ejemplo/auth` → `hxxps://login-verificacion[.]ejemplo/auth`
- `198.51.100.42` → `198[.]51[.]100[.]42`
- `soporte@dominio.invalid` → `soporte[@]dominio[.]invalid`

<!-- salto -->

### Caza de amenazas especializadas: Beaconing, Ransomware, RMM y *Deception*

Además de buscar indicadores estáticos conocidos, el *Threat Hunting* proactivo formula hipótesis sobre comportamientos difíciles de ocultar incluso cuando el atacante cambia dominios o recompila binarios:

- **Caza de *beaconing* C2 y túneles DNS con Zeek y `RITA` (*Real Intelligence Threat Analytics*):** Al ingerir registros `conn.log` y `dns.log` de Zeek, herramientas estadísticas como `RITA` puntúan conexiones periódicas comparando la regularidad de los intervalos entre paquetes (*jitter* bajo), la cantidad total de conexiones sostenidas hacia un mismo par IP/puerto y la longitud o entropía de subdominios DNS. En túneles DNS o dominios generados algorítmicamente (*DGA*), la señal característica combina subdominios de alta entropía, consultas frecuentes de registros `TXT`/`NULL` y picos sostenidos de respuestas `NXDOMAIN` desde un mismo host interno.
- **Caza temprana de Ransomware:** Antes de completar el cifrado masivo en endpoints o recursos compartidos SMB, muchos operadores ejecutan comandos de inhibición de recuperación local (`vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `bcdedit /set {default} recoveryenabled No`). Correlacionar estas líneas de comando (Sysmon ID `1` / Event ID `4688`) con picos súbitos de creación o renombrado masivo de archivos con extensiones atípicas en red (Sysmon ID `11` y auditoría SMB `5145`) permite contener el brote en los primeros minutos.
- **Abuso de herramientas RMM legítimas (*Living off Trusted RMM*):** Para evitar disparar alertas de malware binario, varios grupos intrusos instalan o ejecutan clientes comerciales de administración remota (*AnyDesk*, *TeamViewer*, *ScreenConnect*, *Atera*, *Splashtop*). La hipótesis de caza parte del inventario oficial de software corporativo: se buscan ejecuciones por nombre original en metadatos PE (`OriginalFileName`), firmas digitales de proveedores RMM o conexiones hacia sus relés públicos desde hosts de usuarios finales o fuera de la ventana y subred autorizada de mesa de ayuda.
- **Threat Hunting basado en *Deception* (Honeypots, Honeytokens y Canarytokens):** El despliegue deliberado de sensores pasivos —como servicios señuelo internos (*honeypots*), cuentas falsas de Active Directory sin uso real (*honeytokens*) o documentos/entradas DNS trampa (*Canarytokens*)— invierte la carga de la prueba: como ningún proceso legítimo ni usuario autorizado debe interactuar con esos recursos, cualquier autenticación Kerberos/NTLM o consulta contra ellos produce una alerta de fidelidad cercana al 100 % y señal temprana de reconocimiento lateral.

::: aviso Contención y recuperación práctica ante ransomware
Si durante el *Threat Hunting* o la respuesta temprana confirmás cifrado activo o preparación de ransomware, cada minuto y cada decisión operativa definen si recuperás la operación o destruís evidencia crítica:

1. **Estrategia de respaldos inmutables y aislados (regla `3-2-1-1-0`):** Mantené al menos **3** copias de tus datos en **2** tipos de medios distintos, **1** copia fuera del sitio (*offsite*), **1** copia completamente aislada de la red o **inmutable** (*air-gapped* / Object Lock WORM que ni siquiera un administrador de dominio comprometido pueda borrar) y **0** errores verificados mediante pruebas periódicas de restauración en entorno aislado.
2. **Aislamiento de red sin apagar la máquina (preservar RAM crítica):** Aislá el host comprometido mediante cuarentena del EDR, corte de puerto en switch o VLAN de aislamiento, **pero no lo apagues ni lo reinicies de inmediato**. La memoria RAM viva puede contener procesos cifradores activos, claves simétricas aún en memoria, líneas de comando completas e IOCs volátiles (sockets C2, payloads *fileless*) indispensables para el equipo DFIR.
3. **Orden seguro de reconstrucción limpia de Active Directory:** Si el atacante alcanzó privilegios de dominio, reconectar estaciones infectadas antes de sanear la identidad reintroduce el compromiso. Recuperá primero la capa **Tier 0** (Controladores de Dominio restaurados desde respaldo limpio previo al compromiso o reconstruidos en bosque limpio, PKI y sincronización híbrida), ejecutá la **doble rotación de la cuenta `krbtgt`** (respetando el intervalo de replicación entre todos los DCs para invalidar cualquier *Golden Ticket* existente), revocá tokens/sesiones activas y recién entonces reincorporá servidores de aplicaciones y estaciones limpias.
4. **Doble extorsión (exfiltración previa al cifrado) — impacto técnico y legal:** Los grupos modernos rara vez cifran sin antes extraer datos sensibles. Desde la perspectiva Purple Team, auditá en paralelo los logs de firewall, proxy, DNS y NetFlow/Zeek buscando picos de egreso o uso de utilidades de empaquetado y transferencia (`7z`, `rclone`, clientes S3/Mega). Confirmar o descartar exfiltración cambia el escenario de recuperación técnica a **gestión de brecha legal y regulatoria** (preservación de cadena de custodia, evaluación de datos personales/contractuales expuestos y notificaciones obligatorias a autoridades y clientes, sin asumir jamás que el pago garantiza la destrucción real de los datos robados).
5. **Mini-playbook específico para hipervisores ESXi / vCenter y restauración verificada:** Si el ransomware compromete el plano de virtualización (**vCenter** o hosts **VMware ESXi** vía credenciales AD integradas o SSH habilitado), cifrará directamente archivos `.vmdk` sin pasar por los agentes EDR de cada VM invitada. **Pasos prioritarios:** (a) desconectar inmediatamente las interfaces de gestión de vCenter/ESXi y deshabilitar SSH/ESXi Shell; (b) revisar procesos cifradores en el hipervisor (`esxcli vm process list` / `/var/log/auth.log` y `shell.log`) antes de reiniciar nodos; (c) **nunca reescribir sobre datastores comprometidos sin evidencia**, reconstruir los hosts ESXi desde medio de instalación limpio verificando firmware/vib no autorizados; y (d) **restaurar backups inmutables en un enclave de cuarentena**, verificando integridad de snapshots, ausencia de persistencia previa al cifrado y validación funcional completa antes de reconectar las VMs a producción (manteniendo vCenter fuera del dominio Active Directory cotidiano y bajo MFA + red de gestión aislada).
:::

## 3. Análisis técnico y seguro de phishing en el SOC

El correo electrónico sigue siendo una de las principales vías de acceso inicial. Todo análisis de un correo sospechoso debe hacerse **en texto plano o visor aislado sobre el archivo `.eml`/`.msg` original**, sin hacer clic en enlaces ni abrir adjuntos fuera de una VM desechable sin red.

### Los cinco pasos ordenados del triage de un `.eml`

1. **Trazar la cadena de transporte (`Received:`):** leer las cabeceras `Received:` **de abajo hacia arriba** (desde el servidor de origen hasta el servidor de correo receptor) para identificar la IP real emisora y detectar saltos anómalos.
2. **Evaluar la autenticación de correo (`SPF`, `DKIM` y `DMARC`):** revisar la cabecera `Authentication-Results` insertada por tu pasarela de correo (`mx`):

| Estándar | Qué valida criptográfica o lógicamente | Indicador de alerta en triage |
|---|---|---|
| **SPF (RFC 7208)** | Comprueba en DNS si la IP del servidor remitente está autorizada a enviar correos en nombre del dominio de **`Return-Path`** (sobre SMTP). | `spf=fail` o `spf=softfail`: el servidor origen no figura en el registro TXT SPF del dominio. |
| **DKIM (RFC 6376)** | Verifica con firma criptográfica asimétrica que el cuerpo y cabeceras firmadas (`From`, `Subject`) no fueron alterados en tránsito por el dominio `d=`. | `dkim=fail` o ausencia total de firma DKIM válida en dominios corporativos críticos. |
| **DMARC (RFC 7489)** | Exige **alineación** entre el dominio visible al usuario en la cabecera **`From:`** y el dominio validado por SPF o DKIM, aplicando la política publicada (`p=reject` / `quarantine` / `none`). | `dmarc=fail` combinado con discrepancia entre `From:` visible (`soporte@empresa.local`) y `Return-Path:` o `Reply-To:` externo. |

3. **Detectar discrepancias en `From:`, `Return-Path:` y `Reply-To:`:** es habitual en campañas de suplantación mostrar una dirección corporativa en `From:` o un *Display Name* engañoso mientras `Reply-To:` apunta a un dominio externo distinto.
4. **Extraer e inspeccionar URLs con *defanging*:** comparar el texto visible del enlace en HTML frente a su atributo `href=` real, buscando acortadores, dominios recién creados o *typosquatting* (`empresaa.example`).
5. **Triage pasivo de adjuntos:** calcular únicamente su hash **SHA-256**, revisar el tipo real por *magic bytes* (por ejemplo distinguir un `.html` disfrazado o un archivo `.iso`/`.lnk`/`.zip`), sin ejecutarlo nunca en el equipo del analista.

<!-- salto -->

## 4. Ejemplo paso a paso: análisis completo de `laboratorios/muestras/correo_phishing_simulado.eml`

En nuestro kit `laboratorios/muestras/` tenés un archivo `.eml` seguro diseñado específicamente para practicar triage pasivo con Python sin red:

```python
# Archivo de laboratorio: triage_eml_lab.py (100 % pasivo, sin conexión de red)
import email
import re
from email import policy

ruta_eml = "laboratorios/muestras/correo_phishing_simulado.eml"
with open(ruta_eml, "rb") as f:
    msg = email.message_from_binary_file(f, policy=policy.default)

print("=== METADATOS DE CABECERA ===")
for campo in ("From", "Return-Path", "Reply-To", "Subject", "Authentication-Results"):
    print(f"{campo:23s}: {msg.get(campo)}")

print("\n=== CADENA RECEIVED (DE ORIGEN A DESTINO) ===")
for idx, rec in enumerate(reversed(msg.get_all("Received", [])), 1):
    print(f"Salto {idx}: {' '.join(rec.split())}")

cuerpo = msg.get_body(preferencelist=("plain", "html"))
texto = cuerpo.get_content() if cuerpo else ""
urls = re.findall(r"(?:https?|hxxps?)://[^\s\"'<>]+", texto)
print("\n=== ENLACES EXTRAIDOS (CON DEFANGING) ===")
for u in sorted(set(urls)):
    print(" ->", u.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]"))
```

Salida real verificada sobre `laboratorios/muestras/correo_phishing_simulado.eml`:

```text
=== METADATOS DE CABECERA ===
From                   : "Soporte TI Empresa" <soporte@empresa.local>
Return-Path            : <soporte-falso@notificaciones-seguridad.invalid>
Reply-To               : "Mesa Externa" <respuesta-urgente@dominio-externo.invalid>
Subject                : URGENTE: Verificacion de cuenta requerida en 2 horas
Authentication-Results : mx.empresa.local; spf=fail (... 198.51.100.99 ...); dkim=fail (no signature); dmarc=fail (p=REJECT) header.from=empresa.local

=== CADENA RECEIVED (DE ORIGEN A DESTINO) ===
Salto 1: from mail-relay.ejemplo-externo.invalid (198.51.100.99) by mx.empresa.local with ESMTPS; Sun, 22 Nov 2026 14:10:05 +0000

=== ENLACES EXTRAIDOS (CON DEFANGING) ===
 -> hxxps://portal-verificacion[.]ejemplo[.]invalid/login?id=99182
```

En tres segundos de inspección pasiva comprobamos cuatro indicadores claros de suplantación:
1. `From` declara `@empresa.local`, pero `Return-Path` proviene de `@notificaciones-seguridad.invalid` y `Reply-To` redirige respuestas a `@dominio-externo.invalid`.
2. La IP `198.51.100.99` falló **SPF, DKIM y DMARC (`p=REJECT`)**.
3. El asunto impone urgencia artificial (*"URGENTE: en 2 horas"*).
4. El enlace apunta a un dominio externo no corporativo.

::: defensa Perspectiva defensiva y mitigación
1. **Endurecimiento progresivo de correo corporativo:** publicar registros SPF estrictos (`-all`), firmar todo el correo saliente legítimo con **DKIM de 2048 bits** y avanzar la política **DMARC** de `p=none` → `p=quarantine` → `p=reject` monitoreando los reportes agregados RUA para no bloquear envíos propios legítimos.
2. **Retroalimentación del Hunting a Detection Engineering:** cada consulta de hunting que demuestre ser útil para encontrar relaciones padre-hijo o anomalías de red debe convertirse al cierre de la sesión en una regla versionada (Sigma/SPL/KQL) revisada en Git (Cap. 4.5).
:::

## Práctica en laboratorio local

1. Ejecutá el script `triage_eml_lab.py` directamente contra la muestra real incluida en `laboratorios/muestras/correo_phishing_simulado.eml` y guardá la salida comentada.
2. Probá también ejecutar `python laboratorios/analizador_logs_soc.py laboratorios/muestras/web_access_simulado.log 4` y redactá una hipótesis de Threat Hunting sobre qué buscarías a continuación si esa IP `198.51.100.88` hubiera recibido además un código `200 OK` tras probar `/.env`.
3. Redactá un objeto indicador JSON con formato básico **STIX 2.1** que modele la IP de prueba `198.51.100.99` observada en el `.eml` de laboratorio (incluyendo `type: "indicator"`, `spec_version: "2.1"`, `pattern` y `valid_from`).

::: practica Entregable mínimo
Salida real del triage sobre `correo_phishing_simulado.eml`, resultado JSON de `analizador_logs_soc.py` sobre `web_access_simulado.log`, hipótesis escrita de hunting posterior y tu objeto JSON STIX 2.1 validado sintácticamente.
:::

## Preguntas de repaso

**1. ¿Qué diferencia al Threat Hunting proactivo de la atención tradicional de alertas en un SOC?** El Threat Hunting parte de hipótesis verificables sobre actividad sigilosa o no alertada (por ejemplo abuso de herramientas administrativas legítimas o patrones estadísticos raros) para descubrir intrusiones ocultas, mientras que el monitoreo L1/L2 reacciona a eventos que ya coincidieron con reglas de detección existentes.

**2. ¿Por qué el apilamiento de frecuencias (*stacking*) es eficaz para detectar anomalías en miles de eventos de procesos?** Porque en una red operativa las ejecuciones legítimas del sistema y del negocio se repiten con alta frecuencia (cientos o miles de veces), haciendo que relaciones padre-hijo inusuales (`nginx → bash` o `winword.exe → powershell.exe`) aparezcan al inicio del ordenamiento ascendente por frecuencia.

**3. ¿En qué orden se deben leer las cabeceras `Received:` de un archivo `.eml` y qué añade DMARC respecto de SPF y DKIM?** Las cabeceras `Received:` se leen siempre **de abajo hacia arriba** porque cada servidor intermedio que recibe el mensaje inserta su cabecera arriba del todo; abajo figura el primer salto emitido por el remitente. **DMARC** exige además **alineación** entre el dominio visible al usuario en la cabecera `From:` y el dominio validado por SPF o DKIM, definiendo qué política aplicar si falla (`none`, `quarantine` o `reject`).

**4. ¿Por qué es obligatorio aplicar *defanging* a URLs e IPs sospechosas al documentar un caso de CTI o un ticket SOC?** Para evitar que clientes de correo, sistemas de tickets, mensajería o el propio analista abran accidentalmente un enlace sospechoso al hacer clic o disparen resoluciones DNS y descargas automáticas de vista previa (*link unfurling*).

**5. ¿Cuál es el entregable más importante al finalizar una sesión de Threat Hunting que descubrió un nuevo patrón de riesgo o una brecha de visibilidad?** Además de contener el hallazgo si fue positivo, traducir el patrón validado en una **regla permanente versionada** (Sigma/SPL/KQL/Suricata) y documentar qué telemetría faltaba en el SIEM/EDR para cerrar la brecha detectada.

## Antes de avanzar

Verificá que podés:
- Formular una hipótesis de Threat Hunting y usar *stacking* para aislar eventos de baja frecuencia.
- Analizar pasivamente `laboratorios/muestras/correo_phishing_simulado.eml` evaluando `Received`, SPF, DKIM, DMARC y enlaces con *defanging*.
- Modelar indicadores básicos en formato STIX 2.1 y retroalimentar detecciones al SOC.

::: nota Puerta de salida
Avanzá al **Capítulo 4.7 · DFIR: forense de disco, artefactos Windows/Linux y análisis de memoria RAM** cuando puedas ejecutar un triage completo de correo y formular hipótesis estructuradas sobre logs y procesos.
:::

## Referencias y estándares abiertos

- **OASIS Cyber Threat Intelligence (STIX 2.1 / TAXII 2.1 Specifications):** estándares abiertos de modelado e intercambio de inteligencia.
- **RFC 7208 (SPF), RFC 6376 (DKIM) y RFC 7489 (DMARC):** especificaciones oficiales del IETF sobre autenticación de correo electrónico.
- **NIST SP 800-150 (*Guide to Cyber Threat Information Sharing*) & MITRE ATT&CK Matrix.**
