::: nota Objetivo de la lección
Al completar este capítulo vas a comprender cómo opera un Centro de Operaciones de Seguridad (SOC) por niveles, cómo estructurar la respuesta a incidentes bajo NIST SP 800-61 y cómo aplicar modelos analíticos (Cyber Kill Chain, Diamond Model y MITRE ATT&CK) para evaluar visibilidad y reducir tiempos de respuesta en tu laboratorio local.
:::

**Prerrequisitos:** Fundamentos de redes TCP/IP, administración básica de Windows y Linux, y conceptos elementales de seguridad ofensiva y defensiva. **Duración sugerida:** 2 a 3 horas de estudio y práctica en laboratorio aislado.

## 1. Arquitectura de un SOC, niveles y métricas operativas

Un Centro de Operaciones de Seguridad (SOC) centraliza el monitoreo continuo, el triage de alertas y la coordinación frente a incidentes. Su eficacia depende de separar responsabilidades por complejidad técnica para evitar la fatiga de alertas y garantizar tiempos de respuesta predecibles.

### Niveles operativos: L1, L2 y L3

| Nivel | Rol principal | Responsabilidades clave | Salida habitual |
| --- | --- | --- | --- |
| **L1 (Triage)** | Monitoreo continuo y filtrado inicial | Validar alertas, descartar falsos positivos, recolectar contexto básico y escalar incidentes confirmados. | Cierre documentado o ticket escalado a L2. |
| **L2 (Respuesta)** | Investigación profunda y contención | Correlacionar telemetría entre endpoints y red, aislar activos comprometidos, erradicar artefactos y redactar reportes. | Incidente contenido y plan de remediación. |
| **L3 (Hunting / Ingeniería)** | Caza proactiva y mejora de detección | Buscar amenazas no alertadas, afinar reglas de detección y cerrar brechas de visibilidad en la arquitectura. | Nuevas detecciones y ajustes de plataforma. |

### Gestión de alertas y métricas clave

Cada alerta procesada en la cola del SOC debe recibir una clasificación consistente para medir la salud del monitoreo:

- **True Positive (TP):** Actividad maliciosa o no autorizada confirmada que requiere respuesta.
- **False Positive (FP):** Alerta disparada por una regla defectuosa o sin evento malicioso real; exige afinado (*tuning*).
- **Benign Positive (BP):** Actividad legítima esperada (por ejemplo, una tarea administrativa programada) que coincide con una firma de detección.

El rendimiento operativo se controla mediante acuerdos de nivel de servicio (**SLA**) y dos métricas centrales expresadas en tiempo:

- `MTTD = Promedio(t_detección − t_evento_inicial)`: tiempo medio hasta detectar un compromiso.
- `MTTR = Promedio(t_contención − t_detección)`: tiempo medio hasta contener y mitigar el incidente.

Reducir el `MTTD` mejora con telemetría bien configurada; reducir el `MTTR` depende de playbooks claros y automatización segura.

## 2. Respuesta a incidentes según NIST SP 800-61 Rev. 3 y NIST CSF 2.0

La actualización **NIST SP 800-61 Rev. 3 (abril de 2025)** (*Incident Response Recommendations and Considerations for Cybersecurity Risk Management*) reemplaza el antiguo esquema lineal de 4 fases de la Rev. 2 e integra la gestión de incidentes directamente dentro de las **6 funciones del NIST CSF 2.0**, alineándose con el cierre del **Cap. 4.8**:

1. **Govern (Gobernar):** establecer políticas de respuesta, roles RACI, métricas (`MTTD`/`MTTR`), acuerdos legales/RoE y mecanismos de mejora continua.
2. **Identify (Identificar):** mantener el inventario de activos críticos, modelar riesgos, validar firmas mediante **PKI** y verificar la línea base criptográfica (*golden baseline* SHA-256) sobre binarios y configuraciones antes y durante un incidente.
3. **Protect (Proteger):** aplicar endurecimiento preventivo, segmentación, copias de seguridad inmutables y capacitación para reducir superficie de ataque y tiempo de recuperación.
4. **Detect (Detectar):** operar el monitoreo continuo en SIEM/EDR, validar indicadores, clasificar alertas (TP/FP/BP) y recolectar evidencia volátil sin alterar el sistema innecesariamente.
5. **Respond (Responder):** contener hosts afectados mediante aislamiento lógico en red, erradicar causas raíz (cuentas comprometidas, persistencia, artefactos) y ejecutar notificaciones internas o regulatorias.
6. **Recover (Recuperar):** restaurar servicios desde respaldos verificados en entorno limpio, confirmar integridad operativa y retroalimentar controles y reglas de detección con las lecciones aprendidas (*post-incidente*).

### Triage inicial en sistemas Windows y Linux

Durante la fase de detección y análisis en un laboratorio aislado, priorizá la recolección de estado volátil (procesos activos y conexiones de red) antes de reiniciar el equipo.

```powershell
# Triage rápido de solo lectura en Windows (PowerShell en laboratorio)
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | Format-Table -AutoSize
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
Get-AuthenticodeSignature "C:\Windows\System32\cmd.exe" | Select-Object Status, SignerCertificate
```

```bash
# Triage rápido de solo lectura en Linux (entorno de laboratorio)
ps -ef --forest | head -n 30
ss -tunap | grep ESTAB
sha256sum /tmp/artefacto_sospechoso.bin 2>/dev/null || echo "Sin artefacto en /tmp"
```

### Identificación de amenazas, documentos sospechosos y verificación de línea base

Ante archivos adjuntos sospechosos (como documentos ofimáticos o PDF recibidos por correo), el análisis seguro se realiza exclusivamente en máquinas virtuales aisladas sin salida a Internet: se inspeccionan metadatos, flujos embebidos y presencia de macros o enlaces externos antes de ejecutar cualquier contenido.

En paralelo, una parte crítica de la fase de **Preparación** del SOC consiste en mantener una **línea base criptográfica de binarios críticos** (*golden baseline*) y verificar firmas digitales en modo solo lectura para detectar de inmediato reemplazos o manipulaciones antes y durante un incidente:

```python
# Verificación defensiva de línea base SHA-256 para preparación SOC (solo lectura)
import hashlib
from pathlib import Path

BASELINE_ESPERADA = {
    "reglas_sigma_ejemplo.yml": "<sha256_conocido_de_repositorio>",
    "sysmon_config_lab.xml": "<sha256_aprobado_por_soc>",
}

def verificar_integridad_artefactos(carpeta: str) -> list[str]:
    alertas = []
    for nombre, hash_ok in BASELINE_ESPERADA.items():
        ruta = Path(carpeta) / nombre
        if not ruta.exists():
            alertas.append(f"AUSENTE: {nombre}")
            continue
        digest = hashlib.sha256(ruta.read_bytes()).hexdigest()
        if hash_ok.startswith("<"):
            print(f"[BASELINE] {nombre} -> {digest}")
        elif digest != hash_ok:
            alertas.append(f"ALTERADO: {nombre} ({digest})")
    return alertas
```

### Estructura de un reporte de incidente de seguridad

Un buen reporte separa hechos verificables de hipótesis y permite que tanto dirección técnica como gestión comprendan el impacto:

- **Resumen ejecutivo:** Impacto en negocio, activos afectados y estado actual (contenido / resuelto).
- **Línea de tiempo (UTC):** Secuencia breve de hitos principales con marca horaria normalizada.
- **Causa raíz y alcance:** Vector inicial identificado, sistemas tocados y datos expuestos.
- **Acciones correctivas:** Contención aplicada, parches, rotaciones de credenciales y mejoras de monitoreo.

## 3. Modelos analíticos y uso operativo de MITRE ATT&CK

Los modelos analíticos permiten estructurar observaciones dispersas y detectar brechas de cobertura defensiva.

| Modelo | Enfoque principal | Utilidad práctica en el SOC |
| --- | --- | --- |
| **Cyber Kill Chain** | Secuencia lineal de fases de una intrusión externa | Visualizar en qué etapa se puede interrumpir el ataque antes del objetivo final. |
| **Diamond Model** | Relación entre cuatro vértices: Adversario, Capacidad, Infraestructura y Víctima | Agrupar incidentes relacionados y pivotar investigaciones a partir de un único indicador. |
| **MITRE ATT&CK** | Base de conocimiento de tácticas y comportamientos observables | Mapear visibilidad real de sensores y priorizar reglas de detección por táctica. |

### Mapeo operativo de brechas con MITRE ATT&CK

En lugar de intentar cubrir toda la matriz en un día, un SOC maduro agrupa sus prioridades en pocas tácticas padre de alto impacto y mide si posee telemetría suficiente en cada una:

| Táctica padre (MITRE ATT&CK) | Comportamiento de alto nivel a vigilar | Fuente de visibilidad principal |
| --- | --- | --- |
| **Acceso Inicial** | Ingreso por credenciales expuestas, servicios públicos o adjuntos maliciosos | Logs de autenticación, proxy/correo y firewall perimetral |
| **Ejecución** | Lanzamiento de intérpretes de comandos o scripts no autorizados | Auditoría de procesos en endpoints (Windows/Linux) |
| **Movimiento Lateral** | Uso de sesiones remotas administrativas entre equipos internos | Telemetría de red interna y logs de inicio de sesión |

Este mapeo evidencia rápido dónde hay puntos ciegos (por ejemplo, tener registros de red perimetral pero ninguna visibilidad sobre la táctica de Ejecución en estaciones de trabajo).

::: nota Validación continua de reglas ATT&CK: Atomic Red Team y MITRE CALDERA
Para comprobar si tus alertas realmente disparan sin esperar un incidente real, los SOC maduros ejecutan emulación acotada de técnicas ATT&CK en un entorno de prueba: **`Atomic Red Team`** permite correr pruebas unitarias YAML reproducibles por técnica (por ejemplo `T1059.001` o `T1003`) y medir segundos hasta la alerta en SIEM/EDR, mientras **`MITRE CALDERA`** automatiza cadenas completas multi-paso mediante un agente de laboratorio para validar correlaciones de extremo a extremo.
:::

## 4. Triage con VirusTotal, análisis de servidores web comprometidos, ASM y seguridad en asistentes IA

En la operación diaria de un SOC L1/L2 intervienen cuatro flujos prácticos adicionales:

1. **Uso seguro de VirusTotal y reputación de IOCs:** consultá siempre **el hash SHA-256**, la IP o el dominio en VirusTotal antes de compartir archivos. **Regla estricta de confidencialidad:** nunca subas documentos corporativos internos, correos confidenciales ni ejecutables propietarios desarrollados por tu organización a sandboxes públicos.
2. **Investigación de servidores web comprometidos (*Hacked Web Server Analysis*):** cuando un servidor web presenta actividad anómala, inspeccioná los logs de acceso (`POST` inusuales hacia rutas nuevas como `/uploads/cmd.php` seguidos de códigos `200`), buscá modificaciones recientes de archivos en el *webroot* (`find /var/www -mtime -2`) y verificá con Sysmon/`auditd` si el worker web (`w3wp.exe`, `www-data`) generó shells hijas.
3. **Gestión continua de Superficie de Ataque (*ASM — Attack Surface Management*) y Ciclo SDLC:** inventariá periódicamente subdominios olvidados, servicios expuestos y certificados próximos a vencer antes de que aparezcan en un incidente, e integrá validaciones tempranas de seguridad en cada fase del **SDLC** (*Software Development Life Cycle* / DevSecOps).
4. **Riesgos emergentes en agentes de código e integraciones MCP:** los asistentes de desarrollo conectados mediante *Model Context Protocol (MCP)* leen archivos locales, *issues* y repositorios con permisos del desarrollador; aplicá siempre controles deterministas en el host (principio de mínimo privilegio, revisión de comandos y restricciones de red saliente) frente a texto malicioso sembrado en repositorios externos.

## 5. Programa defensivo continuo: Gestión de Vulnerabilidades, Tabletop, PAM, DLP e ITDR

Un SOC y un equipo Blue Team maduros no viven solo de responder alertas reactivas: operan controles preventivos y programas continuos que reducen la probabilidad y el impacto antes de que ocurra la brecha.

### Ciclo del programa de Gestión de Vulnerabilidades

Mientras el pentesting evalúa escenarios puntuales en profundidad, la **Gestión de Vulnerabilidades (*Vulnerability Management*)** mantiene inventario y remediación continua en todo el parque mediante cuatro etapas cerradas:

1. **Descubrir:** inventario actualizado de activos y escaneo periódico con motores como **OpenVAS (Greenbone)** o **Nessus** (combinando **escaneo autenticado** mediante credenciales SSH/WMI de solo lectura para detectar paquetes faltantes con **escaneo externo no autenticado** para verificar lo expuesto), complementado por telemetría continua de agentes EDR/TVM.
2. **Priorizar:** cruzar **CVSS v4.0**, **EPSS**, catálogo **CISA KEV** y criticidad del activo (exposición externa/Tier 0 vs. laboratorio aislado) mediante árbol SSVC.
3. **Remediar dentro de SLAs acordados:** parches de seguridad, mitigaciones compensatorias (regla WAF/segmentación) o excepciones formales firmadas con fecha de vencimiento.
4. **Verificar:** re-escaneo dirigido tras el despliegue del parche para confirmar el cierre efectivo (métricas clave: **MTTR por severidad**, **cobertura de escaneo autenticado %** y **tasa de reincidencia**).

| Nivel / Criterio | SLA de remediación sugerido | Métrica de seguimiento para dirección |
|---|---|---|
| **Explotación activa (CISA KEV) / Crítica en perímetro** | `24 a 72 horas` (o mitigación compensatoria inmediata) | Porcentaje resuelto dentro de SLA + MTTR crítico |
| **Alta en servidores internos / Tier 0** | `7 a 15 días` | Backlog vencido por unidad de negocio |
| **Media / Baja** | `30 a 90 días` (ciclo de mantenimiento regular) | Tendencia de reducción de deuda técnica trimestral |

### Ejercicios *Tabletop* y controles de programa (PAM, DLP e ITDR)

- **Ejercicios *Tabletop* (simulacros de escritorio):** reuniones estructuradas donde SOC, IR, Infraestructura, Legal, Comunicación y Dirección recorren paso a paso un guion realista (*ransomware* en VMware, robo de sesión SaaS o compromiso de proveedor) sin apagar producción. Permiten medir tiempos de decisión, validar contactos fuera de banda y detectar ambigüedades en la matriz RACI antes de sufrir un incidente real.
- **PAM (*Privileged Access Management*):** más allá de tener cuentas administrativas separadas, un programa PAM centraliza credenciales críticas en bóvedas cifradas con rotación automática tras cada uso, aplica acceso **Just-In-Time (JIT)** (permiso temporal aprobado solo durante una ventana de cambio), **JEA** (*Just Enough Administration*) y grabación auditable de sesiones SSH/RDP sobre bastiones.
- **DLP (*Data Loss Prevention*):** políticas en endpoint, pasarela web/CASB y correo electrónico para identificar, etiquetar y bloquear transferencias no autorizadas de información clasificada o PII (tarjetas, documentos legales, código fuente) hacia USBs, webs de IA públicas o cuentas de almacenamiento personal.
- **ITDR (*Identity Threat Detection & Response*):** disciplina enfocada específicamente en proteger el plano de identidad (Active Directory local, Microsoft Entra ID, Okta) correlacionando señales que un EDR puro de archivo no ve —viajes imposibles, *MFA fatigue*, concesión anómala de permisos OAuth, alteración de DACLs en Tier 0 o abuso de tokens de sesión— con respuesta automatizada para revocar *refresh tokens* y suspender identidades comprometidas en segundos.

## Ejemplo paso a paso: Triage L1/L2 y registro de incidente en laboratorio

En este escenario simulado en tu red local Host-Only, una alerta señala una conexión saliente inusual desde un servidor Linux de pruebas hacia un puerto no estándar.

**Paso 1:** Verificar el proceso propietario de la conexión y su binario en disco sin matar el proceso todavía.

```bash
# Identificar proceso y ruta real del ejecutable
ss -tunap | grep 4444
ls -l /proc/1842/exe
```

```text
# Salida comentada en laboratorio
tcp   ESTAB 0 0 192.168.56.20:51922 192.168.56.10:4444 users:(("python3",pid=1842,fd=3))
# El socket pertenece a python3 (PID 1842) conectado al host de laboratorio 192.168.56.10
lrwxrwxrwx 1 labuser labuser 0 Nov 22 14:10 /proc/1842/exe -> /usr/bin/python3.11
```

**Paso 2:** Documentar el caso con formato estructurado antes de aislar la interfaz de red de la VM afectada.

```yaml
incidente_id: INC-2026-0042
severidad: Alta
clasificacion: True Positive
fase_nist: Contención
tacticas_observadas:
  - Ejecución
  - Movimiento Lateral
activo_afectado:
  hostname: srv-lab-linux01
  ip: 192.168.56.20
resumen: "Proceso python3 (PID 1842) estableció sesión TCP saliente no autorizada hacia 192.168.56.10:4444."
accion_contencion: "Aislamiento de red Host-Only y captura de metadatos de proceso."
```

**Paso 3:** Aplicar contención lógica en la VM de laboratorio bloqueando tráfico no esencial y preservando la evidencia para análisis posterior.

```bash
# Contención temporal en laboratorio mediante firewall local
sudo ufw default deny outgoing
sudo ufw default deny incoming
sudo ufw status verbose
```

::: defensa Perspectiva defensiva, detección y mitigación
La respuesta eficaz combina prevención y visibilidad previa al incidente:
- **Contención segura:** Aislá el host a nivel de red (segmentación VLAN o reglas de firewall) en lugar de apagarlo bruscamente, para no destruir memoria volátil ni sesiones abiertas.
- **Integridad y confianza:** Verificá firmas digitales respaldadas por PKI en binarios críticos y restringí la ejecución de intérpretes a usuarios autorizados.
- **Ciclo de mejora:** Cada incidente confirmado debe cerrar su fase post-incidente con al menos una nueva regla de detección o un endurecimiento medible que reduzca `MTTD` y `MTTR`.
:::

## Práctica en laboratorio local

Desplegá dos VMs en una red local aislada (Host-Only): una estación analista y un equipo objetivo (Linux o Windows). Generá una actividad controlada y benigna (por ejemplo, una conexión TCP de prueba con `nc` o un script Python de eco local), recolectá evidencia volátil con los comandos de triage y documentá todo el ciclo conforme a **NIST SP 800-61 Rev. 3** (funciones *Detect*, *Respond* y *Recover* de **CSF 2.0**).

::: practica Entregable mínimo
Creá un archivo `reporte_incidente_lab.md` en tu carpeta de prácticas que contenga:
1. Clasificación de la alerta (TP/FP/BP) con justificación breve.
2. Tabla de línea de tiempo en UTC con marcas de detección y contención, incluyendo el cálculo de `MTTD` y `MTTR`.
3. Mapeo del ejercicio a 2 o 3 tácticas padre de MITRE ATT&CK y los 4 vértices del Diamond Model.
4. Captura de la salida de triage de procesos y conexiones de red de tu VM aislada.
:::

## Preguntas de repaso

**1. ¿Cuál es la diferencia funcional entre un analista SOC L1 y un analista L2?** El analista L1 realiza monitoreo continuo, valida alertas y filtra falsos positivos bajo tiempos de SLA estrictos, mientras que L2 ejecuta investigaciones profundas, correlaciona múltiples fuentes y coordina la contención y erradicación del incidente.

**2. ¿Qué diferencia a un False Positive de un Benign Positive y cómo impacta cada uno en el SOC?** Un False Positive ocurre cuando no existe el comportamiento buscado y señala un fallo en la lógica de detección; un Benign Positive refleja actividad legítima que coincide con la regla y requiere excepciones controladas para evitar ruido operativo.

**3. ¿Por qué NIST SP 800-61 Rev. 3 articula la respuesta a incidentes mediante las seis funciones de NIST CSF 2.0 (*Govern, Identify, Protect, Detect, Respond, Recover*)?** Porque la preparación preventiva (*Govern, Identify, Protect*), la detección y análisis (*Detect*) y la contención y restauración (*Respond, Recover*) forman un ciclo continuo de gestión de riesgos: cada lección aprendida tras recuperar un servicio retroalimenta directamente la gobernanza y las detecciones futuras.

**4. ¿Qué aporta el Diamond Model que no cubre por sí sola la Cyber Kill Chain?** Mientras la Cyber Kill Chain ordena fases secuenciales de un ataque, el Diamond Model vincula relaciones entre adversario, capacidad, infraestructura y víctima, permitiendo agrupar campañas y pivotar evidencia.

**5. ¿Cómo ayuda MITRE ATT&CK a priorizar inversiones defensivas en un SOC?** Permite mapear qué tácticas de alto nivel tienen cobertura real de sensores y detecciones y cuáles presentan puntos ciegos, orientando el esfuerzo de ingeniería hacia brechas concretas.

## Antes de avanzar

- [ ] Diferenciás con claridad las responsabilidades de L1, L2 y L3 y el cálculo de `MTTD`/`MTTR`.
- [ ] Sabés aplicar el marco **NIST SP 800-61 Rev. 3** alineado con **CSF 2.0** y estructurar un reporte de incidente claro (ver [Cap. 4.8](33-telemetria-bajo-nivel-y-analisis-malware.html)).
- [ ] Ejecutaste comandos de triage volátil en Windows o Linux dentro de una VM aislada.
- [ ] Mapeaste un escenario de laboratorio al Diamond Model y a tácticas padre de MITRE ATT&CK.

::: nota Puerta de salida
Con los procesos del SOC y el marco de respuesta establecidos, el siguiente paso es construir la materia prima de toda detección: configurar la telemetría de endpoints en Windows (Event Logs y Sysmon) y Linux (`auditd` y `journald`).
:::

## Referencias y estándares abiertos

- NIST Special Publication 800-61 Rev. 3 (abril 2025) — *Incident Response Recommendations and Considerations for Cybersecurity Risk Management* & *NIST CSF 2.0*: https://csrc.nist.gov/publications/sp800
- MITRE ATT&CK Framework (Enterprise Matrix): https://attack.mitre.org/
- Caltagirone, Pendergast & Betz — *The Diamond Model of Intrusion Analysis*: https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf
- CIS Critical Security Controls v8 (Incident Response Management): https://www.cisecurity.org/controls
