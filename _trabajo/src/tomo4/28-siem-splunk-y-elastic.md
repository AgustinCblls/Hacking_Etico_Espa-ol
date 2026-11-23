::: nota Objetivo de la lección
Al completar este capítulo vas a dominar la arquitectura de un SIEM (ingestión, normalización con ECS/CIM, indexado y retención) y vas a saber construir búsquedas y correlaciones prácticas lado a lado en **Splunk (SPL)** y **Elastic (KQL y ES|QL con tuberías)**, además de automatizar el análisis inicial de logs web con Python en tu laboratorio.
:::

**Prerrequisitos:** Conocimiento de logs de Windows/Sysmon y Linux (Capítulo 4.2), sintaxis básica de expresiones regulares y fundamentos HTTP. **Duración sugerida:** 3 horas de lectura y práctica en laboratorio aislado.

## 1. Arquitectura interna de un SIEM y normalización de datos

Un **SIEM** (*Security Information and Event Management*) transforma millones de líneas de texto heterogéneas en eventos consultables y alertas accionables. Su flujo interno sigue cinco etapas secuenciales:

1. **Recolección:** Agentes livianos en los endpoints (como Splunk Universal Forwarder, Elastic Agent/Filebeat o reenvío por Syslog) capturan logs y los envían cifrados hacia el colector central.
2. **Ingestión y Parsing:** El SIEM recibe el flujo, extrae la marca horaria (normalizada a UTC) y separa cada evento en campos clave-valor (IP origen, usuario, proceso, código de resultado).
3. **Normalización (CIM y ECS):** Distintos fabricantes nombran igual concepto de formas distintas (`src_ip`, `ClientIP`, `IpAddress`). Para correlacionar fuentes diversas, **Splunk** utiliza el *Common Information Model* (**CIM**) y **Elastic** utiliza el *Elastic Common Schema* (**ECS**).
4. **Indexado y Retención:** Los eventos se almacenan en índices optimizados para búsqueda rápida y se rigen por políticas de ciclo de vida (*Hot → Warm → Cold → Frozen*) según requisitos legales y operativos.
5. **Correlación y Alertado:** Consultas programadas o reglas en tiempo real detectan secuencias anómalas, generan alertas y alimentan tableros de monitoreo.

| Concepto común | Campo en Splunk (CIM) | Campo en Elastic (ECS) |
| --- | --- | --- |
| IP origen | `src_ip` / `src` | `source.ip` |
| Usuario objetivo | `user` | `user.name` |
| Nombre del proceso | `process_name` | `process.name` |
| Línea de comandos | `process` | `process.command_line` |
| Código de respuesta HTTP | `status` | `http.response.status_code` |

## 2. Fundamentos prácticos: Splunk SPL frente a Elastic KQL y ES|QL

**SPL** (*Search Processing Language*) opera como una tubería (*pipeline*) similar a Unix: filtrás primero a la izquierda del carácter `|` y luego transformás o agregás datos con comandos como `stats`, `eval`, `rex`, `transaction`, `lookup` y `timechart`.

En **Elastic**, conviven dos lenguajes principales de consulta según el alcance analítico:
- **Elastic KQL** (*Kibana Query Language*): lenguaje declarativo liviano orientado únicamente a **filtrar documentos** en Kibana Discover o reglas simples (`and`, `or`, `not` y comodines `*`), sin tuberías ni agregaciones dentro de la propia consulta.
- **Elastic ES|QL** (*Elasticsearch Piped Query Language*, disponible desde Elastic 8.14 / junio de 2024): lenguaje completo basado en **tuberías (`|`)** (`FROM ... | WHERE ... | EVAL ... | STATS ... BY ... | SORT ...`) que permite filtrar, transformar campos, hacer *lookups* (`ENRICH`) y calcular agregaciones estadísticas en una sola consulta —equivalente directo en Elastic de **Splunk SPL** y **Microsoft Kusto KQL**.

| Operación analítica | Splunk (SPL) | Elastic (KQL / filtros) | Elastic (ES\|QL · tuberías) |
| --- | --- | --- | --- |
| Filtrado exacto | `index=win EventCode=4625` | `event.code: "4625"` | `FROM logs-* \| WHERE event.code == "4625"` |
| Coincidencia parcial | `CommandLine="*Encoded*"` | `process.command_line: *Encoded*` | `\| WHERE process.command_line LIKE "*Encoded*"` |
| Negación / exclusión | `NOT user="svc_backup"` | `not user.name: "svc_backup"` | `\| WHERE user.name != "svc_backup"` |
| Agregación y conteo | `\| stats count by src_ip` | Agregación *Terms* en Lens/Discover | `\| STATS total = COUNT(*) BY source.ip \| SORT total DESC` |
| Serie temporal | `\| timechart span=5m count` | Histograma de fecha con intervalo `5m` | `\| EVAL bucket = DATE_TRUNC(5 minutes, @timestamp) \| STATS COUNT(*) BY bucket` |

::: aviso Aclaración clave: los dos «KQL» y dónde encaja Elastic ES|QL
En entrevistas técnicas, certificaciones y laboratorios suele aparecer una confusión muy frecuente porque dos tecnologías distintas comparten exactamente la misma sigla **KQL**:

- **Elastic KQL (*Kibana Query Language*):** sintaxis declarativa liviana orientada exclusivamente a **filtrar documentos** en Kibana Discover / Elastic Security usando `campo: valor` y operadores booleanos (`and`, `or`, `not`). Carece de tuberías (`|`) y agregaciones.
- **Elastic ES|QL (*Elasticsearch Piped Query Language*):** introducido en junio de 2024 para resolver esa limitación dentro de Elastic, incorpora **tuberías (`|`)**, `EVAL`, `DISSECT`/`GROK`, `STATS ... BY` y `SORT`, igualando la expresividad analítica de SPL y Kusto en un único pipeline.
- **Microsoft KQL (*Kusto Query Language*):** lenguaje basado en **tuberías (`|`)** utilizado en **Microsoft Sentinel**, **Azure Monitor (Log Analytics)** y **Microsoft Defender XDR** para filtrar, proyectar, unir tablas y agregar eventos.

Comparación directa buscando ejecuciones codificadas de PowerShell fuera de un host de administración:

```kql
# 1. Elastic KQL (Kibana Discover / reglas de filtro simple) -> Solo filtrado
event.code: "1" and process.name: "powershell.exe" and
process.command_line: *-enc* and not host.name: "adm-srv-01"
```

```esql
// 2. Elastic ES|QL (Elastic 8.14+, junio 2024+) -> Filtro + agregación con tuberías
FROM winlogbeat-*, logs-endpoint.*
| WHERE @timestamp > NOW() - 24 hours
| WHERE event.code == "1" AND process.name == "powershell.exe"
| WHERE process.command_line LIKE "*-enc*" AND host.name != "adm-srv-01"
| STATS Ejecuciones = COUNT(*) BY host.name, user.name, process.command_line
| SORT Ejecuciones DESC
```

```kusto
// 3. Microsoft KQL (Kusto Query Language en Sentinel / Defender XDR) -> Filtro + agregación
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe" and ProcessCommandLine has "-enc"
| where DeviceName !~ "adm-srv-01"
| summarize Ejecuciones = count() by DeviceName, AccountName, ProcessCommandLine
| sort by Ejecuciones desc
```

Desde un enfoque **Purple Team**, cuando diseñás una detección en Sigma conviene saber qué motor la ejecutará: **Elastic KQL** genera el filtro base de alerta o Discover, **ES|QL** resuelve agregaciones estadísticas, umbrales y correlaciones directamente en Elastic Security, y **Sentinel (Kusto KQL)** cumple el mismo rol en el ecosistema Microsoft.
:::

## 3. Casos de detección lado a lado (SPL y KQL)

A continuación se presentan cuatro escenarios esenciales de monitoreo en un SOC, alineados con tácticas padre de MITRE ATT&CK (**Acceso a Credenciales**, **Ejecución** y **Persistencia**).

### Caso A: Fuerza bruta seguida de inicio de sesión exitoso

Buscamos múltiples fallos de autenticación desde una misma IP seguidos de un acceso exitoso dentro de una ventana corta, usando `transaction` y `eval` en SPL.

```splunk
index=wineventlog (EventCode=4625 OR EventCode=4624)
| eval estado=if(EventCode=4625, "fallo", "exito")
| transaction src_ip maxspan=10m
| eval fallos=mvcount(mvfilter(match(estado, "fallo")))
| eval exitos=mvcount(mvfilter(match(estado, "exito")))
| where fallos >= 10 AND exitos >= 1
| table _time, src_ip, user, fallos, exitos
```

```kql
# Filtro KQL en Discover para auditar el mismo patrón por IP origen en ventana de 10 minutos
event.code: ("4625" or "4624") and source.ip: * and not source.ip: "127.0.0.1"
```

*(En Elastic SIEM, la regla de umbral o secuencia se activa cuando `event.code: "4625"` supera ≥ 10 eventos seguidos de `event.code: "4624"` agrupados por `source.ip`.)*

### Caso B: Ejecución sospechosa de PowerShell con argumentos ofuscados

Usamos `rex` para extraer indicadores del comando y `lookup` para enriquecer o excluir hosts de administración autorizados.

```splunk
index=sysmon EventCode=1 Image="*\\powershell.exe"
| rex field=CommandLine "(?i)(?<bandera>-enc|-encodedcommand|-nop|-w\s+hidden)"
| where isnotnull(bandera)
| lookup servidores_admin.csv host OUTPUT rol_equipo
| where isnull(rol_equipo)
| stats count values(CommandLine) as comandos by host, user, bandera
```

```kql
event.code: "1" and process.name: "powershell.exe" and
(process.command_line: *-enc* or process.command_line: *hidden*) and
not host.name: ("adm-srv-01")
```

### Caso C: Creación de cuentas y asignación a grupos privilegiados

Monitorear altas de cuentas locales o de dominio permite detectar persistencia temprana en el entorno.

```splunk
index=wineventlog EventCode IN (4720, 4732)
| timechart span=1h count by EventCode
```

```kql
event.code: ("4720" or "4732") and not user.name: "SYSTEM"
```

### Caso D: Anomalías en logs web (escaneo y errores masivos)

El incremento brusco de respuestas `404` o `401/403` desde un mismo origen suele delatar enumeración automatizada o intentos de acceso indebido.

```splunk
index=web_access status>=400
| stats count as errores, dc(uri_path) as rutas_unicas by src_ip
| where errores >= 50 AND rutas_unicas >= 20
| sort -errores
```

```kql
http.response.status_code >= 400 and not source.ip: ("192.168.56.1")
```

## 4. Afinado de alertas (Tuning) y reducción de falsos positivos

Una regla recién desplegada rara vez es perfecta. El afinado disciplinado evita la fatiga del analista L1:

- **Establecé línea base (*baseline*):** Ejecutá la consulta en modo informativo durante varios días antes de convertirla en alerta crítica.
- **Usá listas de contexto (*lookups*):** Documentá cuentas de servicio, escáneres autorizados y servidores de mantenimiento en tablas mantenibles en lugar de llenar la consulta de excepciones fijas.
- **Ajustá umbrales y ventanas:** Combiná volumen con diversidad (por ejemplo, `errores >= 50` **y** `rutas_unicas >= 20`) para distinguir un usuario distraído de un barrido automatizado.

## Normalización multi-SIEM (`ECS`, `CIM`, *IBM QRadar*) y SOAR con *TheHive*

En organizaciones medianas o grandes raramente existe un único producto de registro. Un ingeniero o analista SOC necesita trasladar lógicas de correlación entre distintos esquemas y conectar las alertas hacia plataformas de respuesta:

| Plataforma / Estándar | Campo IP origen / Evento normalizado | Lógica de correlación y concepto clave |
| :--- | :--- | :--- |
| **Elastic (`ECS`)** | `source.ip`, `user.name`, `event.code` | Documentos JSON tipados; **KQL** para filtrado rápido, **ES\|QL** (tuberías `\|`) para análisis y agregaciones, y **EQL** para secuencias temporales. |
| **Splunk (`CIM`)** | `src_ip`, `user`, `signature_id` | *Data Models* acelerados (`Authentication`, `Network_Traffic`, `Web`) que desacoplan las búsquedas `tstats` del proveedor del log. |
| **IBM QRadar** | Propiedades parseadas por DSM + identificador **QID** (*QRadar Identifier*) | El **CRE** (*Custom Rule Engine*) agrupa eventos y flujos relacionados en una **Offense** única deduplicada por magnitud, credibilidad y relevancia. |

- **Gestión de casos (*Case Management*) con *TheHive* y orquestación SOAR:** Cuando una regla de SIEM o una *Offense* requiere investigación formal, la alerta se promueve a un **caso en TheHive**. Cada caso agrupa **observables** clasificados (IP, hash, dominio, cuenta) etiquetados con `TLP` (*Traffic Light Protocol*), tareas secuenciales estandarizadas y analizadores automáticos (como **Cortex**) que consultan reputación o contexto interno sin intervención manual repetitiva.
- **Playbooks SOAR con control humano (*Human-in-the-Loop*):** Un flujo **SOAR** (*Security Orchestration, Automation and Response*) automatiza primero tareas de bajo riesgo y solo lectura —enriquecer la IP en CMDB, consultar sesiones VPN activas y adjuntar contexto del usuario—, pero exige confirmación explícita del analista antes de ejecutar acciones destructivas o de contención (aislar un controlador de dominio o revocar tokens críticos).

## Ejemplo paso a paso: Análisis rápido de logs con `laboratorios/analizador_logs_soc.py`

Cuando todavía no desplegaste un clúster SIEM completo o necesitás hacer triage reproducible en tu laboratorio local, el repositorio ya incluye el script defensivo en Python [`laboratorios/analizador_logs_soc.py`](../laboratorios/analizador_logs_soc.py) junto a bitácoras simuladas listas para auditar. El script evalúa fallos SSH (`SOC-AUTH-001`) y escaneos HTTP 401/403/404 (`SOC-WEB-002`), emitiendo alertas normalizadas en formato JSON.

**Paso 1:** Ejecutar el analizador sobre las muestras de autenticación SSH y acceso web incluidas en `laboratorios/muestras/`.

```bash
python3 laboratorios/analizador_logs_soc.py laboratorios/muestras/auth_ssh_simulado.log
python3 laboratorios/analizador_logs_soc.py laboratorios/muestras/web_access_simulado.log
```

**Paso 2:** Inspeccionar las alertas JSON emitidas (con el umbral por defecto `5` para SSH y `umbral * 3 = 15` para HTTP 4xx).

```json
{
  "archivo": "laboratorios/muestras/auth_ssh_simulado.log",
  "total_alertas": 1,
  "alertas": [
    {
      "regla": "SOC-AUTH-001",
      "severidad": "media",
      "tactica_mitre": "Credential Access",
      "ip_origen": "198.51.100.42",
      "intentos_fallidos": 7,
      "usuarios_distintos": [
        "admin",
        "admin_lab",
        "backup",
        "deploy",
        "oracle",
        "root",
        "test"
      ]
    }
  ]
}
```

```json
{
  "archivo": "laboratorios/muestras/web_access_simulado.log",
  "total_alertas": 1,
  "alertas": [
    {
      "regla": "SOC-WEB-002",
      "severidad": "media",
      "tactica_mitre": "Discovery",
      "ip_origen": "198.51.100.88",
      "respuestas_4xx": 15
    }
  ]
}
```

*(En la salida web real, `198.51.100.88` dispara `SOC-WEB-002` al acumular exactamente 15 respuestas `403`/`404` contra rutas administrativas como `/admin`, `/.env`, `/.git/config` y `/phpmyadmin`, mientras que el cliente legítimo `192.168.56.10` no genera falsos positivos).*

::: defensa Perspectiva defensiva, detección y mitigación
Para que un SIEM aporte valor sostenido en defensa:
- **Integridad de relojes:** Sincronizá todos los hosts mediante NTP en UTC; un desfase de minutos rompe las correlaciones basadas en ventanas (`transaction` o reglas EQL).
- **Retención y respaldo:** Aplicá permisos de solo lectura a los analistas sobre los índices históricos y verificá alertas de salud de agentes (*heartbeat*) para detectar equipos que dejaron de reportar logs.
- **Respuesta acoplada:** Cada alerta de alta fidelidad (como fuerza bruta exitosa o alta no autorizada de cuenta privilegiada) debe asociarse a un procedimiento claro de bloqueo de cuenta y revisión de sesiones activas.
:::

## Práctica en laboratorio local

Levantá una instancia local de pruebas (por ejemplo, Splunk Free o Elastic Stack en Docker dentro de tu red Host-Only) o utilizá un conjunto de logs exportados de tus VMs del Capítulo 4.2 junto con `laboratorios/analizador_logs_soc.py`. Simulá de forma benigna tres eventos: varios intentos fallidos de acceso seguidos de un ingreso válido, un comando PowerShell benigno con `-NoProfile` y un grupo de peticiones `404` contra tu servidor web local.

::: practica Entregable mínimo
Entregá un archivo `consultas_siem_lab.md` que incluya:
1. Tabla con al menos 4 campos mapeados entre el log crudo de tu laboratorio, CIM y ECS.
2. Dos consultas probadas (una en SPL y su equivalente en KQL) con una captura o salida resumida de resultados.
3. La salida ejecutada de `laboratorios/analizador_logs_soc.py` sobre un `access.log` generado en tu laboratorio.
4. Una propuesta concreta de afinado (*tuning*) para reducir al menos un falso positivo identificado.
:::

## Preguntas de repaso

**1. ¿Por qué son indispensables los esquemas de normalización como CIM (Splunk) y ECS (Elastic) en un SIEM?** Porque permiten escribir una sola regla de detección o tablero reutilizable sobre campos estandarizados (`source.ip`, `user.name`), sin depender del formato propietario de cada firewall, servidor o endpoint.

**2. ¿Qué diferencia práctica existe entre `stats` y `transaction` en Splunk SPL?** `stats` agrega eventos de forma muy eficiente en memoria y escala bien en grandes volúmenes, mientras que `transaction` agrupa eventos relacionados en el tiempo dentro de una misma sesión o secuencia, pero consume más recursos y debe usarse tras filtrar al máximo.

**3. ¿Por qué conviene combinar conteo de errores HTTP con diversidad de rutas (`dc(uri_path)`) al detectar anomalías web?** Porque un cliente con una aplicación mal configurada puede repetir 100 errores contra la misma URL, mientras que una exploración de directorios o vulnerabilidades suele tocar decenas de rutas diferentes en poco tiempo.

**4. ¿Qué riesgo introduce el desfase horario entre servidores que envían logs al SIEM?** Impide reconstruir la línea de tiempo real de un incidente y hace fallar las reglas de correlación secuencial (por ejemplo, detectar fallos seguidos de un inicio de sesión exitoso dentro de una ventana de pocos minutos).

**5. ¿Cuál es la forma recomendada de gestionar excepciones durante el afinado (tuning) de alertas?** Centralizar entidades autorizadas (cuentas de servicio, escáneres internos, equipos de administración) en tablas *lookup* auditadas y con fecha de revisión, en lugar de incrustar exclusiones sueltas difíciles de mantener.

## Antes de avanzar

- [ ] Comprendés el flujo completo del SIEM: recolección, parsing, normalización, indexado y correlación.
- [ ] Sabés traducir una búsqueda con agregación entre Splunk SPL y Elastic KQL / ES|QL.
- [ ] Ejecutaste `laboratorios/analizador_logs_soc.py` sobre un archivo de logs local.
- [ ] Aplicaste criterios de afinado para distinguir actividad benigna de alertas accionables.

::: nota Puerta de salida
Con la telemetría de endpoints centralizada y correlacionada en el SIEM, el paso final de esta parte es sumar la perspectiva de red: inspección de paquetes con Wireshark/tshark, metadatos con Zeek y reglas IDS/IPS en Suricata.
:::

## Referencias y estándares abiertos

- Splunk Documentation — *Search Reference (SPL) & Common Information Model (CIM)*: https://docs.splunk.com/
- Elastic Documentation — *Elastic Common Schema (ECS), KQL & ES|QL (Elasticsearch Piped Query Language)*: https://www.elastic.co/guide/
- NIST Special Publication 800-92 — *Guide to Computer Security Log Management*: https://csrc.nist.gov/publications/detail/sp/800-92/final
- SigmaHQ — *Generic Signature Format for SIEM Systems*: https://sigmahq.io/
