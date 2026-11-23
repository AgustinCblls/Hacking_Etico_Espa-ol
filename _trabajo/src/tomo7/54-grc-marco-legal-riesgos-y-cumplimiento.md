::: nota Objetivo de la lección
Al finalizar este capítulo vas a dominar la arquitectura contractual y operativa de una auditoría de seguridad (MSA, NDA, RoE y protocolo stop-and-notify), aplicar metodologías cualitativas y cuantitativas de riesgos (SLE, ARO y ALE), diferenciar ISO/IEC 27001, NIST CSF 2.0, PCI-DSS v4.0.1, SOC 2, NIS2, DORA e ISO/IEC 42001, y comprender el mapa legal hispanohablante de privacidad, notificación de brechas (72 h GDPR frente a plazos de LATAM), divulgación responsable sin *Safe Harbor*, cadena de custodia y ruta profesional de certificaciones.
:::

Encontrar una vulnerabilidad crítica sirve de poco si se descubre fuera del alcance autorizado, sin cobertura contractual o sin capacidad para traducir el riesgo técnico a impacto de negocio y cumplimiento normativo. La disciplina de **Gobernanza, Riesgo y Cumplimiento (GRC)** conecta la práctica técnica de seguridad con la estrategia ejecutiva y el marco jurídico que protege tanto a la organización auditada como al equipo evaluador.

## Gobernanza, Riesgo y Cumplimiento en la práctica

Aunque suelen agruparse en una sigla, sus tres pilares cumplen funciones diferenciadas:

- **Gobernanza:** define *quién decide qué* y *cómo se rinde cuentas*. Abarca la estrategia de seguridad alineada al negocio, políticas corporativas, comités directivos y asignación presupuestaria.
- **Riesgo:** evalúa la incertidumbre sobre activos críticos para priorizar inversiones. No busca eliminar todo riesgo —algo económicamente inviable—, sino mantenerlo dentro del **apetito de riesgo** aprobado por la dirección.
- **Cumplimiento (*Compliance*):** demuestra con evidencia auditable la adhesión a leyes vigentes, contratos y estándares (como ISO 27001 o PCI-DSS).

::: aviso Cumplimiento no equivale a seguridad real
Superar una auditoría de cumplimiento acredita controles mínimos en una fecha puntual, pero no garantiza resiliencia frente a atacantes reales si las medidas operan solo en papel. Un programa maduro usa el cumplimiento como piso obligatorio y la gestión continua de riesgos como motor operativo.
:::

## Anatomía contractual real de una evaluación de seguridad

Antes de iniciar cualquier reconocimiento activo o campaña autorizada de *phishing*, todo servicio de hacking ético exige una cadena documental firmada por representantes legales facultados del cliente:

| Documento | Naturaleza | Contenido indispensable |
| :--- | :--- | :--- |
| **MSA** (*Master Services Agreement*) | Marco legal comercial | Responsabilidad civil, límites de indemnización, seguros, jurisdicción y propiedad intelectual. |
| **NDA** (*Non-Disclosure Agreement*) | Confidencialidad bilateral | Resguardo de hallazgos, credenciales vistas accidentalmente, topologías y datos personales. |
| **SOW** (*Statement of Work*) | Alcance de proyecto | Objetivos, metodología, cronograma, entregables (informes y *retest*) y honorarios. |
| **RoE** (*Rules of Engagement*) | **Contrato operativo técnico** | IPs/dominios exactos, exclusiones, ventanas horarias, límites de prueba y protocolo *stop-and-notify*. |
| **Carta de autorización** | Respaldo frente a terceros | Autorización escrita breve firmada por un directivo para presentar ante ISPs, nube o vigilancia física. |

### Cláusulas esenciales de las Reglas de Enfrentamiento (RoE)

El **RoE** regula la ejecución técnica día a día para evitar incidentes no deseados:

1. **Alcance exacto (*In-Scope* y *Out-of-Scope*):** rangos IP/CIDR, dominios, APIs o sedes físicas autorizadas, junto con exclusiones explícitas (entornos OT sensibles, terceros SaaS sin permiso o sistemas médicos productivos).
2. **Ventanas horarias y coordinación:** franjas permitidas para pruebas potencialmente intrusivas (por ejemplo, de 02:00 a 05:00 hora local) y contactos de emergencia 24/7 con el SOC/NOC.
3. **Límites de prueba:** prohibición explícita de ataques DoS/DDoS, límites sobre ingeniería social, prohibición de modificar datos productivos o exfiltrar información confidencial real (limitándose a metadatos mínimos de prueba de concepto) y limpieza de cuentas o artefactos temporales al finalizar.
4. **Protocolo *Stop-and-Notify*:** obliga al auditor a detener la prueba sobre el activo involucrado y notificar de inmediato al contacto de emergencia en dos situaciones críticas:
   - **Hallazgo crítico de riesgo inminente:** por ejemplo, una base de datos productiva expuesta sin autenticación o riesgo inmediato de caída operativa.
   - **Evidencia de brecha activa previa:** si observás *webshells* ajenas, tareas maliciosas o rastros de *ransomware* ya presentes, debés **suspender toda acción invasiva sobre ese sistema**, no alterar logs ni archivos, preservar la evidencia observada y avisar al instante para activar al equipo de respuesta a incidentes (CSIRT).

## Gestión y cuantificación de riesgos

La evaluación de riesgos vincula cuatro elementos: un **Activo** valioso expuesto a una **Amenaza** capaz de explotar una **Vulnerabilidad**, produciendo un **Impacto** de negocio.

### Análisis cualitativo vs. análisis cuantitativo (SLE / ARO / ALE)

- **Análisis cualitativo:** puntúa probabilidad e impacto en escalas ordinales (1 a 4 o *Bajo / Medio / Alto / Crítico*) mediante una **matriz de probabilidad × impacto**. Es ágil para priorizar remediaciones técnicas diarias, aunque introduce cierta subjetividad.
- **Análisis cuantitativo:** expresa la exposición en dinero y frecuencia anual para justificar inversiones ante finanzas y directorio:
  - **AV (*Asset Value*):** valor económico total del activo (reemplazo, parada y multas).
  - **EF (*Exposure Factor*):** proporción del activo perdida ante el incidente (`0.0` a `1.0`).
  - **SLE (*Single Loss Expectancy*):** pérdida esperada por un solo evento: `SLE = AV * EF`.
  - **ARO (*Annualized Rate of Occurrence*):** frecuencia anual estimada de ocurrencia (ej. `0.25` = una vez cada 4 años).
  - **ALE (*Annualized Loss Expectancy*):** pérdida anualizada esperada: `ALE = SLE * ARO`.

Ejemplo práctico: una plataforma de ventas tiene un valor `AV = USD 500.000`. Una brecha masiva comprometería el `40 %` de su valor (`EF = 0.40`), resultando en `SLE = 500.000 * 0.40 = USD 200.000`. Con una frecuencia estimada de una vez cada 4 años (`ARO = 0.25`), la pérdida anual esperada sin controles adicionales es `ALE_antes = 200.000 * 0.25 = USD 50.000`. Si un control (respaldo inmutable + MFA + EDR) cuesta `ACS = USD 18.000` al año y reduce el `ARO` a `0.05` (una vez cada 20 años), la pérdida baja a `ALE_despues = 200.000 * 0.05 = USD 10.000`, generando un beneficio neto anual de `50.000 - 10.000 - 18.000 = USD 22.000`.

| Matriz cualitativa | Impacto Bajo (1) | Impacto Medio (2) | Impacto Alto (3) | Impacto Crítico (4) |
| :--- | :--- | :--- | :--- | :--- |
| **Probabilidad Muy Alta (4)** | Medio (4) | Alto (8) | Crítico (12) | Crítico (16) |
| **Probabilidad Alta (3)** | Bajo (3) | Medio (6) | Alto (9) | Crítico (12) |
| **Probabilidad Media (2)** | Bajo (2) | Medio (4) | Medio (6) | Alto (8) |
| **Probabilidad Baja (1)** | Bajo (1) | Bajo (2) | Bajo (3) | Medio (4) |

### Opciones de tratamiento del riesgo

1. **Mitigar:** implementar controles técnicos u organizativos para reducir probabilidad o impacto.
2. **Transferir:** contratar ciberseguros o pactar SLAs con terceros (recordando que la responsabilidad legal frente al regulador nunca se transfiere).
3. **Evitar:** desactivar el servicio obsoleto o eliminar el proceso riesgoso.
4. **Aceptar:** asumir conscientemente el riesgo cuando mitigar cuesta más que el `ALE` o existe una excepción temporal; exige obligatoriamente **firma formal de la alta dirección** o dueño del riesgo con fecha de revisión.

### Metodologías de riesgo, CIS Controls v8.1, terceros y Continuidad de Negocio

- **Metodologías de riesgo complementarias:** junto al cálculo `SLE/ARO/ALE`, las organizaciones emplean **ISO/IEC 27005** (gestión formal de riesgos ligada a ISO 27001), **MAGERIT** (metodología abierta de referencia en administraciones públicas hispanohablantes basada en activos, amenazas y salvaguardas) y **FAIR** (*Factor Analysis of Information Risk*, cuantificación probabilística por rangos y frecuencia de eventos de pérdida).
- **CIS Controls v8.1, terceros y concienciación:** **CIS Critical Security Controls v8.1** agrupa 18 controles priorizados en tres *Implementation Groups* (`IG1` higiene básica obligatoria, `IG2` mediana complejidad e `IG3` alta madurez); la gobernanza moderna exige además evaluación continua de **riesgo de terceros (TPRM / *supply chain*)** y métricas continuas de **concienciación** (tasa de reporte al SOC).

| Concepto de Continuidad (**ISO 22301**) | Definición operativa | Impacto en arquitectura técnica |
| :--- | :--- | :--- |
| **`BIA`** (*Business Impact Analysis*) | Identifica procesos críticos de negocio y cuánto cuesta cada hora de interrupción. | Prioriza qué sistemas reciben respaldos inmutables y redundancia primero. |
| **`RTO`** (*Recovery Time Objective*) | **Tiempo máximo tolerable de caída** desde el incidente hasta restaurar el servicio. | Define nivel de automatización de recuperación (*failover*, *IaC*, en frío vs. caliente). |
| **`RPO`** (*Recovery Point Objective*) | **Pérdida máxima admisible de datos** medida hacia atrás en tiempo desde la falla. | Fija la frecuencia mínima de *snapshots* y replicación (p. ej. cada 15 min o 24 h). |

## Principales marcos de cumplimiento: ISO 27001, NIST CSF 2.0 y PCI-DSS v4.0.1

### ISO/IEC 27001 (Edición 2022)

Estándar internacional certificable para un **SGSI (*Sistema de Gestión de Seguridad de la Información*)**. Combina cláusulas obligatorias (4 a 10, basadas en el ciclo de mejora continua PDCA, contexto, liderazgo y gestión de riesgos) con la **Declaración de Aplicabilidad (SoA)** y los **93 controles del Anexo A**, agrupados en cuatro temáticas: **Organizacionales (37)**, **Personas (8)**, **Físicos (14)** y **Tecnológicos (34)**.

### NIST Cybersecurity Framework (CSF 2.0)

Marco voluntario del NIST basado en resultados, perfiles (*Profiles*) y niveles (*Tiers*). En su versión **2.0** (2024) amplió su alcance a todo tipo de organizaciones e incorporó la función transversal **Govern (GV)** sobre las cinco funciones operativas clásicas: **Identify (ID)**, **Protect (PR)**, **Detect (DE)**, **Respond (RS)** y **Recover (RC)**.

### PCI-DSS v4.0.1

Estándar contractual obligatorio para toda entidad que almacene, procese o transmita datos de tarjetas de pago dentro del **CDE (*Cardholder Data Environment*)**. Se estructura en **12 requisitos** en 6 objetivos. La versión **v4.0.1** introduce el **Enfoque Personalizado (*Customized Approach*)** y aclara los requisitos que pasaron a regir de forma obligatoria el **31/03/2025** (*future-dated requirements*), incluyendo **MFA para todo acceso al CDE** y controles estrictos de integridad y autorización de scripts JavaScript en páginas de pago web (requisitos 6.4.3 y 11.6.1) para frenar ataques de *e-skimming*.

| Marco / Norma | Enfoque principal | Estructura clave | Certificación / Evaluación |
| :--- | :--- | :--- | :--- |
| **ISO/IEC 27001:2022** | SGSI integral basado en riesgos | Cláusulas 4–10 + 93 controles Anexo A + SoA | Certificable por organismo acreditado |
| **NIST CSF 2.0** | Lenguaje común y madurez por resultados | 6 funciones: *Govern, Identify, Protect, Detect, Respond, Recover* | Marco de referencia flexible (no certificable) |
| **PCI-DSS v4.0.1** | Protección de datos de tarjetas (CDE) | 12 requisitos; requisitos *future-dated* obligatorios desde 31/03/2025 (MFA, 6.4.3, 11.6.1) | Auditoría anual QSA o cuestionario SAQ |

### Marcos GRC complementarios clave en 2026

En entornos corporativos SaaS, financieros, europeos y basados en IA, los auditores y equipos *Purple Team* deben mapear sus controles técnicos y reportes ejecutivos contra cuatro marcos adicionales de adopción prioritaria:

| Marco / Regulación | Alcance y propósito | Requisitos o pilares clave | Evidencia y plazos críticos |
| :--- | :--- | :--- | :--- |
| **SOC 2** (*AICPA TSC*) | Confianza en proveedores SaaS y servicios cloud | Evalúa hasta 5 *Trust Services Criteria*: **Security** (obligatorio), **Availability**, **Processing Integrity**, **Confidentiality** y **Privacy**. | **Tipo I** (diseño de controles en fecha puntual) vs. **Tipo II** (eficacia operativa continua durante 3–12 meses). |
| **Directiva NIS2** (UE) | Ciberseguridad de infraestructura crítica europea | Aplica a **entidades esenciales e importantes**; exige gestión de riesgos en cadena de suministro, MFA, cifrado y responsabilidad directa de la dirección. | **Reporte en fases**: alerta temprana en **24 h**, notificación detallada del incidente en **72 h** e informe final al mes. |
| **Reglamento DORA** (UE) | Resiliencia operativa digital del sector financiero | Regula bancos, aseguradoras, *fintech* y proveedores TIC críticos; unifica gestión de riesgos TIC, pruebas de resiliencia y supervisión de terceros. | Exige pruebas avanzadas guiadas por amenazas (**TLPT** / *Red Teaming* periódico) y reporte estricto de incidentes mayores. |
| **ISO/IEC 42001** | Sistema de Gestión de Inteligencia Artificial (AIMS) | Primer estándar certificable para gobernanza de IA: inventario de modelos, evaluación de sesgos, transparencia, trazabilidad de datos y seguridad de *pipelines*. | Certificable por organismo acreditado bajo estructura análoga a ISO 27001 (PDCA + controles de ciclo de vida de IA). |
| **EU Cyber Resilience Act (`CRA`)** | Seguridad de productos con elementos digitales (hardware/software en UE) | Exige diseño seguro por defecto, SBOM, actualizaciones de seguridad durante el ciclo de soporte y marcado CE. | **Reporte obligatorio** de vulnerabilidades explotadas activamente e incidentes graves desde el **11/09/2026** (`24 h` / `72 h`); cumplimiento pleno desde **11/12/2027**. |
| **EU AI Act** (`Reg. UE 2024/1689`) | Regulación europea de sistemas de Inteligencia Artificial por niveles de riesgo | Prohíbe prácticas de riesgo inaceptable, regula modelos fundacionales (**GPAI**) e impone auditoría estricta a sistemas de alto riesgo. | Prohibiciones vigentes desde **02/02/2025**, obligaciones **GPAI** desde **02/08/2025**, transparencia desde **02/08/2026** y despliegue escalonado de alto riesgo hacia **2027**. |

## Marco legal, privacidad, notificación de brechas y delitos informáticos

### Privacidad y delitos informáticos en España y Latinoamérica (mapa comparativo)

El **GDPR** europeo fijó el estándar de referencia en privacidad con siete principios centrales: **licitud, lealtad y transparencia**; **limitación de finalidad**; **minimización de datos**; **exactitud**; **limitación de conservación**; **integridad y confidencialidad**; y **responsabilidad proactiva (*accountability*)**, diferenciando entre **Responsable (*Controller*)** y **Encargado (*Processor*)**. En el ámbito penal internacional coexisten el **Convenio de Budapest** del Consejo de Europa y la **Convención de la ONU contra la Ciberdelincuencia** (adoptada por la Asamblea General mediante Res. 79/243 en diciembre de 2024 y abierta a firma en Hanoi en octubre de 2025, sujeta a ratificación para su entrada en vigor).

| Jurisdicción | Marco de privacidad / ciberseguridad | Delitos informáticos y notas clave para auditores |
| :--- | :--- | :--- |
| **España** | **GDPR (UE) + LOPDGDD (LO 3/2018)** + **ENS** | **Código Penal arts. 197 bis/ter y 264 bis/ter**: los **arts. 197 ter y 264 ter** penan producir, adquirir o facilitar herramientas o credenciales específicamente concebidas o adaptadas **con intención de cometer los delitos** de acceso o daño; el contrato RoE previo acredita uso técnico legítimo. |
| **Argentina** | **Ley 25.326** (AAIP, adecuación UE) | **Ley 26.388** (reforma el Código Penal en acceso ilegítimo, interceptación y daño informático) y **Ley 27.411** (adhesión formal al **Convenio de Budapest**). |
| **México** | **Nueva LFPDPPP (2025)** — autoridad: **Secretaría Anticorrupción y Buen Gobierno** (reemplazó al extinto INAI) | **Código Penal Federal arts. 211 bis 1 a 211 bis 7** (acceso ilícito a sistemas y equipos informáticos, con agravantes por infraestructura pública o financiera). |
| **Colombia** | **Ley 1581 de 2012** (SIC) | **Ley 1273 de 2009** (*De la protección de la información y de los datos*: tipifica acceso abusivo, obstaculización ilegítima, suplantación web e interceptación). |
| **Chile** | **Ley Marco de Ciberseguridad 21.663** (ANCI) y **Ley 21.719** (fecha legal de vigencia estipulada en su art. 1.º transitorio: **1 de diciembre de 2026**) | **Ley 21.459** sobre delitos informáticos (alineada al Convenio de Budapest: acceso ilícito, ataque a la integridad de sistemas y datos, receptación). |
| **Perú** | **Ley 29733** de Protección de Datos Personales | **Ley 30096** de Delitos Informáticos (y modificatoria Ley 30171 sobre acceso ilícito, atentado a la integridad de datos y fraude informático). |

### Plazos de notificación de brechas: 72 horas en GDPR frente a plazos regionales

Es un error frecuente suponer que el plazo de **72 horas** rige de manera universal:

- **Unión Europea (GDPR Art. 33 y NIS2):** exige notificar brechas de datos con riesgo a la autoridad supervisora dentro de un máximo de **72 horas** desde que se toma conocimiento (y a los afectados si hay alto riesgo, Art. 34). En **NIS2**, las entidades esenciales e importantes reportan alerta temprana en **24 h**, evaluación inicial en **72 h** e informe final al mes.
- **Latinoamérica (plazos variables según país):** cada país fija plazos propios. Por ejemplo, en **Brasil (LGPD / ANPD)** el plazo reglamentario general es de **3 días hábiles**; en **Chile**, la **Ley Marco 21.663** impone alerta temprana en **3 horas** para incidentes con impacto significativo en servicios esenciales; y otras leyes nacionales combinan términos reglamentarios específicos u obligación "sin dilación indebida".

### Cadena de custodia, delitos informáticos y divulgación sin *Safe Harbor*

Cuando ocurre un incidente o se halla evidencia de intrusión ajena durante una auditoría, la preservación forense determina su validez legal:

- **Cadena de custodia:** registro cronológico e ininterrumpido de recolección, traslado, resguardo y análisis de evidencia digital (volcados de memoria, imágenes de disco, logs). Exige copias bit a bit de solo lectura, cálculo inmediato de hash **SHA-256** y control estricto de acceso.
- **Frontera legal (*autorización escrita*):** la **autorización previa, escrita y delimitada** del legítimo titular es el límite exacto entre una evaluación ética y un delito penal.

::: peligro Divulgación fuera de Bug Bounty y ausencia de Safe Harbor en LATAM
En casi ningún país de Latinoamérica existe una cláusula legal automática de ***Safe Harbor*** (puerto seguro) que proteja al investigador que prueba sistemas ajenos sin contrato ni programa público de recompensas con alcance explícito. Si advertís de manera pasiva una exposición accidental sin autorización previa: **detenete de inmediato**, no descargues ni manipules registros, no exijas pago o recompensa (puede encuadrarse como extorsión) y canalizá el aviso de forma neutral mediante el contacto oficial (`security.txt` / `security@`) o el **CSIRT nacional** (*CERT.ar*, *CSIRT.gob.cl*, *colCERT*, *INCIBE-CERT*), evaluando asesoría legal antes de publicar detalles.
:::

## Inserción laboral: portafolio demostrable y entrevistas técnicas

Completar los siete tomos de esta biblioteca cubre la teoría de entrada e intermedia del mercado; convertir ese conocimiento en un primer empleo (**Analista SOC L1/L2**, **AppSec Junior**, **Pentester Junior** o **Cloud Security Junior**) depende de demostrar criterio práctico y comunicación clara con equipos reales.

### Cómo armar un portafolio ético y verificable

Los selectores técnicos priorizan evidencia observable de cómo trabajás por encima de listados de herramientas en el currículum:

1. **Repositorio público limpio (GitHub / blog técnico):** publicá utilidades defensivas o de automatización propias, reglas **Sigma / YARA / Suricata** probadas contra bitácoras ficticias creadas por vos y guías técnicas sobre aplicaciones intencionalmente vulnerables en laboratorio local (*OWASP Juice Shop*, *DVWA*) o máquinas **retiradas** (nunca publiques soluciones de máquinas o retos activos ni datos confidenciales de terceros).
2. **Muestras reales de documentación:** incluí uno o dos reportes anónimos de laboratorio redactados con [`plantilla_informe_pentest.md`](../laboratorios/plantilla_informe_pentest.md) o [`plantilla_informe_incidente.md`](../laboratorios/plantilla_informe_incidente.md), mostrando que sabés traducir un problema técnico en pasos de mitigación accionables.
3. **Resolución de tickets y trato con desarrollo:** en roles corporativos (especialmente AppSec y SOC), gran parte del trabajo diario ocurre en *Jira/Linear*, revisiones de *Pull Requests* y coordinación con infraestructura; explicá cada hallazgo con empatía técnica y parches concretos en lugar de limitarte a señalar fallos.

### Qué evalúan en entrevistas técnicas por rol (guía de preparación)

| Rol objetivo | Escenario clásico de entrevista técnica | Qué esperan escuchar en tu respuesta |
| :--- | :--- | :--- |
| **Analista SOC L1/L2** | *"Te llega una alerta con `winword.exe` lanzando `powershell.exe -enc ...` y una conexión saliente. ¿Qué hacés paso a paso?"* | Triage ordenado: verificar `4104` (Script Block ya desofuscado), `Sysmon 3/22` (IP/dominio destino), usuario/equipo afectado, diferenciar falso positivo (script firmado de IT) de verdadero positivo, aislar host antes de reiniciar para preservar RAM y escalar según NIST SP 800-61. |
| **AppSec / Web Junior** | *"Encontramos un IDOR o una SQLi en un endpoint de pagos. ¿Cómo la reproducís y cómo la arreglás?"* | Reproducir mínimo en Burp/`curl` (sin dañar datos), explicar causa raíz (falta de control de propietario o concatenación SQL), proponer corrección precisa en código (`WHERE id = ? AND owner_id = ?` o consultas parametrizadas) y test de regresión en CI. |
| **Pentester / Cloud Junior** | *"Ves abierto un servidor web y SMB, o una cuenta AWS con `iam:PassRole`. ¿Cómo razonás tu metodología?"* | Enumeración metódica antes de explotar, toma de notas reproducible, manejo de falsos positivos, respeto de alcance (*Stop-and-Notify* ante riesgo productivo) y priorización de riesgo combinando probabilidad e impacto real. |

### Mapa de certificaciones prácticas y plataformas de práctica (CTFs)

Ningún certificado reemplaza el criterio técnico ni la experiencia verificable, pero una hoja de ruta ordenada ayuda a validar conocimientos prácticos por perfil:

| Certificación | Nivel y orientación | Qué demuestra en la práctica |
| :--- | :--- | :--- |
| **`eJPT`** (INE) | Inicial · *Red / Pentest Junior* | Fundamentos reales de enumeración de redes, servicios web básicos y evaluación guiada en entorno de laboratorio. |
| **`BTL1`** (*Security Blue Team*) | Inicial / Intermedio · *Blue Team / SOC* | Examen práctico de 24 h resolviendo incidentes reales con SIEM, análisis de phishing, forense, YARA y detección de amenazas. |
| **`CPTS`** (*Hack The Box*) | Intermedio / Avanzado · *Pentest* | Evaluación exhaustiva de múltiples días sobre Web, pivoting y Active Directory junto con un informe profesional completo. |
| **`OSCP+`** (*OffSec*) | Intermedio / Avanzado · *Pentest* | Examen práctico cronometrado de 24 h enfocado en explotación manual, escalada de privilegios y compromiso de Active Directory. |
| **`CRTO`** (*Zero-Point Security*) | Avanzado · *Red Team / Purple* | Operación en dominio Active Directory con énfasis en **OPSEC**, evasión de detección, delegación/ADCS y control C2 realista. |

- **Plataformas y CTFs recomendados:** combiná **TryHackMe** (rutas guiadas iniciales), **PortSwigger Web Security Academy** (laboratorios web gratuitos), **Hack The Box** (máquinas retiradas para AD e infraestructura), **LetsDefend** / **CyberDefenders** (laboratorios SOC y DFIR) y competencias abiertas en **OverTheWire** o **CTFtime**.

## Práctica guiada en laboratorio

En esta práctica vas a integrar un RoE operativo, un cálculo cuantitativo de riesgo y un protocolo inicial de brecha y cadena de custodia sobre un caso simulado.

1. **Escenario:** auditás la plataforma `tienda.ejemplo.local` (`198.51.100.0/26`), valorada en **USD 400.000** (`AV`), que procesa pagos mediante un proveedor externo tokenizado pero almacena datos personales de 80.000 clientes.
2. **Alcance y *Stop-and-Notify*:** redactá la tabla *In-Scope / Out-of-Scope* del RoE (excluyendo expresamente la pasarela externa) y definí los pasos de *stop-and-notify* si descubrís un script de *e-skimming* ya implantado por un tercero.
3. **Cálculo cuantitativo:** calculá `SLE` y `ALE_antes` con `EF = 0.50` y `ARO = 0.20`, y evaluá el beneficio neto de un control anual de `ACS = USD 14.000` que reduce el `ARO` a `0.04`.
4. **Notificación y SHA-256:** listá los 5 datos mínimos del reporte preliminar a 72 horas ante la autoridad de datos y escribí el procedimiento para generar y registrar el hash SHA-256 de los logs preservados.

::: practica Entregable mínimo
Entregá un documento de GRC (2 páginas) con: (a) matriz de alcance y cláusula *Stop-and-Notify* del RoE; (b) desarrollo numérico completo de `SLE`, `ALE_antes`, `ALE_despues` y ahorro neto en USD; y (c) checklist de cadena de custodia con SHA-256 y borrador de notificación a 72 horas.
:::

::: defensa Perspectiva defensiva y gobernanza
Gobernar la seguridad digital implica combinar rigor técnico con respaldo contractual y normativo. Exigí siempre la cadena **MSA + NDA + SOW + RoE firmado** antes de auditar; traducí hallazgos mediante matrices cualitativas y análisis **SLE/ARO/ALE**; articulá controles con **ISO/IEC 27001**, **NIST CSF 2.0** (iniciando por su función transversal *Govern*) y **PCI-DSS v4.0** cuando corresponda; documentá toda excepción mediante aceptación formal firmada por dirección; y ensayá periódicamente el manejo de **cadena de custodia** y notificaciones legales en **72 horas**.
:::

## Preguntas de repaso

**1. ¿Qué papel cumple el documento Rules of Engagement (RoE) frente al MSA y el NDA, y qué activa la cláusula Stop-and-Notify?** El MSA fija el marco legal comercial y el NDA la confidencialidad, mientras que el RoE define los límites técnicos operativos (IPs, dominios, horarios, exclusiones y técnicas permitidas); la cláusula *Stop-and-Notify* obliga a detener las pruebas y notificar de inmediato al cliente ante un riesgo crítico inminente, una caída operativa o evidencia de una brecha activa previa, preservando artefactos sin alterarlos.

**2. Dado un activo con AV = USD 300.000, EF = 0.30 y ARO = 0.50, ¿cuánto valen su SLE y su ALE, y qué ventaja aporta frente al análisis cualitativo?** Su `SLE` es `300.000 * 0.30 = USD 90.000` y su `ALE` es `90.000 * 0.50 = USD 45.000` anuales; frente a etiquetas cualitativas subjetivas, el cálculo `ALE` cuantifica la pérdida esperada en dinero para comparar directamente el retorno de un control contra su costo anual.

**3. ¿Cuáles son las cuatro opciones de tratamiento del riesgo y qué requisito exige la aceptación?** Las opciones son **mitigar**, **transferir** (sin delegar la responsabilidad legal), **evitar** y **aceptar**; aceptar un riesgo exige siempre una justificación formal documentada con **firma de la alta dirección** o dueño ejecutivo del riesgo y una fecha de vencimiento para reevaluación.

**4. ¿Cómo se diferencian ISO/IEC 27001, NIST CSF 2.0 y PCI-DSS v4.0?** ISO/IEC 27001 es una norma certificable enfocada en un SGSI y 93 controles del Anexo A; NIST CSF 2.0 es un marco flexible basado en resultados que incorpora la función transversal **Govern** sobre *Identify, Protect, Detect, Respond y Recover*; y PCI-DSS v4.0 es un estándar obligatorio para entornos con datos de tarjetas (CDE) que suma MFA obligatorio y control de integridad de scripts en páginas de pago.

**5. ¿Cuál es el plazo general de notificación de brechas ante la autoridad bajo el GDPR y por qué es crítica la cadena de custodia desde el inicio?** El Artículo 33 del GDPR fija un plazo máximo de **72 horas** desde que se tiene constancia de la brecha (y aviso a los afectados si existe alto riesgo); mantener la cadena de custodia mediante copias bit a bit, hashes SHA-256 y registro de accesos preserva la validez jurídica de la evidencia frente a reguladores y procesos penales por delitos informáticos.

## Antes de avanzar

::: nota Puerta de salida
Con este capítulo completaste el núcleo regulatorio del Tomo VII. Antes de avanzar al **Capítulo 7.8 (Anexo Técnico · Seguridad en IA, Modelos de Lenguaje y Agentes)**, verificá que puedas redactar el alcance y el protocolo *Stop-and-Notify* de un RoE, calcular el retorno de un control con SLE/ARO/ALE, distinguir ISO 27001, NIST CSF 2.0, PCI-DSS v4.0, SOC 2, NIS2/DORA e ISO/IEC 42001, y explicar el flujo de notificación a 72 horas y cadena de custodia.
:::

## Referencias y estándares abiertos

- Normas **ISO/IEC 27001:2022** e **ISO/IEC 27002:2022**.
- **NIST Cybersecurity Framework (CSF) 2.0** (2024) y **NIST SP 800-30 Rev. 1**.
- **PCI Security Standards Council**: *PCI DSS v4.0 / v4.0.1*.
- Reglamento (UE) 2016/679 (**GDPR**), **LOPDGDD** (España), **Ley 25.326** (Argentina), **LGPD** (Brasil) y **Convenio de Budapest** sobre Ciberdelincuencia.
- **NIST SP 800-86** (*Guide to Integrating Forensic Techniques into Incident Response*).
