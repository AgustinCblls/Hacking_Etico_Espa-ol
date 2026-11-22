::: nota Objetivo de la lección
Al finalizar este capítulo vas a dominar la arquitectura contractual y operativa de una auditoría de seguridad (MSA, NDA, RoE y protocolo stop-and-notify), aplicar metodologías cualitativas y cuantitativas de riesgos (SLE, ARO y ALE), diferenciar ISO/IEC 27001, NIST CSF 2.0 y PCI-DSS v4.0, y comprender las obligaciones legales de privacidad, notificación de brechas en 72 horas, cadena de custodia y delitos informáticos en Europa y Latinoamérica.
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

## Principales marcos de cumplimiento: ISO 27001, NIST CSF 2.0 y PCI-DSS v4.0

### ISO/IEC 27001 (Edición 2022)

Estándar internacional certificable para un **SGSI (*Sistema de Gestión de Seguridad de la Información*)**. Combina cláusulas obligatorias (4 a 10, basadas en el ciclo de mejora continua PDCA, contexto, liderazgo y gestión de riesgos) con la **Declaración de Aplicabilidad (SoA)** y los **93 controles del Anexo A**, agrupados en cuatro temáticas: **Organizacionales (37)**, **Personas (8)**, **Físicos (14)** y **Tecnológicos (34)**.

### NIST Cybersecurity Framework (CSF 2.0)

Marco voluntario del NIST basado en resultados, perfiles (*Profiles*) y niveles (*Tiers*). En su versión **2.0** (2024) amplió su alcance a todo tipo de organizaciones e incorporó la función transversal **Govern (GV)** sobre las cinco funciones operativas clásicas: **Identify (ID)**, **Protect (PR)**, **Detect (DE)**, **Respond (RS)** y **Recover (RC)**.

### PCI-DSS v4.0

Estándar contractual obligatorio para toda entidad que almacene, procese o transmita datos de tarjetas de pago dentro del **CDE (*Cardholder Data Environment*)**. Se estructura en **12 requisitos** en 6 objetivos. La versión **v4.0** introduce el **Enfoque Personalizado (*Customized Approach*)**, exige **MFA para todo acceso al CDE** e incorpora requisitos críticos de integridad y autorización de scripts JavaScript en páginas de pago web (requisitos 6.4.3 y 11.6.1) para frenar ataques de *e-skimming*.

| Marco / Norma | Enfoque principal | Estructura clave | Certificación / Evaluación |
| :--- | :--- | :--- | :--- |
| **ISO/IEC 27001:2022** | SGSI integral basado en riesgos | Cláusulas 4–10 + 93 controles Anexo A + SoA | Certificable por organismo acreditado |
| **NIST CSF 2.0** | Lenguaje común y madurez por resultados | 6 funciones: *Govern, Identify, Protect, Detect, Respond, Recover* | Marco de referencia flexible (no certificable) |
| **PCI-DSS v4.0** | Protección de datos de tarjetas (CDE) | 12 requisitos; foco en segmentación, MFA y scripts de pago | Auditoría anual QSA o cuestionario SAQ |

## Marco legal, privacidad, notificación de brechas y delitos informáticos

### GDPR y principios equivalentes en España y Latinoamérica

El **GDPR** europeo fijó el estándar de referencia en privacidad con siete principios centrales: **licitud, lealtad y transparencia**; **limitación de finalidad**; **minimización de datos**; **exactitud**; **limitación de conservación**; **integridad y confidencialidad**; y **responsabilidad proactiva (*accountability*)**, diferenciando entre **Responsable (*Controller*)** y **Encargado (*Processor*)**.

En el mundo hispanohablante y regional convergen marcos equivalentes: **España** aplica el GDPR junto con la **LOPDGDD (Ley Orgánica 3/2018)** y el **Esquema Nacional de Seguridad (ENS)**; **Argentina** (Ley 25.326, autoridad AAIP) y **Uruguay** (Ley 18.331) cuentan con estatus de adecuación europea; **Brasil** aplica la **LGPD (Ley 13.709/2018)** ante la ANPD; **México** rige bajo la **LFPDPPP**; y **Chile** modernizó su régimen con la **Ley 21.719**, alineada al estándar europeo.

### Plazos estrictos de notificación: la regla de las 72 horas

El **Artículo 33 del GDPR** (replicado o tomado como referencia por legislaciones modernas de privacidad) exige notificar toda brecha de datos personales con riesgo potencial a la autoridad supervisora competente **sin dilación indebida y dentro de un plazo máximo de 72 horas** desde que la organización toma conocimiento. Si persiste un **alto riesgo** para las personas afectadas (por ejemplo, filtración en claro de datos financieros o contraseñas), debe notificarse además directamente a los titulares (Art. 34).

### Cadena de custodia y delitos informáticos

Cuando ocurre un incidente o se halla evidencia de intrusión ajena durante una auditoría, la preservación forense determina su validez legal:

- **Cadena de custodia:** registro cronológico e ininterrumpido de recolección, traslado, resguardo y análisis de evidencia digital (volcados de memoria, imágenes de disco, logs). Exige copias bit a bit de solo lectura, cálculo inmediato de hash **SHA-256** y control estricto de acceso.
- **Delitos informáticos:** las leyes penales alineadas al **Convenio de Budapest** (como los artículos 197 bis/ter y 264 del Código Penal español o los artículos 153 bis y 183 del Código Penal argentino) tipifican el acceso ilegítimo, la interceptación ilícita, el daño informático y el fraude. La **autorización previa, escrita y delimitada** del legítimo titular es la frontera exacta entre una auditoría ética y un delito penal.

::: peligro Prohibido operar bajo permisos verbales
Un mensaje informal o autorización verbal sin SOW/RoE firmado no brinda cobertura legal, especialmente sobre activos alojados en terceros o proveedores nube. Ante cualquier duda de alcance, detené las pruebas y solicitá confirmación escrita.
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
Con este capítulo completaste el Tomo VII. Verificá que puedas redactar el alcance y el protocolo *Stop-and-Notify* de un RoE, calcular el retorno de un control con SLE/ARO/ALE, distinguir ISO 27001, NIST CSF 2.0 y PCI-DSS v4.0, y explicar el flujo de notificación a 72 horas y cadena de custodia.
:::

## Referencias y estándares abiertos

- Normas **ISO/IEC 27001:2022** e **ISO/IEC 27002:2022**.
- **NIST Cybersecurity Framework (CSF) 2.0** (2024) y **NIST SP 800-30 Rev. 1**.
- **PCI Security Standards Council**: *PCI DSS v4.0 / v4.0.1*.
- Reglamento (UE) 2016/679 (**GDPR**), **LOPDGDD** (España), **Ley 25.326** (Argentina), **LGPD** (Brasil) y **Convenio de Budapest** sobre Ciberdelincuencia.
- **NIST SP 800-86** (*Guide to Integrating Forensic Techniques into Incident Response*).
