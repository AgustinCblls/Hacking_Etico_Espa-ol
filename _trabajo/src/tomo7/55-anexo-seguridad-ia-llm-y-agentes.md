::: nota Objetivo de la lección
Al finalizar este capítulo vas a comprender la arquitectura completa de una aplicación con IA generativa (prompt de sistema, usuario, RAG, herramientas/MCP y salida), dominar los diez riesgos del **OWASP Top 10 for LLM Applications** (incluyendo `LLM09` y `LLM10`) junto con el **OWASP Top 10 for Agentic Applications (`ASI01–ASI10`, diciembre 2025)**, evaluar modelos con herramientas de **AI Red Teaming (`garak`, `PyRIT`, `promptfoo`)** y auditar/endurecer flujos de **RAG + Tool Calling / MCP** en Python 3 tanto en modo simulado como contra **Ollama local**, alineando guardrails deterministas con **NIST AI RMF**, **MITRE ATLAS** e **ISO/IEC 42001**.
:::

**Prerrequisitos:** Tomo II (Seguridad Web y APIs), Tomo VI (White-Box Code Review y Threat Modeling) y Cap. 7.7 (GRC). **Duración sugerida:** 7 a 9 horas.

## 1. Superficie de ataque en aplicaciones con IA generativa

Un Modelo de Lenguaje Grande (**LLM**) por sí solo recibe texto y devuelve texto. El riesgo crítico de seguridad aparece cuando se lo conecta como motor de decisión dentro de una aplicación que ingiere documentos externos no confiables (**RAG**) e invoca acciones sobre bases de datos, APIs o sistemas operativos (**Agentes y Tool Calling / MCP**):

```text
+-------------------+       +--------------------------------------------+
| Usuario / Atacante| ----> | 1. Prompt del Sistema (Reglas e identidad) |
+-------------------+       +--------------------------------------------+
                                             |
+-------------------+                        v
| Corpus RAG / Web  | -----> [ 2. Contexto concatenado en el LLM ]
| Correos / Issues  |        (Frontera de confianza mixta: DATOS != CODIGO)
+-------------------+                        |
                                             v
                            +------------------------------------+
                            | 3. Motor LLM (Probabilístico)      |
                            +------------------------------------+
                                      |                   |
                 +--------------------+                   +--------------------+
                 v                                                             v
+---------------------------------+                           +---------------------------------+
| 4a. Salida al Cliente / Backend |                           | 4b. Tool Calling / Servidor MCP   |
| (Si va sin escapar -> XSS/SQLi) |                           | (API, BD, FS, Shell en Sandbox) |
+---------------------------------+                           +---------------------------------+
```

El error arquitectónico raíz equivale al que vimos en SQL Injection (Cap. 2.3): el LLM procesa en **un mismo canal lineal de tokens** las instrucciones confiables del desarrollador (*System Prompt*) y los datos no confiables de usuarios o documentos externos. Por eso, el modelo no ofrece una separación criptográfica entre código y datos.

## 2. OWASP Top 10 for LLM Applications y riesgos en agentes

### 2.1 Prompt Injection directa e indirecta (`LLM01`)

- **Inyección directa:** el usuario redacta instrucciones en el chat buscando anular el *System Prompt* o evadir restricciones (*jailbreaking*). Aunque los filtros de texto ayudan, ningún filtro basado solo en otro modelo probabilístico es infalible.
- **Inyección indirecta (la más peligrosa en producción):** el usuario hace una pregunta inocente (*"Resumí los correos recibidos hoy"* o *"Analizá esta página web"*), pero dentro del documento externo, correo, comentario de *pull request* o registro web recuperado se esconde una instrucción maliciosa dirigida al LLM. Si el agente tiene herramientas conectadas, esa carga externa puede intentar secuestrar su flujo de ejecución.

### 2.2 Improper Output Handling (`LLM05:2025`)

Tratar la respuesta de un LLM como si fuera texto seguro de confianza reintroduce vulnerabilidades web clásicas en la aplicación que consume esa salida:
- Si el frontend inserta la respuesta del LLM directamente en el DOM (`innerHTML` / `dangerouslySetInnerHTML`) sin escapar HTML, una inyección puede provocar **XSS**.
- Si el backend concatena código o consultas SQL generadas por el modelo directamente en `cursor.execute()` o `os.system()`, reaparecen **SQL Injection**, **SSRF** o **Command Injection**.
- **Regla estructural:** aplicá exactamente los mismos controles que para entrada de usuario no confiable: escape contextual en navegador, **consultas parametrizadas** y validación estricta por esquema antes de consumir cualquier salida del LLM.

### 2.3 Excessive Agency y seguridad en Tool Calling / MCP (`LLM06`)

Los protocolos modernos de conexión entre agentes y herramientas —como el **Model Context Protocol (`MCP`)**— permiten que un modelo descubra servidores externos y llame funciones con parámetros JSON. Sin barreras deterministas externas al modelo surgen tres fallas críticas:

1. ***Excessive Agency* (agencia excesiva):** otorgar al agente herramientas de escritura o borrado (`delete_user`, `run_sql`, `exec_shell`) cuando la tarea solo requería lectura acotada.
2. ***Tool Poisoning* y *Rug Pulls* en servidores MCP:** un servidor MCP de terceros comprometido puede ocultar instrucciones manipuladoras dentro de las descripciones de sus propias herramientas para desviar el comportamiento del agente hacia otras herramientas confiables del mismo host.
3. **Ausencia de verificación determinista:** confiar en que "el prompt dice que solo consulte su propio usuario". **Todo control de autorización, validación de argumentos (regex/tipos/esquemas) y confirmación humana (*Human-in-the-Loop*) debe vivir en código determinista fuera del LLM.**

### 2.4 Seguridad en RAG y fugas de datos sensibles (`LLM02` / `LLM08`)

En una arquitectura **RAG (*Retrieval-Augmented Generation*)**, los fragmentos recuperados desde una base vectorial se inyectan como contexto en el prompt. Los fallos más frecuentes ocurren por omisión de autorización previa o contaminación del índice:
- **Fuga multi-tenant / entre roles:** si el buscador vectorial busca solo por similitud semántica sin filtrar metadatos (`tenant_id`, `role`, `classification`) **antes** de entregar fragmentos al LLM, un empleado de Finanzas podría recuperar nóminas confidenciales de RRHH o documentos de otro cliente.
- **Envenenamiento del corpus RAG (*RAG Poisoning*):** un actor externo capaz de subir tickets, reseñas o documentos indexados puede plantar textos optimizados semánticamente para ser recuperados con alta frecuencia e inyectar respuestas falsas o enlaces de phishing.

### 2.5 Envenenamiento de datos, Supply Chain de modelos y System Prompts (`LLM03`, `LLM04`, `LLM07`)

| Riesgo en ciclo de vida IA | Mecanismo técnico observable | Mitigación verificable |
| :--- | :--- | :--- |
| **Supply Chain de pesos (`pickle`)** | Cargar modelos heredados `.pkl`/`.pt` ejecuta deserialización Python arbitraria al cargar los pesos en memoria. | Exigir formato seguro **`safetensors`**, verificar hashes SHA-256 publicados y firmas criptográficas antes de cargar modelos. |
| **Envenenamiento de entrenamiento (*Data Poisoning*)** | Incorporar muestras adulteradas o etiquetas manipuladas en el *fine-tuning* para implantar sesgos o disparadores (*backdoors*). | Auditar procedencia (*data lineage*), validar integridad de datasets y evaluar modelos contra conjuntos de prueba limpios. |
| **Fuga de *System Prompt* (`LLM07`)** | Consultar el contexto inicial del modelo mediante técnicas de reformulación o traducción. | **Nunca guardar secretos, claves API, URLs privadas ni reglas de autorización exclusivas dentro del *System Prompt***: asumilo público por diseño. |

*(Complemento de seguridad ML clásica: en clasificadores supervisados también existen ataques adversarios de **evasión** —pequeñas perturbaciones diseñadas para cruzar fronteras de decisión— e **inversión/extracción de modelo** mediante consultas masivas; se mitigan con limitación de tasa, redondeo de probabilidades devueltas y entrenamiento adversario).*

### 2.6 Misinformation (`LLM09:2025`) y Unbounded Consumption (`LLM10:2025`)

- **Desinformación y alucinaciones (`LLM09:2025 — Misinformation`):** los LLMs predicen tokens probables y pueden fabricar con aparente seguridad citas legales falsas, diagnósticos incorrectos o nombres inexistentes de librerías (`pip`/`npm`) y comandos. Esto origina incluso riesgos de *slopsquatting*: un atacante registra paquetes maliciosos en PyPI/npm usando nombres que los LLMs suelen inventar repetidamente. **Mitigación:** exigir *grounding* RAG con enlaces verificables al documento fuente, validar existencia y hashes antes de instalar dependencias sugeridas por IA, e imponer revisión humana en decisiones críticas.
- **Consumo ilimitado (`LLM10:2025 — Unbounded Consumption`):** prompts gigantescos, entradas repetitivas o bucles autónomos de agentes que reintentan indefinidamente saturan GPU/CPU o generan costos financieros masivos en APIs (*Denial of Wallet*). **Mitigación:** fijar topes duros de `max_tokens` en entrada y salida, límite de pasos (`max_iterations`) en agentes, *timeouts* por petición, cuotas por usuario/tenant (`rate limiting`) y caché semántico o exacto.

## 3. OWASP Top 10 for Agentic Applications (diciembre 2025)

A diferencia de un chatbot estático de un turno, los **sistemas agénticos** combinan planificación autónoma de múltiples pasos, memoria persistente, ejecución de herramientas/MCP y comunicación entre agentes. Para responder a esa superficie ampliada, OWASP publicó en **diciembre de 2025** la taxonomía específica **`ASI01` a `ASI10`**:

| Código | Riesgo en aplicaciones agénticas (OWASP Dec 2025) | Impacto técnico principal | Control determinista prioritario |
| :--- | :--- | :--- | :--- |
| **`ASI01`** | *Agent Goal Hijack* | Desvío del objetivo del plan mediante instrucciones ocultas en RAG, correos o salidas de herramientas. | Aislamiento estricto de datos no confiables y validación de intención antes de ejecutar pasos sensibles. |
| **`ASI02`** | *Tool Misuse and Exploitation* | Uso abusivo o fuera de parámetro de herramientas válidas (API, SQL, CLI). | Lista blanca por herramienta, validación estricta por esquema/regex y mínimo privilegio. |
| **`ASI03`** | *Identity and Privilege Abuse* | Herencia excesiva de credenciales del usuario o escalada entre servicios desde el agente. | Tokens efímeros con alcance acotado (*least privilege*) y sin delegación ciega de administrador. |
| **`ASI04`** | *Agentic Supply Chain Vulnerabilities* | Servidores MCP, plugins o definiciones de agentes de terceros alterados o maliciosos (*tool poisoning*). | Fijado de versiones/hashes, firmas y auditoría previa de descriptores de herramientas. |
| **`ASI05`** | *Unexpected Code Execution* | Generación y ejecución insegura de código o comandos del sistema (RCE). | Prohibir `eval`/`shell=True`; ejecutar código solo en contenedores sandbox sin red ni privilegios. |
| **`ASI06`** | *Memory and Context Poisoning* | Corrupción persistente de memoria a largo plazo o base vectorial que altera decisiones futuras. | Firmado/validación de entradas persistidas, partición por tenant y expiración controlada. |
| **`ASI07`** | *Insecure Inter-Agent Communication* | Suplantación o alteración de mensajes entre múltiples agentes cooperantes. | Autenticación mTLS/firmas entre agentes y verificación de esquema en cada mensaje recibido. |
| **`ASI08`** | *Cascading Failures* | Alucinación o fallo menor que se amplifica en cadena a través de subagentes autónomos. | Cortacircuitos (*circuit breakers*), límites `max_iterations` y verificación de invariantes entre etapas. |
| **`ASI09`** | *Human-Agent Trust Exploitation* | Uso de tono persuasivo o explicaciones engañosas para inducir aprobación humana riesgosa. | Mostrar en la interfaz *Human-in-the-Loop* parámetros crudos exactos (monto, destino, comando), nunca resúmenes generados por el agente. |
| **`ASI10`** | *Rogue Agents* | Agente desviado o atrapado en bucles dañinos fuera de sus límites operativos. | *Kill-switch* inmediato, monitoreo continuo de acciones y revocación automática de credenciales ante anomalías. |

## 4. Red Teaming automatizado de IA: `garak`, `PyRIT` y `promptfoo`

Al auditar aplicaciones con IA antes de pasar a producción (integrando seguridad en CI/CD y evaluación defensiva), tres herramientas abiertas cumplen roles complementarios:

- **`garak` (NVIDIA):** escáner de sondas (*probes*) automatizadas especializado en descubrir *jailbreaks*, fugas de contexto, codificaciones evasivas y generación de código peligroso contra modelos locales o APIs (por ejemplo en laboratorio local con Ollama: `garak --model_type ollama --model_name llama3.2 --probes promptinject`).
- **`PyRIT` (*Python Risk Identification Tool*, Microsoft):** framework programático pensado para **AI Red Teaming multivuelta**: un modelo o motor orquestador adapta dinámicamente los mensajes de prueba y un evaluador califica si el objetivo violó políticas tras varios turnos.
- **`promptfoo`:** herramienta CLI/YAML ideal para **pruebas de regresión continuas en CI/CD**; permite definir casos declarativos de *prompt injection*, fuga RAG y abuso de herramientas y fallar el *build* si un cambio de modelo o *system prompt* reintroduce una vulnerabilidad.

## 5. Ejemplo paso a paso en laboratorio local (`laboratorios/lab_rag_mcp_seguro.py`)

El repositorio incluye el script educativo 100 % local [`laboratorios/lab_rag_mcp_seguro.py`](../laboratorios/lab_rag_mcp_seguro.py), que funciona de manera **determinista por defecto (sin GPU ni red externa)** y ofrece además el flag opcional **`--ollama`** para probar flujos reales contra una instancia local de **Ollama (`http://127.0.0.1:11434`)**. Compara un flujo ingenuo **vulnerable** frente a un flujo **endurecido** cuando un documento externo indexado en el RAG intenta ejecutar una inyección indirecta sobre un usuario del tenant `finanzas`.

**Paso 1:** Ejecutar el script desde la raíz del curso (modo determinista por defecto, o con `--ollama` si tenés un modelo local corriendo en `127.0.0.1:11434`):

```bash
# Modo por defecto (100 % determinista, sin GPU ni APIs)
python laboratorios/lab_rag_mcp_seguro.py

# Modo opcional contra Ollama local (requiere servicio activo en 127.0.0.1:11434)
python laboratorios/lab_rag_mcp_seguro.py --ollama --modelo llama3.2
```

**Paso 2:** Comparar las dos salidas JSON generadas por la ejecución real:

```json
{
  "modo": "VULNERABLE",
  "docs_recuperados": [
    "doc-01",
    "doc-02",
    "doc-03"
  ],
  "salida_sin_escapar": "Procesado ticket: <script>alert('XSS')</script>",
  "tool_ejecutada": {
    "nombre": "exportar_archivo",
    "arg": "/etc/shadow"
  }
}
```

```json
{
  "modo": "SEGURO",
  "docs_recuperados": [
    "doc-01",
    "doc-03"
  ],
  "salida_escapada": "Resumen basado en documentos autorizados para: Revisar factura #402",
  "tool_resultado": {
    "estado": "EJECUTADA_EN_SANDBOX",
    "tool": "consultar_estado_ticket",
    "arg": "TK-0402"
  },
  "auditoria": [
    {
      "evento": "PROMPT_INJECTION_DETECTADA",
      "doc_id": "doc-03"
    }
  ]
}
```

Observá las tres diferencias críticas:
1. En el modo vulnerable se filtró `doc-02` (documento `confidencial` del tenant `rrhh`), salió `<script>` sin escapar hacia el cliente y el agente aceptó llamar `exportar_archivo(/etc/shadow)`.
2. En el modo seguro, el filtro **RBAC previo** excluyó `doc-02` antes de tocar el LLM, la detección de patrón en `doc-03` puso el fragmento en cuarentena registrando `PROMPT_INJECTION_DETECTADA` en auditoría, y la **lista blanca determinista de herramientas** + `html.escape()` mantuvieron la ejecución acotada.

::: defensa Perspectiva defensiva: guardrails, sandboxing y telemetría
1. **Guardrails deterministas antes que probabilísticos:** un clasificador basado en IA ayuda como primera señal, pero la última línea de defensa debe ser **código determinista**: validación por esquema (`JSON Schema` / `Pydantic`), listas blancas de herramientas permitidas, verificación RBAC por documento en el recuperador RAG y escape de salidas según contexto.
2. **Aislamiento (*Sandboxing*) de agentes con ejecución:** si un asistente o servidor MCP ejecuta código o comandos, debe correr dentro de contenedores efímeros sin privilegios (`--cap-drop=ALL`, usuario no root, sistema de archivos de solo lectura, sin acceso a `169.254.169.254` ni a secretos de red interna).
3. **Auditoría y telemetría IA:** registrá en logs inmutables del SIEM cada invocación de herramientas (usuario autenticado, herramienta solicitada, argumentos saneados, aprobación *Human-in-the-Loop* y bloqueos de guardrails) para detectar intentos sistemáticos de abuso o deriva del agente.
4. **Gobernanza formal:** alineá el inventario de modelos, pruebas de *AI Red Teaming* periódicas y gestión de riesgos con **NIST AI RMF**, **MITRE ATLAS** e **ISO/IEC 42001**.
:::

## Práctica en laboratorio local

1. Ejecutá `python laboratorios/lab_rag_mcp_seguro.py` y revisá en su código cómo `flujo_seguro()` combina filtro RBAC multi-tenant, detección de inyección indirecta, validación por regex de argumentos y `html.escape()`.
2. Extendé `HERRAMIENTAS_PERMITIDAS` agregando una herramienta ficticia marcada como `"sensible": True` (por ejemplo `aprobar_reembolso`) e implementá una comprobación determinista que exija un flag explícito `aprobacion_humana=True` antes de permitir su ejecución.
3. Escribí una segunda prueba unitaria donde `motor_llm_simulado` devuelva `"tool_call": {"nombre": "consultar_estado_ticket", "arg": "../../etc/passwd"}` y verificá que el guardrail determinista rechace el argumento por no cumplir el patrón `^TK-[0-9]{4}$` dejando el evento registrado en `auditoria`.

::: practica Entregable mínimo
Tu extensión de `lab_rag_mcp_seguro.py` con control *Human-in-the-Loop* para herramientas sensibles, la captura de rechazo ante intento de *Path Traversal* en el argumento y una matriz corta mapeando tus controles contra OWASP LLM Top 10.
:::

## Preguntas de repaso

**1. ¿Cuál es la causa raíz común entre la Prompt Injection indirecta y vulnerabilidades clásicas como SQL Injection?** En ambos casos se mezclan en un mismo canal secuencial las instrucciones de control del sistema (*System Prompt* o sentencia SQL) con datos externos no confiables (fragmentos recuperados de RAG, correos o formularios). Como un LLM procesa todo como tokens de texto continuo, no ofrece aislamiento criptográfico nativo entre reglas y datos, exigiendo validaciones y controles de autorización deterministas fuera del modelo.

**2. ¿Por qué el control de acceso (RBAC/tenant) en una arquitectura RAG debe aplicarse en la consulta a la base vectorial ANTES de enviar el texto al LLM?** Porque si un documento confidencial perteneciente a otro departamento o tenant llega a inyectarse en el contexto del prompt, el modelo ya tuvo acceso a esa información y puede filtrarla en su respuesta incluso si el prompt del sistema indica "no reveles datos ajenos". Filtrar primero por permisos de usuario garantiza que el secreto nunca entre al contexto.

**3. ¿Qué diferencia existe entre *Excessive Agency* y *Insecure Output Handling* en OWASP LLM Top 10?** *Excessive Agency* ocurre cuando se le conceden al modelo o servidor MCP herramientas con permisos, acciones destructivas o alcance superior al estrictamente necesario sin validación externa ni confirmación humana. *Insecure Output Handling* ocurre cuando la aplicación consumidora confía ciegamente en el texto generado por el LLM e inserta esa salida sin escapar ni parametrizar dentro de HTML (`XSS`), SQL (`SQLi`) o subprocesos del sistema.

**4. ¿Por qué nunca deben almacenarse claves API, contraseñas ni lógica exclusiva de autorización dentro de un *System Prompt*?** Porque el *System Prompt* no es un almacén de secretos ni un límite criptográfico: mediante técnicas de inyección o reformulación de contexto puede filtrarse total o parcialmente al usuario. Los secretos deben gestionarse en *Secrets Managers* en el backend, y la autorización debe verificarse en código determinista antes de invocar herramientas o consultar datos.

**5. ¿Qué riesgo introduce cargar modelos en formato `.pkl` frente a `safetensors`, y qué tres marcos de referencia estructuran la defensa en sistemas de IA?** Los archivos `.pkl` usan el módulo `pickle` de Python, capaz de ejecutar código arbitrario durante la deserialización del archivo de pesos; el formato `safetensors` almacena tensores de forma puramente declarativa sin ejecución de código. Los tres marcos de referencia centrales son el **OWASP Top 10 for LLM Applications** (riesgos de aplicación/agentes), **MITRE ATLAS** (matriz de tácticas y técnicas adversarias en IA) y **NIST AI RMF** junto a **ISO/IEC 42001** (gestión integral de riesgos y gobernanza).

## Antes de avanzar

::: nota Puerta de salida
Con este capítulo completaste los **7 Tomos (55 capítulos)** de **Hacking Ético Español**, integrando desde fundamentos de sistemas y redes hasta defensa Cloud, Code Review, OT/ICS, GRC y Seguridad en IA/LLMs y Agentes. Tu próximo paso es transformar esta teoría en kilometraje práctico resolviendo máquinas y laboratorios reales con ayuda de la [Separata de Escritorio](../hojas-referencia-rapida.html) y el [Kit de Laboratorios](../laboratorios.html).
:::

## Referencias y estándares abiertos

- **OWASP Top 10 for LLM Applications (v2025) & OWASP Top 10 for Agentic Applications (`ASI01–ASI10`, diciembre 2025):** clasificación y mitigaciones de riesgos en LLMs, RAG y sistemas agénticos.
- **MITRE ATLAS (*Adversarial Threat Landscape for Artificial-Intelligence Systems*):** matriz de tácticas, técnicas y casos de estudio adversarios en IA/ML.
- **NIST AI Risk Management Framework (AI RMF 1.0 + Generative AI Profile NIST AI 600-1).**
- **ISO/IEC 42001:2023:** requisitos para un Sistema de Gestión de Inteligencia Artificial (AIMS).
- **Herramientas abiertas de AI Red Teaming y estándares:** NVIDIA **garak**, Microsoft **PyRIT**, **promptfoo**, documentación de **`safetensors`** y especificación de seguridad de **Model Context Protocol (MCP)**.
