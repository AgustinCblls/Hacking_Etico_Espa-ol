::: nota Objetivo de la lección
Al finalizar este capítulo vas a comprender la Ingeniería Social como una disciplina sociotécnica estructurada alrededor de principios cognitivos verificables; vas a saber cómo se modela la exposición mediante OSINT humano corporativo y metadatos; vas a distinguir los vectores controlados (*spear phishing*, *smishing*, *vishing* y *pretexting*); y vas a poder diseñar programas éticos de simulación de phishing y concientización con métricas de madurez orientadas al SOC, respaldados por controles técnicos resistentes a phishing como FIDO2/WebAuthn y DMARC `p=reject`.
:::

## La Ingeniería Social como disciplina sociotécnica

Durante años se repitió el cliché de que "el usuario es el eslabón más débil de la seguridad". En seguridad moderna, ese enfoque es contraproducente e impreciso: el ser humano no es un fallo de software, sino un **componente cognitivo que opera bajo presión de productividad**, diseñando atajos mentales (heurísticas) para resolver tareas cotidianas. La **Ingeniería Social** estudia sistemáticamente cómo esos atajos pueden ser inducidos para provocar decisiones que sortean controles técnicos perimetrales.

Desde el marco académico de la psicología de la persuasión formulado por **Robert Cialdini**, existen disparadores cognitivos concretos que explican por qué un mensaje o llamada logra suspender el análisis crítico de una persona incluso cuando conoce las políticas básicas de seguridad:

1. **Autoridad**: las personas tienden a obedecer o priorizar pedidos que parecen provenir de una figura jerárquica, legal o técnica legítima (Gerencia General, RRHH, Mesa de Ayuda de IT, Auditoría Interna o un organismo fiscalizador). Cuando el remitente aparente proyecta autoridad, el receptor teme las consecuencias de demorar la respuesta.
2. **Urgencia**: la presión temporal artificial ("su cuenta de correo será suspendida en 90 minutos", "cierre contable hoy a las 17:00") reduce deliberadamente la ventana de verificación fuera de banda y empuja hacia la acción impulsiva.
3. **Escasez**: la percepción de oportunidad limitada ("quedan 4 licencias disponibles", "beneficio de actualización vigente solo hasta el mediodía") activa aversión a la pérdida y acelera el clic sin inspección previa del dominio.
4. **Reciprocidad**: cuando el emisor entrega primero un supuesto favor, una ayuda técnica no solicitada ("detectamos un error en tu acceso VPN y ya preparamos el ticket para ahorrarte el trámite") o un recurso útil, genera una deuda psicológica implícita que facilita la cooperación posterior.
5. **Prueba social**: la validación por pares ("el 85% de tu gerencia ya completó la migración al nuevo portal de beneficios") reduce la duda individual al presentar la acción riesgosa como un comportamiento ya aceptado por el grupo de pertenencia.

Un escenario sólido rara vez depende de un solo principio: suele combinar **Autoridad + Urgencia + Prueba social** (por ejemplo, un aviso supuestamente enviado por IT indicando que todo el departamento ya actualizó su certificado antes del corte de las 18:00). Comprender esta matriz permite al equipo de defensa entrenar a la organización para reconocer *patrones emocionales de manipulación*, no solo errores ortográficos.

## OSINT humano corporativo y superficie de exposición

Antes de diseñar un escenario de evaluación autorizada o auditar la exposición externa de una organización, se realiza **OSINT humano corporativo** (*Open Source Intelligence*) utilizando exclusivamente información de acceso público, sin interacción intrusiva con los sistemas privados del objetivo.

Los cuatro vectores de recolección pasiva más relevantes para modelar el riesgo de acceso inicial son:

1. **Nomenclatura de correos electrónicos**: a partir de comunicados de prensa, repositorios públicos de código, notas técnicas o perfiles profesionales, se deduce el patrón estándar de direcciones (`nombre.apellido@empresa.example`, `n.apellido@empresa.example`). Conocer la convención permite estimar qué tan fácil resulta para un tercero enumerar buzones ejecutivos o de áreas sensibles.
2. **Organigramas, jerarquías y eventos corporativos**: redes profesionales y memorias anuales revelan quién reporta a quién, qué gerencias tienen aprobaciones financieras, qué empleados ingresaron recientemente (quienes aún no conocen los canales internos reales y suelen temer desobedecer a un superior) y qué procesos de fusión, adquisición o cambio de marca están en curso.
3. **Ecosistema de proveedores y herramientas**: las búsquedas laborales publicadas por la propia empresa suelen detallar su pila tecnológica exacta ("experiencia excluyente en Okta, Microsoft 365, SAP Concur, Jira y VPN Cisco"). Sumado a casos de éxito publicados por terceros (estudios contables, aseguradoras de riesgos del trabajo, servicios de paquetería o SaaS de firma electrónica), esto permite construir pretextos altamente contextualizados.
4. **Metadatos en documentos públicos (FOCA y ExifTool)**: archivos PDF, DOCX o XLSX publicados en sitios web corporativos (licitaciones, manuales de proveedores, balances) frecuentemente conservan metadatos residuales valiosos:
   - Nombres de usuario reales de Active Directory en rutas locales (`C:\Users\mfernandez\Documents\...`).
   - Versiones exactas de software de oficina o generadores de PDF.
   - Nombres de servidores internos de impresión o recursos compartidos SMB.
   - Herramientas abiertas como **ExifTool** (multiplataforma CLI) y **FOCA** (*Fingerprinting Organizations with Collected Archives*) automatizan la extracción de estos metadatos para auditar qué información interna se filtra inadvertidamente al exterior.
5. **Fugas previas de credenciales (*breaches*) y exposición accidental**: la auditoría defensiva verifica mediante servicios de inteligencia de amenazas autorizados si correos corporativos aparecieron en filtraciones históricas de sitios de terceros (donde los empleados pudieron haberse registrado con su correo laboral) o en commits públicos accidentales. En una evaluación ética, **nunca se descargan ni comercializan bases filtradas ilícitas ni se reutilizan contraseñas reales sin autorización específica**; se cuantifica el riesgo de reutilización de credenciales para forzar rotaciones y habilitar MFA resistente a phishing.

## Vectores controlados: *spear phishing*, *smishing*, *vishing* y *pretexting*

En ejercicios de Red Teaming o programas de concientización, los vectores se clasifican por el canal de comunicación y el nivel de personalización:

- ***Spear phishing***: a diferencia del phishing masivo genérico, consiste en correos electrónicos altamente dirigidos a un grupo acotado o rol específico (por ejemplo, Analistas de Cuentas a Pagar o Administradores Cloud), referenciando proyectos, proveedores o nomenclatura interna real recolectada mediante OSINT.
- ***Smishing***: phishing ejecutado a través de SMS o plataformas de mensajería instantánea corporativa/personal (WhatsApp, Teams, Slack, Telegram). Suele explotar notificaciones breves de urgencia (entregas de paquetería corporativa, alertas de inicio de sesión, solicitud de código MFA) en pantallas móviles donde inspeccionar URLs largas resulta incómodo.
- ***Vishing*** (*Voice Phishing*): ingeniería social por canal de voz (telefonía tradicional, VoIP o llamadas de conferencias). Un escenario clásico es la suplantación de la mesa de ayuda solicitando aprobar una notificación *push* de MFA o leer un código temporal durante una supuesta "incidencia crítica en la VPN". Hoy incluye el riesgo emergente de síntesis o clonación de voz asistida por IA sobre ejecutivos con exposición mediática.
- ***Pretexting***: es el diseño integral de una historia, identidad y contexto verosímil (*pretexto*) que sostiene toda la interacción. Un buen pretexto para auditoría autorizada tiene coherencia interna: un motivo lógico para el contacto, un dominio o número consistente con el rol declarado, conocimiento del vocabulario interno del área objetivo y un guion de salida limpio que no genere pánico ni disrupción operativa.

| Vector | Canal principal | Disparador psicológico típico | Señal técnica o conductual de detección |
| :--- | :--- | :--- | :--- |
| ***Spear phishing*** | Correo electrónico corporativo | Autoridad + Urgencia laboral | Fallo DMARC/SPF, dominio *lookalike* reciente, etiqueta externa |
| ***Smishing*** | SMS / Mensajería móvil | Escasez + Urgencia operativa | Acortadores de URL, dominios móviles no corporativos, falta de MDM |
| ***Vishing*** | Teléfono / VoIP / Llamada | Autoridad técnica (IT) + Reciprocidad | Solicitud de códigos MFA o aprobación *push*; sin ticket previo verificable |
| ***Pretexting*** | Multicanal (voz + correo + chat) | Prueba social + Autoridad | Inconsistencias al verificar identidad fuera de banda en directorio real |

## Diseño ético y ejecución de campañas autorizadas de simulación

Ejecutar simulaciones de phishing en una organización sin un marco ético estricto destruye la confianza entre los empleados y el equipo de seguridad. Una campaña mal diseñada genera resentimiento y hace que las personas oculten incidentes reales por miedo a represalias.

### Reglas éticas irrenunciables

::: peligro Reglas estrictas para simulaciones autorizadas
1. **Autorización formal y privacidad**: toda campaña requiere aprobación ejecutiva escrita, alcance exacto (departamentos excluidos si corresponde) y revisión legal/DPO de protección de datos personales.
2. **Cero humillación pública**: está estrictamente prohibido publicar listas de "quiénes cayeron", aplicar sanciones disciplinarias automáticas por un primer clic o utilizar señuelos ridiculizantes. La cultura debe ser de aprendizaje y refuerzo positivo.
3. **Prohibición de pretextos traumatizantes**: nunca simular notificaciones de despidos masivos, emergencias médicas familiares, accidentes o catástrofes. El objetivo es entrenar criterio laboral, no causar angustia personal.
4. **Landing pages educativas sin guardar contraseñas reales**: si una simulación incluye un portal de inicio de sesión ficticio para medir el ingreso de credenciales, el formulario **JAMÁS debe transmitir, registrar ni almacenar la contraseña tipeada**. El campo de contraseña debe limpiarse o ignorarse en el navegador antes de enviar únicamente un token anónimo de evento (`campaign_id` + `event=submitted`), redirigiendo inmediatamente a una página educativa clara que muestre las señales que delataban la simulación.
:::

### Métricas de madurez de una campaña

Medir únicamente "porcentaje de clics" ofrece una visión incompleta y punitiva. Un programa maduro evalúa cuatro indicadores complementarios, inspirados en guías como el **NIST Phish Scale** (que además pondera la dificultad objetiva de cada señuelo):

1. **Tasa de apertura (*Open Rate*)**: porcentaje de destinatarios que cargaron el píxel de seguimiento. *Limitación técnica*: muchos clientes modernos bloquean imágenes remotas por defecto o usan proxies de privacidad (como Apple Mail Privacy Protection), por lo que esta métrica es orientativa y puede subestimar o inflar lecturas.
2. **Tasa de clic (*Click Rate*)**: porcentaje de usuarios que hicieron clic en el enlace simulado respecto al total de correos entregados. Conviene filtrar clics automáticos generados por *sandboxes* de correo o escáneres de enlaces (*link scanners*) que pre-visitan URLs antes que el usuario.
3. **Tasa de ingreso simulado (*Submit / Credential Entry Rate*)**: porcentaje que completó la acción final en la *landing page* educativa (siempre sin capturar secretos reales). Mide la vulnerabilidad efectiva cuando falla el filtrado técnico.
4. **Tasa de reporte al SOC (*Report Rate*) y Tiempo Medio de Reporte**: es **la métrica positiva más importante del programa**. Mide qué porcentaje de usuarios detectó la anomalía y presionó el botón de reporte al SOC, y cuántos minutos pasaron desde el envío del correo hasta el primer reporte. Cuando la tasa de reporte supera ampliamente a la tasa de clic y el tiempo de alerta temprana cae por debajo de pocos minutos, el factor humano pasa de ser superficie de ataque a funcionar como **sensor distribuido de detección**.

| Métrica de campaña | Cálculo base | Interpretación madura | Riesgo o sesgo de medición |
| :--- | :--- | :--- | :--- |
| **Tasa de apertura** | `aperturas_unicas / entregados` | Referencia general de visibilidad | Píxeles bloqueados por cliente o pre-cargados por proxy |
| **Tasa de clic** | `clics_humanos / entregados` | Mide exposición inicial ante el señuelo | Falsos clics de *URL rewriting* y *sandboxes* antiphishing |
| **Tasa de ingreso simulado** | `envios_simulados / entregados` | Mide riesgo de compromiso sin FIDO2 | Riesgo ético grave si el formulario llegara a loguear datos |
| **Tasa de reporte al SOC** | `reportes_validos / entregados` | **KPI principal de resiliencia humana** | Baja si el proceso de reporte es lento o punitivo |

## Defensas técnicas y humanas contra acceso inicial

Ninguna campaña de concientización reemplaza a los controles criptográficos y de infraestructura. La postura defensiva efectiva combina **eliminación técnica del impacto del engaño** con **detección humana rápida**:

1. **Autenticación FIDO2 / WebAuthn resistente a phishing**: a diferencia de contraseñas, códigos SMS o tokens TOTP de 6 dígitos —que pueden ser capturados en tiempo real por un proxy inverso tipo *Adversary-in-the-Middle* (AiTM)—, los autenticadores **FIDO2 / WebAuthn** (llaves de hardware o *passkeys* vinculadas a plataforma) realizan una firma criptográfica vinculada al **origen exacto (`RP ID` / dominio TLS)** verificado por el navegador. Si el usuario cae en un dominio proxy fraudulento (`login-empresa-auth.example` en lugar de `login.empresa.example`), la llave criptográfica simplemente **no firma la aserción** para ese origen, neutralizando técnicamente el robo de sesión por phishing.
2. **DMARC `p=reject` respaldado por SPF y DKIM**:
   - **SPF (*Sender Policy Framework*)**: lista qué IPs/servidores están autorizados a enviar correo en nombre de un dominio en el `Return-Path`.
   - **DKIM (*DomainKeys Identified Mail*)**: firma criptográficamente cabeceras y cuerpo del mensaje para garantizar integridad y autenticidad del dominio firmante.
   - **DMARC (*Domain-based Message Authentication, Reporting, and Conformance*)**: exige **alineación** entre el dominio visible en la cabecera `From:` y el dominio validado por SPF/DKIM. Configurar `p=none` solo monitorea; una postura madura exige **`p=reject`** (con `pct=100` y reportes agregados `rua=` hacia el SOC) para que los servidores receptores rechacen directamente intentos de suplantación exacta del dominio corporativo.
3. **Etiquetado externo (*External Email Banner*) y monitoreo de dominios *lookalike***: agregar una etiqueta visual automática y consistente a todo correo originado fuera del tenant corporativo ayuda a detectar rápidamente intentos de suplantación de nombres ejecutivos (*CEO Fraud*) enviados desde dominios gratuitos o tipográficos (`emp1esa.example`), complementado con alertas tempranas sobre registros de certificados TLS y dominios recién creados parecidos a la marca.
4. **Protocolos de verificación fuera de banda (*Out-of-band*) y botón de reporte conectado al SOAR**: toda solicitud de cambio de cuenta bancaria, transferencia urgente o restablecimiento de MFA debe validarse por un canal independiente previamente conocido (nunca respondiendo al mismo hilo ni llamando al número incluido en el correo sospechoso). Y el botón de reporte en el cliente de correo debe enviar el mensaje con cabeceras completas al flujo SOAR/SOC para purgar copias similares en otros buzones en minutos.

### Proxies inversos AiTM y defensas complementarias a FIDO2/WebAuthn

El phishing tradicional con formularios estáticos perdió efectividad frente al MFA clásico (SMS o TOTP). Para sortearlo, los atacantes modernos despliegan **proxies inversos *Adversary-in-the-Middle* (AiTM)** montados sobre dominios fraudulentos con certificados TLS válidos: el proxy actúa como intermediario transparente en tiempo real entre el navegador de la víctima y el proveedor de identidad legítimo (*IdP*), reescribiendo cabeceras (`Host`, `Location`, `Set-Cookie`) y URLs en vuelo.

```text
+------------------+          TLS (dominio falso)          +------------------------+          TLS (dominio real)          +------------------+
|     Víctima      | <===================================> |   Proxy Inverso AiTM   | <===================================> |  IdP Legítimo    |
|   (Navegador)    |   1. Ingresa usuario, clave y TOTP    |  (login-corp.example)  |   2. Reenvía credenciales y TOTP      | (login.corp.com) |
+------------------+                                       |                        |                                       +------------------+
                                                           |  [Captura en vuelo:]   | <---- 3. Responde Set-Cookie / Token -------|
                                                           |  - Password            |       de sesión YA autenticada
                                                           |  - Cookie de sesión    |
                                                           +------------------------+
```

Como el flujo completo se negocia contra el IdP real, la víctima supera normalmente su segundo factor (código TOTP, SMS o aprobación *push*), y el proxy intercepta la **cookie de sesión autenticada** emitida por el IdP. Con esa cookie, el atacante reutiliza la sesión activa desde otro equipo sin volver a necesitar la contraseña ni el código MFA.

Si bien **FIDO2/WebAuthn** neutraliza el proxy AiTM al vincular criptográficamente la firma al origen exacto (`RP ID`), en despliegues empresariales reales suele coexistir con métodos legados durante migraciones o cuentas de servicio. Por eso la defensa en profundidad exige tres controles complementarios sobre la capa de identidad:

- **Conditional Access basado en cumplimiento de dispositivo (*Device Compliance* / *Hybrid Joined*):** el IdP exige que la solicitud de autenticación provenga de un dispositivo enrolado en MDM/Intune y marcado como conforme (cifrado activo, EDR saludable y parches al día) o unido a *Hybrid Entra ID / AD*. Como el servidor donde corre el proxy AiTM no posee el certificado de dispositivo corporativo ni cumple las políticas, el IdP bloquea la emisión del token aunque la contraseña y el TOTP sean válidos.
- ***Token Protection* (vinculación criptográfica del token al dispositivo):** vincula criptográficamente los tokens de actualización (*Refresh Tokens* / *Primary Refresh Tokens*) a una clave asimétrica almacenada en el **TPM** del endpoint físico. Incluso si un proxy AiTM o un *infostealer* lograra exfiltrar la cookie o el token, al intentar presentarlo desde otra máquina sin la clave privada del TPM el IdP rechaza la renovación de sesión.
- **Continuous Access Evaluation (CAE):** supera la limitación clásica de los tokens JWT de vida fija (por ejemplo, 60 minutos sin revalidación). Con CAE, el IdP y las aplicaciones compatibles mantienen un canal de eventos críticos para revocar sesiones activas **en pocos minutos** ante señales de compromiso: cambio abrupto de IP/ubicación hacia infraestructura anónima, pérdida de estado de cumplimiento del dispositivo, deshabilitación de cuenta o alerta de usuario en riesgo emitida por el SOC.

## Vectores *Client-Side* en escritorio Windows (enfoque PEN-200 y defensa en endpoint)

Cuando un perímetro no expone servicios vulnerables externos, las evaluaciones prácticas estilo **PEN-200** modelan escenarios donde un usuario interno abre un archivo en su estación Windows, desencadenando la conexión inicial hacia la red interna del laboratorio:

- **Archivos `.Library-ms` y servicio `WebClient` (WebDAV):** una Biblioteca de Windows (`.Library-ms`) es un documento XML legítimo que define rutas de carpetas mostradas en el Explorador. Si su etiqueta `<url>` apunta a una ruta WebDAV (`http://servidor-lab/carpeta`) o recurso SMB, al abrir el archivo el Explorador intenta conectarse automáticamente por HTTP/WebDAV (si el servicio `WebClient` está activo) o por SMB (`TCP/445`), exponiendo el listado remoto o enviando autenticación Net-NTLMv2 si no está restringido. **Mitigación:** bloquear tráfico SMB saliente (`TCP/445`) en el firewall perimetral, deshabilitar `WebClient` en endpoints que no utilicen SharePoint/WebDAV legado y filtrar adjuntos `.Library-ms` y `.searchConnector-ms` en el gateway de correo.
- **Accesos directos manipulados (`.lnk`) y contenedores de disco (`.iso` / `.img`):** un archivo `.lnk` puede invocar intérpretes nativos (`cmd.exe`, `powershell.exe`, `mshta.exe`) pasando argumentos en la línea de comando mientras muestra el icono de un documento PDF o carpeta inofensiva. **Mitigación:** mostrar siempre extensiones reales, bloquear archivos `.lnk`, `.iso` y `.vhd` entrantes en correo, y crear alertas en SIEM cuando `explorer.exe` genere procesos hijos de línea de comandos con banderas codificadas (`-enc`) o de descarga.
- **Macros VBA en documentos Office y protección *Mark-of-the-Web (MotW)*:** en escenarios clásicos, un documento con macro `AutoOpen()` / `Document_Open()` invoca a `WScript.Shell` dejando el árbol característico `winword.exe` → `cmd.exe` / `powershell.exe`. Hoy Microsoft bloquea por defecto las macros provenientes de archivos marcados con el *Alternate Data Stream* **`Zone.Identifier` (`ZoneId=3`)** (*Mark-of-the-Web*), pero contenedores comprimidos mal filtrados pueden perder esa marca si se extraen sin propagarla. Por eso resulta obligatorio reforzar la defensa con **Attack Surface Reduction (ASR)** de Microsoft Defender activando las reglas *"Block all Office applications from creating child processes"* y *"Block Win32 API calls from Office macros"*.

## Verificación defensiva en laboratorio

En tu entorno de laboratorio podés automatizar controles preventivos tanto sobre la postura de autenticación de correo como sobre la fuga de metadatos en documentos salientes.

El siguiente script en **Python** audita un archivo `.eml` de laboratorio (o un ejemplo de cabeceras) verificando la presencia de resultados `SPF`, `DKIM` y `DMARC` junto con discrepancias entre el dominio visible `From` y el `Return-Path` o dominios externos:

```python
import email
from email import policy
from email.utils import parseaddr
import re


def extraer_dominio(direccion: str) -> str:
    _, correo = parseaddr(direccion)
    if "@" in correo:
        return correo.split("@", 1)[1].lower().strip("> ")
    return ""


def auditar_eml_laboratorio(contenido_eml: str, dominio_corporativo: str):
    """
    Inspecciona cabeceras de un correo de laboratorio para detectar
    senales basicas de suplantacion y estado de DMARC/SPF/DKIM.
    """
    msg = email.message_from_string(contenido_eml, policy=policy.default)
    dom_from = extraer_dominio(msg.get("From", ""))
    dom_reply = extraer_dominio(msg.get("Reply-To", ""))
    dom_ret = extraer_dominio(msg.get("Return-Path", ""))
    auth_res = msg.get("Authentication-Results", "")

    hallazgos = []

    if dom_reply and dom_from and dom_reply != dom_from:
        hallazgos.append(f"Discrepancia From ({dom_from}) vs Reply-To ({dom_reply})")

    if dom_ret and dom_from and not dom_ret.endswith(dom_from):
        hallazgos.append(f"Desalineacion From ({dom_from}) vs Return-Path ({dom_ret})")

    dmarc_match = re.search(r"dmarc=(\w+)", auth_res, re.IGNORECASE)
    dmarc_estado = dmarc_match.group(1).lower() if dmarc_match else "ausente"
    if dmarc_estado != "pass":
        hallazgos.append(f"DMARC no aprobado (estado={dmarc_estado})")

    if dom_from != dominio_corporativo.lower() and dominio_corporativo.lower().split(".")[0] in dom_from:
        hallazgos.append(f"Posible dominio lookalike respecto a {dominio_corporativo}: {dom_from}")

    return {
        "subject": msg.get("Subject", ""),
        "from_domain": dom_from,
        "dmarc_status": dmarc_estado,
        "alertas": hallazgos,
    }


if __name__ == "__main__":
    eml_prueba = """From: Gerencia Finanzas <finanzas@empresa-lab.example>
Reply-To: tesoreria@soporte-externo.example
Return-Path: <bounce@mailer-tercero.example>
Subject: Urgente: validacion de proveedor antes de las 17:00
Authentication-Results: mx.empresa.example; spf=fail; dkim=none; dmarc=fail action=reject

Estimado, complete la validacion antes del cierre.
"""
    resultado = auditar_eml_laboratorio(eml_prueba, "empresa.example")
    print("[AUDITORIA EML]", resultado)
```

Para prevenir la fuga de metadatos corporativos antes de publicar documentos PDF o DOCX en un portal web público, podés auditar archivos de salida en laboratorio mediante **ExifTool** o revisar la configuración de correo en **PowerShell**:

```powershell
# Verificacion defensiva en laboratorio: auditoria de metadatos con ExifTool
# y chequeo de politica DMARC via DNS sobre un dominio de prueba autorizado
$dominio = "ejemplo.org"
$registroDmarc = Resolve-DnsName -Name "_dmarc.$dominio" -Type TXT -ErrorAction SilentlyContinue

if ($registroDmarc) {
    $txt = ($registroDmarc | Select-Object -ExpandProperty Strings) -join ""
    Write-Host "Registro DMARC encontrado: $txt" -ForegroundColor Cyan
    if ($txt -match "p=reject") {
        Write-Host "[OK] Politica estricta p=reject configurada." -ForegroundColor Green
    } elseif ($txt -match "p=quarantine") {
        Write-Host "[AVISO] Politica intermedia p=quarantine; evaluar migrar a p=reject." -ForegroundColor Yellow
    } else {
        Write-Host "[ALERTA] Politica en monitoreo (p=none); no bloquea suplantacion." -ForegroundColor Red
    }
} else {
    Write-Host "[ALERTA] No se encontro registro _dmarc para $dominio" -ForegroundColor Red
}
```

## Práctica guiada en laboratorio

En tu entorno de laboratorio local (sin enviar correos reales hacia terceros ni consultar dominios fuera de tu alcance autorizado):

1. **Diseñá una ficha de pretexto ético**: redactá un escenario de simulación interna para un equipo ficticio de Finanzas identificando explícitamente qué **2 o 3 principios de Cialdini** intervienen, qué datos ficticios de OSINT lo hacen verosímil y qué **3 señales observables** debería notar el empleado para reportarlo al SOC (por ejemplo, dominio externo, urgencia artificial, discrepancia en `Reply-To`).
2. **Auditá un `.eml` simulado**: guardá un correo de prueba en texto plano con cabeceras `From`, `Reply-To`, `Return-Path` y `Authentication-Results`, ejecutá el script `auditar_eml_laboratorio` en Python y verificá cómo detecta desalineación de dominios y fallos DMARC.
3. **Verificá metadatos en documentos de prueba**: creá un documento `.docx` o `.pdf` de prueba en tu laboratorio, inspeccionalo con `exiftool archivo_prueba.pdf` (o propiedades de archivo) para observar qué usuario, software y fechas quedan embebidos, y documentá cómo sanitizarlos (`exiftool -all= archivo_prueba.pdf`) antes de una publicación externa.

::: practica Entregable mínimo
Entregá un documento de diseño Purple Team que incluya: (a) la ficha de pretexto ético con principios de Cialdini, indicadores de detección para el usuario y verificación de que la *landing page* educativa nunca captura contraseñas reales; (b) la salida del script Python auditando un `.eml` con fallo DMARC y `Reply-To` discrepante; y (c) el listado de metadatos observados y limpiados en un archivo de prueba.
:::

::: defensa Perspectiva defensiva y mitigación
La mitigación integral frente a la Ingeniería Social exige desplazar el peso desde la memoria del usuario hacia controles verificables: exigir **FIDO2 / WebAuthn** para eliminar la utilidad de portales proxy AiTM; publicar **SPF + DKIM + DMARC `p=reject`**; aplicar **etiquetado visible de correos externos** y filtrado de dominios *lookalike*; sanitizar metadatos antes de publicar documentos corporativos; y sostener un programa de concientización **sin humillación pública** centrado en incrementar la **tasa de reporte al SOC** y reducir el tiempo de respuesta.
:::

## Preguntas de repaso

**1. ¿Cómo operan conjuntamente los principios de Autoridad y Urgencia de Cialdini en un incidente típico de acceso inicial?** La autoridad reduce el cuestionamiento del receptor frente a quien supuestamente ordena la acción (por ejemplo, Gerencia o IT), mientras que la urgencia artificial acorta el tiempo disponible para realizar una verificación fuera de banda, induciendo a tomar un atajo riesgoso antes de analizar las señales técnicas del mensaje.

**2. ¿Qué información crítica de infraestructura interna suele filtrarse mediante herramientas como FOCA o ExifTool sobre documentos publicados en la web corporativa?** Suelen exponerse nombres reales de usuarios de Active Directory en rutas locales, versiones exactas de suites ofimáticas o generadores PDF, direcciones de servidores internos de impresión o compartición de archivos y nombres de autores que revelan la nomenclatura corporativa de correos.

**3. ¿Cuál es la regla técnica obligatoria respecto a las contraseñas en una *landing page* educativa durante una campaña autorizada de phishing?** La página de simulación jamás debe transmitir, registrar ni almacenar en servidor la contraseña real ingresada por el usuario; debe descartar o ignorar el contenido del campo secreto antes de cualquier envío, registrando únicamente un evento anónimo de simulación completada para mostrar la guía educativa inmediata.

**4. ¿Por qué la tasa de reporte al SOC se considera una métrica de madurez superior a la tasa de apertura o de clic?** Porque la tasa de apertura está distorsionada por bloqueos de imágenes y proxies, y la tasa de clic solo mide error pasivo; en cambio, la tasa de reporte (junto con el tiempo medio hasta el primer reporte) mide la capacidad activa de los usuarios para detectar anomalías y alertar al SOC a tiempo para purgar una campaña real antes de que escale.

**5. ¿Por qué FIDO2/WebAuthn resiste ataques de phishing con proxy inverso (*Adversary-in-the-Middle*) donde TOTP o SMS fallan?** Porque un código TOTP o SMS puede ser retransmitido en tiempo real por un proxy atacante al servidor legítimo, mientras que FIDO2/WebAuthn vincula criptográficamente la firma de autenticación al dominio exacto (`RP ID` / origen) verificado por el navegador, impidiendo que la credencial produzca una firma válida sobre el dominio fraudulento del proxy.

## Antes de avanzar

::: nota Puerta de salida
Antes de iniciar el **Tomo VII** con el **Capítulo 7.1 (Seguridad Mobile I: arquitectura Android/iOS y análisis estático según OWASP MASTG)**, asegurate de poder responder con precisión:
- Qué cinco principios de Cialdini estructuran los pretextos y cómo se contrarrestan operativamente.
- Qué diferencia hay entre DMARC `p=none`, `p=quarantine` y `p=reject`, y qué protege FIDO2 frente a proxies AiTM.
- Qué reglas éticas rigen una campaña autorizada de simulación y por qué la tasa de reporte al SOC es su indicador central.
:::

## Referencias y estándares abiertos

- NISTIR 8292 / **NIST Phish Scale**: metodología abierta para calificar la dificultad de señuelos de phishing y analizar tasas de clic y reporte.
- W3C & FIDO Alliance — Especificación abierta **WebAuthn / FIDO2** (*Phishing-Resistant MFA*).
- IETF RFC 7489 (DMARC), RFC 7208 (SPF) y RFC 6376 (DKIM) — Estándares abiertos de autenticación de correo electrónico.
- MITRE ATT&CK — `T1566` (*Phishing*), `T1598` (*Phishing for Information*), `T1589` (*Gather Victim Identity Information*).
- **ExifTool** (Phil Harvey) y **FOCA** — Documentación técnica sobre inspección y sanitización de metadatos en documentos.
