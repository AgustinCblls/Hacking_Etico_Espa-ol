::: nota Objetivo de la lección
En este capítulo vas a dominar la arquitectura de telemetría, auditoría y defensa perimetral en entornos multicloud (AWS, GCP y Azure). Vas a aprender a configurar registros inmutables en AWS CloudTrail, consultar y alertar con AWS CloudWatch, interpretar registros de auditoría en GCP Cloud Logging y Azure Monitor, analizar hallazgos de AWS GuardDuty y desplegar controles perimetrales de borde y mitigación DDoS mediante AWS WAF, AWS Shield y GCP Cloud Armor.
:::

## Telemetría y auditoría de plano de control y datos en la nube

Sin visibilidad centralizada, un incidente en la nube pasa desapercibido hasta que genera impacto operativo o financiero. El primer pilar defensivo consiste en distinguir entre el registro del **plano de control** (quién creó un usuario, cambió una política IAM o expuso un bucket) y el del **plano de datos** (quién leyó o descargó un objeto específico o invocó una función).

### AWS CloudTrail: registro multi-región e integridad criptográfica

**AWS CloudTrail** registra las llamadas a las APIs de AWS realizadas desde la consola, CLI, SDKs o servicios internos. De forma predeterminada, el historial de eventos conserva 90 días de eventos de administración básicos, pero para investigación forense y monitoreo continuo debés crear un **Trail multi-región** que almacene los logs en un bucket S3 centralizado (idealmente en una cuenta dedicada de seguridad con Object Lock).

Es fundamental diferenciar los dos tipos principales de eventos en CloudTrail:

- **Management Events (Eventos de administración):** Operaciones sobre el plano de control (`CreateUser`, `AttachRolePolicy`, `RunInstances`, `StopLogging`). Deben habilitarse tanto para lectura (`ReadOnly`) como para escritura (`WriteOnly`) en todas las regiones.
- **Data Events (Eventos de datos):** Operaciones de alto volumen sobre recursos concretos, como `GetObject` / `PutObject` en S3 o `Invoke` en AWS Lambda. No vienen habilitados por defecto por su costo y volumen; conviene activarlos de forma selectiva sobre buckets con datos sensibles, secretos o artefactos críticos.

Para garantizar que ningún atacante con acceso administrativo posterior alteró los registros almacenados en S3, CloudTrail ofrece **validación de integridad de archivos de registro** (`LogFileValidationEnabled`). Cada hora, CloudTrail genera un archivo *digest* que contiene hashes **SHA-256** de cada archivo de log entregado y firma digitalmente el digest con RSA.

```bash
# Crear un Trail multi-región con validación SHA-256 y cifrado KMS
aws cloudtrail create-trail \
  --name org-audit-trail \
  --s3-bucket-name sec-central-cloudtrail-logs \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --kms-key-id arn:aws:kms:us-east-1:111122223333:key/abcd-1234

# Verificar criptográficamente la integridad de los logs en una ventana temporal
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:us-east-1:111122223333:trail/org-audit-trail \
  --start-time 2026-05-01T00:00:00Z \
  --end-time 2026-05-02T00:00:00Z
```

Un evento crudo de CloudTrail en JSON expone campos clave para el análisis azul: `eventTime`, `eventSource`, `eventName`, `sourceIPAddress`, `userAgent`, `userIdentity` (tipo de entidad, ARN, `accessKeyId`) y `errorCode` (`AccessDenied` o `UnauthorizedOperation` suelen delatar enumeración previa). Podés filtrar patrones sospechosos directamente sobre archivos JSON descargados con `jq` o mediante filtros de suscripción:

```json
{
  "eventVersion": "1.09",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROAXAMPLE123456:ci-session",
    "arn": "arn:aws:sts::111122223333:assumed-role/DeployRole/ci-session"
  },
  "eventTime": "2026-05-01T14:22:10Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateAccessKey",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "198.51.100.44",
  "requestParameters": {
    "userName": "backup-service"
  }
}
```

### AWS CloudWatch: Metric Filters, Logs Insights y Alarmas

Integrar CloudTrail con **Amazon CloudWatch Logs** transforma los registros estáticos en detección casi en tiempo real. El flujo defensivo sigue tres piezas: un **Metric Filter** convierte coincidencias JSON en métricas numéricas de CloudWatch, una **CloudWatch Alarm** evalúa umbrales sobre esa métrica y dispara notificaciones vía Amazon SNS o respuestas automatizadas.

Por ejemplo, un Metric Filter para detectar intentos de deshabilitar CloudTrail o borrar llaves KMS utiliza la sintaxis de filtro JSON de CloudWatch, y se enlaza luego a una alarma con notificación por SNS:

```bash
# Crear Metric Filter sobre el Log Group de CloudTrail
aws logs put-metric-filter \
  --log-group-name /aws/cloudtrail/org-audit \
  --filter-name CloudTrailTamperingFilter \
  --filter-pattern '{ ($.eventName = "StopLogging") || ($.eventName = "DeleteTrail") || ($.eventName = "ScheduleKeyDeletion") }' \
  --metric-transformations \
    metricName=CloudTrailTamperingCount,metricNamespace=Security/Audit,metricValue=1

# Crear Alarma CloudWatch que notifique al superar 1 evento en 5 minutos
aws cloudwatch put-metric-alarm \
  --alarm-name Alert-CloudTrail-Tampering \
  --metric-name CloudTrailTamperingCount \
  --namespace Security/Audit \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:111122223333:secops-critical-alerts
```

Para investigación interactiva sobre millones de eventos, **CloudWatch Logs Insights** provee un lenguaje de consulta veloz. La siguiente consulta busca actividad administrativa fuera de lo común o ráfagas de errores de autorización agrupadas por identidad e IP de origen:

```sql
fields @timestamp, eventSource, eventName, userIdentity.arn, sourceIPAddress, errorCode
| filter errorCode in ["AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"]
   or eventName in ["ConsoleLogin", "CreateAccessKey", "PutBucketPolicy", "AuthorizeSecurityGroupIngress"]
| stats count() as totalEvents by userIdentity.arn, sourceIPAddress, eventName, errorCode
| sort totalEvents desc
| limit 50
```

### GCP Cloud Logging y Azure Monitor / Activity Log

En **Google Cloud Platform (GCP)**, **Cloud Logging** unifica registros de infraestructura, aplicaciones y **Cloud Audit Logs**. Igual que en AWS, debés distinguir las categorías de auditoría:

- **Admin Activity (`cloudaudit.googleapis.com/activity`):** Siempre habilitados y sin costo adicional; registran creación o modificación de recursos, cambios de políticas IAM (`SetIamPolicy`) y metadatos.
- **Data Access (`cloudaudit.googleapis.com/data_access`):** Deshabilitados por defecto (salvo BigQuery); registran lecturas de configuración (`ADMIN_READ`), lectura de datos (`DATA_READ`) y escritura de datos (`DATA_WRITE`) en Cloud Storage, Secret Manager o KMS. Deben activarse explícitamente en proyectos productivos críticos.
- **System Event y Policy Denied:** Registran acciones ejecutadas por sistemas internos de Google y denegaciones por controles como VPC Service Controls.

Para investigar cambios de permisos IAM o descargas sensibles en GCP usando **Logging Query Language (LQL)** desde la consola o `gcloud logging read`:

```text
logName:"cloudaudit.googleapis.com"
AND protoPayload.serviceName=("iam.googleapis.com" OR "storage.googleapis.com")
AND protoPayload.methodName:("SetIamPolicy" OR "storage.objects.get")
AND severity>=NOTICE
```

Para retención a largo plazo e inmutabilidad, enrutá estos logs mediante un **Log Sink** agregado a nivel de Organización hacia un bucket de Cloud Storage bloqueado con *Bucket Lock* o hacia BigQuery para análisis SQL.

En **Microsoft Azure**, la arquitectura equivalente se apoya en **Azure Activity Log** (plano de control a nivel de suscripción) y **Diagnostic Settings** en cada recurso (Key Vault, Storage Accounts, Azure AD/Entra ID) enviados hacia un **Azure Monitor Log Analytics Workspace**, donde las consultas se escriben en KQL (*Kusto Query Language*):

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has_any ("MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", "MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, ResourceGroup
| order by TimeGenerated desc
```

---

## Detección gestionada de amenazas con AWS GuardDuty

Configurar reglas manuales para cada anomalía operativa resulta difícil de escalar. **Amazon GuardDuty** es un servicio de detección de amenazas gestionado que ingiere y correlaciona telemetría sin necesidad de instalar agentes en las instancias ni impactar el rendimiento del plano de datos:

- **Fuentes base:** CloudTrail Management Events, VPC Flow Logs y registros DNS internos de AWS.
- **Planes de protección adicionales:** Protección de S3 (CloudTrail Data Events), EKS Protection (registros de auditoría de Kubernetes y monitoreo en runtime de nodos), Malware Protection para volúmenes EBS y RDS/Lambda Protection.

Los hallazgos (*findings*) de GuardDuty se organizan por categoría de recurso afectado y severidad numérica (Baja, Media, Alta):

| Dominio | Ejemplos de hallazgos representativos | Señal subyacente analizada |
| :--- | :--- | :--- |
| **IAM** | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | Credenciales temporales de un rol EC2 usadas desde una IP externa a AWS |
| **EC2** | `CryptoCurrency:EC2/BitcoinTool.B!DNS` o `Backdoor:EC2/C&CActivity.B!DNS` | Consultas DNS o flujos VPC hacia destinos asociados a infraestructura maliciosa |
| **S3** | `Policy:S3/BucketBlockPublicAccessDisabled` o acceso anómalo masivo | Cambio de política pública combinado con patrón de lectura inusual en CloudTrail Data |
| **Kubernetes (EKS)** | `PrivilegeEscalation:Kubernetes/PrivilegedContainer` o llamadas anómalas a la API | Auditoría de API server de EKS (`pods/exec`, ClusterRoleBinding riesgoso) |

::: aviso Integración operativa con EventBridge
GuardDuty detecta pero no bloquea por sí mismo. La práctica estándar es conectar GuardDuty mediante **Amazon EventBridge** hacia AWS Security Hub, un canal de Slack/SOAR para alertas de severidad media, y funciones Lambda o playbooks de SSM para contención automatizada en hallazgos de alta confianza (como el uso externo de credenciales de instancia).
:::

El siguiente patrón de evento en EventBridge captura únicamente hallazgos de GuardDuty con severidad alta o crítica (de `7.0` en adelante) para enrutarlos de inmediato al equipo de respuesta:

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [
      { "numeric": [">=", 7] }
    ]
  }
}
```

### Evaluación continua de postura (CSPM abierto): Prowler, ScoutSuite y Steampipe

Mientras la telemetría (CloudTrail / Cloud Logging) registra *qué pasó* en el tiempo y GuardDuty alerta sobre *comportamientos anómalos*, las herramientas **CSPM (*Cloud Security Posture Management*)** auditan de forma periódica la *configuración actual* contra marcos como CIS Benchmark, PCI-DSS o NIST. En operaciones Purple Team abiertas destacan tres herramientas complementarias:

- **Prowler:** herramienta CLI en Python orientada inicialmente a AWS (y extendida a Azure, GCP y Kubernetes) que evalúa cientos de controles CIS, IAM, cifrado, S3, VPC e IMDSv2 generando reportes HTML, JSON-OCSF y hallazgos exportables a AWS Security Hub.
- **ScoutSuite:** auditor multi-cloud desarrollado por NCC Group que recolecta la configuración de solo lectura vía APIs de AWS, Azure y GCP y construye un informe HTML navegable offline para revisar rápidamente superficies expuestas (buckets públicos, Security Groups `0.0.0.0/0`, claves antiguas).
- **Steampipe:** motor basado en PostgreSQL + plugins que expone las APIs de AWS, Azure, GCP, Kubernetes y GitHub como tablas consultables en tiempo real mediante **SQL estándar** (por ejemplo, cruzar en una sola consulta instancias EC2 expuestas con `http_tokens = 'optional'` y roles IAM adjuntos).

---

## Defensa perimetral web y mitigación Anti-DDoS

Mientras la telemetría observa lo que ocurre dentro de la cuenta, la capa perimetral filtra el tráfico entrante antes de que alcance tus balanceadores, contenedores o funciones serverless.

### AWS WAF: Web ACLs, reglas gestionadas y Rate Limiting

**AWS WAF** opera en capa 7 (HTTP/HTTPS) integrándose con Amazon CloudFront, Application Load Balancer (ALB), API Gateway y AppSync. Su unidad central es la **Web ACL**, compuesta por reglas evaluadas por prioridad que terminan en acciones `Allow`, `Block`, `Count` (indispensable para probar reglas nuevas sin romper tráfico legítimo) o `CAPTCHA`/`Challenge`.

Un diseño robusto combina tres capas dentro de la misma Web ACL:
1. **Reglas gestionadas (*AWS Managed Rules*):** Conjuntos mantenidos por AWS como `AWSManagedRulesCommonRuleSet` (protección base OWASP), `AWSManagedRulesKnownBadInputsRuleSet` y `AWSManagedRulesSQLiRuleSet`.
2. **Control de tasa (*Rate-Based Rules*):** Limita ráfagas por IP de origen en ventanas de 5 minutos para frenar fuerza bruta sobre `/login`, abuso de APIs o *scraping* agresivo.
3. **Reglas personalizadas:** Bloqueo por geolocalización, inspección de cabeceras obligatorias o filtrado de rutas administrativas expuestas.

Ejemplo de definición declarativa en JSON de una regla de *Rate Limiting* en AWS WAF v2 enfocada específicamente sobre el endpoint de autenticación:

```json
{
  "Name": "RateLimitLoginEndpoint",
  "Priority": 10,
  "Action": {
    "Block": {
      "CustomResponse": {
        "ResponseCode": 429
      }
    }
  },
  "Statement": {
    "RateBasedStatement": {
      "Limit": 150,
      "EvaluationWindowSec": 300,
      "AggregateKeyType": "IP",
      "ScopeDownStatement": {
        "ByteMatchStatement": {
          "SearchString": "/api/v1/auth/login",
          "FieldToMatch": {
            "UriPath": {}
          },
          "TextTransformations": [
            { "Priority": 0, "Type": "LOWERCASE" }
          ],
          "PositionalConstraint": "STARTS_WITH"
        }
      }
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "RateLimitLoginMetric"
  }
}
```

### AWS Shield: Standard frente a Advanced

Para ataques volumétricos y de agotamiento de estado en capas 3 y 4 (SYN floods, amplificación UDP/DNS, paquetes malformados), AWS ofrece **AWS Shield** en dos niveles:

- **AWS Shield Standard:** Activo automáticamente sin costo adicional para todos los clientes. Mitiga ataques comunes de capa de red y transporte en tiempo real, con máxima eficacia cuando el tráfico entra a través de servicios de borde como **Amazon CloudFront** y **Route 53**.
- **AWS Shield Advanced:** Servicio pago orientado a cargas críticas. Agrega detección y mitigación mejorada en capas 3, 4 y 7 (incluye uso de AWS WAF sin costo adicional por Web ACL sobre recursos protegidos), acceso directo 24/7 al **Shield Response Team (SRT)**, soporte para mitigación automática de capa de aplicación basada en métricas de salud de Route 53, y **protección financiera (*DDoS Cost Protection*)** que otorga créditos ante picos de escalado o transferencia causados por un ataque DDoS confirmado.

### GCP Cloud Armor: políticas de borde, reglas CEL y Adaptive Protection

En Google Cloud, **Cloud Armor** protege aplicaciones expuestas detrás de Cloud Load Balancing (Application Load Balancers globales y regionales) y cachés en el borde. Conviene distinguir dos tipos de políticas:

- **Backend Security Policies:** Adjuntas a un *Backend Service*, evalúan tráfico HTTP(S) completo: firmas preconfiguradas basadas en OWASP ModSecurity Core Rule Set (`evaluatePreconfiguredWaf`), expresiones **CEL** (*Common Expression Language*), listas de IP, geolocalización y *rate limiting* avanzado (`throttle` o `rate-based-ban`).
- **Edge Security Policies:** Se aplican en la capa de borde sobre servicios de **Cloud CDN** o Media CDN para descartar tráfico no deseado (por ejemplo, restricciones geográficas o listas de bloqueo de IPs) antes incluso de consultar la caché o llegar al origen.

Además, Cloud Armor ofrece **Adaptive Protection** (en nivel Enterprise/Managed Protection), que entrena modelos de comportamiento sobre el tráfico legítimo de tus backends y genera alertas con firmas sugeridas automáticamente cuando detecta anomalías volumétricas L7.

Un despliegue práctico mediante `gcloud` creando una política de seguridad, activando mitigación SQLi/XSS preconfigurada en modo estricto equilibrado, imponiendo bloqueo geográfico con CEL y aplicando *rate limiting*:

```bash
# 1. Crear la política de seguridad en Cloud Armor
gcloud compute security-policies create prod-web-armor-policy \
  --description "Política WAF y Rate Limit para API de producción"

# 2. Bloquear firmas preconfiguradas de SQLi y XSS (nivel de sensibilidad 1-4)
gcloud compute security-policies rules create 1000 \
  --security-policy prod-web-armor-policy \
  --expression "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 2}) || evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 2})" \
  --action deny-403 \
  --description "Mitigación OWASP SQLi y XSS"

# 3. Regla CEL personalizada: restringir /admin a rangos corporativos permitidos
gcloud compute security-policies rules create 1100 \
  --security-policy prod-web-armor-policy \
  --expression "request.path.startsWith('/admin') && !inIpRange(origin.ip, '203.0.113.0/24')" \
  --action deny-403 \
  --description "Proteger ruta administrativa por IP"

# 4. Rate limiting: máximo 100 req/min por IP; excedente recibe HTTP 429
gcloud compute security-policies rules create 2000 \
  --security-policy prod-web-armor-policy \
  --src-ip-ranges "*" \
  --action throttle \
  --rate-limit-threshold-count 100 \
  --rate-limit-threshold-interval-sec 60 \
  --conform-action allow \
  --exceed-action deny-429 \
  --enforce-on-key IP \
  --description "Throttling global por IP"

# 5. Adjuntar la política al backend service del Load Balancer
gcloud compute backend-services update prod-api-backend \
  --global \
  --security-policy prod-web-armor-policy
```

::: peligro Modo evaluación antes de bloquear en producción
Tanto en AWS WAF (`Count`) como en GCP Cloud Armor (`--preview`), activá siempre las reglas nuevas en modo auditoría durante 24 a 72 horas sobre tráfico real antes de pasarlas a `Block` o `deny-403`. Una regla SQLi o XSS con sensibilidad alta sin ajuste previo suele generar falsos positivos sobre payloads JSON o campos de texto enriquecido legítimos.
:::

---

## Seguridad en ecosistemas SaaS corporativos: Microsoft 365 y Google Workspace

En la práctica operativa, la mayoría de las intrusiones corporativas no comienzan vulnerando una instancia EC2 ni un clúster Kubernetes, sino comprometiendo identidades y flujos de correo/archivos en plataformas **SaaS** como **Microsoft 365** y **Google Workspace**. Para el equipo defensivo, el buzón y el almacenamiento colaborativo forman parte crítica del perímetro cloud:

- **BEC (*Business Email Compromise*):** Ataques orientados a secuestrar o suplantar cuentas ejecutivas/financieras (mediante phishing *Adversary-in-the-Middle* que roba cookies de sesión MFA) para modificar datos bancarios de proveedores o autorizar transferencias fraudulentas sin desplegar malware binario.
- **Abuso de *OAuth App Consent Grants* maliciosos (Consent Phishing):** En lugar de robar la contraseña, el atacante induce a un usuario a autorizar una aplicación OAuth de terceros con permisos delegados de alto impacto —como `Mail.Read`, `Mail.Send`, `Files.Read.All` u `offline_access`—. Una vez otorgado el consentimiento, la aplicación mantiene acceso persistente a correos y documentos vía API Graph/REST incluso si el usuario cambia su contraseña, hasta que un administrador revoque explícitamente el permiso o el *Enterprise App*.
- ***Device Code Phishing* (RFC 8628):** El atacante solicita un código de dispositivo legítimo ante el endpoint real de Microsoft (`microsoft.com/devicelogin`) y engaña a la víctima por chat o correo para que lo ingrese en el portal oficial del proveedor. Como la víctima se autentica en el dominio real —superando incluso **MFA FIDO2** si no hay restricción de dispositivo—, el atacante recibe en segundo plano los tokens de sesión (`access_token` / `refresh_token`). **Defensa y detección:** bloquear el flujo *Device Code* por completo mediante **Conditional Access** (`Authentication flows` = *Device code flow* → *Block*) salvo excepciones estrictas de hardware sin teclado, y alertar en Entra ID `SignInLogs` ante `AuthenticationProtocol = deviceCode`.
- **Reglas ocultas de reenvío y eliminación en *Exchange Online* y Gmail:** Tras ingresar al buzón, es habitual crear reglas silenciosas (`New-InboxRule` en Exchange Online o filtros automáticos en Gmail) que desvían respuestas de facturación o alertas de seguridad hacia la carpeta *Deleted Items* / *RSS Feeds* o reenvían copias hacia dominios externos bajo control del atacante.
- **Auditoría en el *Unified Audit Log* (M365) y *Google Workspace Audit Logs*:**
  - En **Microsoft 365**, habilitá el **Unified Audit Log (UAL)** en Microsoft Purview y monitoreá eventos críticos como `Consent to application`, `Add app role assignment grant to user`, `New-InboxRule`, `Set-InboxRule`, `MailItemsAccessed` (para dimensionar exfiltración real de correos) y `UserLoggedIn` desde IPs o *User-Agents* atípicos.
  - En **Google Workspace**, auditá los registros de **Token / OAuth** (`authorize` con `scope` sobre Gmail o Drive), cambios en configuraciones de reenvío y delegación en **Gmail Audit Logs**, y restringí qué aplicaciones de terceros no verificadas pueden solicitar acceso mediante *API Controls / App Access Control*.

::: defensa Controles inmediatos para frenar abuso SaaS
1. **Deshabilitá el autoconsentimiento de usuarios para apps OAuth:** Configurá el flujo de **Admin Consent** en Entra ID y la lista blanca de aplicaciones confiables en Google Workspace para que ningún empleado pueda otorgar `Mail.Read` o `Files.Read.All` sin revisión previa de seguridad.
2. **Bloqueá el reenvío automático externo por política:** Desactivá el *auto-forwarding* hacia dominios externos a nivel de tenant en *Exchange Online* (*Anti-spam outbound policy*) y en *Google Workspace*, permitiendo únicamente excepciones documentadas y monitoreadas.
:::

---

## Práctica guiada en laboratorio

Vas a diseñar e implementar un paquete declarativo de visibilidad y defensa perimetral replicable en entorno sandbox (sin exponer recursos productivos).

1. Definí una consulta en **CloudWatch Logs Insights** y un filtro LQL de **GCP Cloud Logging** orientados a detectar cambios en políticas IAM, creación de llaves de acceso y errores reiterados de autorización.
2. Redactá una política JSON para **AWS WAF v2** que combine un grupo de reglas gestionadas en modo `Count` y una regla de `RateBasedStatement` en modo `Block` con código `429` acotada a `/login`.
3. Escribí el script CLI de **GCP Cloud Armor** con al menos tres prioridades: regla preconfigurada OWASP, regla CEL restringiendo un endpoint sensible por IP y regla `throttle` por IP.
4. Documentá cómo validarías la integridad SHA-256 de archivos en CloudTrail mediante `validate-logs` y cómo conectarías un hallazgo de GuardDuty de alta severidad a una notificación vía EventBridge.

::: practica Entregable mínimo
Un archivo de diseño defensivo que incluya: la consulta CloudWatch Logs Insights probada sintácticamente, el filtro LQL para Cloud Audit Logs, la definición JSON de la Web ACL de AWS WAF con rate limiting por ruta, y la secuencia de comandos `gcloud compute security-policies` para Cloud Armor en modo `--preview` y producción.
:::

::: defensa Perspectiva defensiva y mitigación
La defensa cloud efectiva articula profundidad en capas: el perímetro (CloudFront + AWS Shield + AWS WAF o Cloud Load Balancing + Cloud Armor) absorbe ataques volumétricos y automatizados en el borde antes de generar costos de cómputo en el origen; mientras que la telemetría inmutable (CloudTrail con validación SHA-256, Cloud Audit Logs con Data Access selectivo, Azure Activity Log) y la detección comportamental (GuardDuty) garantizan que cualquier abuso de identidad o movimiento interno deje rastro verificable y dispare alertas accionables en segundos.
:::

## Preguntas de repaso

**1. ¿Por qué conviene habilitar Data Events en AWS CloudTrail (o Data Access Logs en GCP) de forma selectiva en lugar de dejarlos apagados o activarlos indiscriminadamente?** Porque los Management Events/Admin Activity solo registran cambios en la configuración de recursos, no quién leyó o modificó objetos concretos en S3 o Cloud Storage; activarlos selectivamente sobre buckets críticos aporta trazabilidad de acceso a datos sensibles evitando costos excesivos y ruido por volúmenes masivos de tráfico no sensible.

**2. ¿Cómo garantiza AWS CloudTrail que los archivos de log depositados en S3 no fueron manipulados después de generarse?** Mediante la validación de integridad de archivos de registro, que genera archivos *digest* horarios con hashes SHA-256 de cada archivo de log entregado y los firma digitalmente, permitiendo verificar toda la cadena de forma offline o con `aws cloudtrail validate-logs`.

**3. ¿Qué diferencia existe entre una regla estándar de AWS WAF y una regla `RateBasedStatement`, y por qué usar `Count` inicialmente?** Una regla estándar inspecciona atributos de cada petición individual (URI, cabeceras, payloads), mientras que `RateBasedStatement` contabiliza el volumen de peticiones por clave de agregación (como IP) en una ventana temporal para mitigar ráfagas; usar `Count` primero permite registrar coincidencias y ajustar falsos positivos antes de bloquear tráfico legítimo.

**4. ¿Qué aporta AWS Shield Advanced por encima de AWS Shield Standard?** Además de mitigación L3/L4 automática, Shield Advanced suma defensa L7 integrada con uso de AWS WAF incluido sobre recursos protegidos, acceso 24/7 al Shield Response Team (SRT), integración con métricas de salud de Route 53 y protección económica (*DDoS Cost Protection*) ante picos de facturación causados por un ataque DDoS.

**5. ¿Cuál es la diferencia operativa entre una *Backend Security Policy* y una *Edge Security Policy* en GCP Cloud Armor?** La *Backend Security Policy* evalúa solicitudes HTTP(S) completas (incluyendo reglas OWASP preconfiguradas, expresiones CEL sobre cabeceras/rutas y throttling avanzado) antes de llegar al servicio backend, mientras que la *Edge Security Policy* se aplica antes en el borde sobre Cloud CDN para descartar IPs o regiones bloqueadas antes de consultar la caché.

## Antes de avanzar

::: nota Puerta de salida
Antes de avanzar hacia la respuesta a incidentes y el análisis forense en la nube, asegurate de saber distinguir qué telemetría corresponde al plano de control y cuál al plano de datos, cómo consultar registros con Logs Insights o LQL, y qué capa del perímetro (WAF, Shield o Cloud Armor) resuelve cada clase de ataque web o volumétrico.
:::

## Referencias y estándares abiertos

- AWS CloudTrail Log File Integrity Validation: [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)
- Amazon GuardDuty Finding Types: [https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- AWS WAF & AWS Shield Best Practices: [https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html)
- Google Cloud Armor Security Policies & CEL: [https://cloud.google.com/armor/docs/security-policy-overview](https://cloud.google.com/armor/docs/security-policy-overview)
- Google Cloud Audit Logs Overview: [https://cloud.google.com/logging/docs/audit](https://cloud.google.com/logging/docs/audit)
