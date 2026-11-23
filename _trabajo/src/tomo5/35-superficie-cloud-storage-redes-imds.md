::: nota Objetivo de la lección
Al finalizar este capítulo vas a dominar los mecanismos de control de acceso en almacenamiento de objetos multi-cloud (AWS S3, Azure Blob Storage y GCP Cloud Storage), diseñar y auditar topologías de red seguras en AWS VPC (subredes, tablas de ruteo, Security Groups y NACLs), evaluar la superficie de riesgo en funciones Serverless y gestores de secretos, y comprender la diferencia arquitectónica crítica entre IMDSv1 e IMDSv2 frente a vulnerabilidades de Server-Side Request Forgery (SSRF).
:::

Una vez comprendido el plano de identidades, el siguiente paso al auditar una infraestructura en la nube es examinar dónde residen los datos, cómo fluye el tráfico de red y qué interfaces internas exponen las cargas de trabajo. Muchos incidentes graves no requieren romper el cifrado ni comprometer el hipervisor: nacen de un repositorio de objetos accesible al público, una regla de red demasiado permisiva, un secreto guardado en texto plano dentro de una variable de entorno o una aplicación web vulnerable que consulta el servicio local de metadatos de la instancia.

Este capítulo cubre la superficie de exposición de servicios cloud en profundidad, alineado con los módulos *AWS S3 Basics* y *Amazon Virtual Private Cloud (VPC)*.

## Almacenamiento en la Nube: S3, Azure Blob y GCP Cloud Storage

El almacenamiento de objetos (*Object Storage*) sustituye los sistemas de archivos jerárquicos tradicionales por contenedores planos (**Buckets** en AWS/GCP o **Containers** en Azure) donde cada archivo se almacena como un objeto identificado por una clave única y metadatos asociados. Su acceso ocurre íntegramente mediante peticiones HTTP/HTTPS hacia APIs REST, lo que convierte la configuración de acceso en la única barrera entre un repositorio privado y la exposición global en Internet.

### AWS S3: Bucket Policies vs ACLs y Block Public Access

En **Amazon S3**, la autorización de acceso puede provenir de múltiples fuentes que se evalúan en conjunto:

1. **Políticas IAM (basadas en identidad):** Definen qué puede hacer un usuario o rol interno sobre determinados buckets.
2. **Bucket Policies (basadas en recursos):** Documentos JSON adjuntos directamente al bucket. Permiten definir acceso entre cuentas o acceso anónimo mediante `"Principal": "*"`. Son el mecanismo moderno recomendado para gestionar permisos a nivel de bucket.
3. **Access Control Lists (ACLs):** Mecanismo heredado anterior a IAM que otorga permisos gruesos (`READ`, `WRITE`, `FULL_CONTROL`) a nivel de bucket u objeto individual. AWS recomienda deshabilitarlas por completo mediante la configuración **Object Ownership: Bucket owner enforced**.
4. **S3 Block Public Access:** Red de seguridad superior que actúa a nivel de cuenta o de bucket individual. Posee cuatro interruptores independientes que, al activarse, bloquean y anulan cualquier ACL o Bucket Policy que intente otorgar acceso público, previniendo exposiciones accidentales por error humano.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RechazarConexionesSinTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::lab-respaldos-privados",
        "arn:aws:s3:::lab-respaldos-privados/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

### Azure Blob Storage y SAS Tokens

En **Azure Storage**, los contenedores residen dentro de una *Storage Account*. Además de los controles de acceso basados en Entra ID (RBAC) y las claves compartidas de la cuenta (*Shared Key*), Azure utiliza intensivamente **Shared Access Signatures (SAS)**.

Un token **SAS** es una cadena de parámetros de consulta firmada criptográficamente con la clave de la cuenta (o delegada por Entra ID) que concede acceso granular (lectura, escritura, listado) durante una ventana temporal definida (`se` / *expiry*). Los riesgos frecuentes al auditar SAS tokens incluyen:

- **Ventanas de expiración excesivas:** Emitir SAS válidos por años sin mecanismo de revocación individual (si se compromete un *Account SAS*, se debe rotar la clave de la cuenta o revocar la *Stored Access Policy* asociada).
- **Ausencia de restricción TLS (`spr=https`) o IP (`sip`):** Permitir que el token viaje por HTTP plano o sea utilizable desde cualquier dirección en Internet.
- **Permisos excedidos:** Incluir el permiso de listado (`l`) o escritura (`w`) cuando la aplicación cliente solo requería descargar un objeto puntual (`r`).

### Google Cloud Storage (GCS)

En **GCP**, Cloud Storage ofrece dos modos de control: **Fine-grained** (ACLs por objeto más IAM) y **Uniform bucket-level access (UBLA)**, que desactiva las ACLs individuales para centralizar toda la autorización exclusivamente mediante políticas IAM y condiciones de proyecto. Además, el control organizacional **Public Access Prevention (PAP)** cumple una función equivalente a *Block Public Access* en S3, impidiendo otorgar permisos a los identificadores especiales `allUsers` o `allAuthenticatedUsers`.

| Característica | AWS S3 | Azure Blob Storage | GCP Cloud Storage |
| :--- | :--- | :--- | :--- |
| **Control recomendado** | Bucket Policy + IAM | Azure RBAC (Entra ID) | Uniform Bucket-Level Access (IAM) |
| **Control heredado a desactivar** | S3 ACLs | Acceso anónimo por contenedor / Shared Keys | Fine-grained ACLs |
| **Bloqueo global anti-fugas** | S3 Block Public Access | `AllowBlobPublicAccess = false` | Public Access Prevention (`enforced`) |
| **Acceso temporal delegado** | Presigned URLs (STS/SigV4) | SAS Tokens / User Delegation SAS | Signed URLs |

## Redes en la Nube: Anatomía de AWS VPC

Una **Amazon Virtual Private Cloud (VPC)** es una red virtual aislada lógicamente dentro de AWS donde desplegás recursos con control total sobre direccionamiento IP (CIDR), subredes, tablas de ruteo y compuertas de salida.

### Subredes Públicas vs Subredes Privadas

La diferencia técnica entre una subred pública y una privada **no** radica en el rango de direcciones IP ni en un ajuste booleano mágico, sino exclusivamente en su **tabla de ruteo (*Route Table*)**:

- **Subred pública:** Su tabla de ruteo posee una ruta por defecto (`0.0.0.0/0`) apuntando hacia un **Internet Gateway (IGW)**. Los recursos allí ubicados que tengan IP pública asignada pueden recibir tráfico entrante directo desde Internet y responder hacia afuera. Se reserva para balanceadores de carga (ALB), bastiones o **NAT Gateways**.
- **Subred privada:** Carece de ruta directa hacia un IGW. Sus instancias (bases de datos RDS, servidores de aplicación, nodos internos) no son alcanzables directamente desde Internet. Si requieren descargar actualizaciones salientes, su tabla de ruteo dirige `0.0.0.0/0` hacia un **NAT Gateway** ubicado en la subred pública, o bien utilizan **VPC Endpoints** (Gateway o Interface/PrivateLink) para consumir servicios como S3 o Secrets Manager sin atravesar jamás la red pública.

### Security Groups (Stateful) vs Network ACLs (Stateless)

AWS ofrece dos capas complementarias de filtrado de red dentro de la VPC cuyo comportamiento debes distinguir con exactitud:

| Propiedad | Security Group (SG) | Network ACL (NACL) |
| :--- | :--- | :--- |
| **Ámbito de aplicación** | Nivel de interfaz de red (ENI / instancia / recurso) | Nivel completo de subred |
| **Naturaleza de estado** | **Stateful:** Si permitís el tráfico entrante, la respuesta saliente se permite automáticamente | **Stateless:** Debés definir reglas explícitas tanto para entrada (*Inbound*) como para salida (*Outbound*, incluyendo puertos efímeros `1024-65535`) |
| **Tipos de reglas** | Solo reglas `Allow` (denegación implícita al final) | Reglas `Allow` y `Deny` evaluadas en orden numérico ascendente |
| **Caso de uso principal** | Microsegmentación por rol de aplicación (ej. App -> RDS en puerto 5432) | Defensa perimetral de subred y bloqueo explícito de rangos IP maliciosos |

### Interconexión: VPC Peering y Transit Gateway

Cuando la arquitectura crece a múltiples VPCs o cuentas, surgen dos patrones de interconexión:

- **VPC Peering:** Conexión punto a punto entre dos VPCs sin solapamiento de rangos CIDR. **No es transitivo**: si la VPC A tiene peering con B, y B con C, A no puede enrutar hacia C a través de B. Requiere actualizar manualmente cada tabla de ruteo y ajustar los Security Groups referenciando CIDRs o IDs de SG pares.
- **AWS Transit Gateway (TGW):** Concentrador de enrutamiento regional (*hub-and-spoke*) que conecta cientos de VPCs y enlaces VPN/Direct Connect desde un único punto centralizado, simplificando la inspección centralizada del tráfico mediante firewalls virtuales antes de cruzar entre entornos productivos y de desarrollo.

## Serverless y Gestión de Secretos

Las arquitecturas sin servidor como **AWS Lambda**, **Azure Functions** o **Google Cloud Functions** eliminan la gestión de servidores, pero no eliminan los errores de privilegio ni la exposición de credenciales.

### Riesgos en AWS Lambda

Cada función Lambda opera bajo un **Execution Role** (un rol IAM asumido dinámicamente). Los dos errores más recurrentes en auditorías son:

1. **Permisos de ejecución excesivos:** Otorgar al rol de la función políticas genéricas como `AmazonDynamoDBFullAccess` o `s3:*` cuando la función solo necesita `dynamodb:GetItem` sobre una tabla específica.
2. **Secretos en variables de entorno en texto claro:** Almacenar claves de API externas, cadenas de conexión a bases de datos o tokens dentro de las *Environment Variables* de Lambda expone esos valores a cualquier operador o canal de lectura que posea `lambda:GetFunctionConfiguration` o acceso a la consola web. Además, los *logs* enviados a CloudWatch pueden registrar accidentalmente trazas de variables si el manejo de errores no depura el contexto.

### Gestores de Secretos Dedicados

En lugar de incrustar credenciales en código fuente, imágenes de contenedor o variables de entorno planas, debés delegar su custodia a bóvedas cifradas con rotación automática y trazabilidad por evento:

- **AWS Secrets Manager:** Diseñado específicamente para secretos de bases de datos y credenciales de terceros. Cifra los valores mediante **AWS KMS**, soporta rotación automática nativa mediante funciones Lambda y audita cada lectura en CloudTrail (`secretsmanager:GetSecretValue`).
- **AWS Systems Manager (SSM) Parameter Store:** Almacena configuraciones jerárquicas y secretos en modalidad `SecureString` cifrada con KMS. Resulta ideal para parámetros de aplicación no rotativos con menor costo operativo.
- **Azure Key Vault:** Bóveda centralizada en Azure para secretos, claves criptográficas y certificados TLS, integrada de forma nativa con *Managed Identities* y políticas de acceso basadas en Azure RBAC.

## SSRF en la Nube: IMDSv1 vs IMDSv2

El servicio de metadatos de instancia (**IMDS**, *Instance Metadata Service*) responde en la dirección IP de enlace local no enrutable `169.254.169.254` dentro de las máquinas virtuales de AWS, Azure y GCP (en GCP también vía `metadata.google.internal`). Su propósito legítimo es permitir que la propia instancia consulte su identificador, región, datos de usuario (*user-data*) y, fundamentalmente, obtenga **credenciales temporales del rol IAM adjunto**.

### El problema arquitectónico de IMDSv1

En la versión original (**IMDSv1**), el servicio opera bajo un modelo simple de petición-respuesta sin estado: cualquier solicitud `HTTP GET` hacia `http://169.254.169.254/latest/meta-data/iam/security-credentials/<nombre-rol>` devuelve directamente las credenciales temporales (`AccessKeyId`, `SecretAccessKey`, `Token`).

Si una aplicación web alojada en esa instancia padece una vulnerabilidad de **Server-Side Request Forgery (SSRF)** —un fallo donde el servidor realiza peticiones HTTP hacia una URL controlada o influenciada por un parámetro de entrada sin validación estricta—, el backend puede ser inducido a consultar `169.254.169.254` y reflejar las credenciales del rol IAM en la respuesta o canal observado. El riesgo también se amplifica cuando existen proxies inversos mal configurados o contenedores en red compartida que reenvían peticiones locales.

### La defensa estructural de IMDSv2

Para neutralizar este patrón de abuso sin eliminar la funcionalidad legítima, AWS introdujo **IMDSv2**, basado en sesiones orientadas a tokens con dos controles deterministas:

1. **Exigencia de petición `PUT` y cabeceras personalizadas:** Para obtener credenciales o metadatos, el cliente local primero debe solicitar un token de sesión enviando una petición `HTTP PUT` a `/latest/api/token` incluyendo obligatoriamente la cabecera `X-aws-ec2-metadata-token-ttl-seconds` (entre 1 y 21600 segundos). Un SSRF típico basado solo en `GET` (o que no permite inyectar métodos `PUT` ni cabeceras arbitrarias) falla de inmediato. Además, IMDSv2 rechaza peticiones que contengan la cabecera `X-Forwarded-For`, bloqueando el tránsito a través de proxies HTTP abiertos.
2. **Restricción de salto de red (`HttpPutResponseHopLimit = 1`):** El paquete IP de respuesta del token lleva un límite de saltos (*TTL*) igual a `1` por defecto. Si un paquete debe cruzar un enrutamiento adicional hacia un contenedor con NAT o un proxy intermedio antes de llegar al destino, se descarta antes de completar el intercambio.

```bash
# Flujo legítimo local desde la propia instancia con IMDSv2 habilitado
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

::: peligro Degradación silenciosa por modo opcional
Por compatibilidad heredada, muchas instancias antiguas mantienen `HttpTokens: optional`. Esto deja activo IMDSv1 en paralelo aunque IMDSv2 esté disponible, anulando la protección frente a SSRF. Auditar e imponer **`HttpTokens: required`** es obligatorio en toda infraestructura moderna.
:::

La forma más robusta de garantizar que ningún equipo despliegue instancias heredadas con IMDSv1 activo consiste en aplicar una **Service Control Policy (SCP)** en AWS Organizations que bloquee el aprovisionamiento si no se exige token de sesión:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ExigirIMDSv2AlLanzarInstancias",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": {
          "ec2:MetadataHttpTokens": "required"
        }
      }
    }
  ]
}
```

### Comparativa Multi-Cloud: Protección del Plano de Metadatos (IMDS)

Cuando auditás o defendés instancias y contenedores frente a vulnerabilidades **SSRF**, verificá las defensas nativas específicas de cada servicio de metadatos en **AWS**, **Azure** y **GCP**:

| Proveedor | Protección nativa del servicio de metadatos (IMDS) | Validación y mitigación Purple Team |
| :--- | :--- | :--- |
| **AWS** | **IMDSv2:** flujo obligatorio de sesión en dos pasos (`PUT /latest/api/token` + cabecera `X-aws-ec2-metadata-token`), rechaza `X-Forwarded-For` y limita `HopLimit = 1`. | Imponer `HttpTokens: required` y `HopLimit = 1` vía SCP en AWS Organizations y monitorear en GuardDuty el uso externo de credenciales de instancia. |
| **Azure** | **IMDS de Azure (`169.254.169.254`):** bloquea peticiones sin la cabecera explícita **`Metadata: true`**, neutralizando SSRF simples que no pueden inyectar cabeceras HTTP personalizadas. | Usar *Managed Identities* con privilegio RBAC mínimo y validar en proxies inversos o clientes HTTP que no se reenvíen cabeceras arbitrarias al backend. |
| **GCP** | **Metadata Server (`169.254.169.254` / `metadata.google.internal`):** exige obligatoriamente la cabecera **`Metadata-Flavor: Google`**, rechaza `X-Forwarded-For` y deshabilita endpoints `v1beta1` heredados. | Desactivar APIs de metadatos heredadas en instancias/clústeres y restringir la salida hacia rangos link-local desde aplicaciones web vulnerables. |

## Auditoría CLI en Laboratorio

Usá estos comandos desde tu terminal configurada contra un laboratorio propio o entorno LocalStack para auditar S3, redes VPC y cumplimiento de IMDSv2:

```bash
# 1. Verificar estado de Block Public Access en un bucket S3
aws s3api get-public-access-block --bucket lab-bucket-laboratorio

# 2. Inspeccionar la política adjunta de un bucket y verificar si exige cifrado en tránsito
aws s3api get-bucket-policy --bucket lab-bucket-laboratorio --output text

# 3. Auditar Security Groups que permitan acceso entrante desde 0.0.0.0/0 en puertos sensibles
aws ec2 describe-security-groups \
  --filters "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query "SecurityGroups[*].{ID:GroupId,Nombre:GroupName,Permisos:IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']].FromPort}" \
  --output table

# 4. Listar instancias EC2 y comprobar qué versión de IMDS exigen (HttpTokens y HopLimit)
aws ec2 describe-instances \
  --query "Reservations[*].Instances[*].{ID:InstanceId,Tokens:MetadataOptions.HttpTokens,HopLimit:MetadataOptions.HttpPutResponseHopLimit}" \
  --output table

# 5. Forzar IMDSv2 obligatorio y HopLimit=1 en una instancia existente
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --http-endpoint enabled
```

## Práctica guiada en laboratorio
En tu entorno de pruebas (LocalStack o cuenta personal aislada), desplegá un bucket S3 con `Block Public Access` habilitado y adjuntale una *Bucket Policy* que deniegue explícitamente toda operación cuando `aws:SecureTransport` sea `false`. Adicionalmente, simulá o verificá mediante `aws ec2 describe-security-groups` y `aws ec2 describe-instances` (o una plantilla de infraestructura Terraform/CloudFormation validada localmente) que ninguna regla permita `0.0.0.0/0` hacia puertos administrativos (`22`, `3389`) y que todas las definiciones de cómputo impongan `HttpTokens: required`.

::: practica Entregable mínimo
Registrá en un reporte `auditoria-superficie-cloud.md`:
1. El fragmento JSON de la *Bucket Policy* con cumplimiento TLS verificado y la salida de `get-public-access-block`.
2. Un diagrama ASCII o tabla de ruteo diferenciando una subred pública con IGW de una subred privada con NAT Gateway o VPC Endpoint.
3. El bloque de configuración o comando CLI aplicado para forzar IMDSv2 (`HttpTokens: required`, `HopLimit: 1`) y la justificación técnica de por qué mitiga la exposición vía SSRF.
:::

::: defensa Perspectiva defensiva y endurecimiento
- **Almacenamiento blindado por defecto:** Activá *S3 Block Public Access* a nivel de cuenta entera desde AWS Organizations, deshabilitá las ACLs heredadas (`BucketOwnerEnforced`) y exigí cifrado en reposo (SSE-KMS) y en tránsito (`aws:SecureTransport: true`).
- **Segmentación estricta de VPC:** Ubicá todas las cargas de cómputo y bases de datos en subredes privadas sin IP pública. Exponé servicios HTTP únicamente mediante balanceadores de carga (ALB) con WAF en subredes públicas y activá *VPC Flow Logs* para detectar anomalías de tráfico lateral.
- **Gestión centralizada de secretos:** Prohibí credenciales planas en variables de entorno de Lambda o *user-data* de EC2; consumí secretos en tiempo de ejecución desde Secrets Manager o Azure Key Vault con roles de mínimo privilegio.
- **IMDSv2 obligatorio por política organizacional:** Implementá una SCP en AWS Organizations que deniegue `ec2:RunInstances` a menos que la condición `ec2:MetadataHttpTokens` sea igual a `required` y `ec2:MetadataHttpPutResponseHopLimit` sea `1`.
:::

## Preguntas de repaso

**1. ¿Qué determina técnicamente si una subred en AWS VPC es pública o privada?** La presencia de una ruta por defecto (`0.0.0.0/0`) en su tabla de ruteo asociada apuntando hacia un Internet Gateway (IGW) la convierte en pública; si carece de ruta directa hacia un IGW (enrutando salidas solo vía NAT Gateway o VPC Endpoints), la subred es privada.

**2. ¿Cuál es la diferencia operativa entre un Security Group y una Network ACL al evaluar tráfico de respuesta?** Un Security Group es *stateful*: al autorizar una conexión entrante, el tráfico de respuesta saliente se permite automáticamente. Una Network ACL es *stateless*, por lo que exige reglas explícitas tanto de entrada como de salida (incluyendo el rango de puertos efímeros) y evalúa reglas `Allow` y `Deny` por orden numérico.

**3. ¿Por qué `S3 Block Public Access` es superior a depender únicamente de revisar manualmente las Bucket Policies?** Porque actúa como una barrera superior a nivel de cuenta o bucket que anula automáticamente cualquier ACL o Bucket Policy nueva o preexistente que otorgue acceso público, evitando filtraciones accidentales por configuraciones erróneas de desarrolladores o terceros.

**4. ¿Qué dos requisitos introduce IMDSv2 para proteger las credenciales temporales del rol frente a vulnerabilidades SSRF?** Exige obtener primero un token de sesión mediante una petición `HTTP PUT` con la cabecera `X-aws-ec2-metadata-token-ttl-seconds` (rechazando peticiones con `X-Forwarded-For`), y configura por defecto `HttpPutResponseHopLimit = 1` para evitar que el paquete de respuesta cruce saltos de red adicionales como contenedores con NAT o proxies intermedios.

**5. ¿Por qué no se deben almacenar contraseñas de bases de datos dentro de las variables de entorno de una función AWS Lambda?** Porque cualquier identidad con permiso de lectura de configuración (`lambda:GetFunctionConfiguration`) o acceso a la consola puede visualizarlas en texto plano, además de carecer de rotación automática y poder quedar expuestas accidentalmente en registros de depuración.

## Antes de avanzar

::: nota Puerta de salida
Antes de introducirte en la arquitectura de contenedores Linux y Docker, asegurate de dominar estos puntos:
- Sabés auditar un bucket S3, diferenciar Bucket Policies de ACLs y verificar *Block Public Access*.
- Podés diseñar una VPC básica separando capas públicas y privadas mediante Security Groups y NACLs.
- Comprendés el riesgo de IMDSv1 y sabés exigir IMDSv2 (`HttpTokens: required`, `HopLimit: 1`) en instancias y políticas de organización.
:::

## Referencias y estándares abiertos

- **AWS Well-Architected Framework – Security Pillar:** Mejores prácticas de protección de datos en reposo/tránsito, aislamiento de red y gestión de secretos.
- **OWASP Cloud-Native Application Security Top 10 / OWASP SSRF Prevention Cheat Sheet:** Análisis de riesgos de abuso en servicios de metadatos y mitigaciones estructurales.
- **CIS Amazon Web Services Foundations Benchmark:** Controles normativos para S3 Block Public Access, VPC Flow Logs, Security Groups y metadatos de instancias EC2.
- **Azure Security Benchmark – Network Security & Data Protection:** Guías de configuración segura para Storage Accounts, SAS Tokens y Key Vault.
