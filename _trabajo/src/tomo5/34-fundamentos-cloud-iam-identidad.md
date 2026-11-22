::: nota Objetivo de la lección
Al completar este capítulo vas a comprender los fundamentos arquitectónicos de la computación en la nube multi-proveedor (AWS, Azure y GCP), los límites reales del Modelo de Responsabilidad Compartida y la mecánica interna de la virtualización mediante hipervisores. Además, vas a dominar el modelo de evaluación de identidades y accesos (IAM), analizar rutas conceptuales de escalada de privilegios en políticas JSON y arquitectura híbrida con Microsoft Entra ID, y aplicar controles de endurecimiento y auditoría con herramientas CLI en entornos de laboratorio propios.
:::

La transición desde centros de datos físicos hacia infraestructuras definidas por software desplazó el perímetro de seguridad tradicional. En entornos de nube pública y privada, la red deja de ser el principal límite de confianza: **la identidad pasa a ser el plano de control crítico**. Un error en una política JSON, un rol sobredimensionado o una relación de confianza mal acotada puede exponer la infraestructura completa sin necesidad de vulnerar un solo servicio de red.

Este capítulo consolida la base conceptual y operativa necesaria para auditar identidades en la nube, cubriendo el recorrido de los módulos *Virtualization and Cloud Security*, *AWS Identity and Access Management* e *Identity and Access Management*.

## Arquitectura Multi-Cloud y Modelo de Responsabilidad Compartida

Las organizaciones modernas raramente dependen de un único proveedor. Adoptan estrategias **multi-cloud** (combinando **Amazon Web Services (AWS)**, **Microsoft Azure** y **Google Cloud Platform (GCP)**) para evitar el bloqueo de proveedor (*vendor lock-in*), cumplir normativas de residencia de datos o aprovechar servicios especializados de analítica e inteligencia artificial. Sin embargo, operar múltiples nubes multiplica la complejidad del plano de control porque cada plataforma nombra, agrupa y delega sus recursos con jerarquías distintas.

| Capa o Concepto | AWS | Microsoft Azure | Google Cloud (GCP) |
| :--- | :--- | :--- | :--- |
| **Unidad de aislamiento superior** | Organization / Root | Tenant (Entra ID) / Management Group | Organization |
| **Contenedor de facturación y límites** | AWS Account | Subscription | Project (y Folders) |
| **Identidad humana / servicio** | IAM User / IAM Role | Entra ID User / Service Principal | Cloud Identity / Service Account |
| **Unidad de permisos** | IAM Policy (JSON) | RBAC Role Definition (JSON) | IAM Role (conjunto de permisos) |
| **Plano de metadatos local** | IMDS (`169.254.169.254`) | IMDS (`169.254.169.254`) | Metadata Server (`metadata.google.internal`) |

A pesar de estas diferencias de nomenclatura, los tres proveedores operan bajo el **Modelo de Responsabilidad Compartida**. Este modelo traza una frontera contractual y técnica entre la **seguridad *de* la nube** (responsabilidad del proveedor: seguridad física de los centros de datos, hardware de red, hipervisores subyacentes y aislamiento multi-inquilino) y la **seguridad *en* la nube** (responsabilidad del cliente: configuración de identidades, cifrado de datos, reglas de firewall virtuales, parches del sistema operativo invitado y gestión de secretos).

```
+-------------------------------------------------------------------+
| RESPONSABILIDAD DEL CLIENTE (Seguridad EN la nube)                |
|  - Datos, clasificación y cifrado en reposo / tránsito            |
|  - Identidades, MFA, políticas IAM y principio de mínimo privilegio|
|  - Configuración de aplicaciones, red virtual (VPC/VNet) y OS     |
+===================================================================+
| RESPONSABILIDAD DEL PROVEEDOR (Seguridad DE la nube)              |
|  - Cómputo físico, almacenamiento subyacente y red troncal        |
|  - Hipervisores (Nitro, Hyper-V, KVM) y aislamiento físico        |
|  - Seguridad perimetral física, energía y certificaciones         |
+-------------------------------------------------------------------+
```

::: aviso La zona gris de la responsabilidad según el modelo de servicio
A medida que avanzás desde **IaaS** (EC2, Azure VMs, Compute Engine) hacia **PaaS** (RDS, App Service, Cloud SQL) y **SaaS / Serverless** (Lambda, Cloud Functions, Microsoft 365), el proveedor absorbe la gestión del sistema operativo y del entorno de ejecución. Sin embargo, **nunca** absorbe la configuración lógica de tus permisos, la exposición pública de tus repositorios de objetos ni la higiene de tus credenciales. La gran mayoría de los incidentes en la nube ocurren en la capa lógica administrada por el cliente.
:::

## Virtualización, Hipervisores y Aislamiento Multi-Inquilino

Para garantizar que múltiples clientes compartan un mismo servidor físico (*bare metal*) sin interferencias ni fugas de memoria, los proveedores de nube se apoyan en **hipervisores**. Un hipervisor es una capa de software o firmware que abstrae el hardware físico (CPU, RAM, controladores de E/S) y presenta máquinas virtuales independientes (*guests*) con sus propios núcleos de sistema operativo.

Existen dos arquitecturas clásicas de hipervisores:

1. **Hipervisores de Tipo 1 (Bare-Metal):** Se ejecutan directamente sobre el hardware físico sin un sistema operativo anfitrión intermedio. Ejemplos representativos son **KVM** (Kernel-based Virtual Machine, núcleo de la infraestructura de GCP y base histórica de múltiples nubes), **Xen**, **Microsoft Hyper-V** y **VMware ESXi**. En la nube moderna, AWS evolucionó este modelo hacia **AWS Nitro System**, descargando la virtualización de red, almacenamiento y gestión hacia tarjetas dedicadas basadas en hardware para reducir al mínimo la superficie de ataque en el procesador principal.
2. **Hipervisores de Tipo 2 (Hosted):** Se ejecutan como una aplicación sobre un sistema operativo convencional (por ejemplo, VirtualBox o VMware Workstation en un laboratorio local). Ofrecen gran portabilidad para pruebas, pero introducen mayor latencia y dependen de la seguridad del sistema anfitrión.

El aislamiento fuerte requiere soporte por hardware en el procesador (**Intel VT-x / EPT** o **AMD-V / RVI**) para separar tablas de páginas de memoria y anillos de privilegio, junto con **IOMMU** (*Input-Output Memory Management Unit*, como Intel VT-d) para impedir que dispositivos PCIe virtuales realicen accesos directos a memoria (DMA) fuera de su espacio asignado.

En auditorías de virtualización, los riesgos principales surgen cuando se debilitan estas fronteras:

- **Escape de máquina virtual (VM Escape):** Fallos críticos en dispositivos emulados (como controladores gráficos virtuales, disquetes o interfaces de red heredadas en QEMU) que permiten conceptualmente saltar desde el espacio de usuario o kernel del *guest* hacia el proceso del hipervisor en el *host*.
- **Ataques de canal lateral (Side-Channel):** Técnicas basadas en contención de caché compartida de CPU (L1/L2/L3) o ejecución especulativa cuando dos inquilinos comparten núcleos físicos (*Simultaneous Multithreading*). La mitigación estándar incluye microcódigo actualizado, aislamiento de núcleos y, para cargas reguladas, instancias dedicadas (*Dedicated Hosts*).
- **Instantáneas y volúmenes compartidos:** Dejar *snapshots* de discos virtuales sin cifrado o con permisos de lectura amplios expone el sistema de archivos completo de la máquina fuera del tiempo de ejecución.

## Anatomía Profunda de IAM en AWS

**AWS Identity and Access Management (IAM)** gobierna quién (*Principal*) puede hacer qué (*Action*) sobre qué recurso (*Resource*) y bajo qué contexto (*Condition*). Antes de escribir o auditar una política, debés distinguir con precisión los cuatro componentes identitarios básicos:

- **IAM User:** Identidad permanente asociada a una persona o servicio legado con credenciales de largo plazo (contraseña de consola o pares `AccessKeyId` / `SecretAccessKey`). En arquitecturas modernas se desaconseja su uso en favor de federación SSO y roles temporales.
- **IAM Group:** Colección lógica de usuarios para asignar políticas de forma uniforme. Un grupo **no** es una entidad de destino (*Principal*) en políticas de recursos ni puede anidarse dentro de otro grupo.
- **IAM Role:** Identidad temporal sin credenciales estáticas propias. Se asume mediante el servicio **AWS STS** (*Security Token Service*), que emite credenciales efímeras (`AccessKeyId`, `SecretAccessKey` y `SessionToken`) con tiempo de vida acotado. Es el mecanismo recomendado para instancias EC2, funciones Lambda, accesos entre cuentas y usuarios federados.
- **IAM Policy:** Documento JSON que declara permisos. Puede ser **basada en identidad** (adjunta a usuarios, grupos o roles) o **basada en recursos** (adjunta directamente a un bucket S3, una cola SQS, una clave KMS o la *Trust Policy* de un rol).

### Estructura JSON y Política de Ejemplo

Todo documento de política IAM sigue un esquema declarativo estricto con una lista de sentencias (`Statement`). Cada sentencia define:

- **`Sid`:** Identificador legible opcional para documentación y auditoría.
- **`Effect`:** `Allow` o `Deny`.
- **`Action` / `NotAction`:** Operaciones específicas de API con prefijo de servicio (`servicio:Operación`).
- **`Resource` / `NotResource`:** Identificadores únicos (**ARN**, *Amazon Resource Name*) de los objetos alcanzados.
- **`Condition`:** Bloque lógico que restringe cuándo aplica la sentencia (IP de origen, presencia de MFA, etiquetas de recurso o región).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PermitirLecturaS3ConMFAYRedCorporativa",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::lab-datos-auditoria",
        "arn:aws:s3:::lab-datos-auditoria/*"
      ],
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        },
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        }
      }
    },
    {
      "Sid": "DenegarCambiosFueraDeRegionPermitida",
      "Effect": "Deny",
      "Action": "ec2:*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "sa-east-1"
          ]
        }
      }
    }
  ]
}
```

### Lógica de Evaluación de Políticas (Explicit Deny siempre gana)

Cada llamada a la API de AWS dispara un motor de decisión determinista. Comprender este orden de evaluación es vital para no asumir falsamente que una política de permiso habilita una acción cuando existe una barrera superior:

1. **Denegación por defecto (*Implicit Deny*):** Toda acción comienza denegada si ninguna sentencia la autoriza.
2. **Evaluación de `Deny` explícito:** Si *cualquier* política aplicable (identidad, recurso, *Permission Boundary*, *Session Policy* o **Service Control Policy (SCP)** a nivel de AWS Organizations) contiene un `Effect: "Deny"` coincidente, la petición se rechaza de inmediato. **Un `Deny` explícito nunca puede ser anulado por un `Allow`.**
3. **Evaluación de límites organizacionales:** Si la cuenta pertenece a AWS Organizations, las **SCP** deben permitir la acción explícitamente. Lo mismo ocurre si el usuario o rol tiene un **Permissions Boundary** adjunto: la intersección efectiva es la que prevalece.
4. **Evaluación de `Allow` explícito:** Solo si no hay `Deny` explícito y los límites superiores lo permiten, basta con que exista al menos una sentencia `Allow` coincidente (en política de identidad o en política de recurso dentro de la misma cuenta; en accesos entre cuentas deben permitirlo ambas partes).

## Vectores Conceptuales de Escalada de Privilegios en IAM

Durante una auditoría de seguridad en la nube, el hallazgo más crítico suele ser la capacidad de un usuario o rol con privilegios aparentemente acotados para obtener permisos administrativos mediante combinaciones de acciones IAM. No se trata de errores en el software del proveedor, sino de delegaciones lógicas excesivas.

### 1. Abuso de políticas con comodines (`*`)
Otorgar `"Action": "iam:*"` o `"Action": "*"` sobre `"Resource": "*"` equivale a control total. Sin embargo, riesgos equivalentes aparecen con comodines parciales aparentemente inofensivos, como `iam:Put*` o `iam:Attach*`, que permiten adjuntar políticas administradas como `AdministratorAccess` a la propia identidad o crear nuevas versiones activas de una política existente (`iam:CreatePolicyVersion` con `SetAsDefault`).

### 2. Combinación de `iam:PassRole` con servicios de cómputo
El permiso `iam:PassRole` autoriza a una identidad a asignar un rol existente a un servicio de AWS (como una instancia EC2, una función Lambda o una tarea ECS). Si un operador de desarrollo posee `iam:PassRole` sin restricción de `Resource` (o sin filtro de condición `iam:PassedToService`), sumado al permiso de crear un recurso de cómputo (`ec2:RunInstances` o `lambda:CreateFunction`), puede conceptualmente lanzar una carga de trabajo vinculada a un rol con privilegios superiores y operar dentro de ese contexto de ejecución.

### 3. Cadena de confianza mediante `sts:AssumeRole`
Un rol define una **Trust Policy** (política de confianza) que especifica qué identidades pueden invocar `sts:AssumeRole`. Si una política de confianza declara un principal demasiado amplio (por ejemplo, toda la raíz de la cuenta `arn:aws:iam::123456789012:root` sin condiciones adicionales, o un comodín hacia cuentas externas sin `sts:ExternalId`), cualquier identidad con permiso genérico de `sts:AssumeRole` podrá pivotar hacia ese rol. El riesgo se agrava cuando existen cadenas transitivas: el Rol A asume al Rol B, y este al Rol C administrativo.

### 4. Creación de credenciales de acceso para terceros
Permisos como `iam:CreateAccessKey`, `iam:CreateLoginProfile` o `iam:UpdateLoginProfile` sin restricción estricta a la propia identidad (`${aws:username}`) habilitan que un operador genere credenciales nuevas sobre cuentas de servicio o usuarios administrativos preexistentes.

| Permiso IAM Auditado | Riesgo Arquitectónico Principal | Control de Mitigación Recomendado |
| :--- | :--- | :--- |
| `iam:PassRole` | Delegación de un rol de mayor privilegio a un recurso controlable | Acotar `Resource` a ARNs específicos y exigir condición `iam:PassedToService` |
| `sts:AssumeRole` | Movimiento lateral entre roles o cuentas por políticas de confianza laxas | Restringir el ARN exacto del rol destino y exigir `aws:MultiFactorAuthPresent` o `sts:ExternalId` |
| `iam:CreatePolicyVersion` | Sobreescritura de la versión activa de una política existente | Prohibir en desarrolladores; aplicar *Permissions Boundaries* |
| `iam:AttachUserPolicy` / `AttachRolePolicy` | Autoasignación de políticas administrativas predefinidas | Limitar mediante SCP o restringir a prefijos de roles no privilegiados |
| `iam:CreateAccessKey` | Generación de credenciales estáticas sobre otras identidades | Restringir `Resource` a `arn:aws:iam::*:user/${aws:username}` o bloquear vía SCP |

## Identidad Híbrida y Moderna: Microsoft Entra ID

En ecosistemas empresariales, la identidad suele originarse en un directorio corporativo centralizado sincronizado con la nube. **Microsoft Entra ID** (anteriormente Azure Active Directory) funciona como el proveedor de identidad (IdP) central para Azure, Microsoft 365 y aplicaciones federadas por **SAML 2.0** u **OpenID Connect (OIDC)** hacia AWS o GCP.

### Conceptos Clave en Entra ID

- **Tenant:** Instancia dedicada y aislada de Entra ID que representa a una organización.
- **Enterprise Applications vs App Registrations:** Una *App Registration* define el plano global de la aplicación (su modelo de permisos OAuth2/OIDC), mientras que el **Service Principal** es la representación local concreta de esa aplicación dentro de un *tenant* específico donde recibe asignaciones de roles Azure RBAC.
- **Service Principals y Secretos de Aplicación:** Equivalen a las identidades de máquina no humanas. El riesgo habitual radica en otorgarles roles amplios como `Contributor` o `Owner` a nivel de suscripción completa y almacenar sus secretos de cliente con expiraciones prolongadas dentro de repositorios de código.
- **Managed Identities:** Son la contrapartida moderna en Azure frente a los roles de instancia en AWS. Eliminan por completo la gestión manual de secretos: Azure inyecta un identificador manejado directamente en la VM, App Service o función, permitiendo solicitar tokens OAuth2 al endpoint local de metadatos sin almacenar contraseñas en disco. Existen dos variantes:
  - *System-assigned:* Ligada al ciclo de vida del recurso; si se elimina la máquina virtual, la identidad desaparece automáticamente.
  - *User-assigned:* Recurso independiente reutilizable por múltiples cargas de trabajo que comparten el mismo perfil de acceso.

### Conditional Access (Acceso Condicional)

A diferencia de las políticas estáticas basadas solo en permisos, **Conditional Access** evalúa señales en tiempo real antes de emitir un token de sesión. Actúa como un motor de decisiones *If-Then*:

- **Señales de entrada:** Identidad del usuario o grupo, ubicación IP de origen, estado de cumplimiento del dispositivo (administrado por Intune/MDM), aplicación destino y nivel de riesgo de inicio de sesión.
- **Controles de acceso:** Requerir **MFA resistente a phishing** (FIDO2 / Windows Hello for Business), exigir dispositivo híbrido unido o compatible, bloquear protocolos heredados sin soporte MFA (IMAP/POP3/SMTP básico) o denegar directamente el acceso desde ubicaciones geográficas no autorizadas.

### Separación de Planos: Entra ID vs Azure RBAC

Un error frecuente en auditorías híbridas es confundir los roles de directorio de **Entra ID** (como *Global Administrator* o *User Administrator*, que gobiernan identidades, grupos y aplicaciones del *tenant*) con los roles de **Azure RBAC** (como *Owner*, *Contributor* o *Reader*, que gobiernan recursos de infraestructura como máquinas virtuales, redes y almacenamiento dentro de suscripciones). El endurecimiento exige evitar que cuentas operativas de infraestructura posean roles administrativos globales en Entra ID y restringir la propiedad de *App Registrations* para impedir que un usuario estándar cree aplicaciones con permisos de directorio delegados.

## Auditoría CLI y Endurecimiento de IAM

En tus laboratorios locales o cuentas de práctica propias, auditá sistemáticamente el inventario de identidades y políticas mediante **AWS CLI** antes de desplegar cargas de trabajo productivas.

```bash
# 1. Verificar la identidad activa del contexto actual
aws sts get-caller-identity

# 2. Listar usuarios IAM y revisar antigüedad de claves de acceso
aws iam list-users --query "Users[*].[UserName,CreateDate,PasswordLastUsed]" --output table
aws iam list-access-keys --user-name operador-lab

# 3. Obtener el resumen de autorización completo de la cuenta para auditar políticas inline y adjuntas
aws iam get-account-authorization-details --filter User Role LocalManagedPolicy > iam_snapshot.json

# 4. Simular si una identidad tiene permiso efectivo sobre una acción crítica sin ejecutarla realmente
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:role/RolAplicacion \
  --action-names iam:PassRole sts:AssumeRole s3:PutBucketPolicy

# 5. Identificar credenciales no utilizadas o sin MFA habilitado (reporte de credenciales)
aws iam generate-credential-report
aws iam get-credential-report --query "Content" --output text | base64 --decode > credential_report.csv
```

## Práctica guiada en laboratorio
En tu entorno local (podés usar **LocalStack** o una cuenta propia de pruebas en AWS Free Tier), creá un rol de aplicación llamado `RolLecturaLogs` y un usuario de pruebas `auditor-junior`. Adjuntale al usuario una política JSON acotada que permita consultar metadatos de IAM (`iam:Get*`, `iam:List*`) y simular políticas, más un `Deny` explícito sobre cualquier operación fuera de tu región elegida. Ejecutá `aws iam simulate-principal-policy` para comprobar cómo el motor prioriza el `Deny` explícito frente a un `Allow` amplio.

::: practica Entregable mínimo
Documentá en un archivo `auditoria-iam.md`:
1. La política JSON completa redactada con al menos una condición (`Condition`) por región o etiqueta.
2. La salida capturada del comando `aws iam simulate-principal-policy` demostrando un caso permitido (`allowed`) y un caso bloqueado por `explicitDeny`.
3. Una tabla de remediación proponiendo el reemplazo de al menos un permiso con comodín `*` por acciones específicas de mínimo privilegio.
:::

::: defensa Perspectiva defensiva y endurecimiento
Para blindar el plano de identidad en entornos multi-cloud, aplicá estos controles de referencia basados en el **CIS AWS Foundations Benchmark**:
- **Eliminá el uso operativo de la cuenta Root:** Activá MFA por hardware sobre el usuario raíz, eliminá sus claves de acceso programáticas y usalo únicamente para tareas de facturación o cierre de cuenta.
- **Priorizá credenciales temporales:** Reemplazá `IAM Users` humanos por federación SSO (IAM Identity Center conectado a Entra ID) y reemplazá claves estáticas en cargas de trabajo por `IAM Roles` o `Managed Identities`.
- **Aplicá *Permissions Boundaries* y *SCPs*:** Definí un techo máximo de permisos que ninguna política adjunta por desarrolladores pueda superar, bloqueando acciones de auto-escalada o desactivación de CloudTrail.
- **Habilitá AWS IAM Access Analyzer:** Detectá automáticamente recursos compartidos externamente y generá políticas basadas en actividad real observada en CloudTrail en lugar de permisos teóricos amplios.
- **Auditoria continua y rotación:** Configurá alertas automáticas ante eventos `AssumeRole`, `CreateAccessKey` o cambios en `Trust Policies` mediante CloudTrail y EventBridge.
:::

## Preguntas de repaso

**1. ¿Qué diferencia fundamental existe entre la seguridad *de* la nube y la seguridad *en* la nube dentro del Modelo de Responsabilidad Compartida?** El proveedor garantiza la seguridad *de* la nube (centros de datos físicos, hardware de red, almacenamiento subyacente e hipervisores), mientras que el cliente es responsable de la seguridad *en* la nube (gestión de identidades IAM, configuración de redes virtuales, cifrado de datos, parches de sistemas invitados y control de acceso a sus servicios).

**2. ¿Cómo resuelve el motor de IAM un conflicto entre una política administrada que incluye un `Allow` sobre `s3:*` y una SCP o política de identidad que declara un `Deny` explícito sobre `s3:DeleteObject`?** El `Deny` explícito siempre prevalece sobre cualquier `Allow`. En el flujo de evaluación de AWS IAM, si alguna política aplicable (identidad, recurso, límite de permisos o SCP) contiene un `Deny` explícito coincidente, la petición se rechaza de inmediato sin posibilidad de anulación.

**3. ¿Por qué el permiso `iam:PassRole` sin restricciones representa un vector crítico de escalada de privilegios?** Porque permite a un operador asignar un rol existente con privilegios elevados a un servicio de cómputo (como una instancia EC2 o una función Lambda) bajo su control. Si no se acota el `Resource` a ARNs permitidos ni se exige la condición `iam:PassedToService`, la identidad puede operar indirectamente bajo los permisos de ese rol superior.

**4. ¿Qué ventaja de seguridad aporta una Managed Identity en Microsoft Azure frente a un Service Principal autenticado mediante secreto de cliente?** Una Managed Identity elimina la necesidad de generar, almacenar y rotar manualmente secretos o certificados en código o variables de entorno, ya que la plataforma gestiona automáticamente el ciclo de vida de la identidad y provee tokens temporales a través del endpoint local de metadatos únicamente al recurso autorizado.

**5. ¿Qué comando de AWS CLI permite verificar de forma segura y sin efectos secundarios cómo evaluará IAM una acción específica para un rol o usuario?** El comando `aws iam simulate-principal-policy`, pasando el ARN del principal mediante `--policy-source-arn` y la lista de acciones a comprobar con `--action-names`, devolviendo el veredicto (`allowed`, `implicitDeny` o `explicitDeny`) y las sentencias responsables.

## Antes de avanzar

::: nota Puerta de salida
Antes de pasar al análisis de la superficie de exposición en almacenamiento, redes virtuales y metadatos de instancia, verificá que cumplís estos tres criterios:
- Sabés leer y escribir una política JSON de IAM identificando `Effect`, `Action`, `Resource` y `Condition`.
- Comprendés por qué un `Deny` explícito anula cualquier `Allow` y cómo interactúan las *Trust Policies* con `sts:AssumeRole`.
- Podés diferenciar las identidades humanas federadas de las identidades de máquina (`IAM Roles`, `Service Principals` y `Managed Identities`).
:::

## Referencias y estándares abiertos

- **CIS AWS Foundations Benchmark (Center for Internet Security):** Controles de referencia para cuentas root, MFA, políticas de contraseñas, rotación de credenciales y auditoría IAM.
- **AWS Well-Architected Framework – Security Pillar:** Guía oficial de diseño para gestión de identidades, trazabilidad y privilegio mínimo.
- **Microsoft Cloud Security Benchmark (MCSB):** Controles de identidad, Conditional Access y gobierno de accesos en Entra ID y Azure RBAC.
- **NIST SP 800-145 / SP 800-53 (AC Family):** Definiciones formales de modelos de servicio en la nube (IaaS/PaaS/SaaS) y controles de acceso lógico.
