::: nota Objetivo de la lección
En este capítulo vas a aprender a ejecutar una respuesta a incidentes ordenada y una adquisición forense preservando cadena de custodia en AWS, Azure y GCP. Vas a incorporar el orden de volatilidad propio de entornos cloud, aplicar contención de identidades IAM y aislamiento de red sin destruir evidencia volátil, adquirir memoria RAM y snapshots cifrados hacia una cuenta forense aislada (*Clean Room*), y automatizar playbooks de recolección y respuesta mediante AWS Systems Manager (SSM) y AWS Incident Manager.
:::

## Orden de volatilidad y principios forenses en la nube

En infraestructura tradicional, el equipo de respuesta suele desconectar un cable de red o apagar un servidor físico. En la nube, **apagar o terminar una instancia destruye evidencia irreemplazable**: se pierde el contenido completo de la memoria RAM (procesos residentes, llaves de cifrado en memoria, comandos no volcados a disco), desaparecen los volúmenes efímeros locales (*Instance Store* / NVMe temporal) y los grupos de autoescalado pueden reemplazar automáticamente la máquina eliminando su rastro operativo.

El **orden de volatilidad adaptado a la nube** prioriza la preservación de mayor a menor fragilidad:

1. **Credenciales efímeras, sesiones STS y metadatos de ejecución:** Tokens emitidos por STS, credenciales obtenidas del servicio de metadatos (IMDSv1/v2) y sesiones activas en consolas o Service Principals. Caducan o pueden ser rotados en minutos, pero permiten reconstruir el alcance del acceso.
2. **Conexiones de red activas y tablas de flujo:** Sockets abiertos en la instancia, tablas ARP/conntrack y flujos recientes en VPC Flow Logs o NSG Flow Logs.
3. **Memoria RAM de instancias y contenedores:** Procesos ocultos, artefactos inyectados en memoria, variables de entorno de contenedores y buffers de red.
4. **Almacenamiento efímero de instancia:** Discos locales no persistentes vinculados al ciclo de vida del hipervisor físico.
5. **Discos persistentes y snapshots:** Volúmenes EBS (AWS), Managed Disks (Azure) y Persistent Disks (GCP).
6. **Registros del plano de control y auditoría:** CloudTrail, Cloud Audit Logs, Azure Activity Log y logs de balanceadores o WAF (menos volátiles si tienen retención e integridad habilitadas, aunque vulnerables si el atacante obtuvo permisos sobre el proyecto origen).

::: peligro Nunca modifiques el sistema de archivos original
Toda inspección profunda debe realizarse sobre una **copia montada en solo lectura dentro de una cuenta o proyecto forense aislado** (*Forensic Clean Room*), nunca ejecutando herramientas de análisis directamente sobre el volumen productivo comprometido. Cada artefacto adquirido debe quedar acompañado de su hash criptográfico **SHA-256** y marca temporal UTC para sostener la cadena de custodia.
:::

---

## Contención de identidades IAM comprometidas

Cuando la telemetría (CloudTrail, GuardDuty o Cloud Logging) confirma el uso anómalo de una identidad, la contención de identidad debe ejecutarse antes o en paralelo al aislamiento de red, ya que un token válido permite operar sobre APIs cloud desde cualquier punto de Internet.

### Contención en AWS IAM y STS

Un error clásico consiste en borrar las Access Keys de un usuario o quitarle una política, olvidando que los tokens temporales de **AWS STS** emitidos previamente siguen siendo válidos hasta su expiración natural (entre 15 minutos y 12 horas). Para invalidar sesiones activas de un rol o usuario federado de manera inmediata:

- **Revocar sesiones STS activas:** Adjuntá una política inline que deniegue explícitamente toda acción cuyo token haya sido emitido antes de la hora actual (`aws:TokenIssueTime`).
- **Desactivar llaves estáticas en lugar de eliminarlas:** Usá `Status=Inactive` para conservar metadatos de auditoría (`GetAccessKeyLastUsed`) sin destruir evidencia.
- **Aplicar denegación total (`AWSDenyAll`):** Adjuntá la política administrada `AWSDenyAll` o un permiso explícito `Deny` sobre `*` si la identidad debe quedar congelada mientras se investiga.

```bash
# 1. Desactivar Access Key sospechosa sin borrar el usuario ni su historial
aws iam update-access-key \
  --user-name svc-backup \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive

# 2. Adjuntar política de denegación total al usuario o rol comprometido
aws iam attach-role-policy \
  --role-name AppWorkerRole \
  --policy-arn arn:aws:iam::aws:policy/AWSDenyAll

# 3. Revocar sesiones STS anteriores a un timestamp UTC específico (política inline)
cat << 'EOF' > revoke-older-sessions.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "2026-05-01T15:30:00Z"
        }
      }
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name AppWorkerRole \
  --policy-name RevokeActiveSessions \
  --policy-document file://revoke-older-sessions.json
```

### Contención en Azure Entra ID y GCP IAM

En **Microsoft Azure**, si se compromete una cuenta de usuario o un **Service Principal** (Application Identity):
1. Revocá inmediatamente todos los tokens de actualización y sesiones activas del usuario con Microsoft Graph (`Revoke-MgUserSignInSession`), o deshabilitá el inicio de sesión (`AccountEnabled = false`).
2. Para un Service Principal, deshabilitá la capacidad de emitir tokens (`az ad sp update --id <APP_ID> --set accountEnabled=false`), rotá o eliminá secretos/certificados vencidos o filtrados y revisá asignaciones RBAC recientes en la suscripción.

En **Google Cloud Platform (GCP)**, las credenciales de servicio comprometidas se contienen deshabilitando la **Service Account** y eliminando la llave comprometida:

```bash
# Deshabilitar Service Account comprometida en GCP (bloquea nuevos tokens y uso)
gcloud iam service-accounts disable sa-deploy@prod-project-123.iam.gserviceaccount.com

# Listar y revocar la llave privada filtrada si usaba claves administradas por el usuario
gcloud iam service-accounts keys list \
  --iam-account=sa-deploy@prod-project-123.iam.gserviceaccount.com

gcloud iam service-accounts keys delete <KEY_ID> \
  --iam-account=sa-deploy@prod-project-123.iam.gserviceaccount.com
```

---

## Aislamiento de cómputo en cuarentena sin pérdida de evidencia

Una vez contenidas las credenciales, necesitás aislar la instancia comprometida para cortar cualquier comunicación hacia el exterior o desplazamiento lateral dentro de la VPC/VNet, **manteniéndola encendida** mientras completás la adquisición de RAM y snapshots.

Antes de cambiar el firewall virtual en AWS EC2, hay tres pasos previos obligatorios para evitar que la automatización cloud destruya la máquina:
1. **Proteger contra terminación:** Habilitá `DisableApiTermination` en la instancia.
2. **Desacoplar de Auto Scaling Group (ASG):** Si la instancia pertenece a un ASG, al quedar incomunicada fallará el *health check* y el ASG la terminará automáticamente para lanzar otra. Ejecutá `detach-instances` (sin decrementar o ajustando la capacidad deseada).
3. **Desregistrar de Load Balancers:** Quitala del Target Group para cortar tráfico de usuarios legítimos sin esperar timeouts.

Recién entonces reemplazá todos los Security Groups de la instancia por un **Security Group de cuarentena** sin reglas de entrada ni salida (o únicamente permitiendo tráfico hacia la interfaz de SSM/estación forense si necesitás extraer memoria antes del corte total):

```bash
# Crear Security Group de cuarentena (sin reglas ingress; remover regla egress por defecto)
QUARANTINE_SG=$(aws ec2 create-security-group \
  --group-name sg-forensic-quarantine \
  --description "Aislamiento forense sin trafico entrante ni saliente" \
  --vpc-id vpc-0a1b2c3d4e5f \
  --query 'GroupId' --output text)

aws ec2 revoke-security-group-egress \
  --group-id "$QUARANTINE_SG" \
  --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'

# Desacoplar del Auto Scaling Group y proteger contra terminación
aws autoscaling detach-instances \
  --instance-ids i-0987654321fedcba0 \
  --auto-scaling-group-name prod-web-asg \
  --no-should-decrement-desired-capacity

aws ec2 modify-instance-attribute \
  --instance-id i-0987654321fedcba0 \
  --disable-api-termination

# Aplicar el Security Group de cuarentena a la instancia comprometida
aws ec2 modify-instance-attribute \
  --instance-id i-0987654321fedcba0 \
  --groups "$QUARANTINE_SG"
```

Los equivalentes en las otras dos nubes siguen exactamente la misma lógica de red:
- **Azure:** Creá un **Network Security Group (NSG)** con reglas de máxima prioridad (100) `DenyAllInbound` y `DenyAllOutbound` y asocialo a la interfaz de red (`az network nic update --network-security-group nsg-quarantine`). Si la VM forma parte de un *Virtual Machine Scale Set (VMSS)*, desasociala o aplicá protección contra eliminación (`az vmss deallocate` solo después de adquirir RAM y discos).
- **GCP:** Asigná una etiqueta de red exclusiva (por ejemplo `forensic-quarantine`) a la instancia Compute Engine y creá reglas de **VPC Firewall** con prioridad `0` (máxima precedencia) para bloquear todo tráfico `INGRESS` y `EGRESS` hacia ese tag, además de abandonar el *Managed Instance Group (MIG)* (`gcloud compute instance-groups managed abandon-instances`).

---

## Adquisición forense de memoria y volúmenes en AWS, Azure y GCP

### Adquisición de memoria RAM con LiME en AWS EC2

Mientras la instancia Linux sigue viva y aislada en cuarentena, podés capturar una imagen completa de la memoria RAM utilizando **LiME (Linux Memory Extractor)**, un módulo de kernel cargable (*LKM*) diseñado específicamente para adquirir memoria volátil minimizando la huella en páginas activas. Para evitar descargar binarios desde Internet desde una máquina en cuarentena o alterar el disco local, lo recomendable es compilar previamente el módulo `lime.ko` para las versiones de kernel estándar de tu organización y distribuirlo desde un bucket interno vía **AWS Systems Manager** o un volumen auxiliar montado, volcando el archivo `.lime` directamente a un bucket S3 forense o a un volumen forense adjunto temporalmente (nunca al disco raíz comprometido):

```bash
# Ejemplo ejecutado en la instancia objetivo sobre un volumen auxiliar /mnt/forensic-dump
sudo insmod /mnt/forensic-tools/lime-$(uname -r).ko "path=/mnt/forensic-dump/i-0987654321-mem.lime format=lime"
sha256sum /mnt/forensic-dump/i-0987654321-mem.lime > /mnt/forensic-dump/i-0987654321-mem.lime.sha256
```

Posteriormente, la imagen `.lime` se analiza offline en la estación forense aislada con **Volatility 3** (generando previamente los símbolos ISF del kernel correspondiente) para inspeccionar procesos ocultos, sockets cerrados recientemente, módulos cargados y variables de entorno.

### Snapshots EBS cifrados y transferencia a cuenta forense aislada (AWS)

Una vez asegurada la memoria RAM, capturá todos los volúmenes EBS asociados a la instancia comprometida y transferilos a una **cuenta forense dedicada** (*Clean Room*). Si el volumen original estaba cifrado con una llave KMS administrada por AWS (`aws/ebs`), no es posible compartir el snapshot directamente con otra cuenta: primero debés copiarlo recifrándolo con una **Customer Managed Key (CMK)** cuya política permita acceso a la cuenta forense.

```bash
# 1. Crear snapshot del volumen comprometido preservando etiquetas de cadena de custodia
SNAP_ID=$(aws ec2 create-snapshot \
  --volume-id vol-0123456789abcdef0 \
  --description "Evidencia incidente INC-2026-042" \
  --tag-specifications 'ResourceType=snapshot,Tags=[{Key=IncidentId,Value=INC-2026-042},{Key=SourceInstance,Value=i-0987654321fedcba0}]' \
  --query 'SnapshotId' --output text)

aws ec2 wait snapshot-completed --snapshot-ids "$SNAP_ID"

# 2. Copiar snapshot recifrándolo con la CMK KMS compartida con la cuenta forense
FORENSIC_SNAP=$(aws ec2 copy-snapshot \
  --source-region us-east-1 \
  --source-snapshot-id "$SNAP_ID" \
  --encrypted \
  --kms-key-id arn:aws:kms:us-east-1:111122223333:key/forensic-cmk-id \
  --description "Copia KMS compartible INC-2026-042" \
  --query 'SnapshotId' --output text)

aws ec2 wait snapshot-completed --snapshot-ids "$FORENSIC_SNAP"

# 3. Compartir el snapshot cifrado con la cuenta forense aislada (999988887777)
aws ec2 modify-snapshot-attribute \
  --snapshot-id "$FORENSIC_SNAP" \
  --attribute createVolumePermission \
  --operation-type add \
  --user-ids 999988887777
```

Ya dentro de la **cuenta forense aislada**, creá un volumen EBS desde el snapshot compartido, adjuntalo a tu estación de análisis forense y montalo estrictamente en **solo lectura sin reproducir el journal** (`ro,noexec,noload` en ext4 o `ro,norecovery` en XFS) para no alterar marcas de tiempo MACB ni bloques del sistema de archivos:

```bash
# En la estación de trabajo de la cuenta forense aislada
lsblk
sudo mkdir -p /mnt/evidence
sudo mount -o ro,noexec,noload /dev/nvme1n1p1 /mnt/evidence
# Generar hash de la partición cruda para registro de cadena de custodia
sudo sha256sum /dev/nvme1n1 > /cases/INC-2026-042/vol-0123456789abcdef0.sha256
```

### Adquisición en Azure y GCP con Flow Logs

El flujo forense equivalente en **Azure** y **GCP** mantiene la separación estricta entre el entorno productivo y el entorno de análisis:

| Plataforma | Adquisición de disco | Telemetría de red clave | Aislamiento destino |
| :--- | :--- | :--- | :--- |
| **AWS** | `aws ec2 create-snapshot` + CMK KMS + `modify-snapshot-attribute` | VPC Flow Logs (en S3 / CloudWatch) | Cuenta AWS dedicada (*Security / Forensics OU*) |
| **Azure** | `az snapshot create` sobre el Managed Disk + copia a Storage Account forense o SAS de corta duración | **NSG Flow Logs** v2 vía Azure Network Watcher | Suscripción forense separada con RBAC restringido |
| **GCP** | `gcloud compute disks snapshot` + `gcloud compute disks create --source-snapshot` en proyecto destino | **VPC Flow Logs** habilitados en la subred | Proyecto GCP forense separado con VPC aislada |

```bash
# Azure: crear snapshot de disco administrado sin detener la VM
az snapshot create \
  --resource-group rg-prod-web \
  --name snap-inc-2026-042-osdisk \
  --source /subscriptions/<SUB_ID>/resourceGroups/rg-prod-web/providers/Microsoft.Compute/disks/vm-web-01_OsDisk

# GCP: crear snapshot y restaurar disco en el proyecto forense aislado
gcloud compute disks snapshot vm-api-01 \
  --zone=us-central1-a \
  --snapshot-names=snap-inc-2026-042 \
  --project=prod-project-123

gcloud compute disks create forensic-disk-inc-2026-042 \
  --source-snapshot=projects/prod-project-123/global/snapshots/snap-inc-2026-042 \
  --zone=us-central1-a \
  --project=forensic-cleanroom-999
```

---

## Automatización de respuesta con AWS Systems Manager e Incident Manager

Ejecutar docenas de comandos manuales bajo presión humana introduce demoras y errores. **AWS Systems Manager (SSM)** y **AWS Incident Manager** permiten estandarizar tanto la recolección inicial de evidencia volátil como los playbooks completos de contención y coordinación.

### Recolección segura sin SSH mediante SSM Run Command y Automation

Si una instancia tiene instalado el **SSM Agent** con el rol IAM mínimo (`AmazonSSMManagedInstanceCore`), el equipo de respuesta puede ejecutar comandos remotos auditados en CloudTrail **sin abrir el puerto 22 (SSH)**, sin llaves privadas compartidas y aunque el Security Group de cuarentena haya bloqueado todo el tráfico entrante (solo requiere conectividad saliente hacia los endpoints de SSM, idealmente mediante **VPC Interface Endpoints** privados dentro de la VPC).

Un documento de **SSM Automation (Runbook)** en formato YAML encapsula una secuencia reproducible: aislar la instancia, activar protección contra terminación, recolectar artefactos volátiles en vivo (`ps auxef`, `ss -tupna`, `lsof`, últimas líneas de `/var/log/auth.log` o journalctl) hacia un bucket S3 forense con Object Lock, y disparar el snapshot EBS:

```yaml
schemaVersion: '0.3'
description: 'Playbook forense: aislar instancia EC2, recolectar volátiles vía SSM y crear snapshot EBS'
assumeRole: '{{ AutomationAssumeRole }}'
parameters:
  InstanceId:
    type: String
    description: 'ID de la instancia EC2 afectada'
  QuarantineSecurityGroupId:
    type: String
    description: 'Security Group de cuarentena sin ingress/egress'
  ForensicBucket:
    type: String
    description: 'Bucket S3 de evidencia con Object Lock'
  AutomationAssumeRole:
    type: String
    description: 'ARN del rol de automatización SSM'

mainSteps:
  - name: EnableTerminationProtection
    action: aws:executeAwsApi
    inputs:
      Service: ec2
      Api: ModifyInstanceAttribute
      InstanceId: '{{ InstanceId }}'
      DisableApiTermination:
        Value: true

  - name: CollectVolatileArtifacts
    action: aws:runCommand
    inputs:
      DocumentName: AWS-RunShellScript
      InstanceIds:
        - '{{ InstanceId }}'
      Parameters:
        commands:
          - 'mkdir -p /tmp/ir-volatile'
          - 'date -u > /tmp/ir-volatile/timestamp_utc.txt'
          - 'ps auxef > /tmp/ir-volatile/processes.txt'
          - 'ss -tupna > /tmp/ir-volatile/sockets.txt'
          - 'lsof -nP > /tmp/ir-volatile/open_files.txt'
          - 'tar -czf /tmp/ir-{{ InstanceId }}.tar.gz -C /tmp/ir-volatile .'
          - 'sha256sum /tmp/ir-{{ InstanceId }}.tar.gz > /tmp/ir-{{ InstanceId }}.tar.gz.sha256'
          - 'aws s3 cp /tmp/ir-{{ InstanceId }}.tar.gz s3://{{ ForensicBucket }}/cases/{{ InstanceId }}/'
          - 'aws s3 cp /tmp/ir-{{ InstanceId }}.tar.gz.sha256 s3://{{ ForensicBucket }}/cases/{{ InstanceId }}/'
          - 'rm -rf /tmp/ir-volatile /tmp/ir-{{ InstanceId }}.tar.gz*'

  - name: ApplyQuarantineSecurityGroup
    action: aws:executeAwsApi
    inputs:
      Service: ec2
      Api: ModifyInstanceAttribute
      InstanceId: '{{ InstanceId }}'
      Groups:
        - '{{ QuarantineSecurityGroupId }}'
```

::: nota Orden en el playbook de SSM
Fijate en el orden de los pasos del Runbook: **primero** recolecta los artefactos volátiles mediante `AWS-RunShellScript` y sube el paquete cifrado a S3, y **después** aplica el Security Group de cuarentena sin salida (salvo que cuentes con VPC Endpoints privados para SSM y S3 en la red de cuarentena). Si cortaras todo el tráfico saliente antes de tener VPC Endpoints, el agente SSM perdería contacto antes de entregar la telemetría viva.
:::

### Coordinación de incidentes con AWS Incident Manager

**AWS Incident Manager** (capacidad integrada dentro de Systems Manager) estructura la respuesta operativa cuando salta una alarma crítica de CloudWatch o una regla de EventBridge alimentada por GuardDuty:

1. **Contacts & Escalation Plans:** Define responsables de guardia (On-Call), canales (SMS, correo, integraciones con Slack/Teams mediante AWS Chatbot) y tiempos de escalamiento si nadie reconoce el incidente.
2. **Response Plans:** Asocian la severidad del evento con la plantilla del incidente, los contactos a convocar y el **SSM Automation Runbook** que debe iniciarse automáticamente (o con aprobación de un clic) apenas se abre el incidente.
3. **Timeline y Post-Incident Analysis:** Registra cronológicamente qué métricas cambiaron, qué pasos ejecutó el runbook, qué analista intervino y genera plantillas de análisis post-incidente orientadas a causas raíz y acciones preventivas medibles.

---

## Práctica guiada en laboratorio

Vas a construir y validar en un entorno controlado de laboratorio los artefactos de contención y adquisición forense sin destruir evidencia volátil.

1. Definí la secuencia exacta de comandos para **contener una identidad comprometida** en AWS (desactivar llave, adjuntar `AWSDenyAll` y política `RevokeActiveSessions` con `aws:TokenIssueTime`) y su equivalente en GCP (`gcloud iam service-accounts disable`).
2. Escribí el script de **aislamiento de instancia EC2** que cree un Security Group sin ingress ni egress, desacople la instancia de su Auto Scaling Group, active `disable-api-termination` y aplique la cuarentena.
3. Redactá el procedimiento de **adquisición forense cross-account** en AWS: creación de snapshot EBS, copia recifrada con CMK KMS, compartición hacia la cuenta forense y montaje en solo lectura (`ro,noexec,noload`) con cálculo de SHA-256.
4. Adaptá y validá sintácticamente el documento YAML de **SSM Automation** para recolectar procesos, sockets y archivos abiertos hacia un bucket S3 de evidencia antes de aplicar la cuarentena estricta.

::: practica Entregable mínimo
Un runbook documentado de respuesta a incidentes que incluya: la matriz de orden de volatilidad aplicada a tu arquitectura cloud, los bloques CLI verificados de contención IAM y cuarentena de red (AWS + GCP/Azure), el flujo de transferencia de snapshot cifrado a cuenta forense y el archivo YAML del playbook SSM Automation listo para ejecutarse.
:::

::: defensa Perspectiva defensiva y mitigación
La capacidad de responder a un incidente en la nube se construye **antes** de que ocurra la intrusión: requiere tener preparada la cuenta forense aislada (*Clean Room*), las llaves CMK KMS habilitadas para recifrado de snapshots, VPC Endpoints para SSM/S3 operativos incluso bajo aislamiento de Internet, buckets con Object Lock para evidencia inmutable y runbooks probados en simulacros periódicos (*GameDays*) para evitar improvisar bajo presión.
:::

## Preguntas de repaso

**1. ¿Por qué apagar o terminar una instancia EC2 comprometida al detectar un incidente suele ser un error grave desde el punto de vista forense?** Porque al apagar o terminar la instancia se pierde de inmediato toda la memoria RAM (procesos residentes, llaves en memoria, payloads en ejecución), se destruyen los volúmenes efímeros locales y un Auto Scaling Group puede reemplazar la máquina eliminando evidencia clave antes de ser adquirida.

**2. ¿Por qué deshabilitar una Access Key o quitar una política IAM no basta para cortar de inmediato el acceso de un atacante que ya obtuvo credenciales temporales STS?** Porque los tokens temporales STS emitidos previamente siguen siendo válidos criptográficamente hasta su expiración; para revocarlos al instante es necesario adjuntar una política con `Deny` explícito condicionada a `aws:TokenIssueTime` (o `AWSDenyAll`) sobre el rol o identidad afectada.

**3. ¿Qué dos acciones previas son indispensables antes de aplicar un Security Group de cuarentena a una instancia EC2 que forma parte de un entorno autoescalado?** Desacoplar la instancia del Auto Scaling Group (`detach-instances`) y activar `disable-api-termination` (además de retirarla del Target Group del balanceador), evitando así que el fallo del *health check* provoque que el grupo termine automáticamente la máquina aislada.

**4. ¿Por qué es necesario copiar y recifrar un snapshot EBS con una Customer Managed Key (CMK) antes de compartirlo con una cuenta forense aislada?** Porque los snapshots cifrados con la llave administrada predeterminada de AWS (`aws/ebs`) no pueden compartirse entre cuentas distintas; copiarlo usando una CMK propia permite otorgar permisos de descifrado en la política de la llave hacia la cuenta forense (*Clean Room*).

**5. ¿Qué ventaja operativa aporta recolectar artefactos volátiles mediante AWS Systems Manager (SSM) en lugar de conectarse por SSH a una instancia comprometida?** Permite ejecutar comandos auditados en CloudTrail sin abrir el puerto 22 en el Security Group, sin exponer llaves privadas SSH en la máquina afectada y funcionando incluso sin salida a Internet si la VPC dispone de Interface Endpoints privados para SSM y S3.

## Antes de avanzar

::: nota Puerta de salida
Antes de dar por cerrado el módulo de seguridad en la nube, verificá que podés ordenar correctamente qué evidencia adquirir primero (RAM y sesiones antes que discos y logs), cómo contener identidades con tokens activos en AWS/Azure/GCP, cómo aislar una máquina virtual sin que el autoescalado la destruya y cómo trasladar snapshots cifrados a una cuenta forense limpia.
:::

## Referencias y estándares abiertos

- NIST SP 800-61 Rev. 2 / Rev. 3 — Computer Security Incident Handling Guide: [https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- AWS Security Incident Response Guide: [https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- AWS Systems Manager Incident Manager Documentation: [https://docs.aws.amazon.com/incident-manager/latest/userguide/what-is-incident-manager.html](https://docs.aws.amazon.com/incident-manager/latest/userguide/what-is-incident-manager.html)
- LiME (Linux Memory Extractor) & Volatility 3: [https://github.com/504ensicsLabs/LiME](https://github.com/504ensicsLabs/LiME) / [https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)
- Google Cloud Security Best Practices — Incident Response & Forensics: [https://cloud.google.com/architecture/framework/security/incident-response](https://cloud.google.com/architecture/framework/security/incident-response)
