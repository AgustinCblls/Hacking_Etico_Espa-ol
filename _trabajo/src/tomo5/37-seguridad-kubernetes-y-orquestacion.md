::: nota Objetivo de la lección
Al finalizar este capítulo vas a dominar la arquitectura interna de Kubernetes (plano de control y nodos trabajadores), auditar permisos en el modelo RBAC (`Role`, `ClusterRole`, `RoleBinding` y `ServiceAccount`) detectando combinaciones de riesgo como creación de pods, suplantación de identidad o lectura de secretos, evaluar riesgos de configuración en especificaciones de Pods y manejo de datos en `etcd`/`ConfigMaps`, diseñar aislamiento de tráfico con `NetworkPolicies`, y aplicar controles preventivos modernos mediante Pod Security Standards (PSS), motores de admisión (OPA Gatekeeper / Kyverno) y auditoría con `kube-bench`.
:::

Cuando una organización escala de decenas de contenedores individuales en un servidor hacia cientos o miles de cargas distribuidas en múltiples máquinas, necesita un orquestador. **Kubernetes (K8s)** se consolidó como el estándar de facto para automatizar despliegue, escalado y recuperación de contenedores, pero introduce un plano de control distribuido complejo basado en APIs REST declarativas.

En Kubernetes, comprometer un contenedor aislado ya no es el fin del análisis sino el posible punto de partida: **una mala configuración de RBAC, un token de cuenta de servicio montado innecesariamente o un Pod sin restricciones de seguridad puede comprometer todo el clúster**.

## Arquitectura del Clúster: Plano de Control y Nodos

Un clúster de Kubernetes se divide lógicamente en dos planos claramente diferenciados: el **Control Plane** (cerebro que toma decisiones globales y almacena el estado) y los **Worker Nodes** (máquinas donde corren efectivamente las aplicaciones dentro de Pods).

```
+-----------------------------------------------------------------------+
| CONTROL PLANE                                                         |
|  [kubectl / Usuarios] ---> [ kube-apiserver ] <---> [ etcd (TLS) ]    |
|                                ^        ^                             |
|                                |        |                             |
|                    [ kube-scheduler ] [ kube-controller-manager ]     |
+--------------------------------|--------------------------------------+
                                 | (HTTPS / mTLS)
+--------------------------------v--------------------------------------+
| WORKER NODE                                                           |
|  [ kubelet ] <---> [ Container Runtime (CRI: containerd / CRI-O) ]    |
|  [ kube-proxy ]    [ Pod A ] [ Pod B ]                                |
+-----------------------------------------------------------------------+
```

### Componentes Críticos y su Superficie de Seguridad

1. **`kube-apiserver`:** Es la única puerta de entrada al estado del clúster. Todas las peticiones (`kubectl`, controladores internos, nodos) pasan por su tubería de **Autenticación -> Autorización (RBAC) -> Control de Admisión** antes de persistirse. Nunca debe exponerse sin autenticación o con acceso anónimo habilitado (`--anonymous-auth=false` en entornos estrictos o fuertemente acotado).
2. **`etcd`:** Base de datos distribuida clave-valor que guarda **todo** el estado del clúster, incluidos manifiestos de configuración, tokens y objetos `Secret`. Si un actor logra acceso directo al puerto de `etcd` (TCP `2379`) sin autenticación mutua TLS (mTLS) o accede a copias de respaldo sin cifrar, obtiene control administrativo total del clúster.
3. **`kube-scheduler`:** Observa Pods recién creados sin nodo asignado y selecciona el Worker Node óptimo según recursos disponibles, afinidad y restricciones de seguridad (*taints* y *tolerations*).
4. **`kube-controller-manager`:** Ejecuta bucles de control continuos (Controlador de Replicación, Controlador de Nodos, Controlador de Tokens de ServiceAccount) para reconciliar el estado real con el estado deseado.
5. **`kubelet`:** Agente residente en cada Worker Node que recibe especificaciones de Pods desde el `kube-apiserver` y ordena su ejecución al **CRI** (*Container Runtime Interface*, típicamente `containerd` o `CRI-O`). Expone su propia API (puerto TCP `10250`); históricamente, configurarlo con `--anonymous-auth=true` y `--authorization-mode=AlwaysAllow` permitía ejecutar comandos remotos dentro de los Pods del nodo sin credenciales.
6. **`kube-proxy`:** Mantiene las reglas de red (iptables/IPVS/eBPF) en cada nodo para enrutar servicios internos, pero **no** aplica aislamiento de firewall entre Pods por sí solo (para eso se requiere un plugin CNI compatible con `NetworkPolicy`, como Cilium o Calico).

## RBAC (Role-Based Access Control) y Riesgos de Autorización

Kubernetes utiliza **RBAC** como mecanismo estándar de autorización sobre los recursos de la API. Todo permiso es **denegado por defecto** y únicamente existen reglas aditivas (`allow`); a diferencia de AWS IAM, **RBAC de Kubernetes no posee reglas explícitas de `Deny`**.

### Objetos Fundamentales de RBAC

| Objeto RBAC | Ámbito | Propósito |
| :--- | :--- | :--- |
| **`Role`** | Un único Namespace | Define verbos (`get`, `list`, `create`, `delete`, `patch`) sobre recursos dentro de ese namespace |
| **`ClusterRole`** | Todo el clúster (o reutilizable por namespace) | Define permisos sobre nodos, namespaces, PersistentVolumes o recursos globales |
| **`RoleBinding`** | Un único Namespace | Vincula un `Role` (o `ClusterRole`) con sujetos (`User`, `Group`, `ServiceAccount`) solo dentro de ese namespace |
| **`ClusterRoleBinding`** | Todo el clúster | Otorga los permisos de un `ClusterRole` a nivel global en todos los namespaces |
| **`ServiceAccount`** | Un único Namespace | Identidad no humana asignada automáticamente a los Pods para autenticarse ante el `kube-apiserver` |

### Combinaciones RBAC de Alto Riesgo

Al auditar manifiestos RBAC, debés buscar permisos que permiten escalar privilegios dentro de un namespace o hacia el clúster completo:

- **Creación o modificación de cargas de trabajo (`create pods`, `deployments`, `daemonsets`):** Un sujeto que puede crear Pods dentro de un namespace puede definir en el YAML un Pod privilegiado o que monte el token de otro `ServiceAccount` existente en el mismo namespace con mayores privilegios.
- **Lectura masiva de secretos (`get`/`list`/`watch` sobre `secrets`):** Permite extraer tokens de ServiceAccounts de larga duración, contraseñas de bases de datos o certificados TLS almacenados en el namespace o en todo el clúster si está vinculado por `ClusterRoleBinding`.
- **Suplantación de identidad (`impersonate` sobre `users`, `groups` o `serviceaccounts`):** Permite que una identidad actúe ante el `kube-apiserver` enviando cabeceras de suplantación (`Impersonate-User: system:masters`), asumiendo el nivel de privilegio del sujeto suplantado.
- **Modificación de enlaces RBAC (`bind` / `escalate` / `create rolebindings`):** Permite asignar roles existentes de mayor jerarquía a la propia cuenta de servicio.
- **Ejecución remota (`pods/exec` o `pods/attach`):** Habilita abrir sesiones interactivas en contenedores ya en ejecución dentro del namespace y acceder a los secretos montados en sus procesos.

```yaml
# Ejemplo de Role RBAC bien acotado (Principio de Mínimo Privilegio)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: produccion-pagos
  name: lector-configuracion-acotado
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["config-publica-app"] # Restringido a un recurso específico, no a todo el namespace
  verbs: ["get"]
```

## Riesgos Críticos en la Especificación de Pods

Por defecto, Kubernetes monta automáticamente un token JWT del `ServiceAccount` `default` dentro de cada Pod en `/var/run/secrets/kubernetes.io/serviceaccount/token` e inicia los contenedores sin restricciones estrictas sobre `securityContext`.

Los principales indicadores de riesgo en un manifiesto `Pod` o `Deployment` son:

1. **`securityContext.privileged: true`:** Equivalente a `--privileged` en Docker; otorga control total de capabilities y dispositivos del nodo trabajador subyacente.
2. **`hostPID: true` / `hostIPC: true` / `hostNetwork: true`:** Rompe el aislamiento de namespaces compartiendo el árbol de procesos, memoria compartida o interfaces de red del nodo anfitrión (incluyendo escucha en puertos del nodo o acceso a interfaces locales de metadatos/kubelet).
3. **`volumes` con `hostPath`:** Monta directorios arbitrarios del nodo trabajador (como `/`, `/var/log`, `/etc/kubernetes` o el socket del runtime `/run/containerd/containerd.sock`) directamente dentro del Pod.
4. **Tokens montados innecesariamente:** Si una aplicación web no necesita consultar la API de Kubernetes, dejar `automountServiceAccountToken` habilitado por defecto expone credenciales internas válidas ante cualquier vulnerabilidad de aplicación (por ejemplo, lectura local de archivos). Debés fijar explícitamente **`automountServiceAccountToken: false`** en la definición del `ServiceAccount` o del Pod.

## Secretos en `etcd` y Manejo de `ConfigMaps`

Un error conceptual frecuente es asumir que los objetos `Secret` de Kubernetes están cifrados por defecto. **En realidad, los `Secrets` simplemente se codifican en Base64** en los manifiestos y, si no se configura explícitamente **Encryption at Rest** (`EncryptionConfiguration` en el `kube-apiserver` usando KMS o AES-CBC/GCM), se almacenan en **texto claro** dentro de `etcd`.

Por su parte, los **`ConfigMaps`** están pensados exclusivamente para configuración no sensible (banderas de entorno, rutas, puertos). Jamás debés almacenar claves API o cadenas de conexión en un `ConfigMap`, ya que suelen ser legibles por múltiples roles de monitoreo y desarrollo con permisos amplios de lectura. Para entornos productivos exigentes, la mejor práctica es utilizar gestores externos como **External Secrets Operator (ESO)** o **CSI Secrets Store Driver** integrados con AWS Secrets Manager, Azure Key Vault o HashiCorp Vault.

## Aislamiento de Red con NetworkPolicies

Por defecto, la red de Kubernetes es **plana**: cualquier Pod en cualquier namespace puede comunicarse libremente con cualquier otro Pod del clúster. Para implementar microsegmentación de confianza cero (*Zero Trust*), se definen objetos **`NetworkPolicy`** (que requieren un plugin CNI con soporte activo, como Calico, Cilium o Antrea).

Un enfoque profesional comienza aplicando una política de **denegación por defecto** (*Default Deny*) para todo el tráfico entrante y saliente en cada namespace productivo, y luego habilitando explícitamente únicamente los flujos indispensables:

```yaml
# 1. Bloquear todo tráfico entrante y saliente por defecto en el namespace 'pagos'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: pagos
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# 2. Permitir únicamente tráfico de la API hacia PostgreSQL en el puerto 5432
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: permitir-api-a-postgres
  namespace: pagos
spec:
  podSelector:
    matchLabels:
      app: postgres-pagos
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api-pagos
    ports:
    - protocol: TCP
      port: 5432
```

## Pod Security Standards (PSS) y Control de Admisión

Tras la eliminación definitiva de *PodSecurityPolicy (PSP)* en Kubernetes 1.25, el estándar nativo incorporado en el plano de control es **Pod Security Admission (PSA)** aplicando los **Pod Security Standards (PSS)** mediante etiquetas directamente en cada `Namespace`.

| Perfil PSS | Nivel de Restricción | Qué Permite o Bloquea |
| :--- | :--- | :--- |
| **`Privileged`** | Sin restricciones | Permite cualquier configuración (solo para infraestructura crítica del sistema como CNI/CSI) |
| **`Baseline`** | Protección mínima estándar | Bloquea escaladas conocidas: prohíbe `privileged: true`, `hostNetwork`, `hostPID`, `hostIPC`, `hostPath` y capabilities peligrosas |
| **`Restricted`** | Endurecimiento máximo recomendado | Exige además ejecución no root (`runAsNonRoot: true`), `allowPrivilegeEscalation: false`, eliminación de todas las capabilities (`drop: ["ALL"]`) y perfil `seccompProfile: RuntimeDefault` |

PSA puede operar en tres modos simultáneos por namespace: `enforce` (rechaza Pods que violen el perfil), `audit` (registra la infracción en el log de auditoría) y `warn` (advierte al usuario por CLI).

```yaml
# Etiquetar un namespace para exigir el perfil Restricted en producción
apiVersion: v1
kind: Namespace
metadata:
  name: produccion-pagos
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
# Fragmento de Pod compatible con el perfil PSS Restricted
apiVersion: v1
kind: Pod
metadata:
  name: api-pagos-endurecida
  namespace: produccion-pagos
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: api
    image: mi-org/api-pagos@sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
```

### Motores de Políticas de Admisión: OPA Gatekeeper y Kyverno

Cuando los requisitos organizacionales superan el alcance de PSS (por ejemplo: prohibir imágenes sin firmar, exigir etiquetas de propietario, impedir repositorios públicos no autorizados o validar reglas personalizadas en Ingress), se implementan **Validating/Mutating Admission Webhooks**:

- **OPA Gatekeeper:** Basado en Open Policy Agent y el lenguaje declarativo **Rego**; evalúa restricciones complejas mediante `ConstraintTemplates` y `Constraints`.
- **Kyverno:** Motor nativo de Kubernetes que define políticas de validación, mutación y generación directamente en **YAML** sin necesidad de aprender un lenguaje de consulta externo, lo que acelera su adopción en equipos DevSecOps.

## Seguridad en Runtime en Kubernetes con eBPF (Falco y Tetragon)

Los controles de admisión (`PSA`, Gatekeeper, Kyverno) inspeccionan el manifiesto YAML **antes** de que el Pod arranque, pero no ven lo que ocurre **adentro** del contenedor si una aplicación sufre ejecución remota de código o si un usuario autorizado abre una sesión interactiva. Para cubrir esa brecha en tiempo real se despliegan sensores basados en **eBPF** como `DaemonSet` en cada Worker Node —principalmente **Falco** (detección y alertas) y **Cilium Tetragon** (observabilidad y bloqueo activo en kernel mediante `TracingPolicy`)— capaces de correlacionar llamadas al sistema con metadatos de Kubernetes (namespace, Pod, imagen y cuenta de servicio):

1. **Detección de shells dentro de contenedores (`kubectl exec` o spawn anómalo):** Alerta cuando un proceso de aplicación (`nginx`, `node`, `java`, `python`) lanza `/bin/sh` o `/bin/bash`, o cuando alguien inicia una shell interactiva mediante `kubectl exec` en producción.
2. **Lectura inesperada de tokens de *ServiceAccount*:** Monitorea aperturas (`openat`) sobre `/var/run/secrets/kubernetes.io/serviceaccount/token` realizadas por procesos que no corresponden al binario legítimo de la aplicación (por ejemplo `curl`, `cat` o un intérprete recién invocado).
3. **Acceso o montaje inesperado a rutas sensibles del nodo:** Detecta intentos de lectura o escritura sobre `/etc/shadow`, `/etc/kubernetes/pki`, `/proc/sysrq-trigger` o el socket del runtime (`/run/containerd/containerd.sock`) desde procesos en contenedores.

```yaml
# Ejemplo de regla Falco (eBPF) para detectar lectura del token de ServiceAccount por utilidades o shells
- rule: Lectura sospechosa de token ServiceAccount en contenedor
  desc: Detecta acceso al token JWT de Kubernetes desde shells o herramientas CLI dentro de un Pod
  condition: >
    open_read and container and
    fd.name startswith "/var/run/secrets/kubernetes.io/serviceaccount" and
    proc.name in (sh, bash, dash, cat, curl, wget, python3)
  output: >
    Acceso anomalo a token K8s (ns=%k8s.ns.name pod=%k8s.pod.name
    proc=%proc.name cmd=%proc.cmdline file=%fd.name)
  priority: WARNING
```

*(Nota operativa Purple Team: si usás **Tetragon**, además de registrar el evento en JSON podés adjuntar una acción `Sigkill` sobre `sys_execve` o `security_file_open` para frenar la ejecución en el kernel en microsegundos tras validar la regla en modo auditoría).*

## Auditoría con CIS Kubernetes Benchmark y `kube-bench`

Al igual que en Docker, la verificación sistemática de la configuración del plano de control, `etcd`, `kubelet` y políticas del clúster se automatiza mediante **CIS Kubernetes Benchmark** utilizando la herramienta de código abierto **`kube-bench`** de Aqua Security, complementada con comandos nativos de verificación `kubectl auth can-i`:

```bash
# 1. Auditar qué acciones tiene permitidas el ServiceAccount actual o un usuario específico
kubectl auth can-i --list --namespace=produccion-pagos
kubectl auth can-i create pods --as=system:serviceaccount:produccion-pagos:app-sa -n produccion-pagos

# 2. Listar todos los ClusterRoleBindings para detectar asignaciones amplias (ej. cluster-admin)
kubectl get clusterrolebindings -o custom-columns="NOMBRE:.metadata.name,ROL:.roleRef.name,SUJETOS:.subjects[*].name"

# 3. Buscar Pods en ejecución con configuración privilegiada o namespaces del host compartidos
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] | select(
    .spec.hostPID == true or
    .spec.hostNetwork == true or
    (.spec.containers[]?.securityContext.privileged == true)
  ) | "\(.metadata.namespace)/\(.metadata.name)"'

# 4. Ejecutar auditoría de cumplimiento CIS Kubernetes Benchmark en un clúster local (kind / k3s / minikube)
kube-bench run --targets master,node,policies
```

## Práctica guiada en laboratorio
Desplegá un clúster local liviano en tu estación de trabajo utilizando **`kind`** (*Kubernetes in Docker*) o **`k3s`** con un CNI compatible con `NetworkPolicy` (como Calico o Cilium). Creá un namespace `lab-seguro` etiquetado con Pod Security Standards en modo `enforce: restricted`. Intentá aplicar un manifiesto de Pod inseguro (con `privileged: true` o sin `runAsNonRoot: true`) para verificar que el controlador de admisión lo rechaza en tiempo real. Luego corregí el manifiesto aplicando `securityContext` endurecido, `automountServiceAccountToken: false` y una `NetworkPolicy` de denegación por defecto.

::: practica Entregable mínimo
Consolidá en un archivo `auditoria-k8s-lab.md`:
1. El mensaje exacto de rechazo emitido por Pod Security Admission al intentar desplegar el Pod inseguro en `lab-seguro`.
2. El YAML final del Pod o Deployment aprobado bajo perfil `restricted` junto con el `Role` RBAC mínimo y la `NetworkPolicy` *default-deny*.
3. Un resumen con al menos 3 hallazgos (`FAIL` o `WARN`) detectados al ejecutar `kube-bench` o `kubectl auth can-i --list` en tu clúster de laboratorio y su plan de remediación.
:::

::: defensa Perspectiva defensiva y endurecimiento
- **Blindá el plano de control y `etcd`:** Exigí mTLS entre `kube-apiserver` y `etcd`, habilitá el cifrado en reposo (`EncryptionConfiguration`) con KMS externo, deshabilitá la autenticación anónima en `kubelet` y activá los *Audit Logs* de la API para monitorear eventos de RBAC y `pods/exec`.
- **Implementá PSS `restricted` y motores de admisión:** Aplicá `pod-security.kubernetes.io/enforce: restricted` en todos los namespaces de aplicación y complementalo con **Kyverno** u **OPA Gatekeeper** para validar firmas de imágenes y bloquear etiquetas `:latest`.
- **Principio de mínimo privilegio en RBAC y tokens:** Fijá `automountServiceAccountToken: false` en los ServiceAccounts predeterminados, evitá `ClusterRoleBindings` innecesarios y auditá periódicamente permisos críticos (`impersonate`, `secrets`, `create pods`, `bind`).
- **Microsegmentación por defecto:** Desplegá un CNI con soporte completo de `NetworkPolicy` e imponé políticas `default-deny` de ingreso y egreso en cada namespace antes de habilitar comunicaciones entre microservicios.
:::

## Preguntas de repaso

**1. ¿Por qué `etcd` representa el componente más sensible del plano de control de Kubernetes?** Porque almacena la totalidad del estado del clúster, incluyendo configuraciones, credenciales de acceso y objetos `Secret`. Si no se habilita cifrado en reposo (`EncryptionConfiguration`) ni autenticación mutua TLS estricta, la lectura directa de `etcd` expone los secretos de todos los namespaces en texto plano (codificados únicamente en Base64).

**2. ¿Qué riesgo implica otorgar el permiso RBAC `create` sobre `pods` a un usuario o ServiceAccount en un namespace compartido?** Aunque la identidad no tenga permiso directo para leer `secrets`, puede crear un Pod que monte los secretos o el `ServiceAccount` de mayor privilegio existente en ese mismo namespace, o intentar desplegar configuraciones de riesgo si no hay políticas de admisión que lo impidan.

**3. ¿Qué diferencia existe entre una `NetworkPolicy` y un objeto `Service` en Kubernetes?** Un `Service` provee descubrimiento y balanceo de tráfico interno, mientras que una `NetworkPolicy` actúa como reglas de firewall L3/L4 aplicadas por el plugin CNI para aislar qué Pods o namespaces pueden enviar o recibir tráfico entre sí.

**4. ¿Qué exige el perfil `restricted` de Pod Security Standards (PSS) que el perfil `baseline` no impone?** Además de bloquear configuraciones peligrosas de host (`privileged`, `hostNetwork`, `hostPath`), el perfil `restricted` obliga a ejecutar contenedores sin privilegios de root (`runAsNonRoot: true`), deshabilitar la escalada de privilegios (`allowPrivilegeEscalation: false`), eliminar todas las capabilities (`drop: ["ALL"]`) y definir un perfil `seccompProfile` válido (`RuntimeDefault` o `Localhost`).

**5. ¿Para qué sirve la propiedad `automountServiceAccountToken: false` y cuándo conviene aplicarla?** Evita que Kubernetes inyecte automáticamente el token JWT del `ServiceAccount` dentro del sistema de archivos del Pod (`/var/run/secrets/kubernetes.io/serviceaccount/token`). Conviene aplicarla en todo Pod y cuenta de servicio de aplicación que no necesite interactuar directamente con la API de Kubernetes, reduciendo la superficie de exposición ante fallos de aplicación.

## Antes de avanzar

::: nota Puerta de salida
Antes de continuar hacia los capítulos siguientes de seguridad en pipelines DevSecOps y respuesta a incidentes en la nube, verificá que cumplís estos criterios:
- Identificás el rol de cada componente del plano de control (`kube-apiserver`, `etcd`, `kube-scheduler`) y del worker node (`kubelet`, CRI).
- Sabés auditar roles RBAC, detectar combinaciones de alto riesgo y restringir `ServiceAccount` tokens.
- Podés escribir e implementar políticas `NetworkPolicy` *default-deny*, aplicar Pod Security Standards `restricted` y auditar un clúster con `kube-bench`.
:::

## Referencias y estándares abiertos

- **CIS Kubernetes Benchmark (Center for Internet Security):** Controles exhaustivos de endurecimiento para `kube-apiserver`, `etcd`, `kubelet`, políticas RBAC y configuración de red.
- **Kubernetes Official Documentation – Pod Security Standards & RBAC:** Especificación oficial de los perfiles `Privileged`, `Baseline` y `Restricted`, así como reglas de autorización.
- **NSA / CISA Kubernetes Hardening Guidance:** Guía conjunta de arquitectura segura enfocada en aislamiento de red, cifrado de secretos, motores de admisión y auditoría de registros.
- **OWASP Kubernetes Security Cheat Sheet:** Recomendaciones operativas para desarrolladores y administradores de clústeres productivos.
