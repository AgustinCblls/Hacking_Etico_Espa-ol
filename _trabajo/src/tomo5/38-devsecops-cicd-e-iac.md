::: nota Objetivo de la lección
En este capítulo vas a analizar la superficie de ataque de los pipelines de integración y entrega continua (CI/CD) y de la Infraestructura como Código (IaC). Vas a aprender a identificar configuraciones inseguras en GitHub Actions, GitLab CI y Jenkins, implementar higiene de secretos en Git, integrar controles automatizados (SAST, DAST, SCA y SBOM), auditar plantillas Terraform con herramientas estáticas y reemplazar credenciales estáticas mediante federación OIDC y firma criptográfica de artefactos con Sigstore/Cosign.
:::

## El pipeline CI/CD como superficie de ataque en la cadena de suministro

En arquitecturas modernas, el sistema de CI/CD concentra privilegios que rara vez coinciden en otro componente: lee el código fuente, accede a secretos de despliegue, construye artefactos de producción y posee identidad para modificar infraestructura cloud. Desde una perspectiva defensiva, comprometer un flujo de compilación equivale a obtener ejecución remota dentro de un entorno confiable aguas arriba del entorno productivo.

En plataformas como **GitHub Actions**, **GitLab CI/CD** y **Jenkins**, el modelo de amenazas gira en torno a cuatro fronteras de confianza: el disparador (*trigger*) que inicia el trabajo, la evaluación de variables provenientes de entradas externas, el aislamiento del agente ejecutor (*runner*) y el alcance mínimo de los tokens efímeros emitidos durante la ejecución.

### Riesgos en disparadores privilegiados: `pull_request_target` y contextos no confiables

Uno de los errores más graves en GitHub Actions ocurre al combinar el evento `pull_request_target` con el checkout explícito del código propuesto por un colaborador externo (por ejemplo, desde un *fork*). A diferencia del evento `pull_request` —que se ejecuta en un contexto aislado de solo lectura y sin acceso a secretos cuando proviene de un fork—, `pull_request_target` se ejecuta en el contexto de la rama base del repositorio destino: tiene acceso a los secretos configurados y puede recibir un `GITHUB_TOKEN` con permisos de escritura.

Si el flujo hace checkout de `github.event.pull_request.head.sha` o `github.event.pull_request.head.ref` y luego ejecuta pasos de compilación, pruebas (`npm test`, `pytest`, `make`) o linters con plugins cargados desde el repositorio, el código no revisado del pull request se ejecuta dentro del entorno privilegiado de la rama base.

```yaml
# PATRÓN INSEGURO: nunca hagas checkout del head de un PR bajo pull_request_target
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }} # Peligro: código no confiable con secretos
      - run: npm ci && npm test
```

La mitigación arquitectónica consiste en separar responsabilidades: usar `pull_request` (sin secretos ni permisos elevados) para compilar, correr tests y subir un artefacto inerte si hace falta; y reservar un segundo flujo disparado por `workflow_run` (con validaciones estrictas sobre los datos consumidos y sin ejecutar código del artefacto) para tareas que requieran comentar en el PR o etiquetarlo.

### Inyección de expresiones en flujos de trabajo

Otro vector frecuente es la interpolación directa de metadatos controlables por usuarios externos (títulos de issues o PRs, nombres de ramas, cuerpos de comentarios o mensajes de commit) dentro de bloques `run:` mediante la sintaxis `${{ ... }}`. El motor de GitHub Actions sustituye la expresión **antes** de entregar el script al intérprete de shell (`bash` o `pwsh`), de modo que comillas, operadores de encadenamiento o sustituciones de comando presentes en el texto se interpretan como sintaxis del shell.

La regla defensiva es absoluta: nunca interpoles expresiones `${{ github.event.* }}` directamente dentro de `run:`. En su lugar, pasá esos valores a través del bloque `env:` y referencialos como variables de entorno entrecomilladas en el script:

```yaml
# PATRÓN ENDURECIDO: paso seguro por variables de entorno
name: Validar título de PR
on:
  pull_request:
    types: [opened, edited]

permissions:
  contents: read

jobs:
  check-title:
    runs-on: ubuntu-latest
    steps:
      - name: Inspeccionar título sin interpolación directa
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
          HEAD_REF: ${{ github.head_ref }}
        run: |
          printf 'Revisando rama: %s\n' "$HEAD_REF"
          if [[ ! "$PR_TITLE" =~ ^(feat|fix|chore|docs): ]]; then
            echo "El título debe seguir Conventional Commits."
            exit 1
          fi
```

### Runners compartidos persistentes y exposición de tokens

Tanto en Jenkins (agentes estáticos compartidos entre múltiples proyectos) como en GitLab CI o GitHub Actions con *self-hosted runners* persistentes, reutilizar el mismo sistema de archivos o demonio de contenedores entre ejecuciones rompe el aislamiento entre trabajos. Un proceso anterior —o una ejecución sobre una rama no confiable— puede dejar archivos residuales en `/tmp`, modificar herramientas en `$PATH`, leer cachés compartidas o interactuar con `/var/run/docker.sock` si el runner monta el socket del host.

::: peligro Runners persistentes en repositorios públicos
Nunca habilites *self-hosted runners* persistentes para ejecutar flujos disparados por forks externos en repositorios públicos. Todo ejecutor que procese código no confiable debe ser **efímero** (destruido inmediatamente al finalizar el job mediante micro-VMs o pods aislados como Actions Runner Controller) y operar con conectividad de salida restringida.
:::

Respecto al token automático del pipeline (`GITHUB_TOKEN` en GitHub o `CI_JOB_TOKEN` en GitLab), aplicá siempre el principio de mínimo privilegio:

1. En GitHub Actions, declará `permissions: read-all` o un mapa vacío `{}` a nivel global del workflow y otorgá permisos puntuales (`contents: read`, `security-events: write`, `id-token: write`) únicamente al job que los necesite.
2. Fijá las acciones de terceros por **hash SHA-1 completo del commit** (no solo por etiqueta mutable como `@v4`) y habilitá Dependabot para mantenerlas actualizadas de forma auditable.
3. En GitLab CI, restringí el alcance de `CI_JOB_TOKEN` habilitando la lista de proyectos autorizados (*CI/CD job token allowlist*).
4. En Jenkins, evitá almacenar credenciales globales accesibles desde cualquier `Jenkinsfile`; usá carpetas con credenciales con ámbito limitado (*Folder-scoped credentials*), el bloque `withCredentials` con enmascaramiento de salida y `agent none` a nivel raíz.

---

## Higiene de secretos en repositorios Git

Cada vez que una clave de API, certificado privado o token de base de datos llega a un commit de Git, deja de ser un secreto en el instante en que se sincroniza con un remoto o se replica en clones y cachés de CI. Borrar la línea en un commit posterior no resuelve el problema: el objeto blob sigue intacto en el historial y en referencias internas como `refs/pull/*`.

La estrategia defensiva combina prevención local, bloqueo en servidor y detección continua en el historial:

- **Bloqueo temprano (`pre-commit` y Push Protection):** Configurar hooks locales que analicen el *staging area* antes de confirmar el commit, complementados con controles del lado del servidor (como GitHub Push Protection) que rechazan el `git push` si detectan patrones conocidos.
- **Escaneo en CI sobre commits e historial completo:** Ejecutar herramientas como `gitleaks` y `trufflehog` en cada Pull Request (analizando el rango de commits nuevo) y de forma periódica sobre todo el repositorio. `trufflehog` aporta además verificación activa contra proveedores compatibles para distinguir credenciales reales de cadenas de prueba.

```bash
# Escaneo incremental en CI con gitleaks sobre los commits de un PR
gitleaks detect \
  --source . \
  --log-opts="origin/main..HEAD" \
  --config .gitleaks.toml \
  --redact \
  --exit-code 1

# Análisis completo de historial y verificación de estado con trufflehog
trufflehog git file://. --only-verified --json > trufflehog-report.json
```

Podés afinar falsos positivos sin desactivar reglas críticas declarando un archivo `.gitleaks.toml` versionado y revisado por el equipo de seguridad:

```toml
title = "Política corporativa de detección de secretos"

[extend]
useDefault = true

[allowlist]
description = "Excluir fixtures sintéticos de pruebas unitarias"
paths = [
  '''^tests/fixtures/.*\.json$''',
]
regexes = [
  '''EXAMPLE_KEY_DO_NOT_USE_[0-9]{6}''',
]
```

::: aviso Orden correcto ante una filtración confirmada
Si detectás una credencial real en un repositorio, **primero revocá y rotá el secreto** en el proveedor origen y revisá los logs de auditoría para descartar uso anómalo. Recién después evaluá limpiar el historial con `git filter-repo` y forzar la actualización de ramas; reescribir el historial sin rotar la clave genera una falsa sensación de seguridad.
:::

---

## Puertas de seguridad automatizadas: SAST, DAST, SCA y SBOM

Un pipeline DevSecOps maduro distribuye verificaciones complementarias en distintas etapas del ciclo de vida, equilibrando velocidad de retroalimentación para desarrollo con rigor de bloqueo hacia producción.

| Control | Qué inspecciona | Momento óptimo en CI | Herramientas abiertas típicas |
| :--- | :--- | :--- | :--- |
| **SAST** | Código fuente propio y flujo de datos | Cada PR (análisis diferencial rápido) | Semgrep, CodeQL, Bandit |
| **SCA** | Dependencias declaradas y transitivas | Cada PR + escaneo nocturno | Trivy (`fs`), `pip-audit`, `npm audit`, Grype |
| **SBOM** | Inventario formal de componentes | En cada build de release o contenedor | Syft, Trivy (`sbom`), CycloneDX CLI |
| **DAST** | Aplicación desplegada en ejecución | Entorno efímero de staging previo a prod | OWASP ZAP, Nuclei (plantillas controladas) |

### Análisis estático (SAST) con Semgrep

Las expresiones regulares simples producen demasiados falsos positivos porque ignoran la sintaxis del lenguaje. **Semgrep** analiza el árbol de sintaxis abstracta (AST) y permite escribir reglas legibles en YAML adaptadas a los patrones internos de tu organización, además de exportar resultados en formato estándar **SARIF** para integrarlos en la pestaña de seguridad del repositorio.

```yaml
# .semgrep/python-tls-check.yml
rules:
  - id: requests-tls-verification-disabled
    patterns:
      - pattern: requests.$METHOD(..., verify=False, ...)
    message: >-
      Se deshabilitó la validación de certificados TLS (verify=False).
      Usá el almacén de confianza del sistema o un bundle CA explícito.
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-295"
```

### SCA y generación de SBOM (CycloneDX y SPDX)

El análisis de composición de software (**SCA**) exige trabajar siempre con archivos de bloqueo deterministas (`package-lock.json`, `poetry.lock`, `go.sum`) para conocer las versiones transitivas exactas que llegan a producción. A su vez, generar un **SBOM** (*Software Bill of Materials*) en cada compilación te permite saber en segundos qué servicios usan una librería vulnerable cuando aparece una vulnerabilidad crítica nueva, sin necesidad de recompilar todo el parque de aplicaciones.

Los dos estándares abiertos predominantes son **CycloneDX** (muy orientado a seguridad, dependencias y documentos VEX de explotabilidad) y **SPDX** (estándar ISO/IEC 5962 ampliamente usado para licencias y cumplimiento).

```bash
# Generar SBOM CycloneDX de un directorio de proyecto e inspeccionar vulnerabilidades
syft dir:. -o cyclonedx-json=sbom.cdx.json
grype sbom:./sbom.cdx.json --fail-on high

# Alternativa equivalente con Trivy en formato SPDX para una imagen OCI
trivy image --format spdx-json --output image.spdx.json ghcr.io/org/app:1.4.2
```

### Casos reales de *Supply Chain* (2024–2026), NIST SSDF y *OpenSSF Scorecard*

| Caso real | Componente afectado | Mecanismo de compromiso | Contramedida de ingeniería clave |
| :--- | :--- | :--- | :--- |
| **`xz-utils`** (`CVE-2024-3094`) | Utilidad `xz` / `liblzma` | Puerta trasera oculta en *tarballs* de compilación tras cooptar el rol de mantenedor. | Revisiones múltiples de mantenedores, compilaciones reproducibles y monitoreo de artefactos binarios. |
| **`Leaky Vessels`** (`CVE-2024-21626` y afines) | `runc` y `BuildKit` | Fuga de descriptores de archivos del host durante construcción/arranque de contenedores. | Parchear runtime OCI, aislar *builders* en nodos efímeros sin privilegios y evitar Dockerfiles no confiables. |
| **`IngressNightmare`** (`CVE-2025-1974` y afines) | Kubernetes `Ingress-NGINX` | Ejecución remota sin autenticación mediante el *admission webhook* exponiendo secretos del clúster. | Restringir red hacia webhooks de admisión solo al plano de control, parchear urgente y aplicar mínimo privilegio RBAC. |
| **`tj-actions/changed-files`** (`CVE-2025-30066`) | GitHub Actions de terceros | Alteración retroactiva de etiquetas (`@v44`) para imprimir secretos de CI/CD en logs de *workflows*. | **Fijar acciones por hash SHA completo** (`@<commit-sha>`), tokens efímeros mínimos y no usar secretos en repos públicos. |
| **`Shai-Hulud`** (npm / PyPI 2025) | Registros de paquetes públicos | Gusano en scripts `preinstall` que roba tokens cloud/registro y republica versiones infectadas. | Deshabilitar scripts automáticos (`--ignore-scripts`) en CI, usar *lockfiles* estrictos y **MFA FIDO2** en cuentas de publicación. |

Para gobernar este ciclo de forma sistemática, combiná **NIST SSDF (`SP 800-218`)** (prácticas verificables de preparación, compilación aislada y respuesta a vulnerabilidades) con **`OpenSSF Scorecard`**, que audita automáticamente repositorios en busca de protección de ramas, dependencias fijadas por SHA, firmas y permisos mínimos en `GITHUB_TOKEN`.

### Pruebas dinámicas (DAST) controladas

El **DAST** evalúa cabeceras HTTP de seguridad, exposición de endpoints administrativos, errores de CORS y fallas en flujos de autenticación contra una instancia viva desplegada en un entorno efímero de *staging* (nunca contra producción sin autorización ni ventanas de control). Un patrón práctico es levantar la aplicación con Docker Compose dentro del job de CI y ejecutar un escaneo base o contra la especificación OpenAPI con OWASP ZAP.

---

## Seguridad de Infraestructura como Código (IaC)

Cuando la infraestructura se define declarativamente en **Terraform (HCL)**, **OpenTofu** o **AWS CloudFormation**, los errores de configuración (buckets públicos, grupos de seguridad abiertos a `0.0.0.0/0`, discos sin cifrar o roles IAM con comodines) pueden detectarse antes de crear un solo recurso en la nube (*shift-left*).

Compará un bloque Terraform con omisiones frecuentes frente a su versión endurecida:

```hcl
# ANTES: bucket S3 sin cifrado explícito ni bloqueo de acceso público
resource "aws_s3_bucket" "logs_legacy" {
  bucket = "empresa-logs-aplicacion"
}

# DESPUÉS: bucket S3 endurecido en código declarativo
resource "aws_s3_bucket" "logs_seguros" {
  bucket = "empresa-logs-aplicacion"
}

resource "aws_s3_bucket_public_access_block" "logs_seguros" {
  bucket                  = aws_s3_bucket.logs_seguros.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs_seguros" {
  bucket = aws_s3_bucket.logs_seguros.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.logs.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "logs_seguros" {
  bucket = aws_s3_bucket.logs_seguros.id
  versioning_configuration {
    status = "Enabled"
  }
}
```

Para automatizar esta auditoría en cada Pull Request se utilizan motores estáticos como **Checkov** y **Trivy Config** (que integró las capacidades de `tfsec`). Además de reglas integradas basadas en guías CIS, podés definir políticas personalizadas para hacer cumplir convenciones internas (por ejemplo, exigir etiquetas `Owner` y `Environment` o prohibir cierto tipo de instancia).

```bash
# Auditoría estática de Terraform y CloudFormation con Checkov y Trivy
checkov -d ./infra/terraform --framework terraform --compact --soft-fail-on LOW
trivy config ./infra/terraform --severity HIGH,CRITICAL --exit-code 1
```

---

## Autenticación sin llaves estáticas (OIDC) y firma de artefactos con Sigstore

Almacenar pares `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` o archivos JSON de Service Accounts de GCP dentro de los secretos del repositorio es un riesgo estructural: las credenciales son de larga duración, suelen tener permisos amplios y requieren rotación manual periódica.

La solución moderna es **OpenID Connect (OIDC)** entre el proveedor CI/CD y el proveedor cloud. Durante la ejecución, el runner solicita un JWT firmado por el emisor OIDC de la plataforma (por ejemplo, `https://token.actions.githubusercontent.com`) con *claims* criptográficos que identifican exactamente el repositorio, la rama, el entorno de aprobación y el commit. AWS STS, GCP Workload Identity Federation o Azure Entra ID validan ese JWT contra la política de confianza y entregan credenciales temporales válidas solo por unos minutos.

### Ejemplo real de federación OIDC hacia AWS

En AWS IAM, la política de confianza (*Trust Policy*) del rol de despliegue restringe estrictamente qué repositorio y rama pueden asumirlo:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:mi-org/mi-servicio:environment:production"
        }
      }
    }
  ]
}
```

Observá que filtrar por `environment:production` permite además exigir aprobación manual de un revisor antes de que el runner obtenga el token OIDC.

### Firma y verificación de artefactos con Sigstore y Cosign

Asegurar quién despliega es la mitad del problema; la otra mitad es verificar que la imagen de contenedor o binario que llega a Kubernetes o producción fue construida legítimamente por tu pipeline oficial y no alterada en el registro. **Sigstore / Cosign** permite realizar firma *keyless* apoyándose en el mismo token OIDC del pipeline: **Fulcio** emite un certificado efímero X.509 ligado a la identidad OIDC del workflow y **Rekor** registra la firma en un libro mayor de transparencia inmutable.

```yaml
# Fragmento de pipeline con OIDC hacia AWS y firma keyless con Cosign
permissions:
  contents: read
  id-token: write
  packages: write

jobs:
  build-sign-deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1

      - name: Instalar Cosign
        uses: sigstore/cosign-installer@59acb6260d9c0ba8f4a2f9d9b48431a222b68e20 # v3.5.0

      - name: Autenticar en AWS mediante OIDC sin llaves estáticas
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502 # v4.0.2
        with:
          role-to-assume: arn:aws:iam::123456789012:role/ci-deploy-prod
          aws-region: us-east-1

      - name: Firmar imagen por digest (keyless OIDC)
        env:
          IMAGE_DIGEST: ghcr.io/mi-org/api@sha256:4f8c9b...
        run: |
          cosign sign --yes "$IMAGE_DIGEST"
```

Del lado del clúster de despliegue (por ejemplo mediante Kyverno o Policy Controller), la verificación rechaza cualquier imagen cuya firma no corresponda exactamente al emisor y workflow autorizados:

```bash
cosign verify ghcr.io/mi-org/api@sha256:4f8c9b... \
  --certificate-identity-regexp="^https://github\.com/mi-org/mi-servicio/\.github/workflows/release\.yml@refs/heads/main$" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

---

## Práctica guiada en laboratorio

En un repositorio de laboratorio local o privado vas a endurecer un flujo CI/CD de extremo a extremo combinando detección estática de secretos, análisis IaC y verificación de artefactos.

1. Inicializá un repositorio con un módulo Terraform que declare un bucket de almacenamiento y un archivo Python con un llamado inseguro de ejemplo para pruebas locales.
2. Configurá `.gitleaks.toml` y ejecutá `gitleaks detect` verificando que detecte tokens de prueba sintéticos y respete las exclusiones explícitas.
3. Escribí una regla personalizada de Semgrep y correla junto con `trivy config` sobre el directorio Terraform hasta obtener código de salida `0` tras aplicar los controles de cifrado y bloqueo público.
4. Generá un SBOM en formato CycloneDX con `syft` y comparalo tras actualizar una dependencia en el archivo lock.
5. Simulá o validá localmente un workflow YAML que use `permissions:` mínimas, variables `env:` seguras en lugar de interpolación en `run:` y pasos de firma/verificación con `cosign`.

::: practica Entregable mínimo
Un directorio reproducible de laboratorio con: el workflow YAML endurecido (acciones fijadas por SHA, sin interpolación de `${{ github.event.* }}` en `run:` y con `id-token: write`), el archivo `.gitleaks.toml`, una regla Semgrep propia, el manifiesto Terraform corregido tras pasar `checkov` o `trivy config` con salida limpia, y el archivo `sbom.cdx.json` generado.
:::

::: defensa Perspectiva defensiva y mitigación
La defensa efectiva de la cadena de suministro software exige asumir que cualquier repositorio con colaboradores o dependencias externas recibirá entradas no confiables. La combinación de disparadores aislados (`pull_request` frente a `pull_request_target`), runners efímeros sin persistencia, permisos mínimos en tokens, federación OIDC con condiciones estrictas de entorno y firma criptográfica verificable antes del despliegue elimina por diseño toda una clase de compromisos silenciosos en la tubería de entrega.
:::

## Preguntas de repaso

**1. ¿Por qué combinar `pull_request_target` con el checkout del `head.sha` de un Pull Request representa un riesgo crítico en GitHub Actions?** Porque `pull_request_target` ejecuta el workflow en el contexto privilegiado de la rama base (con acceso a secretos y posibles permisos de escritura en `GITHUB_TOKEN`), por lo que hacer checkout del código no revisado del fork permite que scripts de compilación o pruebas ejecuten acciones arbitrarias dentro de ese contexto confiable.

**2. ¿Cuál es la forma segura de procesar valores como el título de un PR o el nombre de una rama dentro de un paso `run:` en un workflow?** Pasando las expresiones `${{ github.event.* }}` a través del bloque `env:` del paso y referenciándolas en el script como variables de entorno debidamente entrecomilladas (por ejemplo `"$PR_TITLE"`), evitando que el motor de plantillas las interpole directamente antes de invocar al shell.

**3. ¿Qué diferencia práctica aportan CycloneDX y SPDX frente a ejecutar únicamente un escáner de dependencias en tiempo de compilación?** Un SBOM en formato CycloneDX o SPDX deja un inventario formal y portable de todos los componentes y dependencias transitivas exactas contenidas en cada artefacto liberado, permitiendo auditar exposición ante nuevas vulnerabilidades de forma retrospectiva e inmediata sin tener que reconstruir el proyecto.

**4. ¿Qué ventaja de seguridad ofrece la federación OIDC frente al almacenamiento de Access Keys de AWS o Service Accounts JSON en los secretos del CI?** Elimina credenciales estáticas de larga duración; el runner obtiene credenciales efímeras emitidas por STS únicamente si el JWT firmado por el proveedor CI cumple con las condiciones de la política de confianza (repositorio, rama o entorno con aprobación manual).

**5. ¿Qué rol cumplen Fulcio y Rekor dentro del modelo de firma sin llaves (*keyless*) de Sigstore/Cosign?** Fulcio actúa como autoridad certificadora que emite certificados X.509 de vida muy corta vinculados a la identidad OIDC verificada del pipeline, mientras que Rekor registra la firma y el certificado en un log público de transparencia inmutable para permitir auditoría y verificación posterior sin gestionar llaves privadas permanentes.

## Antes de avanzar

::: nota Puerta de salida
Antes de pasar al monitoreo y defensa perimetral en la nube, asegurate de poder distinguir en una revisión de código cuándo un disparador de CI/CD expone secretos a código externo, por qué las expresiones de plantilla nunca deben mezclarse en scripts de shell sin pasar por `env:`, y cómo una política de confianza OIDC restringe el despliegue por repositorio y entorno.
:::

## Referencias y estándares abiertos

- OWASP Top 10 CI/CD Security Risks: [https://owasp.org/www-project-top-10-ci-cd-security-risks/](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- SLSA (Supply-chain Levels for Software Artifacts): [https://slsa.dev/](https://slsa.dev/)
- GitHub Actions Security Hardening Documentation: [https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- Sigstore & Cosign Documentation: [https://docs.sigstore.dev/](https://docs.sigstore.dev/)
- CycloneDX & SPDX Specifications: [https://cyclonedx.org/](https://cyclonedx.org/) / [https://spdx.dev/](https://spdx.dev/)
