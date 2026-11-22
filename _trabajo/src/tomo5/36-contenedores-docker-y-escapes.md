::: nota Objetivo de la lección
Al concluir este capítulo vas a comprender en profundidad las primitivas del kernel Linux que sustentan el aislamiento de contenedores (Namespaces, cgroups, Linux Capabilities, seccomp y AppArmor), identificar los riesgos arquitectónicos de configuraciones inseguras en Docker (`--privileged`, montaje de `docker.sock`, volúmenes del host y ejecución como `root`), analizar la mecánica conceptual por la cual se rompen las fronteras de aislamiento en un laboratorio controlado, y aplicar técnicas de endurecimiento profesional en Dockerfiles e imágenes mediante multi-stage builds, usuarios sin privilegios, imágenes `distroless`, `hadolint`, `trivy` y el CIS Docker Benchmark.
:::

A diferencia de las máquinas virtuales estudiadas en los capítulos anteriores, los contenedores **no virtualizan hardware ni ejecutan un sistema operativo invitado independiente**. Un contenedor en Linux es, en esencia, un proceso (o grupo de procesos) estándar que corre directamente sobre el **mismo kernel compartido del sistema anfitrión (*host*)**, envuelto en un conjunto de restricciones y vistas aisladas administradas por el núcleo.

Esta arquitectura explica tanto la extraordinaria eficiencia de Docker y OCI (*Open Container Initiative*) como su principal desafío de seguridad: **si el aislamiento lógico del proceso se debilita o se configura erróneamente, no existe un hipervisor de por medio que separe al contenedor del sistema operativo anfitrión**.

## Fundamentos del Aislamiento en el Kernel Linux

El motor de contenedores (*container runtime*, como `containerd` y `runc`) combina cinco mecanismos nativos del kernel Linux para construir la ilusión de un sistema aislado y acotar su impacto.

| Mecanismo del Kernel | Función Principal | Qué Aísla o Limita | Riesgo si se Deshabilita o Comparte |
| :--- | :--- | :--- | :--- |
| **Namespaces** | Aislamiento de visibilidad | PID, Red (`NET`), Montajes (`MNT`), Usuarios (`USER`), IPC, UTS | El contenedor ve procesos, interfaces o archivos reales del host |
| **Control Groups (cgroups)** | Cuotas de recursos físicos | CPU, RAM, ancho de banda E/S, cantidad máxima de PIDs | Un proceso descontrolado agota la memoria o CPU del host (DoS) |
| **Linux Capabilities** | Granularidad de privilegios `root` | Subconjunto acotado de permisos de kernel (ej. `CAP_NET_BIND_SERVICE`) | Permisos excesivos como `CAP_SYS_ADMIN` habilitan operaciones administrativas sobre el host |
| **seccomp** | Filtrado de llamadas al sistema | Bloquea syscalls peligrosas o innecesarias (ej. `kexec_load`, `mount`) | Mayor superficie de ataque directa hacia vulnerabilidades del kernel |
| **LSM (AppArmor / SELinux)** | Control de acceso obligatorio (MAC) | Restringe acceso a rutas, sockets y capacidades por perfil | Procesos comprometidos pueden operar libremente dentro de los límites de UID |

### 1. Namespaces: La Frontera de Visibilidad

Los *namespaces* particionan los recursos globales del kernel de modo que un conjunto de procesos solo perciba sus propios recursos:

- **PID (`pid`):** Otorga al contenedor su propio árbol de procesos comenzando desde el PID `1`. Desde adentro no se observan los procesos de otros contenedores ni del host, aunque desde el host todos los procesos del contenedor son visibles con un PID real en el namespace raíz.
- **Network (`net`):** Proporciona una pila de red independiente (interfaces virtuales `veth`, tablas de ruteo, reglas `iptables` y puertos propios).
- **Mount (`mnt`):** Aísla la tabla de puntos de montaje del sistema de archivos (combinado con `pivot_root` y sistemas de archivos en capas como **OverlayFS**).
- **IPC (`ipc`):** Separa colas de mensajes POSIX, semáforos y segmentos de memoria compartida System V.
- **User (`user`):** Permite mapear el UID `0` (`root`) dentro del contenedor a un UID no privilegiado (por ejemplo, `100000`) en el sistema anfitrión (*Rootless / User Namespace Remapping*). Sin este mapeo activo, el UID `0` del contenedor coincide con el UID `0` del kernel del host.
- **UTS (`uts`) y Cgroup (`cgroup`):** Aíslan el nombre de host/dominio y la jerarquía visible de cgroups respectivamente.

### 2. Control Groups (cgroups v1/v2)

Mientras los *namespaces* definen qué puede **ver** un proceso, los **cgroups** definen cuánto puede **consumir**. Impiden que un contenedor consuma el 100 % de la memoria física (`--memory`), sature los núcleos de CPU (`--cpus`) o genere una bomba *fork* (`--pids-limit`) que paralice al nodo completo.

### 3. Linux Capabilities

Históricamente en UNIX existía una dicotomía binaria: un usuario era `root` (omnipotente) o un usuario sin privilegios. Las **Capabilities** dividen el poder tradicional de `root` en más de 40 privilegios discretos. Por defecto, Docker elimina la mayoría de ellas y otorga únicamente un subconjunto reducido (como `CAP_NET_BIND_SERVICE` para abrir puertos menores a 1024, `CAP_CHOWN` o `CAP_NET_RAW`).

Dos capabilities merecen atención prioritaria en cualquier auditoría:

- **`CAP_SYS_ADMIN`:** Considerada el "nuevo `root`" en Linux por la enorme cantidad de operaciones administrativas que agrupa (montar sistemas de archivos, manipular namespaces, configurar trazas del kernel). Nunca debe concederse a contenedores de aplicación.
- **`CAP_NET_RAW`:** Permite abrir sockets crudos (*raw sockets*) y fabricar paquetes arbitrarios (como ICMP o ARP spoofing en la red puente local de Docker). En aplicaciones web convencionales debe eliminarse explícitamente (`--cap-drop=ALL`).

### 4. Seccomp y AppArmor

- **seccomp (*Secure Computing Mode*):** Intercepta las llamadas al sistema (*syscalls*) entre el espacio de usuario y el kernel. El perfil por defecto de Docker bloquea aproximadamente 44 syscalls de alto riesgo de un total superior a 300 (deshabilitando funciones como `reboot`, `swapon`, `init_module` o `ptrace` en configuraciones estrictas).
- **AppArmor / SELinux:** Implementan *Mandatory Access Control (MAC)*. El perfil `docker-default` de AppArmor bloquea escrituras sobre rutas críticas virtuales del kernel como `/proc/sysrq-trigger`, `/proc/kcore` o `/sys/firmware` incluso si el proceso dentro del contenedor corre como `root`.

## Riesgos Críticos de Configuración en Docker

En la práctica, casi ningún incidente de contenedores se produce por un fallo cero-día en `runc`, sino por decisiones operativas inseguras al ejecutar `docker run` o redactar archivos `docker-compose.yml`.

### 1. El flag `--privileged`

Ejecutar un contenedor con `--privileged` desmantela prácticamente todas las capas de seguridad anteriores: otorga **todas** las Linux Capabilities (incluyendo `CAP_SYS_ADMIN`), desactiva el perfil de **seccomp**, deshabilita **AppArmor/SELinux** y expone todos los dispositivos físicos del host bajo `/dev` (incluidos los discos duros en bloque como `/dev/sda` o `/dev/nvme0n1`). Un contenedor privilegiado posee control administrativo equivalente al del sistema anfitrión.

### 2. Montaje del socket `/var/run/docker.sock`

Es habitual observar herramientas de CI/CD, agentes de monitoreo o tableros de gestión montando el socket UNIX del demonio Docker dentro del contenedor (`-v /var/run/docker.sock:/var/run/docker.sock`) para "gestionar otros contenedores".

El demonio `dockerd` escucha en ese socket con privilegios de `root` en el host y **sin autenticación adicional** para cualquier proceso que pueda escribir en él. Quien controla el socket dentro del contenedor puede emitir peticiones HTTP locales a la API de Docker para crear un nuevo contenedor con el sistema de archivos raíz del host montado, rompiendo por completo el aislamiento previsto.

### 3. Montaje de rutas sensibles del host (`bind mounts`)

Montar directorios críticos como `/`, `/etc`, `/root`, `/var/log` o `/proc` en modo lectura/escritura (`rw`) rompe el aislamiento del *Mount Namespace*. Por ejemplo, montar `/etc` en modo escritura permite modificar archivos de configuración de autenticación o tareas programadas del sistema anfitrión directamente desde el interior del contenedor.

### 4. Ejecución como usuario `root` (UID 0) por defecto

Si un `Dockerfile` omite la directiva `USER`, el proceso principal del contenedor arranca como UID `0`. Si además existe cualquier volumen montado desde el host sin *User Namespace Remapping*, el proceso del contenedor interactúa con los archivos del host con identidad efectiva de `root`.

## Mecánica Conceptual de Escapes de Contenedor en Laboratorio

En entornos de prueba propios, comprender cómo se produce conceptualmente un escape ayuda a verificar si las defensas del nodo están activas. Un escape de contenedor ocurre cuando un proceso logra cruzar la frontera del namespace hacia el sistema anfitrión debido a una configuración permisiva:

1. **Vía montaje de dispositivos o `CAP_SYS_ADMIN`:** Cuando un contenedor posee `CAP_SYS_ADMIN` (o `--privileged`), puede invocar la syscall `mount` desde su propio espacio de usuario. Si accede a dispositivos de bloque del host en `/dev`, puede montar el disco raíz del anfitrión en un subdirectorio temporal del contenedor y leer o alterar archivos del host.
2. **Vía subsistema `cgroup` (`release_agent` en cgroups v1 heredados):** En sistemas antiguos con cgroups v1 y `CAP_SYS_ADMIN`, un contenedor con acceso de escritura a la jerarquía de cgroups podía registrar un binario de limpieza (`release_agent`) que el **kernel del host** ejecutaba automáticamente en el namespace raíz al finalizar un grupo de procesos. La migración a **cgroups v2** y la eliminación de `CAP_SYS_ADMIN` cierran por diseño esta clase de vector.
3. **Vía API del daemon Docker (`docker.sock`):** El contenedor no "rompe" el kernel; simplemente le solicita legítimamente al demonio del host a través del socket montado que lance un segundo contenedor sin restricciones y con `/` del host montado en `/mnt/host`.
4. **Vía exposición de `/proc` y depuración (`CAP_SYS_PTRACE` + `--pid=host`):** Compartir el namespace de procesos del host (`--pid=host`) junto con `CAP_SYS_PTRACE` expone los procesos reales del anfitrión (incluidos servicios administrativos y variables de entorno en `/proc/<pid>/environ`) a inspección e interacción directa.

```
[Contenedor mal configurado]
  |-- (--privileged / CAP_SYS_ADMIN) --> Acceso directo a /dev/* o mount() sobre host
  |-- (-v /var/run/docker.sock)      --> Petición API a dockerd para crear contenedor sin aislamiento
  |-- (--pid=host + CAP_SYS_PTRACE)  --> Visibilidad e interacción sobre procesos del host
```

## Hardening de Dockerfiles y Auditoría de Imágenes

La seguridad de un contenedor comienza al construir su imagen. Un `Dockerfile` endurecido reduce drásticamente el tamaño de la imagen, elimina herramientas innecesarias (compiladores, gestores de paquetes, shells interactivas) y ejecuta el proceso bajo un usuario no privilegiado.

### Comparativa: Dockerfile Inseguro vs Dockerfile Endurecido

Observá cómo transformar una definición clásica vulnerable en una imagen lista para producción usando **multi-stage builds** e imágenes mínimas (`distroless` o Alpine acotada):

```dockerfile
# --- PATRÓN INSEGURO (Evitar) ---
FROM python:3.12
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 8000
CMD ["python", "app.py"]
# Problemas: corre como root, incluye compiladores/curl/bash, copia secretos locales (.env/.git),
# no fija digests ni versiones, imagen pesada (>900 MB) con cientos de CVEs en paquetes del OS.
```

```dockerfile
# --- PATRÓN ENDURECIDO (Recomendado) ---
# Etapa 1: Construcción de dependencias en entorno completo temporal
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends gcc=4:12.* \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.txt

# Etapa 2: Imagen final mínima sin compiladores ni gestor de paquetes
FROM gcr.io/distroless/python3-debian12:nonroot AS runtime

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=nonroot:nonroot src/ ./src/

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER nonroot
EXPOSE 8000
ENTRYPOINT ["/opt/venv/bin/python", "src/app.py"]
```

### Controles Clave en Tiempo de Ejecución (`docker run`)

Además de endurecer el `Dockerfile`, aplicá parámetros restrictivos al lanzar el contenedor:

```bash
# Ejecución endurecida: sin capabilities, sistema de archivos raíz de solo lectura y sin escalada de privilegios
docker run -d \
  --name api-endurecida \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --pids-limit=128 \
  --memory=256m \
  --cpus=0.5 \
  -p 127.0.0.1:8000:8000 \
  mi-org/api-segura:1.0.0
```

La opción `--security-opt=no-new-privileges:true` impide que cualquier binario dentro del contenedor adquiera privilegios adicionales mediante bits **SUID/SGID** o capabilities de archivo durante `execve()`. Combinada con `--read-only` y `--cap-drop=ALL`, reduce al mínimo el margen de maniobra post-compromiso.

### Auditoría Automatizada: Hadolint, Trivy y Docker Bench

Integrá herramientas de análisis estático y cumplimiento normativo tanto en desarrollo local como en pipelines CI/CD:

```bash
# 1. Análisis estático de buenas prácticas y seguridad en el Dockerfile con Hadolint
docker run --rm -i hadolint/hadolint < Dockerfile

# 2. Escaneo de vulnerabilidades (CVEs) y configuraciones erróneas en la imagen construida con Trivy
trivy image --severity HIGH,CRITICAL --ignore-unfixed mi-org/api-segura:1.0.0

# 3. Auditoría del propio Dockerfile/Compose frente a reglas de configuración (misconfig)
trivy config --severity HIGH,CRITICAL .

# 4. Inspeccionar en tiempo real los privilegios efectivos de un contenedor en ejecución
docker inspect --format '{{.Name}} | Privileged={{.HostConfig.Privileged}} | User={{.Config.User}} | CapDrop={{.HostConfig.CapDrop}} | ReadOnly={{.HostConfig.ReadonlyRootfs}}' api-endurecida
```

Para auditar la configuración completa del demonio Docker y del sistema anfitrión frente al **CIS Docker Benchmark**, se utiliza **Docker Bench for Security**, que verifica controles desde el cifrado TLS del socket remoto y la habilitación de *User Namespaces* (`userns-remap`) hasta la configuración de *live-restore* y límites de registro (`log-driver`).

Una configuración endurecida base para `/etc/docker/daemon.json` en el nodo anfitrión luce así:

```json
{
  "icc": false,
  "no-new-privileges": true,
  "userns-remap": "default",
  "live-restore": true,
  "userland-proxy": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "5"
  }
}
```

Desactivar la comunicación inter-contenedores por defecto (`"icc": false`) obliga a que los servicios se comuniquen únicamente mediante redes Docker definidas explícitamente y puertos declarados, eliminando el tráfico lateral irrestricto dentro del puente `docker0`.

## Práctica guiada en laboratorio
En tu laboratorio local con Docker instalado, tomá una aplicación web sencilla en Python o Node.js (por ejemplo, un servidor HTTP mínimo de laboratorio) y redactá dos versiones de `Dockerfile`: una versión base estándar y una versión endurecida utilizando **multi-stage build**, usuario no privilegiado (`USER nonroot` o `UID 10001`) e imagen base mínima (`alpine` o `distroless`). Ejecutá `hadolint` y `trivy image` sobre ambas imágenes para comparar la cantidad de advertencias y vulnerabilidades críticas reportadas, y lanzá la versión final aplicando `--cap-drop=ALL`, `--read-only` y `--security-opt=no-new-privileges:true`.

::: practica Entregable mínimo
Generá un informe breve `auditoria-docker-lab.md` que incluya:
1. El `Dockerfile` endurecido completo junto con el archivo `.dockerignore` utilizado para excluir archivos sensibles del contexto de compilación.
2. Tabla comparativa con los resultados de `trivy image` (cantidad de CVEs `HIGH`/`CRITICAL` y tamaño final en MB) entre la imagen base y la imagen endurecida.
3. La salida de `docker inspect` verificando `Privileged=false`, `ReadonlyRootfs=true`, usuario no root y `CapDrop=["ALL"]`.
:::

::: defensa Perspectiva defensiva y endurecimiento
- **Aplicá el CIS Docker Benchmark:** Configurá el daemon con `no-new-privileges: true` por defecto en `/etc/docker/daemon.json`, activá `userns-remap` (o **Rootless Docker**), restringí la comunicación entre contenedores (`"icc": false`) y mantené habilitados seccomp y AppArmor.
- **Prohibí cargas privilegiadas y montajes del socket:** Nunca expongas `/var/run/docker.sock` a contenedores orientados a aplicaciones ni CI compartidos sin aislamiento fuerte (usá constructores sin daemon como **Kaniko** o **BuildKit rootless**).
- **Imágenes inmutables y firmadas:** Construí imágenes mínimas `distroless` fijadas por digest SHA-256, escanealas con **Trivy** en cada *pull request* y firmalas criptográficamente con **Cosign (Sigstore)** antes de admitirlas en producción.
:::

## Preguntas de repaso

**1. ¿Por qué una vulnerabilidad o mala configuración dentro de un contenedor puede impactar al sistema operativo anfitrión de forma más directa que en una máquina virtual?** Porque los contenedores comparten el mismo kernel Linux del host en lugar de ejecutar un núcleo independiente aislado por un hipervisor de hardware, dependiendo exclusivamente de *namespaces*, *cgroups*, *capabilities*, *seccomp* y módulos LSM para mantener las fronteras.

**2. ¿Cuál es la diferencia funcional entre los *Namespaces* y los *Control Groups (cgroups)* en Linux?** Los *namespaces* aíslan lo que un proceso puede ver (árbol de PIDs, interfaces de red, puntos de montaje, usuarios), mientras que los *cgroups* limitan cuántos recursos físicos puede consumir (memoria RAM, tiempo de CPU, operaciones de disco y número máximo de procesos).

**3. ¿Por qué montar `/var/run/docker.sock` dentro de un contenedor equivale operativamente a otorgar privilegios de administrador en el host?** Porque el socket permite enviar comandos directos sin autenticación al demonio `dockerd` que corre como `root` en el host, lo que habilita crear nuevos contenedores privilegiados o con la raíz `/` del sistema anfitrión montada en lectura y escritura.

**4. ¿Qué efecto concreto producen las opciones `--cap-drop=ALL`, `--read-only` y `--security-opt=no-new-privileges:true` al ejecutar un contenedor?** Eliminan todas las Linux Capabilities del proceso, montan su sistema de archivos raíz en modo de solo lectura para impedir la persistencia o modificación de binarios en disco, y bloquean la adquisición de privilegios elevados mediante bits SUID/SGID o capabilities de archivo al ejecutar nuevos procesos.

**5. ¿Qué ventajas de seguridad aporta construir una imagen con *multi-stage builds* sobre una base `distroless`?** Separa las herramientas de compilación y descarga de dependencias en una etapa temporal que se descarta, entregando en la imagen final únicamente el binario o runtime mínimo sin shell interactiva (`/bin/sh`), sin gestor de paquetes (`apt`/`apk`) y con una superficie de CVEs y tamaño drásticamente menores.

## Antes de avanzar

::: nota Puerta de salida
Antes de dar el salto hacia la orquestación distribuida con Kubernetes, confirmá estos puntos clave:
- Distinguís con claridad qué función cumple cada primitiva del kernel (Namespaces, cgroups, Capabilities, seccomp, AppArmor).
- Sabés detectar al instante banderas peligrosas en despliegues Docker (`--privileged`, `docker.sock`, `--pid=host`, `CAP_SYS_ADMIN`).
- Podés escribir un `Dockerfile` multi-stage con usuario no root y auditarlo mediante `hadolint` y `trivy`.
:::

## Referencias y estándares abiertos

- **CIS Docker Benchmark (Center for Internet Security):** Estándar de referencia para configuración segura del host, demonio Docker, archivos de configuración e imágenes de contenedores.
- **NIST SP 800-190 (Application Container Security Guide):** Guía técnica integral sobre riesgos en imágenes, registros, orquestadores, contenedores y sistema operativo anfitrión.
- **OWASP Docker Security Cheat Sheet:** Lista práctica de endurecimiento para `Dockerfile`, `docker-compose` y parámetros de ejecución.
- **Linux Kernel Documentation (Namespaces, cgroups v2, Capabilities, seccomp):** Documentación oficial de las primitivas de aislamiento del núcleo Linux.
