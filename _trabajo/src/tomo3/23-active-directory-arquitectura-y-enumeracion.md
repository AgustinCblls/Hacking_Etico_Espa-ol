::: nota Objetivo de la lección
Al finalizar este capítulo vas a comprender la arquitectura lógica y física de Active Directory Domain Services (AD DS), el rol de los Controladores de Dominio, la base de datos `NTDS.dit`, las Unidades Organizativas (OU), las Políticas de Grupo (GPO) y el protocolo LDAP; aprenderás a auditar el inventario de objetos, membresías y permisos de un dominio mediante consultas LDAP/PowerShell y análisis de grafos de control (BloodHound), y a diseñar una arquitectura defensiva por niveles (**Modelo de Tiering 0 / 1 / 2**).
:::

**Prerrequisitos:** Capítulo 1.4 (Fundamentos de Windows), Capítulo 1.7 (Protocolos de red) y Capítulo 3.4 (Seguridad en Windows). **Duración sugerida:** 8 a 10 horas.

## 1. Por qué Active Directory es el núcleo de la infraestructura corporativa

En una red pequeña de cinco computadoras, cada equipo administra sus propias cuentas locales dentro de su archivo **SAM (`C:\Windows\System32\config\SAM`)**. Pero cuando una organización supera las decenas o miles de estaciones de trabajo y servidores, administrar cuentas locales individuales se vuelve inviable.

**Active Directory Domain Services (AD DS)** resuelve este problema centralizando la identidad, la autenticación, la autorización y la configuración de todos los equipos en un directorio jerárquico distribuido. Comprender su arquitectura es indispensable tanto para quien audita la seguridad de una red empresarial como para quien la administra y defiende.

```text
[Bosque (Forest): corp.local]  ◄── Frontera real de seguridad en Active Directory
  │
  ├── [Dominio Raíz: corp.local]
  │     ├── Controladores de Dominio (DC01, DC02) -> Almacenan NTDS.dit y SYSVOL
  │     ├── OU=Tier0_Admin     (Cuentas y servidores críticos de identidad)
  │     ├── OU=Servidores      (Aplicaciones, bases de datos, archivos)
  │     └── OU=Estaciones      (Equipos de usuarios finales y departamentos)
  │
  └── [Subdominio / Dominio Hijo: lab.corp.local]
```

### Componentes estructurales esenciales

| Componente de AD | Qué es técnicamente | Importancia en auditoría y defensa |
|---|---|---|
| **Bosque (*Forest*)** | El contenedor lógico superior que agrupa uno o más árboles de dominios que comparten el mismo Esquema y Catálogo Global. | **El Bosque (y no el dominio individual) es la verdadera frontera de seguridad** en Active Directory. |
| **Dominio (*Domain*)** | Unidad administrativa que agrupa usuarios, grupos y equipos bajo una misma base de datos de directorio y políticas de contraseñas. | Cada objeto del dominio recibe un identificador de seguridad (`SID`) compuesto por el SID del dominio más un `RID` único (`S-1-5-21-...-<RID>`). |
| **Controlador de Dominio (DC)** | Servidor Windows que ejecuta AD DS, el Centro de Distribución de Claves Kerberos (KDC), el servidor LDAP y el recurso compartido `SYSVOL`. | Aloja el archivo **`C:\Windows\NTDS\ntds.dit`**, que contiene todos los objetos y hashes de credenciales del dominio. |
| **Unidad Organizativa (OU)** | Contenedor jerárquico dentro de un dominio para organizar usuarios y equipos. | Sirve para **vincular Políticas de Grupo (GPOs)** y para **delegar permisos administrativos** a equipos de soporte sin darles Domain Admin. |
| **GPO (*Group Policy Object*)** | Conjunto de directivas de configuración y seguridad que se distribuyen a través de LDAP y de la carpeta compartida `\\<dominio>\SYSVOL`. | Permite endurecer masivamente firewalls, auditoría de eventos, restricciones de software y privilegios locales en miles de equipos. |

### RIDs predefinidos (*Well-Known RIDs*) que debés reconocer al instante

En cualquier dominio Active Directory, los últimos dígitos del SID (`RID`) identifican a los grupos y cuentas nativas con independencia del idioma del sistema operativo:
- **`RID 500`:** Cuenta `Administrator` integrada del dominio.
- **`RID 502`:** Cuenta `krbtgt` (cuenta de servicio del KDC utilizada para firmar y cifrar todos los tickets TGT de Kerberos del dominio).
- **`RID 512`:** Grupo `Domain Admins` (Administradores del dominio).
- **`RID 516`:** Grupo `Domain Controllers` (Controladores de dominio).
- **`RID 518`:** Grupo `Schema Admins` / **`RID 519`:** Grupo `Enterprise Admins` (privilegios a nivel de todo el Bosque).
- **`RID 513`:** Grupo `Domain Users` / **`RID 515`:** Grupo `Domain Computers`.

## 2. El protocolo LDAP y la estructura de nombres distinguidos (DN)

Todo usuario, equipo, grupo o OU en Active Directory es un objeto almacenado en `NTDS.dit` y accesible mediante el protocolo **LDAP (*Lightweight Directory Access Protocol*, RFC 4511)** sobre los puertos `TCP/389` (LDAP con o sin StartTLS/Signing) y `TCP/636` (LDAPS sobre TLS), además de los puertos del Catálogo Global (`3268`/`3269`).

Cada objeto se identifica de manera única por su **`distinguishedName` (DN)**, leído desde la hoja hasta la raíz del dominio:

```text
CN=Ana Ceballos,OU=Analistas_SOC,OU=Seguridad,DC=corp,DC=local
```

- **`DC` (*Domain Component*):** cada parte del nombre DNS del dominio (`DC=corp,DC=local`).
- **`OU` (*Organizational Unit*):** carpeta organizativa donde reside el objeto.
- **`CN` (*Common Name*):** nombre común del objeto individual o contenedor estándar (`CN=Users`).

### Atributos LDAP críticos durante una auditoría de directorio

Por diseño, cualquier usuario o equipo autenticado en el dominio necesita consultar LDAP para resolver nombres de grupos, ubicar impresoras, aplicar GPOs y validar permisos. Durante una auditoría de higiene del directorio, estos son los atributos clave que se inspeccionan:

| Atributo LDAP | Qué almacena | Qué anomalía de seguridad buscar |
|---|---|---|
| `sAMAccountName` / `userPrincipalName` | Nombre de inicio de sesión (`ana` / `ana@corp.local`). | Cuentas genéricas compartidas o cuentas de prueba olvidadas activas. |
| `memberOf` / `member` | Membresía de grupos de seguridad (incluyendo anidamiento). | Usuarios estándar agregados indirectamente a grupos privilegiados mediante grupos anidados. |
| `userAccountControl` (UAC flags) | Máscara de bits que controla el estado de la cuenta. | Bit `0x0002` (`ACCOUNTDISABLE`), `0x10000` (`DONT_EXPIRE_PASSWORD`), `0x80000` (`TRUSTED_FOR_DELEGATION`), `0x400000` (`DONT_REQ_PREAUTH`). |
| `servicePrincipalName` (SPN) | Lista de instancias de servicio Kerberos asociadas a la cuenta. | Cuentas de usuario humanas con `servicePrincipalName` asignado (expuestas a auditoría de TGS / Kerberoasting). |
| `adminCount` | Vale `1` si la cuenta pertenece o perteneció alguna vez a un grupo protegido por **`AdminSDHolder`**. | Cuentas que fueron sacadas de `Domain Admins` pero conservan `adminCount=1` y permisos heredados bloqueados. |
| `description` / `info` | Campo de texto descriptivo del objeto. | Administradores que anotaron por error contraseñas temporales o datos sensibles en el campo `description` legible por todo el dominio. |

## 3. Auditoría de higiene del directorio con PowerShell nativo

No hace falta instalar herramientas externas no verificadas para realizar una auditoría profunda y transparente de Active Directory: el módulo oficial **`ActiveDirectory`** de Microsoft (RSAT) y el proveedor ADSI (`[adsisearcher]`) integrado en todo Windows permiten consultar el directorio de forma nativa y auditable:

```powershell
# 1. Consultar información general del dominio y nivel funcional
Get-ADDomain | Select-Object Name, DomainMode, InfrastructureMaster, PDCEmulator

# 2. Auditar miembros efectivos (desenrollando grupos anidados con -Recursive) de Domain Admins
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Select-Object Name, SamAccountName, objectClass

# 3. Buscar cuentas de usuario (no equipos) que tengan SPNs registrados (candidatas a migrar a gMSA)
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet |
    Select-Object SamAccountName, PasswordLastSet, ServicePrincipalName

# 4. Buscar cuentas con la preautenticación Kerberos deshabilitada (bit 4194304 = 0x400000)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth |
    Select-Object SamAccountName, Enabled

# 5. Auditar descripciones de usuarios en busca de palabras como "pass", "clave" o "temp"
Get-ADUser -Filter * -Properties Description |
    Where-Object { $_.Description -match "pass|clave|contrase|temp" } |
    Select-Object SamAccountName, Description
```

## 4. Teoría de grafos aplicada a Active Directory: BloodHound y rutas de control

En un dominio pequeño podés revisar la lista de miembros de `Domain Admins` a mano. Pero en una organización con 5.000 usuarios, 800 grupos anidados, decenas de OUs con permisos delegados y cientos de servidores, las relaciones de control forman un **grafo dirigido complejo**.

Un usuario `A` puede no figurar directamente en `Domain Admins`, pero:
1. `A` pertenece al grupo `Soporte_Nivel2`.
2. `Soporte_Nivel2` tiene permiso de escritura (`GenericAll` o `AddMember`) sobre el grupo `Administradores_SQL`.
3. `Administradores_SQL` tiene permisos de administrador local sobre el servidor `SRV-APP01`.
4. En `SRV-APP01` inicia sesión regularmente una cuenta que pertenece a `Domain Admins`.

Herramientas de auditoría basadas en grafos como **BloodHound Community Edition** (junto con auditorías defensivas como **PingCastle** y **Purple Knight**) modelan el directorio como nodos (Usuarios, Grupos, Equipos, OUs, GPOs, Dominios) y aristas (`MemberOf`, `AdminTo`, `HasSession`, `GenericAll`, `WriteDacl`, `ForceChangePassword`, `AllowedToDelegate`). Usando algoritmos de camino más corto (*Shortest Path*, como Dijkstra/BFS en Neo4j), permiten al equipo de seguridad visualizar y cortar esos caminos indirectos de escalada antes de que sean abusados.

### Herramientas de inventario multiprotocolo (`NetExec`), colectores BloodHound y acceso inicial AD

En evaluaciones autorizadas desde tu estación de auditoría en laboratorio, la dupla **`BloodHound`** (`bloodhound-python` / `SharpHound`) + **`NetExec` (`nxc`, sucesor mantenido de `CrackMapExec`)** permite reproducir tanto el mapeo del grafo AD como la verificación de controles de red:

```bash
# 1. Colector remoto BloodHound CE desde Linux (en lab autorizado)
bloodhound-python -c All -d corp.local -u usuario_lab -p 'ClaveLab!' -ns 10.10.20.10 --zip

# 2. Alternativa nativa en endpoint Windows del laboratorio (SharpHound)
.\SharpHound.exe -c All --Domain corp.local

# 3. NetExec: verificar firma SMB (signing), recursos compartidos, política y cuentas pre-Windows 2000
nxc smb 10.10.20.0/24 --shares -u usuario_lab -p 'ClaveLab!'
nxc ldap dc01.corp.local -u usuario_lab -p 'ClaveLab!' --users --pass-pol
```

::: nota Telemetría de detección para BloodHound y `NetExec` (Event IDs + Sigma)
- **Event ID `1644` (*Directory Service*):** consultas LDAP amplias sin filtro o paginación excesiva sobre todos los usuarios, grupos, GPOs y ACLs del dominio ejecutadas por `bloodhound-python` / `SharpHound` / `nxc ldap`.
- **Event ID `4624` (Logon Type `3`) y `5145` (SMB Shares):** ráfaga de conexiones SMB/RPC desde una misma estación de usuario hacia decenas de hosts en pocos segundos para recolectar sesiones (`HasSession`) y administradores locales (`AdminTo`).
- **Sysmon Event ID `1` y `3` + criterio Sigma:** proceso no administrativo (`SharpHound.exe` / PowerShell) generando alta cardinalidad de `DestinationIp` hacia puertos `445/TCP`, `135/TCP` y `389/TCP` en una ventana menor a 60 segundos (`sigma: windows/network_connection` + `process_creation` con `OriginalFileName: SharpHound.exe`).
:::

Asimismo, la auditoría de acceso inicial en AD (**AD Hardening — Recon & Initial Access**) obliga a verificar y cerrar cuatro debilidades heredadas de red:
1. **Envenenamiento de resolución de nombres locales (`LLMNR`, `NBT-NS` y `mDNS`):** cuando un equipo Windows falla al resolver un nombre por DNS, emite consultas broadcast/multicast LLMNR/NBT-NS en la subred local que pueden recibir respuestas falsas. **Mitigación obligatoria:** deshabilitar LLMNR por GPO (*Turn off multicast name resolution = Enabled*) y desactivar NetBIOS over TCP/IP vía opción DHCP o script de inicio.
2. **Sesiones SMB nulas (*NULL Sessions*) y superficie `Pre-Windows 2000`:** verificar que `Everyone` y `Anonymous Logon` no pertenezcan al grupo heredado `Pre-Windows 2000 Compatible Access` (evita enumeración LDAP sin credenciales) y auditar también que no existan **cuentas de computadora pre-creadas con la casilla Pre-Windows 2000** (cuya mecánica, detección y remediación se detalla en el Cap. 3.7).
3. **Credenciales heredadas en `SYSVOL` (`GPP cpassword` MS14-025):** auditar que ningún archivo XML antiguo de Group Policy Preferences conserve el atributo `cpassword` en `\\dominio\SYSVOL`.

### El vector IPv6 en Active Directory (DHCPv6, RA spoofing y NTLM Relay)

Incluso cuando una organización ya deshabilitó correctamente `LLMNR`, `NBT-NS` y `mDNS`, las estaciones de trabajo Windows conservan la pila **IPv6 habilitada de forma predeterminada con prioridad sobre IPv4** para la resolución DNS. Si la red corporativa opera solo en IPv4 y no existe un servidor DHCPv6 autorizado, los equipos continúan solicitando configuración por **DHCPv6** y escuchando anuncios **ICMPv6 Router Advertisement (RA)** en el enlace local.

Herramientas de auditoría de red como **`mitm6`** aprovechan ese comportamiento respondiendo a las solicitudes DHCPv6/RA para asignarse como servidor DNS IPv6 preferido de la víctima y resolver selectivamente peticiones internas (por ejemplo `WPAD` o nombres corporativos) hacia el equipo del auditor. Cuando el cliente intenta autenticarse automáticamente sobre HTTP o SMB, esa autenticación NetNTLMv2 se combina con **NTLM Relay hacia LDAPS** (para modificar DACLs, crear objetos de máquina o configurar RBCD) o hacia **ADCS Web Enrollment** para emitir certificados de usuario o equipo.

::: defensa Remediación integral contra el abuso de IPv6 en Active Directory
1. **Controles en switches de acceso (Capa 2):** habilitá **RA Guard** (RFC 6105) y **DHCPv6 Guard** (RFC 7610) en todos los puertos de usuario final para descartar anuncios RA y respuestas DHCPv6 originados desde puertos no autorizados.
2. **Hardening de pila IPv6 en endpoints:** si IPv6 no se utiliza en producción, deshabilitá los componentes innecesarios mediante la clave de registro `DisabledComponents` en `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters` (siguiendo la matriz oficial de Microsoft y evitando `0xFF` si rompe servicios internos dependientes de loopback IPv6), y desactivá la detección automática de proxy **WPAD** por GPO cuando no se requiera.
3. **Cierre criptográfico del destino del Relay:** exigí **LDAP Signing + LDAP Channel Binding (CBT = Always)** en todos los Controladores de Dominio y configurá **HTTPS con Extended Protection for Authentication (EPA = Required)** en IIS / ADCS Web Enrollment, neutralizando cualquier intento de relayar la sesión NTLM aunque exista suplantación de DNS IPv6 en la subred.
:::

## 5. Arquitectura defensiva: el Modelo de Administración por Niveles (Tiering)

El hallazgo más frecuente en auditorías de Active Directory es el uso de una misma cuenta `Domain Admin` para iniciar sesión por escritorio remoto (RDP) en servidores de aplicaciones o estaciones de trabajo de usuarios para "instalar un programa rápido".

Cada vez que un administrador inicia sesión interactivamente en un equipo, una credencial o ticket de esa sesión se carga en la memoria del proceso **`lsass.exe`** de ese equipo. Si un administrador del dominio inicia sesión en una estación de trabajo de usuario final comprometida, el atacante puede reutilizar esa sesión para comprometer todo el Bosque.

Para erradicar este riesgo estructural, Microsoft y las agencias de ciberseguridad (ANSSI / CISA) definen el **Modelo de Administración por Niveles (*Active Directory Tier Model* / ESAE)**:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ TIER 0 (Control de Identidad y Bosque)                                  │
│ • Activos: Controladores de Dominio, ADCS (PKI), Entra Connect, PAWs T0 │
│ • Regla absoluta: Las cuentas Tier 0 JAMÁS inician sesión en Tier 1 o 2 │
├─────────────────────────────────────────────────────────────────────────┤
│ TIER 1 (Servidores y Aplicaciones Corporativas)                         │
│ • Activos: Servidores Web, Bases de Datos, Archivos, ERP                │
│ • Regla: Administrados solo con cuentas Tier 1; prohibido loguear en T2 │
├─────────────────────────────────────────────────────────────────────────┤
│ TIER 2 (Estaciones de Trabajo y Dispositivos de Usuario Final)          │
│ • Activos: Notebooks, PCs de escritorio, impresoras, soporte Helpdesk   │
│ • Regla: Las cuentas de soporte Tier 2 no tienen permisos en Tier 1/0   │
└─────────────────────────────────────────────────────────────────────────┘
```

El aislamiento entre niveles no se deja a la buena voluntad de los administradores: se hace cumplir técnicamente mediante **GPOs de derechos de usuario** (`Deny log on through Remote Desktop Services`, `Deny log on locally`, `Deny access to this computer from the network`) y **Políticas de Autenticación y Silos (*Authentication Policy Silos*)** que impiden físicamente que una cuenta de Tier 0 se autentique en una máquina de Tier 1 o Tier 2.

::: defensa Perspectiva defensiva, detección y mitigación
1. **Separación de cuentas administrativas:** ningún administrador debe leer el correo ni navegar por internet con su cuenta privilegiada. Debe tener una cuenta estándar sin privilegios para sus tareas diarias y cuentas separadas específicas de su nivel (`admin_t0_...`, `admin_t1_...`, `admin_t2_...`) usadas desde estaciones de trabajo de administración endurecidas (**PAW — Privileged Access Workstations**).
2. **Deshabilitar el anidamiento descontrolado y auditar `AdminSDHolder`:** ejecutá periódicamente consultas que listen todas las cuentas con `adminCount=1` y verificá que correspondan únicamente a administradores activos reales.
3. **Monitorear consultas LDAP masivas en el SOC:** una ráfaga inusual de consultas LDAP que enumeran todos los objetos `user`, `group`, `computer` y sus listas de control de acceso (`nTSecurityDescriptor`) desde una estación de trabajo no administrativa se detecta habilitando la telemetría de **Event ID `1644`** en el registro `Directory Service` de los Controladores de Dominio (o mediante Sysmon / sensores MDI).
:::

## Anexo: Cómo armar un laboratorio reproducible de Active Directory

Para ejecutar las prácticas de este bloque (Caps. 3.6–3.8) sin depender de plataformas externas, elegí una de tres arquitecturas aisladas según la memoria RAM de tu equipo:

| Opción | Componentes mínimos | RAM sugerida en host | Cuándo conviene |
|---|---|---|---|
| **1. Lab liviano manual** | 1× Windows Server 2022/2025 Eval (DC01: AD DS + DNS, 4 GB RAM) + 1× Windows 10/11 Eval unido al dominio (4 GB) + 1× Kali/Parrot (2–4 GB). | **12–16 GB RAM** | Equipos portátiles o estudio enfocado paso a paso. |
| **2. GOAD / GOAD-Light** | Despliegue automático vía Terraform/Packer/Ansible (`goad.py`): `GOAD` completo (5 VMs, multi-dominio + ADCS) o `GOAD-Light` (3 VMs). | **16 GB (`Light`) a 32 GB** | Practicar Trusts entre bosques, NTLM Relay y ADCS realistas. |
| **3. Ludus (Proxmox VE)** | Servidor Proxmox con definición declarativa YAML (`ludus range`), plantillas Windows Server + cliente + red aislada automática. | **32+ GB RAM** (servidor) | Entornos persistentes de equipo Purple Team y reseteo rápido. |

**Checklist rápido para la opción liviana (VirtualBox / VMware / Hyper-V):**
1. **Red aislada:** creá un switch interno o red **Host-Only** (`10.10.20.0/24`) sin DHCP externo y configurá IP fija en `DC01` (`10.10.20.10`, DNS apuntando a `127.0.0.1`).
2. **Promoción mínima:** instalá el rol `AD-Domain-Services`, promovelo a nuevo bosque (`corp.local`), uní `WS01` (`10.10.20.20`) al dominio usando `10.10.20.10` como DNS y opcionalmente instalá ADCS en otro servidor o rol de prueba.
3. **Snapshots obligatorios:** antes de habilitar configuraciones vulnerables intencionales (p. ej. cuenta de prueba con SPN o sin pre-auth) o ejecutar scripts de auditoría, tomá un **snapshot limpio (`Base-AD-Limpio`)** para revertir al cerrar cada práctica.

## Práctica en laboratorio local

1. Escribí un script de auditoría defensiva en PowerShell llamado `auditar_higiene_ad.ps1` que agrupe las cinco verificaciones de la sección 3 (miembros recursivos de grupos críticos, usuarios con SPN, cuentas con `DoesNotRequirePreAuth`, cuentas con `PasswordNeverExpires` y cuentas con `adminCount -eq 1`) y exporte un reporte limpio en formato CSV o JSON.
2. Si estás en una máquina Windows que aún no forma parte de un dominio de laboratorio, agregá en tu script una validación inicial (`if (Get-Module -ListAvailable ActiveDirectory)`) y un modo de prueba local que audite las cuentas y miembros del grupo `Administrators` local con `Get-LocalUser` y `Get-LocalGroupMember`, verificando el estado de `PasswordRequired` y `Enabled`.
3. Diseñá en tu bitácora la estructura de Unidades Organizativas (`OU=Tier0`, `OU=Tier1`, `OU=Tier2`) y la tabla de políticas GPO de denegación de inicio de sesión (`SeDenyInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight`, `SeDenyNetworkLogonRight`) que aplicarías en cada OU.

::: practica Entregable mínimo
El script `auditar_higiene_ad.ps1` funcional tanto en entorno de dominio como en modo local de verificación, junto con el diseño de OUs y matriz de bloqueo de inicio de sesión entre Tiers 0, 1 y 2.
:::

## Preguntas de repaso

**1. ¿Por qué decimos que en Active Directory la verdadera frontera de seguridad es el Bosque (*Forest*) y no el Dominio individual?** Porque todos los dominios dentro de un mismo Bosque comparten el mismo Esquema, el mismo contenedor de Configuración y relaciones de confianza transitivas automáticas; un administrador que compromete o controla un dominio dentro del bosque puede abusar de características compartidas (como `SID History` o plantillas de configuración) para escalar hacia los demás dominios del mismo Bosque.

**2. ¿Qué indican los RIDs `500`, `502` y `512` al final del SID de un objeto de Active Directory?** El RID `500` identifica siempre a la cuenta `Administrator` original del dominio; el RID `502` identifica a la cuenta de servicio `krbtgt` del Centro de Distribución de Claves Kerberos (KDC); y el RID `512` identifica al grupo de seguridad `Domain Admins`.

**3. ¿Por qué cualquier usuario estándar autenticado en un dominio puede consultar por LDAP la lista de usuarios, grupos y equipos si no tiene privilegios de administrador?** Porque el funcionamiento normal de Windows en un dominio requiere que los clientes y servicios autenticados consulten el directorio LDAP para aplicar Políticas de Grupo (GPOs), resolver nombres y SIDs en listas de control de acceso, buscar recursos compartidos y localizar servicios mediante registros SRV y atributos de objetos.

**4. ¿Qué problema resuelve el análisis basado en grafos (como BloodHound) que no se ve fácilmente al mirar una tabla plana de usuarios?** Permite descubrir rutas de escalada transitivas de múltiples saltos (por ejemplo, un usuario que pertenece a un grupo A, el cual tiene permiso de escritura sobre un grupo B, que a su vez es administrador local de un servidor donde tiene sesión abierta un administrador de Tier superior) combinando membresías de grupo, permisos DACL delegados y sesiones activas.

**5. ¿Cuál es la regla cardinal del Modelo de Tiering (Tier 0 / Tier 1 / Tier 2) y qué mecanismo técnico la hace cumplir?** La regla cardinal es que una cuenta de un nivel superior (por ejemplo Tier 0, `Domain Admins`) jamás debe iniciar sesión en un equipo de un nivel inferior (Tier 1 servidores o Tier 2 estaciones de trabajo), para evitar exponer sus credenciales o tickets en la memoria `lsass.exe` de un equipo menos seguro. Se hace cumplir mediante GPOs de asignación de derechos de usuario (`Deny log on...`) y Políticas/Silos de Autenticación Kerberos.

## Antes de avanzar

Verificá que podés:
- Explicar la jerarquía Bosque → Dominio → OU → Objeto y el papel de `NTDS.dit` y `SYSVOL`.
- Leer un `distinguishedName` (DN) y auditar atributos críticos de cuentas y grupos con PowerShell.
- Explicar cómo el modelo de Tiering 0/1/2 corta las rutas de escalada en el grafo del directorio.

::: nota Puerta de salida
Con la estructura del directorio y su modelo de inventario claros, el siguiente paso es analizar a nivel de protocolo cómo funcionan la autenticación Kerberos, NTLM y las listas de control de acceso (DACLs) sobre los objetos del dominio: avanzá al **Capítulo 3.7 · Kerberos, NTLM Relay, abuso de DACLs y delegación en Active Directory**.
:::

## Referencias y estándares abiertos

- **Microsoft Learn — Active Directory Domain Services Overview & Securing Active Directory (Tier Model / Privileged Access):** documentación oficial de arquitectura y modelo de administración por niveles.
- **RFC 4511 (Lightweight Directory Access Protocol — The Protocol) y RFC 4514 (LDAP String Representation of Distinguished Names).**
- **ANSSI (Agencia Nacional de Seguridad de los Sistemas de Información) — Active Directory Security Assessment Checklist:** guía pública de referencia para auditoría de puntos de control en AD.
- **Documentación oficial del módulo PowerShell `ActiveDirectory` (Microsoft Learn).**
