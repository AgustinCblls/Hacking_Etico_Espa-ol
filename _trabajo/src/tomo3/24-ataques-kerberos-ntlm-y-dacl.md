::: nota Objetivo de la lección
Al completar este capítulo vas a dominar el funcionamiento criptográfico paso a paso del protocolo **Kerberos v5 (RFC 4120)** en Active Directory, comprender por qué configuraciones débiles habilitan debilidades como AS-REP Roasting, Kerberoasting, NTLM Relay, abuso de permisos en DACLs, delegaciones mal restringidas y replicación no autorizada (DCSync), y sabrás exactamente con qué **Event IDs** detectarlas en el SOC y con qué políticas de endurecimiento erradicarlas de raíz.
:::

**Prerrequisitos:** Capítulo 3.2 (Auditoría de contraseñas y hashes) y Capítulo 3.6 (Arquitectura de Active Directory). **Duración sugerida:** 9 a 11 horas.

## 1. El protocolo Kerberos v5 por dentro (RFC 4120)

Desde Windows 2000, **Kerberos v5** es el protocolo de autenticación predeterminado de Active Directory. Su diseño busca un objetivo brillante: **que la contraseña del usuario (ni su hash) jamás viaje por la red** y que el usuario no tenga que volver a escribir su clave cada vez que accede a una carpeta compartida, una base de datos SQL o una intranet del dominio.

Para lograrlo, el Controlador de Dominio actúa como **Centro de Distribución de Claves (*Key Distribution Center*, KDC)**, el cual cumple dos funciones:
1. **Servicio de Autenticación (*Authentication Service*, AS):** verifica la identidad inicial del usuario y le entrega su pasaporte temporal para el dominio, llamado **TGT (*Ticket Granting Ticket*)**.
2. **Servicio Emisor de Tickets (*Ticket Granting Service*, TGS):** recibe el TGT del usuario y le emite entradas específicas para cada servidor al que quiera conectarse, llamadas **TGS (*Service Tickets*)**.

```text
[1. AS-REQ] Cliente envía marca de tiempo cifrada con el hash del usuario ──► [KDC (Controlador de Dominio)]
[2. AS-REP] KDC valida y devuelve el TGT (cifrado con el hash de krbtgt)  ◄──

[3. TGS-REQ] Cliente presenta su TGT y pide ticket para SPN (MSSQLSvc/db01) ──► [KDC (Controlador de Dominio)]
[4. TGS-REP] KDC devuelve el TGS (cifrado con el hash de la cuenta del SPN) ◄──

[5. AP-REQ]  Cliente presenta el TGS directamente al servidor destino     ──► [Servidor de Aplicación (db01)]
```

### Los tres pares de mensajes que todo analista debe dominar

| Paso del flujo | Mensaje | Qué se envía y con qué clave se cifra | Event ID en el Controlador de Dominio |
|---|---|---|---|
| **1. Preautenticación y solicitud de TGT** | `AS-REQ` → `AS-REP` | El cliente cifra el *timestamp* actual con su propia clave derivada de su contraseña. El KDC lo descifra y devuelve el **TGT** (cuya parte interna solo puede abrir el propio KDC porque está cifrada con la clave de la cuenta **`krbtgt`**). | **Event ID `4768`** (*A Kerberos authentication ticket (TGT) was requested*). |
| **2. Solicitud de Ticket de Servicio** | `TGS-REQ` → `TGS-REP` | El cliente presenta su TGT al KDC e indica el **SPN (*Service Principal Name*)** del servicio que desea usar (ej. `HTTP/intranet.corp.local`). El KDC no necesita consultar al servidor destino: cifra el ticket **TGS** usando el hash de la cuenta de AD dueña de ese SPN. | **Event ID `4769`** (*A Kerberos service ticket was requested*). |
| **3. Presentación al servidor destino** | `AP-REQ` → `AP-REP` | El cliente entrega el TGS al servidor de aplicación. El servidor lo descifra en memoria con su propia clave local y lee el **PAC (*Privilege Attribute Certificate*)** firmado por el KDC, que lista los SIDs y grupos del usuario. | **Event ID `4624`** (Logon Type `3`, Authentication Package: `Kerberos`) en el servidor destino. |

## 2. Configuraciones débiles en Kerberos y cómo erradicarlas

Cuando entendés con qué clave se cifra cada mensaje de la tabla anterior, comprendés inmediatamente por qué surgen dos riesgos clásicos de configuración en las cuentas de Active Directory:

### 1. Cuentas sin preautenticación Kerberos (*AS-REP Roasting*)

- **Causa técnica:** si un administrador marca por error la casilla **`Do not require Kerberos preauthentication`** (flag `DONT_REQ_PREAUTH = 0x400000` en `userAccountControl`) en una cuenta de usuario, el KDC omite la verificación del paso 1 y responde a cualquier solicitud `AS-REQ` para ese usuario entregando un mensaje `AS-REP` cuya parte de sesión viene cifrada con el hash de la contraseña de ese usuario. Si esa cuenta tiene una contraseña débil, ese bloque puede someterse a auditoría de diccionario offline.
- **Detección en el SOC:** monitorear el **Event ID `4768`** en los Controladores de Dominio filtrando por **`Pre-Authentication Type: 0`** y **`Ticket Encryption Type: 0x17` (RC4-HMAC)**; **criterio Sigma:** `EventID: 4768` con `PreAuthType: '0'` y `Status: '0x0'` emitido hacia cuentas con `DONT_REQ_PREAUTH`.
- **Laboratorio Purple Team (`GetNPUsers.py`) y remediación:** mantener obligatoria la preautenticación Kerberos en el 100 % de las cuentas del dominio (auditable con `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`).

```bash
# Verificación en laboratorio autorizado (sin contraseña, si la cuenta carece de pre-auth)
impacket-GetNPUsers corp.local/ -usersfile usuarios_lab.txt -no-pass -dc-ip 10.10.20.10 -format hashcat
```

### 2. Cuentas de servicio humanas con SPN y contraseñas estáticas (*Kerberoasting*)

- **Causa técnica:** en el paso 2 (`TGS-REQ` → `TGS-REP`), cualquier usuario autenticado del dominio puede solicitar legítimamente al KDC un ticket de servicio (TGS) para cualquier **SPN** registrado en el directorio, y el KDC devuelve ese ticket cifrado con el hash de la cuenta de Active Directory asociada al SPN.
  - Si el servicio corre bajo la cuenta de máquina del servidor (`db01$`) o bajo una cuenta **gMSA (*Group Managed Service Account*)**, su contraseña tiene **240 bytes aleatorios** generados y rotados automáticamente por Active Directory, resultando inviable para adivinar por fuerza bruta.
  - El problema ocurre cuando un administrador crea una **cuenta de usuario común** (por ejemplo `svc_sql`), le asigna una contraseña escrita a mano que nunca rota, le registra un SPN (`setspn -A ...`) y además permite el algoritmo heredado **RC4 (`0x17`)** en lugar de **AES-256 (`0x12`)**.
- **Detección en el SOC:** alertar sobre el **Event ID `4769`** cuando `Ticket Encryption Type` sea **`0x17` (RC4)** o cuando un mismo usuario solicite decenas de tickets TGS para distintos SPNs en pocos segundos. **Criterio Sigma:** `EventID: 4769` con `TicketEncryptionType: '0x17'` excluyendo cuentas máquina (`!*$`) y `krbtgt`.

```bash
# Verificación de cuentas kerberoasteables en laboratorio autorizado (`GetUserSPNs.py`)
impacket-GetUserSPNs corp.local/usuario_lab:'ClaveLab!' -dc-ip 10.10.20.10 -request -outputfile tgs_lab.txt
```

- **Remediación definitiva:**
  1. Migrar todas las cuentas de servicio con SPN a **gMSA (`New-ADServiceAccount`)** para que Active Directory gestione y rote automáticamente contraseñas de 240 bytes.
  2. Donde aún no se pueda usar gMSA, exigir contraseñas generadas aleatoriamente de **al menos 25 a 32 caracteres** y forzar el uso exclusivo de **AES-128 / AES-256** deshabilitando RC4 en las propiedades de la cuenta.

## 3. NTLM, NTLM Relay, cambio en Windows 11 24H2 / Server 2025 y vectores relacionados

Aunque Kerberos sea el protocolo principal, Windows conserva soporte para el protocolo de desafío-respuesta heredado **NetNTLMv2** cuando un cliente se conecta a un servidor usando su **dirección IP** (`\\10.10.20.50\carpeta`) en vez de su nombre DNS (`\\srv01.corp.local\carpeta`), o cuando el SPN no está disponible.

El protocolo NTLM carece de autenticación mutua del servidor por sí solo. Si una conexión NetNTLMv2 entrante es interceptada en la red local, el riesgo de **NTLM Relay** consiste en reenviar ese desafío-respuesta en tiempo real hacia otro servicio del dominio (como SMB, LDAP o un endpoint HTTP de certificados) que **no verifique la firma criptográfica de los paquetes ni el vínculo con el canal TLS**.

```bash
# Validación controlada de objetivos sin SMB Signing o sin EPA en laboratorio aislado (`ntlmrelayx.py`)
impacket-ntlmrelayx -tf objetivos_lab.txt -smb2support --no-dump
```

::: importante Cambio estructural en Windows 11 24H2 y Windows Server 2025: SMB Signing por defecto y fin de NTLMv1
A partir de **Windows 11 24H2** (en todas sus ediciones **salvo Home**) Microsoft exige **SMB Signing por defecto** en conexiones **entrantes y salientes** (`RequireSecuritySignature = True`). En **Windows Server 2025**, en cambio, el cambio por defecto exige firma en las conexiones **salientes** (cliente SMB) —mientras que en entrantes sigue activo de fábrica solo en Controladores de Dominio y **no** en servidores miembro—; ambos sistemas además **eliminan completamente el protocolo NTLMv1**. En consecuencia, la frase *"el relay hacia SMB falla de fábrica"* **no aplica a servidores miembro Windows Server 2025** ni a Windows 11 Home: la **GPO que obliga a firmar conexiones entrantes** (`Microsoft network server: Digitally sign communications (always)`) **sigue siendo imprescindible** en servidores miembro y estaciones, además de auditar **LDAPS/LDAP sin Channel Binding** y **ADCS Web Enrollment sin EPA (ESC8)**.
:::

### Vectores complementarios: Kerberos Relay, ADIDNS y cuentas Pre-Windows 2000

| Vector en AD | Mecanismo técnico | Detección (Event IDs + Sigma) | Mitigación obligatoria |
|---|---|---|---|
| **Kerberos Relay** | Reenvío de un ticket `AP-REQ` capturado tras coerción o alias DNS (`DNS/SPN` compatible) hacia servicios SMB/HTTP/LDAP sin firma ni vinculación de canal. | **Event ID `4769`** hacia SPNs `cifs/` o `http/` seguido de **`4624`** Kerberos desde IP intermediaria no esperada y **`5136`** si modifica RBCD/ACLs. **Sigma:** desajuste entre IP cliente de `4624` y estación emisora original del ticket. | Exigir **SMB Signing**, **LDAP Signing + Channel Binding (CBT)**, **HTTPS + EPA** y parches actualizados contra suplantación de SPN. |
| **ADIDNS** (*AD-Integrated DNS*) | Por defecto, `Authenticated Users` tiene permiso `CreateChild` en `DomainDnsZones`, permitiendo crear registros DNS dinámicos (incluidos comodines `*`) para interceptar tráfico hacia un host inexistente. | **Event ID `5136`** sobre objetos `dnsNode` en `DomainDnsZones` + registros de auditoría DNS (**Event ID `541`**). **Sigma:** creación de nodo DNS desde estación Tier 2 apuntando a IP no perteneciente a servidores autorizados. | Retirar `CreateChild` / `Write` a `Authenticated Users` en la zona ADIDNS, definir entradas estáticas críticas (WPAD/servicios) y bloquear `LLMNR`/`NBT-NS`. |
| **Cuentas Pre-Windows 2000** | Equipos pre-creados marcando *"pre-Windows 2000 computer"* fijan su contraseña inicial como su **nombre en minúsculas sin `$`** (auditable con `nxc ldap dc01.corp.local -u usuario_lab -p 'ClaveLab!' --pre2k`). | **Event ID `4741`** (alta de equipo) seguida de **`4768` / `4624`** desde IP no corporativa usando la cuenta `$` pre-creada. **Sigma:** logon inicial de objeto `$` con `pwdLastSet == whenCreated` sin unión real al dominio. | Nunca habilitar la opción Pre-Windows 2000 al pre-crear equipos; asignar contraseñas aleatorias únicas, rotar cuentas `$` inactivas y limpiar `Pre-Windows 2000 Compatible Access`. |

### Las cinco defensas que neutralizan por completo el Relay NTLM y Kerberos

| Control de endurecimiento | Qué protege | Cómo configurarlo en el dominio |
|---|---|---|
| **1. SMB Signing obligatorio en todos los equipos** | Impide reenviar autenticaciones NTLM hacia sesiones SMB (`TCP/445`). Viene activo por defecto en Controladores de Dominio, pero debe forzarse también en servidores miembro y estaciones. | GPO: `Microsoft network server: Digitally sign communications (always)` = **Enabled** y `Microsoft network client: Digitally sign communications (always)` = **Enabled**. |
| **2. LDAP Signing y LDAP Channel Binding (CBT)** | Impide que una autenticación NTLM reenviada modifique objetos o ACLs en el servidor LDAP/LDAPS del Controlador de Dominio. | GPO en DCs: `Domain controller: LDAP server signing requirements` = **Require signing** y `Domain controller: LDAP server channel binding token requirements` = **Always**. |
| **3. Extended Protection for Authentication (EPA)** | Vincula criptográficamente el handshake NTLM con el certificado TLS de la sesión HTTPS en servicios web (IIS / ADCS Web Enrollment). | Activar **Extended Protection = Required** y exigir HTTPS en IIS / servicios web integrados. |
| **4. Bloqueo de Coerción de Autenticación (RPC)** | Ciertas llamadas RPC remotas (*MS-EFSRPC*, *MS-RPRN Spooler*) fuerzan a servidores o Controladores de Dominio a autenticarse contra una IP elegida para combinarlo con NTLM Relay. | Deshabilitar el servicio **Print Spooler** en Controladores de Dominio, bloquear puertos RPC salientes innecesarios y aplicar filtros RPC. |
| **5. Reducción y bloqueo progresivo de NTLM** | Elimina NTLMv1 de inmediato y restringe NTLMv2 en cuentas privilegiadas. | GPO `Network security: LAN Manager authentication level` = **Send NTLMv2 response only. Refuse LM & NTLM** + incluir a todos los administradores en el grupo **`Protected Users`** (que prohíbe usar NTLM). |

## 4. Permisos en objetos del directorio (DACLs), Delegación y DCSync

Cada objeto de Active Directory (usuario, grupo, equipo, OU y el propio nodo raíz del dominio) tiene una **Lista de Control de Acceso Discrecional (`DACL`)** que define quién puede modificarlo. Cuando se delegan permisos excesivos a grupos de soporte o cuentas de servicio, aparecen vectores críticos de escalada dentro del directorio:

### Permisos DACL de alto riesgo a auditar

| Permiso / Derecho Extendido en la DACL | Impacto sobre el objeto destino | Event ID de auditoría en AD |
|---|---|---|
| `GenericAll` (Control total) | Permite modificar cualquier atributo del objeto, cambiar contraseñas o agregar miembros si es un grupo. | **`5136`** (*A directory service object was modified*). |
| `WriteDacl` / `WriteOwner` | Permite modificar la propia lista de permisos del objeto o tomar posesión de él para otorgarse control total. | **`5136`** sobre el atributo `nTSecurityDescriptor`. |
| `ForceChangePassword` (`User-Force-Change-Password`) | Permite restablecer la contraseña de un usuario objetivo sin conocer la anterior. | **`4724`** (*An attempt was made to reset an account's password*). |
| `WriteProperty` sobre `member` | Permite añadirse a sí mismo o a otra cuenta dentro de un grupo de seguridad. | **`4728`** (grupo global) / **`4732`** (grupo local) / **`4756`** (grupo universal). |
| `WriteProperty` sobre `msDS-KeyCredentialLink` (*Shadow Credentials*) | Permite registrar un certificado efímero propio en el objeto usuario/equipo para autenticarse vía Kerberos PKINIT sin modificar su contraseña. | **`5136`** sobre el atributo `msDS-KeyCredentialLink`. |
| `WriteProperty` sobre `servicePrincipalName` (*Targeted Kerberoasting*) | Permite asignar un SPN a otra cuenta de usuario controlada por DACL para solicitar su TGS, o bien alterar `sAMAccountName` en equipos sin parchear (`CVE-2021-42278/42287`). | **`5136`** sobre `servicePrincipalName` / **`4781`** (renombrado de cuenta). |
| `WriteDacl` / `WriteOwner` en **GPOs** (`Group Policy`) | Permite editar una GPO aplicada sobre una OU administrativa o de servidores para desplegar tareas programadas o permisos locales. | **`5136`** sobre objetos `groupPolicyContainer` + cambios en `\\dominio\SYSVOL\...\Policies`. |
| `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` (en la raíz del dominio) | Permisos exclusivos de los Controladores de Dominio para sincronizar `NTDS.dit`. Si se otorgan a una cuenta no-DC, permiten solicitar la replicación de hashes de credenciales (**DCSync**). | **`4662`** con propiedades GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` y `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` desde una IP que no es un DC. |

### Delegación Kerberos: por qué prohibir la delegación sin restricciones

La delegación Kerberos se creó para escenarios de múltiples capas (por ejemplo, el usuario se autentica en un servidor web frontal `WEB01` y ese servidor web necesita consultar la base de datos `SQL01` actuando en nombre del usuario):

1. **Delegación sin restricciones (*Unconstrained Delegation* — obsoleta y peligrosa):** cuando un servidor tiene activado `TRUSTED_FOR_DELEGATION`, cualquier usuario que se conecte a él le envía una copia completa de su propio **TGT** para que el servidor lo guarde en memoria (`lsass.exe`). Si ese servidor se ve comprometido, expone los TGTs de cualquier usuario que se haya conectado. **Remediación:** quitar la delegación sin restricciones de todos los servidores miembro y activar `Account is sensitive and cannot be delegated` (o grupo `Protected Users`) en todas las cuentas administrativas.
2. **Delegación restringida (*Constrained Delegation* — KCD) y Basada en Recursos (*RBCD*):** limitan a qué servicios exactos (`msDS-AllowedToDelegateTo`) puede delegar un frontal, o qué cuenta específica tiene permiso para delegar hacia un recurso destino (`msDS-AllowedToActOnBehalfOfOtherIdentity`). Deben auditarse continuamente para asegurar que ningún equipo no autorizado modifique el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity`.

### Extracción de secretos (`secretsdump.py`), memoria `lsass.exe` (`Mimikatz`/`Rubeus`) y mitigación `RunAsPPL`

En evaluaciones de Active Directory (incluido el set práctico de PEN-200), escalar a administrador local en una máquina no es el final, sino el medio para inspeccionar qué secretos de dominio residen en el Registro o en la memoria de ese equipo:

- **Volcado remoto y offline con `secretsdump.py` (Impacket):** una vez obtenidos privilegios administrativos sobre un host Windows, `secretsdump.py` lee el Registro (`SAM`, `SYSTEM` y `SECURITY`) para recuperar hashes NT de cuentas locales, **LSA Secrets** (como contraseñas de servicios configurados con `Log On As` o cuentas de máquina `$`) y **DCC2** (*Domain Cached Credentials*). Cuando se ejecuta contra un Controlador de Dominio con derechos de replicación, la bandera `-just-dc-ntlm` invoca **DCSync** sin tocar el archivo físico `NTDS.dit`.
- **Auditoría de `lsass.exe` y tickets Kerberos (`Mimikatz`, `pypykatz` y `Rubeus`):** el proceso **`lsass.exe`** mantiene en RAM material criptográfico de sesiones activas (hashes NT, claves AES Kerberos y tickets TGT/TGS). En laboratorio aislado, herramientas como `Mimikatz` (`sekurlsa::logonpasswords`, `sekurlsa::tickets /export`) o el análisis offline de volcados con `pypykatz` ilustran el riesgo de reutilizar sesiones administrativas en múltiples servidores. Para manipular y validar tickets Kerberos en Windows (solicitud `asktgt`, listado `triage` e inyección en sesión `ptt`), **`Rubeus`** cumple el equivalente en .NET al uso de `KRB5CCNAME` en Linux.

```bash
# Extraer hashes locales SAM y LSA Secrets desde Linux usando credenciales de administrador local del lab
impacket-secretsdump DOMINIO/admin_local:PasswordLab@10.10.20.30

# Análisis offline seguro de un volcado de memoria autorizado en laboratorio (sin ejecutar binarios en el host)
pypykatz lsa minidump /ruta/lab/lsass_dump.dmp
```

::: defensa Endurecimiento obligatorio contra extracción en memoria (`RunAsPPL` y Credential Guard)
1. **LSA Protection (`RunAsPPL`):** configurar `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1` obliga a `lsass.exe` a ejecutarse como proceso protegido (*Protected Process Light*), bloqueando la apertura de handles de lectura de memoria (`PROCESS_VM_READ`) incluso desde cuentas con privilegios locales de administrador sin controlador kernel firmado.
2. **Windows Defender Credential Guard (VBS):** en hardware moderno con virtualización, aísla los hashes NTLM y TGTs dentro de un contenedor seguro basado en hipervisor (`LsaIso.exe`), impidiendo que herramientas en espacio de usuario accedan al material criptográfico de `lsass.exe`.
3. **Deshabilitar WDigest en claro (`UseLogonCredential = 0`)** y aplicar estrictamente **Tiering** para impedir que administradores de Dominio inicien sesión en servidores de nivel inferior.
:::

### Reutilización y falsificación de credenciales: PtH, Overpass-the-Hash, PtT y tickets forjados

Cuando una evaluación o un incidente expone hashes NT, claves AES, tickets Kerberos en memoria o el secreto de la cuenta **`krbtgt`**, el riesgo pasa del acceso inicial a la persistencia y el movimiento lateral sin necesidad de conocer contraseñas en texto claro:

| Técnica | Material criptográfico utilizado | Mecanismo técnico y alcance | Detección prioritaria en SIEM y mitigación |
|---|---|---|---|
| **Pass-the-Hash (PtH)** | Hash NT (RC4) de usuario local o de dominio. | Reutiliza el hash NT directamente para completar el desafío-respuesta NTLM hacia servicios remotos (SMB, WMI, WinRM) sin descifrar la contraseña. | **Event ID `4624` (`Logon Type 9` / `NewCredentials`)** en el origen al clonar sesión o `Logon Type 3` con autenticación NTLM en destino. Mitigar con **Windows LAPS**, `Protected Users` y restricción de NTLM. |
| **Overpass-the-Hash (Pass-the-Key)** | Hash NT o clave **AES-128 / AES-256** del usuario. | Usa la clave derivada para firmar el timestamp del `AS-REQ` y obtener del KDC un **TGT Kerberos legítimo**, evitando tráfico NTLM hacia el servidor destino. | **Event ID `4768`** con **`Ticket Encryption Type: 0x17` (RC4)** en dominios que operan con AES, junto a `4624` (`Logon Type 9`). Exigir AES-256 y `Protected Users`. |
| **Pass-the-Ticket (PtT)** | Ticket TGT o TGS exportado (`.kirbi` en Windows / `.ccache` vía `KRB5CCNAME` en Linux). | Inyecta un ticket vigente extraído de `lsass.exe` en otra sesión para suplantar al usuario hasta que expire el ticket, sin usar su contraseña ni su hash. | **Event ID `4624` (`Logon Type 9`)** en el host que inyecta el ticket y uso de un mismo TGT desde IPs distintas en **`4769`**. Mitigar con **RunAsPPL**, **Credential Guard** y límites de vida de TGT. |
| **Golden Ticket** | Hash NT o clave AES de la cuenta **`krbtgt`** (obtenido vía DCSync). | Permite forjar offline un **TGT** para cualquier identidad (real o inexistente) con un **PAC** arbitrario de `Domain Admins` / `Enterprise Admins` o `sIDHistory`. | Solicitudes **`4769`** sin un **`4768`** previo coherente, algoritmos RC4 (`0x17`), nombres de cuenta inexistentes o tiempos de vida de ticket anómalos. Erradicar únicamente con la **doble rotación de `krbtgt`** (Cap. 3.8). |
| **Silver Ticket** | Hash NT o clave AES de la cuenta dueña de un **SPN** (servicio o equipo). | Permite forjar offline un **TGS** únicamente válido para ese servicio puntual sin contactar al KDC; el servidor destino descifra el ticket con su propia clave y confía en el PAC si no valida contra el DC. | Ausencia total de **`4769`** en el KDC frente a un **`4624` (`Logon Type 3`, Kerberos)** registrado en el servidor destino, o anomalías de firma PAC (`PAC Validation`). Rotar la clave de la cuenta del servicio o migrar a **gMSA**. |
| **Diamond / Sapphire Ticket** | Clave AES/NT de **`krbtgt`** (y en Sapphire, consulta S4U2self + U2U al KDC). | Técnicas diseñadas para evadir detecciones simples de Golden Tickets: **Diamond** solicita un TGT real al KDC (`4768` legítimo), lo descifra con `krbtgt`, altera únicamente el PAC y lo recifra; **Sapphire** obtiene además un PAC real y completo de un usuario objetivo mediante S4U2self antes de reempaquetar el TGT. | Correlacionar en **`4768` / `4769`** anomalías sutiles de cuenta y duración, solicitudes S4U2self inusuales desde equipos no autorizados y alertas previas de **DCSync (`4662`)**. Su remediación definitiva también exige la **doble rotación de `krbtgt`** descrita en el Cap. 3.8. |

::: aviso Por qué la doble rotación de `krbtgt` es obligatoria ante Golden, Diamond o Sapphire Tickets
El KDC conserva válidas tanto la clave actual (`N`) como la inmediatamente anterior (`N-1`) de `krbtgt` para no interrumpir sesiones vigentes. Por eso, si un actor comprometió `krbtgt` (habilitando Golden, Diamond o Sapphire Tickets), rotar la contraseña una sola vez deja los tickets forjados aún válidos contra `N-1`: debés ejecutar **dos rotaciones consecutivas** respetando el intervalo máximo de vida del TGT (Cap. 3.8).
:::

## 5. Ejemplo paso a paso: auditoría de DACLs, delegación y firma con PowerShell

Este script de diagnóstico defensivo verifica en segundos el estado de delegación Kerberos, permisos de replicación en la raíz del dominio y configuración de firma SMB/LDAP:

```powershell
# 1. Auditar equipos (excluyendo Domain Controllers) con Unconstrained Delegation activa
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516} |
    Select-Object Name, DNSHostName, OperatingSystem

# 2. Auditar cuentas o equipos con Resource-Based Constrained Delegation (RBCD) configurada
Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like "*"} `
    -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Select-Object Name, DistinguishedName

# 3. Auditar la DACL de la raíz del dominio buscando quién tiene permisos de replicación (DCSync)
$raiz = (Get-ADDomain).DistinguishedName
(Get-Acl "AD:\$raiz").Access |
    Where-Object { $_.ObjectType -in @(
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    ) -and $_.AccessControlType -eq "Allow" } |
    Select-Object IdentityReference, ActiveDirectoryRights, ObjectType

# 4. Comprobar en el host local si SMB Signing está exigido (RequireSecuritySignature = True)
Get-SmbServerConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature
Get-SmbClientConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature
```

Salida esperada en un servidor correctamente endurecido para el punto 4:

```text
EnableSecuritySignature RequireSecuritySignature
----------------------- ------------------------
                   True                     True
```

::: defensa Perspectiva defensiva, detección y mitigación
1. **Grupo `Protected Users` para el 100 % de las cuentas privilegiadas:** al agregar todas las cuentas de Tier 0 y Tier 1 al grupo nativo `Protected Users` (introducido en Windows Server 2012 R2), el dominio aplica automáticamente cuatro protecciones a nivel de protocolo: prohíbe autenticarse con NTLM, prohíbe usar cifrado DES o RC4 en Kerberos (exige AES), prohíbe delegar la cuenta (`Constrained` o `Unconstrained`) y reduce la vida útil del TGT a 4 horas sin renovación automática más allá de ese límite.
2. **Reglas SIEM prioritarias para Active Directory:**
   - **Event ID `4768` / `4769`** con `Ticket Encryption Type = 0x17` (uso de RC4 que debe investigarse o migrarse a AES/gMSA).
   - **Event ID `4662`** en DCs con GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` originado desde cualquier cuenta o IP que no pertenezca al grupo `Domain Controllers` (alerta crítica inmediata de replicación no autorizada).
   - **Event ID `5136`** cuando se modifica el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` o `servicePrincipalName`.
:::

## Práctica en laboratorio local

1. En tu máquina Windows de laboratorio, ejecutá `Get-SmbServerConfiguration` y `Get-SmbClientConfiguration` para comprobar el estado actual de `RequireSecuritySignature`. Si está en `$false`, activalo en tu VM de laboratorio con `Set-SmbServerConfiguration -RequireSecuritySignature $true -Force` y `Set-SmbClientConfiguration -RequireSecuritySignature $true -Force` y volvé a verificarlo.
2. Creá un script PowerShell `auditar_kerberos_dacl.ps1` que integre las cuatro consultas de la sección 5 y agregue una quinta verificación que compruebe si todas las cuentas miembros de `Domain Admins` están también incluidas dentro del grupo `Protected Users`.
3. Redactá una tabla de correlación para el SOC que asocie cada uno de los cinco vectores estudiados (AS-REP sin pre-auth, Kerberoasting RC4, modificación de grupo privilegiado, cambio de atributo RBCD y DCSync) con su **Event ID exacto** y el campo clave del evento XML que confirma la anomalía.

::: practica Entregable mínimo
Tu script `auditar_kerberos_dacl.ps1`, la captura de consola mostrando `RequireSecuritySignature = True` en tu VM Windows y la tabla de correlación de los 5 Event IDs de Active Directory para el SIEM.
:::

## Preguntas de repaso

**1. En el flujo Kerberos v5, ¿con qué clave se cifra el TGT devuelto en el `AS-REP` y con qué clave se cifra el ticket de servicio (TGS) devuelto en el `TGS-REP`?** El **TGT** se cifra con la clave secreta de la cuenta **`krbtgt`** del Controlador de Dominio (para que solo el KDC pueda abrirlo y verificarlo). El **TGS** se cifra con el hash de la contraseña de la **cuenta de Active Directory propietaria del SPN** del servicio destino (para que el servidor de aplicación pueda descifrarlo localmente al recibir el `AP-REQ`).

**2. ¿Por qué migrar una cuenta de servicio tradicional a una cuenta gMSA (*Group Managed Service Account*) elimina el riesgo de Kerberoasting?** Porque el riesgo de Kerberoasting reside en que un humano asigne una contraseña débil o adivinable por diccionario a la cuenta dueña del SPN. Una cuenta **gMSA** utiliza una contraseña aleatoria criptográfica de **240 bytes** generada y rotada automáticamente por los Controladores de Dominio y fuerza el uso de cifrado AES, haciendo inviable cualquier intento de fuerza bruta offline sobre el TGS.

**3. ¿Qué tres configuraciones de dominio son necesarias para cerrar de forma integral los vectores de NTLM Relay hacia SMB, LDAP y servicios web HTTP/HTTPS?** Exigir **SMB Signing** (`RequireSecuritySignature = True`) en todos los servidores y estaciones; exigir **LDAP Signing y LDAP Channel Binding** en todos los Controladores de Dominio; y habilitar **HTTPS con Extended Protection for Authentication (EPA)** en los servicios web integrados como IIS y ADCS Web Enrollment.

**4. ¿Qué indica en los registros de seguridad de un Controlador de Dominio un evento `4662` que solicita el permiso GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` desde una estación de trabajo que no es un Controlador de Dominio?** Ese GUID corresponde al derecho extendido `DS-Replication-Get-Changes-All`, utilizado para sincronizar hashes de contraseñas desde `NTDS.dit`. En una operación legítima solo otros Controladores de Dominio solicitan esa replicación; verla originada desde una estación de trabajo o servidor común es el indicador definitivo de una extracción de credenciales mediante **DCSync**.

**5. ¿Qué cuatro protecciones automáticas aplica Active Directory a cualquier cuenta administrativa que se incorpore al grupo `Protected Users`?** Impide que la cuenta se autentique mediante **NTLM** (forzando Kerberos); prohíbe el uso de suites de cifrado débiles como **DES o RC4** en Kerberos (exigiendo AES); bloquea cualquier forma de **delegación Kerberos** sobre esa cuenta; y limita la validez máxima del **TGT a 4 horas** sin almacenar credenciales en caché a largo plazo.

## Antes de avanzar

Verificá que podés:
- Dibujar de memoria el intercambio `AS-REQ/AS-REP` (4768), `TGS-REQ/TGS-REP` (4769) y `AP-REQ/AP-REP` (4624).
- Auditar cuentas con SPN, cuentas sin preautenticación, delegaciones Kerberos y permisos DACL críticos.
- Configurar SMB Signing, LDAP Signing/Channel Binding, gMSA y el grupo `Protected Users`.

::: nota Puerta de salida
Ya dominás los protocolos centrales de autenticación y autorización del directorio. Para completar el **Tomo III**, en el próximo capítulo analizaremos la infraestructura de certificados PKI de Active Directory (ADCS), las relaciones de confianza entre dominios/bosques y el plan maestro integral de endurecimiento: avanzá al **Capítulo 3.8 · ADCS (ESC1–ESC8), trusts entre dominios y plan maestro de hardening AD**.
:::

## Referencias y estándares abiertos

- **RFC 4120 (The Kerberos Network Authentication Service V5):** especificación oficial del protocolo Kerberos v5.
- **Microsoft Learn — Group Managed Service Accounts (gMSA) Overview & Protected Users Security Group:** guías oficiales para asegurar cuentas de servicio y cuentas privilegiadas.
- **Microsoft Learn — ADV190023 (Microsoft Guidance for Enabling LDAP Channel Binding and LDAP Signing):** configuración oficial contra NTLM Relay sobre LDAP/LDAPS.
- **Microsoft Learn — Audit Directory Service Access (Event IDs 4662, 4768, 4769, 5136):** referencia de telemetría de seguridad de Active Directory.
