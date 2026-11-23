::: nota Objetivo de la lección
Al finalizar este capítulo vas a comprender la arquitectura de **Active Directory Certificate Services (ADCS)** y su integración con la autenticación del dominio (`PKINIT` y SChannel), identificar y remediar las malas configuraciones clásicas en plantillas de certificados y servicios de inscripción (**ESC1 a ESC8**), auditar relaciones de confianza entre dominios y bosques (*Domain & Forest Trusts*, `SID Filtering` y *Selective Authentication*), asegurar servicios corporativos integrados (MSSQL y SCCM/MECM) y aplicar un **Plan Maestro de Hardening de Active Directory**.
:::

**Prerrequisitos:** Capítulo 3.6 (Arquitectura de AD y Tiering) y Capítulo 3.7 (Kerberos, NTLM y DACLs). **Duración sugerida:** 9 a 11 horas.

## 1. Arquitectura de Active Directory Certificate Services (ADCS)

**Active Directory Certificate Services (ADCS)** es la implementación de Infraestructura de Clave Pública (PKI) de Microsoft integrada nativamente en Active Directory. En una red empresarial, la Autoridad de Certificación (**Enterprise CA**) emite certificados X.509 para múltiples fines: cifrar tráfico TLS interno, firmar código, autenticar conexiones VPN/Wi-Fi (`802.1X`), usar tarjetas inteligentes y **autenticar usuarios y máquinas directamente contra el KDC Kerberos mediante el estándar `PKINIT` (RFC 4556)**.

```text
[Usuario / Máquina del Dominio]
       │
       │ 1. Solicita certificado (CSR) basado en una Plantilla de Certificado publicada en AD
       ▼
[Servidor Enterprise CA (ADCS)] ──(Verifica permisos de Enrollment en la plantilla y EKUs)
       │
       │ 2. Emite Certificado X.509 firmado por la CA del dominio
       ▼
[KDC Kerberos (Controlador de Dominio)]
  • Si el certificado tiene EKU "Client Authentication" y un UPN/DNS válido en el SAN,
    el KDC valida la firma de la CA mediante PKINIT y emite un TGT (Event ID 4768) para esa identidad.
```

Observá la implicación arquitectónica: **en un dominio con ADCS habilitado, la Autoridad de Certificación (CA) es un activo de Tier 0 exactamente igual de crítico que un Controlador de Dominio**, porque cualquier certificado que la CA firme con capacidad de autenticación de cliente permite obtener un TGT Kerberos válido para la identidad inscrita en el certificado.

### Conceptos clave de una Plantilla de Certificado (*Certificate Template*)

Las plantillas de certificados son objetos almacenados en la partición de Configuración de Active Directory (`CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=...`). Su seguridad depende de cinco propiedades:

1. **DACL de la plantilla:** quién tiene permiso de **`Enroll`** (inscribirse) o **`Autoenroll`** y quién tiene permisos de escritura (`WriteProperty` / `WriteDacl`) para editar la plantilla.
2. **EKU (*Extended Key Usage*):** define para qué sirve el certificado. Los EKUs que permiten autenticarse en el dominio son `Client Authentication` (`1.3.6.1.5.5.7.3.2`), `Smart Card Logon` (`1.3.6.1.4.1.311.20.2.2`), `PKINIT Client Authentication` o `Any Purpose`.
3. **Nombre del Sujeto (*Subject Name* / *Subject Alternative Name*, SAN):** por defecto y de forma segura, la CA ignora lo que pida el cliente y construye el nombre del certificado leyendo la identidad real del solicitante desde Active Directory. Sin embargo, si se activa el flag **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (*Supply in the request*)**, la plantilla permite que el solicitante escriba cualquier `Subject Alternative Name (SAN)` dentro de su solicitud CSR.
4. **Requisitos de emisión (*Issuance Requirements*):**
   - **Aprobación del administrador de CA (*CA certificate manager approval*):** deja la solicitud en estado *Pending* hasta que un oficial de PKI la apruebe manualmente.
   - **Firmas autorizadas (*Authorized Signatures Required*):** exige que la solicitud venga cofirmada por un Agente de Inscripción.

## 2. Configuraciones vulnerables en ADCS (ESC1–ESC8) y su remediación

La investigación publicada por SpecterOps sistematizó las principales configuraciones riesgosas de ADCS bajo los códigos **ESC1 a ESC8**. Esta tabla resume las condiciones exactas que debe buscar un auditor y cómo corregir cada una:

| Código | Condición de mala configuración en ADCS | Por qué representa un riesgo crítico | Remediación de ingeniería obligatoria |
|---|---|---|---|
| **ESC1** | Plantilla con EKU de autenticación + permiso `Enroll` para grupos amplios (`Domain Users`) + **`ENROLLEE_SUPPLIES_SUBJECT` activo** + sin aprobación de CA Manager. | Cualquier usuario autorizado a inscribirse puede solicitar un certificado especificando en el campo `SAN` el UPN de otro usuario del dominio. | Desactivar `Supply in the request` (hacer que la CA construya el sujeto desde AD). Si una plantilla de servidores requiere SAN manual, restringir `Enroll` exclusivamente al grupo de servidores necesarios y exigir aprobación de CA Manager. |
| **ESC2 / ESC3** | Plantilla con EKU `Any Purpose`, sin EKU (*SubCA*) o con EKU `Certificate Request Agent` otorgada a usuarios no privilegiados. | Permite emitir certificados comodín o actuar como Agente de Inscripción (`Enrollment Agent`) para solicitar certificados en nombre de terceros. | Restringir plantillas `Enrollment Agent` y `SubCA` exclusivamente a oficiales de PKI de Tier 0 y configurar restricciones de ámbito de agente en la CA. |
| **ESC4** | Permisos de escritura (`WriteOwner`, `WriteDacl`, `WriteProperty`) sobre el objeto de una plantilla de certificado otorgados a usuarios no-Tier 0. | Quien tiene permiso de escritura sobre la plantilla puede modificar sus atributos en LDAP para convertirla temporalmente en una plantilla tipo ESC1. | Auditar las DACLs de `CN=Certificate Templates` y dejar permisos de modificación únicamente a `Domain Admins` / `Enterprise Admins` (Tier 0). |
| **ESC5 / ESC7** | Permisos débiles sobre el servidor de la CA, sus claves privadas o el permiso administrativo `ManageCA` / `ManageCertificates`. | Un administrador del servidor donde reside la CA controla toda la PKI del Bosque. | Tratar todo servidor ADCS como **activo estricto de Tier 0**: ningún administrador de Tier 1 o Tier 2 debe tener acceso local ni permisos `ManageCA`. |
| **ESC6** | El servidor CA tiene activado el flag global **`EDITF_ATTRIBUTESUBJECTALTNAME2`**. | Ese flag global peligroso hace que **todas** las plantillas de la CA acepten un SAN arbitrario enviado por el cliente, aunque la plantilla individual no tenga `ENROLLEE_SUPPLIES_SUBJECT`. | Desactivarlo inmediatamente en la CA: `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2` y reiniciar el servicio `certsvc`. |
| **ESC8** | Servicio web **ADCS HTTP Web Enrollment** (`/certsrv/`) habilitado por HTTP sin HTTPS ni **Extended Protection for Authentication (EPA)**. | Permite que una autenticación NTLM reenviada (*NTLM Relay*, Cap. 3.7) solicite un certificado a través de la interfaz web. | Desinstalar el rol obsoleto `CA Web Enrollment` si no se utiliza; si es indispensable, forzar **HTTPS únicamente**, activar **EPA = Required** y deshabilitar NTLM en el sitio IIS `/certsrv`. |

### Evolución post-ESC8: resumen de vectores ESC9 a ESC16

Con la adopción de defensas contra ESC1–ESC8, nuevas investigaciones identificaron vectores adicionales centrados en el **mapeo débil de certificados sin SID**, interfaces RPC alternativas, enlaces de políticas OID y modificaciones de atributos de esquema:

| Código | Condición técnica o superficie afectada | Impacto y mecanismo de abuso | Remediación obligatoria |
|---|---|---|---|
| **ESC9 / ESC10** | Plantillas con el flag `CT_FLAG_NO_SECURITY_EXTENSION` (**ESC9**) o Controladores de Dominio con mapeo débil de certificados (`StrongCertificateBindingEnforcement` en `0` o `CertificateMappingMethods` permisivo sobre UPN/DNS, **ESC10**). | Al no exigir la extensión fuerte con el **SID exacto** (`szOID_NTDS_CA_SECURITY_EXT`), quien controle el atributo `userPrincipalName` o `dNSHostName` de una cuenta puede suplantar temporalmente el UPN de otro usuario para obtener un certificado y autenticarse como él. | Aplicar el parche **KB5014754** en modo estricto (`StrongCertificateBindingEnforcement = 2`), restringir `CertificateMappingMethods` y eliminar `CT_FLAG_NO_SECURITY_EXTENSION` de las plantillas. |
| **ESC11** | Interfaz RPC de inscripción de certificados (**`MS-ICPR`**) expuesta en la CA sin el flag **`IF_ENFORCEENCRYPTICERTREQUEST`** en `InterfaceFlags`. | Permite ejecutar **NTLM Relay directamente sobre RPC (`MS-ICPR`)** para inscribir certificados sin pasar por IIS Web Enrollment (`/certsrv/`), eludiendo mitigaciones aplicadas solo a ESC8. | Activar la privacidad obligatoria de paquete RPC en la CA (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) y reiniciar `certsvc`. |
| **ESC12** | Acceso local o de lectura sobre la configuración/PIN de módulos criptográficos (YubiHSM / PKCS#11) que resguardan la clave privada de la CA. | Permite acceder directamente a la clave privada de la CA para firmar certificados arbitrarios fuera de los registros normales de emisión. | Aislar la CA en **Tier 0**, proteger con permisos estrictos los archivos/claves del HSM y auditar accesos al servicio criptográfico. |
| **ESC13** | Plantilla configurada con una política de emisión (`msPKI-Certificate-Policy`) vinculada mediante **`msDS-OIDToGroupLink`** a un grupo privilegiado en AD. | Cualquier usuario autorizado a inscribirse en esa plantilla recibe en su PAC el SID del grupo universal vinculado cuando se autentica con el certificado emitido. | Auditar todos los OIDs con `msDS-OIDToGroupLink` en la partición `Configuration` y eliminar vínculos hacia grupos privilegiados o plantillas abiertas. |
| **ESC14** | Permisos delegados para modificar el atributo `altSecurityIdentities` o métodos débiles de mapeo explícito (p. ej. `X509:<RFC822>`). | Permite asociar manualmente un certificado emitido para una identidad controlada hacia una cuenta objetivo mediante mapeo explícito débil. | Restringir quién puede escribir `altSecurityIdentities` en AD y exigir mapeos fuertes (`X509:<SID>` o `IssuerSerialNumber`) conforme a KB5014754. |
| **ESC15 / ESC16** | Plantillas esquema v1 con `ENROLLEE_SUPPLIES_SUBJECT` vulnerables a inyección arbitraria de **Application Policies** (`CVE-2024-49019`, **ESC15**); o la deshabilitación global en la CA de la extensión SID (`1.3.6.1.4.1.311.25.2` en `policy\DisableExtensionList`, **ESC16**). | **ESC15** permite inyectar EKU de autenticación o *Enrollment Agent* en plantillas v1 que no los tenían; **ESC16** suprime la extensión SID en **todos** los certificados emitidos por esa CA (replicando el riesgo de ESC9 a escala global). | Instalar la actualización de seguridad contra `CVE-2024-49019` y migrar plantillas v1; verificar con `certutil -getreg policy\DisableExtensionList` que `1.3.6.1.4.1.311.25.2` no esté deshabilitado y mantener `StrongCertificateBindingEnforcement = 2`. |

### Telemetría de detección de ADCS en el SIEM

Para que el SOC tenga visibilidad completa sobre la emisión de certificados:
1. En las propiedades de la Autoridad de Certificación (pestaña *Auditing*), activar la casilla **`Issue and manage certificate requests`**.
2. Monitorear en el registro `Security` de la CA los eventos:
   - **Event ID `4886`:** *Certificate Services received a certificate request*.
   - **Event ID `4887`:** *Certificate Services approved a certificate request and issued a certificate* (inspeccionar que el `Subject` y el `Subject Alternative Name` coincidan con la cuenta `Requester`).
3. Monitorear en los Controladores de Dominio el **Event ID `4768`** cuando el certificado utilizado para `PKINIT` difiera de la cuenta que solicitó el certificado minutos antes, y verificar que esté aplicado el parche de mapeo fuerte de certificados de Microsoft (**`StrongCertificateBindingEnforcement`** en `HKLM\SYSTEM\CurrentControlSet\Services\Kdc`).

## 3. Relaciones de confianza entre dominios y bosques (Domain & Forest Trusts)

En grandes corporaciones (o tras fusiones y adquisiciones de empresas) suelen coexistir múltiples dominios dentro de un mismo bosque o **múltiples bosques separados** vinculados mediante **Relaciones de Confianza (*Trusts*)**:

| Propiedad de un Trust | Opciones | Implicación de seguridad |
|---|---|---|
| **Dirección** | Unidireccional (*One-way*) o Bidireccional (*Two-way*) | Atención a la regla fundamental: **el acceso fluye en sentido opuesto a la confianza**. Si el Dominio A *confía* en el Dominio B (`A ──confía──► B`), entonces los usuarios del Dominio B pueden acceder a recursos a los que se les dé permiso en el Dominio A. |
| **Transitividad** | Transitivo o No transitivo | En un trust transitivo, si A confía en B y B confía en C, entonces A confía implícitamente en C. Todos los dominios de un mismo bosque tienen trusts bidireccionales y transitivos automáticos. |
| **Tipo de relación** | *Parent-Child* / *Tree-Root* (mismo bosque), *External Trust* o *Forest Trust* (entre bosques distintos) | Los *Intra-Forest Trusts* comparten la frontera de seguridad del bosque. Los *External* y *Forest Trusts* conectan fronteras de seguridad distintas y deben tener activados **SID Filtering** y **Selective Authentication**. |

### Dos controles obligatorios en cualquier Trust entre bosques (`Forest / External Trust`)

1. **Filtrado de SIDs (*SID Filtering* / *Quarantine*):** durante una migración legítima de dominios, el atributo `sIDHistory` permite que un usuario conserve temporalmente su antiguo SID para no perder acceso a archivos. Sin embargo, entre dos bosques distintos, **SID Filtering debe estar siempre habilitado** para que el Controlador de Dominio descarte cualquier SID en `sIDHistory` que no pertenezca explícitamente al dominio vecino confiable.
2. **Autenticación Selectiva (*Selective Authentication*) frente a *Forest-Wide Authentication*:** con *Forest-Wide Authentication*, todos los usuarios del bosque externo pasan a formar parte automáticamente del grupo `Authenticated Users` del bosque local, pudiendo leer todo el directorio LDAP y cualquier recurso compartido abierto a `Authenticated Users`. Al activar **Selective Authentication**, ningún usuario del bosque vecino puede autenticarse en un servidor local a menos que se le otorgue explícitamente el permiso `Allowed to Authenticate` sobre ese servidor puntual.

## 4. Superficies corporativas integradas: Microsoft SQL Server y SCCM / MECM

En entornos Active Directory reales, dos plataformas empresariales concentran privilegios elevados y deben incluirse siempre en el alcance de auditoría y hardening:

1. **Microsoft SQL Server (MSSQL) integrado al dominio:**
   - **Cuentas de servicio:** cada instancia de SQL Server debe correr bajo una cuenta **gMSA** o cuenta virtual local (`NT Service\MSSQLSERVER`) con privilegios mínimos, nunca bajo una cuenta de administrador del dominio.
   - **Enlaces entre servidores (*Linked Servers*):** auditar `sys.servers` para verificar que ningún enlace hacia otro SQL Server utilice credenciales fijas con rol `sysadmin`.
   - **`xp_cmdshell` y procedimientos extendidos:** verificar en todas las instancias que `xp_cmdshell` permanezca estrictamente deshabilitado (`SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'` → `0`).
2. **Microsoft Endpoint Configuration Manager (SCCM / MECM):**
   - Dado que SCCM despliega software y scripts como `SYSTEM` en todas las estaciones y servidores que administra, **el servidor de sitio de SCCM y su base de datos SQL deben clasificarse como activos de máxima criticidad (Tier 0 o Tier 1 crítico)**.
   - Deshabilitar el uso de **Cuentas de Instalación de Cliente (*Client Push Installation Accounts*)** con privilegios de administrador local global o exigir Kerberos mutuo y firma SMB en todos los puntos de distribución, y eliminar credenciales estáticas de acceso a red (*Network Access Accounts*, NAA) migrando a **Enhanced HTTP / PKI**.

### El puente híbrido: AD On-Premises ↔ Microsoft Entra ID

Cuando un dominio corporativo se sincroniza con la nube mediante **Microsoft Entra ID** (antes Azure AD), la frontera de seguridad ya no termina en el bosque local: un compromiso on-premises puede escalar hacia la identidad en la nube y viceversa. Para auditar y endurecer esta superficie debés controlar tres puntos críticos:

1. **Servidor Microsoft Entra Connect (criticidad Tier 0 obligatoria):** el servidor que ejecuta **Microsoft Entra Connect** (junto con su base de datos local o SQL y la cuenta de conector `MSOL_*` / `AAD_*` en AD) posee permisos de replicación equivalentes a **DCSync** (`DS-Replication-Get-Changes` y `DS-Replication-Get-Changes-All`) cuando utiliza *Password Hash Synchronization* o *Password Writeback*, además de mantener secretos capaces de sincronizar identidades hacia el tenant de Entra ID. Tratalo siempre como **activo estricto de Tier 0** (sin acceso de administradores Tier 1/Tier 2, aislado en red, con `RunAsPPL` y sin cuentas sincronizadas con roles `Global Administrator` en la nube).
2. **Objeto `AZUREADSSOACC` en *Seamless SSO*:** al habilitar *Microsoft Entra Seamless Single Sign-On*, se crea en Active Directory la cuenta de equipo **`AZUREADSSOACC$`** vinculada al SPN `urn:federation:MicrosoftOnline` cuya clave Kerberos se comparte con Entra ID. Si un actor extrae el hash NT o la clave AES de `AZUREADSSOACC$` (por ejemplo tras un DCSync o acceso privilegiado en un DC), puede **forjar tickets TGS (estilo Silver Ticket)** hacia `urn:federation:MicrosoftOnline` para suplantar en la nube a cualquier usuario sincronizado sin conocer su contraseña ni su sesión local. **Remediación:** rotá periódicamente la clave de descifrado de Seamless SSO (con el módulo `AzureADSSO.psd1` / `Update-AzureADSSOForest`), protegé el objeto contra modificaciones no autorizadas y exigí **MFA resistente al phishing** en Entra ID (el ticket forjado de Seamless SSO no elude por sí solo una política robusta de Acceso Condicional con MFA).
3. **Protección de Primary Refresh Tokens (PRT) en endpoints híbridos:** en equipos unidos a dominio híbrido (*Microsoft Entra hybrid joined*), el **PRT** es un artefacto criptográfico emitido por Entra ID que habilita SSO transparente hacia aplicaciones cloud. Aunque la clave de sesión del PRT idealmente queda ligada al **TPM** del equipo, un atacante con ejecución en el contexto del usuario (o privilegios locales `SYSTEM` para extraer cookies/claves en memoria) puede solicitar tokens derivados del PRT (`x-ms-RefreshTokenCredential`) hacia recursos de Microsoft 365. **Defensa:** garantizá hardware con **TPM 2.0** activo, habilitá **Credential Guard / RunAsPPL**, aplicá estrictamente **Tiering** (ninguna cuenta administrativa de Entra ID debe iniciar sesión en estaciones Tier 2) y reforzá las políticas de **Conditional Access** exigiendo cumplimiento de dispositivo (*Device Compliance*) y reautenticación con MFA para acciones sensibles.

## 5. Ejemplo paso a paso: auditoría de plantillas ADCS y Trusts con PowerShell

Este script de verificación defensiva inspecciona por LDAP todas las plantillas de certificados publicadas en el bosque en busca de configuraciones tipo ESC1 (`ENROLLEE_SUPPLIES_SUBJECT = 1`), comprueba el flag global `EditFlags` de la CA y lista las relaciones de confianza del dominio:

```powershell
# 1. Localizar el contenedor de plantillas de certificados en la partición Configuration
$configNC = (Get-ADRootDSE).configurationNamingContext
$templatesDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# 2. Buscar plantillas con el bit CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x1 = 1) activado
#    en el atributo msPKI-Certificate-Name-Flag
Get-ADObject -SearchBase $templatesDN -Filter {objectClass -eq "pKICertificateTemplate"} `
    -Properties cn, displayName, "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", pKIExtendedKeyUsage |
    Where-Object { $_."msPKI-Certificate-Name-Flag" -band 1 } |
    Select-Object displayName, cn, "msPKI-Certificate-Name-Flag", pKIExtendedKeyUsage

# 3. Auditar todas las relaciones de confianza (Trusts) del dominio actual
Get-ADTrust -Filter * |
    Select-Object Name, Direction, TrustType, ForestTransitive, SelectiveAuthentication, SIDFilteringQuarantined
```

## 6. Plan Maestro de Hardening de Active Directory (Lista de Verificación en 10 Puntos)

Para cerrar el **Tomo III**, esta matriz condensa los diez controles de mayor impacto para blindar un entorno Active Directory corporativo:

| # | Pilar de Hardening | Control técnico verificable |
|---|---|---|
| **1** | **Aislamiento de Tier 0 y PAWs** | Separar cuentas y estaciones de administración por niveles (Tier 0, 1 y 2) aplicando GPOs de denegación de logon cruzado y Silos de Autenticación. |
| **2** | **Grupo `Protected Users`** | Incluir al 100 % de las cuentas de Tier 0 (`Domain Admins`, `Enterprise Admins`, `Schema Admins`) en el grupo `Protected Users`. |
| **3** | **Cuentas de servicio gMSA** | Migrar todas las cuentas de servicio con SPN a `gMSA` (120 bytes rotados automáticamente) y forzar cifrado Kerberos AES-256 (`0x12`), deshabilitando RC4 (`0x17`). |
| **4** | **Rotación de `krbtgt`** | Rotar la contraseña de la cuenta `krbtgt` periódicamente (dos rotaciones espaciadas según el tiempo máximo de vida del TGT, mínimo 10–24 horas entre la primera y la segunda) siguiendo el script oficial de Microsoft. |
| **5** | **LAPS (*Windows LAPS*)** | Desplegar **Windows LAPS** en el 100 % de las estaciones de trabajo y servidores miembro para que cada equipo tenga una contraseña de Administrador local única, aleatoria y rotada automáticamente almacenada con cifrado en AD. |
| **6** | **Firma SMB, LDAP y EPA** | Exigir `SMB Signing` en clientes y servidores, `LDAP Signing` + `LDAP Channel Binding` en todos los DCs, y `HTTPS + EPA` en todos los servicios web integrados. |
| **7** | **Endurecimiento de ADCS** | Desactivar `EDITF_ATTRIBUTESUBJECTALTNAME2`, auditar plantillas con `ENROLLEE_SUPPLIES_SUBJECT`, exigir `StrongCertificateBindingEnforcement`, eliminar HTTP Web Enrollment sin EPA y proteger la CA en Tier 0. |
| **8** | **Restricción de creación de máquinas** | Cambiar el atributo del dominio **`ms-DS-MachineAccountQuota`** de su valor por defecto (`10`) a **`0`** para impedir que usuarios no administrativos unan o creen hasta 10 cuentas de máquina arbitrarias en el dominio. |
| **9** | **Higiene de DACLs y Delegación** | Eliminar cualquier servidor con *Unconstrained Delegation*, auditar permisos `WriteDacl`/`GenericAll`/replicación en la raíz del dominio y verificar trusts con `SID Filtering` y `Selective Authentication`. |
| **10** | **Auditoría continua y Telemetría SOC** | Ejecutar mensualmente evaluaciones automatizadas de postura (PingCastle / Purple Knight / BloodHound) y enviar al SIEM los Event IDs `4624`, `4662`, `4720`, `4728/4732/4756`, `4768`, `4769`, `4886/4887`, `5136` y `7045`. |

::: defensa Perspectiva defensiva, detección y mitigación
Ajustar **`ms-DS-MachineAccountQuota = 0`** y desplegar **Windows LAPS** son dos cambios que pueden completarse en una tarde con riesgo operativo mínimo y que eliminan simultáneamente la reutilización de credenciales de administrador local entre estaciones de trabajo y la creación no autorizada de objetos de computadora para abusar de RBCD o certificados de máquina.
:::

## Práctica en laboratorio local

1. Guardá las consultas de la sección 5 en un script `auditar_adcs_y_trusts.ps1` y agregale una consulta que verifique el valor actual de `ms-DS-MachineAccountQuota`:
   `Get-ADDomain | Select-Object Name, @{N="MachineAccountQuota";E={(Get-ADObject $_.DistinguishedName -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"}}`
2. Redactá un documento técnico `plan_hardening_ad_corporativo.md` de una página que ordene los 10 controles del Plan Maestro de Hardening en tres fases de implementación: **Fase 1 (Victorias rápidas en 7 días sin impacto a usuarios)**, **Fase 2 (30 días: firmas SMB/LDAP, LAPS y gMSA)** y **Fase 3 (90 días: Tiering completo, PAWs y Silos de Autenticación)**.

::: practica Entregable mínimo
El script `auditar_adcs_y_trusts.ps1` completo y el documento `plan_hardening_ad_corporativo.md` con la hoja de ruta de implementación en tres fases (7, 30 y 90 días).
:::

## Preguntas de repaso

**1. ¿Por qué un servidor de Autoridad de Certificación (Enterprise CA) de ADCS debe protegerse en el Nivel 0 (Tier 0) con el mismo rigor que un Controlador de Dominio?** Porque los Controladores de Dominio confían en los certificados firmados por la Enterprise CA para autenticar usuarios y máquinas mediante `PKINIT` (Kerberos) o SChannel. Quien tiene control administrativo sobre el servidor de la CA o sus plantillas puede emitir un certificado de autenticación válido para cualquier administrador del dominio.

**2. ¿Qué combinación de cuatro condiciones en una plantilla de certificado de ADCS define la vulnerabilidad clásica `ESC1` y cómo se corrige?** Ocurre cuando la plantilla: (1) permite un EKU de autenticación de cliente, (2) otorga permisos `Enroll` a usuarios o grupos amplios de bajo privilegio, (3) tiene activado el flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (*Supply in the request*, permitiendo especificar un SAN arbitrario) y (4) no exige aprobación del administrador de la CA ni firmas autorizadas. Se corrige desactivando `Supply in the request` (o restringiendo el enrolamiento y exigiendo aprobación manual del CA Manager).

**3. En una relación de confianza unidireccional donde el Dominio A confía en el Dominio B (`A → confía en → B`), ¿en qué sentido fluye el acceso y para qué sirve activar *Selective Authentication*?** El acceso fluye en sentido contrario a la flecha de confianza: los usuarios del **Dominio B** pueden acceder a recursos del **Dominio A** si se les conceden permisos. Activar *Selective Authentication* impide que cualquier usuario del Dominio B sea tratado automáticamente como `Authenticated Users` en todos los equipos del Dominio A, exigiendo otorgar permiso explícito equipo por equipo (`Allowed to Authenticate`).

**4. ¿Qué controla el atributo de dominio `ms-DS-MachineAccountQuota`, cuál es su valor predeterminado en Active Directory y a qué valor debe cambiarse durante el hardening?** Controla cuántas cuentas de equipo (`Computer Objects`) puede crear y unir al dominio cualquier usuario autenticado estándar sin ser administrador. Su valor por defecto histórico es **`10`**, y debe cambiarse a **`0`** para que solo las cuentas o grupos con delegación explícita de soporte puedan dar de alta nuevos objetos de máquina en el directorio.

**5. ¿Por qué la rotación de la contraseña de la cuenta `krbtgt` debe realizarse dos veces consecutivas dejando un intervalo de tiempo entre la primera y la segunda rotación?** Porque el KDC de Active Directory mantiene válidas en memoria tanto la clave actual de `krbtgt` (`N`) como la clave inmediatamente anterior (`N-1`) para no cortar la sesión de los usuarios legítimos cuyos TGTs fueron emitidos minutos antes del cambio. Si solo se rota una vez, un TGT firmado con la clave comprometida sigue siendo aceptado como `N-1`; la segunda rotación reemplaza ambas claves tras expirar el tiempo de vida de los tickets legítimos.

## Antes de avanzar

Verificá que podés:
- Explicar cómo `PKINIT` conecta un certificado X.509 emitido por ADCS con un TGT de Kerberos.
- Auditar y remediar las configuraciones ESC1 a ESC8 en plantillas y servidores de ADCS.
- Configurar y auditar Trusts entre dominios/bosques (`SID Filtering` y `Selective Authentication`).
- Diseñar y priorizar un Plan Maestro de Hardening de Active Directory de 10 puntos.

::: nota Puerta de salida
¡Excelente trabajo! Completaste el **Tomo III · Ruta 3 (Avanzado): Infraestructura, Escalada de Privilegios y Active Directory**. Ahora tenés una visión profunda de cómo se auditan y aseguran servidores Linux, endpoints Windows y dominios corporativos enteros. El siguiente paso dentro de los 7 tomos de la colección es dominar la ingeniería de defensa activa, monitoreo y respuesta a incidentes en el **Tomo IV · Defensivo, SOC, SIEM, DFIR y Detection Engineering** (Capítulo 4.1).
:::

## Referencias y estándares abiertos

- **RFC 4556 (Public Key Cryptography for Initial Authentication in Kerberos — PKINIT):** estándar de autenticación con certificados X.509 en Kerberos.
- **Microsoft Learn — Securing PKI: Planning and Implementing Active Directory Certificate Services Hardening & KB5014754 (Certificate-based authentication changes on Windows domain controllers).**
- **Microsoft Learn — Windows LAPS Overview & Securing Active Directory Trusts (SID Filtering and Selective Authentication).**
- **SpecterOps Whitepaper — Certified Pre-Owned (Abusing and Defending Active Directory Certificate Services):** taxonomía pública de configuraciones ESC1–ESC8 y guía de auditoría defensiva.
