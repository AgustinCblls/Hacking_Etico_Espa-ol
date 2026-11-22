# -*- coding: utf-8 -*-
"""Contenidos de apoyo para Hacking Ético Español:
- Hojas de Referencia Rápida (Cheat Sheets)
- Glosario técnico (65+ términos)
- Guía del Kit de Laboratorios
- Fuentes, Estándares Abiertos y Límites Éticos
"""

CHEAT_SHEETS_HTML = """
<h1 id="hojas-de-referencia-rapida">Hojas de referencia rápida (Cheat Sheets)</h1>
<p>Resumen operativo de escritorio para consultar durante tus prácticas en laboratorio local. Está incluido íntegro en la <strong>Separata de Escritorio PDF</strong> para imprimir aparte y tener a mano.</p>

<h2 id="cs-redes">1. Redes TCP/IP, CIDR y Nmap (Tomo I y II)</h2>
<div class="tabla"><table>
<thead><tr><th>Máscara CIDR</th><th>Máscara decimal</th><th>IPs totales</th><th>Hosts utilizables</th><th>Uso típico en laboratorio</th></tr></thead>
<tbody>
<tr><td><code>/24</code></td><td><code>255.255.255.0</code></td><td>256</td><td>254</td><td>Red LAN / Host-Only estándar</td></tr>
<tr><td><code>/25</code></td><td><code>255.255.255.128</code></td><td>128</td><td>126</td><td>Segmento mediano (DMZ / Lab)</td></tr>
<tr><td><code>/26</code></td><td><code>255.255.255.192</code></td><td>64</td><td>62</td><td>Subred departamental</td></tr>
<tr><td><code>/28</code></td><td><code>255.255.255.240</code></td><td>16</td><td>14</td><td>Subred pequeña de servidores</td></tr>
<tr><td><code>/30</code></td><td><code>255.255.255.252</code></td><td>4</td><td>2</td><td>Enlace punto a punto entre routers</td></tr>
</tbody></table></div>
<pre><code class="lenguaje-bash"># Descubrimiento de hosts en subred de laboratorio (sin escaneo de puertos)
nmap -sn 192.168.56.0/24

# Escaneo TCP SYN rápido de los 1000 puertos más comunes + guardado en 3 formatos
nmap -sS -T4 --open -oA escaneo_inicial 192.168.56.10

# Escaneo completo de puertos TCP + detección de versiones y scripts seguros por defecto
nmap -p- --min-rate 1500 -sV -sC -oA escaneo_completo 192.168.56.10

# Top 50 puertos UDP críticos (DNS 53, SNMP 161, NTP 123, DHCP 67/68)
sudo nmap -sU --top-ports 50 --open 192.168.56.10

# Captura local con tcpdump (filtro BPF por host y puerto)
sudo tcpdump -i eth0 host 192.168.56.10 and port 80 -w captura_lab.pcap</code></pre>

<h2 id="cs-linux-win">2. Auditoría rápida Linux y Windows (Tomo I y III)</h2>
<div class="tabla"><table>
<thead><tr><th>Objetivo de auditoría</th><th>Linux (Bash)</th><th>Windows (PowerShell / CMD)</th></tr></thead>
<tbody>
<tr><td>Identidad y privilegios</td><td><code>id; groups; sudo -l</code></td><td><code>whoami /all</code></td></tr>
<tr><td>Versión del SO / kernel</td><td><code>uname -a; cat /etc/os-release</code></td><td><code>systeminfo | findstr /B /C:"OS"</code></td></tr>
<tr><td>Puertos en escucha local</td><td><code>ss -tulnp</code></td><td><code>netstat -ano</code> / <code>Get-NetTCPConnection</code></td></tr>
<tr><td>Procesos en ejecución</td><td><code>ps auxf</code></td><td><code>Get-Process</code> / <code>tasklist /v</code></td></tr>
<tr><td>Servicios activos</td><td><code>systemctl list-units --type=service --state=running</code></td><td><code>Get-Service | Where Status -eq Running</code></td></tr>
<tr><td>Tareas programadas</td><td><code>crontab -l; ls -la /etc/cron*</code></td><td><code>schtasks /query /fo LIST /v</code></td></tr>
<tr><td>Binarios SUID / Permisos</td><td><code>find / -perm -4000 2&gt;/dev/null</code></td><td><code>icacls "C:\\Ruta\\Servicio"</code></td></tr>
<tr><td>Logs recientes del sistema</td><td><code>journalctl -u ssh -n 50 --no-pager</code></td><td><code>Get-WinEvent -LogName Security -MaxEvents 20</code></td></tr>
</tbody></table></div>

<h2 id="cs-web">3. Seguridad Web, OWASP y Remediación (Tomo II)</h2>
<div class="tabla"><table>
<thead><tr><th>Clase de vulnerabilidad</th><th>Causa raíz típica</th><th>Remediación definitiva (Estándar OWASP)</th></tr></thead>
<tbody>
<tr><td><strong>SQL Injection (SQLi)</strong></td><td>Concatenar entrada del usuario en la cadena SQL.</td><td>Consultas parametrizadas (<em>Prepared Statements</em>) en el 100 % de las queries + mínimo privilegio en BD.</td></tr>
<tr><td><strong>Cross-Site Scripting (XSS)</strong></td><td>Reflejar o almacenar datos no confiables en HTML/JS sin escape contextual.</td><td>Escape automático contextual (Jinja2/React) + cabecera <code>Content-Security-Policy</code> con nonces + cookie <code>HttpOnly</code>.</td></tr>
<tr><td><strong>CSRF</strong></td><td>Confiar únicamente en cookies enviadas automáticamente en peticiones de cambio de estado.</td><td>Cookies con <code>SameSite=Lax</code> o <code>Strict</code> + token anti-CSRF sincronizado por sesión.</td></tr>
<tr><td><strong>IDOR / BOLA</strong></td><td>Usar un ID directo (<code>/ticket/42</code>) sin verificar si pertenece al usuario autenticado.</td><td>Comprobar propiedad en el servidor en cada consulta (<code>WHERE id = ? AND owner_id = ?</code>) + pruebas unitarias de autorización.</td></tr>
<tr><td><strong>SSRF</strong></td><td>Hacer peticiones HTTP desde el backend a URLs arbitrarias provistas por el cliente.</td><td>Lista blanca estricta de esquemas/dominios + bloqueo de rangos privados (<code>127.0.0.0/8</code>, <code>169.254.169.254</code>, RFC 1918).</td></tr>
<tr><td><strong>JWT inseguro</strong></td><td>Aceptar <code>alg: none</code>, claves HMAC débiles o no validar <code>exp</code>/<code>iss</code>/<code>aud</code>.</td><td>Fijar algoritmo explícito en el servidor, rotación de claves largas y expiraciones cortas.</td></tr>
<tr><td><strong>Path Traversal / Upload</strong></td><td>Construir rutas de archivo desde el nombre subido o servir uploads desde webroot.</td><td>Renombrar con UUID, validar tipo MIME real (<em>magic bytes</em>), guardar fuera de webroot y resolver <code>realpath</code> dentro del directorio base.</td></tr>
</tbody></table></div>
<pre><code class="lenguaje-bash"># Enumeración controlada de rutas en laboratorio local con ffuf
ffuf -u http://127.0.0.1:5050/FUZZ -w wordlist_comun.txt -fc 404 -t 20

# Inspección de cabeceras de seguridad HTTP con curl
curl -sI http://127.0.0.1:5050/saludo-seguro</code></pre>

<h2 id="cs-ad">4. Active Directory: Enumeración, Vectores y Hardening (Tomo III)</h2>
<div class="tabla"><table>
<thead><tr><th>Vector / Riesgo en AD</th><th>Condición vulnerable</th><th>Telemetría clave (Event IDs)</th><th>Hardening obligatorio</th></tr></thead>
<tbody>
<tr><td><strong>AS-REP Roasting</strong></td><td>Cuentas con <code>DONT_REQ_PREAUTH</code> activado.</td><td><code>4768</code> (TGT sin pre-auth, cifrado <code>0x17</code> RC4).</td><td>Deshabilitar <code>Do not require Kerberos preauthentication</code> en todos los usuarios.</td></tr>
<tr><td><strong>Kerberoasting</strong></td><td>Cuentas de servicio humanas con SPN y contraseña débil/RC4.</td><td><code>4769</code> (TGS con Ticket Encryption Type <code>0x17</code>).</td><td>Migrar a <strong>gMSA</strong> (contraseñas rotadas automáticamente de 120 bytes) y forzar AES256.</td></tr>
<tr><td><strong>NTLM Relay</strong></td><td>SMB Signing deshabilitado o LDAP/HTTP ADCS sin EPA/Channel Binding.</td><td><code>4624</code>/<code>4776</code> NTLM anómalos entre hosts.</td><td>Habilitar <strong>SMB Signing</strong>, <strong>LDAP Signing + Channel Binding</strong> y <strong>EPA</strong>; deshabilitar NTLMv1.</td></tr>
<tr><td><strong>Abuso de DACL / ACL</strong></td><td>Permisos <code>GenericAll</code>, <code>WriteDacl</code>, <code>WriteOwner</code> delegados a grupos amplios.</td><td><code>5136</code> (modificación de objeto AD) / <code>4662</code>.</td><td>Auditar grafos de privilegio (BloodHound/PingCastle) y aplicar modelo <strong>Tier 0/1/2</strong>.</td></tr>
<tr><td><strong>DCSync</strong></td><td>Cuentas no-DC con <code>DS-Replication-Get-Changes-All</code>.</td><td><code>4662</code> sobre el objeto dominio desde IP no-DC.</td><td>Restringir replicación estrictamente a Controladores de Dominio y monitorear cambios en ACLs del dominio.</td></tr>
<tr><td><strong>ADCS (ESC1 / ESC8)</strong></td><td>Plantillas con <code>ENROLLEE_SUPPLIES_SUBJECT</code> + enrolamiento abierto, o Web Enrollment HTTP sin EPA.</td><td><code>4886</code> / <code>4887</code> (emisión de certificados).</td><td>Desactivar SAN arbitrario, exigir aprobación de CA Manager y deshabilitar HTTP Web Enrollment o forzar HTTPS+EPA.</td></tr>
</tbody></table></div>
<pre><code class="lenguaje-bash"># Búsqueda e inspección segura de PoCs públicos + compilación cruzada en laboratorio (Cap. 3.1)
searchsploit -t "Apache 2.4"
searchsploit -x 12345
x86_64-w64-mingw32-gcc poc_lab.c -o poc_win64.exe -lws2_32

# Movimiento lateral y auditoría de secretos en laboratorio AD (Cap. 3.5 y 3.7)
impacket-wmiexec DOMINIO/admin_lab@10.10.20.30 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0
impacket-secretsdump DOMINIO/admin_local:PasswordLab@10.10.20.30
pypykatz lsa minidump /ruta/lab/lsass_dump.dmp</code></pre>

<h2 id="cs-soc">5. SOC, Sysmon, SPL/KQL, Suricata, Sigma y YARA (Tomo IV)</h2>
<div class="tabla"><table>
<thead><tr><th>Fuente / Event ID</th><th>Qué registra</th><th>Señal típica de investigación en SOC</th></tr></thead>
<tbody>
<tr><td><strong>Security 4624 / 4625</strong></td><td>Inicio de sesión exitoso / fallido (Logon Types: 2 Interactivo, 3 Red, 10 RDP).</td><td>Picos de <code>4625</code> seguidos de <code>4624</code> desde la misma IP (password spraying / fuerza bruta).</td></tr>
<tr><td><strong>Security 4688 / Sysmon 1</strong></td><td>Creación de proceso (incluyendo <code>ParentImage</code> y <code>CommandLine</code>).</td><td><code>winword.exe</code> o <code>w3wp.exe</code> lanzando <code>cmd.exe</code> / <code>powershell.exe</code>.</td></tr>
<tr><td><strong>PowerShell 4104</strong></td><td>Script Block Logging (código completo ya desofuscado en memoria).</td><td><code>FromBase64String</code>, <code>IEX</code>, descargas remotas o desactivación de defensas.</td></tr>
<tr><td><strong>Sysmon 3 / 22</strong></td><td>Conexión de red saliente / Consulta DNS asociada al proceso exacto.</td><td>LOLBins (<code>certutil</code>, <code>mshta</code>, <code>rundll32</code>) iniciando conexiones externas.</td></tr>
<tr><td><strong>Sysmon 8 / 10</strong></td><td><code>CreateRemoteThread</code> / <code>ProcessAccess</code> entre procesos.</td><td>Acceso de lectura de memoria hacia <code>lsass.exe</code> desde un binario no autorizado.</td></tr>
<tr><td><strong>Security 7045 / Sysmon 13</strong></td><td>Instalación de nuevo servicio / Modificación de claves de Registro.</td><td>Nuevos servicios con rutas en <code>C:\\Users\\Public</code> o cambios en claves <code>Run</code>.</td></tr>
</tbody></table></div>
<pre><code class="lenguaje-text"># Consulta rápida Splunk (SPL) — Top IPs con más de 10 fallos 4625 en 15 min
index=windows EventCode=4625 | stats count dc(TargetUserName) as usuarios by IpAddress | where count &gt; 10 | sort - count

# Consulta rápida Elastic (KQL) — PowerShell codificado lanzado por aplicaciones de Office
event.code: "1" and process.name: ("powershell.exe" or "pwsh.exe") and process.parent.name: ("winword.exe" or "excel.exe")

# Regla Suricata didáctica — Detectar User-Agent de prueba en HTTP interno
alert http $HOME_NET any -&gt; any any (msg:"LAB SEC User-Agent de Auditoria Detectado"; flow:to_server,established; http.user_agent; content:"Lab-Audit-Probe"; sid:9000001; rev:1;)</code></pre>

<h2 id="cs-cripto">6. Criptografía Aplicada, Certificados X.509 y OpenSSL (Cap. 1.9)</h2>
<div class="tabla"><table>
<thead><tr><th>Necesidad de seguridad</th><th>Algoritmo / Estándar recomendado</th><th>Qué evitar siempre</th></tr></thead>
<tbody>
<tr><td><strong>Cifrado simétrico</strong></td><td><code>AES-256-GCM</code> o <code>ChaCha20-Poly1305</code> (AEAD)</td><td><code>AES-ECB</code>, <code>DES/3DES</code>, <code>RC4</code> o <code>CBC</code> sin MAC</td></tr>
<tr><td><strong>Integridad y autenticidad</strong></td><td><code>HMAC-SHA256</code> (comparar con <code>hmac.compare_digest</code>)</td><td>Hash plano sin clave secreta o comparación con <code>==</code></td></tr>
<tr><td><strong>Hashing de contraseñas</strong></td><td><code>Argon2id</code> (o <code>bcrypt</code>/<code>scrypt</code> con salt único)</td><td><code>MD5</code>, <code>SHA-1</code>, <code>SHA-256</code> directo sin factor de costo</td></tr>
<tr><td><strong>Firmas digitales e intercambio</strong></td><td><code>Ed25519</code>, <code>ECDSA P-256</code>, <code>RSA-PSS ≥ 2048</code>, <code>ECDHE</code></td><td>Claves RSA &lt; 2048 bits, curvas débiles, TLS sin PFS</td></tr>
<tr><td><strong>Protocolo TLS</strong></td><td><strong>TLS 1.3</strong> y <strong>TLS 1.2</strong> con suites AEAD + <code>ECDHE</code></td><td><code>SSLv2</code>, <code>SSLv3</code>, <code>TLS 1.0</code>, <code>TLS 1.1</code></td></tr>
</tbody></table></div>
<pre><code class="lenguaje-bash"># Inspeccionar campos críticos (Emisor, Validez, SAN) de un certificado PEM local
openssl x509 -in cert.pem -noout -subject -issuer -dates -ext subjectAltName

# Verificar conexión TLS 1.3 y cadena de certificados contra un servicio local
openssl s_client -connect 127.0.0.1:8443 -tls1_3 -showcerts &lt;/dev/null

# Calcular hash SHA-256 de integridad sobre un artefacto o evidencia DFIR
sha256sum evidencia.raw</code></pre>

<h2 id="cs-cloud">7. Cloud, Contenedores, Kubernetes y DevSecOps (Tomo V)</h2>
<div class="tabla"><table>
<thead><tr><th>Área Cloud / Contenedores</th><th>Control o comando clave de auditoría / hardening</th><th>Qué previene</th></tr></thead>
<tbody>
<tr><td><strong>IMDSv2 en AWS EC2</strong></td><td>Exigir <code>HttpTokens: required</code> y <code>HttpPutResponseHopLimit: 1</code></td><td>Robo de credenciales de rol IAM mediante SSRF o desde contenedores internos.</td></tr>
<tr><td><strong>Docker rootless y mínimo</strong></td><td><code>docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges:true</code></td><td>Escalada local y persistencia en contenedor tras vulnerabilidad en la aplicación.</td></tr>
<tr><td><strong>Kubernetes Pod Security</strong></td><td>Perfil <code>restricted</code>, <code>runAsNonRoot: true</code>, <code>automountServiceAccountToken: false</code></td><td>Abuso de tokens de API, montaje <code>hostPath</code> y escapes hacia el nodo.</td></tr>
<tr><td><strong>CI/CD y Secretos</strong></td><td><code>gitleaks detect</code>, <code>trivy config .</code>, <code>semgrep --config auto</code>, OIDC sin llaves</td><td>Fuga de secretos en Git, misconfigurations IaC e inyección en workflows.</td></tr>
</tbody></table></div>
<pre><code class="lenguaje-bash"># Auditar configuraciones IaC (Terraform/Dockerfile/YAML K8s) localmente con Trivy
trivy config ./laboratorios/

# Revisar permisos efectivos actuales en Kubernetes antes de desplegar un Pod
kubectl auth can-i --list -n laboratorio-seguro

# Verificar si el socket de Docker está montado indebidamente dentro de un contenedor
ls -la /var/run/docker.sock 2&gt;/dev/null</code></pre>

<h2 id="cs-ofensiva-av">8. Web Avanzado, Code Review, Threat Modeling y OPSEC (Tomo VI)</h2>
<div class="tabla"><table>
<thead><tr><th>Disciplina</th><th>Vector o patrón de evaluación</th><th>Contramedida estructural / Detección</th></tr></thead>
<tbody>
<tr><td><strong>Race Conditions HTTP/2</strong></td><td>Sincronización <em>single-packet</em> sobre operaciones con saldo o cupones.</td><td>Bloqueo transaccional atómico (<code>SELECT ... FOR UPDATE</code>) o llaves de idempotencia.</td></tr>
<tr><td><strong>Web Cache Poisoning / Deception</strong></td><td>Cabeceras no indexadas (<code>X-Forwarded-Host</code>) o sufijos estáticos (<code>/cuenta/x.css</code>).</td><td>Separar respuestas privadas con <code>Cache-Control: private, no-store</code> y validar encabezados.</td></tr>
<tr><td><strong>Threat Modeling (STRIDE)</strong></td><td>Mapear entidades, flujos y fronteras de confianza en DFD.</td><td>Traducir cada amenaza a un control verificable <strong>OWASP ASVS</strong> antes del desarrollo.</td></tr>
<tr><td><strong>White-Box (Source → Sink)</strong></td><td>Seguir entradas HTTP hasta <code>eval</code>, SQL, deserialización o shell.</td><td>Validación por esquema + APIs seguras + reglas SAST continuas en CI.</td></tr>
<tr><td><strong>OPSEC / AMSI / ETW</strong></td><td>Comandos ruidosos LOLBAS, <em>PPID Spoofing</em>, anomalías <em>Call Stack</em>.</td><td>Sysmon (IDs 1, 8, 10, 25), ETW-TI desde kernel y bloqueo ASR/WDAC.</td></tr>
</tbody></table></div>
<pre><code class="lenguaje-bash"># Auditoría estática White-Box AST en laboratorio Python (Cap. 2.7 y 6.4)
python laboratorios/auditor_whitebox_codereview.py ./laboratorios/

# Escaneo SAST multiproyecto con Semgrep usando reglas comunitarias
semgrep --config auto ./mi_proyecto_lab/</code></pre>

<h2 id="cs-mobile-wifi-grc">9. Mobile, Wi-Fi, Hardware/OT y GRC (Tomo VII)</h2>
<div class="tabla"><table>
<thead><tr><th>Dominio</th><th>Herramienta / Marco de referencia</th><th>Control o verificación esencial</th></tr></thead>
<tbody>
<tr><td><strong>Android (OWASP MASTG)</strong></td><td><code>jadx</code>, <code>apktool</code>, <code>adb</code>, <code>Frida</code>, MobSF</td><td>Revisar <code>android:exported="true"</code>, <code>allowBackup</code>, WebViews y pinning TLS.</td></tr>
<tr><td><strong>Wi-Fi (802.11 / WPA3)</strong></td><td><code>airodump-ng</code>, <code>hcxdumptool</code>, <code>hashcat -m 22000</code></td><td>Desactivar WEP/WPS, habilitar WPA3-SAE o <code>EAP-TLS</code> con validación RADIUS y PMF (<code>802.11w</code>).</td></tr>
<tr><td><strong>Física / Hardware / IoT</strong></td><td>BitLocker+PIN / LUKS2, IOMMU, <code>binwalk</code></td><td>Bloquear DMA Thunderbolt, deshabilitar UART/JTAG en producción y auditar firmware.</td></tr>
<tr><td><strong>OT / ICS / SCADA</strong></td><td>Modelo Purdue (IEC 62443), Modbus TCP (502), OPC UA</td><td>Aislar con DMZ (Nivel 3.5), monitoreo pasivo sin escaneo activo y <em>Data Diodes</em>.</td></tr>
<tr><td><strong>GRC y Cumplimiento</strong></td><td>RoE, ISO/IEC 27001, NIST CSF 2.0, PCI-DSS v4, GDPR</td><td>Autorización escrita previa, matriz ALE/SLE, notificación de brechas (72 h GDPR).</td></tr>
</tbody></table></div>
<pre><code class="lenguaje-bash"># Descompilar un APK de prueba en laboratorio e inspeccionar firmware embebido
jadx -d ./salida_apk/ muestra_lab.apk
binwalk -e firmware_lab.bin</code></pre>
"""

GLOSARIO_ITEMS = [
    ("ACL / DACL", "Access Control List / Discretionary ACL. Lista de entradas de control de acceso que define qué usuarios o grupos tienen permisos (lectura, escritura, control total) sobre un archivo NTFS, servicio u objeto de Active Directory."),
    ("ADCS", "Active Directory Certificate Services. Infraestructura de clave pública (PKI) de Microsoft integrada en AD que emite certificados digitales; una mala configuración en sus plantillas (ESC1–ESC8) puede permitir escalada a Domain Admin."),
    ("AEAD", "Authenticated Encryption with Associated Data. Familia de modos criptográficos modernos (AES-GCM, ChaCha20-Poly1305) que garantizan confidencialidad, integridad y autenticidad en una sola operación."),
    ("AES-GCM", "Modo Galois/Counter Mode para AES; estándar AEAD de alto rendimiento que cifra datos y genera una etiqueta criptográfica de autenticación (requiere no repetir nunca la pareja Clave + Nonce)."),
    ("AMSI", "Antimalware Scan Interface. Interfaz de Windows que permite a motores de scripting (PowerShell, WSH, .NET) enviar contenido dinámico ya desofuscado al antivirus/EDR antes de ejecutarlo."),
    ("ARP", "Address Resolution Protocol. Protocolo de capa 2/3 que traduce una dirección IPv4 a su dirección física MAC dentro de un mismo segmento de red local."),
    ("AS-REP Roasting", "Técnica de auditoría en Kerberos contra cuentas que tienen deshabilitada la preautenticación; permite solicitar un bloque cifrado con el hash del usuario para evaluar la fortaleza de su contraseña offline."),
    ("ATT&CK (MITRE)", "Base de conocimiento abierta de tácticas, técnicas y procedimientos (TTPs) observados en intrusiones reales, usada por Red Teams y SOCs para mapear detecciones y brechas de visibilidad."),
    ("auditd", "Demonio de auditoría del kernel de Linux que registra llamadas al sistema, accesos a archivos críticos, cambios de privilegios y ejecuciones de comandos para monitoreo defensivo y DFIR."),
    ("BFLA / BOLA", "Broken Function Level Authorization / Broken Object Level Authorization. Fallos críticos de OWASP API Top 10 donde un usuario accede a funciones administrativas o a objetos de otro usuario cambiando identificadores."),
    ("BloodHound", "Herramienta basada en teoría de grafos que mapea relaciones de permisos, sesiones y membresías en Active Directory para identificar rutas de escalada y planificar su remediación."),
    ("Capabilities (Linux)", "Mecanismo del kernel de Linux que divide los privilegios de root en permisos granulares (como cap_net_bind_service o cap_setuid) asignables a binarios específicos."),
    ("CIDR", "Classless Inter-Domain Routing. Notación de subredes (ej. 192.168.56.0/24) que indica cuántos bits corresponden a la porción de red y cuántos a los hosts."),
    ("CIM / ECS", "Common Information Model (Splunk) y Elastic Common Schema (Elastic). Esquemas de normalización de campos que permiten correlacionar logs heterogéneos (firewall, Windows, Linux) bajo nombres uniformes."),
    ("CORS", "Cross-Origin Resource Sharing. Mecanismo basado en cabeceras HTTP que relaja controladamente la política del mismo origen (SOP) para permitir peticiones entre distintos dominios."),
    ("CSP", "Content Security Policy. Cabecera HTTP defensiva que restringe qué orígenes de scripts, estilos, imágenes y marcos puede cargar el navegador, mitigando el impacto de XSS."),
    ("CSRF", "Cross-Site Request Forgery. Vulnerabilidad web que induce al navegador de un usuario autenticado a enviar una petición no deseada aprovechando que las cookies se adjuntan automáticamente."),
    ("CTI", "Cyber Threat Intelligence. Recolección, análisis y contextualización de información sobre amenazas, campañas, TTPs e indicadores (IOCs) para apoyar decisiones defensivas."),
    ("CVSS / EPSS", "Common Vulnerability Scoring System (mide severidad técnica intrínseca 0–10) y Exploit Prediction Scoring System (estima probabilidad estadística de explotación activa en los próximos 30 días)."),
    ("DCSync", "Técnica que abusa de los permisos de replicación de Active Directory (MS-DRSR) para solicitar hashes de credenciales a un Controlador de Dominio simulando ser otro DC."),
    ("Defanging", "Práctica segura en SOC/CTI de desactivar URLs o IPs sospechosas al documentarlas (ej. hxxp://ejemplo[.]invalid) para evitar clics accidentales."),
    ("Detection-as-Code", "Práctica de ingeniería que gestiona reglas de detección (Sigma, YARA, Suricata, SPL) con control de versiones Git, revisiones de pares y pruebas automatizadas."),
    ("DFIR", "Digital Forensics and Incident Response. Disciplina que combina la respuesta y contención ante incidentes con la preservación y análisis forense de evidencia en disco, memoria y red."),
    ("DLL Hijacking", "Debilidad en Windows donde una aplicación carga una biblioteca DLL mal ubicada aprovechando el orden de búsqueda de directorios cuando existen permisos de escritura inadecuados."),
    ("DNS", "Domain Name System. Sistema jerárquico distribuido que traduce nombres de dominio a direcciones IP y almacena registros de correo (MX, SPF, DKIM, DMARC) y servicios (SRV en AD)."),
    ("EPA", "Extended Protection for Authentication. Mecanismo de seguridad en Windows que vincula la autenticación NTLM/Kerberos al canal TLS externo para prevenir ataques de relay."),
    ("ETW", "Event Tracing for Windows. Subsistema nativo de telemetría de alto rendimiento integrado en el kernel y user mode de Windows, clave para EDRs y análisis de comportamiento."),
    ("EVTX", "Formato binario XML de los registros de eventos modernos de Windows ubicados en C:\\Windows\\System32\\winevt\\Logs\\."),
    ("Falso Positivo (FP)", "Alerta disparada por un SIEM o IDS ante actividad legítima y benigna. Reducir falsos positivos mediante afinado es esencial para evitar fatiga de alertas en el SOC."),
    ("Forward Secrecy (PFS)", "Propiedad de intercambio de claves efímero (ECDHE) en TLS 1.2/1.3 que impide descifrar tráfico capturado en el pasado aunque la clave privada del servidor sea comprometida en el futuro."),
    ("Fuzzing Web", "Técnica automatizada de enviar listas controladas de rutas, vhosts o parámetros contra una aplicación autorizada (ej. con ffuf) para descubrir superficie expuesta o comportamientos anómalos."),
    ("gMSA", "Group Managed Service Account. Cuenta de servicio de Active Directory cuya contraseña de 120 bytes es gestionada y rotada automáticamente por el dominio, eliminando el riesgo de Kerberoasting."),
    ("GPO", "Group Policy Object. Objeto de configuración centralizada en Active Directory que aplica políticas de seguridad, scripts y configuraciones a equipos y usuarios de una OU."),
    ("GraphQL", "Lenguaje de consulta para APIs que expone un esquema tipado en un único endpoint; requiere controles explícitos de autorización por resolver, límite de profundidad y desactivación de introspección en producción."),
    ("Hardening", "Proceso sistemático de reducir la superficie de ataque de un sistema operativo, aplicación o dominio eliminando servicios innecesarios, aplicando mínimo privilegio y fortaleciendo configuraciones."),
    ("Hash (Criptográfico)", "Función matemática unidireccional de tamaño fijo (ej. SHA-256) usada para verificar integridad de archivos y evidencias. Para contraseñas se requieren KDF lentos con salt como Argon2id."),
    ("HMAC", "Hash-based Message Authentication Code (RFC 2104). Código de autenticación calculado con un hash y una clave secreta compartida para verificar integridad y autenticidad sin cifrar el contenido."),
    ("HttpOnly / SameSite", "Atributos defensivos de cookies: HttpOnly impide leer la cookie desde JavaScript (mitiga robo por XSS); SameSite controla su envío en peticiones entre sitios (mitiga CSRF)."),
    ("IDOR", "Insecure Direct Object Reference. Subtipo clásico de fallo de autorización donde modificar un identificador visible permite acceder a recursos pertenecientes a otro usuario."),
    ("IDS / IPS", "Intrusion Detection System (monitorea y alerta tráfico anómalo en pasivo) e Intrusion Prevention System (opera en línea y puede bloquear tráfico malicioso, ej. Suricata)."),
    ("IOC", "Indicator of Compromise. Artefacto observable (hash SHA-256, IP, dominio, clave de registro) que sugiere una posible intrusión. Ocupa la base de la Pirámide del Dolor por ser fácil de cambiar."),
    ("JWT", "JSON Web Token. Estándar abierto (RFC 7519) para transmitir claims firmados (header.payload.signature) usado en autenticación stateless y OAuth/OIDC."),
    ("Kerberoasting", "Técnica de auditoría en AD que solicita tickets de servicio (TGS) para cuentas con SPN registrado; si la cuenta usa cifrado débil o contraseña corta, puede exponerse offline."),
    ("Kerberos", "Protocolo de autenticación mutua basado en tickets (TGT y TGS) emitidos por el Key Distribution Center (KDC) en Active Directory, diseñado para evitar enviar contraseñas por la red."),
    ("KQL / SPL", "Kibana Query Language (Elastic) y Search Processing Language (Splunk). Lenguajes de consulta usados por analistas SOC e ingenieros de detección para investigar eventos en el SIEM."),
    ("LDAP / LDAPS", "Lightweight Directory Access Protocol (389) y su variante cifrada sobre TLS (636). Protocolo estándar para consultar y administrar objetos en Active Directory."),
    ("LFI / Path Traversal", "Local File Inclusion / Traversal de rutas. Debilidad donde una entrada no saneada con secuencias como ../ permite leer archivos del sistema fuera del directorio previsto."),
    ("LOLBins", "Living-off-the-Land Binaries. Herramientas legítimas y firmadas del propio sistema operativo (como certutil, powershell, mshta o curl) que los atacantes reutilizan para pasar desapercibidos."),
    ("MFT ($MFT)", "Master File Table. Estructura central del sistema de archivos NTFS que registra metadatos, permisos y marcas temporales (timestamps) de todos los archivos del volumen; vital en DFIR."),
    ("MTTD / MTTR", "Mean Time to Detect (tiempo medio de detección) y Mean Time to Respond/Recover (tiempo medio de respuesta/contención). Métricas operativas clave de eficacia de un SOC."),
    ("NSM", "Network Security Monitoring. Recolección, análisis y correlación continua de datos de red (PCAP, NetFlow, Zeek, IDS) para detectar y responder a intrusiones."),
    ("NTLM Relay", "Técnica de intermediación donde una autenticación NetNTLM entrante se reenvía en tiempo real a otro servidor de la red que no exige firma (SMB/LDAP Signing) ni EPA."),
    ("OWASP WSTG / ASVS", "Web Security Testing Guide (metodología de pruebas web) y Application Security Verification Standard (requisitos verificables de arquitectura y código seguro)."),
    ("PCAP", "Packet Capture. Formato de archivo estándar generado por tcpdump o Wireshark que almacena tráfico de red completo para análisis técnico y forense."),
    ("PKI / Certificado X.509", "Public Key Infrastructure. Sistema de Autoridades de Certificación (CA) que firman certificados digitales X.509 v3 (RFC 5280) vinculando identidades DNS o usuarios con sus claves públicas."),
    ("Pirámide del Dolor", "Modelo de David Bianco que clasifica los indicadores de menor a mayor dificultad de reemplazo para un adversario: Hashes → IPs → Dominios → Artefactos → Herramientas → TTPs."),
    ("Pivoting", "Técnica de enrutar tráfico autorizado de auditoría a través de un host intermedio en un laboratorio segmentado (mediante túneles SSH o SOCKS5) para alcanzar una subred interna."),
    ("Prefetch / ShimCache", "Artefactos nativos de Windows que registran evidencia histórica de programas ejecutados en el equipo, esenciales en investigaciones DFIR incluso si el binario fue borrado."),
    ("Protected Users", "Grupo de seguridad de Active Directory que endurece cuentas privilegiadas bloqueando NTLM, deshabilitando delegación y reduciendo el tiempo de vida de tickets Kerberos."),
    ("RBCD", "Resource-Based Constrained Delegation. Mecanismo de delegación Kerberos configurado en el recurso destino (msDS-AllowedToActOnBehalfOfOtherIdentity) que debe auditarse estrictamente."),
    ("RoE (Rules of Engagement)", "Documento contractual y técnico previo a una auditoría que fija alcance exacto (IPs/dominios), ventanas horarias, contactos de emergencia y límites estrictos."),
    ("SAN (Subject Alternative Name)", "Extensión estándar X.509 que enumera los nombres DNS, IPs o UPNs válidos para un certificado digital TLS o PKINIT."),
    ("SIEM", "Security Information and Event Management. Plataforma centralizada (como Splunk o Elastic Security) que recopila, normaliza, almacena y correlaciona logs para generar alertas SOC."),
    ("Sigma", "Formato abierto y agnóstico basado en YAML para describir reglas de detección sobre logs, convertible automáticamente a consultas de múltiples SIEMs (SPL, KQL, Sentinel)."),
    ("SMB Signing", "Mecanismo criptográfico del protocolo SMB que firma cada paquete para garantizar integridad y autenticidad, bloqueando ataques de NTLM Relay hacia SMB."),
    ("Snapshot", "Instantánea del estado de disco y configuración de una máquina virtual en un instante dado, permitiendo volver a un entorno limpio en segundos."),
    ("SPF / DKIM / DMARC", "Estándares de autenticación de correo electrónico: SPF valida IPs autorizadas por DNS, DKIM firma criptográficamente el mensaje y DMARC exige alineación del dominio visible From."),
    ("SPN", "Service Principal Name. Identificador único de una instancia de servicio registrado en una cuenta de Active Directory para asociarlo a tickets Kerberos."),
    ("SQL Injection (SQLi)", "Vulnerabilidad crítica causada por concatenar datos de usuario en sentencias SQL sin parametrización, permitiendo alterar la lógica de la consulta o extraer datos."),
    ("SSRF", "Server-Side Request Forgery. Fallo donde el servidor realiza peticiones de red hacia destinos internos o externos controlados por el atacante."),
    ("SSTI", "Server-Side Template Injection. Vulnerabilidad que ocurre al incrustar entrada no confiable directamente como plantilla en motores como Jinja2 o Twig en lugar de pasarla como variable."),
    ("SUID / SGID", "Bits especiales de permisos en Unix/Linux que ejecutan un binario con los privilegios efectivos de su propietario (usualmente root) o grupo."),
    ("Sysmon", "System Monitor (Microsoft Sysinternals). Servicio y driver del sistema que enriquece Windows Event Log con telemetría detallada de procesos, red, DLLs, acceso a procesos y DNS."),
    ("Threat Hunting", "Búsqueda proactiva y guiada por hipótesis de amenazas ocultas o TTPs no detectados aún por las alertas automáticas del SOC."),
    ("Tiering (Tier 0/1/2)", "Modelo de administración segregada de Active Directory que impide iniciar sesión con credenciales de Tier 0 (Domain Admins/DCs) en servidores (Tier 1) o estaciones de trabajo (Tier 2)."),
    ("Timestomping", "Alteración deliberada de marcas temporales de un archivo en disco ($STANDARD_INFORMATION), detectable comparándolas contra $FILE_NAME, $UsnJrnl y Prefetch."),
    ("Volatility 3", "Framework abierto en Python para el análisis forense de volcados de memoria RAM (procesos ocultos, sockets, DLLs inyectadas y artefactos volátiles)."),
    ("XSS", "Cross-Site Scripting. Vulnerabilidad web que permite inyectar y ejecutar JavaScript no autorizado en el contexto del navegador de la víctima."),
    ("XXE", "XML External Entity. Fallo en parsers XML mal configurados que resuelven entidades externas DTD, permitiendo lectura de archivos locales o SSRF."),
    ("YARA", "Herramienta y lenguaje de reglas basadas en patrones de texto/hexadecimal y condiciones lógicas utilizado para clasificar archivos y realizar triage estático de malware."),
    ("Zeek", "Monitor de análisis de red de código abierto que transforma tráfico de red en logs estructurados de alto nivel (conn.log, dns.log, http.log, ssl.log) ideales para hunting y SIEM."),
    ("802.1X / EAP-TLS", "Estándar de control de acceso a red cableada e inalámbrica basado en RADIUS; EAP-TLS exige autenticación mutua mediante certificados digitales tanto del servidor como del cliente."),
    ("Bucket Policy / Public Access Block", "Controles de autorización sobre almacenamiento en la nube (como AWS S3) que definen quién puede leer o escribir objetos y bloquean exposiciones públicas accidentales."),
    ("Container Escape", "Fallo de aislamiento (por --privileged, capacidades excesivas o montaje de docker.sock) que permite salir del namespace del contenedor y tomar control del sistema anfitrión."),
    ("CSWSH", "Cross-Site WebSocket Hijacking. Variante de CSRF aplicada sobre el handshake inicial Upgrade: websocket cuando el servidor no valida la cabecera Origin ni tokens anti-CSRF."),
    ("Data Diode", "Dispositivo o enlace físico unidireccional usado en entornos OT/SCADA críticos para exportar telemetría hacia redes corporativas sin permitir jamás tráfico de retorno hacia planta."),
    ("DOM Clobbering", "Técnica web que inyecta elementos HTML con atributos id o name para sobrescribir variables globales esperadas por scripts del cliente y alterar su flujo de ejecución."),
    ("Entra ID", "Servicio de identidad y acceso en la nube de Microsoft (antes Azure AD) que gestiona usuarios híbridos, Service Principals, tokens OIDC/OAuth y políticas de Acceso Condicional."),
    ("Frida", "Toolkit de instrumentación dinámica multiplataforma usado en pruebas móviles autorizadas (Android/iOS) para inspeccionar llamadas en memoria, WebViews y validaciones TLS en emulador."),
    ("GRC", "Governance, Risk and Compliance. Disciplina que alinea la ciberseguridad con los objetivos del negocio, la cuantificación de riesgos (SLE/ALE) y marcos como ISO 27001, NIST CSF 2.0 y GDPR."),
    ("IMDSv2", "Instance Metadata Service v2 en AWS; sustituye peticiones GET simples de metadatos por un flujo con token de sesión PUT y límite de saltos (hop-limit 1) para mitigar SSRF hacia credenciales IAM."),
    ("IOMMU / Kernel DMA Protection", "Mecanismo de hardware y sistema operativo que aísla la memoria frente a dispositivos PCIe/Thunderbolt conectados físicamente, bloqueando ataques DMA en frío."),
    ("ISO/IEC 27001", "Estándar internacional de referencia para diseñar, operar y auditar un Sistema de Gestión de Seguridad de la Información (SGSI) basado en riesgos y controles del Anexo A."),
    ("Modbus / DNP3 / OPC UA", "Protocolos industriales OT/SCADA; Modbus y DNP3 clásicos carecen de cifrado y autenticación nativa, por lo que exigen segmentación estricta y monitoreo pasivo."),
    ("Modelo Purdue (ISA-95)", "Arquitectura jerárquica de referencia (Niveles 0 a 5 más DMZ Industrial en 3.5) para segmentar maquinaria física OT respecto de la red corporativa IT."),
    ("Namespaces y cgroups", "Primitivas del kernel Linux sobre las que funcionan los contenedores: namespaces aíslan qué ve cada proceso (PID, red, montajes) y cgroups limitan los recursos físicos que consume."),
    ("NetworkPolicy (Kubernetes)", "Recurso declarativo de Kubernetes que actúa como firewall de capa 3/4 entre Pods y namespaces; sin él, todo el tráfico interno del clúster suele estar permitido por defecto."),
    ("NIST CSF 2.0", "Cybersecurity Framework del NIST estructurado en seis funciones continuas: Govern, Identify, Protect, Detect, Respond y Recover."),
    ("OAuth 2.0 / PKCE", "Protocolo estándar de autorización delegada; PKCE (Proof Key for Code Exchange) protege el flujo Authorization Code contra intercepción del código de autorización en apps web y móviles."),
    ("OPSEC", "Operations Security. Disciplina de minimizar la huella operativa y telemétrica (comandos ruidosos, artefactos en disco, horarios anómalos) durante ejercicios autorizados de Red Team."),
    ("OWASP MASTG", "Mobile Application Security Testing Guide. Guía técnica abierta para auditar aplicaciones Android e iOS de forma estática y dinámica."),
    ("PASTA", "Process for Attack Simulation and Threat Analysis. Metodología de modelado de amenazas en siete etapas centrada en el riesgo real del negocio y la validación de ataques plausibles."),
    ("PMKID", "Identificador derivado en el primer paquete EAPOL del handshake WPA/WPA2; su captura en APs vulnerables permite evaluar la robustez de la contraseña offline sin esperar un cliente conectado."),
    ("Pod Security Standards", "Niveles oficiales de endurecimiento de Kubernetes (Privileged, Baseline y Restricted) orientados a impedir contenedores privilegiados, escaladas de privilegio y acceso al host."),
    ("PPID Spoofing", "Técnica inspeccionada en ingeniería de detección donde un proceso hijo declara un identificador de proceso padre falso para simular legitimidad frente a reglas simplistas del SOC."),
    ("Race Condition (Single-Packet)", "Condición de carrera avanzada sobre HTTP/2 que agrupa decenas de solicitudes en un solo paquete TCP para hacerlas llegar simultáneamente en microsegundos al backend."),
    ("RBAC (Kubernetes)", "Role-Based Access Control en Kubernetes; regula mediante Roles, ClusterRoles y Bindings qué acciones puede ejecutar cada usuario o ServiceAccount sobre la API del clúster."),
    ("SAST / DAST / SCA / SBOM", "Pruebas automatizadas DevSecOps: análisis estático de código (SAST), dinámico en ejecución (DAST), composición de dependencias (SCA) e inventario de componentes (SBOM)."),
    ("Source → Sink", "Trazado fundamental en revisión White-Box que sigue el recorrido de un dato externo desde su punto de entrada (Source) hasta una función sensible (Sink) verificando sanitización."),
    ("STRIDE", "Modelo mnemotécnico de amenazas por componente: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service y Elevation of Privilege."),
    ("UART / JTAG / SPI", "Interfaces físicas habituales en placas IoT y hardware embebido usadas respectivamente para consola serie de depuración, control de procesador en placa y lectura de memorias flash."),
    ("Unhooking", "Concepto defensivo/ofensivo referido a restaurar bytes originales de bibliotecas del sistema (como ntdll.dll) cuando han sido interceptados en modo usuario por hooks de monitoreo."),
    ("Web Cache Poisoning / Deception", "Ataques a cachés HTTP/CDN: el Poisoning fuerza a guardar una respuesta manipulada para otros usuarios usando cabeceras no incluidas en la cache key; el Deception engaña a la caché para almacenar datos privados."),
    ("WPA3-SAE", "Estándar Wi-Fi moderno basado en Simultaneous Authentication of Equals (Dragonfly) que sustituye PSK clásico e impide ataques de diccionario offline tras capturar un handshake."),
    ("Bug Bounty / VDP", "Programas públicos o privados (HackerOne, Bugcrowd, Intigriti) donde investigadores reportan vulnerabilidades dentro de una Policy y Scope explícitos a cambio de recompensas o reconocimiento (VDP)."),
    ("Subdomain Takeover", "Vulnerabilidad que ocurre cuando un registro DNS CNAME apunta a un recurso SaaS o Cloud externo dado de baja y aún reclamable, permitiendo servir contenido bajo el subdominio de la organización."),
]

LABORATORIOS_HTML = """
<h1 id="kit-de-laboratorios">Kit de laboratorios locales y plantillas</h1>
<p>Todas las prácticas de este curso se ejecutan en <strong>tu propia máquina virtual aislada o en contenedores locales ligados exclusivamente a <code>127.0.0.1</code></strong>. La carpeta <a href="laboratorios/"><code>laboratorios/</code></a> reúne los archivos base listos para estudiar y modificar sin depender de internet ni exponer servicios a tu red local.</p>

<aside class="callout peligro">
<p class="callout-titulo">Regla estricta de entorno local</p>
<p>Los archivos de práctica están configurados para escuchar únicamente en <code>127.0.0.1</code> (loopback) o dentro de redes virtuales aisladas (Host-Only / Docker interno). Nunca expongas una aplicación educativa a internet ni ejecutes scripts de auditoría contra sistemas sin autorización escrita previa.</p>
</aside>

<h2 id="inventario-labs">Contenido de la carpeta <code>laboratorios/</code></h2>
<div class="tabla"><table>
<thead><tr><th>Archivo / Recurso</th><th>Capítulos donde se usa</th><th>Propósito técnico</th></tr></thead>
<tbody>
<tr><td><a href="laboratorios/docker-compose.yml"><code>docker-compose.yml</code></a></td><td>Tomo I (1.8) y Tomo II</td><td>Despliega la app educativa local en <code>127.0.0.1:5050</code>, Nginx en <code>127.0.0.1:8080</code> y perfil opcional <code>--profile owasp</code> (OWASP Juice Shop en <code>127.0.0.1:3000</code>).</td></tr>
<tr><td><a href="laboratorios/app_lab_educativa.py"><code>app_lab_educativa.py</code></a></td><td>Cap. 1.8 y Tomo II (2.3–2.5)</td><td>Aplicación Flask + SQLite en memoria con endpoints seguros de referencia (SQL parametrizado, escape HTML + CSP, control anti-IDOR).</td></tr>
<tr><td><a href="laboratorios/auditor_red_local.py"><code>auditor_red_local.py</code></a></td><td>Cap. 1.6 y 2.1</td><td>Inspector TCP y banners en Python 3 restringido por código a direcciones <code>127.0.0.0/8</code> y RFC 1918.</td></tr>
<tr><td><a href="laboratorios/analizador_logs_soc.py"><code>analizador_logs_soc.py</code></a></td><td>Cap. 1.6, 4.3 y 4.6</td><td>Parser de logs SSH/HTTP en Python 3 que detecta fuerza bruta y escaneo 4xx emitiendo alertas JSON estructuradas.</td></tr>
<tr><td><a href="laboratorios/diccionario_web_lab.txt"><code>diccionario_web_lab.txt</code></a></td><td>Cap. 2.2</td><td>Lista controlada de 40 rutas y parámetros comunes para practicar enumeración HTTP y calibración de filtros con <code>ffuf</code> en <code>127.0.0.1</code>.</td></tr>
<tr><td><a href="laboratorios/sysmon_config_lab.xml"><code>sysmon_config_lab.xml</code></a></td><td>Cap. 4.2</td><td>Configuración educativa Sysmon v4.90 que captura creación de procesos, red de shells, <code>CreateRemoteThread</code>, acceso a <code>lsass.exe</code>, claves Run y DNS.</td></tr>
<tr><td><a href="laboratorios/suricata_lab.rules"><code>suricata_lab.rules</code></a></td><td>Cap. 4.4</td><td>Cuatro reglas IDS Suricata comentadas para detectar sondas HTTP de auditoría, accesos a <code>.env</code>/<code>.git</code>, descargas PE y ráfagas SSH.</td></tr>
<tr><td><a href="laboratorios/reglas_sigma_ejemplo.yml"><code>reglas_sigma_ejemplo.yml</code></a></td><td>Cap. 4.5</td><td>Regla Sigma válida en YAML para detectar invocaciones sospechosas de PowerShell codificado con exclusiones documentadas.</td></tr>
<tr><td><a href="laboratorios/reglas_yara_ejemplo.yar"><code>reglas_yara_ejemplo.yar</code></a></td><td>Cap. 4.5 y 4.8</td><td>Regla YARA educativa para triage estático de scripts ofuscados en entorno de laboratorio DFIR.</td></tr>
<tr><td><a href="laboratorios/muestras/auth_ssh_simulado.log"><code>muestras/auth_ssh_simulado.log</code></a></td><td>Cap. 1.5, 1.6 y 4.3</td><td>Registro SSH simulado con actividad legítima más ráfaga de fuerza bruta desde IP RFC 5737 (<code>198.51.100.42</code>) listo para probar <code>analizador_logs_soc.py</code>.</td></tr>
<tr><td><a href="laboratorios/muestras/web_access_simulado.log"><code>muestras/web_access_simulado.log</code></a></td><td>Cap. 2.2, 4.3 y 4.6</td><td>Log de acceso Nginx simulado con barrido <code>404/403</code> (<code>198.51.100.88</code>) y sonda <code>Lab-Audit-Probe</code>.</td></tr>
<tr><td><a href="laboratorios/muestras/correo_phishing_simulado.eml"><code>muestras/correo_phishing_simulado.eml</code></a></td><td>Cap. 4.6</td><td>Correo de práctica 100 % seguro (dominios RFC 2606 <code>.invalid</code>) con fallos SPF/DKIM/DMARC para practicar triage pasivo de cabeceras.</td></tr>
<tr><td><a href="laboratorios/muestras/muestra_triage_inofensiva.txt"><code>muestras/muestra_triage_inofensiva.txt</code></a></td><td>Cap. 4.8</td><td>Muestra de texto 100 % inofensiva codificada en Base64 UTF-16LE que activa <code>reglas_yara_ejemplo.yar</code> para practicar desofuscación pasiva.</td></tr>
<tr><td><a href="laboratorios/plantilla_informe_pentest.md"><code>plantilla_informe_pentest.md</code></a></td><td>Cap. 2.8</td><td>Estructura profesional de informe técnico y ejecutivo con alcance, fichas de hallazgo, CVSS/CWE y hoja de remediación.</td></tr>
<tr><td><a href="laboratorios/plantilla_informe_incidente.md"><code>plantilla_informe_incidente.md</code></a></td><td>Cap. 4.1 y 4.8</td><td>Plantilla de reporte de incidentes alineada con NIST SP 800-61 (línea temporal UTC, IOCs defanged, contención y lecciones aprendidas).</td></tr>
<tr><td><a href="laboratorios/auditor_whitebox_codereview.py"><code>auditor_whitebox_codereview.py</code></a></td><td>Cap. 2.7 y 6.4</td><td>Analizador AST en Python para auditar fuentes → sumideros (<code>eval</code>, <code>pickle</code>, <code>shell=True</code>, SQL dinámico) en revisión White-Box.</td></tr>
<tr><td><a href="laboratorios/Dockerfile.lab_seguro"><code>Dockerfile.lab_seguro</code></a></td><td>Cap. 5.3 y 5.5</td><td>Ejemplo de compilación multi-etapa endurecida (usuario sin privilegios, versión fijada, mínima superficie) para auditar con Trivy.</td></tr>
<tr><td><a href="laboratorios/k8s_pod_hardening.yaml"><code>k8s_pod_hardening.yaml</code></a></td><td>Cap. 5.4</td><td>Manifiesto Kubernetes con perfil <em>Restricted</em> (sin root, <code>drop: ALL</code>, rootfs solo lectura) y <code>NetworkPolicy</code> por defecto.</td></tr>
<tr><td><a href="laboratorios/iac_cloud_hardening.tf"><code>iac_cloud_hardening.tf</code></a></td><td>Cap. 5.1, 5.2 y 5.5</td><td>Plantilla Terraform con bloqueo público S3, cifrado en reposo y exigencia obligatoria de tokens <code>IMDSv2</code>.</td></tr>
<tr><td><a href="laboratorios/plantilla_threat_model_stride.md"><code>plantilla_threat_model_stride.md</code></a></td><td>Cap. 6.3</td><td>Plantilla lista para construir Diagramas de Flujo de Datos, matriz STRIDE, árboles de ataque y controles ASVS.</td></tr>
<tr><td><a href="laboratorios/plantilla_roe_alcance.md"><code>plantilla_roe_alcance.md</code></a></td><td>Cap. 2.8 y 7.7</td><td>Plantilla de <em>Rules of Engagement</em> (RoE), exclusiones, protocolo <em>stop-and-notify</em> y firmas de autorización escrita.</td></tr>
</tbody></table></div>

<h2 id="arranque-rapido-lab">Arranque rápido y pruebas verificables sin descargas externas</h2>
<pre><code class="lenguaje-bash"># 1. Probar de inmediato el analizador SOC y el auditor White-Box AST desde la raíz del curso
python laboratorios/analizador_logs_soc.py laboratorios/muestras/auth_ssh_simulado.log 5
python laboratorios/analizador_logs_soc.py laboratorios/muestras/web_access_simulado.log 4
python laboratorios/auditor_whitebox_codereview.py ./laboratorios/

# 2. Levantar la app educativa y Nginx localmente (solo en 127.0.0.1)
cd laboratorios
docker compose up -d

# 3. (Opcional Tomo II) Activar también OWASP Juice Shop local para prácticas web interactivas en 127.0.0.1:3000
docker compose --profile owasp up -d

# 4. Verificar puertos locales y probar endpoints seguros
python auditor_red_local.py 127.0.0.1
curl -s "http://127.0.0.1:5050/buscar-seguro?q=redes"
curl -sI "http://127.0.0.1:5050/saludo-seguro?nombre=Analista"

# 5. Detener contenedores al finalizar la sesión
docker compose --profile owasp down</code></pre>
"""

FUENTES_LIMITES_HTML = """
<h1 id="fuentes-y-limites">Fuentes abiertas, puente con Curso de Reversing y límites éticos</h1>
<p>Esta obra es un manual técnico independiente, libre y <strong>100 % original</strong> en español orientado al aprendizaje estructurado de la ciberseguridad ofensiva y defensiva.</p>

<h2 id="origen-temario">Cómo se construyó el mapa curricular (transparencia total)</h2>
<p>Para garantizar que el curso cubra habilidades reales demandadas en roles técnicos (Pentester, Analista Web, Especialista en Active Directory, Analista SOC e Ingeniero de Detección), se relevó únicamente la <strong>taxonomía pública</strong> de 358 módulos y 25 rutas de estudio del catálogo abierto de Hack The Box Academy (títulos, dificultades, categorías y agrupación de rutas) sin utilizar credenciales privadas ni reproducir texto, ejercicios o material propietario de terceros.</p>
<p>A partir de esa taxonomía y de los estándares internacionales abiertos de referencia, la obra consolidó <strong>54 capítulos originales distribuidos en 7 Tomos</strong>, redactados íntegramente desde documentación primaria y guías técnicas verificables.</p>

<h2 id="estandares-abiertos">Estándares abiertos y documentación primaria de referencia</h2>
<div class="tabla"><table>
<thead><tr><th>Área temática</th><th>Fuentes y estándares de referencia</th></tr></thead>
<tbody>
<tr><td><strong>Metodología, Threat Modeling y GRC</strong></td><td>NIST SP 800-115, PTES, FIRST CVSS v3.1/v4, EPSS, STRIDE, PASTA, ISO/IEC 27001, NIST CSF 2.0, PCI-DSS v4.0 y GDPR.</td></tr>
<tr><td><strong>Redes, Criptografía y Protocolos</strong></td><td>RFC 791 (IPv4), RFC 9293 (TCP), RFC 1035 (DNS), RFC 9110/9112 (HTTP), RFC 8446 (TLS 1.3), RFC 5280 (X.509 PKI), NIST SP 800-52 Rev. 2, NIST SP 800-38D (AES-GCM), Nmap, tcpdump y Wireshark.</td></tr>
<tr><td><strong>Sistemas Operativos y Hardening</strong></td><td>Linux man-pages, documentación de systemd/auditd/AppArmor, CIS Benchmarks, Microsoft Learn (Windows Security, NTFS, PowerShell, WinEvent, Sysinternals).</td></tr>
<tr><td><strong>Seguridad Web, APIs y Code Review</strong></td><td>OWASP Top 10, OWASP API Security Top 10, OWASP Web Security Testing Guide (WSTG), OWASP ASVS, OWASP Code Review Guide, OWASP Cheat Sheet Series, RFC 7519 (JWT) y RFC 6749/9700 (OAuth 2.0).</td></tr>
<tr><td><strong>Active Directory, Red Team y OPSEC</strong></td><td>RFC 4120 (Kerberos v5), RFC 4556 (PKINIT), Microsoft Learn (AD DS, ADCS, Protected Users, gMSA, Tiering, Windows LAPS, MS-DRSR, AMSI/ETW), LOLBAS, GTFOBins y NIST SP 800-63B.</td></tr>
<tr><td><strong>SOC, SIEM, NSM, Detection &amp; DFIR</strong></td><td>NIST SP 800-61 Rev. 3 (Incident Handling), MITRE ATT&amp;CK / CAR / D3FEND, RFC 3227, RFC 7208/6376/7489 (SPF/DKIM/DMARC), SigmaHQ, YARA, Suricata, Zeek, Elastic ECS, Splunk CIM y Volatility 3.</td></tr>
<tr><td><strong>Cloud, Contenedores y DevSecOps</strong></td><td>AWS/Azure/GCP Security &amp; Well-Architected Docs, CIS Docker &amp; Kubernetes Benchmarks, Kubernetes Pod Security Standards, Terraform/Trivy/Sigstore y OWASP CI/CD Security Risks.</td></tr>
<tr><td><strong>Mobile, Wireless, IoT y OT/ICS</strong></td><td>OWASP MASTG / MASVS (Android/iOS), IEEE 802.11 (WEP/WPA2/WPA3-SAE/802.1X), IEC 62443 / NIST SP 800-82 (OT/ICS y Modelo Purdue).</td></tr>
</tbody></table></div>

<h2 id="puente-cls-guia">Puente curricular con la obra hermana: Curso de Reversing en Windows</h2>
<p>Los módulos orientados a ensamblador x86/x64, formato ejecutable PE, depuración de binarios, ingeniería inversa con IDA/Ghidra, análisis profundo de WinDbg/ETW e internos del kernel de Windows se encuentran desarrollados de forma exhaustiva en nuestro manual hermano <a href="../CLS_Guia/00_EMPEZAR_AQUI.html"><strong>Curso de Reversing en Windows</strong></a>, permitiendo estudiar ambos proyectos como una suite complementaria sin duplicar material:</p>
<div class="tabla"><table>
<thead><tr><th>Temática en el catálogo (10 mód. puente)</th><th>Cobertura recomendada en la suite hermano <code>Curso de Reversing</code></th></tr></thead>
<tbody>
<tr><td><em>Intro to Assembly Language</em></td><td><a href="../CLS_Guia/guia/index.html">Curso de Reversing · Etapa 1 y Bloque 2A</a> (Números, memoria, instrucciones x86/x64 y convenciones de llamada).</td></tr>
<tr><td><em>Reverse Engineering / 2 / Introduction to IDA / Game Reversing</em></td><td><a href="../CLS_Guia/guia/index.html">Curso de Reversing · Bloques 2A, 2B y 2C</a> (x64dbg, IDA Free, Ghidra, ofuscación, C++ y desvirtualización SLEIGH).</td></tr>
<tr><td><em>Stack-Based Buffer Overflows / Binary Fuzzing</em></td><td><a href="../CLS_Guia/guia/index.html">Curso de Reversing · Etapa 5 (5.2) y Etapa 6 (6.10)</a>.</td></tr>
<tr><td><em>Dynamic Analysis with WinDbg / Windows Kernel Telemetry &amp; ETW</em></td><td><a href="../CLS_Guia/2d.html">Curso de Reversing · Rama 2D (Windows Internals, VAD, ETW, COM/RPC)</a> y <a href="../CLS_Guia/guia/etapa-6.html">Etapa 6 (Kernel y WinDbg)</a>.</td></tr>
</tbody></table></div>

<h2 id="alcance-y-exclusiones">Alcance integral de la Edición 2.0 (Hiper Biblioteca)</h2>
<ul>
  <li><strong>Incluido en profundidad (332 módulos HTB mapeados + expansión integral → 54 capítulos en 7 Tomos):</strong>
    <ul>
      <li><strong>Tomos I–IV:</strong> Fundamentos de sistemas, redes y criptografía, Pentesting Web y APIs, Infraestructura/PrivEsc/Active Directory, SOC/SIEM/NSM/Sigma-YARA/Hunting/DFIR.</li>
      <li><strong>Tomo V:</strong> Seguridad Multi-Cloud (AWS, Azure/Entra ID, GCP), Contenedores Docker, Kubernetes, CI/CD, DevSecOps, Telemetría y Forense Cloud (incluye los 17 módulos Cloud).</li>
      <li><strong>Tomo VI:</strong> Web Avanzado nivel PortSwigger/WSTG (<em>Race Conditions</em> HTTP/2, <em>Cache Poisoning</em>, OAuth complejo, lógica de negocio, WebSockets, <em>DOM Clobbering</em>), Threat Modeling (STRIDE/PASTA), White-Box Code Review, Red Teaming/OPSEC/LOLBAS, arquitectura AV/EDR y Engineering Social controlada.</li>
      <li><strong>Tomo VII:</strong> Mobile Android/iOS (OWASP MASTG, Frida, forense móvil — 9 módulos), Redes Inalámbricas Wi-Fi (WEP, WPS, WPA/WPA2/WPA3, 802.1X/RADIUS, Evil Twin — 11 módulos), Seguridad Física/Hardware/IoT, Entornos Industriales OT/ICS/SCADA (Purdue) y GRC/ISO 27001/NIST CSF/PCI-DSS/GDPR.</li>
    </ul>
  </li>
  <li><strong>Puente con <code>Curso de Reversing</code> (10 módulos):</strong> Ensamblador, reversing de binarios, IDA Pro/Free, fuzzing binario y explotación de memoria remitidos directamente a <a href="../CLS_Guia/00_EMPEZAR_AQUI.html"><code>Curso de Reversing</code></a>.</li>
  <li><strong>Anexo de referencia (16 módulos):</strong> Tópicos complementarios de seguridad en IA/LLM registrados en el catálogo maestro.</li>
</ul>

<h2 id="marco-etico">Marco legal, ético y de seguridad</h2>
<aside class="callout peligro">
<p class="callout-titulo">Compromiso de uso responsable</p>
<ul>
  <li>El conocimiento de este manual tiene fines estrictamente <strong>educativos, de auditoría autorizada y de defensa de sistemas</strong>.</li>
  <li>Jamás apliques técnicas de enumeración, pruebas de inyección o auditoría de credenciales contra redes, aplicaciones o dominios sin <strong>autorización explícita y por escrito</strong> del propietario.</li>
  <li>Toda práctica propuesta en los 7 tomos está diseñada para ejecutarse en <strong>tu propio laboratorio aislado</strong> (VMs en red Host-Only o contenedores Docker ligados a <code>127.0.0.1</code>).</li>
  <li>El curso no incluye malware funcional, código de evasión maliciosa ni exploits armados contra terceros.</li>
</ul>
</aside>
"""
