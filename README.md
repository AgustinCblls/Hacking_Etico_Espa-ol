# Hacking Ético y Defensa Integral (Edición 2.0 · Hiper Biblioteca)

Manual técnico completo, libre y offline de **ciberseguridad ofensiva y defensiva** en español, estructurado en **7 Tomos / 7 Rutas progresivas (54 capítulos)** con trazabilidad curricular sobre **358 módulos y 25 rutas de estudio** de referencia, más hojas de referencia rápida, glosario técnico, 270 preguntas de autoevaluación y kit local de laboratorios.

## Alcance temático
- **Tomo I · Ruta 1 (Principiante — 9 caps.):** Laboratorio aislado, marco legal, redes TCP/IP (incl. 802.1Q, OSPF/BGP, IPv6 NDP/RA Guard), Linux, Windows, Bash/PowerShell, Python 3 (y panorama Golang/C#), protocolos de red, HTTP y Criptografía aplicada / TLS / PKI.
- **Tomo II · Ruta 2 (Intermedio — 8 caps.):** Reconocimiento/OSINT/Supply Chain/Nmap, enumeración web/CMS/fuzzing, inyecciones (SQLi/NoSQLi/CMDi/LDAP/XPath), XSS/CSRF/CORS/CSP, autenticación/JWT/OAuth/SAML/IDOR, LFI/SSRF/XXE/SSTI/deserialización, APIs/GraphQL/HTTP2/Whitebox y reportes profesionales + flujo Bug Bounty (*Subdomain Takeover* y criterio de triaje).
- **Tomo III · Ruta 3 (Avanzado — 8 caps.):** Shells, transferencias, `searchsploit` + compilación cruzada de PoCs y Metasploit; auditoría de contraseñas; escalada de privilegios y hardening Linux/Windows; pivoting (`Ligolo-ng`/`Chisel`) + `Impacket` + *Assumed Breach*; y Active Directory integral (LDAP, BloodHound, NetExec, Kerberos, NTLM Relay, DACLs, `secretsdump`/`Rubeus`/`RunAsPPL`, ADCS ESC1–8 y Hardening Tier 0).
- **Tomo IV · Ruta 4 (Especialista Blue Team / SOC — 8 caps.):** Operaciones SOC e Incident Response (NIST SP 800-61), Sysmon/Wazuh/`auditd`, SIEM (Splunk SPL, Elastic KQL, QRadar, ECS/CIM, SOAR/TheHive), NSM (Wireshark, Zeek, Suricata/Snort, NetworkMiner), Detection Engineering (Sigma, YARA, MITRE CAR/D3FEND), Threat Hunting (`RITA`, Deception) / CTI / Phishing, DFIR (FTK/LiME/Hindsight/Volatility 3/Antiforense) y triage estático de malware + ETW/AMSI.
- **Tomo V · Ruta 5 (Cloud y DevSecOps — 7 caps.):** Multi-Cloud IAM / Entra ID, Storage/VPC/`IMDSv2`, Docker y escapes de contenedores, Kubernetes (RBAC, NetworkPolicy, Pod Security Standards), CI/CD e IaC (Terraform/GitHub Actions/SAST/SCA/SBOM/Sigstore), telemetría y perímetro Cloud (`CloudTrail`, `GuardDuty`, `AWS WAF`, `Shield`, `Cloud Armor`) y Forense Cloud (AWS, Azure, GCP).
- **Tomo VI · Ruta 6 (Ingeniería Ofensiva Avanzada y OPSEC — 7 caps.):** Web avanzado (*Race Conditions* HTTP/2, *Cache Poisoning/Deception*, WebSockets/*CSWSH*, *DOM Clobbering*, *CSPT*), OAuth/OIDC complejo y lógica de negocio, Threat Modeling (`STRIDE`/`PASTA`/ASVS), White-Box Code Review multi-lenguaje (Python, Node, PHP, Java, .NET), Red Teaming/OPSEC/`LOLBAS`, arquitectura AV/EDR (`ThreatCheck`/`DefenderCheck`/AMSI/ETW/PPID) e Ingeniería Social + vectores *Client-Side* (`.Library-ms`, `.lnk`, VBA/MotW/ASR).
- **Tomo VII · Ruta 7 (Mobile, Wireless, Hardware/OT y GRC — 7 caps.):** Mobile Android/iOS (`OWASP MASTG`, `jadx`, `apktool`, `Frida`, forense móvil), Redes Inalámbricas Wi-Fi (`802.11`, WEP, WPS, WPA2/PMKID, WPA3-SAE, `802.1X`/RADIUS/`EAP-TLS`, Evil Twin, WIDS), Seguridad Física/Hardware/IoT (RFID, BadUSB, DMA/IOMMU, BitLocker/LUKS, UART/JTAG/`binwalk`), Entornos Industriales OT/ICS/SCADA (Modelo Purdue, Modbus, OPC UA), y GRC/Legal/Portafolio y Entrevistas Técnicas.
- **Puente con curso hermano de Reversing:** Los 10 módulos de ensamblador x86/x64, reversing binario, IDA/Ghidra, WinDbg y kernel de Windows se enlazan al proyecto hermano [`CLS_Guia`](../CLS_Guia/00_EMPEZAR_AQUI.html).

## Cómo usar el paquete
1. Abrí [`00_EMPEZAR_AQUI.html`](00_EMPEZAR_AQUI.html) en cualquier navegador (funciona 100 % offline).
2. Explorá los 358 módulos y 25 rutas filtrables en [`catalogo_completo.html`](catalogo_completo.html) (con descripciones, prerrequisitos y 4,068 secciones).
3. Consultá [`laboratorios.html`](laboratorios.html) para levantar el entorno Docker local (`127.0.0.1`) y probar los scripts y plantillas.
4. Registrá tu avance en [`seguimiento.csv`](seguimiento.csv) y consultá los 9 PDFs A4 en [`orden_impresion.html`](orden_impresion.html).
5. Para recompilar todo el sitio HTML y los 9 PDFs A4:
   ```bash
   python construir_suite.py
   ```

## Marco ético y educativo
Todo el contenido es **100 % original**, basado en estándares abiertos (OWASP, MITRE ATT&CK/D3FEND, NIST, RFCs, CIS Benchmarks, ISO/IEC 27001 y documentación oficial). Las prácticas están diseñadas exclusivamente para ejecutarse en **laboratorios locales propios** (`127.0.0.1`, contenedores Docker locales, emuladores o máquinas virtuales aisladas).
