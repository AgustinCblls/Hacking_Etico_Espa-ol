# Informe de Respuesta a Incidentes SOC / DFIR (Plantilla de Laboratorio)

## 1. Metadatos del Incidente
- **ID de Ticket / Caso:** `INC-2026-0001`
- **Clasificación:** `<Acceso no autorizado | Phishing | Malware | Falso Positivo>`
- **Severidad:** `<P1 Crítica | P2 Alta | P3 Media | P4 Baja>`
- **Analista responsable:** `<Nombre>`
- **Estado actual:** `<Triage | Contención | Erradicación | Recuperación | Cerrado>`

## 2. Resumen del Incidente
Descripción breve de qué ocurrió, cuándo se detectó, qué activos se vieron afectados y cuál fue el impacto operativo.

## 3. Línea Temporal (UTC)
| Marca temporal (UTC) | Fuente de telemetría | Evento observado | Evidencia / Hash |
|---|---|---|---|
| `YYYY-MM-DD HH:MM:SSZ` | Firewall / Sysmon / SIEM | Detección inicial | `SHA-256 / EventID` |

## 4. Indicadores de Compromiso (IOCs) y Tácticas
- **IPs / Dominios / URLs (defanged):** `hxxp://ejemplo[.]invalid`
- **Hashes de archivos (SHA-256):** `<hash>`
- **Tácticas de alto nivel (MITRE ATT&CK):** `<ej. Initial Access, Execution, Persistence>`

## 5. Acciones de Contención, Erradicación y Recuperación
1. **Contención:** aislamiento de host, revocación de sesiones/credenciales, bloqueo perimetral.
2. **Erradicación:** eliminación de artefactos, persistencia y corrección de causa raíz.
3. **Recuperación:** restauración desde backup limpio, monitoreo reforzado.

## 6. Lecciones Aprendidas y Mejoras de Detección
- Nuevas reglas SIEM / Sigma / YARA creadas a partir del incidente.
- Cambios de hardening preventivo recomendados.
