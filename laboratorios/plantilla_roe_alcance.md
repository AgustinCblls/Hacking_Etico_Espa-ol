# Plantilla de Reglas de Enfrentamiento (Rules of Engagement — RoE)

> Uso recomendado: Cap. 2.8 y Cap. 7.7 · Ninguna evaluación autorizada comienza sin este documento aprobado y firmado.

## 1. Partes, autorizaciones y contactos
- **Organización cliente / Propietaria de los activos:**
- **Equipo auditor / Proveedor:**
- **Contacto de emergencia técnica (24/7):**
- **Contacto ejecutivo / Legal:**

## 2. Alcance exacto autorizado (*In-Scope*)
| Tipo de activo | Identificador / Rango CIDR / URL | Tipo de prueba permitida | Notas |
| :--- | :--- | :--- | :--- |
| Aplicación Web | | | |
| Infraestructura | | | |

## 3. Activos y técnicas explícitamente excluidas (*Out-of-Scope*)
- Sistemas excluidos (terceros, proveedores SaaS no autorizados, equipos médicos/OT críticos):
- Pruebas prohibidas por defecto: Denegación de servicio (DoS/DDoS), ingeniería social salvo anexo explícito, borrado de datos en producción.

## 4. Ventana operativa, IP origen y protocolo *Stop-and-Notify*
- **Fechas y huso horario permitido:**
- **IPs públicas / VPN desde donde operará el equipo auditor:**
- **Protocolo ante hallazgo crítico o indicio de intrusión real activa:** detener pruebas sobre ese vector y notificar dentro de `<X horas>` al contacto de emergencia sin alterar evidencia ajena.

## 5. Manejo de datos sensibles y firmas
- Cifrado obligatorio de evidencias en reposo, retención máxima post-entrega (`<N días>`) y borrado seguro verificado.
- **Firma de autorización explícita:** `[Nombre, Cargo, Fecha]`
