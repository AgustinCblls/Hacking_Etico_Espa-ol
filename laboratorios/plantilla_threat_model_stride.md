# Plantilla de Threat Modeling (DFD + STRIDE + Árbol de Ataque + OWASP ASVS)

> Uso recomendado: Cap. 6.3 · Completar antes de codificar o desplegar un servicio nuevo.

## 1. Descripción del sistema y activos críticos
- **Sistema / Funcionalidad evaluada:**
- **Activos críticos (datos, credenciales, fondos, disponibilidad):**
- **Supuestos y dependencias externas:**

## 2. Diagrama de Flujo de Datos (DFD) y Fronteras de Confianza
- **Entidades externas:**
- **Procesos:**
- **Almacenes de datos:**
- **Fronteras de confianza (*Trust Boundaries*):**

## 3. Matriz STRIDE por componente en frontera de confianza
| Elemento DFD | Categoría STRIDE | Amenaza concreta | Impacto | Mitigación de diseño | Requisito ASVS |
| :--- | :--- | :--- | :--- | :--- | :--- |
| API Auth | **S**poofing | | | | |
| Flujo Pago | **T**ampering | | | | |
| Auditoría | **R**epudiation | | | | |
| Storage | **I**nformation Disclosure | | | | |
| Endpoint | **D**enial of Service | | | | |
| Admin Panel | **E**levation of Privilege | | | | |

## 4. Árbol de ataque resumido (Objetivo raíz)
- Objetivo raíz: `[Ej. Acceso administrativo no autorizado]`
  - `[OR]` Ruta A:
    - `[AND]` Condición A1 + Condición A2
  - `[OR]` Ruta B:
    - Condición B1

## 5. Verificación final ("¿Hicimos un buen trabajo?")
- [ ] Cada frontera de confianza tiene controles de autenticación, autorización y validación documentados.
- [ ] Existen pruebas automatizadas o casos de abuso ligados a los riesgos de severidad Alta/Crítica.
