::: nota Objetivo de la lección
Al completar este capítulo vas a distinguir con precisión entre codificación, cifrado y hashing, evaluar por qué los algoritmos rápidos (MD5, SHA-1, NTLM) resultan inadecuados para almacenar contraseñas frente a funciones de derivación modernas (Argon2id, bcrypt, scrypt, PBKDF2), auditar hashes de prueba en laboratorio con Hashcat y John the Ripper, analizar el riesgo del password spraying y diseñar políticas de autenticación alineadas con NIST SP 800-63B.
:::

**Prerrequisitos:** Manejo básico de consola Linux, conceptos elementales de criptografía y laboratorio local aislado. **Duración sugerida:** 90 a 120 minutos.

## 1. Codificación, cifrado y hashing: diferencias técnicas esenciales

Confundir estas tres operaciones conduce a errores críticos de diseño en sistemas de autenticación. Cada mecanismo responde a un propósito distinto y ofrece propiedades matemáticas diferentes.

| Mecanismo | Objetivo principal | ¿Es reversible? | ¿Usa clave secreta? | Ejemplos típicos |
| --- | --- | --- | --- | --- |
| **Codificación** | Compatibilidad de transporte y formato | Sí (sin secreto) | No | Base64, URL encoding, Hex |
| **Cifrado** | Confidencialidad de datos | Sí (con la clave) | Sí (simétrica o asimétrica) | AES-GCM, ChaCha20, RSA |
| **Hashing** | Integridad o almacenamiento unidireccional | No (función unidireccional) | No (salvo HMAC) | SHA-256, Argon2id, bcrypt |

Un error frecuente en aplicaciones heredadas es almacenar contraseñas "cifradas" con una clave simétrica o simplemente codificadas en Base64. Si la base de datos y la clave se ven comprometidas, todas las credenciales quedan expuestas de inmediato. El almacenamiento correcto exige funciones unidireccionales diseñadas específicamente para contraseñas.

## 2. Hashes rápidos heredados vs. KDF modernas con salt y costo

Los algoritmos de propósito general como MD5, SHA-1 o el formato NTLM fueron diseñados para calcularse a altísima velocidad. Esa virtud para verificar integridad de archivos se convierte en una debilidad grave cuando se aplican a contraseñas: una GPU moderna evalúa miles de millones de candidatos por segundo contra hashes sin costo computacional.

### Propiedades de una KDF robusta

Para proteger credenciales en reposo se utilizan Funciones de Derivación de Claves (KDF) resistentes a fuerza bruta masiva:

- **Salt único por usuario:** Cadena aleatoria generada criptográficamente que impide el uso de tablas precalculadas (rainbow tables) y garantiza que dos usuarios con la misma contraseña produzcan hashes distintos.
- **Factor de costo ajustable (iteraciones):** Incrementa de forma controlada el tiempo de cómputo a medida que evoluciona el hardware.
- **Dureza en memoria (*memory-hardness*):** Exige una cantidad significativa de RAM por evaluación, frenando drásticamente la paralelización masiva en GPUs y ASICs.

| Algoritmo | Categoría | Salt nativo | Dureza en memoria | Recomendación actual |
| --- | --- | --- | --- | --- |
| **MD5 / SHA-1 / NTLM** | Hash rápido heredado | No | No | Obsoleto para contraseñas |
| **PBKDF2-HMAC-SHA256** | KDF por iteraciones | Sí | Baja | Aceptable con iteraciones altas (FIPS) |
| **bcrypt** | KDF basada en Blowfish | Sí | Moderada (fija) | Válida (cuidado con límite de 72 bytes) |
| **scrypt** | KDF memory-hard | Sí | Alta | Recomendada |
| **Argon2id** | KDF híbrida (PHC winner) | Sí | Alta y configurable | Estándar preferido actual |

## 3. Auditoría autorizada de hashes de prueba con Hashcat y John the Ripper

En una auditoría interna autorizada (por ejemplo, evaluando la robustez de credenciales sintéticas o volcados de laboratorio propios), herramientas como **Hashcat** y **John the Ripper** permiten medir qué porcentaje de contraseñas incumplen criterios mínimos de entropía frente a diccionarios y reglas comunes.

### Estrategias de evaluación en laboratorio

- **Modo diccionario:** Compara hashes de prueba contra listas de palabras frecuentes o filtradas históricamente.
- **Modo basado en reglas:** Aplica transformaciones determinísticas sobre un diccionario (mayúscula inicial, sustitución simple de caracteres, sufijos de años como `2025` o `2026`), evidenciando por qué las políticas tradicionales basadas en patrones predecibles fallan.
- **Modo máscara:** Evalúa patrones estructurales acotados en pruebas controladas de longitud y conjunto de caracteres.

```bash
# 1. Medir el rendimiento local del hardware en modo benchmark (sin atacar objetivos reales)
hashcat -b -m 0 --quiet
john --test --format=raw-sha256

# 2. Inspeccionar formatos soportados y verificar un archivo de hashes sintéticos de laboratorio
# Archivo de ejemplo creado localmente para auditoría educativa
printf 'usuario_lab:%s\n' "$(printf 'ClaveDebil2026' | sha256sum | awk '{print $1}')" > /tmp/hashes_lab.txt

# 3. Evaluar el archivo sintético con un diccionario local reducido y mostrar coincidencias
john --format=raw-sha256 --wordlist=/tmp/diccionario_lab.txt /tmp/hashes_lab.txt
john --show --format=raw-sha256 /tmp/hashes_lab.txt
```

::: peligro Alcance estrictamente autorizado
Nunca ejecutes auditorías de hashes ni pruebas de autenticación sobre cuentas o bases de datos sin autorización escrita y un alcance formalmente definido. Todas las prácticas de este manual se limitan a hashes generados por vos mismo en tu laboratorio aislado.
:::

## 4. Riesgos de la fuerza bruta en línea y del password spraying

A diferencia de la auditoría offline sobre hashes, las pruebas contra servicios de autenticación en línea interactúan directamente con el directorio de identidades o el portal de acceso.

### Por qué el password spraying evade bloqueos simples

En un intento vertical clásico (muchas contraseñas contra un solo usuario), la política de bloqueo de cuenta (*account lockout*) detiene la actividad tras 5 o 10 fallos consecutivos. El **password spraying** invierte la matriz: prueba unas pocas contraseñas muy comunes de manera horizontal contra cientos de cuentas distintas, espaciando los intentos por debajo del umbral de bloqueo individual.

Esta técnica suele tener éxito en organizaciones que combinan dos debilidades: rotación obligatoria frecuente (que empuja a los usuarios a elegir patrones estacionales predecibles) y ausencia de autenticación multifactor (MFA) o monitoreo agregado por origen.

## 5. Políticas modernas de contraseñas según NIST SP 800-63B

La guía NIST SP 800-63B revolucionó las recomendaciones clásicas al demostrar empíricamente que las reglas arbitrarias de complejidad y rotación periódica reducen la seguridad real en lugar de aumentarla.

### Principios centrales para implementar hoy

1. **Priorizar la longitud sobre la complejidad arbitraria:** Fomentar frases de contraseña largas (mínimo 8 caracteres exigibles, recomendando ≥ 12–15 caracteres y permitiendo al menos 64 caracteres con espacios y Unicode).
2. **Eliminar reglas de composición artificiales:** No forzar combinaciones obligatorias de mayúsculas, números y símbolos que inducen patrones predecibles.
3. **Bloquear contraseñas comprometidas:** Comparar cada nueva contraseña contra listas de contraseñas filtradas, palabras de diccionario comunes y términos derivados del servicio o nombre de usuario.
4. **Suprimir la rotación periódica sin evidencia de compromiso:** Cambiar contraseñas cada 90 días sin indicios de filtración degrada la calidad de las claves; solo se debe forzar el cambio ante sospecha o confirmación de compromiso.
5. **Desplegar MFA resistente a phishing:** Complementar las contraseñas con autenticadores criptográficos vinculados al origen (FIDO2/WebAuthn o passkeys) y aplicar limitación de tasa (*rate limiting*) en todos los puntos de acceso.

## Ejemplo paso a paso: comparación empírica entre SHA-256 rápido y PBKDF2/scrypt en Python

Este script local permite observar directamente la diferencia de costo computacional entre un hash rápido sin salt y una KDF moderna en tu propia máquina.

```python
import hashlib
import os
import time

password = b"FraseDePruebaEnLaboratorio2026"
salt = os.urandom(16)

# 1. Hash rápido (inadecuado para contraseñas)
t0 = time.perf_counter()
for _ in range(1000):
    digest_rapido = hashlib.sha256(password).hexdigest()
t1 = time.perf_counter()

# 2. KDF con salt y alto número de iteraciones (PBKDF2-HMAC-SHA256)
t2 = time.perf_counter()
digest_pbkdf2 = hashlib.pbkdf2_hmac("sha256", password, salt, 600_000).hex()
t3 = time.perf_counter()

# 3. KDF memory-hard (scrypt)
t4 = time.perf_counter()
digest_scrypt = hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1).hex()
t5 = time.perf_counter()

print(f"1000 x SHA-256 rápido : {(t1 - t0)*1000:.2f} ms")
print(f"1 x PBKDF2 (600k iter): {(t3 - t2)*1000:.2f} ms")
print(f"1 x scrypt (memory)   : {(t5 - t4)*1000:.2f} ms")
# Salida esperada (referencial):
# 1000 x SHA-256 rápido : ~1.20 ms (millones por segundo en GPU)
# 1 x PBKDF2 (600k iter): ~220.00 ms (frena drásticamente la evaluación offline)
# 1 x scrypt (memory)   : ~45.00 ms (añade penalización de memoria contra GPUs)
```

::: defensa Perspectiva defensiva, detección y mitigación
Dentro de los marcos de defensa (tácticas de alto nivel de MITRE ATT&CK como **Credential Access** e **Initial Access**), el fortalecimiento de identidades combina arquitectura criptográfica y detección conductual:
- **Detección en telemetría de autenticación:** Correlacionar fallos de inicio de sesión distribuidos sobre múltiples cuentas desde una misma IP, ASN o huella de cliente en ventanas cortas de tiempo, además de alertas por autenticaciones desde ubicaciones o dispositivos atípicos.
- **Controles preventivos clave:** Migrar almacenamiento de credenciales a Argon2id o scrypt con salt único, habilitar MFA resistente a phishing (WebAuthn/FIDO2), implementar bloqueo inteligente (*smart lockout*) y aplicar validación contra listas de contraseñas filtradas durante el alta o cambio de clave.
:::

## Práctica en laboratorio local

1. Ejecutá el script de Python del ejemplo paso a paso en tu máquina de laboratorio y documentá los tiempos medidos para SHA-256, PBKDF2 y scrypt.
2. Creá un pequeño archivo con tres hashes sintéticos (dos contraseñas débiles con patrón año/mayúscula y una frase de contraseña larga de 18 caracteres) y auditalo localmente con `john` o `hashcat` usando un diccionario reducido creado por vos.
3. Redactá una política técnica breve (media página) para una aplicación web ficticia aplicando los criterios de NIST SP 800-63B.

::: practica Entregable mínimo
Tabla comparativa con los tiempos reales obtenidos en tu laboratorio, resultado de la verificación de los tres hashes sintéticos (mostrando cómo la frase larga resiste el diccionario) y el borrador de política de contraseñas alineada a NIST SP 800-63B.
:::

## Preguntas de repaso

**1. ¿Por qué no se debe usar cifrado simétrico ni Base64 para almacenar contraseñas de usuarios?** Porque Base64 es una codificación reversible sin secreto y el cifrado simétrico permite recuperar las contraseñas en claro si la clave se filtra; las contraseñas deben protegerse mediante funciones unidireccionales (KDF) con salt único.

**2. ¿Qué dos problemas resuelve el uso de un salt criptográfico único por usuario?** Impide el aprovechamiento de tablas precalculadas (rainbow tables) y evita que un observador pueda detectar usuarios que comparten la misma contraseña dentro de una base de datos.

**3. ¿Por qué Argon2id se considera superior a SHA-256 simple o incluso a PBKDF2 para almacenar contraseñas?** Porque, además de incorporar salt y costo temporal configurable, exige un uso intensivo de memoria RAM (memory-hardness), lo cual limita fuertemente la aceleración paralela mediante GPUs o hardware dedicado.

**4. ¿Por qué el password spraying resulta difícil de frenar únicamente con un umbral básico de bloqueo por cuenta?** Porque distribuye pocos intentos entre muchas cuentas diferentes, manteniéndose por debajo del límite de fallos consecutivos de cada usuario individual.

**5. ¿Por qué NIST SP 800-63B desaconseja la rotación periódica obligatoria de contraseñas sin evidencia de compromiso?** Porque obliga a los usuarios a reutilizar patrones incrementales predecibles (como cambiar el número final o el mes), debilitando la entropía efectiva sin aportar protección real frente a credenciales no comprometidas.

## Antes de avanzar

- [ ] Diferenciás claramente codificación, cifrado y hashing unidireccional.
- [ ] Sabés justificar la selección de Argon2id o scrypt frente a algoritmos heredados.
- [ ] Ejecutaste pruebas controladas con hashes sintéticos y comprendiste el impacto del costo computacional.
- [ ] Entendés la mecánica y mitigación del password spraying.
- [ ] Podés redactar e implementar controles de contraseñas conforme a NIST SP 800-63B.

::: nota Puerta de salida
Eliminá los archivos temporales con diccionarios y hashes de prueba de `/tmp` una vez documentado tu entregable y conservá únicamente tu informe técnico de resultados.
:::

## Referencias y estándares abiertos

- NIST SP 800-63B: *Digital Identity Guidelines — Authentication and Lifecycle Management* (https://pages.nist.gov/800-63-3/sp800-63b.html)
- OWASP Cheat Sheet Series: *Password Storage Cheat Sheet* (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- RFC 9106: *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications* (https://datatracker.ietf.org/doc/html/rfc9106)
- MITRE ATT&CK Enterprise Matrix: tácticas *Credential Access* e *Initial Access* (https://attack.mitre.org/)
- Documentación oficial de Hashcat y John the Ripper (https://hashcat.net/wiki/ y https://www.openwall.com/john/doc/)
