::: nota Objetivo de la lección
Comprender la arquitectura de seguridad de Android y sus diferencias fundamentales frente a iOS, dominar la anatomía interna de un paquete APK y ejecutar una auditoría de análisis estático completa —manual y automatizada— alineada con los estándares **OWASP MASVS** y **OWASP MASTG** en un entorno de laboratorio controlado.
:::

Las aplicaciones móviles manejan credenciales bancarias, tokens de sesión persistentes, datos biométricos y secretos corporativos en dispositivos que salen constantemente del perímetro de la red empresarial. Auditar una aplicación móvil exige primero entender cómo el sistema operativo intenta aislarla y qué ocurre cuando un desarrollador debilita esas garantías mediante configuraciones permisivas o código descuidado. En este capítulo vas a recorrer las capas de defensa nativas de Android, la estructura interna de un archivo APK y las técnicas de análisis estático con herramientas de código abierto como `apktool`, `jadx` y **MobSF**.

## Arquitectura de seguridad de Android frente a iOS

El modelo de seguridad de Android se apoya en un núcleo Linux modificado sobre el cual opera el entorno de ejecución **ART** (*Android Runtime*). A diferencia de un sistema de escritorio tradicional donde todas las aplicaciones ejecutadas por un usuario comparten permisos sobre sus archivos personales, Android trata a cada aplicación instalada como un usuario distinto del sistema operativo.

### Aislamiento por UID, SELinux y Sandbox de aplicaciones

Durante la instalación, el gestor de paquetes (`PackageManagerService`) asigna a cada aplicación un identificador de usuario Linux único (`UID`), generalmente con el formato `u0_aXXX` (por ejemplo, `u0_a142`). Todos los procesos que lanza esa aplicación corren bajo ese UID y poseen un directorio privado en `/data/data/<nombre_paquete>/` (o `/data/user/0/<nombre_paquete>/`) con permisos restrictivos (`0700` o `0751`). Gracias a este control de acceso discrecional (**DAC**), una aplicación no puede leer archivos internos, bases SQLite ni preferencias de otra aplicación, salvo que el desarrollador los exponga explícitamente o escriba en el almacenamiento compartido externo.

Por encima del aislamiento clásico por UID actúa **SELinux** (*Security-Enhanced Linux*) en modo *enforcing* desde Android 5.0. SELinux implementa un control de acceso obligatorio (**MAC**) que restringe qué puede hacer cada proceso según su dominio de seguridad, independientemente de los permisos POSIX tradicionales. Las aplicaciones de terceros se ejecutan dentro del dominio `untrusted_app`, lo que bloquea el acceso directo a dispositivos de hardware, archivos de configuración del sistema, propiedades sensibles o procesos de otras apps, mitigando el impacto incluso si un atacante logra corromper memoria dentro de un componente nativo.

### Android Keystore y almacenamiento criptográfico por hardware

Guardar claves simétricas o privadas en texto plano dentro del directorio privado de la aplicación sigue siendo riesgoso ante dispositivos con acceso `root` o vulnerabilidades de extracción física. Para resolverlo, Android provee el sistema **Android Keystore**, que delega la generación y el uso de material criptográfico a un entorno aislado por hardware: el **TEE** (*Trusted Execution Environment*) o, en dispositivos modernos compatibles, un chip dedicado denominado **StrongBox Keymaster**.

Cuando una aplicación genera una clave dentro del Keystore, la clave privada nunca abandona el hardware seguro hacia la memoria de la aplicación. La app solo solicita operaciones de cifrado, descifrado o firma mediante un alias, y puede exigir además políticas de uso como `setUserAuthenticationRequired(true)` para vincular el desbloqueo de la clave a una validación biométrica reciente.

### Evolución de la firma de paquetes APK (v1, v2 y v3)

Todo paquete Android debe estar firmado criptográficamente para verificar la integridad del código y establecer la identidad del autor en actualizaciones futuras o al compartir permisos con `protectionLevel="signature"`. Sin embargo, la evolución del esquema de firma refleja vulnerabilidades históricas importantes:

- **Firma v1 (JAR Signing)**: heredada del formato JAR de Java (`META-INF/MANIFEST.MF`, `CERT.SF`, `CERT.RSA`). Solo verifica la integridad de las entradas individuales declaradas dentro del archivo ZIP, dejando sin validar metadatos ZIP arbitrarios o bytes agregados al inicio. Esta debilidad permitió la vulnerabilidad **Janus (CVE-2017-13156)**, mediante la cual un atacante podía anteponer un archivo DEX malicioso a un APK legítimo sin invalidar la firma v1.
- **Firma v2 (APK Signature Scheme v2)**: introducida en Android 7.0. Inserta un bloque binario de firma inmediatamente antes del *ZIP Central Directory* y calcula el hash sobre la totalidad de los contenidos binarios de las secciones del paquete. Cualquier alteración de un solo bit en el archivo invalida la firma de inmediato.
- **Firma v3 (APK Signature Scheme v3)**: introducida en Android 9. Añade soporte para rotación de claves mediante un registro *Proof-of-rotation* firmado por la clave anterior, permitiendo a los desarrolladores renovar certificados comprometidos sin perder compatibilidad con instalaciones previas.

Podés verificar qué esquemas de firma protegen un APK de laboratorio usando `apksigner` del Android SDK:

```bash
apksigner verify --verbose --print-certs objetivo-lab.apk
```

### Comparativa arquitectónica rápida con iOS

Aunque ambos sistemas comparten el objetivo de aislar aplicaciones mediante *sandboxing* y criptografía por hardware, sus filosofías de implementación presentan diferencias clave que conviene tener presentes al cambiar de plataforma en una auditoría:

| Capa de seguridad | Android | iOS |
| :--- | :--- | :--- |
| **Núcleo y aislamiento** | Kernel Linux + UID único por app + SELinux (MAC) | Kernel XNU (Darwin) + Sandbox basado en perfiles Seatbelt/MACF y contenedores UUID |
| **Protección de código** | Firma APK (v1/v2/v3/v4) validada al instalar; bytecode DEX generalmente legible | Firma obligatoria verificada en cada ejecución por AMFI; binarios Mach-O cifrados con FairPlay en App Store |
| **Hardware criptográfico** | Android Keystore respaldado por TEE o StrongBox | Keychain Services respaldado por el **Secure Enclave Processor (SEP)** |
| **Distribución y superficie** | Ecosistema abierto (Play Store, tiendas alternativas, *sideloading* directo) | Ecosistema cerrado controlado por perfiles de aprovisionamiento y firma de Apple |
| **Comunicación entre apps** | `Intent`, `Broadcast`, `ContentProvider`, `Binder` IPC | URL Schemes, Universal Links, App Extensions, XPC |

::: nota Alcance práctico: Android frente a iOS
El **análisis dinámico** de iOS (instrumentación en tiempo real, evasión de detección de *jailbreak*, inspección de Keychain o *hooking* de métodos Swift/Objective-C) requiere hardware iOS físico compatible o un entorno **macOS** con Xcode. En cambio, el **análisis estático** inicial de paquetes iOS (`.ipa` de desarrollo o sin cifrado FairPlay) sí es completamente multiplataforma y podés ejecutarlo desde cualquier estación **Linux o Windows**.
:::

::: aviso Alineación con OWASP MASVS y MASTG
El estándar **OWASP MASVS** (*Mobile Application Security Verification Standard*) define los requisitos verificables de seguridad para aplicaciones móviles en ocho categorías principales (como `MASVS-STORAGE`, `MASVS-CRYPTO`, `MASVS-AUTH`, `MASVS-NETWORK` y `MASVS-PLATFORM`). Su guía hermana, **OWASP MASTG** (*Mobile Application Security Testing Guide*), detalla los procedimientos técnicos exactos para verificar cada control en Android e iOS. Usá ambos documentos como lista de comprobación base durante toda auditoría.
:::

## Anatomía de un archivo APK

Un archivo `.apk` (*Android Package*) es estructuralmente un contenedor ZIP estándar. Si descomprimís un APK con `unzip`, vas a observar archivos compilados que no resultan legibles directamente con un editor de texto común. Entender qué contiene cada pieza te permite saber dónde buscar secretos, configuraciones inseguras y lógica crítica.

- **`AndroidManifest.xml`**: es el mapa maestro de la aplicación. Declara el nombre del paquete, los permisos que solicita, los permisos personalizados que define, la versión mínima y objetivo de SDK (`minSdkVersion`, `targetSdkVersion`), las políticas de respaldo o depuración y todos los componentes de la app (`Activity`, `Service`, `BroadcastReceiver`, `ContentProvider`). En el APK compilado se encuentra en formato binario **AXML**.
- **`classes.dex` (y `classes2.dex`, `classes3.dex`...)**: contienen el código Java o Kotlin compilado a bytecode Dalvik (`.dex`). Cuando una aplicación supera el límite de 65.536 referencias de métodos en un único archivo DEX (*Multidex*), el compilador genera archivos numerados adicionales.
- **`resources.arsc` y carpeta `res/`**: `resources.arsc` funciona como una tabla de índices que vincula identificadores numéricos del código con cadenas de texto (`res/values/strings.xml`), diseños XML (`res/layout/`), imágenes y configuraciones de seguridad de red (`res/xml/network_security_config.xml`).
- **`lib/<abi>/*.so`**: bibliotecas nativas compiladas en C o C++ mediante el NDK para arquitecturas específicas (`arm64-v8a`, `armeabi-v7a`, `x86_64`). Suelen utilizarse para motores de juegos, procesamiento multimedia, ofuscación o rutinas criptográficas y de detección de manipulación (*anti-tampering*).
- **`assets/`**: archivos arbitrarios empaquetados sin compresión o procesado adicional (bases SQLite precargadas, certificados `.cer` o `.p12`, archivos de configuración JSON, scripts JavaScript para WebViews o cargas secundarias).
- **`META-INF/`**: almacena los archivos de firma v1 (`MANIFEST.MF`, `CERT.SF`, `CERT.RSA`) cuando el paquete incluye compatibilidad heredada.

## Flujo de análisis estático con adb, apktool y jadx

En un escenario de auditoría en caja gris o caja negra autorizada, el primer paso es obtener el APK desde el dispositivo de pruebas o emulador y convertir sus artefactos compilados en código legible.

### Extracción desde el dispositivo de pruebas con adb

Conectá tu emulador o dispositivo físico de laboratorio mediante **ADB** (*Android Debug Bridge*) y localizá la ruta exacta del paquete instalado:

```bash
adb devices
adb shell pm list packages | grep -i laboratorio
adb shell pm path com.ejemplo.laboratorio
```

Si la aplicación utiliza **Android App Bundles (AAB)** con *Split APKs*, `pm path` va a devolver múltiples rutas (`base.apk`, `split_config.arm64_v8a.apk`, `split_config.es.apk`). Descargá todas al directorio de trabajo local:

```bash
adb pull /data/app/~~hash==/com.ejemplo.laboratorio-hash==/base.apk ./muestra/
```

### Decodificación de recursos y Smali con apktool

`apktool` decodifica el `AndroidManifest.xml` binario a XML legible, extrae `resources.arsc` y desensambla los archivos `.dex` a código **Smali**, una representación intermedia muy cercana a las instrucciones del bytecode Dalvik:

```bash
apktool d ./muestra/base.apk -o ./analisis_apktool
```

¿Por qué seguimos usando `apktool` si existe `jadx`? Por dos motivos prácticos: primero, `apktool` reconstruye de forma fiel los recursos XML (`strings.xml`, `network_security_config.xml`, `AndroidManifest.xml`) sin errores de decompilación; segundo, cuando un código Java está fuertemente ofuscado y el decompilador falla en reconstruir un método complejo, la lectura directa del archivo `.smali` te muestra exactamente qué registro (`v0`, `p1`) recibe cada cadena o qué método es invocado mediante `invoke-virtual` o `invoke-static`.

### Decompilación a Java con jadx y jadx-gui

Para auditar la lógica de negocio a gran escala, `jadx` convierte el bytecode `.dex` directamente en código fuente Java aproximado. Podés abrir la interfaz gráfica con `jadx-gui ./muestra/base.apk` para navegar con clics por referencias cruzadas (`Find Usage`), o exportar todo el proyecto desde la línea de comandos para buscar patrones con `ripgrep` (`rg`):

```bash
jadx -d ./analisis_jadx --deobf ./muestra/base.apk
rg -n "Cipher\.getInstance|TrustManager|JavascriptInterface|SharedPreferences" ./analisis_jadx/sources/
```

El modificador `--deobf` instruye a `jadx` para renombrar identificadores ilegibles de un solo carácter generados por ProGuard/R8 (como clases llamadas `a.b.c`) a nombres consistentes como `C0042a`, facilitando el seguimiento durante la lectura.

### Inspección inicial de bibliotecas nativas (.so)

No te quedes solo en la capa Java/Kotlin. Muchas aplicaciones esconden claves de API, algoritmos propietarios o validaciones de licencia dentro de bibliotecas en C/C++ ubicadas en `lib/arm64-v8a/`. Un triaje estático rápido comienza verificando arquitectura, cadenas legibles y símbolos exportados vinculados a **JNI** (*Java Native Interface*):

```bash
file ./analisis_apktool/lib/arm64-v8a/libseguridad.so
nm -D ./analisis_apktool/lib/arm64-v8a/libseguridad.so | grep "Java_"
strings -n 8 ./analisis_apktool/lib/arm64-v8a/libseguridad.so | grep -Ei "key|secret|token|http"
```

Toda función nativa cuyo nombre siga la convención `Java_<paquete>_<clase>_<metodo>` representa un puente directo invocable desde Java y merece inspección profunda en herramientas de ingeniería inversa como Ghidra.

## Auditoría crítica del AndroidManifest y configuraciones

El archivo `AndroidManifest.xml` decodificado suele revelar vulnerabilidades estructurales graves antes siquiera de abrir una sola línea de código Java.

### Permisos declarados y nivel de protección

Revisá las etiquetas `<uses-permission>` aplicando el principio de mínimo privilegio (`MASVS-PLATFORM`). Una aplicación de lectura de noticias o calculadora corporativa no debería requerir `READ_SMS`, `ACCESS_FINE_LOCATION`, `READ_CALL_LOG` o `MANAGE_EXTERNAL_STORAGE`. Prestá también atención a etiquetas `<permission>` propias: si una app define un permiso personalizado para proteger un componente interno pero le asigna `android:protectionLevel="normal"`, cualquier otra aplicación instalada en el teléfono puede solicitar ese permiso y acceder al recurso sin aprobación del usuario. Para comunicación exclusiva entre apps del mismo desarrollador debe utilizarse `protectionLevel="signature"`.

### Componentes exportados y superficie de ataque IPC

Android estructura sus aplicaciones en cuatro tipos de componentes principales. Si un componente tiene `android:exported="true"` —o si en aplicaciones compiladas para API inferior a 31 declara un `<intent-filter>` sin especificar `android:exported="false"`—, cualquier aplicación de terceros o incluso comandos locales vía `adb` pueden invocarlo directamente:

1. **`Activity`**: representa una pantalla de interfaz gráfica. Si una actividad interna (por ejemplo, `AdminPanelActivity` o `TransferConfirmActivity`) queda exportada sin validar si el usuario completó el inicio de sesión o el PIN previo, un atacante puede lanzarla directamente saltándose la pantalla de autenticación:
   ```bash
   adb shell am start -n com.ejemplo.laboratorio/.ui.AdminPanelActivity
   ```
2. **`Service`**: ejecuta operaciones en segundo plano. Un servicio exportado sin verificación de permisos (`checkCallingPermission`) permite a aplicaciones maliciosas enviar comandos arbitrarios, reiniciar sincronizaciones o extraer datos devueltos mediante `Messenger` o AIDL.
3. **`BroadcastReceiver`**: escucha eventos del sistema o de otras apps. Un receptor exportado acepta `Intent` falsificados (por ejemplo, simular un evento de pago confirmado o cambio de configuración), mientras que enviar información sensible mediante `sendBroadcast()` sin especificar un paquete destino ni permiso permite que cualquier receptor malicioso escuche esos datos.
4. **`ContentProvider`**: gestiona el acceso estructurado a bases de datos o archivos mediante URIs `content://`. Un proveedor exportado sin restricciones granulares (`readPermission`, `writePermission`, `grantUriPermissions`) suele derivar en tres fallas clásicas: exposición directa de registros, **SQL Injection** cuando los parámetros `projection` o `selection` se concatenan en consultas SQLite locales, y **Path Traversal** en implementaciones vulnerables de `openFile()` que no normalizan segmentos `../`. Podés validar la exposición en laboratorio ejecutando:
   ```bash
   adb shell content query --uri content://com.ejemplo.laboratorio.provider/usuarios
   ```

### Secretos, claves embebidas, allowBackup y debuggable

En `AndroidManifest.xml`, buscá inmediatamente dos atributos críticos dentro de la etiqueta `<application>`:

- **`android:debuggable="true"`**: nunca debe llegar a compilaciones de producción. Permite conectar depuradores JDWP directamente al proceso de la app y ejecutar comandos dentro de su sandbox usando `adb shell run-as com.ejemplo.laboratorio` sin necesidad de permisos `root`.
- **`android:allowBackup="true"`** (que históricamente fue el valor por defecto si se omitía): habilita la extracción del directorio privado de datos mediante copias de seguridad ADB en versiones compatibles o su transferencia no cifrada en la nube. En compilaciones modernas orientadas a Android 12+ (`API 31+`), además de fijar `android:allowBackup="false"`, verificá `android:dataExtractionRules` para confirmar que no se respalden tokens ni bases sensibles.

A la par del manifiesto, escaneá el proyecto decodificado en busca de credenciales hardcodeadas en `res/values/strings.xml`, clases `BuildConfig.java`, archivos `google-services.json` o constantes estáticas. Es habitual encontrar claves de administración de AWS (`AKIA...`), secretos de firma JWT, tokens de Firebase con reglas permisivas o URLs de entornos internos de desarrollo.

### Auditoría de `network_security_config.xml`

Desde Android 9 (API 28), el tráfico HTTP en texto plano está deshabilitado por defecto. Sin embargo, muchos desarrolladores desactivan esta protección para agilizar pruebas o integrar servidores heredados mediante `android:usesCleartextTraffic="true"` en el manifiesto o a través de un archivo `res/xml/network_security_config.xml` mal diseñado.

Observá el siguiente ejemplo de configuración **insegura** que expone el tráfico a ataques *Man-in-the-Middle* y acepta certificados instalados por el usuario en producción:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

En contraste, una configuración **endurecida** para producción prohíbe el tráfico en texto claro, confía exclusivamente en las autoridades certificadoras del sistema (restringiendo los certificados de usuario solo a compilaciones `debug-overrides`) y aplica *Certificate Pinning* sobre el dominio de la API con un pin de respaldo:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.ejemplo-seguro.local</domain>
        <pin-set expiration="2027-12-31">
            <pin digest="SHA-256">47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</pin>
            <pin digest="SHA-256">9hN+4bL2kP0vX8mQ1rT5yU7wZ3cE6gJ9lN2pS4vY6zA=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

## Análisis estático multiplataforma de paquetes iOS (.ipa)

Aunque no cuentes con una Mac ni un iPhone de pruebas en tu laboratorio, podés ejecutar la auditoría estática completa de un paquete **`.ipa`** (*iOS App Store Package*) de desarrollo o sin cifrado FairPlay directamente desde **Linux o Windows**:

1. **Descompresión del contenedor ZIP:** un archivo `.ipa` es un archivo ZIP estándar que contiene la carpeta `Payload/<NombreApp>.app/`:
   ```bash
   unzip muestra-lab.ipa -d ./analisis_ipa
   ls -la ./analisis_ipa/Payload/*.app/
   ```
2. **Lectura de `Info.plist`, permisos y URL Schemes:** el archivo `Info.plist` suele estar en formato binario (*bplist*). Podés convertirlo a XML legible en Linux/Windows con `plistutil` (`libplist-utils`) o con el módulo estándar `plistlib` de Python para revisar permisos de privacidad (`NSCameraUsageDescription`, `NSLocationWhenInUseUsageDescription`), esquemas personalizados (`CFBundleURLSchemes`) expuestos a secuestro de enlaces (*URL Scheme Hijacking*) y listas de apps consultables (`LSApplicationQueriesSchemes`):
   ```bash
   python3 -c 'import plistlib, pprint; pprint.pprint(plistlib.load(open("./analisis_ipa/Payload/AppLab.app/Info.plist", "rb")))'
   ```
3. **Revisión de App Transport Security (ATS):** dentro de `Info.plist`, buscá el diccionario `NSAppTransportSecurity`. La presencia de `NSAllowsArbitraryLoads = True` desactiva globalmente la exigencia de HTTPS con TLS moderno en toda la aplicación, mientras que `NSExceptionAllowsInsecureHTTPLoads` habilita tráfico en texto claro para dominios puntuales que deben justificarse formalmente.
4. **Inspección de binarios Mach-O:** el ejecutable principal (`Payload/<NombreApp>.app/<NombreApp>`) y los frameworks internos (`Frameworks/*.framework/`) usan formato **Mach-O**. Desde Linux o Windows podés verificar banderas de compilación defensiva (`PIE`, *Stack Canary*, `ARC`), extraer URLs/secretos y analizar funciones sin cifrar mediante **`strings`**, **`rabin2`** (del paquete Radare2) o **Ghidra**:
   ```bash
   rabin2 -I ./analisis_ipa/Payload/AppLab.app/AppLab | grep -iE "pic|canary|nx|crypto"
   strings -n 8 ./analisis_ipa/Payload/AppLab.app/AppLab | grep -Ei "http://|api_key|secret|token"
   ```

Desde el enfoque **Purple Team**, toda compilación iOS de producción debe mantener **ATS habilitado sin `NSAllowsArbitraryLoads`**, reemplazar URL Schemes ambiguos por **Universal Links** verificados vía `apple-app-site-association`, compilar con **PIE + ARC + Stack Canaries** activos y evitar credenciales estáticas dentro de `Info.plist` o del binario Mach-O.

### OWASP Mobile Top 10:2024, Play Integrity, Flutter/React Native y flujo dinámico iOS

- **Mapeo OWASP Mobile Top 10 (edición final 2024):** estructura los hallazgos de tu auditoría sobre las diez categorías vigentes: **`M1`** *Improper Credential Usage*, **`M2`** *Inadequate Supply Chain Security*, **`M3`** *Insecure Authentication/Authorization*, **`M4`** *Insufficient Input/Output Validation*, **`M5`** *Insecure Communication*, **`M6`** *Inadequate Privacy Controls*, **`M7`** *Insufficient Binary Protections*, **`M8`** *Security Misconfiguration*, **`M9`** *Insecure Data Storage* y **`M10`** *Insufficient Cryptography*.
- **Atestación con Google Play Integrity API:** sustituye al antiguo SafetyNet para verificar desde backend si la petición proviene de una instalación auténtica desde Play Store en un dispositivo Android no manipulado (mitigando ataques automatizados y *repackaging* cuando la decisión se valida criptográficamente en servidor).
- **Intercepción en frameworks híbridos (`Flutter` y `React Native`):** en apps **React Native** el tráfico JS suele pasar por las APIs HTTP nativas del SO (aunque puede exigir desactivar pinning en Android/OkHttp); en cambio **Flutter** compila Dart AOT incluyendo **BoringSSL** propio que **ignora el almacén de certificados de usuario del sistema**, por lo que en auditorías autorizadas sobre compilaciones de prueba se recurre a parches (`reFlutter`) o *hooks* Frida sobre `ssl_crypto_x509_session_verify_cert_chain`.
- **Flujo conceptual de análisis dinámico en iOS (`Frida` / `Objection`):** mientras Android permite instrumentar emuladores estándar fácilmente, **en iOS existen límites técnicos estrictos**: los ejecutables descargados de App Store llegan cifrados con *FairPlay* y el sistema impide cargar librerías no firmadas. Un análisis dinámico real requiere un **iPhone físico con *jailbreak*** en laboratorio o un paquete **`.ipa` de desarrollo sin cifrar reempaquetado con `FridaGadget`** y firmado con perfil de desarrollador válido, sobre el cual `frida` y `objection -g <App> explore` permiten auditar Keychain, `NSUserDefaults` y pinning TLS en tiempo de ejecución.

## Automatización del análisis estático con MobSF en Docker

Cuando necesitás auditar múltiples versiones de una aplicación o establecer una primera línea base rápida antes de pasar al análisis manual, **MobSF** (*Mobile Security Framework*) automatiza la descompilación, el escaneo del manifiesto, la búsqueda de secretos por patrones y entropía, la revisión de protecciones binarias en archivos `.so` (como *NX*, *PIE*, *Stack Canary* y *RELRO*) y el mapeo de hallazgos contra **OWASP MASVS**.

Para desplegarlo de forma limpia, efímera y aislada exclusivamente en tu interfaz local (`127.0.0.1`) mediante Docker, ejecutá:

```bash
docker run -it --rm --name mobsf-lab -p 127.0.0.1:8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Una vez iniciado el contenedor, accedé desde el navegador local a `http://127.0.0.1:8000`, cargá el archivo `.apk` de laboratorio y esperá a que concluya el análisis estático. MobSF también expone una API REST local (autenticada mediante la clave mostrada en el panel web o en los logs de inicio del contenedor) que te permite automatizar la carga y descarga del reporte JSON dentro de un flujo de trabajo reproducible:

```bash
curl -F "file=@./muestra/base.apk" http://127.0.0.1:8000/api/v1/upload -H "Authorization: TU_API_KEY_LOCAL"
```

::: aviso Criterio técnico frente a falsos positivos
Nunca entregues un reporte generado automáticamente por MobSF o cualquier otro escáner SAST sin validación manual. Las herramientas automáticas suelen marcar URLs de esquemas XML estándar (como `http://schemas.android.com/...`) como tráfico inseguro o reportar cadenas en Base64 inofensivas como secretos filtrados. Tu valor como auditor reside en confirmar si un componente marcado como exportado es realmente explotable, si una clave encontrada otorga acceso efectivo y qué impacto real tiene sobre la confidencialidad o integridad de los datos.
:::

## Práctica guiada en laboratorio

En tu estación de trabajo aislada, prepará un APK vulnerable de práctica (como InsecureBankv2, DIVA o Mastg-Hacking-Playground) y ejecutá el flujo completo de auditoría estática:

1. Levantá el contenedor local de MobSF en `127.0.0.1:8000` y subí el APK para generar la línea base automatizada.
2. En paralelo, decodificá el mismo APK con `apktool d` y decompilalo con `jadx -d`.
3. Inspeccioná `AndroidManifest.xml` y `res/xml/network_security_config.xml` (si existe) para inventariar todos los componentes con `android:exported="true"`, permisos peligrosos y banderas `allowBackup` / `debuggable`.
4. Buscá en el árbol de código Java decompilado y en `res/values/strings.xml` posibles secretos embebidos, algoritmos criptográficos débiles (`ECB`, `DES`, `MD5`) y consultas SQL concatenadas dentro de `ContentProvider`.
5. Contrastá tus hallazgos manuales con el reporte de MobSF, descartando falsos positivos y documentando la evidencia exacta (archivo, línea y fragmento de configuración).

::: practica Entregable mínimo
Un informe técnico breve en Markdown con: (a) tabla de componentes exportados identificados en `AndroidManifest.xml` indicando su riesgo y vector de invocación por ADB; (b) evaluación de los atributos de seguridad (`allowBackup`, `debuggable`, `network_security_config.xml` y esquemas de firma detectados por `apksigner`); y (c) al menos dos hallazgos estáticos verificados manualmente comparados frente a la salida de MobSF, con su referencia exacta al requisito de **OWASP MASVS** correspondiente.
:::

::: defensa Perspectiva defensiva y mitigación
La mitigación temprana de fallas estáticas en Android se integra directamente en el ciclo de desarrollo seguro (DevSecOps):
- **Principio de menor exposición en el manifiesto**: declarará explícitamente `android:exported="false"` en cada `Activity`, `Service`, `BroadcastReceiver` y `ContentProvider` que no deba ser invocado por aplicaciones externas. Si un componente debe ser público, protegelo con `android:permission` de nivel `signature` o validá estrictamente la identidad del llamador y sanitizá cada dato recibido en el `Intent` o URI.
- **Compilaciones de producción endurecidas**: configurá los perfiles `release` en `build.gradle` para garantizar `debuggable false`, `allowBackup false` (o reglas estrictas en `dataExtractionRules`), activación de ofuscación y reducción de código con **R8/ProGuard**, y firma obligatoria con esquemas **v2 y v3**.
- **Tráfico y secretos**: eliminá cualquier credencial estática del código cliente y de los recursos; delegá operaciones privilegiadas al backend. Configurá `network_security_config.xml` bloqueando el tráfico en texto claro (`cleartextTrafficPermitted="false"`), deshabilitando CAs de usuario en `release` y aplicando *pinning* con claves de respaldo.
- **Puertas de calidad automatizadas**: integrá herramientas SAST específicas de móvil (`mobsfscan`, reglas de Semgrep para Android y escáneres de secretos en Git) dentro del pipeline CI/CD para bloquear *merges* que introduzcan configuraciones inseguras.
:::

## Preguntas de repaso

**1. ¿Por qué la firma APK v1 resulta insuficiente frente a ataques de manipulación como Janus y qué resuelve la firma v2?** La firma v1 (JAR signing) calcula hashes únicamente sobre las entradas registradas en el índice del contenedor ZIP y no protege la totalidad de los bytes del archivo ni las cabeceras agregadas antes del bloque ZIP; esto permitió anteponer un DEX malicioso sin invalidar la firma. La firma v2 inserta un bloque dedicado antes del *ZIP Central Directory* y verifica criptográficamente el contenido binario íntegro de las secciones del paquete, rechazando cualquier byte modificado o añadido.

**2. ¿Qué diferencia práctica existe entre el aislamiento por UID de Linux y las políticas de SELinux en Android?** El aislamiento por UID aplica control de acceso discrecional (DAC) para que el directorio y los procesos de cada aplicación pertenezcan a un usuario Linux exclusivo e inaccesible para otras apps. SELinux añade un control de acceso obligatorio (MAC) en modo *enforcing* que restringe las acciones permitidas del proceso según su dominio (como `untrusted_app`), impidiendo acceder a dispositivos, sockets o rutas del sistema incluso si existen permisos POSIX laxos o un fallo de escalada local.

**3. ¿En qué escenario conviene inspeccionar el código Smali generado por `apktool` en lugar de depender exclusivamente de `jadx`?** Cuando una aplicación emplea ofuscadores agresivos, estructuras de control anómalas o instrucciones de bytecode que confunden al decompilador Java de `jadx` (provocando errores de reconstrucción o código incompleto), el código Smali extraído por `apktool` ofrece una representación exacta y sin pérdidas de las instrucciones Dalvik reales que ejecutará el runtime ART.

**4. ¿Qué riesgos introduce declarar un `ContentProvider` con `android:exported="true"` sin permisos ni validación adecuada?** Cualquier aplicación instalada en el dispositivo puede consultar o modificar los datos mediante URIs `content://`, provocando fuga de información sensible, inyección SQL si los parámetros `projection` o `selection` se concatenan directamente en consultas SQLite, y *Path Traversal* si el método `openFile()` construye rutas de archivo a partir de segmentos de URI sin sanitizar.

**5. ¿Por qué `android:debuggable="true"` y `<certificates src="user" />` dentro de `network_security_config.xml` no deben llegar nunca a una compilación de producción?** `android:debuggable="true"` permite adjuntar depuradores JDWP al proceso en ejecución y acceder al almacenamiento privado de la app mediante `adb shell run-as`. Por su parte, confiar en `<certificates src="user" />` dentro de la configuración base habilita que cualquier certificado raíz instalado manualmente en el almacén de usuario del dispositivo sea aceptado por la app, facilitando la interceptación TLS sin modificar el binario.

## Antes de avanzar

Ya dominás la lectura estructural, la inspección del manifiesto, la decompilación y el escaneo automatizado de una aplicación Android en reposo. Antes de pasar a ejecutar la aplicación y manipular su comportamiento en tiempo real, asegurate de cumplir con estos puntos de control:

::: nota Puerta de salida
- Podés descomponer un APK con `apktool` y `jadx`, ubicando el manifiesto, los recursos y las bibliotecas `.so`.
- Sabés identificar componentes exportados peligrosos, configuraciones débiles (`allowBackup`, `debuggable`, tráfico en texto claro) y esquemas de firma v1/v2/v3.
- Tenés levantado y probado tu entorno local de **MobSF** en Docker y comprendés la diferencia entre un hallazgo automático y uno verificado manualmente.
:::

## Referencias y estándares abiertos

- **OWASP Mobile Application Security Verification Standard (MASVS)**: https://mas.owasp.org/MASVS/
- **OWASP Mobile Application Security Testing Guide (MASTG)**: https://mas.owasp.org/MASTG/
- **Android Developers — Security Overview & App Signing**: https://developer.android.com/privacy-and-security/security-tips
- **Android Developers — Network Security Configuration**: https://developer.android.com/privacy-and-security/security-config
- **Mobile Security Framework (MobSF) — Documentación oficial**: https://mobsf.github.io/docs/
