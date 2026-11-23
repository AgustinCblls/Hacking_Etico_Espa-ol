::: nota Objetivo de la lección
Configurar un laboratorio dinámico seguro con emulador Android y proxy interceptivo, auditar controles de **SSL/TLS Pinning** mediante instrumentación con **Frida** y **objection**, evaluar las vulnerabilidades en tiempo de ejecución más críticas en plataformas móviles y aplicar técnicas de triage de malware Android y **análisis forense** en dispositivos Android e iOS.
:::

El análisis estático te muestra lo que la aplicación declara que puede hacer; el análisis dinámico revela lo que realmente hace cuando procesa sesiones reales, intercambia tráfico con su API y escribe estado en el dispositivo. Para estudiar ese comportamiento sin comprometer hardware personal ni redes productivas, todo el trabajo se ejecuta sobre dispositivos virtuales dedicados o teléfonos de laboratorio aislados, combinando depuración por **ADB**, interceptación TLS controlada, instrumentación en memoria y extracción forense de artefactos.

## Laboratorio dinámico seguro con emulador Android y ADB

Para auditar aplicaciones de prueba en profundidad necesitás acceso administrativo sobre el entorno de ejecución. En Android Studio AVD, creá una máquina virtual seleccionando una imagen **Google APIs** (evitá las imágenes *Google Play*, ya que bloquean `adb root` y restringen la escritura en la partición del sistema). Si requerís un sistema con partición `/system` escribible para instalar certificados raíz del sistema o herramientas nativas, iniciá el emulador desde consola con soporte de escritura temporal:

```bash
emulator -avd Pixel_Lab_API33 -writable-system -no-snapshot-load
adb wait-for-device
adb root
adb remount
```

Verificá la conectividad y mantené a mano los comandos esenciales de **ADB** para inspeccionar procesos, registros en tiempo real y redirección de puertos hacia tu estación de análisis:

```bash
adb devices -l
adb shell ps -A | grep com.ejemplo.laboratorio
adb logcat --pid=$(adb shell pidof -s com.ejemplo.laboratorio)
adb reverse tcp:8080 tcp:8080
```

La instrucción `adb reverse tcp:8080 tcp:8080` mapea el puerto `8080` interno del emulador (`127.0.0.1:8080`) directamente al puerto `8080` de tu máquina anfitriona donde escucha tu proxy de inspección, evitando exponer el proxy a la red local o lidiar con reglas de firewall del adaptador puente.

::: peligro Aislamiento de muestras y red de laboratorio
Al analizar aplicaciones desconocidas o muestras sospechosas de malware, deshabilitá carpetas compartidas con el host, usá instantáneas limpias del emulador y canalizá todo el tráfico saliente a través de una red virtual aislada o una interfaz *host-only* con captura controlada, sin acceso directo a tu red corporativa ni cuentas reales.
:::

## Interceptación HTTP/S y auditoría de SSL/TLS Pinning

Desde Android 7.0 (API 24), las aplicaciones confían por defecto únicamente en las Autoridades Certificadoras (CA) instaladas en el almacén del sistema (`/system/etc/security/cacerts/`), ignorando los certificados instalados por el usuario salvo que el desarrollador los habilite expresamente en `network_security_config.xml`.

### Instalación de certificado de proxy en el almacén del sistema

Para auditar tráfico HTTPS con un proxy local (como Burp Suite o mitmproxy) en un emulador rooteado de laboratorio, exportá el certificado raíz del proxy en formato PEM/DER, calculá su hash antiguo de OpenSSL y copialo con el formato `<hash>.0`:

```bash
openssl x509 -inform DER -in burp_ca.der -out burp_ca.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp_ca.pem | head -n 1)
cp burp_ca.pem "${HASH}.0"
adb push "${HASH}.0" /system/etc/security/cacerts/
adb shell chmod 644 "/system/etc/security/cacerts/${HASH}.0"
adb reboot
```

En Android 14+ (API 34+), los certificados raíz del sistema residen dentro de un módulo APEX inmutable (`/apex/com.android.conscrypt/cacerts/`), por lo que en entornos de prueba modernos suele recurrirse a un montaje `tmpfs` en memoria sobre esa ruta o a módulos de laboratorio específicos para replicar el almacén de confianza sin alterar imágenes firmadas.

### Evasión de SSL/TLS Pinning con Frida y objection

Incluso con la CA del proxy instalada en el sistema, muchas aplicaciones financieras o corporativas implementan **Certificate Pinning** (mediante `network_security_config.xml`, `okhttp3.CertificatePinner` o bibliotecas nativas) para aceptar únicamente la clave pública exacta de su servidor. En una auditoría de caja gris o negra, necesitás comprobar cómo responde el backend manipulando peticiones, lo cual exige deshabilitar temporalmente el *pinning* en tu emulador de laboratorio mediante **Frida**.

Descargá el binario `frida-server` correspondiente a la arquitectura del emulador (`x86_64` o `arm64`), transferilo a `/data/local/tmp/` y ejecutalo en segundo plano:

```bash
adb push frida-server-16.x-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server -D &"
frida-ps -Uai
```

Frida inyecta un motor JavaScript (QuickJS/V8) dentro del proceso de la aplicación objetivo y permite reemplazar (*hookear*) implementaciones de métodos Java o funciones nativas C/C++ en tiempo real. El siguiente script de ejemplo intercepta la clase `okhttp3.CertificatePinner` para neutralizar la verificación del pin en un entorno autorizado:

```javascript
Java.perform(function () {
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCertificates) {
            console.log("[+] Pinning omitido en OkHttp para: " + hostname);
            return;
        };
    } catch (err) {
        console.log("[-] OkHttp CertificatePinner no presente: " + err);
    }
});
```

Lanzá la aplicación bajo instrumentación desde el inicio (*spawn*) con:

```bash
frida -U -f com.ejemplo.laboratorio -l bypass_pinning.js
```

Para tareas repetitivas sin escribir scripts desde cero, **objection** (construido sobre Frida) ofrece comandos interactivos inmediatos para explorar clases en memoria, deshabilitar múltiples implementaciones comunes de *pinning*, listar actividades y volcar el almacén de datos:

```bash
objection -g com.ejemplo.laboratorio explore
# Dentro de la consola interactiva de objection:
android sslpinning disable
android hooking list classes
android keystore list
```

## Vulnerabilidades móviles frecuentes en tiempo de ejecución

Una vez interceptado el tráfico y conectado al runtime de la app, centrá las pruebas dinámicas en cuatro familias de debilidades recurrentes en Android:

### Almacenamiento inseguro y exposición de secretos locales

Las aplicaciones frecuentemente persisten tokens de sesión, PINs o datos personales sin cifrar dentro de su directorio privado o en almacenamiento compartido. En un entorno con privilegios de laboratorio, revisá inmediatamente:
- **`SharedPreferences`**: archivos XML en `/data/data/<paquete>/shared_prefs/`. Buscá credenciales o claves de API guardadas con `MODE_WORLD_READABLE` (obsoleto pero aún visto en código heredado) o en texto plano cuando debería usarse `EncryptedSharedPreferences`.
- **Bases SQLite sin cifrar**: ubicadas en `/data/data/<paquete>/databases/`. Verificá si contienen historial de transacciones o PII legible directamente con `sqlite3`.
- **Logs y caché**: revisá `adb logcat` mientras autenticás un usuario; es común encontrar contraseñas, JWT completos o respuestas JSON sensibles impresas mediante `Log.d()`. Verificá también el archivo `Cache.db` o cachés HTTP de OkHttp en `/data/data/<paquete>/cache/`, y confirmá que las pantallas críticas apliquen `FLAG_SECURE` para impedir capturas de pantalla en el selector de aplicaciones recientes.

### Abuso de Deep Links e Intent Redirection

Los **Deep Links** con esquemas personalizados (por ejemplo, `labapp://transferir?monto=100&destino=X`) carecen de verificación de propiedad del dominio: cualquier app maliciosa instalada en el dispositivo puede registrar el mismo esquema para interceptar tokens OAuth, o lanzar un enlace manipulado contra la aplicación víctima. Incluso los **App Links** (`https://`) fallan si el archivo `/.well-known/assetlinks.json` está mal configurado o si `android:autoVerify="true"` se omite.

El patrón de **Intent Redirection** ocurre cuando un componente exportado recibe un `Intent` que contiene otro `Intent` anidado dentro de un *extra* (por ejemplo, `getParcelableExtra("next_intent")`) y lo reenvía directamente a `startActivity(nextIntent)` o `setResult()`. Como la llamada parte desde el proceso de la propia aplicación víctima, un atacante puede forzar a la app a abrir actividades internas no exportadas (`android:exported="false"`) o incluso acceder a `ContentProvider` privados propagando `FLAG_GRANT_READ_URI_PERMISSION`.

### WebViews inseguros y puentes JavaScript

El componente `WebView` permite renderizar contenido web dentro de la app nativa, pero varias configuraciones lo convierten en una superficie crítica:
- **`setJavaScriptEnabled(true)` + `@JavascriptInterface`**: si la aplicación expone objetos Java al contexto JavaScript mediante `addJavascriptInterface(objeto, "AndroidBridge")` y además carga URLs controlables por el usuario (vía Deep Link o parámetros HTTP sin *allowlist* estricta de dominio HTTPS), cualquier código JavaScript ejecutado en ese WebView podrá invocar métodos nativos de Java con los permisos de la app.
- **`setAllowFileAccess(true)` y `setAllowUniversalAccessFromFileURLs(true)`**: habilitan que un script cargado mediante esquema `file://` lea archivos locales del sandbox privado de la aplicación (como bases de datos o XML de `SharedPreferences`).
- **Ignorar errores TLS**: sobreescribir `WebViewClient.onReceivedSslError()` llamando incondicionalmente a `handler.proceed()` anula toda validación de certificados HTTPS dentro del WebView.

### Autenticación biométrica sin CryptoObject

Implementar `BiometricPrompt` únicamente mediante sus callbacks de éxito o fallo (`onAuthenticationSucceeded`) representa una falla clásica de control de acceso en el cliente (`MASVS-AUTH`). Si la operación posterior (como liberar la sesión o descifrar un token) no depende criptográficamente de un `BiometricPrompt.CryptoObject` vinculado a una clave del Android Keystore configurada con `setUserAuthenticationRequired(true)`, un auditor con Frida puede invocar o forzar el callback `onAuthenticationSucceeded(null)` sin presentar huella válida alguna y desbloquear la aplicación.

## Triage inicial de malware móvil Android

Cuando analizás un APK sospechoso recibido en un incidente (triage defensivo), combinás inspección estática rápida con observación controlada en sandbox para identificar capacidades maliciosas típicas de troyanos bancarios y *spyware*:

1. **Permisos de alto impacto**: prestá máxima atención a solicitudes de `BIND_ACCESSIBILITY_SERVICE` (los servicios de accesibilidad permiten leer todo el contenido de la pantalla de otras apps, capturar contraseñas e inyectar pulsaciones automatizadas), `RECEIVE_SMS` y `READ_SMS` (robo de códigos OTP), `SYSTEM_ALERT_WINDOW` (superposición de ventanas falsas o *overlays* sobre aplicaciones bancarias legítimas) y `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` (persistencia en segundo plano).
2. **Carga dinámica de código (`DexClassLoader`)**: gran parte del malware evita incluir su lógica destructiva en el `classes.dex` principal para evadir firmas estáticas. En su lugar, almacena un payload cifrado dentro de `assets/` o lo descarga de un servidor C2, lo descifra en memoria o disco temporal y lo carga dinámicamente mediante `dalvik.system.DexClassLoader` o `InMemoryDexClassLoader`, invocando sus métodos por reflexión Java.
3. **Evasión de análisis**: el malware suele comprobar propiedades como `ro.kernel.qemu`, la existencia de binarios `su`, o puertos abiertos de Frida (`27042`) antes de ejecutar su payload.

Durante el triage en tu emulador aislado, podés usar Frida para interceptar llamadas a `DexClassLoader` y volcar la ruta del archivo DEX secundario antes de que sea eliminado:

```javascript
Java.perform(function () {
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.implementation = function (dexPath, optimizedDir, librarySearchPath, parent) {
        console.log("[!] Carga dinámica detectada desde: " + dexPath);
        return this.$init(dexPath, optimizedDir, librarySearchPath, parent);
    };
});
```

### Seguridad del canal celular: `SIM Swapping`, `SS7` y fragilidad del SMS como 2FA

En Latinoamérica y servicios financieros digitales, el **SMS como segundo factor de autenticación (2FA)** constituye un riesgo operativo severo que no depende de vulnerar la aplicación móvil sino la red telefónica subyacente:
- **SIM Swapping (portabilidad o duplicación fraudulenta):** mediante ingeniería social en centros de atención o abuso interno en operadoras móviles, un atacante transfiere la línea de la víctima a una nueva SIM/eSIM bajo su control. Al recibir llamadas y códigos SMS OTP, logra restablecer accesos bancarios, billeteras virtuales y correos de recuperación.
- **Debilidades estructurales de SS7 y Diameter:** las redes celulares heredadas intercambian señalización mediante **SS7** (y **Diameter** en 4G) con escasa autenticación mutua entre operadoras internacionales, permitiendo históricamente a nodos comprometidos desviar SMS de autenticación o geolocalizar líneas sin interacción del usuario.
- **Defensa y mitigación recomendada:** **abandonar el SMS como 2FA** para cuentas críticas o bancarias y migrar hacia **FIDO2 / Passkeys**, aprobaciones criptográficas vinculadas a dispositivo (*in-app signing* con llave en Keystore/Secure Enclave) o TOTP local; en entidades financieras y plataformas móviles, consultar señales antifraude de operadora (*SIM Swap Check* / antigüedad de activación de SIM) antes de autorizar cambios de clave o transferencias de alto valor.

## Fundamentos de forense móvil en Android e iOS

En una investigación de respuesta a incidentes o análisis forense digital (DFIR), la prioridad absoluta es preservar la integridad de la evidencia y mantener la cadena de custodia: documentá cada acción, aislá el dispositivo de la red (modo avión, desactivación de Wi-Fi/Bluetooth o bolsa Faraday para evitar borrado remoto) y calculá hashes SHA-256 de toda extracción obtenida.

### Adquisición y artefactos clave en Android

Según el nivel de acceso permitido por el dispositivo y la autorización legal/técnica, se distinguen extracciones **lógicas** (vía ADB, backups o agentes forenses que copian archivos accesibles del sistema de archivos) y extracciones **físicas** (volcado bit a bit de particiones de memoria flash como `userdata` mediante modos de fabricante como EDL, *custom recovery* o acceso `root` forense).

Entre los artefactos prioritarios en Android se destacan:
- **Registros volátiles**: capturá cuanto antes los buffers del sistema antes de que roten o se reinicie el equipo (`adb logcat -d -b all > logcat_completo.txt` y `adb shell dumpsys > dumpsys.txt`), ya que `dumpsys usagestats` y `dumpsys battery` revelan actividad reciente de aplicaciones aunque hayan sido cerradas.
- **Bases SQLite de comunicación y navegación**: ubicadas dentro de `/data/data/`:
  - Mensajes y contactos del sistema: `/data/data/com.android.providers.telephony/databases/mmssms.db` y `/data/data/com.android.providers.contacts/databases/contacts2.db`.
  - Navegador Chrome: `/data/data/com.android.chrome/app_chrome/Default/History` (historial y descargas) y `Login Data`.
  - Apps de mensajería: bases locales (por ejemplo, tablas de mensajes y contactos en `msgstore.db` o `wa.db` cuando se dispone de acceso al contenedor o clave de respaldo).
- **Cuentas y preferencias**: `/data/system/users/0/accounts_ce.db` y archivos XML en `shared_prefs/`. Recordá inspeccionar también los archivos `-wal` (*Write-Ahead Logging*) junto a cada `.db` SQLite, ya que transacciones recientes pueden no haberse consolidado aún en el archivo principal.

Podés consultar tablas y convertir marcas de tiempo Unix (en milisegundos para `mmssms.db`) directamente con `sqlite3`:

```bash
sqlite3 mmssms.db "SELECT address, datetime(date/1000, 'unixepoch', 'localtime'), body FROM sms ORDER BY date DESC LIMIT 20;"
```

### Análisis forense de backups y artefactos en iOS

Debido al cifrado basado en hardware y al estricto aislamiento de iOS, gran parte del trabajo forense en escenarios corporativos o de laboratorio parte de **backups lógicos completos estilo iTunes/Finder** (generados con `idevicebackup2` de `libimobiledevice` o herramientas forenses comerciales). Un backup de iOS organiza los archivos mediante sus hashes SHA-1 en subcarpetas de dos caracteres (`ab/ab12cd34...`) y mantiene el índice maestro en una base SQLite llamada **`Manifest.db`**, acompañada de **`Info.plist`**, **`Status.plist`** y **`Manifest.plist`** (que indica si el respaldo está cifrado con contraseña).

En `Manifest.db`, la tabla `Files` relaciona cada `fileID` (nombre del archivo hash en disco) con su dominio original (`domain`, como `HomeDomain` o `AppDomain-com.ejemplo.app`) y ruta relativa (`relativePath`):

```bash
sqlite3 Manifest.db "SELECT fileID, domain, relativePath FROM Files WHERE relativePath LIKE '%.sqlite%' OR relativePath LIKE '%.db';"
```

Otros artefactos esenciales en iOS incluyen:
- **Property Lists (`.plist`)**: archivos de configuración en formato binario o XML que almacenan preferencias, historial de redes Wi-Fi (`com.apple.wifi.plist`) y metadatos del sistema. Podés convertir `.plist` binarios a XML legible en Linux con `plistutil -i archivo.plist -o salida.xml` o leerlos en Python con el módulo estándar `plistlib`.
- **Bases SQLite nativas de iOS**: `sms.db` (SMS/iMessage), `AddressBook.sqlitedb` (contactos), `CallHistory.storedata` (registro de llamadas) y `KnowledgeC.db` (base de conocimiento de actividad del sistema: bloqueos de pantalla, uso de apps y conexiones).
- **Marcas de tiempo Mac Absolute Time (Cocoa Core Data)**: a diferencia del Epoch Unix (1 de enero de 1970), la mayoría de las bases SQLite y archivos `.plist` de iOS almacenan fechas en segundos (o nanosegundos) transcurridos desde el **1 de enero de 2001 a las 00:00:00 UTC**, lo que equivale a sumar `978307200` segundos al Epoch Unix al convertir con `sqlite3`:

```bash
sqlite3 sms.db "SELECT text, datetime(date/1000000000 + 978307200, 'unixepoch', 'localtime') FROM message LIMIT 10;"
```

## Práctica guiada en laboratorio

En tu emulador Android Studio aislado (imagen Google APIs) junto con una aplicación móvil vulnerable de laboratorio:

1. Levantá el emulador con privilegios `adb root`, configurá `adb reverse tcp:8080 tcp:8080` y registrá el certificado CA de tu proxy en `/system/etc/security/cacerts/` para interceptar tráfico HTTPS estándar.
2. Instalá e iniciá `frida-server` en el emulador, cargá la app objetivo mediante `frida -U -f` con un script JS personalizado (u `objection`) para deshabilitar el control de **SSL/TLS Pinning** y verificá que las peticiones de la API aparecen descifradas en el proxy.
3. Revisá dinámicamente el directorio `/data/data/<paquete>/` en busca de secretos en `shared_prefs/` o SQLite, y probá un componente con `WebView` o *Deep Link* enviando parámetros controlados por `adb shell am start -a android.intent.action.VIEW -d "..."`.
4. Tomá un snapshot o captura forense lógica del directorio privado de la app y de `adb logcat -d`, consultá una base SQLite con `sqlite3` convirtiendo sus marcas de tiempo y calculá el hash SHA-256 de la evidencia recolectada.

::: practica Entregable mínimo
Un registro técnico de laboratorio que contenga: (a) evidencia del tráfico HTTPS interceptado tras el *hook* de Frida/objection (incluyendo el fragmento de script utilizado); (b) captura o transcripción de al menos una vulnerabilidad dinámica confirmada (almacenamiento inseguro, *Deep Link*/`Intent` redirection, WebView o biometría sin `CryptoObject`); y (c) salida de consulta `sqlite3` sobre un artefacto forense extraído junto al hash SHA-256 del paquete de evidencia.
:::

::: defensa Perspectiva defensiva y mitigación
Para proteger aplicaciones móviles y responder ante incidentes de forma eficaz:
- **Pinning robusto y validación en servidor**: implementá *Certificate Pinning* con pines de respaldo y rotación planificada mediante `network_security_config.xml` o bibliotecas nativas, recordando siempre que cualquier control del cliente puede ser alterado en dispositivos comprometidos; toda autorización crítica debe validarse en el servidor.
- **Almacenamiento cifrado y biometría criptográfica**: guardá tokens y preferencias sensibles con `EncryptedSharedPreferences` (respaldado por Android Keystore) o SQLCipher, aplicá `FLAG_SECURE` en pantallas sensibles, limpiá registros `Log.*` en compilaciones `release` y vinculá `BiometricPrompt` obligatoriamente a un `CryptoObject`.
- **Endurecimiento de WebViews y Deep Links**: deshabilitá `setAllowFileAccess` y `setAllowUniversalAccessFromFileURLs`, validá estrictamente el esquema y dominio HTTPS antes de exponer `@JavascriptInterface`, y verificá App Links mediante `assetlinks.json` sin reenviar jamás objetos `Intent` recibidos desde extras no confiables.
- **Visibilidad y preparación forense**: centralizá telemetría de seguridad en el backend (detección de anomalías de sesión y revocación inmediata de tokens), y mantené procedimientos documentados de preservación, cálculo de hashes y manejo de backups cifrados para investigaciones DFIR.
:::

## Preguntas de repaso

**1. ¿Por qué instalar el certificado de un proxy en el almacén de usuario de Android no permite interceptar el tráfico HTTPS de aplicaciones modernas compiladas para API 24 o superior?** Porque desde Android 7.0 (API 24), la configuración de seguridad de red por defecto confía únicamente en las autoridades certificadoras del almacén del sistema (`/system/etc/security/cacerts/`) e ignora las CAs instaladas por el usuario a menos que la aplicación declare explícitamente `<certificates src="user" />` en su `network_security_config.xml`.

**2. ¿Cuál es la falla fundamental de implementar autenticación biométrica con `BiometricPrompt` sin utilizar un `CryptoObject`?** Sin un `CryptoObject` ligado a una clave del Android Keystore protegida por hardware, el resultado de la biometría depende únicamente de si se invoca el método callback `onAuthenticationSucceeded()`. Un atacante o auditor con Frida puede interceptar la verificación en memoria y forzar la ejecución de ese callback exitoso sin desbloquear ninguna clave criptográfica real.

**3. ¿Qué combinación de configuraciones convierte a un `WebView` de Android en un vector de riesgo crítico?** Habilitar JavaScript (`setJavaScriptEnabled(true)`), exponer puentes nativos con `@JavascriptInterface` o permitir acceso a archivos locales (`setAllowFileAccess` / `setAllowUniversalAccessFromFileURLs`) mientras se cargan URLs no validadas o provenientes de *Deep Links* externos sin lista blanca de dominios HTTPS.

**4. ¿Qué indicador técnico sugiere fuertemente que una muestra Android analizada en triage oculta su payload principal frente a escáneres estáticos?** La presencia de permisos intrusivos combinados (como `BIND_ACCESSIBILITY_SERVICE`, `RECEIVE_SMS` y `SYSTEM_ALERT_WINDOW`) junto con llamadas a `DexClassLoader` o `InMemoryDexClassLoader` que descifran y cargan archivos `.dex` secundarios desde `assets/` o red en tiempo de ejecución.

**5. ¿Cómo se relacionan los archivos reales dentro de un backup lógico de iOS con sus rutas originales y qué época temporal utilizan sus bases SQLite?** Cada archivo copiado se almacena nombrado según su hash SHA-1 y se indexa en la base SQLite `Manifest.db`, cuya tabla `Files` mapea el `fileID` con el `domain` y la `relativePath` original. A su vez, las marcas de tiempo suelen expresarse en *Mac Absolute Time* (segundos o nanosegundos desde el 1 de enero de 2001 UTC, es decir, sumando `978307200` segundos al Epoch Unix).

## Antes de avanzar

Ya cubriste el ciclo completo de seguridad móvil desde la arquitectura y el análisis estático hasta la instrumentación dinámica y la recolección forense. Antes de dar el salto al ámbito de las auditorías inalámbricas 802.11, comprobá que cumplís con estos objetivos:

::: nota Puerta de salida
- Sabés configurar un emulador Android aislado con `adb reverse` y certificado de sistema para inspeccionar tráfico HTTPS.
- Podés escribir y ejecutar scripts básicos de **Frida** o comandos de **objection** para auditar *SSL/TLS Pinning* y validar flujos biométricos o de *WebView*.
- Comprendés cómo identificar indicadores de carga dinámica de malware Android y cómo extraer y consultar bases SQLite y archivos `.plist` en análisis forense móvil.
:::

## Referencias y estándares abiertos

- **OWASP Mobile Application Security Testing Guide (MASTG) — Dynamic & Tampering**: https://mas.owasp.org/MASTG/
- **Frida — Dynamic Instrumentation Toolkit Documentation**: https://frida.re/docs/home/
- **Android Developers — Biometric Authentication & CryptoObject**: https://developer.android.com/training/sign-in/biometric-auth
- **Android Developers — WebView Security Best Practices**: https://developer.android.com/privacy-and-security/risks/unsafe-use-of-webview
- **libimobiledevice — Documentación de herramientas para iOS**: https://libimobiledevice.org/
