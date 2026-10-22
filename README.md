# Credential Detector (Montoya) - Extensión de Burp Suite

Versión en **Java / API Montoya** de la extensión Credential Detector.
A diferencia de la versión Jython, esta aprovecha la API moderna de Burp para
**resaltar las coincidencias directamente en el editor de respuesta nativo**
(solapas Pretty / Raw / Hex), usando la barra de búsqueda del editor.

## Qué hace

- Analiza **todas las respuestas HTTP** que pasan por Burp (Proxy, Repeater,
  etc.) mediante un `HttpHandler`.
- Detecta las palabras clave de la regex, tratando `_`, `-` y `.` como
  separadores intercambiables (detecta `api_key`, `api-key` y `api.key`).
- Lista cada hallazgo en una **pestaña propia** `Credential Detector` con:
  - Tabla ordenable: `#`, `Hora`, `Método`, `Host`, `URL`, `Coincidencias`,
    `Términos`.
  - Campo de **búsqueda/filtro** en vivo (Host, URL, Términos).
  - Contadores de detecciones y de respuestas HTTP analizadas.
  - Botones **Exportar CSV** y **Limpiar**.
  - **Menú contextual** (clic derecho): Enviar a Repeater, Enviar a Intruder,
    Copiar URL, Exportar CSV.
- Al seleccionar una fila, muestra la petición y la respuesta en los editores
  nativos de Burp y **resalta las coincidencias** en el visor Response
  (`setSearchExpression` con la regex).

## Requisitos para compilar

- **JDK 21 o inferior** para el bytecode (Burp solo soporta extensiones Java
  21 o menor). Se puede compilar con un JDK más nuevo usando `--release 21`.
- El JAR de la API Montoya ya está incluido en `lib/montoya-api-2026.7.jar`.
- No requiere Maven ni Gradle: se compila con `javac` + `jar`.

## Compilar

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Esto genera `CredentialDetector.jar` en esta carpeta.

Compilación manual equivalente:

```powershell
javac --release 21 -cp lib\montoya-api-2026.7.jar -d build (Get-ChildItem -Recurse src -Filter *.java).FullName
jar cfm CredentialDetector-montoya.jar manifest.txt -C build .
```

> Nota: en este equipo `jar.exe` no está en el PATH; se encuentra en
> `C:\Program Files\Java\jdk-22\bin\jar.exe`. El script `build.ps1` lo resuelve
> automáticamente.

## Instalar en Burp

1. En Burp: **Extensions > Installed > Add**.
2. **Extension type:** Java.
3. **Extension file:** seleccioná `CredentialDetector.jar`.
4. En la salida deberías ver:
   ```
   [+] Credential Detector (Montoya) cargada.
   [+] Pestana 'Credential Detector' agregada.
   [+] Analizando respuestas HTTP en busca de credenciales.
   ```

## Uso

1. Pasá tráfico por Burp (Proxy o Repeater). Para el sitio de prueba local,
   usá Repeater apuntando a `127.0.0.1:8000` (o el puerto que uses), ya que el
   navegador suele hacer bypass del proxy para `localhost`.
2. Abrí la pestaña **Credential Detector**.
3. Seleccioná una fila: en el visor **Response** las coincidencias quedan
   resaltadas por la barra de búsqueda del editor nativo.

## Estructura del proyecto

```
montoya/
├─ src/creddetector/
│  ├─ CredentialDetectorExtension.java  (entry point BurpExtension)
│  ├─ CredentialHttpHandler.java        (analiza respuestas)
│  ├─ CredentialDetectorTab.java        (UI: tabla, filtro, editores, menú)
│  ├─ DetectionTableModel.java          (modelo de la tabla)
│  ├─ Detection.java                    (una fila)
│  ├─ CredentialRegex.java              (regex + variantes de separador)
│  └─ SimpleDocListener.java            (helper de filtro)
├─ lib/montoya-api-2026.7.jar           (API, solo para compilar)
├─ manifest.txt                         (Burp-Extension-Class)
├─ build.ps1                            (script de compilación)
└─ CredentialDetector-montoya.jar       (extensión compilada)
```
