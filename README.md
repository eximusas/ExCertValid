# Validate Truststore Utility

**validate\_truststore** es una herramienta de diagnóstico en Python diseñada para identificar y resolver problemas de validación de certificados en el truststore (`cacerts`) de Java, evitando errores como:

```
PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
```

---

## Contenido

1. [Descripción](#descripción)
2. [Precondiciones](#precondiciones)
3. [Instalación](#instalación)
4. [Uso](#uso)
5. [Opciones y comprobaciones](#opciones-y-comprobaciones)
6. [Casos de diagnóstico](#casos-de-diagnóstico)

---

## Descripción

El script `validate_truststore.py` realiza los siguientes pasos:

1. **Localización del truststore**

   * Busca automáticamente `jssecacerts` o `cacerts` en el directorio `JAVA_HOME` usado por Tomcat.
2. **Carga del keystore**

   * Soporta formatos **JKS** y **PKCS12**.
3. **Listado de aliases**

   * Extrae y muestra todos los aliases (certificados) presentes.
4. **Verificación de aliases esperados**

   * Comprueba que un conjunto determinado de alias (`--expected`) esté importado.
5. **Validación de archivos de certificado externos**

   * Permite pasar uno o varios archivos `.cer` o `.pem` y verifica, por huella (SHA256), si están realmente importados.
6. **Prueba de handshake SSL**

   * Extrae el truststore a PEM y realiza un handshake TLS con un host remoto (`--host`, `--port`), detectando fallos PKIX.

---

## Precondiciones

* Tener instalado **Python 3.6+**.
* Contar con el paquete:

  ```bash
  pip install pyjks cryptography
  ```
* Disponer de:

  * Un **JDK** (o JRE) con su variable `JAVA_HOME` apuntando al directorio raíz.
  * (Opcional) Certificados externos `.cer` o `.pem` que se deseen validar.
* (Para uso del ejecutable) Ninguna dependencia adicional: el `.exe` incluye todo.

---

## Instalación

1. Clona o descarga el proyecto.
2. (Opción Python) Instala dependencias:

   ```bash
   pip install pyjks cryptography
   ```
3. (Opción ejecutable) Genera el `.exe` con PyInstaller:

   ```bash
   pyinstaller --onefile --clean validate_truststore.py --name validate_truststore
   ```

---

## Uso en Windows

1. Descarga el **validate_truststore.exe** que se encuentra en el directorio: "dist".

2. Copialo en directorio simple del Servidor, ejemplo: "C:\Utilidades".

3. Abre la terminar de Power Shell.

4. Ejecuta el comando **cd** para ubicarte en el directorio de descarga, ejemplo:

```powershell
cd C:\Utilidades
```
5. Edita los parámetros del siguiente comando, una vez ajustados copiar y pegar en la consola de Power Shell y ejecutar: 

```powershell
.\dist\validate_truststore.exe \
  --jdk "C:\Program Files\Java\jdk-21" \
  --storepass changeit \
  --expected "nosis,sectigo,usertrust" \
  --certfiles "C:\ruta\nosis.cer,C:\ruta\sectigo.cer" \
  --host sac.nosis.com \
  --port 443
```

### Parámetros principales

* `--jdk` **(requerido)**: Ruta al directorio `JAVA_HOME`.
* `--storepass`: Contraseña del truststore (por defecto `changeit`).
* `--expected`: Lista de alias esperados en el truststore (coma-separados).
* `--certfiles`: Archivos de certificado externos para validar huellas (opcional).
* `--host`, `--port`: Host y puerto para probar handshake TLS.

---

## Opciones y comprobaciones realizadas

1. **Existencia de truststore**:

   * Verifica que exista `jssecacerts` o `cacerts` en `JAVA_HOME`.
2. **Formato y carga**:

   * Detecta y carga automáticamente **JKS** o **PKCS12**.
3. **Listado de certificados**:

   * Muestra todos los aliases disponibles en el truststore.
4. **Verificación de alias**:

   * Indica si faltan alias esperados.
5. **Validación de certificados externos**:

   * Calcula huella SHA‑256 de cada `.cer`/`.pem` y comprueba si existe en el truststore.
6. **Handshake SSL/TLS**:

   * Realiza una conexión TLS al host remoto usando el truststore extraído y reporta éxito o error PKIX.

---

## Casos de diagnóstico

* **Alias faltantes**: detectará si los certificados no fueron importados correctamente.
* **Formatos incorrectos**: alertará si el truststore no es JKS ni PKCS12.
* **Contraseña inválida**: validará si la contraseña del truststore es correcta.
* **Error PKIX**: mostrará error de validación de ruta de certificación contra el servicio remoto.

---

Con **validate\_truststore** podrás diagnosticar y resolver rápidamente problemas de confianza de certificados en tu entorno Java/Tomcat.
