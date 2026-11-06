# WinAudit

**Auditoría de procesos y eventos de Windows con PowerShell.**

WinAudit permite buscar procesos por PID o nombre, verificar firmas Authenticode y hashes, consultar eventos históricos y capturar evidencia durante un intervalo. Genera informes locales y árboles de procesos; descubre equipos de Active Directory mediante LDAP/LDAPS o RSAT y consulta inventarios remotos mediante WinRM. VirusTotal es una integración avanzada, opcional y desactivada por defecto.

> **v0.5.0-alpha — pre-release para pruebas.** Hay pruebas automatizadas con datos y conexiones simulados en Windows PowerShell 5.1 y PowerShell 7. Sigue pendiente la validación operativa con registros reales, un dominio, hosts remotos y una cuenta autorizada de VirusTotal. WinAudit no determina automáticamente si un proceso es malicioso.

[Código corregido](dist/WinAudit-Standalone.ps1) · [Guía de uso](docs/USAGE.md) · [Modelo de seguridad y limitaciones](docs/SECURITY.md) · [Workflow aprobado](https://github.com/DarkCristian/WinAudit/actions/runs/42142511491)

> **v0.5.0-alpha:** incluye las correcciones de seguridad, chequeo de PowerShell y actualización opcional con confirmación S/N. [Descargar release](https://github.com/DarkCristian/WinAudit/releases/tag/v0.5.0-alpha) · [Revisión y alcance](docs/SECURITY_REVIEW.md).

## Funciones y alcance

| Función | Implementación actual |
| --- | --- |
| Procesos locales | Nombre, PID, PID padre, creación, ruta y argumentos, cuando Windows permite leerlos |
| Búsqueda | Nombre exacto del ejecutable, sin distinguir mayúsculas; devuelve todos los PID activos coincidentes |
| Eventos históricos | PID o nombre, inicio y fin; consulta registros locales existentes de Security, PowerShell y Sysmon |
| Captura por horario | Espera hasta el inicio y consulta hasta el fin, dentro de la sesión abierta; no crea tareas programadas |
| Árbol de procesos | Instantáneas con identidad PID + creación; TXT y pantalla con MD5, Signature y firmante |
| Archivos | Firma Authenticode y SHA-256, MD5 o ambos; resultados correspondientes al archivo leído en disco |
| Active Directory | LDAPS o LDAP firmado/cifrado sin RSAT; proveedor RSAT disponible como alternativa |
| WinRM | Inventario de procesos de un host autorizado, directamente o seleccionado desde el inventario de AD |
| VirusTotal | Consulta de informes por SHA-256 y enriquecimiento local voluntario; sin subidas de archivos |
| Informes | JSON, eventos JSONL y árbol TXT; la salida depende del modo utilizado |
| Pendientes | Informes HTML, escaneo por lotes y clasificación avanzada de riesgos |

`-FullScan` exporta el inventario local completo de procesos: no realiza un análisis antivirus completo, ni un escaneo de red o de todos los archivos. Los eventos, la captura y la evidencia del árbol son locales; WinRM actualmente ofrece inventario remoto de procesos.

## Requisitos

| Uso | Requisitos |
| --- | --- |
| Local | Windows actualizado y Windows PowerShell 5.1, o PowerShell estable 7.4.21+, 7.5.12+ o 7.6.7+ en su rama; permisos adecuados para cada fuente |
| LDAP/LDAPS | Runtime de Windows con `System.DirectoryServices.Protocols`, DNS y acceso autorizado al directorio |
| LDAPS | Conectividad al puerto elegido y certificado validado normalmente por Windows |
| Proveedor RSAT | Módulo PowerShell `ActiveDirectory` instalado |
| WinRM | Host con WinRM ya configurado, nombre DNS y credenciales/permisos remotos autorizados |
| VirusTotal | Activación explícita y API key propia con licencia apropiada para el uso previsto |

WinAudit no necesita compilación. No habilita WinRM, no modifica el firewall ni cambia las políticas de auditoría. Ejecutarlo con elevación puede permitir acceso a registros protegidos, pero no concede permisos en AD ni en equipos remotos.

## Instalación y ejecución

### 1. Archivo independiente

Para las correcciones de seguridad, descargá el [standalone de v0.5.0-alpha](https://github.com/DarkCristian/WinAudit/releases/download/v0.5.0-alpha/WinAudit-Standalone.ps1) y comprobá el SHA-256 indicado más abajo antes de ejecutarlo:

```powershell
.\WinAudit-Standalone.ps1
```

Incluye los módulos propios en un archivo; no requiere Git. También podés [revisar el código actual](dist/WinAudit-Standalone.ps1). `main` puede avanzar después de la publicación: para reproducir el código corregido fijado por el launcher, usá el commit y SHA-256 de la sección de seguridad. El asset de `v0.4.0-alpha` corresponde a la versión anterior.

### 2. Repositorio con Git

```powershell
git clone https://github.com/DarkCristian/WinAudit.git
cd WinAudit
.\WinAudit.ps1
```

Para actualizar esa copia de `main`, ejecutá `git pull`. Solo para reproducir la publicación anterior sin estas correcciones:

```powershell
git clone --branch v0.4.0-alpha https://github.com/DarkCristian/WinAudit.git
```

### 3. Bootstrapper mediante IRM

```powershell
irm https://raw.githubusercontent.com/DarkCristian/WinAudit/main/install.ps1 | iex
```

Descarga un único standalone desde un commit inmutable, comprueba su SHA-256 fijado en el launcher y recién entonces inicia el menú. Rechaza una descarga alterada. Usa una carpeta temporal local y mantiene el archivo bloqueado contra escritura durante la ejecución; limpia al finalizar normalmente. No instala RSAT ni eleva privilegios.

El primer `irm | iex` todavía confía en el launcher recibido de `main`: su hash interno no autentica al propio launcher. Para mayor control, descargá y revisá `install.ps1` antes de ejecutarlo o fijá una revisión aprobada. No se cambia la política de ejecución ni se omiten certificados.

## PowerShell: aviso y actualización opcional

Si detecta una versión conocida afectada, pregunta **S/N** antes de actualizar. Usa WinGet y, si no está disponible o falla, ofrece un MSI oficial con SHA-256 y firma Microsoft verificados. Tras el intento exige una sesión nueva. En Windows PowerShell 5.1 ofrece abrir Windows Update; no deduce las KB por el número de versión. Para automatizaciones usá `-NonInteractive`: no instala ni pregunta y detiene versiones conocidas afectadas. [Comportamiento, permisos y límites](docs/USAGE.md#chequeo-y-actualización-de-powershell).

## Menú

| Opción | Acción |
| --- | --- |
| 1 | Mostrar procesos locales |
| 2 | Consultar eventos históricos por PID o nombre, con inicio y fin |
| 3 | Inventario remoto de procesos mediante WinRM |
| 4 | Descubrir equipos mediante LDAP/LDAPS o RSAT y seleccionar un host para WinRM |
| 5 | Inventario local completo de procesos e informe JSON |
| 6 | Buscar un ejecutable activo por nombre exacto |
| 7 | Capturar eventos hasta un horario futuro |
| 8 | Verificar firma y hashes de un archivo |
| 9 | Avanzado: configurar o consultar VirusTotal de forma opcional |
| 0 | Salir |

## Ejemplos rápidos

Los ejemplos usan la copia del repositorio. Sustituí `WinAudit.ps1` por `WinAudit-Standalone.ps1` si usás el archivo independiente.

```powershell
# Todos los PID activos de un ejecutable
.\WinAudit.ps1 -FindProcess 'example.exe'

# Eventos históricos por PID o por nombre
.\WinAudit.ps1 -PIDToAudit 1234 -Start '01-01-2026 10:00:00' -End '01-01-2026 11:00:00'
.\WinAudit.ps1 -FindProcess 'example.exe' -Start '2026-01-01 10:00:00' -End '2026-01-01 11:00:00'

# Captura local: mantener abierta la terminal
.\WinAudit.ps1 -FindProcess 'example.exe' -Monitor -End ((Get-Date).AddMinutes(10))

# Firma y ambos hashes de un archivo
.\WinAudit.ps1 -FilePath 'C:\Example\example.exe' -HashAlgorithm Both

# Descubrir equipos sin RSAT con la identidad actual
.\WinAudit.ps1 -DirectoryServer dc01.ad.example.com -DirectoryProtocol LDAPS -DirectoryNameFilter 'PC-*' -EnabledOnly

# Inventario WinRM con credenciales remotas independientes
$credRemota = Get-Credential
.\WinAudit.ps1 -ComputerName pc001.ad.example.com -RemoteCredential $credRemota
```

Las fechas usan la hora local del equipo donde corre WinAudit. Se aceptan `dd-MM-yyyy HH:mm:ss`, `yyyy-MM-dd HH:mm:ss` y objetos `[datetime]`; los segundos son opcionales en los formatos de texto. El fin debe ser posterior al inicio. Un fin futuro requiere captura con `-Monitor`.

## LDAP/LDAPS, RSAT y WinRM

LDAP/LDAPS y RSAT consultan el directorio. WinRM consulta el host. Un objeto registrado o habilitado en AD no demuestra que el equipo esté encendido o sea accesible.

- **LDAPS**, predeterminado: puerto 636, TLS y validación normal de certificado.
- **LDAP**: puerto 389 con firma y sellado de sesión SASL; no es simple bind sin protección ni StartTLS.
- **Autenticación**: Kerberos por defecto; Negotiate solo cuando se solicita explícitamente.
- **RSAT**: alternativa mediante `Get-ADComputer`; solo este proveedor necesita `ActiveDirectory`.
- **WinRM**: Kerberos por defecto; HTTPS y puerto alternativo cuando se solicitan. No modifica TrustedHosts ni omite certificados.

La opción 4 permite indicar OU, patrón y credenciales, consultar el inventario y elegir una de las primeras 100 filas mostradas para WinRM. Las credenciales de AD no se reutilizan automáticamente para el host. La consulta usa paginación y marca los resultados limitados mediante `QueryTruncated`.

### RSAT opcional

Solo si elegís el proveedor RSAT, desde una copia del repositorio:

```powershell
Get-Module -ListAvailable ActiveDirectory
.\Install-Prerequisites.ps1
```

Si falta y decidís instalarlo, abrí Windows PowerShell elevado:

```powershell
.\Install-Prerequisites.ps1 -Install
```

El instalador usa los mecanismos de Microsoft disponibles para Windows cliente o Server. Su compatibilidad depende de la edición, políticas y origen de componentes. Este paso modifica Windows de forma explícita; no es necesario para LDAP/LDAPS ni para WinRM.

## VirusTotal opcional

La opción 9 permite cargar una clave propia para la sesión y consultar manualmente un SHA-256. Cargar la clave no activa consultas automáticas: el enriquecimiento se habilita por separado. Por comando, requiere `-VirusTotal` explícito y `VIRUSTOTAL_API_KEY` ya configurada; la variable por sí sola no activa consultas.

Solo recupera informes existentes por hash. No sube archivos ni logs y no solicita reanálisis. El proveedor recibe el hash, la clave y los datos normales de conexión. Hay caché y límites locales; los errores no se convierten en una clasificación de seguridad.

Usá una cuenta/licencia compatible con los [términos del proveedor](https://docs.virustotal.com/reference/public-vs-premium-api), que restringen el uso de la API pública en determinados contextos comerciales y empresariales. Ver [configuración y resultados](docs/USAGE.md#virustotal-opcional) y [privacidad de la clave](docs/SECURITY.md#virustotal-y-claves).

## Informes y límites de la evidencia

Por defecto se guardan en `%USERPROFILE%\WinAudit-Reports`. Podés cambiar la carpeta con `-ReportDirectory`. Los informes reales pueden incluir usuarios, rutas y argumentos: mantenelos fuera del repositorio y con acceso restringido.

En el árbol se muestra este formato ilustrativo:

```text
example.exe PID 1010 | MD5: <32 caracteres hexadecimales> | Signature: Valid | Firmante: CN=Example Publisher
```

Una firma válida no garantiza seguridad; `NotSigned` no significa malicioso y `NoDisponible` indica evidencia que no se pudo leer. Los PID se reutilizan, las instantáneas pueden perder procesos breves y los registros pueden faltar o llegar tarde. No hay análisis de memoria ni detección concluyente de malware.

## Revisión de seguridad de main

El bootstrapper fija el standalone del commit `c27df4f1a99fabbf13e7c0e8a588ff0c2b930f90`, SHA-256 `00f203f1d5824b64c2ad56bb810a48126be6ee96587013ca96e8ae79ebd12368`. Incluye controles de rutas locales, rechazo de junctions/reparse points, XML sin DTD, saneamiento de pantalla y límites de consulta. Los JSON conservan la evidencia cruda.

Las lecturas de archivo y los informes rechazan UNC, unidades de red, ADS y reparse points. Eventos: `-MaxEventsPerLog` predeterminado 10000, máximo 100000 por registro/consulta; un recorte se marca `Limitado`. Ver [revisión de seguridad](docs/SECURITY_REVIEW.md).

## Versión, SHA y validación

| Identificador | Valor |
| --- | --- |
| Release | [v0.5.0-alpha](https://github.com/DarkCristian/WinAudit/releases/tag/v0.5.0-alpha) |
| Commit inmutable del standalone fijado por el launcher | `c27df4f1a99fabbf13e7c0e8a588ff0c2b930f90` |
| SHA-256 de WinAudit-Standalone.ps1 | `00f203f1d5824b64c2ad56bb810a48126be6ee96587013ca96e8ae79ebd12368` |
| Sumas de los assets | [SHA256SUMS.txt](https://github.com/DarkCristian/WinAudit/releases/download/v0.5.0-alpha/SHA256SUMS.txt) |

El commit fijado identifica los mismos bytes del standalone publicado; el tag incluye además el launcher actualizado y la documentación final. Comprobá el SHA-256 antes de ejecutar. La release v0.4.0-alpha es anterior a estas correcciones.


## Documentación y licencia

- [Guía de uso](docs/USAGE.md): modos, parámetros, ejemplos e informes.
- [Modelo de seguridad y limitaciones](docs/SECURITY.md): confianza, permisos, credenciales, datos y fuentes incompletas.
- [Licencia MIT](LICENSE).
