# WinAudit

**Auditoría de procesos y eventos de Windows con PowerShell.**

WinAudit permite buscar procesos por PID o nombre, verificar firmas Authenticode y hashes, consultar eventos históricos y capturar evidencia durante un intervalo. Genera informes locales y árboles de procesos; descubre equipos de Active Directory mediante LDAP/LDAPS o RSAT y consulta inventarios remotos mediante WinRM. VirusTotal es una integración avanzada, opcional y desactivada por defecto.

> **v0.4.0-alpha — pre-release para pruebas.** Hay pruebas automatizadas con datos y conexiones simulados en Windows PowerShell 5.1 y PowerShell 7. Sigue pendiente la validación operativa con registros reales, un dominio, hosts remotos y una cuenta autorizada de VirusTotal. WinAudit no determina automáticamente si un proceso es malicioso.

[Descargar v0.4.0-alpha](https://github.com/DarkCristian/WinAudit/releases/tag/v0.4.0-alpha) · [Guía de uso](docs/USAGE.md) · [Modelo de seguridad y limitaciones](docs/SECURITY.md) · [Workflow aprobado](https://github.com/DarkCristian/WinAudit/actions/runs/42114961065)

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
| Local | Windows y Windows PowerShell 5.1 o PowerShell 7; permisos adecuados para cada fuente |
| LDAP/LDAPS | Runtime de Windows con `System.DirectoryServices.Protocols`, DNS y acceso autorizado al directorio |
| LDAPS | Conectividad al puerto elegido y certificado validado normalmente por Windows |
| Proveedor RSAT | Módulo PowerShell `ActiveDirectory` instalado |
| WinRM | Host con WinRM ya configurado, nombre DNS y credenciales/permisos remotos autorizados |
| VirusTotal | Activación explícita y API key propia con licencia apropiada para el uso previsto |

WinAudit no necesita compilación. No habilita WinRM, no modifica el firewall ni cambia las políticas de auditoría. Ejecutarlo con elevación puede permitir acceso a registros protegidos, pero no concede permisos en AD ni en equipos remotos.

## Instalación y ejecución

### 1. Archivo independiente

Descargá [WinAudit-Standalone.ps1](https://github.com/DarkCristian/WinAudit/releases/download/v0.4.0-alpha/WinAudit-Standalone.ps1) desde los Assets de la release y ejecutalo:

```powershell
.\WinAudit-Standalone.ps1
```

Incluye los módulos propios en un archivo; no requiere Git. También podés [revisar el código actual](dist/WinAudit-Standalone.ps1). `main` puede avanzar después de la publicación: para reproducir esta versión, usá el asset o el tag `v0.4.0-alpha`.

### 2. Repositorio con Git

```powershell
git clone https://github.com/DarkCristian/WinAudit.git
cd WinAudit
.\WinAudit.ps1
```

Para actualizar esa copia de `main`, ejecutá `git pull`. Para clonar la versión publicada:

```powershell
git clone --branch v0.4.0-alpha https://github.com/DarkCristian/WinAudit.git
```

### 3. Bootstrapper mediante IRM

```powershell
irm https://raw.githubusercontent.com/DarkCristian/WinAudit/main/install.ps1 | iex
```

Descarga el script y sus módulos a una carpeta temporal, inicia el menú y elimina esos archivos al finalizar normalmente. Los informes se conservan por separado. No instala RSAT ni eleva privilegios. Un cierre abrupto puede impedir la limpieza.

`irm | iex` ejecuta código remoto de una rama que puede cambiar. Revisá el código antes de ejecutarlo; el bootstrapper no verifica un checksum fijado a esta release. No se cambia automáticamente la política de ejecución de PowerShell.

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

## Versión, SHA y validación

| Identificador | Valor |
| --- | --- |
| Release | [v0.4.0-alpha](https://github.com/DarkCristian/WinAudit/releases/tag/v0.4.0-alpha) |
| Commit del tag (SHA-1 de Git) | `c2375ea6f57602dc0e74ab6518d16eda300de673` |
| Blob Git del standalone | `74e3279018772eed9cc09e561c6310aa3bde5f73` |
| SHA-256 de `WinAudit-Standalone.ps1` | `ae1faec8d0e407f8c56b4f35637a390ff1b9e1c130cd3af3b6d11a6afec34875` |
| Archivo de sumas | [SHA256SUMS.txt](https://github.com/DarkCristian/WinAudit/releases/download/v0.4.0-alpha/SHA256SUMS.txt) |
| SHA-256 del propio archivo de sumas | `82806d09aacb94740903a2553b9922ff912b0b507caf274652f690a52b6a9d6e` |

Los SHA-1 identifican objetos Git; el SHA-256 verifica los bytes del asset. Podés comprobarlo sin ejecutarlo:

```powershell
$esperado = 'ae1faec8d0e407f8c56b4f35637a390ff1b9e1c130cd3af3b6d11a6afec34875'
$obtenido = (Get-FileHash -LiteralPath '.\WinAudit-Standalone.ps1' -Algorithm SHA256).Hash
if ($obtenido -ine $esperado) { throw 'SHA-256 distinto del publicado.' }
```

[Workflow aprobado](https://github.com/DarkCristian/WinAudit/actions/runs/42114961065): sintaxis, ensamblado, fechas, eventos sintéticos, captura, árbol, hashes, VirusTotal simulado y pruebas de LDAP/LDAPS/RSAT/WinRM simulados, en PowerShell 5.1 y 7. El artefacto incluye el standalone probado y su checksum. Esto no sustituye la validación contra sistemas reales autorizados.

La documentación de `main` puede recibir correcciones después del tag sin cambiar el asset publicado.

## Documentación y licencia

- [Guía de uso](docs/USAGE.md): modos, parámetros, ejemplos e informes.
- [Modelo de seguridad y limitaciones](docs/SECURITY.md): confianza, permisos, credenciales, datos y fuentes incompletas.
- [Licencia MIT](LICENSE).
