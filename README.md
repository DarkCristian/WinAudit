# WinAudit

```text
 __        ___         _             _ _ _
 \ \      / (_)_ __   / \  _   _  __| (_) |_
  \ \ /\ / /| | '_ \ / _ \| | | |/ _` | | __|
   \ V  V / | | | | / ___ \ |_| | (_| | | |_
    \_/\_/  |_|_| |_/_/   \_\__,_|\__,_|_|\__|

    AUDITOR DE SEGURIDAD Y ANALISIS FORENSE DE WINDOWS
```

**WinAudit** es una herramienta de código abierto, desarrollada en PowerShell nativo, para inventariar procesos de Windows, verificar firmas digitales, investigar eventos por PID, consultar procesos remotos mediante acceso autorizado y descubrir equipos registrados en Active Directory.

> **Versión Alpha para pruebas.** El proyecto incluye [pruebas automatizadas](https://github.com/DarkCristian/WinAudit/actions/workflows/validate-standalone.yml) para Windows PowerShell 5.1 y PowerShell 7, con eventos sintéticos, validación de fechas y comprobación del archivo independiente. Las auditorías reales de procesos, registros, WinRM y AD todavía requieren validación en un entorno Windows autorizado. No debe considerarse una herramienta completa de adquisición forense.

## Funciones

| Función | Estado |
| --- | --- |
| Consola ASCII interactiva con menús numéricos | Implementada |
| Inventario local de procesos, PID, PID padre y líneas de comandos | Implementado |
| Firma Authenticode y hashes SHA-256 / MD5 del ejecutable de un PID activo seleccionado | Implementados |
| Consulta histórica por PID o nombre e intervalo horario | Implementación inicial |
| Búsqueda exacta de ejecutables activos, con todos sus PID | Implementada |
| Captura local hasta un horario futuro, con espera y guardado progresivo | Implementada en la sesión actual |
| Informe TXT de árbol observado y relaciones de procesos | Implementado; limitado a evidencia disponible |
| Inventario de procesos remotos mediante WinRM | Implementado |
| Descubrimiento de equipos de AD mediante RSAT | Implementado |
| Exportación local de informes JSON | Implementada |
| Informes HTML, escaneo por lotes y clasificación avanzada de riesgos | Planificados |

## Requisitos

- Windows PowerShell 5.1 o PowerShell 7 en Windows, según las funciones disponibles.
- Permisos elevados para acceder a determinados datos de procesos y registros protegidos.
- WinRM configurado y acceso autorizado para el modo remoto.
- Módulo PowerShell ActiveDirectory de RSAT para descubrir equipos en AD.
- Registros de Windows habilitados y con retención suficiente para el período investigado.

## Dependencias de Active Directory — opcionales

**WinAudit no requiere compilación:** se ejecuta directamente como scripts PowerShell.

RSAT solo es necesario para descubrir objetos de equipo con `Get-ADComputer`. Las auditorías locales y las consultas remotas directas mediante WinRM no requieren RSAT.

Desde la carpeta del repositorio, comprobá si el módulo está disponible:

```powershell
Get-Module -ListAvailable ActiveDirectory
.\Install-Prerequisites.ps1
```

Si falta, abrí **Windows PowerShell como administrador** y ejecutá:

```powershell
.\Install-Prerequisites.ps1 -Install
```

El instalador utiliza los mecanismos oficiales de Windows:

| Sistema | Comando utilizado |
| --- | --- |
| Windows 10/11 Pro, Enterprise o Education, en versiones compatibles | `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` |
| Windows Server | `Install-WindowsFeature RSAT-AD-PowerShell` |

En equipos administrados, la instalación puede depender de Windows Update, de una fuente aprobada o de la autorización del administrador. RSAT puede no estar disponible en determinadas ediciones de Windows. El instalador no modifica la configuración del dominio ni habilita WinRM.

Después de instalarlo, verificá:

```powershell
Import-Module ActiveDirectory
Get-Command Get-ADComputer
```

Luego iniciá WinAudit y seleccioná la opción **[4]**, correspondiente al inventario de equipos de Active Directory.

Ejemplos de entrada:

| Campo | Ejemplo ficticio |
| --- | --- |
| Dominio | `ad.example.com` |
| Controlador de dominio | `dc01.ad.example.com` |
| Base de búsqueda opcional | `OU=Workstations,DC=ad,DC=example,DC=com` |

Las credenciales deben tener permisos de lectura sobre el directorio. Esos permisos no garantizan acceso remoto a los equipos.

## Instalación y ejecución

Podés iniciar WinAudit de tres maneras.

### Opción 1 — Clonar el repositorio con Git

Permite revisar el código, conservar los módulos localmente y actualizar el proyecto.

```powershell
git clone https://github.com/DarkCristian/WinAudit.git
cd WinAudit
.\WinAudit.ps1
```

Para actualizarlo desde la carpeta del repositorio:

```powershell
git pull
```

### Opción 2 — Bootstrapper mediante IRM

Ejecutá el siguiente comando desde PowerShell en Windows, sin instalar Git:

```powershell
irm https://raw.githubusercontent.com/DarkCristian/WinAudit/main/install.ps1 | iex
```

El bootstrapper descarga WinAudit y sus módulos en una carpeta temporal, ejecuta la consola y elimina los archivos del programa al terminar. Los informes se conservan por separado. No instala RSAT ni habilita WinRM.

**Seguridad:** `irm | iex` ejecuta código descargado de Internet. La rama `main` puede cambiar; revisá el código y preferí una revisión fijada a un commit en entornos administrados.

### Opción 3 — Descargar el archivo PowerShell independiente

Para probar las nuevas funciones de búsqueda y captura, descargá **WinAudit-Standalone.ps1** desde los **Assets** de la [pre-release v0.2.0-alpha](https://github.com/DarkCristian/WinAudit/releases/tag/v0.2.0-alpha) y ejecutalo:

```powershell
.\WinAudit-Standalone.ps1
```

Podés [revisar su código](dist/WinAudit-Standalone.ps1) antes de ejecutarlo. La versión `v0.2.0-alpha` incluye búsqueda por nombre, captura por horarios, informes de árbol y hashes SHA-256/MD5.

Incluye los módulos propios en un solo archivo y no requiere Git. RSAT sigue siendo opcional para descubrir equipos de Active Directory; WinRM sigue siendo necesario para el inventario remoto.

**Versión publicada:** el asset `.ps1` y los archivos **Source code** de `v0.2.0-alpha` corresponden al mismo código del tag. Las notas incluyen el SHA-256 del archivo y las pruebas realizadas.

### Ejemplos sin menú interactivo

Desde una copia del repositorio:

```powershell
.\WinAudit.ps1 -FullScan
.\WinAudit.ps1 -PIDToAudit 1234 -StartTime '2026-01-01 10:00' -EndTime '2026-01-01 11:00'
.\WinAudit.ps1 -ComputerName pc001.ad.example.com
```

Si utilizás el archivo independiente, reemplazá `WinAudit.ps1` por `WinAudit-Standalone.ps1`.

## Buscar procesos y consultar o capturar eventos

Búsqueda exacta de todos los PID activos de un ejecutable:

```powershell
.\WinAudit.ps1 -FindProcess 'example.exe'
```

Consulta histórica por nombre (también admite `-PIDToAudit 1234`):

```powershell
.\WinAudit.ps1 -FindProcess 'example.exe' -Start '01-01-2026 10:00:00' -End '01-01-2026 11:00:00'
```

Captura local desde ahora hasta dentro de diez minutos:

```powershell
.\WinAudit.ps1 -FindProcess 'example.exe' -Monitor -End ((Get-Date).AddMinutes(10))
```

Para un inicio futuro, agregá `-Start` con la fecha y hora deseadas. Se admiten `dd-MM-yyyy HH:mm:ss`, `yyyy-MM-dd HH:mm:ss` y objetos `[datetime]`. `-Start` y `-End` son alias de `-StartTime` y `-EndTime`. Se utiliza la hora local del equipo donde corre WinAudit.

**La terminal debe permanecer abierta.** No crea tareas programadas ni servicios. Consulta los registros existentes, guarda eventos progresivamente en JSONL y genera un resumen JSON, evidencia de procesos y un informe TXT con el árbol observado. Los vínculos de eventos se presentan por separado del parentesco. No habilita auditorías de Windows automáticamente. La búsqueda por nombre requiere que el evento registre un campo de ejecutable compatible; no garantiza encontrar toda la actividad de ese programa.

Consultá la [guía de uso](docs/USAGE.md) para conocer los campos, límites, cancelación y disponibilidad de fuentes.

## Verificar un archivo con MD5 o SHA-256

```powershell
.\WinAudit.ps1 -FilePath 'C:\Example\example.exe' -HashAlgorithm Both
```

Usá `MD5`, `SHA256` o `Both`; también están disponibles en la opción **8** del menú. El resultado incluye la firma digital y se guarda en JSON. Los hashes describen el archivo actual en disco. MD5 sirve para comparar identificadores; no demuestra integridad frente a manipulación intencional.

## Menú

| Opción | Acción |
| --- | --- |
| 1 | Mostrar procesos locales |
| 2 | Consultar eventos históricos por PID o nombre, con inicio y fin |
| 3 | Inventario remoto de procesos mediante WinRM |
| 4 | Inventario de equipos de Active Directory |
| 5 | Inventario local completo e informe JSON |
| 6 | Buscar proceso activo por nombre exacto |
| 7 | Esperar y capturar eventos hasta un horario futuro |
| 8 | Verificar archivo: firma, SHA-256, MD5 o ambos |
| 0 | Salir |

## Alcance y límites de la evidencia

Un registro de Windows puede identificar al proceso que **emitió** el evento, en lugar del proceso investigado. Además, los PID se reutilizan y no identifican de forma única un proceso histórico. WinAudit indica el campo coincidente y no deduce automáticamente que una actividad sea maliciosa.

La ausencia de firma digital no demuestra que un ejecutable sea malicioso. La investigación depende de los registros existentes: no se pueden reconstruir actividades que Windows no registró.

WinAudit consulta y exporta información; no aplica remediaciones ni modifica deliberadamente procesos, servicios, políticas de auditoría o la configuración de WinRM. Su propia ejecución puede generar registros del sistema.

Los informes pueden contener datos sensibles de los equipos auditados. Por defecto se guardan localmente en `%USERPROFILE%\WinAudit-Reports`. No publiques informes reales ni los incluyas en commits.

## Documentación

- [Guía de uso](docs/USAGE.md)
- [Modelo de seguridad y limitaciones](docs/SECURITY.md)

## Licencia

MIT. Consultá [LICENSE](LICENSE).
