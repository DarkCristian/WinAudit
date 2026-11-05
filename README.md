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

> **Versión Alpha para pruebas.** El archivo independiente tiene verificadas la sintaxis y la apertura/salida del menú en Windows PowerShell 5.1 y PowerShell 7 mediante [GitHub Actions](https://github.com/DarkCristian/WinAudit/actions/runs/42099606247). Las auditorías reales de procesos, registros, WinRM y AD todavía requieren validación en un entorno Windows autorizado. No debe considerarse una herramienta completa de adquisición forense.

## Funciones

| Función | Estado |
| --- | --- |
| Consola ASCII interactiva con menús numéricos | Implementada |
| Inventario local de procesos, PID, PID padre y líneas de comandos | Implementado |
| Firma Authenticode y hash SHA-256 del ejecutable de un PID activo seleccionado | Implementados |
| Correlación de eventos por PID e intervalo horario | Implementación inicial |
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

Descargá **WinAudit-Standalone.ps1** desde los **Assets** de la [pre-release v0.1.0-alpha](https://github.com/DarkCristian/WinAudit/releases/tag/v0.1.0-alpha) y ejecutalo:

```powershell
.\WinAudit-Standalone.ps1
```

También podés consultar el [archivo independiente actual en main](dist/WinAudit-Standalone.ps1).

Incluye los módulos propios en un solo archivo y no requiere Git. RSAT sigue siendo opcional para descubrir equipos de Active Directory; WinRM sigue siendo necesario para el inventario remoto.

**Nota sobre esta pre-release:** el asset `.ps1` contiene la corrección del ensamblado publicada después del tag original. Los archivos automáticos **Source code** corresponden al tag anterior a esa corrección. Para probar el archivo independiente corregido, descargá el asset **WinAudit-Standalone.ps1**. El detalle y su SHA-256 están publicados en las notas de la pre-release.

### Ejemplos sin menú interactivo

Desde una copia del repositorio:

```powershell
.\WinAudit.ps1 -FullScan
.\WinAudit.ps1 -PIDToAudit 1234 -StartTime '2026-01-01 10:00' -EndTime '2026-01-01 11:00'
.\WinAudit.ps1 -ComputerName pc001.ad.example.com
```

Si utilizás el archivo independiente, reemplazá `WinAudit.ps1` por `WinAudit-Standalone.ps1`.

## Menú

Los textos de la consola actualmente están en inglés. Estas son las opciones y su función:

| Opción | Texto de la consola | Acción |
| --- | --- | --- |
| 1 | List local processes | Mostrar procesos locales |
| 2 | Investigate PID + Windows event logs | Investigar un PID y sus coincidencias en registros de Windows |
| 3 | Remote process inventory (WinRM) | Consultar procesos de un equipo remoto |
| 4 | Active Directory computer inventory | Descubrir equipos registrados en AD |
| 5 | Full local process inventory + JSON report | Exportar el inventario local completo de procesos a JSON |
| 0 | Exit | Salir |

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
