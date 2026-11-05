# Guia de uso

WinAudit se ejecuta en Windows con Windows PowerShell 5.1 o PowerShell 7. Usa `WinAudit.ps1` desde el repositorio o reemplazalo por `WinAudit-Standalone.ps1` para el archivo independiente.

## Buscar un ejecutable activo

```powershell
.\WinAudit.ps1 -FindProcess 'example.exe'
```

La busqueda es por nombre exacto, sin distinguir mayusculas, sin ruta ni comodines. Devuelve todos los PID activos que coincidan, PID padre, fecha de creacion, ruta y linea de comandos cuando Windows permite leerlos. Exporta un informe JSON incluso si no hay coincidencias. `-ProcessName` es un alias de `-FindProcess`.

En el menu, usa la opcion **6**.

## Consultar eventos historicos

Por PID:

```powershell
.\WinAudit.ps1 -PIDToAudit 1234 -Start '01-01-2026 10:00:00' -End '01-01-2026 11:00:00'
```

Por nombre del ejecutable, aunque el proceso haya terminado:

```powershell
.\WinAudit.ps1 -FindProcess 'example.exe' -Start '01-01-2026 10:00:00' -End '01-01-2026 11:00:00'
```

`-Start` y `-End` son alias de `-StartTime` y `-EndTime`. Se admiten `dd-MM-yyyy HH:mm:ss` y `yyyy-MM-dd HH:mm:ss`, con segundos opcionales. El formato se interpreta explicitamente, sin depender de la configuracion regional. Tambien se aceptan objetos `[datetime]`.

El intervalo usa la **hora local del equipo donde se ejecuta WinAudit**. El informe incluye la zona horaria. El fin debe ser posterior al inicio. Para un fin futuro se requiere `-Monitor`.

En el menu, usa la opcion **2**: elegi PID o nombre e ingresa inicio y fin. En una consulta historica, dejar inicio vacio toma las ultimas 24 horas y dejar fin vacio toma la hora actual.

La busqueda por nombre examina campos estructurados de ejecutables, como `Image`, `NewProcessName`, `ProcessName`, `ApplicationName`, `SourceImage`, `TargetImage` y `ParentImage`. No busca texto libre en mensajes ni adivina PID a partir de procesos activos. Los eventos sin esos campos no se pueden asociar por nombre. Una coincidencia con `ParentImage` o `SourceImage` puede referirse a un proceso relacionado; el informe identifica el campo.

## Capturar eventos hasta un horario futuro

Para empezar ahora y finalizar dentro de diez minutos:

```powershell
.\WinAudit.ps1 -FindProcess 'example.exe' -Monitor -End ((Get-Date).AddMinutes(10))
```

Para esperar hasta un inicio futuro y capturar durante diez minutos:

```powershell
$inicio = (Get-Date).AddMinutes(5)
$fin = $inicio.AddMinutes(10)
.\WinAudit.ps1 -FindProcess 'example.exe' -Monitor -Start $inicio -End $fin -PollSeconds 5
```

Tambien funciona con `-PIDToAudit 1234` en lugar de `-FindProcess`. Usa un solo selector por captura. Para nombres, se pueden encontrar eventos de un proceso que todavia no existe al iniciar WinAudit.

En el menu, usa la opcion **7**, selecciona PID o nombre e ingresa el intervalo. Un inicio vacio toma la hora actual. Ingresa un fin futuro.

**Mantene WinAudit y la terminal abiertos hasta finalizar.** La captura es local y funciona en la sesion actual: no crea una tarea programada ni un servicio, no persiste despues de cerrar PowerShell y no garantiza actividad durante suspension o apagado del equipo. Ctrl+C interrumpe la captura; los eventos ya escritos permanecen en disco. La limpieza del resumen al interrumpir depende de que PowerShell pueda ejecutar el bloque de cierre.

Cada captura crea:

- `capture-....jsonl`: un evento por linea, con mensaje y XML original, guardado progresivamente.
- `capture-....json`: selector, intervalo solicitado, zona horaria, estado, cantidad de coincidencias, ultima consulta y disponibilidad de los registros.
- `capture-....-processes.json`: procesos seleccionados y descendientes observados, identificados por PID y fecha de creacion; conserva primera y ultima observacion.
- `capture-....-tree.txt`: informe legible con arbol de procesos, relaciones de eventos y limitaciones de las fuentes.

El arbol usa instantaneas de `Win32_Process` durante la captura. Solo enlaza un hijo con un padre observado cuya fecha de creacion sea compatible; conserva instancias separadas si se reutiliza un PID. Los procesos breves entre consultas pueden faltar. Los eventos de creacion (Sysmon 1 y Security 4688) y de acceso entre procesos (Sysmon 8/10), si estan disponibles entre las coincidencias, aparecen en una seccion separada con sus PID, GUID cuando existen y registro de evidencia. Un acceso entre procesos no se presenta como parentesco ni como prueba de actividad maliciosa. No se agregan procesos no respaldados por datos.

Consulta cada cinco segundos por defecto (`-PollSeconds` acepta de 1 a 300), solapa las lecturas y deduplica por registro, ID y fecha del evento. Al terminar realiza una ultima lectura con dos segundos de margen. Una captura puede incluir el tramo historico si se indica un inicio pasado. Eventos escritos demasiado tarde, eliminados, no registrados o perdidos por retencion pueden faltar. Una captura sin coincidencias no demuestra ausencia de actividad.

No habilita los logs de Security, PowerShell o Sysmon, no instala Sysmon y no modifica politicas. Informa fuentes inaccesibles o registros parcialmente interpretados. La captura puede finalizar con limitaciones aunque haya encontrado eventos en otras fuentes.

## Firmas, SHA-256 y MD5

Desde la opcion **8** del menu, ingresa la ruta del archivo y elegi SHA-256, MD5 o ambos. Por comando:

```powershell
.\WinAudit.ps1 -FilePath 'C:\Example\example.exe' -HashAlgorithm Both
.\WinAudit.ps1 -FilePath 'C:\Example\example.exe' -HashAlgorithm MD5
```

`-HashAlgorithm` admite `SHA256` (predeterminado), `MD5` y `Both`. Se muestra la firma Authenticode y se exporta un JSON. En una investigacion historica, el mismo parametro elige el hash de los ejecutables activos accesibles del selector:

```powershell
.\WinAudit.ps1 -FindProcess 'example.exe' -Start '01-01-2026 10:00:00' -End '01-01-2026 11:00:00' -HashAlgorithm Both
```

Los hashes corresponden al archivo en disco en el momento de leerlo, no a su contenido historico ni a la memoria del proceso. MD5 es util para comparar identificadores existentes, pero no para demostrar integridad frente a manipulacion intencional. No se consultan ni envian hashes a servicios externos.

## Otros modos

```powershell
.\WinAudit.ps1
.\WinAudit.ps1 -FullScan
.\WinAudit.ps1 -ComputerName pc001.ad.example.com
```

El inventario remoto usa `Get-Credential` e `Invoke-Command` con WinRM configurado y acceso autorizado. `-ComputerName` no se combina con busqueda, intervalos ni captura en esta version. AD requiere RSAT ActiveDirectory y credenciales autorizadas para el directorio.

Los informes se guardan por defecto en `%USERPROFILE%\WinAudit-Reports`, fuera del repositorio. Cambia la ruta con `-ReportDirectory`. No publiques informes reales.

## Generar el archivo independiente

No requiere compilacion ni dependencias externas:

```powershell
.\tools\Build-Standalone.ps1
.\tools\Build-Standalone.ps1 -Check
.\tests\Features.Tests.ps1
```

El generador concatena los modulos y la interfaz sin sustituciones de expresiones regulares que puedan alterar cadenas PowerShell. Las pruebas usan eventos sinteticos y no sustituyen una validacion funcional contra los logs, permisos, WinRM y AD de un entorno Windows autorizado.
