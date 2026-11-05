# Guía de uso

Referencia de **main con correcciones de seguridad del 05/11/2026**, posteriores a v0.4.0-alpha. El tag y el asset anteriores no incluyen estas correcciones. Los comandos usan `WinAudit.ps1` desde el repositorio. Para el archivo independiente, reemplazá ese nombre por `WinAudit-Standalone.ps1`. Requieren Windows actualizado y Windows PowerShell 5.1, o una rama estable de PowerShell 7 con mínimo 7.4.21, 7.5.12 o 7.6.7 respectivamente. Ramas anteriores se rechazan. WinAudit no instala parches de Windows ni verifica su nivel de actualización.

[Volver al README](../README.md) · [Modelo de seguridad y limitaciones](SECURITY.md)

## Obtener y comprobar la versión

Para usar las correcciones, descargá el [standalone actual](../dist/WinAudit-Standalone.ps1), cloná `main` o usá el bootstrapper:

```powershell
# Copia actual con correcciones
git clone https://github.com/DarkCristian/WinAudit.git
cd WinAudit
.\WinAudit.ps1

# Alternativa sin Git: ejecuta código descargado de main
irm https://raw.githubusercontent.com/DarkCristian/WinAudit/main/install.ps1 | iex
```

El bootstrapper abre el menú, sin reenviar parámetros. Descarga un standalone de un commit inmutable y valida su SHA-256 antes de ejecutarlo, sin redirecciones HTTP y con timeout de 30 segundos. El propio launcher de `main` sigue siendo código remoto: descargalo y revisalo antes si necesitás aprobación previa. No instala RSAT. [Detalles y SHA del código revisado](SECURITY_REVIEW.md).

SHA-256 del standalone corregido fijado por el bootstrapper:

```text
369a7d9518a240a4a81e76a2dd7acb05146be228eb4d8ad27c2c0e0100229f14
```

```powershell
Get-FileHash -LiteralPath '.\WinAudit-Standalone.ps1' -Algorithm SHA256
```

Compará con el valor anterior para la revisión `6e883047e3b11ba19e68bc19fc2f977f745842ec`. Las sumas del asset v0.4.0-alpha corresponden al código anterior y son distintas. No cambies políticas de ejecución o protecciones para resolver un bloqueo sin conocer la política de tu entorno.

## Menú y permisos

```powershell
.\WinAudit.ps1
```

| Opción | Función | Alcance |
| --- | --- | --- |
| 1 | Mostrar procesos | Local; hasta 40 filas en pantalla |
| 2 | Investigar eventos por PID o nombre | Local; solicita intervalo y exporta JSON |
| 3 | Inventario de procesos por WinRM | Un host DNS autorizado |
| 4 | Descubrir AD y seleccionar WinRM | LDAPS, LDAP o RSAT; selección opcional del host |
| 5 | Inventario completo de procesos | Local; exporta JSON |
| 6 | Buscar un ejecutable activo | Nombre exacto y todos sus PID |
| 7 | Capturar eventos | Local; la sesión debe permanecer abierta |
| 8 | Verificar un archivo | Firma, SHA-256, MD5 o ambos |
| 9 | Avanzado: VirusTotal | Configuración y consultas opcionales |
| 0 | Salir | Finaliza el menú |

Algunos datos de procesos y registros requieren permisos elevados. La elevación local no concede acceso al dominio ni a hosts remotos. `Get-Credential` solicita credenciales; no cambia el token local ni asegura que el acceso remoto esté permitido.

## Procesos activos e inventario local

```powershell
.\WinAudit.ps1 -FindProcess 'example.exe'
.\WinAudit.ps1 -FullScan
```

`-FindProcess` busca el nombre exacto, sin distinguir mayúsculas. No admite rutas ni comodines; `-ProcessName` es su alias. Devuelve todos los PID activos coincidentes. La pantalla muestra hasta 40 filas, pero el JSON conserva los resultados recopilados.

`-FullScan` exporta el inventario local de procesos. No escanea todos los archivos, no consulta eventos de cada PID, no recorre la red ni produce un veredicto antivirus.

## Eventos históricos

Por PID:

```powershell
.\WinAudit.ps1 -PIDToAudit 1234 -Start '01-01-2026 10:00:00' -End '01-01-2026 11:00:00'
```

Por nombre, aunque el proceso haya terminado:

```powershell
.\WinAudit.ps1 -FindProcess 'example.exe' -Start '2026-01-01 10:00:00' -End '2026-01-01 11:00:00'
```

`-PID` es alias de `-PIDToAudit`. `-Start` y `-End` son alias de `-StartTime` y `-EndTime`. Usá un solo selector, PID o nombre. Un nombre sin parámetros de intervalo consulta procesos activos; con un intervalo consulta también eventos históricos. Un PID sin intervalo usa las últimas 24 horas hasta la hora actual.

### Formato y zona horaria

| Entrada | Interpretación |
| --- | --- |
| `01-01-2026 10:00:00` | `dd-MM-yyyy HH:mm:ss` |
| `2026-01-01 10:00:00` | `yyyy-MM-dd HH:mm:ss` |
| Los mismos formatos sin segundos | Segundos iguales a cero |
| Objeto `[datetime]` | Se utiliza el objeto recibido |

Los formatos de texto se interpretan explícitamente, sin depender de la configuración regional. Usá objetos `[datetime]` con la hora local prevista; no se convierten automáticamente horas de un host remoto. Los informes de eventos registran la zona horaria del equipo donde se ejecuta WinAudit.

El fin debe ser posterior al inicio. En la opción 2, dejar el inicio vacío toma las últimas 24 horas y dejar el fin vacío toma la hora actual. Para un fin futuro, usá la opción 7 o `-Monitor`.

### Límites de consulta

`-MaxEventsPerLog` admite 1–100000, predeterminado 10000 por registro y consulta. Se retienen los eventos más recientes antes de filtrar por proceso; si se alcanza el tope, el estado es `Limitado`. Acotá el intervalo para recuperar períodos omitidos. En captura, el límite se aplica a cada lectura, no al total acumulado ni al tamaño final del informe.

### Fuentes y coincidencias

Se consultan los registros locales existentes de Security, PowerShell/Operational y Sysmon/Operational. No se habilitan políticas de auditoría ni se instala Sysmon.

Para PID se examinan el emisor `System.Execution.ProcessID` y campos de PID de EventData, incluidos procesos padre, origen o destino. El informe conserva el campo coincidente, mensaje y XML del evento. Una coincidencia puede referirse a un proceso relacionado y un PID puede reutilizarse.

Para nombre se comparan campos estructurados `Image`, `NewProcessName`, `ProcessName`, `ApplicationName`, `SourceImage`, `TargetImage`, `ParentImage` y `ParentProcessName`. No se busca texto libre ni se infiere un PID histórico a partir del proceso activo. Los eventos sin esos campos pueden no aparecer en una búsqueda por nombre.

El JSON distingue el estado de las fuentes, incluidas consultas sin eventos, registros inaccesibles o eventos parcialmente interpretados. Una lista vacía no demuestra ausencia de actividad.

## Captura local por horario

Para comenzar ahora y terminar dentro de diez minutos:

```powershell
.\WinAudit.ps1 -FindProcess 'example.exe' -Monitor -End ((Get-Date).AddMinutes(10))
```

Para esperar hasta un inicio futuro:

```powershell
$inicio = (Get-Date).AddMinutes(5)
$fin = $inicio.AddMinutes(10)
.\WinAudit.ps1 -FindProcess 'example.exe' -Monitor -Start $inicio -End $fin -PollSeconds 5
```

También podés usar `-PIDToAudit 1234`. Un nombre permite recuperar eventos compatibles de procesos que todavía no existían al abrir la herramienta. Si indicás un inicio pasado, se puede incluir ese tramo histórico de los registros retenidos.

`-Monitor` requiere un `-EndTime` explícito y futuro. Si omitís el inicio, comienza ahora. En el menú 7, un inicio vacío significa ahora; ingresá un fin futuro.

**Mantené la terminal abierta.** La captura no crea tareas programadas ni servicios, no se reanuda después de cerrar PowerShell y no garantiza observación durante suspensión o apagado. Ctrl+C la interrumpe. Los datos ya escritos permanecen sujetos a lo que el sistema haya podido guardar; el bloque de cierre no está garantizado ante una terminación abrupta.

La consulta periódica usa cinco segundos por defecto; `-PollSeconds` acepta de 1 a 300. Las lecturas se solapan y se deduplican por registro, ID y fecha del evento. Al terminar hay una lectura final con dos segundos de margen. Ese mecanismo no garantiza recuperar eventos escritos demasiado tarde o eliminados por retención.

### Informes de una captura

| Archivo | Contenido |
| --- | --- |
| `capture-....jsonl` | Un evento por línea, con mensaje y XML; guardado progresivo |
| `capture-....json` | Intervalo, selector, zona horaria, estado, cantidad y disponibilidad de fuentes |
| `capture-....-processes.json` | Instancias observadas, primera/última observación, archivo, hashes y firma |
| `capture-....-tree.txt` | Árbol, relaciones de eventos y limitaciones; también se muestra en pantalla al terminar |

### MD5 y firma en el árbol

Formato ilustrativo, sin datos reales:

```text
example.exe PID 1010 | MD5: <32 caracteres hexadecimales> | Signature: Valid | Firmante: CN=Example Publisher | creado <fecha>
```

Cada instancia se identifica por PID y fecha de creación. Los descendientes se enlazan con un padre observado y con fecha compatible; no se reasignan automáticamente a otro proceso que reutilice el mismo PID. Los procesos breves entre instantáneas pueden faltar.

La evidencia de archivo se obtiene al observar la instancia. El JSON conserva `MD5`, `SHA256`, `SignatureStatus`, `Signer`, `FileEvidenceAt` y errores por campo. El TXT muestra MD5, estado de firma, firmante, momento de lectura y errores disponibles.

| Valor | Significado |
| --- | --- |
| `Valid` | Estado de validación Authenticode obtenido; no significa proceso benigno |
| `NotSigned` | No se encontró firma; no es una detección de malware |
| `NoDisponible` | Ruta o evidencia inaccesible; se conserva el error |
| Otros estados Authenticode | Se muestran sin convertirlos en un veredicto automático |

Un error de hash no oculta una firma disponible y un error de firma no oculta hashes disponibles. Durante la captura se puede reutilizar evidencia del mismo archivo si no cambiaron ruta, tamaño y modificación; no equivale a una garantía de inmutabilidad. Los hashes y firmas describen el archivo leído, no su memoria ni su contenido histórico.

Las relaciones recuperadas de Sysmon 1 o Security 4688 y los vínculos de Sysmon 8/10 aparecen por separado del árbol observado, cuando esos eventos están entre las coincidencias. No se inventan otros procesos vinculados ni se atribuyen hashes actuales a una relación histórica por su nombre.

## Verificar archivos

```powershell
.\WinAudit.ps1 -FilePath 'C:\Example\example.exe' -HashAlgorithm Both
.\WinAudit.ps1 -FilePath 'C:\Example\example.exe' -HashAlgorithm MD5
```

La opción 8 permite seleccionar lo mismo desde el menú. `-HashAlgorithm` admite `SHA256` (predeterminado), `MD5` y `Both`. El resultado incluye la firma y se exporta a JSON. En la investigación histórica, el parámetro elige los hashes de ejecutables actualmente activos y accesibles, no de versiones históricas del archivo.

MD5 sirve para comparar identificadores existentes; no demuestra integridad frente a manipulación intencional. No se sube el archivo ni se consulta reputación por el solo hecho de calcular hashes.

## Descubrimiento de AD y WinRM

LDAP/LDAPS y RSAT consultan el directorio. WinRM consulta procesos del equipo elegido. Son operaciones y permisos distintos.

### Flujo del menú 4

1. Ingresá el nombre DNS del dominio o DC, por ejemplo `dc01.ad.example.com`.
2. Elegí LDAPS (predeterminado), LDAP firmado/cifrado o RSAT.
3. Opcionalmente ingresá una OU y un patrón como `PC-*`; vacío significa todos.
4. Usá la sesión actual u otras credenciales de lectura AD.
5. Revisá el inventario; se muestran hasta 100 filas y se exportan los resultados recopilados.
6. Para WinRM, elegí un número de la tabla o dejá vacío para terminar con el inventario. Si el objeto no tiene `DNSHostName`, no se adivina un destino.
7. Elegí la sesión actual u otras credenciales autorizadas para WinRM. No se reutiliza automáticamente la credencial del directorio.

Si no aparece el equipo entre las filas mostradas, ajustá el filtro u OU. Un objeto habilitado no implica que el host esté encendido o permita WinRM.

### Inventario por comando

```powershell
# Identidad actual, sin RSAT
.\WinAudit.ps1 -DirectoryServer dc01.ad.example.com -DirectoryProtocol LDAPS -DirectoryNameFilter 'PC-*' -EnabledOnly

# Credenciales explícitas, LDAP con firma y sellado
$credDirectorio = Get-Credential
.\WinAudit.ps1 -DirectoryServer dc01.ad.example.com -DirectoryProtocol LDAP -DirectoryCredential $credDirectorio -SearchBase 'OU=Workstations,DC=ad,DC=example,DC=com'

# Alternativa con el módulo oficial instalado
.\WinAudit.ps1 -DirectoryServer dc01.ad.example.com -DirectoryProtocol RSAT
```

### Inventario WinRM

```powershell
$credRemota = Get-Credential
.\WinAudit.ps1 -ComputerName pc001.ad.example.com -RemoteCredential $credRemota
.\WinAudit.ps1 -ComputerName pc001.ad.example.com -RemoteCredential $credRemota -WinRMUseSSL -WinRMPort 5986
```

Por comando, si omitís `-RemoteCredential`, se solicita con `Get-Credential`. En el menú se puede elegir la sesión actual. La función remota consulta procesos mediante `Get-CimInstance Win32_Process`; no implementa la captura de eventos ni la verificación de hashes en el host remoto.

### Opciones del directorio y transporte

| Parámetro | Valores y alcance |
| --- | --- |
| `-DirectoryServer` | Nombre DNS del dominio/DC; activa inventario de directorio |
| `-DirectoryProtocol` | `LDAPS` (predeterminado), `LDAP` o `RSAT` |
| `-DirectoryCredential` | PSCredential opcional; si se omite, identidad actual |
| `-SearchBase` | DN de OU o base; vacío en LDAP/LDAPS consulta RootDSE/defaultNamingContext |
| `-DirectoryNameFilter` | Patrón de nombre o DNSHostName; `*` es el comodín admitido |
| `-EnabledOnly` | Filtra equipos no deshabilitados en AD; no comprueba conectividad |
| `-DirectoryPort` | Puerto LDAP/LDAPS alternativo; cero elige 636/389; no se aplica a RSAT |
| `-DirectoryAuthentication` | Kerberos por defecto; Negotiate explícito para LDAP/LDAPS; RSAT usa su mecanismo propio |
| `-MaxComputers` | De 1 a 100000; predeterminado 10000; resultados limitados quedan marcados |
| `-RemoteCredential` | Credenciales para el inventario WinRM, independientes de AD |
| `-WinRMAuthentication` | Kerberos por defecto; Negotiate explícito |
| `-WinRMUseSSL` | Solicita HTTPS; no omite la validación del certificado |
| `-WinRMPort` | Puerto remoto alternativo; sin valor usa el predeterminado del transporte WinRM |

LDAPS usa TLS y la validación normal de Windows. LDAP usa SASL con firma y sellado de sesión; no implementa simple bind sin protección ni StartTLS. No hay downgrade automático. Solo se aceptan nombres DNS como destinos, sin URL, IP o puerto incrustado. La autenticación depende del DNS, las identidades, el entorno y sus políticas.

Sin SearchBase, LDAP/LDAPS consulta un contexto de dominio; no enumera automáticamente todo el bosque. No sigue referrals a otros servidores. Escapa caracteres de control del filtro y solicita páginas de hasta 500 objetos por defecto. La conexión LDAP y cada operación de búsqueda tienen tiempo de espera; no es un plazo global para todo el inventario.

La conexión LDAP directa tiene además un máximo de 1000 páginas; `Get-WADirectoryComputers -MaxPages` permite 1–10000 al usar el módulo. Superar ese máximo interrumpe la consulta con error. No es un parámetro de la interfaz principal.

Si se alcanza MaxComputers, se avisa y se marca `QueryTruncated`. En RSAT, alcanzar exactamente el límite se trata de forma conservadora como posible truncamiento. Si falla la paginación o la conexión, no se presenta un inventario parcial como completo. LastLogonDate proviene de datos aproximados de AD y no prueba disponibilidad.

### RSAT opcional

Solo el proveedor RSAT necesita `ActiveDirectory`. LDAP/LDAPS usa `System.DirectoryServices.Protocols` del runtime de Windows y no descarga librerías automáticamente. Si no está disponible, informa el motivo. WinRM tampoco necesita RSAT.

Desde el repositorio:

```powershell
Get-Module -ListAvailable ActiveDirectory
.\Install-Prerequisites.ps1
```

Si decidís instalarlo, en Windows PowerShell elevado:

```powershell
.\Install-Prerequisites.ps1 -Install
Import-Module ActiveDirectory
Get-Command Get-ADComputer
```

El instalador usa Windows Capability en cliente o ServerManager en Server. La edición, políticas y origen de componentes pueden impedir o diferir la instalación. No se ejecuta automáticamente desde la auditoría o el bootstrapper.

## VirusTotal opcional

Sin activar esta integración, las auditorías no realizan consultas propias a VirusTotal. Una variable `VIRUSTOTAL_API_KEY` definida por sí sola tampoco la activa.

En la opción 9:

| Acción | Comportamiento |
| --- | --- |
| 1. Cargar clave | Toma la variable de entorno si existe; si no, solicita entrada oculta. Deja el enriquecimiento automático apagado |
| 2. Consultar SHA-256 | Envía una consulta manual y exporta el resultado a JSON |
| 3. Activar/desactivar enriquecimiento | Afecta las auditorías locales posteriores compatibles |
| 4. Desactivar y olvidar contexto | Deja de usarlo en esta sesión; no elimina una variable de entorno externa |
| 0. Volver | Regresa al menú principal |

Por comando, solo si configuraste la variable de entorno de forma segura:

```powershell
.\WinAudit.ps1 -FilePath 'C:\Example\example.exe' -VirusTotal
.\WinAudit.ps1 -FindProcess 'example.exe' -VirusTotal
.\WinAudit.ps1 -FindProcess 'example.exe' -Monitor -End ((Get-Date).AddMinutes(10)) -VirusTotal
```

`-VirusTotal` es activación explícita para esa ejecución. Si falta la clave, se informa y continúa la auditoría local sin consultas. No se combina con `-FullScan`, `-ComputerName` ni `-DirectoryServer`.

Solo consulta informes existentes por SHA-256. No sube archivos, logs, rutas ni informes y no solicita reanálisis. El proveedor recibe el hash, la clave y los datos normales de conexión. Usá una cuenta/licencia apropiada: la [API pública tiene restricciones de uso](https://docs.virustotal.com/reference/public-vs-premium-api), especialmente en contextos comerciales y empresariales.

### Resultado y límites

El JSON guarda la reputación bajo `VirusTotal`. En el árbol enriquecido se agregan estado, conteos malicioso/sospechoso, cantidad de motores con veredicto, fecha UTC del análisis y enlace. El denominador no incluye motores sin veredicto por error, timeout o tipo no compatible.

| Estado | Interpretación |
| --- | --- |
| `Encontrado` | Hay estadísticas; no es un veredicto de WinAudit |
| `SinAntecedentes` | El proveedor no encontró informe para el hash |
| `SinAnalisisDisponible` | El hash existe, sin estadísticas devueltas |
| `LimiteAlcanzado` | Se omitió la consulta por cuota o límite local |
| `CredencialesInvalidas` / `SinPermiso` | Se rechazó autenticación o autorización |
| `ErrorConexion` / `ErrorServicio` / `RespuestaInvalida` | No hay una respuesta utilizable |
| `EvidenciaNoDisponible` | No se pudo obtener o asociar el hash requerido |

Cero detecciones, una firma válida o falta de antecedentes no significan seguro. La fecha puede ser antigua o faltar; no se fuerza un análisis nuevo.

En captura, se usa el SHA-256 preservado al observar la instancia y se consulta al finalizar la recopilación local, no en cada sondeo. Si no hay SHA-256 capturado, no se infiere otro a partir del nombre. En búsqueda, investigación o archivo, la consulta describe el archivo actualmente leído.

Hay caché en memoria: una hora para informes y 15 minutos para hashes no encontrados. Se espacian consultas únicas al menos 16 segundos y se limita cada contexto a 100 peticiones. Un 429 pausa nuevas solicitudes 60 segundos; un 401/403 requiere reconfigurar. No se reintenta automáticamente una petición fallida. Estos límites no garantizan cuota disponible en una cuenta compartida con otras aplicaciones. El enriquecimiento puede demorar después de terminar la captura local.

La clave no se exporta en los informes. La carga oculta usa memoria de sesión; la variable de entorno es texto y debe configurarse fuera del repositorio, sin valores literales en el historial. Ver [Modelo de seguridad](SECURITY.md#virustotal-y-claves).

## Combinaciones de modos

| Modo | Combinaciones admitidas |
| --- | --- |
| `-FindProcess` sin intervalo | Búsqueda de procesos activos; VirusTotal opcional |
| PID, o nombre con intervalo | Investigación histórica; VirusTotal opcional para archivos activos accesibles |
| `-Monitor` | PID o nombre, fin futuro explícito; VirusTotal opcional al finalizar |
| `-FilePath` | HashAlgorithm, destino de informe y VirusTotal opcional; sin otro modo |
| `-FullScan` | Inventario local; sin selector, intervalo, captura ni VirusTotal |
| `-DirectoryServer` | Inventario AD y opciones del directorio; sin otro modo ni VirusTotal |
| `-ComputerName` | Inventario remoto y opciones WinRM; sin selector, intervalo, captura, directorio ni VirusTotal |

No pases PID y nombre juntos. En comandos, descubrimiento y WinRM son ejecuciones separadas; el menú 4 ofrece la selección entre ambos pasos.

## Rutas locales y protección de salida

Los archivos de evidencia y destinos de informe deben ser locales: se rechazan rutas UNC, unidades de red, dispositivos, ADS y componentes con junction/reparse point. Esto evita que una ruta aportada por un proceso provoque una lectura SMB autenticada. Si la ruta está bloqueada, la evidencia queda no disponible o se informa el error; no desactives la validación para seguirla. Los nuevos archivos de informe no sobrescriben otros existentes.

La pantalla reemplaza controles de terminal y marcas bidi en campos de texto; JSON/XML conservan datos crudos. Abrilos en un visor que trate el contenido como datos. Las carpetas heredan los permisos del destino: elegí una ubicación privada y controlá su retención.

## Ubicación y manejo de informes

El destino predeterminado es `%USERPROFILE%\WinAudit-Reports`:

```powershell
.\WinAudit.ps1 -FullScan -ReportDirectory 'C:\Audit-Reports'
```

Los modos de inventario, búsqueda, investigación, archivo y consulta manual VT generan JSON; solo la captura genera además JSONL, evidencia de procesos y árbol TXT. La herramienta crea la carpeta si es necesario. Un informe puede contener nombres de equipos, usuarios, rutas, argumentos, mensajes y XML de eventos.

No publiques informes reales. Evitá un destino dentro del repositorio: el `.gitignore` no protege cualquier carpeta personalizada. Si compartís evidencia, revisá y anonimiza los datos necesarios antes de hacerlo.

## Diagnóstico de problemas

| Síntoma | Qué revisar |
| --- | --- |
| Registro inaccesible | Permisos, existencia, auditoría habilitada y retención; WinAudit no lo habilita |
| Sin eventos por nombre | Campos estructurados disponibles; probá PID e intervalo adecuado sin asumir identidad única |
| Hash/firma NoDisponible | Ruta, permisos, existencia y cambios del archivo |
| LDAPS falla | DNS, puerto, confianza/correspondencia del certificado y autenticación; no omitas la validación |
| LDAP falla | Kerberos/Negotiate elegido, firma/sellado, políticas y permisos |
| Inventario limitado | QueryTruncated, filtro, OU y MaxComputers |
| RSAT ausente | Elegí LDAP/LDAPS o instalá la dependencia opcional |
| AD funciona, WinRM falla | Permisos independientes, nombre DNS, conectividad, transporte y configuración de WinRM |
| VirusTotal no responde | Estado reportado, clave, licencia, cuota y conectividad; auditoría local independiente |

## Desarrollo y verificación

No hay compilación de aplicación:

```powershell
.\tools\Build-Standalone.ps1
.\tools\Build-Standalone.ps1 -Check
.\tests\Features.Tests.ps1
.\tests\Reputation.Tests.ps1
.\tests\Directory.Tests.ps1
```

El [workflow aprobado de v0.4.0-alpha](https://github.com/DarkCristian/WinAudit/actions/runs/42114961065) ejecuta las pruebas en PowerShell 5.1 y 7 y genera un artefacto con bytes canónicos y SHA-256. Las pruebas usan datos sintéticos y sustituyen las conexiones de VirusTotal, LDAP/LDAPS, RSAT y WinRM. No validan un certificado, dominio, permisos o respuesta real de esos servicios.
