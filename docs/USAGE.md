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


### MD5 y firma en el arbol

Al finalizar la captura, el arbol se guarda en el TXT y se muestra en pantalla con este formato ilustrativo:

```text
+-- example.exe PID 1010 | MD5: <32 caracteres hexadecimales> | Signature: Valid | Firmante: CN=Example Publisher | creado <fecha>
```

Se leen el MD5 y la firma Authenticode del archivo accesible al observar por primera vez cada instancia del proceso. El JSON de procesos conserva `MD5`, `SignatureStatus`, `Signer`, `FileEvidenceAt`, `MD5Error` y `SignatureError`. El TXT incluye la fecha de lectura y los errores.

`NotSigned` indica ausencia de firma; `NoDisponible` indica que falta la ruta o no pudo leerse la evidencia. Un error de firma no oculta un MD5 disponible, ni un error de hash oculta una firma disponible. Otros estados Authenticode, como `HashMismatch`, se conservan sin convertirlos en una conclusion de riesgo.

Para reducir lecturas repetidas, las instancias que usan un mismo archivo pueden reutilizar evidencia obtenida durante esa captura si no cambiaron ruta, tamano y fecha de modificacion. Esta comprobacion no equivale a una garantia de inmutabilidad. Si el archivo cambia durante la lectura, la evidencia se marca no disponible. El hash y la firma describen el archivo leido en disco, no la memoria ni el ejecutable historico de un evento.

Los vinculos historicos de la seccion de eventos no reciben un MD5 ni una firma inferidos a partir de su nombre.

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

El inventario remoto usa `Get-Credential` e `Invoke-Command` con WinRM configurado y acceso autorizado. `-ComputerName` no se combina con busqueda, intervalos ni captura en esta version. Solo el proveedor RSAT requiere ActiveDirectory. LDAP/LDAPS no requiere RSAT; ambos necesitan acceso autorizado al directorio.

Los informes se guardan por defecto en `%USERPROFILE%\WinAudit-Reports`, fuera del repositorio. Cambia la ruta con `-ReportDirectory`. No publiques informes reales.

## Generar el archivo independiente

No requiere compilacion ni dependencias externas:

```powershell
.\tools\Build-Standalone.ps1
.\tools\Build-Standalone.ps1 -Check
.\tests\Features.Tests.ps1
```

El generador concatena los modulos y la interfaz sin sustituciones de expresiones regulares que puedan alterar cadenas PowerShell. Las pruebas usan eventos sinteticos y no sustituyen una validacion funcional contra los logs, permisos, WinRM y AD de un entorno Windows autorizado.

## VirusTotal opcional — menu avanzado 9

WinAudit sigue funcionando sin cuenta, clave ni acceso a VirusTotal. Esta integracion no decide si un proceso es seguro o malicioso; agrega evidencia de reputacion del ultimo analisis conocido.

1. Entra en la opcion **9 — Avanzado: VirusTotal opcional**.
2. Usa **1 — Cargar clave**. Si ya configuraste `VIRUSTOTAL_API_KEY`, se toma de esa variable; si no, se solicita mediante entrada oculta. Se mantiene solo en esta sesion y no se escribe en informes ni en Git.
3. Usa **2** para consultar manualmente un SHA-256, o **3** para activar el enriquecimiento de auditorias locales posteriores. Cargar la clave no activa por si solo consultas automaticas.
4. Usa **4** para desactivar y olvidar el contexto de esta sesion. La variable de entorno externa, si existe, no se modifica.

La consulta transmite el SHA-256 y la clave a VirusTotal; no sube archivos, rutas, procesos completos ni logs. El proveedor tambien recibe informacion normal de la conexion. Usa una cuenta/licencia habilitada para tu caso: la API publica tiene restricciones de uso empresarial. Revisa [las condiciones oficiales](https://docs.virustotal.com/reference/public-vs-premium-api).

### Uso por comando

Solo cuando `VIRUSTOTAL_API_KEY` ya esta configurada de forma segura en tu entorno:

```powershell
.\WinAudit.ps1 -FilePath 'C:\Example\example.exe' -VirusTotal
.\WinAudit.ps1 -FindProcess 'example.exe' -VirusTotal
.\WinAudit.ps1 -FindProcess 'example.exe' -Monitor -End ((Get-Date).AddMinutes(10)) -VirusTotal
```

La variable de entorno por si sola no activa nada: hace falta `-VirusTotal`. Si falta la clave, se informa y la auditoria local continua sin consultas. El inventario remoto y `-FullScan` no admiten `-VirusTotal` en esta version.

### Resultados, limites y privacidad

Los informes JSON guardan el resultado bajo `VirusTotal`. En el arbol TXT y de pantalla, las instancias enriquecidas incluyen estado, cantidad de motores que reportaron malicioso/sospechoso, cantidad de motores con veredicto, fecha UTC del analisis y enlace al informe. El denominador excluye motores sin veredicto por fallos, timeout o tipos no compatibles; no significa que todas las detecciones sean correctas.

Estados posibles incluyen `Encontrado`, `SinAntecedentes`, `SinAnalisisDisponible`, `LimiteAlcanzado`, `CredencialesInvalidas`, `SinPermiso`, `ErrorConexion`, `ErrorServicio` y `RespuestaInvalida`. Sin un SHA-256 capturado, la instancia se marca `EvidenciaNoDisponible`. No encontrar un informe o tener cero detecciones no equivale a seguro.

La captura recopila primero la evidencia local. El enriquecimiento opcional ocurre al finalizar, con el SHA-256 preservado al observar la instancia. Puede demorar: se espacian solicitudes unicas al menos 16 segundos. Hay cache por hash durante la sesion y un tope local de 100 solicitudes por contexto. Un 429 pausa nuevas solicitudes 60 segundos, y un 401/403 requiere reconfigurar. No hay subidas ni reanalisis automaticos.

Consulta el [modelo de seguridad](SECURITY.md) para conocer el almacenamiento de la clave, los datos enviados y las restricciones del proveedor. El workflow prueba la integracion con respuestas simuladas: no necesita claves reales ni realiza consultas a VirusTotal.

## Descubrimiento de AD por LDAP/LDAPS y consulta WinRM

Esta ampliacion esta incluida en `v0.4.0-alpha`, tanto en el asset standalone como en el codigo del tag.

LDAP/LDAPS descubre objetos de equipo del directorio. WinRM consulta procesos en el equipo elegido. Un objeto habilitado en AD no prueba que este encendido ni accesible por WinRM.

### Menu

En la opcion **4**:

1. Ingresa el nombre DNS del dominio o DC, por ejemplo `dc01.ad.example.com`.
2. Elegi **LDAPS** (predeterminado), **LDAP firmado/cifrado** o **RSAT**.
3. Opcionalmente ingresa una OU como `OU=Workstations,DC=ad,DC=example,DC=com` y un patron de equipo como `PC-*`.
4. Usa la sesion actual o credenciales explicitas de lectura del directorio.
5. Revisa la tabla y el informe JSON. Ingresa el numero de un equipo mostrado para consultarlo por WinRM, o deja vacio para terminar con el inventario.
6. Para WinRM, elegi sesion actual u otras credenciales autorizadas. No se reutiliza automaticamente la credencial de LDAP.

Se muestran hasta 100 filas para seleccion. Si faltan equipos, reduce el filtro o consulta el JSON completo. El limite de descubrimiento es 10000 por defecto; si se alcanza se advierte y se marca `QueryTruncated` para no presentar el resultado como completo.

### Comandos

Descubrir sin RSAT usando la identidad actual:

```powershell
.\WinAudit.ps1 -DirectoryServer dc01.ad.example.com -DirectoryProtocol LDAPS -DirectoryNameFilter 'PC-*' -EnabledOnly
```

Con credenciales explicitas y una OU:

```powershell
$credDirectorio = Get-Credential
.\WinAudit.ps1 -DirectoryServer dc01.ad.example.com -DirectoryProtocol LDAP -DirectoryCredential $credDirectorio -SearchBase 'OU=Workstations,DC=ad,DC=example,DC=com'
```

Con el modulo oficial de RSAT instalado:

```powershell
.\WinAudit.ps1 -DirectoryServer dc01.ad.example.com -DirectoryProtocol RSAT
```

Auditar un host conocido o elegido del inventario:

```powershell
$credRemota = Get-Credential
.\WinAudit.ps1 -ComputerName pc001.ad.example.com -RemoteCredential $credRemota
.\WinAudit.ps1 -ComputerName pc001.ad.example.com -RemoteCredential $credRemota -WinRMUseSSL -WinRMPort 5986
```

`-DirectoryServer` realiza inventario solamente y no se combina con `-ComputerName`. En el menu se ofrece el paso de seleccion a WinRM. Desde comandos, usa los dos modos por separado. `-ComputerName` sigue siendo independiente de LDAP y RSAT.

### Conexion y autenticacion

- **LDAPS:** puerto 636 por defecto y validacion normal del certificado por Windows. No hay opcion para omitir el certificado ni downgrade automatico a LDAP.
- **LDAP:** puerto 389 por defecto; SASL con firma y sellado de sesion (`Signing` y `Sealing`). No es un simple bind sin proteccion ni StartTLS.
- **Autenticacion LDAP:** Kerberos por defecto. `-DirectoryAuthentication Negotiate` es una eleccion explicita, sujeta a las politicas del entorno. No se admite Basic ni Anonymous.
- **WinRM:** Kerberos por defecto. `-WinRMAuthentication Negotiate` y `-WinRMUseSSL` son opciones explicitas. No cambia TrustedHosts, firewall, certificados ni politicas.
- **Puertos alternativos:** `-DirectoryPort` y `-WinRMPort`. No se aceptan URLs, direcciones IP ni puertos incrustados en el nombre DNS.
- **Sin RSAT:** LDAP/LDAPS usa `System.DirectoryServices.Protocols` del runtime de Windows; no descarga librerias ni instala dependencias. Si el runtime no lo ofrece, informa el motivo. Solo la opcion RSAT requiere ActiveDirectory.

El descubrimiento usa paginacion. Sin SearchBase consulta RootDSE y utiliza `defaultNamingContext`; no recorre automaticamente otros dominios del bosque. Los referrals estan desactivados para no redirigir la conexion autenticada a otro servidor. Los patrones permiten `*`, pero se escapan caracteres de control de filtros LDAP. LastLogonDate procede de lastLogonTimestamp y es aproximada; no es una prueba de conectividad.

Los fallos de bind, TLS, permisos o paginacion finalizan la consulta y liberan la conexion. Las contrasenas no se escriben en informes. Las pruebas del workflow simulan LDAP/LDAPS/RSAT/WinRM: sigue pendiente validar contra un DC y un host Windows autorizados.
