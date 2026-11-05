# Modelo de seguridad y limitaciones

Referencia de **main revisado el 05/11/2026**, posterior a v0.4.0-alpha. El asset anterior no incorpora estas correcciones. WinAudit es una herramienta de consulta y recopilación de evidencia para Windows. No es un antivirus, EDR ni una herramienta completa de adquisición forense.

[Volver al README](../README.md) · [Guía de uso](USAGE.md)

## Modelo de operación

WinAudit consulta procesos, archivos, registros y directorios que el operador está autorizado a leer. No termina procesos, instala agentes, habilita WinRM, modifica TrustedHosts, cambia reglas de firewall ni configura políticas de auditoría.

El modo de consulta no significa ausencia absoluta de cambios: se escriben informes locales; el bootstrapper descarga y elimina componentes temporales; la ejecución, autenticación y lectura pueden generar registros del propio sistema. El instalador opcional `Install-Prerequisites.ps1 -Install` sí agrega un componente de Windows cuando el operador lo ejecuta explícitamente.

No se aplican remediaciones automáticas. Las recomendaciones o estadísticas no reemplazan el análisis de un operador.

## Autorización y credenciales

| Operación | Ámbito de permisos |
| --- | --- |
| Procesos y archivos locales | Identidad que ejecuta WinAudit; algunos datos pueden requerir elevación |
| Registros protegidos | Permisos de lectura de cada registro y evidencia realmente retenida |
| Directorio LDAP/LDAPS o RSAT | Identidad actual o credenciales autorizadas de AD |
| Inventario WinRM | Identidad o credenciales autorizadas en el host remoto y configuración de WinRM |
| VirusTotal | Cuenta propia, clave y licencia válidas para el uso previsto |

La elevación local no concede derechos sobre AD o equipos remotos. Una cuenta que lee el directorio puede carecer de acceso WinRM. Las credenciales del directorio no se reutilizan automáticamente para el host seleccionado.

Las contraseñas solicitadas mediante `Get-Credential` se manejan como PSCredential y se entregan al mecanismo de autenticación elegido. No se incluyen en los objetos de inventario o informes. Esto no protege frente a quien pueda inspeccionar la memoria, la sesión o el entorno del operador.

No coloques credenciales en el código, ejemplos, argumentos literales guardados en el historial o archivos que se publiquen en Git. Los valores de documentación son ficticios; los datos reales pertenecen a la configuración y evidencia local del operador.

## Límites de procesos y eventos

### Identidad y correlación

Un PID puede reutilizarse. El árbol observado separa instancias mediante PID y fecha de creación, pero depende de instantáneas: los procesos breves entre lecturas pueden faltar. Un proceso padre ausente o con fecha incompatible no se reconstruye por suposición.

`System.Execution.ProcessID` identifica al emisor de un evento. Los campos EventData pueden referirse al sujeto, creador, padre, origen o destino de una relación. Una coincidencia se etiqueta con el campo que la produjo; no implica por sí sola que el proceso haya ejecutado una acción maliciosa.

La búsqueda por nombre compara determinados campos estructurados. Los eventos sin ellos no se asocian por nombre, aunque el programa haya estado activo. Coincidencias con un nombre no identifican una instancia histórica única.

### Disponibilidad

Security, PowerShell y Sysmon pueden no estar habilitados, no existir, ser inaccesibles o haber perdido datos por retención. WinAudit no habilita auditoría de creación de procesos, Script Block Logging ni Sysmon.

La captura consulta periódicamente y realiza una lectura final con margen limitado. Pueden faltar eventos que se escriban demasiado tarde, sean eliminados o nunca se registren. Una fuente parcial o inaccesible queda indicada; cero coincidencias no demuestra ausencia de actividad.

El intervalo usa la hora del equipo donde corre WinAudit. No hay sincronización ni conversión automática entre relojes de hosts remotos. La captura requiere la sesión abierta; no es una tarea persistente ni un servicio. Suspensión, apagado, cierre de PowerShell o interrupciones pueden dejar evidencia incompleta. Los archivos ya escritos y el resumen final dependen de que el sistema y el bloque de cierre alcancen a guardarlos.

### Alcance remoto

WinRM implementa inventario remoto de procesos. La consulta histórica, captura de eventos, árbol y evidencia de archivo descritos en los otros modos son locales. Encontrar un host en AD no habilita esas funciones remotamente.

## Hashes, firmas y árbol

SHA-256 y MD5 identifican los bytes del archivo leído en disco. No prueban qué había en memoria ni qué archivo existía en una fecha histórica. Un ejecutable puede haber sido reemplazado o resultar inaccesible después de terminar el proceso.

La evidencia del árbol se obtiene al observar la instancia. Puede reutilizarse dentro de una captura si coinciden ruta, tamaño y fecha de modificación. Esa caché y la comprobación de cambios durante la lectura no proporcionan una instantánea forense atómica ni garantizan inmutabilidad frente a manipulación deliberada.

| Resultado | Límite de interpretación |
| --- | --- |
| Firma `Valid` | Es el estado obtenido de Authenticode; no demuestra comportamiento benigno |
| `NotSigned` | Ausencia de firma; no es una detección de malware |
| `NoDisponible` | No se pudo obtener evidencia; no debe interpretarse como seguro o sin firma |
| MD5 coincidente | Útil para identificar o comparar referencias; no prueba integridad frente a ataques deliberados |
| SHA-256 coincidente | Identifica contenido leído; no es un veredicto de reputación por sí solo |

La validación de firma depende del estado de confianza y de los mecanismos de Windows. WinAudit no implementa inspección de memoria, detección de inyección, análisis completo de persistencia ni clasificación concluyente de malware.

Los vínculos de creación o acceso recuperados de eventos se presentan por separado del árbol de instantáneas. Un acceso entre procesos no implica parentesco ni actividad maliciosa. No se asignan hashes o firmas actuales a un proceso histórico solo porque comparta nombre.

## LDAP/LDAPS y WinRM

### Directorio

LDAP/LDAPS utiliza `System.DirectoryServices.Protocols` del runtime de Windows y no requiere RSAT. Solo el proveedor RSAT necesita `ActiveDirectory`. Si falta una dependencia, se informa; no se descarga o instala automáticamente desde el modo de consulta.

| Proveedor | Protección implementada |
| --- | --- |
| LDAPS | TLS, puerto 636 predeterminado y validación normal de certificado por Windows |
| LDAP | Puerto 389 predeterminado, SASL con firma y sellado de sesión |
| RSAT | Cmdlets oficiales y su autenticación/configuración; no usa los ajustes de puerto/autenticación de la conexión LDAP directa |

Kerberos es el valor predeterminado de LDAP/LDAPS. Negotiate se ofrece como opción explícita, sujeta al entorno y sus políticas. No se admite Basic o Anonymous ni se implementa simple bind sin protección. LDAP no significa StartTLS en esta versión.

No hay callbacks para aceptar cualquier certificado, downgrade automático de LDAPS a LDAP, modificación de CA o cambio de políticas del dominio. Un error de certificado o autenticación se debe diagnosticar, no resolver desactivando validaciones desde WinAudit.

Los destinos deben ser nombres DNS, sin URL, IP ni puerto incrustado. Los referrals están desactivados para no seguir redirecciones autenticadas hacia otros servidores. Sin SearchBase se utiliza defaultNamingContext del servidor, no un recorrido automático de todo el bosque.

Los valores de filtro escapan paréntesis, barra inversa y NUL; solo `*` mantiene significado de comodín. SearchBase se transmite por separado como DN. Las búsquedas tienen timeout por conexión/operación, paginación y límite de cantidad; no se promete un plazo global de ejecución. Los resultados truncados se marcan, y los fallos de paginación o conexión no se presentan como inventarios completos. La conexión se libera en un bloque de cierre cuando la ejecución normal de PowerShell lo permite.

### WinRM

Usa Kerberos por defecto; Negotiate y HTTPS son elecciones explícitas. No configura el servicio, firewall, TrustedHosts ni opciones para omitir certificados. Las credenciales y la conectividad deben estar preparadas por el administrador.

Un atributo `Enabled`, DNSHostName o LastLogonDate en AD no comprueba disponibilidad remota. LastLogonDate es aproximada. El paso del menú al inventario WinRM requiere que el operador seleccione un destino con nombre DNS válido y permisos propios para esa consulta.

## VirusTotal y claves

### Activación y datos enviados

La integración está apagada por defecto. Importar el módulo, abrir el menú o tener `VIRUSTOTAL_API_KEY` definida no inicia consultas. Cargar la clave en el menú también deja apagado el enriquecimiento; se activa aparte. `-VirusTotal` es una activación explícita para esa ejecución y exige una variable de entorno configurada.

Solo se implementa GET al endpoint fijo de informes de archivo por SHA-256, con la clave en `x-apikey`. No se suben ejecutables, logs, rutas ni informes, ni se solicitan reanálisis. El proveedor recibe el hash consultado, la clave y los datos normales de la conexión, como IP de origen. La validación HTTPS se conserva y no se siguen redirecciones.

Durante la captura se conserva el SHA-256 observado y se consulta reputación al finalizar la recopilación local. Un hash ausente no se reemplaza por una búsqueda por nombre. La búsqueda, investigación y verificación de archivos describen el archivo actualmente leído.

### Manejo de la clave

Cada operador aporta su clave. El menú usa entrada oculta y la mantiene como SecureString en memoria de sesión. Para invocar HTTPS se necesita una representación legible temporal, por lo que esto no protege frente a inspección de memoria por un actor con permisos suficientes.

La variable de entorno es texto. Configurala fuera del repositorio y sin valores literales que queden en el historial. La acción de olvidar el contexto detiene su uso desde esa sesión, pero no borra variables de entorno externas ni garantiza el borrado de todas las copias en memoria.

No se exporta el contexto de autenticación, las cabeceras ni la clave a informes. Los errores de la integración se resumen con estados controlados; no se imprimen deliberadamente cuerpos HTTP ni excepciones remotas completas. No hay una clave compartida de WinAudit ni se requieren secretos reales en el workflow.

### Cuotas y significado del resultado

Los informes se cachean una hora y los hashes no encontrados 15 minutos, en memoria de sesión. Las solicitudes únicas se espacian al menos 16 segundos y cada contexto tiene un tope local de 100 peticiones. Un 429 pausa nuevas solicitudes 60 segundos; un 401/403 detiene nuevas consultas hasta reconfigurar. No se reintenta automáticamente una petición fallida. El consumo de otras aplicaciones puede agotar la cuota de la misma cuenta.

Se muestra la fecha de análisis cuando está disponible; no se fuerza un análisis nuevo. Un resultado antiguo, cero detecciones, falta de antecedentes o un error no prueban seguridad. Los conteos del proveedor pueden incluir falsos positivos. El enriquecimiento puede quedar incompleto si se interrumpe la ejecución después de la captura local.

El operador debe comprobar la licencia y los términos de su cuenta. La API pública tiene restricciones de uso comercial y de flujos empresariales que no aportan archivos nuevos. WinAudit no sube archivos y no supone que una clave gratuita sea adecuada para una organización.

## Informes y distribución

Los informes pueden incluir hostnames, usuarios, rutas, argumentos, DN, eventos y otra información sensible. Por defecto se escriben en `%USERPROFILE%\WinAudit-Reports`; protegé la carpeta y su retención. Elegir una carpeta personalizada dentro del repositorio puede exponerlos en un commit: el `.gitignore` no cubre cualquier ubicación.

El código y los ejemplos del repositorio utilizan valores ficticios. Eso no anonimiza automáticamente los informes reales. Antes de compartir evidencia, revisá qué datos contiene y eliminá o anonimiza lo que no deba divulgarse.

El launcher descarga un único standalone desde un commit inmutable y compara un SHA-256 fijado antes de ejecutarlo; no sigue redirecciones, usa timeout y `-UseBasicParsing`. Mantiene un handle de solo lectura sin compartir escritura/borrado durante la validación y ejecución. El primer `irm | iex` sigue confiando en el propio launcher de `main`: descargalo y revisalo o fijá una revisión aprobada. El hash interno no autentica al launcher ni sustituye una firma del editor.

El tag v0.4.0-alpha y sus assets permanecen fijados a la publicación. Corregir documentación en `main` no actualiza esos binarios ni cambia el código del tag.

## Estado de validación

El [workflow aprobado](https://github.com/DarkCristian/WinAudit/actions/runs/42114961065) valida sintaxis, ensamblado y bytes del standalone, fechas, búsquedas, eventos sintéticos, captura, árbol, hashes, errores y opt-in de reputación, LDAP/LDAPS/RSAT y WinRM con respuestas simuladas, en PowerShell 5.1 y 7.

No constituye una prueba contra un DC real, validación de certificados de una organización, prueba de permisos remotos ni consulta real a VirusTotal. Esas pruebas operativas siguen pendientes en un entorno autorizado. Esta versión conserva el estado Alpha.

## Referencias oficiales

- [LdapConnection](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection)
- [Opciones de sesión LDAP](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapsessionoptions)
- [Paginación LDAP](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.pageresultrequestcontrol)
- [VirusTotal: consulta de informe por hash](https://docs.virustotal.com/reference/file-info)
- [VirusTotal: campos de informes](https://docs.virustotal.com/reference/files)
- [VirusTotal: errores y cuotas](https://docs.virustotal.com/reference/errors)
- [VirusTotal: API pública y Premium](https://docs.virustotal.com/reference/public-vs-premium-api)

## Reportar vulnerabilidades

Usá un aviso privado de seguridad de GitHub cuando esté disponible. No incluyas claves, contraseñas, logs privados ni identificadores corporativos en issues públicos. Los problemas operativos sin datos sensibles pueden describirse con pasos reproducibles y valores ficticios.

## Endurecimiento de main (05/11/2026)

[Revisión de seguridad y CVE del runtime](SECURITY_REVIEW.md). Se rechazan rutas UNC, dispositivos, ADS, unidades de red y componentes reparse/junction antes de leer evidencia o escribir informes. Se crean nuevos informes con CreateNew para no sobrescribir archivos existentes. No hay aislamiento frente a un administrador local ni una garantía contra carreras de reemplazo de directorios por un atacante con permisos de escritura. Las ACL se heredan: no se cifra evidencia ni se configura una ACL privada automáticamente.

El XML de eventos usa XmlReader con DTD prohibido, resolver nulo y máximo de 4 Mi caracteres. La presentación de texto elimina controles C0/C1 y marcas bidi; JSON/XML crudos se preservan y deben abrirse como datos no confiables.

Las consultas de eventos tienen tope por registro/lectura (10000 predeterminado, 100000 máximo), retienen primero los más recientes y explicitan el estado Limitado. No limitan todo el consumo de disco de una captura larga. LDAP directo limita páginas además de equipos y timeout; un exceso falla explícitamente.

Se rechazan ramas antiguas de PowerShell 7 y versiones anteriores a 7.4.21 / 7.5.12 / 7.6.7 según la rama. PowerShell 5.1 requiere Windows actualizado: su número de versión no demuestra que estén instaladas todas las KB. Una rama posterior a 7.6 genera advertencia porque no fue evaluada en este relevamiento. Estos controles no parchean Windows, .NET ni PowerShell y no garantizan ausencia de vulnerabilidades futuras.
