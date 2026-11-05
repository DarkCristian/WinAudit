# Modelo de seguridad

WinAudit consulta evidencia y exporta informes locales. No habilita WinRM, cambia politicas de auditoria, termina procesos ni instala agentes.

## Alcance y limites

- Ejecutalo solo en sistemas que administras o estas autorizado a evaluar.
- El proveedor RSAT requiere ActiveDirectory; LDAP/LDAPS no requiere RSAT. Ambos necesitan permisos de lectura del directorio.
- El inventario remoto requiere WinRM configurado y acceso autorizado.
- La disponibilidad de Security, PowerShell y Sysmon depende de configuracion y retencion.
- Un PID puede reutilizarse. Una coincidencia no identifica por si sola una instancia historica.
- System.Execution.ProcessID identifica al emisor; EventData puede referirse a otros procesos.
- Una firma valida no demuestra que un proceso sea seguro; un archivo sin firma no es automaticamente malicioso.
- Los hashes y firmas del arbol corresponden al archivo accesible al observar la instancia, no a su memoria.
- Los informes pueden incluir usuarios, rutas, argumentos y otros datos sensibles: mantenelos locales y con acceso restringido.

## VirusTotal: integracion externa opcional

La integracion esta desactivada por defecto. Importar el modulo, abrir WinAudit o tener `VIRUSTOTAL_API_KEY` definida no inicia solicitudes. Se requiere consultar explicitamente desde el menu avanzado o activar el enriquecimiento. El parametro `-VirusTotal` es una activacion explicita para esa ejecucion.

Solo se implementa `GET https://www.virustotal.com/api/v3/files/{SHA256}` con la clave en la cabecera `x-apikey`. No se suben ejecutables, logs, rutas, nombres de equipo ni informes, y no se piden reanalisis. Se mantiene la validacion HTTPS y no se siguen redirecciones. El proveedor recibe el hash consultado, la clave de su cuenta y la informacion normal de la conexion (por ejemplo, IP de origen).

Cada operador usa su propia API key. El menu la solicita como entrada oculta y la mantiene en memoria de la sesion como SecureString. Para invocar HTTPS se necesita una representacion temporal legible; esto no protege frente a un administrador o proceso que inspeccione la memoria. La alternativa `VIRUSTOTAL_API_KEY` es una variable de entorno en texto: configurala fuera del repositorio y no la incluyas en comandos con valores literales que queden en el historial.

No se exporta el contexto de autenticacion, ni la clave, ni las cabeceras, ni las excepciones o cuerpos HTTP remotos a los informes. Los errores se resumen con estados controlados. No hay una clave compartida de WinAudit ni secretos requeridos por GitHub Actions.

Los resultados se cachean solo durante la sesion (una hora para informes, 15 minutos para hashes no encontrados). Se espacian consultas unicas al menos 16 segundos y se limita cada contexto a 100 peticiones. Un 429 pausa solicitudes durante 60 segundos; un 401/403 detiene nuevas consultas hasta reconfigurar. No se reintenta una peticion automaticamente. Estas medidas no garantizan cuota disponible: la cuenta puede compartir consumo con otras aplicaciones.

Durante la captura se conserva el SHA-256 observado y la reputacion se consulta al finalizar. Una falta de hash o de respuesta no transforma un proceso en seguro ni malicioso. El informe incluye la fecha de analisis del proveedor, si existe. Las estadisticas pueden ser antiguas o contener falsos positivos; cero detecciones no garantiza seguridad.

**Uso empresarial:** revisa la licencia y los terminos de la cuenta de VirusTotal. Su API publica tiene restricciones de uso comercial y de flujos empresariales que no aportan archivos nuevos. Esta integracion no sube archivos y no supone que una cuenta gratuita sea adecuada para una organizacion.

Fuentes oficiales:

- [Consulta por hash y autenticacion](https://docs.virustotal.com/reference/file-info)
- [Campos de un informe](https://docs.virustotal.com/reference/files)
- [Errores y cuotas](https://docs.virustotal.com/reference/errors)
- [API publica y Premium: condiciones y restricciones](https://docs.virustotal.com/reference/public-vs-premium-api)

## Reportar vulnerabilidades

Usa un aviso privado de seguridad de GitHub para vulnerabilidades. No publiques credenciales, logs privados ni identificadores corporativos en issues publicos.

## LDAP/LDAPS y WinRM

El descubrimiento de directorio no otorga acceso remoto. Los permisos de lectura AD y los permisos WinRM se manejan por separado; seleccionar un equipo del inventario no implica que sea accesible.

LDAP/LDAPS utiliza SASL Kerberos por defecto; Negotiate es una opcion explicita. No se implementa autenticacion Basic/Anonymous. En LDAPS se usa TLS con la validacion normal de Windows, sin callbacks que acepten certificados arbitrarios. En LDAP se exige firma y sellado de sesion. No hay downgrade ni fallback silencioso entre protocolos, ni se modifica la configuracion del cliente o del dominio.

Se restringen los destinos a nombres DNS y se desactivan referrals. Los filtros de nombre escapan parentesis, barra inversa y NUL; solo `*` conserva significado de comodin. SearchBase se transmite como DN separado, no se concatena a un filtro. Las busquedas paginadas tienen timeout y limite local, y los resultados truncados quedan identificados. Las conexiones se liberan en un bloque finally.

WinRM usa Kerberos por defecto; admite HTTPS cuando se solicita. No habilita WinRM, agrega TrustedHosts ni omite validacion de certificados. Las credenciales de LDAP no se reutilizan automaticamente en WinRM, y no se exportan contrasenas.

Referencias oficiales:

- [LdapConnection y autenticacion](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapconnection)
- [Opciones de sesion LDAP](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.ldapsessionoptions)
- [Control de paginacion](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.pageresultrequestcontrol)
