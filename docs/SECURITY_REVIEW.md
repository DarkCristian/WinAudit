# Revisión de seguridad — 05/11/2026

Alcance: revisión del código de WinAudit, launcher, ensamblado standalone, pruebas y workflow. Correcciones en `main` posteriores a `v0.4.0-alpha`; el tag y el asset anteriores permanecen sin estas correcciones. No es una certificación, pentest completo ni comprobación del nivel de parches del equipo del operador.

## Hallazgos y cambios

| Área | Riesgo observado | Cambio |
| --- | --- | --- |
| Bootstrapper | Descargaba varios archivos de `main` sin comprobar integridad ni una revisión común; posible mezcla o sustitución de código | Un standalone desde commit inmutable, SHA-256 fijado, fallo antes de ejecutar si difiere, timeout 30 s, sin redirecciones |
| Evidencia de archivos | Una ruta UNC o unidad de red podía iniciar autenticación SMB durante hashes o firma; junctions podían desviar la lectura o salida | Validación local previa, rechazo de UNC/dispositivos/ADS/unidades de red y componentes reparse |
| Informes | Riesgo de sobrescritura de un archivo existente | Archivos nuevos con CreateNew; destinos locales validados |
| Presentación | Nombres y mensajes no confiables podían contener controles de terminal o marcas bidi | Saneamiento en tablas, árbol, resúmenes y errores de la interfaz; evidencia JSON/XML cruda preservada |
| XML | El parser no explicitaba todas sus restricciones | XmlReader con DTD prohibido, resolver nulo y máximo 4 Mi caracteres; endurecimiento sin afirmar una explotación XXE demostrada en cada runtime |
| Recursos | Consultas amplias y paginación podían consumir recursos durante mucho tiempo | Tope de eventos por registro/lectura, estado Limitado; máximo de páginas LDAP además de timeout y cantidad |
| CI | Referencias mutables de acciones externas | Acciones fijadas a commits, permisos contents:read, checkout sin credenciales persistentes y timeout del job |

Estos hallazgos propios no tienen un identificador CVE asignado. No se presentan como CVE del proyecto.

## CVE del entorno de ejecución

WinAudit utiliza componentes del sistema; no incluye un runtime propio ni paquetes NuGet descargados. La aplicabilidad de una CVE depende de versión, plataforma, parches y funciones utilizadas.

- **CVE-2026-96303 — PowerShell 7 en Windows:** el aviso oficial identifica un bypass de seguridad y mínimos corregidos 7.4.21, 7.5.12 y 7.6.7. El punto de entrada y el launcher rechazan versiones inferiores dentro de esas ramas y ramas antiguas. Una rama posterior genera advertencia por no estar evaluada. [Aviso oficial de PowerShell](https://github.com/PowerShell/Announcements/blob/main/pwsh/2026/10/CVE-2026-96303.md).
- **CVE-2025-54100 — Windows PowerShell 5.1 y contenido web:** Microsoft recomienda `-UseBasicParsing` para evitar ejecución durante el parsing HTML. El launcher ya utilizaba esta opción y la conserva; no se atribuye su introducción a esta corrección. Windows debe tener sus actualizaciones de seguridad. [Guía oficial de Microsoft](https://support.microsoft.com/en-us/servicing/os/windows/2025/12/powershell-5-1-invoke-webrequest-preventing-script-execution-from-web-content).

La versión 5.1 por sí sola no acredita todas las KB instaladas. El script no instala parches, no examina exhaustivamente todas las CVE de Windows/.NET y no garantiza protección frente a vulnerabilidades futuras. Un control de versión dentro de un script tampoco protege el arranque inicial de un intérprete vulnerable ni el primer `irm | iex`.

## Integridad y reproducción

El launcher fija el standalone del commit Git `6e883047e3b11ba19e68bc19fc2f977f745842ec`, blob `a0e6322519a812f5baae1d73e91b0926bc334d19`.

SHA-256 de los bytes LF/UTF-8 sin BOM:

```text
369a7d9518a240a4a81e76a2dd7acb05146be228eb4d8ad27c2c0e0100229f14
```

El launcher mantiene abierto el archivo verificado sin compartir escritura/borrado hasta finalizar su ejecución. Su propio código sigue siendo una raíz de confianza: un atacante que controle el launcher podría cambiar tanto URL como hash. Revisá una copia aprobada o usá un commit fijado por un canal de confianza. No hay firma Authenticode del editor ni garantía frente a un administrador local, manipulación de la sesión o carreras de reemplazo de directorios con permisos de escritura.

## Pruebas y límites

Las pruebas automatizadas en Windows PowerShell 5.1 y PowerShell 7 cubren versiones vulnerables/corregidas de ejemplo, rutas UNC y unidades mapeadas simuladas, junction real temporal, creación exclusiva, rechazo de DTD y XML sobredimensionado, controles de terminal, límites de eventos y descarga alterada sin ejecución. El caso de descarga válida usa el standalone del repositorio y verifica bloqueo de escritura y limpieza; HTTP se simula, sin credenciales reales.

Se mantienen las pruebas de fechas, captura, correlación, árbol, hashes, reputación simulada, LDAP/LDAPS/RSAT y WinRM simulados. Siguen pendientes pruebas operativas contra un dominio real, permisos del entorno, certificados reales y API de VirusTotal autorizada.

El tope de eventos se aplica antes del filtro de proceso, conservando los más recientes. Un intervalo limitado puede omitir evidencia: debe acotarse o consultarse por períodos menores. Una captura larga puede seguir generando mucho volumen; no hay cuota global de disco. Las ACL de informes se heredan y la evidencia no se cifra automáticamente. Authenticode puede realizar consultas de confianza/revocación según Windows; rechazar rutas SMB no significa ausencia total de tráfico de red.

[Guía de uso](USAGE.md) · [Modelo de seguridad y limitaciones](SECURITY.md)
