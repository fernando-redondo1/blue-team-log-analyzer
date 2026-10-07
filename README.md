# Log Anomaly Detector

Prototipo de analítica de seguridad escrito en Go para detectar actividad sospechosa en logs de autenticación y de acceso web. Es un proyecto de portfolio orientado a Blue Team / SOC que muestra cómo la ingesta de logs, la extracción de características y la generación de alertas pueden apoyar las operaciones defensivas.

> Proyecto desarrollado con apoyo de IA. Mi trabajo se ha centrado en el diseño de la detección, las pruebas y la validación de los resultados.

## Por qué es útil

La herramienta encaja en una arquitectura defensiva como una capa ligera de detección que complementa a un colector y a un SIEM:

- **Colector:** recoge y reenvía los logs.
- **SIEM:** centraliza y correla las alertas.
- **Capa de detección:** identifica patrones sospechosos, como intentos de fuerza bruta, fallos repetidos o accesos anómalos.

## Qué hace

- Analiza logs de autenticación SSH, como `auth.log`.
- Analiza logs de acceso de Apache en formato común.
- Normaliza los eventos en un modelo interno sencillo.
- Calcula características de comportamiento por IP.
- Genera alertas ante actividad sospechosa.
- Opcionalmente, guarda las alertas en JSON para integrarlas con otras herramientas.

## Estructura del proyecto

- `cmd/log-anomaly-detector`: punto de entrada de la línea de comandos
- `internal/parser`: análisis de logs en formato SSH y Apache
- `internal/features`: cálculo de características de comportamiento
- `internal/detection`: puntuación y generación de alertas
- `internal/report`: informes por consola y en JSON
- `testdata`: logs de ejemplo para pruebas y demostraciones

## Uso

### Logs SSH

```bash
go run ./cmd/log-anomaly-detector -type ssh ./testdata/sample-auth.log
```

### Logs de Apache

```bash
go run ./cmd/log-anomaly-detector -type apache ./testdata/sample-apache.log
```

### Salida en JSON

```bash
go run ./cmd/log-anomaly-detector -type ssh -json ./out/alerts.json ./testdata/sample-auth.log
```

## Desarrollo

```bash
go test ./...
```

## Próximos pasos

- Puntuación de anomalías más completa y explicable.
- Soporte para más fuentes y formatos de log.
- Mejor ajuste de las reglas para controlar los falsos positivos en entornos reales.
- Evolución hacia una capa de detección basada en Machine Learning.
