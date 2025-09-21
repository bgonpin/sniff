# Sniff - Analizador de Paquetes de Red

Una herramienta de captura y análisis de paquetes de red basada en Python que captura, almacena y organiza paquetes de red para análisis forense detallado. Esta herramienta proporciona interfaces tanto gráficas como de línea de comandos para monitoreo profesional de red.

## Características

### Captura de Red (sniff.py)
- **Captura de Paquetes en Tiempo Real**: Captura tráfico de red en vivo usando Scapy
- **Soporte Multi-interfaz**: Detecta automáticamente y permite selección de interfaces de red
- **Almacenamiento Dual**: Guarda paquetes tanto en base de datos MongoDB como en archivos PCAP
- **Rotación Automática**: Crea nuevos archivos PCAP con marcas de tiempo al alcanzar 1000 paquetes
- **Inserción por Lotes en Base de Datos**: Almacena paquetes en MongoDB eficientemente en lotes de 1000
- **Interfaz Gráfica**: Interfaz gráfica amigable basada en PySide6 para fácil operación

### Análisis y Organización de Paquetes (ordenar_paquetes.py & ordenar_paquetes_sin_entorno_grafico.py)
- **Múltiples Métodos de Ordenamiento**:
  - **Por Timestamp**: Ordenamiento cronológico de paquetes capturados
  - **Por Secuencia TCP**: Organiza paquetes TCP por números de secuencia dentro de cada flujo
  - **Conversacional**: Agrupa paquetes por conversaciones bidireccionales
- **Filtrado Avanzado**: Filtrar paquetes por direcciones IP de origen y destino
- **Resolución DNS**: Resuelve direcciones IP a nombres de dominio para mejor legibilidad
- **Generación de Estadísticas**: Proporciona distribución detallada de protocolos y conteos de paquetes
- **Capacidades de Exportación**: Exporta paquetes organizados al formato JSON
- **Interfaz Dual**: Disponible como aplicación gráfica (PySide6) y herramienta de línea de comandos

## Requisitos

### Requisitos del Sistema
- Python 3.7+
- Servidor MongoDB ejecutándose localmente o remotamente
- Interfaz de red con capacidades de modo promiscuo (para captura)
- Privilegios administrativos (para captura de paquetes)

### Dependencias Python
```
PySide6>=6.0.0    # Framework gráfico
Scapy>=2.4.0      # Manipulación de paquetes
Pymongo>=4.0.0    # Controlador MongoDB
```

## Instalación

1. **Clonar el repositorio**:
   ```bash
   git clone https://github.com/bgonpin/sniff.git
   cd sniff
   ```

2. **Instalar dependencias**:
   ```bash
   pip install pyside6 scapy pymongo
   ```

3. **Iniciar MongoDB** (si está ejecutándose localmente):
   ```bash
   sudo systemctl start mongod
   # o
   mongod
   ```

4. **Otorgar permisos necesarios** (para Linux):
   ```bash
   sudo setcap cap_net_raw=eip $(which python3)
   ```

## Uso

### Captura de Red

Ejecutar la aplicación de captura de paquetes:
```bash
python sniff.py
```

1. Seleccionar la interfaz de red del menú desplegable
2. Hacer clic en "Start Sniffing" para iniciar la captura
3. Los paquetes se guardan automáticamente en MongoDB y archivos PCAP
4. Hacer clic en "Stop Sniffing" cuando termine

Los archivos PCAP se crean con marcas de tiempo: `AAAA-MM-DD_HH-MM-SS.pcap`

### Análisis de Paquetes (GUI)

Lanzar el analizador de paquetes:
```bash
python ordenar_paquetes.py
```

1. Hacer clic en "Load Packets from MongoDB" para cargar datos capturados
2. Opcionalmente filtrar por IP de origen/destino
3. Hacer clic en "Filter and Display Conversations" para ver paquetes organizados

### Análisis de Paquetes (CLI)

Usar la versión de línea de comandos:
```bash
python ordenar_paquetes_sin_entorno_grafico.py
```

Este script automáticamente:
- Carga todos los paquetes desde MongoDB
- Genera estadísticas
- Ordena paquetes por timestamp, secuencia TCP y conversación
- Exporta resultados a `packets_ordered_by_conversation.json`

## Estructura del Proyecto

```
.
├── sniff.py                              # Aplicación principal de captura (GUI)
├── ordenar_paquetes.py                   # Analizador y ordenador de paquetes (GUI)
├── ordenar_paquetes_sin_entorno_grafico.py  # Versión CLI del ordenador de paquetes
└── README.md                             # Este archivo
```

## Estructura de Datos

Los paquetes se almacenan en MongoDB con los siguientes campos:
- `_class`: Tipo de paquete (ej. "Ether", "IP", "TCP")
- `payload`: Capas de paquete anidadas
- `timestamp`: Timestamp Unix de captura
- `length`: Longitud del paquete en bytes
- `summary`: Resumen legible del paquete
- `data`: Datos de carga útil sin procesar (si están disponibles)

## Modos de Ordenamiento

### Ordenamiento por Timestamp
Organiza paquetes cronológicamente basándose en el tiempo de captura.

### Ordenamiento por Secuencia TCP
Agrupa paquetes TCP por flujos unidireccionales y ordena cada flujo por números de secuencia TCP.

### Ordenamiento Conversacional
Agrupa paquetes por conversaciones TCP bidireccionales y los ordena cronológicamente dentro de cada conversación.

## Solución de Problemas

### Problemas Comunes

1. **Permiso denegado para captura de paquetes**:
   ```bash
   sudo setcap cap_net_raw=eip $(which python3)
   ```

2. **Problemas de conexión con MongoDB**:
   - Asegurarse de que MongoDB esté ejecutándose: `sudo systemctl status mongod`
   - Verificar conectividad de red para MongoDB remoto

3. **Interfaz no mostrándose**:
   - Ejecutar como administrador/sudo
   - Verificar que la interfaz soporte modo promiscuo

## Contribuyendo

1. Hacer fork del repositorio
2. Crear rama de funcionalidad: `git checkout -b nombre-funcionalidad`
3. Confirmar cambios: `git commit -am 'Agregar nueva funcionalidad'`
4. Subir a la rama: `git push origin nombre-funcionalidad`
5. Enviar pull request

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para detalles.

## Descargo de Responsabilidad

Esta herramienta está destinada únicamente para propósitos educativos y de análisis de red autorizado. Asegurarse de tener la autorización apropiada antes de capturar tráfico de red. Los desarrolladores no se hacen responsables del mal uso de este software.

## Autor

bgonpin - [GitHub](https://github.com/bgonpin)
