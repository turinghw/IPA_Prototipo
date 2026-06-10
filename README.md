# Sistema RAG con Trazabilidad C2PA

**Institución:** Instituto Tecnológico de Costa Rica (TEC) - Maestría en Ciberseguridad

Este repositorio contiene el prototipo funcional de un sistema de Generación Aumentada por Recuperación (RAG) diseñado con un enfoque estricto en trazabilidad documental, seguridad frente a vulnerabilidades y auditoría de la procedencia de la información. El proyecto implementa los estándares de integridad C2PA (Coalition for Content Provenance and Authenticity) sobre texto puro a través de selectores de variación Unicode.

## Arquitectura del Proyecto

El sistema se compone fundamentalmente de dos aplicaciones de escritorio desarrolladas en Python utilizando la biblioteca Tkinter para garantizar la ejecución local:

1. **`prototipo_generador.py`:** Módulo principal que gestiona la indexación de los documentos, el motor de recuperación semántica con ChromaDB, la inferencia de lenguaje natural conectada a Ollama y el sellado criptográfico del texto generado.
2. **`prototipo_validador.py`:** Módulo cliente independiente que opera fuera de línea. Permite validar si un bloque de texto pegado contiene un manifiesto C2PA genuino y si la información se ha mantenido inalterable.

## Requisitos y Configuración del Entorno

Este proyecto fue desarrollado y validado bajo entorno Windows 11 sin el uso de procesamiento gráfico dedicado (solo CPU). Para la replicación, se requieren los siguientes pasos:

### 1. Instalación de Dependencias

Asegúrese de poseer Python 3.10 o superior y ejecute el siguiente comando para instalar los requerimientos.

```bash
pip install -r requirements.txt
