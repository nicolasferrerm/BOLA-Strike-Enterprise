# Phase 10: Cloud Orchestration & Next-Gen Command Center Backend

Este documento detalla la arquitectura de las funcionalidades propuestas por el **Equipo de Innovación** para la Fase 10 de BOLA Strike Enterprise. Siguiendo las directrices arquitectónicas, el enfoque está en capas de orquestación, telemetría backend y automatización CI/CD, eliminando el UI estático y enfocándose en la infraestructura necesaria para soportarlo (escalabilidad y Big Data).

> [!IMPORTANT]
> **Revisión Requerida**
> Por favor revisa estas arquitecturas. Al aprobar este plan, el *Equipo de Hackers Programadores* procederá con la implementación técnica de estos módulos de infraestructura y orquestación.

## Proposed Changes

### 1. Distributed Ephemeral Fuzzing Orchestrator (K8s)
**Objetivo:** Escalar los ataques de fuzzing horizontalmente usando Kubernetes para ejecutar miles de pruebas simultáneas en mallas de microservicios, simulando un ataque distribuido avanzado.
**Arquitectura a implementar:**
- Nuevo módulo: `backend/app/orchestrator/k8s_job_dispatcher.py`
- Lógica: Un orquestador que simula el despacho de pods efímeros de Kubernetes (K8s Jobs). Cada vez que se descubre una ruta, en lugar de fuzzearla localmente, despacha la orden a un "worker" en la nube.
- Crearemos el archivo de orquestación principal `kubernetes/bola-strike-helm-chart/values.yaml` y plantillas de K8s.

### 2. Zero-Trust FAIR Telemetry Data Lake & Analytics API
**Objetivo:** Evolucionar la API de telemetría hacia un Data Lake orientado a series de tiempo que soporte miles de inserciones por segundo, necesario para alimentar un Dashboard CISO en tiempo real.
**Arquitectura a implementar:**
- Modificación de: `backend/app/api/ciso_telemetry.py`
- Lógica: Se reescribirá el backend para soportar un patrón asíncrono (simulando TimescaleDB/Kafka). Implementaremos autenticación Zero Trust obligatoria (mTLS / JWT estricto) para que únicamente el "Command Center" y los SIEMs tengan acceso a la data.

### 3. Autonomous CI/CD Pipeline Integration (DevSecOps)
**Objetivo:** Automatizar la ejecución de BOLA Strike en el ciclo de vida del desarrollo.
**Arquitectura a implementar:**
- Nuevo módulo CLI headless: `cli_runner.py` (Versión minificada de `bola_strike.py` optimizada para integraciones CI).
- Flujo CI/CD: Creación de la acción de GitHub en `.github/workflows/bola-strike-enterprise.yml`.
- Lógica: En cada *Pull Request*, la herramienta interceptará el esquema (Swagger/OpenAPI), generará un DAG de estado, lanzará los ataques, y si el riesgo financiero FAIR supera un umbral de apetito de riesgo corporativo, romperá el build y generará un parche IaC automáticamente.

## Open Questions

> [!CAUTION]
> **Decisión sobre Tolerancia al Riesgo (Risk Appetite):**
> Para el punto 3 (CI/CD), necesitamos definir un umbral de riesgo corporativo automático. Si una vulnerabilidad genera una expectativa de pérdida anual (ALE) superior a $X CAD, el build se rompe automáticamente. ¿Cuál debería ser el umbral por defecto en CAD para romper el build en un pipeline DevSecOps corporativo? (ej. $10,000 CAD, $50,000 CAD).

## Verification Plan

### Automated Tests
- Validar el despacho simulado de Jobs de Kubernetes en el orquestador.
- Comprobar que el Data Lake asíncrono soporta peticiones masivas y valida el token Zero Trust de forma estricta.
- Ejecutar el pipeline `.github/workflows` de forma teórica para garantizar la estructura del CI/CD de BOLA Strike.
