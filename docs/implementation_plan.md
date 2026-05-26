# Phase 8: Enterprise DevSecOps & AI Integration (BOLA Strike v10.0)

Este documento detalla la arquitectura de las nuevas funcionalidades propuestas por el **Equipo de Innovación** (y revisadas por Investigación/Arquitectura) para la Fase 8 de BOLA Strike Enterprise.

> [!IMPORTANT]
> **User Review Required**
> Por favor revisa estas arquitecturas. Al aprobar este plan, el *Equipo de Hackers Programadores* procederá con la implementación técnica de estos módulos en el backend.

## Proposed Changes

### 1. eBPF-Driven Service Mesh Telemetry Injection
**Objetivo:** Descubrir y auditar microservicios internos en tiempo real interceptando el Service Mesh (Istio/Envoy) sin requerir especificaciones OpenAPI.
**Arquitectura a implementar:**
- Nuevo módulo: `backend/app/core/service_mesh_telemetry.py`
- Lógica: Simularemos un interceptor que extrae esquemas dinámicos del tráfico de red (PCAP o logs de Envoy) y genera dinámicamente payloads de fuzzing BOLA para inyectarlos en la malla de servicios.

### 2. LLM-Driven Contextual State-Machine Fuzzing
**Objetivo:** Evolucionar el fuzzer para que utilice Inteligencia Artificial capaz de inferir lógica de negocio y mantener contexto en ataques transaccionales profundos (APT style).
**Arquitectura a implementar:**
- Nuevo worker: `backend/app/workers/llm_payload_generator.py`
- Lógica: Integrar un mock de comunicación con un SLM/LLM local que, al leer los nombres de los parámetros (ej. `invoice_id`, `tenant_id`), comprenda el contexto financiero y genere cadenas de ataque con lógica de negocio (no solo strings aleatorios).

### 3. FAIR-Model Executive Telemetry Pipeline (GraphQL)
**Objetivo:** Backend para el "Next-Gen CISO Dashboard", cuantificando el riesgo financiero real usando la metodología FAIR.
**Arquitectura a implementar:**
- Nuevo módulo: `backend/app/api/ciso_telemetry.py`
- Lógica: Consolidar las vulnerabilidades encontradas, mapearlas contra criticidad del activo (mock de CMDB) y exponer un endpoint GraphQL o REST avanzado que calcule el impacto financiero en USD/CAD de las brechas de BOLA, alimentando dashboards ejecutivos y SIEMs.

### 4. Gateway-Native Policy Fuzzing & IaC Auto-Remediation
**Objetivo:** Fuzzear directamente las políticas de Gateways (AWS/Kong) y generar *Pull Requests* de remediación en repositorios de Terraform/GitOps automáticamente.
**Arquitectura a implementar:**
- Nuevo módulo: `backend/app/core/iac_remediator.py`
- Lógica: Motor que, al detectar una vulnerabilidad BOLA, genere un parche de infraestructura como código (IaC) (ej. Regla JSON para AWS WAF o política de Kong) diseñado para bloquear el vector de ataque antes de que llegue al código fuente.

## Open Questions

> [!CAUTION]
> **Decisión sobre Modelo de IA:**
> Para el módulo *LLM-Driven Fuzzing* (Punto 2), ¿prefieres que simulemos la interacción de una API genérica de OpenAI (más fácil de integrar inicialmente pero requiere red) o diseñamos la arquitectura para conectarse a un demonio de **Ollama local** (máxima privacidad y aislamiento de red para bancos/energía)? Implementaré la base adaptada a tu preferencia.

## Verification Plan

### Automated Tests
- Validar la extracción de esquemas de un log de Service Mesh.
- Verificar que el generador LLM crea payloads semánticamente correctos para parámetros financieros.
- Consumir el endpoint de telemetría FAIR y comprobar el cálculo de riesgo en dólares.
- Generar un parche de remediación de AWS WAF válido en JSON.
