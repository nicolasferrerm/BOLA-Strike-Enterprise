# BOLA Strike Enterprise (v12.0)

**Guerra Autónoma de APIs, Orquestación DevSecOps y Telemetría de Riesgo Financiero**

[![Quantum Ready](https://img.shields.io/badge/Cryptography-Quantum_Ready-purple.svg)]()
[![OSFI Compliant](https://img.shields.io/badge/Compliance-OSFI%20%7C%20SOC2-blue.svg)]()
[![eBPF Healer](https://img.shields.io/badge/Kernel-eBPF%2FXDP-black.svg)]()

*(English version available in [README.md](README.md))*

## 1. Resumen Ejecutivo
BOLA Strike Enterprise es una plataforma DevSecOps "Nivel Dios", impulsada por Inteligencia Artificial, diseñada para aniquilar vulnerabilidades de Autorización a Nivel de Objeto (BOLA/IDOR) antes de que alcancen entornos de producción. Evolucionando mucho más allá de un escáner tradicional, proporciona una arquitectura autónoma de defensa en profundidad diseñada específicamente para corporaciones Tier-1 (ej. sectores de Energía, Banca y Telecomunicaciones en Canadá).

Descubre automáticamente esquemas de API, sintetiza Amenazas Persistentes Avanzadas (APTs) usando IA polimórfica, traduce riesgos cibernéticos en métricas financieras para juntas directivas (modelo FAIR) y logra una auto-remediación de latencia cero mediante manipulación de paquetes a nivel de kernel.

## 2. Capacidades Principales y Arquitectura (Fases 1-12)

### 2.1. Descubrimiento y Reconocimiento de Máquinas de Estado
*   **Shadow API Parser:** Ingiere dinámicamente esquemas OpenAPI/Swagger y GraphQL para mapear endpoints no documentados.
*   **Service Mesh Interceptor:** Se ancla a flujos de telemetría de Istio/Envoy para descubrir microservicios activos, eliminando la necesidad de documentación técnica provista por humanos.
*   **DAG State Machine Fuzzer:** Traduce las interacciones de API en un Grafo Acíclico Dirigido (DAG) para encadenar ataques transaccionales complejos (ej. `Crear Usuario -> Obtener Token -> Atacar Recurso`).

### 2.2. IA Ofensiva Autónoma
*   **Generador Contextual LLM:** Utiliza un Núcleo Neuronal (Mock Ollama/Llama) para analizar semánticamente los nombres de los parámetros (ej. `tenant_id`) y generar cargas maliciosas contextuales basadas en la lógica de negocio.
*   **Auditoría y Cracking Offline de JWT:** Evalúa JSON Web Tokens buscando secretos débiles y ataques de degradación de algoritmos (`alg: none`), manipulando privilegios para quebrar los perímetros de Zero Trust.
*   **Evasión Avanzada de WAF:** Ofusca automáticamente los payloads (Codificación Unicode, Transferencia Chunked) para evadir firewalls de aplicaciones web tradicionales.

### 2.3. Defensa de Latencia Cero y Engaño
*   **Hyper-Speed Healer (eBPF/XDP):** Despliega código eBPF directamente en la pila de red del kernel de Linux (tarjeta de red). Al detectar un Zero-Day, los paquetes maliciosos son descartados en nanosegundos, otorgando inmunidad absoluta contra DDoS sin latencia aplicacional.
*   **Decepción Polimórfica (Núcleo Red/Blue):** Sintetiza micro-honeypots dinámicos. Cuando los atacantes sondean el perímetro, endpoints falsos mutan para atrapar a los actores APT, aislándolos en sandboxes de Kubernetes para extraer sus Tácticas, Técnicas y Procedimientos (TTPs).

### 2.4. Telemetría Ejecutiva y Cumplimiento
*   **Telemetría Financiera FAIR (Dashboard CISO):** Reemplaza las métricas técnicas CVSS por el modelo FAIR, cuantificando la vulnerabilidad en moneda dura (Expectativa de Pérdida Anualizada en CAD/USD).
*   **Ledger Inmutable Post-Cuántica:** Todos los artefactos de seguridad se anclan a una cadena de bloques interna (Hyperledger) utilizando criptografía estandarizada por el NIST (CRYSTALS-Kyber/Dilithium) para garantizar el no-repudio total (Compliance OSFI).
*   **Integraciones Empresariales:** Exporta inteligencia a plataformas SIEM vía ArcSight CEF y despliega parches de Infraestructura como Código (IaC - Terraform) automáticamente a AWS WAF.

## 3. Guía de Uso para Expertos

### 3.1. Auditoría Local (Ingenieros de Seguridad)
Para ejecutar una auditoría BOLA profunda contra una especificación API:
```bash
python bola_strike.py --swagger https://api.enterprise.corp/v1/openapi.json --depth 5 --enable-ai
```
*   `--depth 5`: Define el límite de recursión en el grafo (previene desbordamientos de memoria RAM).
*   `--enable-ai`: Activa el motor LLM para construir ataques semánticos.

### 3.2. Automatización en CI/CD (DevSecOps)
BOLA Strike se incrusta en GitHub Actions / GitLab CI como una compuerta de seguridad estricta (Security Gate).
```bash
# Ejecutado dentro de un runner efímero (Container)
python cli_runner.py --target ./openapi.yaml --method ALL
```
*Nota: El umbral de Apetito de Riesgo (`--risk-appetite`) está bloqueado a nivel de servidor backend y validado mediante PyJWT para prevenir manipulaciones en el pipeline.*

### 3.3. Orquestación Distribuida en Kubernetes
Para auditorías a escala global, el orquestador K8s despacha pods de ataque efímeros en paralelo.
1. Desplegar el Helm Chart en el namespace `secops-fuzzing`.
2. El `k8s_job_dispatcher.py` montará los certificados mTLS vía CSI Secrets Store y ejecutará cientos de instancias de fuzzing bajo políticas estrictas de `runAsNonRoot`.

## 4. Arquitectura de Seguridad y Zero Trust
BOLA Strike está cimentado en el perímetro de "Nunca Confiar, Siempre Verificar":
*   **Identidad:** Toda petición interna (ej. API FAIR) requiere tokens PyJWT firmados criptográficamente.
*   **Aislamiento de Cargas:** Los nodos operan con sistemas de archivos de solo lectura y sin auto-montaje de tokens K8s (`automountServiceAccountToken: false`).
*   **Integridad de Datos:** Todo reporte es codificado en SHA-256 dentro del *Evidence Locker* antes de ser firmado por la cadena de bloques cuántica.

---
*Desarrollado por Nicolas Ferrer | Arquitecto Principal de Ciberseguridad & Estratega DevSecOps*
