# BOLA Strike Enterprise (v12.0)

**Guerra Autónoma de APIs, Orquestación DevSecOps y Telemetría de Riesgo Financiero**

[![Quantum Ready](https://img.shields.io/badge/Cryptography-Quantum_Ready-purple.svg)]()
[![OSFI Compliant](https://img.shields.io/badge/Compliance-OSFI%20%7C%20SOC2-blue.svg)]()
[![eBPF Healer](https://img.shields.io/badge/Kernel-eBPF%2FXDP-black.svg)]()

*(English version available in [README.md](README.md))*

¡Bienvenido a BOLA Strike Enterprise! Esta plataforma está diseñada para encontrar y neutralizar la vulnerabilidad de API más peligrosa de internet hoy en día: **Broken Object Level Authorization (BOLA/IDOR)**.

Aunque la tecnología interna está construida para expertos élite en ciberseguridad (usando IA y defensas a nivel de Kernel), hemos diseñado esta guía para que sea **muy fácil de seguir**, ¡incluso si eres nuevo en el mundo de DevSecOps!

---

## 🚀 Guía de Inicio Rápido (Para Principiantes)

¿Quieres ver cómo funciona rápidamente? Sigue estos sencillos pasos para escanear una API en tu computadora.

### Requisitos Previos
Solo necesitas tener dos cosas instaladas en tu equipo:
1. **Python 3.10+** (Descárgalo desde python.org)
2. **Git** (Para descargar este proyecto)

### Paso 1: Instalar la Herramienta
Abre tu terminal (o consola de comandos) y ejecuta lo siguiente:
```bash
# Descarga el repositorio a tu computadora
git clone https://github.com/nicolasferrer/bola-strike-enterprise.git
cd bola-strike-enterprise/Tools/API_Logic_Fuzzer

# Instala las dependencias necesarias de Python
pip install -r requirements.txt
```

### Paso 2: Tu Primer Escaneo
Imagina que quieres probar una API de desarrollo que está en `http://localhost:8000/openapi.json`. Ejecuta este comando:
```bash
python bola_strike.py --target http://localhost:8000/openapi.json --method ALL --depth 3
```
**¿Qué acaba de pasar?**
La herramienta leyó la documentación de tu API, descubrió todas las rutas (como `/usuarios` o `/facturas`), e intentó hackearlas cruzando IDs para ver si el Usuario A podía borrar los datos del Usuario B. ¡Así de simple!

---

## 📖 Cómo Usarla como un Profesional (Modos Avanzados)

BOLA Strike puede hacer mucho más que un escaneo simple. Aquí están las 3 formas principales de usarla en una empresa:

### 1. El Modo Hacker Ético (Uso Local)
Si estás probando una API y quieres usar nuestra **Inteligencia Artificial** para generar ataques inteligentes:
```bash
python bola_strike.py --target https://api.tuempresa.com/v1/swagger.yaml \
                      --enable-ai \
                      --evasion-level aggressive \
                      --export-pdf mi_reporte.pdf
```
*   `--enable-ai`: Enciende la IA. En lugar de enviar texto basura aleatorio, la IA lee tu API y genera IDs, correos y datos financieros falsos pero muy realistas.
*   `--evasion-level aggressive`: Oculta el ataque para que los Firewalls (WAF) no te detecten ni te bloqueen.
*   `--export-pdf`: Genera un reporte PDF hermoso y profesional listo para entregar a tu jefe o cliente.

### 2. El Modo DevSecOps (Automatización CI/CD)
Puedes configurar BOLA Strike para que pruebe automáticamente todo el código nuevo *antes* de que salga al público. Solo agrega esto a tu GitHub Actions:
```yaml
      - name: Ejecutar Filtro de Seguridad BOLA Strike
        run: python cli_runner.py --target ./openapi.yaml
        env:
          ZERO_TRUST_TOKEN: ${{ secrets.MI_TOKEN_SECRETO }}
```
**¿Cómo funciona?** Si un programador escribe código vulnerable por accidente, BOLA Strike calcula cuánto dinero podría perder la empresa (en Dólares). Si el riesgo financiero es muy alto, ¡**cancela el despliegue** al instante!

### 3. El Modo Arquitecto Cloud (Kubernetes)
Si trabajas en una empresa gigante con cientos de APIs en la nube:
```bash
helm install bola-strike ./kubernetes/bola-strike-helm-chart -n secops
```
**¿Cómo funciona?** La herramienta lanzará cientos de "cápsulas" (pods) diminutas e invisibles en tu nube. Éstas atacarán masivamente toda tu red al mismo tiempo, reportarán los fallos y luego se auto-destruirán sin dejar rastro.

---

## 🧠 ¿Qué hace a BOLA Strike "Nivel Dios"? (Las 12 Fases explicadas fácil)

Por detrás, la plataforma ejecuta 12 tecnologías súper avanzadas. Aquí te explicamos qué hacen de forma sencilla:

1. **Descubrimiento de APIs:** Encuentra APIs ocultas escuchando el tráfico de tu red.
2. **Fuzzing de Máquina de Estados:** No solo ataca una página. Aprende a "Crear usuario -> Iniciar sesión -> Agregar al carrito -> Intentar robar el carrito de otro".
3. **Soporte GraphQL:** Puede hackear bases de datos modernas (GraphQL) con la misma facilidad que las APIs normales.
4. **Cracking de JWT:** Intenta falsificar los tokens de inicio de sesión (cookies) para hacerle creer al sistema que es el Administrador.
5. **Evasión de WAF:** Actúa como un ninja, esquivando las defensas de firewalls como Cloudflare.
6. **Reportes Ejecutivos:** Crea archivos técnicos para programadores y reportes legibles para gerentes.
7. **Integración Service Mesh:** Se conecta directo al enrutador central de tu nube.
8. **Inteligencia Artificial (LLM):** Usa IA generativa para pensar y atacar como un humano.
9. **Riesgo Financiero (FAIR):** No te dice "Riesgo Alto". Te dice "Este error nos podría costar $150,000 dólares en multas".
10. **Auto-Remediación:** Escribe código automáticamente para bloquear el ataque en tu firewall mientras tus programadores arreglan el error.
11. **Sanador del Kernel (eBPF):** Si detecta un ataque en vivo, corta la conexión del hacker instantáneamente desde la tarjeta de red de la computadora. Esto significa 0 latencia para tus usuarios reales.
12. **Ledger Cuántico:** Guarda todos los registros de seguridad en una blockchain privada usando criptografía Post-Cuántica. Esto significa que ni siquiera una supercomputadora del año 2035 podría alterar tus logs.

---
**Desarrollado por Nicolas Ferrer** | *Arquitecto Principal de Ciberseguridad & Estratega DevSecOps*
