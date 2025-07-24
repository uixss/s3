
# 🛡️ s3 — Network Stress Testing Framework

> ⚠️ **Advertencia:** Esta herramienta es exclusivamente para **pruebas de estrés autorizadas**. El uso indebido contra objetivos no autorizados es ilegal y puede tener consecuencias penales.

---

## 📌 Descripción

**Krypton** es una framework avanzada escrita en Python para realizar **pruebas de estrés en redes y aplicaciones web** a múltiples niveles del modelo OSI. Su propósito es permitir pruebas de carga, rendimiento, y resistencia de servicios ante distintos tipos de tráfico agresivo o anómalo.

---

## 🚀 Características Principales

- ✅ **Multi-nivel (L3, L4, L7)**: métodos de ataque a nivel de red, transporte y aplicación.
- ✅ **Compatible con proxies** (`HTTP`, `SOCKS4`, `SOCKS5`).
- ✅ **Soporte para bypass Cloudflare y otras protecciones**.
- ✅ **Automatización completa con multihilo y threading seguro**.
- ✅ **Generador aleatorio de User-Agent e IP spoofing**.
- ✅ **Gestión avanzada de proxies con scraping y validación automática**.
- ✅ **Soporte para ataques a servidores de juegos (Roblox, Source Engine)**.
- ✅ **CLI intuitiva con validación robusta de parámetros**.
- ✅ **Estructura modular para añadir métodos fácilmente**.

---

## 🧪 Métodos Soportados

### 🔹 Capa 3 (Red)
| Método | Descripción                        |
|--------|------------------------------------|
| `.ICMP` | Flood ICMP tradicional             |
| `.POD`  | Ataque Ping of Death               |
| `.NTP`  | Ataque NTP Amplification           |
| `.MEM`  | Ataque Memcached Amplification     |

### 🔹 Capa 4 (Transporte)
| Método   | Descripción                   |
|----------|-------------------------------|
| `.UDP`   | Flood UDP                     |
| `.TCP`   | Flood TCP                     |
| `.SYN`   | SYN Flood                     |
| `.TUP`   | Combinado TCP + UDP           |
| `.HEX`   | Payload hexadecimal fijo      |
| `.JUNK`  | Datos basura UDP              |
| `.ROBLOX`| Flood personalizado para Roblox |
| `.VSE`   | Ataque a servidores de juegos Source Engine |

### 🔹 Capa 7 (Aplicación)
| Método        | Descripción                        |
|---------------|------------------------------------|
| `.HTTPGET`    | Flood GET                         |
| `.HTTPCFB`    | Bypass Cloudflare vía scraper     |
| `.HTTPSPOOF`  | Spoof con proxies HTTP/SOCKS      |
| `.HTTPSTORM`  | Requests GET + HEAD + scraper     |
| `.HTTPIO`     | Ataque multi-hilo con bypass simple |
| `.CFBSSL`     | Bypass Cloudflare con cookies SSL |

---

## ⚙️ Optimización y Eficiencia

- 🔁 **ThreadPoolExecutor** para paralelización eficiente.
- 📁 **Carga y guardado de proxies** para evitar scraping redundante.
- 🧠 **Validación inteligente de parámetros** (IP, puerto, duración, tamaño).
- 💨 **Envió rápido de paquetes UDP/TCP con sockets raw y Scapy**.
- 🧪 **Uso de `cloudscraper` y `fake_useragent`** para rotación y evasión básica.
- 🔄 **Selección aleatoria de encabezados, métodos y IPs spoofed**.

---

## 📦 Requisitos

- Python 3.7+
- Módulos:
  - `requests`, `aiohttp`, `cloudscraper`
  - `scapy`, `icmplib`, `socks`, `colorama`
  - `fake_useragent`, `argparse`

```bash
pip install -r requirements.txt
```

---

## 🛠️ Uso

```bash
python3 main.py <método> <objetivo> <puerto> <duración> [tamaño] [hilos]
```

### Ejemplo:

```bash
python3 main.py .UDP 192.168.1.1 80 60 1024 20
python3 main.py .HTTPGET https://example.com 0 60
```

---

## 🛡️ Legal

Esta herramienta debe usarse **únicamente en entornos controlados** y con **permiso explícito del propietario del sistema**. Su uso indebido constituye delito informático en la mayoría de las jurisdicciones.

---

