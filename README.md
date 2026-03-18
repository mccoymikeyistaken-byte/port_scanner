# 🔍 Port Scanner

> *A learning project that got a little out of hand.*

Started as "let me try connecting to a port" and somehow ended up with CVE lookups, OS fingerprinting, async I/O, and JSON reports. Funny how that happens.

This is a Python-based TCP port scanner built from scratch — no Nmap, no shortcuts, just sockets, an event loop, and a bit of curiosity about what's listening on your network.

---

## ⚠️ The Usual Disclaimer

Only scan hosts **you own or have explicit permission to scan.**
Scanning someone else's network without permission is illegal in most jurisdictions and generally a bad time for everyone involved.
This tool is for learning, CTFs, and authorized pentesting. Not mischief.

---

## 🧠 What's Actually Happening Under the Hood

When you run this scanner, here's what it does:

1. **Resolves your target** — converts hostname to IP if needed
2. **Fingerprints the OS** — sends an ICMP ping and reads the TTL value from the response. Linux starts at 64, Windows at 128. Simple but surprisingly effective.
3. **Scans ports concurrently** — creates thousands of async tasks and runs them through an event loop controlled by a semaphore. No thread overhead, no OS context switching — just pure I/O concurrency.
4. **Grabs banners** — once a port is open, it tries to read what the service says about itself. HTTP ports get a `HEAD` probe first. SSH, FTP, SMTP etc. announce themselves immediately on connect.
5. **Looks up CVEs** — takes the service/version from the banner and hits the NVD (National Vulnerability Database) API asynchronously to find known vulnerabilities. Free, no API key needed.
6. **Saves a report** — dumps everything into a clean JSON or TXT file so you have receipts.

---

## ✨ Features

| Feature | Details |

| ⚡ Async scanning | `asyncio` + `asyncio.Semaphore` — no thread overhead |

| 🎯 Banner grabbing | HTTP probe + generic recv for other services |

| 🔎 Service detection | Maps open ports to known service names |

| 🧬 OS fingerprinting | TTL-based guess via raw ICMP (requires sudo) |

| 🛡️ CVE lookup | Async queries to NVD API via `aiohttp` |

| 🗂️ Static CVE mapping | Known risky ports (445, 3389, 135) get looked up even without a banner |

| 🎨 Colored output | Because staring at monochrome text is so 1995 |

| 📋 Output reports | Save results as JSON or TXT |

| ✅ Input validation | Handles bad IPs, invalid ranges, and unreachable hosts gracefully |

| ⏱️ Scan timer | Know exactly how fast your network is |

---

## 🚀 Installation

```bash
git clone https://github.com/mccoymikeyistaken-byte/port_scanner.git
cd port_scanner
pip install -r requirements.txt
```

**Requirements:**
```
aiohttp
colorama
scapy
```

---

## 🎮 Usage

### Scan default range (1-1024)
```bash
python port_scanner.py 192.168.1.1
```

### Scan a custom range
```bash
python port_scanner.py 192.168.1.1 1-10000
```

### Scan a single port
```bash
python port_scanner.py 192.168.1.1 80
```

### Save output as JSON
```bash
python port_scanner.py 192.168.1.1 -o report.json
```

### Save output as TXT
```bash
python port_scanner.py 192.168.1.1 -o report.txt
```

### Full options
```bash
python port_scanner.py 192.168.1.1 1-65535 -t 0.5 -w 200 -o results.json
```

### OS fingerprinting (needs root for raw ICMP)
```bash
sudo python port_scanner.py 192.168.1.1 1-1024
```

---

## ⚙️ CLI Arguments

| Argument | Default | Description |
|---|---|---|
| `host` | required | Target IP or hostname |
| `ports` | `1-1024` | Port or range (e.g. `80` or `1-65535`) |
| `-t / --timeout` | `0.3s` | Timeout per port in seconds |
| `-w / --workers` | auto | Semaphore concurrency limit |
| `-o / --output` | `results.txt` | Output file (`.json` or `.txt`) |

---

## 📊 Sample Output

```
  [*] Resolved : scanme.example.com → 192.168.1.1
  [*] OS Guess : Linux/Unix (TTL=63)

  [*] Target   : 192.168.1.1
  [*] Range    : 1 - 1024
  [*] Timeout  : 0.3s

  Scanning...

  [+] Port 22     open   (ssh)
      Banner : SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
      CVEs found: 2
        CVE-2023-38408 | Score: 9.8 | CRITICAL
        Remote code execution via forwarded ssh-agent...

  [+] Port 80     open   (http)
      Banner : HTTP/1.1 200 OK

  ─────────────────────────────────
  SCAN SUMMARY
  ─────────────────────────────────
  OS Guess : Linux/Unix (TTL=63)
  ─────────────────────────────────
  22     open   ssh          SSH-2.0-OpenSSH_8.9p1
  80     open   http         HTTP/1.1 200 OK

  [*] 2 open port(s) found
  [*] Scan completed in 0.87 seconds
  ─────────────────────────────────
```

---

## 🗺️ What I Learned Building This

- **Threading vs Asyncio** — threading spawns OS-level threads, each consuming memory and requiring expensive context switching. Asyncio runs everything in a single thread — the event loop switches between tasks at `await` points. For I/O-bound work like network scanning, asyncio wins cleanly.
- **Why Semaphore** — `asyncio.gather()` would happily spawn 65,535 concurrent tasks and crash your machine. A `Semaphore` acts as a gate — only N tasks run at once, the rest wait their turn politely.
- **Blocking kills async** — mixing synchronous blocking calls (like `requests`) into an async program freezes the entire event loop. Everything waits. Replaced with `aiohttp` which plays nicely with asyncio.
- **DNS resolution is expensive** — resolving the hostname inside each task thousands of times was a real performance bug. Resolve once, reuse everywhere.
- **Race conditions are sneaky** — multiple tasks writing to the same list without an `asyncio.Lock` can silently lose data. No error, no warning, just missing results.
- **Firewalls block ICMP** — phones and some routers drop ping packets entirely, which is why OS fingerprinting returns "no response" on certain targets.
- **Banners are chatty** — a surprising number of services announce exactly what software and version they're running. This is why keeping software updated matters.

---

## 🏗️ Project Structure

```
port_scanner/
├── port_scanner.py   # core scanner — async engine
├── save_reports.py   # report generation (JSON + TXT)
└── README.md
```

---

## 🛣️ What's Coming Next

- [ ] UDP port scanning
- [ ] CIDR range scanning (`192.168.1.0/24`)
- [ ] Web dashboard (Flask)

---

## 🤖 Why This Exists

Because the best way to understand how network security tools work is to build one yourself.
Also because it's genuinely fun to watch your code discover what's quietly listening on a network.

Built with Python, curiosity, and an unreasonable number of Stack Overflow tabs.

---

*Don't forget to say hi to the open ports.* 👋