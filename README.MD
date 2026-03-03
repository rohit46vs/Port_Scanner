# 🔍 Port Scanner

A beginner-friendly cybersecurity project that scans a target for open ports — just like professional tools used by real hackers and security teams!

---

## 📁 Project Structure

```

├── port_scanner.py       # Project 3 
└── README_portscanner.md # This file
```

---

## ⚙️ Requirements

- Python 3.x
- No external libraries needed — uses built-in `socket` and `threading` modules!

---

## 🚀 How to Run

```bash
py  port_scanner.py
```

---

## ⚠️ Legal Warning

> **Only scan systems you OWN or have explicit permission to scan.**
> Scanning someone else's system without permission is **illegal** in most countries.
> Safe targets to scan: `localhost` or `127.0.0.1` (your own machine)

---

## 🖥️ Features

| Option | What it does |
|---|---|
| **1. Common Ports** | Scans 20 well-known ports quickly |
| **2. Custom Range** | Scan any range e.g. ports 1–1024 |
| **3. Single Port** | Check if one specific port is open |
| **4. Learn Mode** | Explains how port scanning works |

---

## 🔍 Example Output

```
=======================================================
  📋 SCAN RESULTS
=======================================================
  Target   : localhost
  IP       : 127.0.0.1
  Scan Time: 2.34 seconds
  Open Ports Found: 3
=======================================================

  PORT     STATUS     SERVICE
  --------------------------------------------------
  80       OPEN       HTTP (Web Server)
  443      OPEN       HTTPS (Secure Web Server)
  3306     OPEN       MySQL (Database)

  ⚠️  Open ports can be potential entry points for attackers!
  ✅ Only keep ports open that you actually need.
=======================================================
```

---

## 🧠 What You Learn From This Project

- What **ports** are and how they work (doors to services)
- How **port scanning** is used in both hacking and defense
- **Multi-threading** in Python — scanning ports simultaneously for speed
- How tools like **Nmap** work under the hood
- The difference between **open, closed, and filtered** ports
- Why closing unnecessary ports is critical for security

---

## 🔒 Common Ports Reference

| Port | Service | Risk if Open |
|---|---|---|
| 21 | FTP | Unencrypted file transfer |
| 22 | SSH | Brute force attacks |
| 23 | Telnet | Very insecure, unencrypted |
| 80 | HTTP | Web attacks |
| 443 | HTTPS | Secure web (generally safe) |
| 3306 | MySQL | Database exposed to network |
| 3389 | RDP | Remote desktop brute force |

---

## 🧪 Safe Testing Targets

| Target | What it is |
|---|---|
| `localhost` or `127.0.0.1` | Your own machine |
| `scanme.nmap.org` | Officially allowed test target by Nmap |

---

