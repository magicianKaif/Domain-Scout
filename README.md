
# Domain-Scout

**Domain-Scout** is a powerful Python-based reconnaissance tool for websites and IPs.  
It performs advanced scanning, fingerprinting, and vulnerability detection — built for cybersecurity learners, red teamers, and CTF warriors.

> 🔥 Developed by: magician slime

---

## 🚀 Features

- 🌐 Resolve domain to IP
- 🔁 Reverse DNS lookup
- 🗺 IP Geolocation (via ipinfo.io)
- 🚪 Custom or full port scanning (1-65535)
- 🧠 Service & version detection (Nmap-based)
- 🧬 OS fingerprinting
- ⚔️ CVE and vulnerability checks (via `--script vuln`)

---

## 🛠 Requirements

- Python 3.x  
- [Nmap](https://nmap.org/) (must be installed on system)  
- Python Libraries:
  ```bash
  pip install requests python-nmap
  ```

---

## ⚙️ Usage

```bash
python domainscout.py -u <target> [-p <ports>]
```

### Arguments

| Flag | Description |
|------|-------------|
| `-u` / `--url` | Target domain or IP address |
| `-p` / `--ports` | Comma-separated ports (e.g., 80,443) or `all` for full scan |

---

### 📌 Examples

```bash
python domainscout.py -u example.com
python domainscout.py -u example.com -p 21,22,80
python domainscout.py -u example.com -p all
```

---

## 📥 Output Includes

- IP Address + reverse DNS
- City, Country, ISP info
- Open Ports and Services
- OS Detection
- Detected CVEs / CPEs

---

## ⚠️ Legal Disclaimer

> Domain-Scout is for **educational use only**.  
> Scanning without permission is illegal. Use it responsibly in labs or authorized environments.

---

## 📬 Contact

- Telegram: [@magician_slime](https://t.me/magician_slime)
- GitHub: [magicianKaif](https://github.com/magicianKaif)
- Instagram: [@magicianslime](https://instagram.com/magicianslime)

---

## 💡 Tip

Try it during CTFs or red team simulations. Combine it with enumeration tools for deeper recon.
