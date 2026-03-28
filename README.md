# Cowrie SSH Honeypot — Attack Analysis Dashboard

> Live Attack Analysis: **10 Days of SSH Honeypot Data on AWS**



---

## Project Overview

This project deploys a **Cowrie SSH honeypot** on an AWS EC2 instance to attract, log, and analyze real automated attacks from the internet. The collected data is processed through a custom Python pipeline and visualized in an interactive security dashboard.

**Key results from 10 days of exposure:**
- **922 unique sessions** from **137 different IPs**
- Attacks from **multiple countries**, predominantly routed through cloud providers
- **706 login attempts** — 265 successfully entered the fake shell
- **320 commands** executed by attackers inside the honeypot
- **9 files uploaded** by attackers (captured safely)

---

## Architecture

- **Port 22** — Exposed to the internet, redirected to Cowrie via `iptables`
- **Port 2222** — Cowrie listens here and simulates a real SSH server in Python
- **Port 60022** — Real OpenSSH, key-pair auth only, for admin access
- **Cowrie** — Logs every connection, credential attempt, command, and file transfer without executing anything real

---

## Dashboard Features

| Section | Description |
|---|---|
|  Choropleth world map | Attack origin by country |
|  Scatter geo map | Individual IP locations with graphical bubble size |
|  Daily timeline | Attack volume over the 10-day period |
|  Hourly heatmap | Peak attack hours |
|  Top passwords | Most commonly tried passwords |
|  Top usernames | Most commonly tried usernames |
|  Top commands | Commands run by attackers inside the honeypot |
|  Top Organizations | Attacking organizations (DigitalOcean, AWS, Azure...) |
|  Logins by country | Failed vs successful logins per country |
|  Top IPs table | Sortable table of the 20 most active attacking IPs |

---

## Key Findings

### Most attacks come from cloud infrastructure
The top attacking organizations were **DigitalOcean** and **AWS EC2** — not home users. This confirms that modern automated attacks run on rented cloud servers, making geolocation by country misleading.

### Password patterns reveal attacker profiles
The most tried credentials follow predictable patterns (`admin/admin`, `root/123456`, `ubuntu/ubuntu`), confirming these are automated credential-stuffing bots, not targeted human attackers.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Honeypot | Cowrie SSH/Telnet honeypot |
| Cloud | AWS EC2 (Ubuntu 22.04) |
| Data processing | Python 3.10, Pandas |
| Geolocation | ip-api.com batch API |
| Visualization | Plotly, Dash, Dash Bootstrap Components |
| Version control | GitHub |

---

##  Project Structure

```
cowrie-honeypot-dashboard/
├── src/
│   ├── parser.py        # Log ingestion and event extraction
│   ├── geoip.py         # IP geolocation with caching
│   └── dashboard.py     # Interactive Dash dashboard
├── logs/                # Cowrie JSON logs (gitignored)
├── data/
│   └── geoip_cache.json # Cached geolocation results
├── requirements.txt
└── README.md
```

---

## Security Notes

- No real commands were ever executed on the host system
- Cowrie runs as an unprivileged user (`cowrie`) isolated from the OS
- The fake filesystem is a JSON file in memory — attackers never touch real disk (it's how Cowrie works)
- All uploaded files were captured to a quarantine folder, never executed
---

##  What I Learned

- Deploying and hardening an AWS EC2 instance for security research
- How SSH honeypots intercept the protocol at the application layer without exposing the real system
- Linux user isolation, `iptables` port redirection, and `systemd` service management
- Python virtual environments for dependency isolation in production-like setups
- Building data pipelines from raw JSON logs to interactive visualizations
- Real-world attack patterns: credential stuffing, botnet infrastructure, and command sequences used by attackers

---

##  Author

**Pol Álvarez** · Computer Engineering student  
[LinkedIn](https://www.linkedin.com/in/pol-alvarez-milla) · [GitHub](https://github.com/pol-alvarezzz)

---

*Data collected from a real honeypot exposed to the internet. All findings represent genuine attack traffic.*
