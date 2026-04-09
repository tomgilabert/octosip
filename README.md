# OctoSIP Honeypot

A real-time SIP attack monitoring system built on Kamailio. Captures and visualizes SIP-based attacks (toll fraud, brute force, scanning) with an animated world map, live feed, and statistics dashboard.

![Dashboard](https://img.shields.io/badge/dashboard-live%20map-00ff88?style=flat-square) ![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square) ![Platform](https://img.shields.io/badge/platform-Debian%2012-informational?style=flat-square)

---

## What it does

- **Kamailio** listens on port 5060 (UDP/TCP) impersonating a FreePBX system to attract attackers
- Every SIP request is logged, geolocated and stored in PostgreSQL
- A web dashboard shows attacks in real time on an animated world map
- A REST API exposes statistics, top attackers, IOC exports and more

## Screenshots

```
┌─────────────────────────────────────────────────────────┐
│  Animated world map with attack trajectories            │
│  Live feed with method, IP, country, UA, extension      │
│  Activity charts (last 24h / last 30 days)              │
│  Top IPs, Countries, Methods, ASNs, User-Agents         │
└─────────────────────────────────────────────────────────┘
```

## Attack classification

| Icon | Type | Detection |
|------|------|-----------|
| ☎ | Toll Fraud | INVITE with long destination number (+10 digits) |
| 🔑 | Brute Force | REGISTER attempts |
| 🔍 | Scan | OPTIONS probing |
| 🚫 | Blocked | Rate-limited by Pike module |

---

## Requirements

- Debian 12 (or compatible)
- Root access
- Open port 5060 UDP/TCP (inbound)
- Free MaxMind account for GeoIP databases → https://www.maxmind.com

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/tomgilabert/OctoSIP.git
cd OctoSIP
```

### 2. Edit config.conf

```bash
nano config.conf
```

Fill in the required fields:

```ini
# MaxMind GeoIP credentials (free account at maxmind.com)
MAXMIND_ACCOUNT_ID=123456
MAXMIND_LICENSE_KEY=xxxxxxxxxxxx

# Map target: coordinates where attack arrows point to
MAP_TARGET_LAT=41.3874
MAP_TARGET_LON=2.1686
MAP_TARGET_NAME=Barcelona

# Timezone
TIMEZONE=Europe/Madrid
```

> The database password is auto-generated on first install and saved back to `config.conf`.
> If you have an existing PostgreSQL setup, set `DB_PASSWORD` to your existing password before running.

### 3. Run the installer

```bash
chmod +x install.sh
sudo ./install.sh
```

The installer will:
- Install Kamailio, PostgreSQL, Python 3 (venv), rsyslog
- Create the database, tables and indexes
- Download GeoLite2-City and GeoLite2-ASN databases
- Configure and start all services
- Set up logrotate and cron jobs

### 4. Post-installation

```
1. Open port 5060 UDP/TCP on your firewall/router towards this machine
2. Access the dashboard at http://<your-ip>:8080
```

---

## Services

| Service | Port | Description |
|---------|------|-------------|
| Kamailio | 5060 UDP/TCP | SIP honeypot |
| octosip-api | 5000 | REST API (Flask) |
| octosip-web | 8080 | Web dashboard |
| PostgreSQL | 5432 | Event storage |

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/stats` | Global counters (total, last hour, last 24h, unique IPs) |
| `GET /api/recent?limit=N` | Latest N events with coordinates |
| `GET /api/stats/hourly` | Hourly activity (last 24h) |
| `GET /api/stats/daily` | Daily activity (last 30 days) |
| `GET /api/top_ips` | Top attacking IPs (last 24h) |
| `GET /api/top_countries` | Top countries (last 24h) |
| `GET /api/top_methods` | Top SIP methods (last 24h) |
| `GET /api/top_asns` | Top ASNs (last 24h) |
| `GET /api/top_useragents` | Top user agents (last 24h) |
| `GET /api/heatmap` | Heatmap points (last 24h) |
| `GET /api/iocs?hours=24` | Export attacker IPs as plaintext IOC list |

---

## File structure

```
OctoSIP/
├── config.conf              # User configuration (edit before install)
├── install.sh               # Installer
├── kamailio.cfg             # Kamailio honeypot config
├── octosip_parser.py         # rsyslog omprog → PostgreSQL
├── octosip_api.py            # REST API (Flask)
├── index.html               # Web dashboard
├── 10-sip-honeypot.conf     # rsyslog config
├── octosip-api.service       # systemd unit
├── octosip-web.service       # systemd unit
├── purge_old_events.sh      # Daily cron: purge events older than 90 days
└── update_geoip.sh          # Weekly cron: update GeoIP databases
```

---

## Maintenance

**Update GeoIP databases manually:**
```bash
/opt/octosip/update_geoip.sh
```

**Export IOCs (last 24h):**
```bash
curl http://localhost:5000/api/iocs?hours=24
```

**Check service status:**
```bash
systemctl status kamailio octosip-api octosip-web
```

**View live parser log:**
```bash
tail -f /var/log/octosip_parser.log
```

---

## How it works

```
Internet
   │  SIP port 5060
   ▼
Kamailio (honeypot)
   │  Logs via LOG_LOCAL0
   ▼
rsyslog (omprog)
   │  stdin pipe
   ▼
octosip_parser.py  ──► GeoIP lookup  ──► PostgreSQL
                                            │
                                    octosip_api.py (Flask :5000)
                                            │
                                    index.html (:8080)
```

Kamailio impersonates a FreePBX 16 / Asterisk 20 system. It responds to:
- **OPTIONS** → `200 OK` (confirms PBX is alive)
- **REGISTER** → `401 Unauthorized` challenge (logs credential attempts)
- **INVITE** → `100 Trying` + `486 Busy Here` (simulates active extensions)
- Flood → `503 Service Unavailable` via Pike module

---

## License

MIT
