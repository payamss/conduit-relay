# Conduit Relay

Volunteer relay for [Psiphon](https://psiphon.ca). Routes traffic for users in censored regions via WebRTC. Your VPS becomes an exit node.

**Requirements:** Linux VPS, root access
**Bandwidth:** 50-200 GB/day depending on demand

**New?** Check the [step-by-step setup guide](SETUP.md) (English + فارسی)

**OrangePi/Raspberry Pi?** See the [Portainer setup guide](docs/portainer-setup.md)

---

## Quick Start (Relay + Dashboard)

One command installs everything:

```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/setup.sh | sudo bash
```

**Already have Docker/ssmirr's setup?** Use `docker-setup.sh` instead - it detects existing containers and offers migration:
```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/docker-setup.sh | sudo bash
```

You'll get:
- **Dashboard URL** - Web interface to monitor your servers
- **Password** - Save it! Won't be shown again
- **Join command** - Run this on other servers to auto-connect them

Optionally enter a domain during setup to get HTTPS via Let's Encrypt.

**Adding more servers:**
```bash
# On each additional server, run the join command shown after setup:
curl -sL "http://YOUR_DASHBOARD_IP:3000/join/TOKEN" | sudo bash
```

Servers auto-register and appear on your dashboard. The join script auto-detects Docker - if available, it uses containers; otherwise native install.

**Mixed fleets supported:** Dashboard monitors both Docker and native servers.

---

## Updating

Already installed? Update everything with one command:

```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/update.sh | sudo bash
```

Or from the dashboard: **Settings → Update Dashboard**

This updates both the relay binary and dashboard code while preserving your config.

**Uninstall:**
```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/uninstall.sh | sudo bash
```

Removes both native and Docker installations.

---

## Dashboard Features

- **Live stats** - Clients, bandwidth, geo distribution per server
- **Per-node controls** - Stop/Start/Restart individual relays
- **Edit servers** - Set bandwidth limits, rename, delete
- **Auto-updates** - Update all relays and dashboard from the web UI
- **Join command** - Easy onboarding for new servers

---

## Relay Only (No Dashboard)

If you just want the relay without the web dashboard:

**Native:**
```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/install.sh | sudo bash
```

**Docker:**
```bash
curl -sLO https://raw.githubusercontent.com/paradixe/conduit-relay/main/docker-compose.relay-only.yml
docker compose -f docker-compose.relay-only.yml up -d
```

**Configuration:**
- `MAX_CLIENTS=200` max concurrent clients (default)
- `BANDWIDTH=-1` unlimited bandwidth (default)

Custom: `curl ... | MAX_CLIENTS=500 BANDWIDTH=100 bash`

**Commands:**
```bash
# Native
systemctl status conduit      # status
journalctl -u conduit -f      # logs

# Docker
docker logs conduit-relay -f  # logs
docker ps                     # status
```

---

## Dashboard Only (No Relay)

Run dashboard on your laptop to manage remote servers:

```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/setup.sh | DASHBOARD_ONLY=1 sudo bash
```

---

## فارسی

یه VPS بگیر، این رو بزن:

```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/setup.sh | sudo bash
```

بعدش یه URL و پسورد میده. با اون میتونی وضعیت سرورت رو ببینی.

**اضافه کردن سرور دیگه:**
دستوری که بعد نصب نشون میده رو روی سرورای دیگت بزن، خودکار وصل میشن.

تمام. سرورت الان داره به مردم کمک میکنه فیلترشکن داشته باشن.
