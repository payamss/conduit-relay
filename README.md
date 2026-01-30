# Conduit Relay

**Volunteer relay for [Psiphon](https://psiphon.ca)**
Routes traffic for users in censored regions via WebRTC. Your VPS becomes an exit node.

**Requirements:** Linux VPS, root access, 50-200 GB/day bandwidth

```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/setup.sh | sudo bash
```

> **Already using [conduit-manager](https://github.com/SamNet-dev/conduit-manager)?** Add the dashboard without touching your relay:
> ```bash
> curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/migrate-dashboard.sh | sudo bash
> ```
> Keeps your container, CLI commands still work, gives you fleet management.

---

## Installation

### Native

```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/setup.sh | sudo bash
```

After install you'll get:
- Dashboard URL at `http://your-ip:3000`
- Admin password — **save it, shown once**
- Join command for adding more servers

> **Optional:** Enter a domain during setup for HTTPS via Let's Encrypt

### Docker

```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/docker-setup.sh | sudo bash
```

Detects existing Docker/ssmirr setups and offers migration.

### Relay Only

No dashboard, just the relay:

```bash
# Native
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/install.sh | sudo bash

# Docker
curl -sLO https://raw.githubusercontent.com/paradixe/conduit-relay/main/docker-compose.relay-only.yml
docker compose -f docker-compose.relay-only.yml up -d
```

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_CLIENTS` | 200 | Max concurrent connections |
| `BANDWIDTH` | -1 | Bandwidth limit in Mbps (-1 = unlimited) |

Custom config: `curl -sL ... | MAX_CLIENTS=500 BANDWIDTH=100 sudo bash`

### Raspberry Pi / OrangePi

See [Portainer setup guide](docs/portainer-setup.md) for ARM devices with a web UI.

### Dashboard Only

Manage remote servers from your laptop (no local relay):

```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/setup.sh | DASHBOARD_ONLY=1 sudo bash
```

---

## Multi-Server Fleet

### Via Dashboard (Recommended)

After initial setup, use the join command on additional servers:

```bash
curl -sL "http://YOUR_DASHBOARD_IP:3000/join/TOKEN" | sudo bash
```

> Auto-detects Docker availability. Mixed fleets (Docker + native) supported.

<details>
<summary><strong>Via CLI (fleet.sh)</strong></summary>

For operators who prefer command-line fleet management:

```bash
curl -sLO https://raw.githubusercontent.com/paradixe/conduit-relay/main/fleet.sh
chmod +x fleet.sh
```

| Command | Description |
|---------|-------------|
| `./fleet.sh add <name> <ip> [user]` | Register a server |
| `./fleet.sh list` | List all servers |
| `./fleet.sh status [name\|all]` | Check status with live stats |
| `./fleet.sh install [name\|all]` | Install conduit remotely |
| `./fleet.sh update [name\|all]` | Update to latest release |
| `./fleet.sh start/stop [name\|all]` | Control relay service |
| `./fleet.sh logs <name>` | Tail logs from server |
| `./fleet.sh dashboard <name> <pass>` | Deploy dashboard to server |

Servers stored in `~/.conduit-servers`.

</details>

---

## Operations

### Update

```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/update.sh | sudo bash
```

Or from dashboard: Settings → Update Dashboard

### Uninstall

```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/uninstall.sh | sudo bash
```

Removes both native and Docker installations.

### Service Commands

**Native:**
```bash
systemctl status conduit        # Status
systemctl restart conduit       # Restart
journalctl -u conduit -f        # Logs
```

**Docker:**
```bash
docker ps                       # Status
docker restart conduit-relay    # Restart
docker logs conduit-relay -f    # Logs
```

---

## Monitoring Tools

<details>
<summary><strong>Live Stats (conduit-stats.sh)</strong></summary>

```bash
curl -sLO https://raw.githubusercontent.com/paradixe/conduit-relay/main/conduit-stats.sh
chmod +x conduit-stats.sh
./conduit-stats.sh              # Current stats
./conduit-stats.sh --live       # Auto-refresh every 5s
./conduit-stats.sh --geo        # Include geographic breakdown
./conduit-stats.sh --live --geo # Both
```

</details>

<details>
<summary><strong>Geographic Distribution (geo-stats.sh)</strong></summary>

See where your clients connect from:

```bash
curl -sLO https://raw.githubusercontent.com/paradixe/conduit-relay/main/geo-stats.sh
chmod +x geo-stats.sh
./geo-stats.sh [seconds] [max-packets]
```

Requires: `tcpdump`, `geoip-bin` (auto-installed)

</details>

---

## Dashboard Features

- Live stats per server (clients, bandwidth, geo)
- Start/Stop/Restart individual relays
- Edit server config (bandwidth limits, names)
- Update all relays from web UI
- Join tokens for easy onboarding
- Monthly bandwidth tracking with auto-stop

---

## Guides

- [Step-by-step setup](SETUP.md) — Detailed walkthrough (English + فارسی)
- [Portainer setup](docs/portainer-setup.md) — For OrangePi/Raspberry Pi

---

<div dir="rtl">

## فارسی

### نصب

**روش عادی (Native):**
```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/setup.sh | sudo bash
```

**داکر:**
```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/docker-setup.sh | sudo bash
```

**فقط ریلی (بدون داشبورد):**
```bash
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/install.sh | sudo bash
```

> بعد از نصب یه URL و پسورد میده. **پسورد رو ذخیره کن** — فقط یه بار نشون میده.

### مدیریت چند سرور

دستور join که بعد نصب نشون میده رو روی سرورای دیگت بزن:
```bash
curl -sL "http://IP_DASHBOARD:3000/join/TOKEN" | sudo bash
```

### آپدیت و حذف

```bash
# آپدیت
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/update.sh | sudo bash

# حذف کامل
curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/uninstall.sh | sudo bash
```

### دستورات سرویس

| دستور | کاربرد |
|-------|--------|
| `systemctl status conduit` | وضعیت |
| `systemctl restart conduit` | ریستارت |
| `journalctl -u conduit -f` | لاگ‌ها |

### راهنمای کامل

- [SETUP.md](SETUP.md) — آموزش قدم به قدم
- [Portainer](docs/portainer-setup.md) — برای رزبری پای و اورنج پای

</div>
