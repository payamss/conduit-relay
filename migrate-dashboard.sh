#!/bin/bash
# Conduit Dashboard Migration for conduit-manager Users
# Run: curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/migrate-dashboard.sh | sudo bash
#
# Adds the Paradixe dashboard to existing conduit-manager Docker installations
# without touching your running relay container.
set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  Conduit Dashboard Migration (for conduit-manager users)  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo)${NC}"
  exit 1
fi

# ════════════════════════════════════════════════════════════════
# [1] Detection Phase
# ════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[1/5] Detecting conduit-manager installation...${NC}"

# Check for conduit container (conduit-manager's naming convention)
if ! command -v docker &>/dev/null; then
  echo -e "${RED}Docker not found. This script is for conduit-manager Docker installations.${NC}"
  exit 1
fi

CONDUIT_CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -E '^conduit$' | head -1 || true)

if [ -z "$CONDUIT_CONTAINER" ]; then
  echo -e "${RED}No 'conduit' container found running.${NC}"
  echo ""
  echo "This script is for users who installed via conduit-manager."
  echo "Looking for a container named 'conduit'..."
  echo ""
  echo "If you want a fresh install, run:"
  echo -e "  ${CYAN}curl -sL https://raw.githubusercontent.com/paradixe/conduit-relay/main/docker-setup.sh | sudo bash${NC}"
  exit 1
fi

echo -e "  ${GREEN}✓${NC} Found container: $CONDUIT_CONTAINER"

# Verify this is a conduit-manager installation
if [ -f "/opt/conduit/settings.conf" ] || command -v conduit &>/dev/null; then
  echo -e "  ${GREEN}✓${NC} Verified conduit-manager installation"
else
  echo -e "  ${YELLOW}!${NC} Note: /opt/conduit not found, may be custom Docker setup"
fi

# Check if dashboard already running
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'conduit-dashboard'; then
  echo -e "${YELLOW}Dashboard container already running.${NC}"
  echo "To reinstall, first remove it: docker rm -f conduit-dashboard"
  exit 0
fi

# Read settings from conduit-manager's settings.conf
SETTINGS_FILE="/opt/conduit/settings.conf"
if [ -f "$SETTINGS_FILE" ]; then
  source "$SETTINGS_FILE" 2>/dev/null || true
  MAX_CLIENTS="${MAX_CLIENTS:-200}"
  BANDWIDTH="${BANDWIDTH:-5}"
  echo -e "  ${GREEN}✓${NC} Read settings: MAX_CLIENTS=$MAX_CLIENTS, BANDWIDTH=$BANDWIDTH"
else
  # Fallback: parse from docker inspect
  MAX_CLIENTS=$(docker inspect "$CONDUIT_CONTAINER" --format '{{range .Config.Cmd}}{{.}} {{end}}' 2>/dev/null | grep -oP '(?<=--max-clients\s)\d+' || echo "200")
  BANDWIDTH=$(docker inspect "$CONDUIT_CONTAINER" --format '{{range .Config.Cmd}}{{.}} {{end}}' 2>/dev/null | grep -oP '(?<=--bandwidth\s)-?\d+' || echo "-1")
  echo -e "  ${GREEN}✓${NC} Detected settings: MAX_CLIENTS=$MAX_CLIENTS, BANDWIDTH=$BANDWIDTH"
fi

# ════════════════════════════════════════════════════════════════
# [2] Prerequisites
# ════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[2/5] Checking prerequisites...${NC}"

# Ensure Docker Compose is available
if ! docker compose version &>/dev/null; then
  echo "  Installing Docker Compose plugin..."
  apt-get update -qq && apt-get install -y -qq docker-compose-plugin
  echo -e "  ${GREEN}Docker Compose installed${NC}"
else
  echo "  Docker Compose available"
fi

# Check SSH server
if ! systemctl is-active --quiet sshd 2>/dev/null && ! systemctl is-active --quiet ssh 2>/dev/null; then
  echo -e "${YELLOW}  SSH server not detected. Starting...${NC}"
  systemctl start sshd 2>/dev/null || systemctl start ssh 2>/dev/null || true
fi
echo "  SSH server running"

# ════════════════════════════════════════════════════════════════
# [3] User Setup (conduitmon)
# ════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[3/5] Setting up monitoring user...${NC}"

MON_USER="conduitmon"
CONDUIT_DIR="/opt/conduit-dashboard"
SSH_KEY_PATH="$CONDUIT_DIR/ssh/id_ed25519"

mkdir -p "$CONDUIT_DIR/ssh"

# Create conduitmon user if not exists
if ! id "$MON_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$MON_USER"
  echo "  Created user: $MON_USER"
else
  echo "  User $MON_USER already exists"
fi

# Add to docker group (critical for container access)
if ! groups "$MON_USER" | grep -q docker; then
  usermod -aG docker "$MON_USER"
  echo "  Added $MON_USER to docker group"
fi

# Generate SSH key for dashboard
if [ ! -f "$SSH_KEY_PATH" ]; then
  ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -q
  echo "  Generated SSH key"
else
  echo "  SSH key exists"
fi

# Add public key to conduitmon's authorized_keys
mkdir -p "/home/$MON_USER/.ssh"
chmod 700 "/home/$MON_USER/.ssh"
touch "/home/$MON_USER/.ssh/authorized_keys"
chmod 600 "/home/$MON_USER/.ssh/authorized_keys"

PUB_KEY=$(cat "${SSH_KEY_PATH}.pub")
if ! grep -qF "$PUB_KEY" "/home/$MON_USER/.ssh/authorized_keys" 2>/dev/null; then
  echo "$PUB_KEY" >> "/home/$MON_USER/.ssh/authorized_keys"
  echo "  Added SSH key to authorized_keys"
fi
chown -R "$MON_USER:$MON_USER" "/home/$MON_USER/.ssh"

# Configure sudoers for tcpdump (bandwidth monitoring)
mkdir -p /etc/sudoers.d
cat > /etc/sudoers.d/conduit-dashboard << 'SUDOEOF'
Defaults:conduitmon !requiretty
conduitmon ALL=(root) NOPASSWD: \
  /usr/bin/timeout * /usr/bin/tcpdump *, /usr/bin/tcpdump *, /usr/sbin/tcpdump *
SUDOEOF
chmod 440 /etc/sudoers.d/conduit-dashboard
echo "  Configured sudoers for tcpdump"

# ════════════════════════════════════════════════════════════════
# [4] Dashboard Deployment
# ════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[4/5] Deploying dashboard...${NC}"

cd "$CONDUIT_DIR"

# Download dashboard-only compose file
curl -sLO https://raw.githubusercontent.com/paradixe/conduit-relay/main/docker-compose.dashboard-only.yml
echo "  Downloaded docker-compose.dashboard-only.yml"

# Generate credentials
PASSWORD=$(openssl rand -base64 12 | tr -d '/+=')
SESSION_SECRET=$(openssl rand -hex 32)
JOIN_TOKEN=$(openssl rand -hex 16)

# Get public IP
PUBLIC_IP=$(curl -4s --connect-timeout 5 ifconfig.me 2>/dev/null || curl -4s --connect-timeout 5 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')

# Create .env file
cat > "$CONDUIT_DIR/.env" << EOF
# Conduit Dashboard Configuration
DASHBOARD_PASSWORD=$PASSWORD
SESSION_SECRET=$SESSION_SECRET
JOIN_TOKEN=$JOIN_TOKEN

# SSH key for monitoring
SSH_KEY_PATH=$SSH_KEY_PATH
EOF
echo "  Created .env file"

# Start dashboard
docker compose -f docker-compose.dashboard-only.yml pull
docker compose -f docker-compose.dashboard-only.yml up -d

echo "  Dashboard container started"

# ════════════════════════════════════════════════════════════════
# [5] Registration
# ════════════════════════════════════════════════════════════════

echo -e "${YELLOW}[5/5] Registering local relay...${NC}"

# Wait for dashboard to be ready
echo "  Waiting for dashboard..."
for i in {1..30}; do
  if curl -s "http://127.0.0.1:3000/api/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# Register localhost
LOCAL_HOSTNAME=$(hostname | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | cut -c1-20)
[ -z "$LOCAL_HOSTNAME" ] && LOCAL_HOSTNAME="relay"

# Detect SSH port
SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
[ -z "$SSH_PORT" ] && SSH_PORT="22"

REGISTER_RESULT=$(curl -s -X POST "http://127.0.0.1:3000/api/register" \
  -H "Content-Type: application/json" \
  -H "X-Join-Token: $JOIN_TOKEN" \
  -d "{\"name\":\"$LOCAL_HOSTNAME\",\"host\":\"host.docker.internal\",\"user\":\"$MON_USER\",\"sshPort\":$SSH_PORT}" 2>/dev/null || echo "")

if echo "$REGISTER_RESULT" | grep -q '"success"'; then
  echo -e "  ${GREEN}✓${NC} Registered local relay"
else
  echo -e "  ${YELLOW}!${NC} Auto-registration skipped (add manually via dashboard)"
fi

# ════════════════════════════════════════════════════════════════
# Done!
# ════════════════════════════════════════════════════════════════

JOIN_URL="http://$PUBLIC_IP:3000/join/$JOIN_TOKEN"

echo ""
echo -e "${GREEN}${BOLD}"
echo "════════════════════════════════════════════════════════════"
echo "               Dashboard Added Successfully!"
echo "════════════════════════════════════════════════════════════"
echo -e "${NC}"
echo -e "  ${CYAN}Dashboard:${NC}  http://$PUBLIC_IP:3000"
echo -e "  ${CYAN}Password:${NC}   $PASSWORD"
echo ""
echo -e "  ${YELLOW}Save this password! It won't be shown again.${NC}"
echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  To add more servers to this dashboard:${NC}"
echo ""
echo -e "  ${CYAN}curl -sL \"$JOIN_URL\" | sudo bash${NC}"
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Your conduit-manager CLI still works!${NC}"
echo "    conduit status      # Check relay status"
echo "    conduit restart     # Restart relay"
echo "    conduit settings    # Change MAX_CLIENTS/BANDWIDTH"
echo ""
echo -e "  ${CYAN}Dashboard commands:${NC}"
echo "    cd $CONDUIT_DIR"
echo "    docker compose -f docker-compose.dashboard-only.yml logs -f"
echo "    docker compose -f docker-compose.dashboard-only.yml down"
echo ""
