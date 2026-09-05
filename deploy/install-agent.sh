#!/bin/bash
#
# Install the AWG agent on the current VDS.
#
# Usage:
#   bash install-agent.sh [PANEL_IP] [TOKEN]
#
#   PANEL_IP  - public IP of the central panel. If given, UFW opens port 5183
#               ONLY for this IP. Otherwise the agent stays open to the world
#               (NOT recommended - you must restrict access yourself).
#   TOKEN     - optional agent token (X-Api-Key). If omitted, a random one is
#               generated and printed at the end.
#
set -euo pipefail

PANEL_IP="${1:-}"
TOKEN="${2:-}"
APP_DIR="/root/awg-agent"
CONF_DIR="/etc/awg-panel"
SERVICE="awg-agent.service"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'

if [ "${EUID}" -ne 0 ]; then
  echo -e "${RED}Run as root${NC}"; exit 1
fi

if [ ! -d "${APP_DIR}" ]; then
  echo -e "${RED}Project directory ${APP_DIR} not found. Copy the repo there first.${NC}"; exit 1
fi

echo "== awg binaries =="
command -v awg awg-quick || { echo -e "${RED}AmneziaWG is not installed here${NC}"; exit 1; }

echo "== python venv and deps =="
cd "${APP_DIR}"
apt-get install -y -q python3-venv >/dev/null 2>&1 || true
python3 -m venv venv
venv/bin/pip install -q --upgrade pip
venv/bin/pip install -q -r requirements.txt
venv/bin/python -c "import fastapi, uvicorn, qrcode, httpx" || { echo -e "${RED}Dependency check failed${NC}"; exit 1; }

echo "== agent config =="
if [ -z "${TOKEN}" ]; then
  TOKEN="$(openssl rand -hex 16)"
fi
mkdir -p "${CONF_DIR}"
umask 077
cat > "${CONF_DIR}/agent-config" <<EOF
AWG_AGENT_TOKEN=${TOKEN}
EOF
chmod 600 "${CONF_DIR}/agent-config"

echo "== systemd service =="
cp "${APP_DIR}/deploy/agent.service" "/etc/systemd/system/${SERVICE}"
systemctl daemon-reload
systemctl enable --now "${SERVICE}"
sleep 2
systemctl is-active --quiet "${SERVICE}" || { echo -e "${RED}Service failed to start${NC}"; journalctl -u "${SERVICE}" -n 20 --no-pager; exit 1; }

echo "== firewall =="
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  if [ -n "${PANEL_IP}" ]; then
    ufw allow from "${PANEL_IP}" to any port 5183 proto tcp >/dev/null
    echo "UFW: opened 5183 for ${PANEL_IP} only"
  else
    ufw allow 5183/tcp >/dev/null
    echo -e "${RED}UFW: opened 5183 for ANYONE (no panel IP given)${NC}"
  fi
else
  echo "UFW not active - make sure your firewall allows TCP 5183 (ideally only from the panel IP)"
fi

echo ""
echo -e "${GREEN}AWG agent installed and running.${NC}"
echo -e "URL:       http://$(hostname -I | awk '{print $1}'):5183"
echo -e "Token:     ${TOKEN}"
echo -e "Add this in the panel: Server -> Manage servers -> URL + Token"