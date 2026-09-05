#!/bin/bash
#
# One-command installer for the AWG Panel on a fresh server that already
# runs a native AmneziaWG install.
#
# Usage:
#   curl -fsSL <raw-url>/deploy/install-panel.sh | bash
#   bash deploy/install-panel.sh [options]
#
# Options:
#   --user NAME        panel login (default: admin)
#   --password PASS    panel password (default: random 20 hex chars, printed)
#   --port N           listen port  (default: 5182)
#   --interface IF     awg interface (default: awg0)
#   --dir PATH         app directory (default: /root/awg-panel)
#   --repo URL         repo to clone if --dir does not contain the app
#   --service NAME     systemd unit name (default: awg-panel)
#   --config-dir PATH  where panel credentials live (default: /etc/awg-panel)
#   --no-ufw           do not open the port in UFW
#
set -euo pipefail

REPO_URL="${AWG_PANEL_REPO:-https://github.com/USER/awg-panel.git}"
USER_NAME="admin"
PASSWORD=""
PORT=5182
IFACE="awg0"
APP_DIR="/root/awg-panel"
NO_UFW=0
SERVICE="awg-panel"
ETC="/etc/awg-panel"

while [ $# -gt 0 ]; do
  case "$1" in
    --user) USER_NAME="$2"; shift 2 ;;
    --password) PASSWORD="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --interface) IFACE="$2"; shift 2 ;;
    --dir) APP_DIR="$2"; shift 2 ;;
    --repo) REPO_URL="$2"; shift 2 ;;
    --service) SERVICE="$2"; shift 2 ;;
    --config-dir) ETC="$2"; shift 2 ;;
    --no-ufw) NO_UFW=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

fatal() { echo -e "${RED}ERROR: $1${NC}" >&2; exit 1; }
info()  { echo -e "${GREEN}$1${NC}"; }

if [ "${EUID}" -ne 0 ]; then fatal "run as root"; fi

# ----------------------------------------------------------------------
echo "== prerequisites =="
command -v git >/dev/null 2>&1  || apt-get install -y -q git >/dev/null 2>&1 || true
command -v python3 >/dev/null 2>&1 || apt-get install -y -q python3 >/dev/null 2>&1 || true
command -v awg   >/dev/null 2>&1 || fatal "AmneziaWG is not installed (missing 'awg'). Install it first."
command -v awg-quick >/dev/null 2>&1 || fatal "AmneziaWG is not installed (missing 'awg-quick'). Install it first."

# ----------------------------------------------------------------------
echo "== locating app code =="
if [ -f "${APP_DIR}/app.py" ] && [ -f "${APP_DIR}/core.py" ]; then
  info "* using directory ${APP_DIR}"
else
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" 2>/dev/null && pwd)"
  if [ -n "${script_dir}" ] && [ -f "${script_dir}/../app.py" ] && [ -f "${script_dir}/../core.py" ]; then
    APP_DIR="$(cd "${script_dir}/.." && pwd)"
    info "* running from local checkout ${APP_DIR}"
  else
    # Clone a fresh copy.
    if [ ! -d "${APP_DIR}" ]; then
      mkdir -p "$(dirname "${APP_DIR}")"
      info "* cloning ${REPO_URL} -> ${APP_DIR}"
      git clone -q --depth 1 "${REPO_URL}" "${APP_DIR}"
    fi
    [ -f "${APP_DIR}/app.py" ] && [ -f "${APP_DIR}/core.py" ] \
      || fatal "app code not found at ${APP_DIR} and could not be cloned from ${REPO_URL}"
  fi
fi

# ----------------------------------------------------------------------
echo "== amneziawg check =="
CONF_DIR="/etc/amnezia/amneziawg"
[ -f "${CONF_DIR}/params" ]                   || fatal "params file not found: ${CONF_DIR}/params"
[ -f "${CONF_DIR}/${IFACE}.conf" ]            || fatal "config not found: ${CONF_DIR}/${IFACE}.conf"
if systemctl is-active --quiet "awg-quick@${IFACE}" 2>/dev/null; then
  info "* interface ${IFACE} is active"
else
  echo -e "${YELLOW}! warning: awg-quick@${IFACE} is not running; you can still manage via the panel${NC}"
fi

# ----------------------------------------------------------------------
echo "== python venv =="
apt-get install -y -q python3-venv >/dev/null 2>&1 || true
cd "${APP_DIR}"
python3 -m venv venv
venv/bin/pip install -q --upgrade pip
venv/bin/pip install -q -r requirements.txt
venv/bin/python -c "import fastapi, uvicorn, qrcode, httpx" || fatal "python dependency check failed"

# ----------------------------------------------------------------------
echo "== panel credentials =="
mkdir -p "${ETC}"
umask 077
if [ -f "${ETC}/config" ] && [ -z "${PASSWORD}" ]; then
  # reuse existing credentials on re-run
  PASSWORD="$(grep '^AWG_PANEL_PASSWORD=' "${ETC}/config" | cut -d= -f2-)"
  USER_NAME="$(grep '^AWG_PANEL_USER=' "${ETC}/config" | cut -d= -f2-)"
  info "* reusing existing credentials"
fi
[ -n "${PASSWORD}" ] || PASSWORD="$(openssl rand -hex 20)"
cat > "${ETC}/config" <<EOF
AWG_PANEL_USER=${USER_NAME}
AWG_PANEL_PASSWORD=${PASSWORD}
EOF
chmod 600 "${ETC}/config"

# ----------------------------------------------------------------------
echo "== systemd service =="
cat > "/etc/systemd/system/${SERVICE}.service" <<UNIT
[Unit]
Description=AWG Panel - AmneziaWG management web UI
After=network.target awg-quick@${IFACE}.service
Wants=awg-quick@${IFACE}.service

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/venv/bin/uvicorn app:app --host 0.0.0.0 --port ${PORT}
Environment=AWG_CONFIG_DIR=/etc/amnezia/amneziawg
Environment=AWG_INTERFACE=${IFACE}
Environment=AWG_STATE_FILE=${APP_DIR}/state.json
Environment=AWG_SERVERS_FILE=${APP_DIR}/servers.json
Environment=AWG_CLIENT_DIR=/root
EnvironmentFile=${ETC}/config
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now "${SERVICE}.service"
sleep 2
systemctl is-active --quiet "${SERVICE}.service" || {
  echo -e "${RED}service failed to start:${NC}"
  journalctl -u "${SERVICE}.service" -n 30 --no-pager || true
  exit 1
}

# ----------------------------------------------------------------------
echo "== firewall =="
if [ "${NO_UFW}" -eq 1 ]; then
  echo "UFW skipped (--no-ufw). Make sure TCP ${PORT} is reachable."
elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow "${PORT}/tcp" >/dev/null
  echo "UFW: opened ${PORT}/tcp"
else
  echo -e "${YELLOW}! UFW not active - make sure TCP ${PORT} is reachable in your firewall${NC}"
fi

PANEL_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "${PANEL_IP}" ] || PANEL_IP="<server-ip>"

echo ""
info "============================================="
info "AWG Panel installed and running. SUMMARY"
info "============================================="
info "  URL:       http://${PANEL_IP}:${PORT}/"
info "  Login:     ${USER_NAME}"
info "  Password:  ${PASSWORD}"
info ""
info "  Local interface:  ${IFACE} (${CONF_DIR}/${IFACE}.conf)"
info "  Config file:      ${ETC}/config"
info "  Systemd:          systemctl {status|restart|stop} ${SERVICE}"
echo ""
info "  Remote VDS? Install the agent there:"
info "    bash ${APP_DIR}/deploy/install-agent.sh ${PANEL_IP} <token>"
info "  then add it in the panel: Server -> Manage servers -> URL + Token."
info "============================================="