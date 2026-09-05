#!/bin/bash
#
# Deploy the AWG agent to a remote VDS from the central panel server.
#
# Usage:
#   bash deploy-agent.sh [user@]host [PANEL_IP] [TOKEN]
#
# Examples:
#   bash deploy-agent.sh root@91.107.126.173 202.181.188.224
#   bash deploy-agent.sh root@91.107.126.173 202.181.188.224 my-custom-token
#
# Requirements: rsync on both machines, sshpass (or agent/keys) for SSH auth.
#
set -euo pipefail

HOST="${1:?usage: deploy-agent.sh [user@]host [PANEL_IP] [TOKEN]}"
PANEL_IP="${2:-}"
TOKEN="${3:-}"
REMOTE_DIR="/root/awg-agent"
THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v rsync >/dev/null 2>&1; then
  echo "rsync not found locally; install it first (apt install rsync)"
  exit 1
fi

echo "== copying project to ${HOST}:${REMOTE_DIR} =="
rsync -az --delete \
  --exclude '.git' --exclude 'venv' --exclude '__pycache__' \
  --exclude 'state.json' --exclude 'servers.json' \
  -e ssh "${THIS_DIR}/" "${HOST}:${REMOTE_DIR}/"

echo "== running install-agent.sh on ${HOST} =="
echo "${TOKEN}" | ssh "${HOST}" "cd ${REMOTE_DIR} && bash deploy/install-agent.sh ${PANEL_IP} -"

echo ""
echo "== done. Add the server in the panel UI =="