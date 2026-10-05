#!/bin/bash
#
# Build the release bundle for the AWG Panel self-update feature.
# Produces (in ./dist):
#   awg-panel-<VER>/                extracted package (reference)
#   awg-panel-<VER>.tar.gz          payload for GitHub Release assets
#   awg-panel-<VER>.tar.gz.sha256   checksum (verified by updater.py)
#
# MANIFEST (relative file paths inside the bundle) drives the swap/rollback
# performed by deploy/upgrade-panel.sh on the server side.
#
# Publish: tag v<VER>, push, the .github/workflows/release.yml workflow
# uploads these assets to the GitHub Release.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${APP_DIR}"

VER="$(cat VERSION)"
[ -n "${VER}" ] || { echo "VERSION is empty" >&2; exit 1; }

DIST="${APP_DIR}/dist"
PKG="${DIST}/awg-panel-${VER}"

rm -rf "${DIST}"
mkdir -p "${PKG}"

for item in app.py agent.py core.py stats.py updater.py deployer.py \
            requirements.txt VERSION README.md LICENSE templates deploy; do
  if [ -e "${APP_DIR}/${item}" ]; then
    cp -a "${APP_DIR}/${item}" "${PKG}/${item}"
  fi
done

# strip generated / platform junk from the package
find "${PKG}" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "${PKG}" -name '*.pyc' -delete
find "${PKG}" -name '*~' -delete
chmod +x "${PKG}/deploy/"*.sh 2>/dev/null || true

# MANIFEST: one relative path per line, sorted for determinism
( cd "${PKG}" && find . -type f | sort | sed 's#^\./##' ) > "${PKG}/MANIFEST"

tar -C "${DIST}" -czf "${DIST}/awg-panel-${VER}.tar.gz" "awg-panel-${VER}"
( cd "${DIST}" && sha256sum "awg-panel-${VER}.tar.gz" > "awg-panel-${VER}.tar.gz.sha256" )

echo "Built awg-panel-${VER}:"
ls -la "${DIST}"
echo
cat "${DIST}/awg-panel-${VER}.tar.gz.sha256"