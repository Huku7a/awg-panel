#!/bin/bash
#
# Swap the AWG Panel code in place (driven by updater.py, no git needed).
# Usage: upgrade-panel.sh <marker.json>
#   marker.json is produced by updater.py and describes the verified payload.
#
# Flow:
#   1) lock (.updates/lock)         2) sanity-check MANIFEST
#   3) backup current tracked files  4) remove files dropped from the app
#   5) copy new payload              6) pip install -r requirements.txt
#   7) import check                  8) systemctl restart
#   9) smoke check                   10) rollback on any failure
# Result is written to .updates/last_result.json, logs to .updates/upgrade.log
set -euo pipefail

MARKER="${1:?usage: upgrade-panel.sh <marker.json>}"

# ----------------------------------------------------------------------
# load marker (avoid a hard dependency on jq)
eval "$(python3 - "$MARKER" <<'PYEOF'
import json, shlex, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
for k, v in d.items():
    if k in ("payload", "app_dir", "python", "service", "backup",
             "update_dir", "version", "current_version", "tid"):
        if isinstance(v, str):
            print(f"{k}={shlex.quote(v)}")
PYEOF
)"

LOG="${update_dir}/upgrade.log"
mkdir -p "${update_dir}"
touch "${LOG}"
exec 2>>"${LOG}"
exec 9>"${update_dir}/lock"
flock -n 9 || { echo "upgrade: another upgrade already running" >&2; exit 2; }

log() { printf 'upgrade: %s\n' "$*" | tee -a "${LOG}"; }

[ -n "${payload:-}" ] && [ -d "${payload}" ] || { log "payload dir missing"; exit 3; }
[ -n "${app_dir:-}" ] && [ -d "${app_dir}" ]  || { log "app dir missing"; exit 3; }
[ -n "${service:-}" ] || service="awg-panel"
[ -n "${python:-}" ]  || python="$(command -v python3)"

ORIG_PAYLOAD="${payload}"
MANIFEST="${payload}/MANIFEST"
OLD_MANIFEST="${update_dir}/manifest.current"
ROLLED_BACK=0

write_result() {
  # $1 status  $2 human detail (kept simple to stay valid JSON)
  local st="$1" dt="$2"
  printf '{"status":"%s","version":"%s","previous":"%s","time":"%s","detail":"%s"}\n' \
    "${st}" "${version}" "${current_version}" "$(date -u +%FT%TZ)" "${dt}" \
    > "${update_dir}/last_result.json"
  log "result: ${st} (${dt})"
}

write_progress() {
  # $1 stage  $2 text  -> live progress shown in the UI
  printf '{"stage":"%s","text":"%s","time":"%s"}\n' \
    "$1" "$2" "$(date -u +%FT%TZ)" > "${update_dir}/progress.json"
}

rollback() {
  [ "${ROLLED_BACK}" -eq 1 ] && return 0
  ROLLED_BACK=1
  log "ROLLBACK after failure"
  local restored=0 removed=0
  if [ -d "${backup}" ] && [ -f "${backup}/__manifest" ]; then
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      if [ -e "${backup}/${f}" ] || [ -L "${backup}/${f}" ]; then
        mkdir -p "${app_dir}/$(dirname "$f")"
        rm -rf "${app_dir}/${f}"
        cp -a "${backup}/${f}" "${app_dir}/${f}"
        restored=$((restored + 1))
      fi
    done < "${backup}/__manifest"
    # remove files only this upgrade introduced
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      if ! grep -qxF -- "$f" "${backup}/__manifest"; then
        rm -rf "${app_dir}/${f}"
        removed=$((removed + 1))
      fi
    done < "${MANIFEST}"
  fi
  ( cd "${app_dir}" && "${python}" -m pip install -q -r requirements.txt ) || true
  systemctl daemon-reload || true
  systemctl restart "${service}" || true
  log "rollback done: restored=$restored removed=$removed"
  rm -f "${update_dir}/progress.json"
  write_result "error" "upgrade failed; previous version restored"
}
trap 'rollback' ERR

write_result "running" "upgrade started"

# ----------------------------------------------------------------------
# 1) never allow a release to touch user data
python3 - "${MANIFEST}" <<'PYEOF'
import sys
blocks = ("venv/", ".git/", ".updates/", ".bak/", "dist/", ".github/", "__pycache__/")
usr = {"state.json", "servers.json", "stats.db", "stats.db-wal", "stats.db-shm"}
bad = []
for raw in open(sys.argv[1]):
    f = raw.strip()
    if not f or f.startswith("#"):
        continue
    if f in usr or any(f.startswith(b) for b in blocks):
        bad.append(f)
if bad:
    print("PROTECTED FILES IN MANIFEST: " + ", ".join(bad), file=sys.stderr)
    sys.exit(1)
PYEOF
log "manifest OK"

# ----------------------------------------------------------------------
# 2) backup every tracked file we are about to replace/remove
write_progress backup "Сохранение резервной копии текущих файлов"
mkdir -p "${backup}"
: > "${backup}/__manifest.new"
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if [ -f "${app_dir}/${f}" ]; then
    mkdir -p "${backup}/$(dirname "$f")"
    cp -a "${app_dir}/${f}" "${backup}/${f}"
    printf '%s\n' "$f" >> "${backup}/__manifest.new"
  fi
done < "${MANIFEST}"
if [ -f "${OLD_MANIFEST}" ]; then
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if [ -f "${app_dir}/${f}" ] && [ ! -e "${backup}/${f}" ]; then
      mkdir -p "${backup}/$(dirname "$f")"
      cp -a "${app_dir}/${f}" "${backup}/${f}"
      printf '%s\n' "$f" >> "${backup}/__manifest.new"
    fi
  done < "${OLD_MANIFEST}"
fi
sort -u "${backup}/__manifest.new" -o "${backup}/__manifest"
rm -f "${backup}/__manifest.new"
log "backed up $(wc -l < "${backup}/__manifest") files"

# ----------------------------------------------------------------------
# 3) remove files that are no longer part of the app
if [ -f "${OLD_MANIFEST}" ]; then
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if ! grep -qxF -- "$f" "${MANIFEST}"; then
      rm -f "${app_dir}/${f}"
      log "removed ${f}"
    fi
  done < "${OLD_MANIFEST}"
fi

# 4) install the new payload
write_progress install "Замена файлов на новые"
while IFS= read -r f; do
  [ -z "$f" ] && continue
  mkdir -p "${app_dir}/$(dirname "$f")"
  rm -f "${app_dir}/${f}"
  cp -a "${payload}/${f}" "${app_dir}/${f}"
done < "${MANIFEST}"
cp -a "${MANIFEST}" "${OLD_MANIFEST}"
log "payload installed"

# ----------------------------------------------------------------------
# 5) requirements + import check
write_progress deps "Установка зависимостей (pip)"
"${python}" -m pip install -q -r "${app_dir}/requirements.txt"
( cd "${app_dir}" && "${python}" -c "import app" )
log "requirements + import OK"

# ----------------------------------------------------------------------
# 6) restart + smoke
write_progress restart "Перезапуск сервиса"
systemctl daemon-reload
systemctl restart "${service}"
ok=0
for i in $(seq 1 20); do
  if systemctl is-active --quiet "${service}"; then ok=1; break; fi
  sleep 1
done
[ "${ok}" -eq 1 ] || { log "service failed to start"; false; }

UNIT="/etc/systemd/system/${service}.service"
PORT="$(grep -oP 'ExecStart=.*--port \K[0-9]+' "${UNIT}" 2>/dev/null || true)"
PORT="${PORT:-5182}"
ENVF="$(grep -oP 'EnvironmentFile=\K\S+' "${UNIT}" 2>/dev/null || true)"
CURL_ARGS=(-s -o /dev/null -w '%{http_code}' --max-time 6 "http://127.0.0.1:${PORT}/api/config-check")
if [ -n "${ENVF}" ] && [ -s "${ENVF}" ]; then
  U="$(grep '^AWG_PANEL_USER=' "${ENVF}" | head -1 | cut -d= -f2-)"
  P="$(grep '^AWG_PANEL_PASSWORD=' "${ENVF}" | head -1 | cut -d= -f2-)"
  [ -n "${P}" ] && CURL_ARGS=(-u "${U:-admin}:${P}" "${CURL_ARGS[@]}")
fi
CODE="$(curl "${CURL_ARGS[@]}" 2>/dev/null || echo 000)"
[ "${CODE}" != "000" ] || { log "HTTP smoke failed (${CODE})"; false; }
log "smoke OK (HTTP ${CODE})"

# ----------------------------------------------------------------------
trap - ERR
write_progress smoke "Готово, проверка завершена"
write_result "ok" "updated to version"
rm -f "${update_dir}/progress.json"
rm -rf "${ORIG_PAYLOAD}"
log "finished OK"