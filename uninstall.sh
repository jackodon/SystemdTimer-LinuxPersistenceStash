#!/usr/bin/env bash
set -euo pipefail

APP_NAME="timer-stash"
SERVICE_USER="timerstash"
SERVICE_GROUP="timerstash"

CODE_DST_DIR="/usr/libexec/${APP_NAME}"
CONFIG_DIR="/etc/${APP_NAME}"
STATE_DIR="/var/lib/${APP_NAME}"
UNIT_DIR="/etc/systemd/system"
SERVICE_UNIT_DST="${UNIT_DIR}/${APP_NAME}.service"
TIMER_UNIT_DST="${UNIT_DIR}/${APP_NAME}.timer"

die() { echo "[!] $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."; }

main() {
  need_root

  # Stop/disable timer first
  systemctl stop    "${APP_NAME}.timer" >/dev/null 2>&1 || true
  systemctl disable "${APP_NAME}.timer" >/dev/null 2>&1 || true

  # Remove units and reload
  rm -f "${SERVICE_UNIT_DST}" "${TIMER_UNIT_DST}" || true
  systemctl daemon-reload || true

  # Remove code/config/state
  rm -rf "${CODE_DST_DIR}" || true
  rm -rf "${CONFIG_DIR}"   || true
  rm -rf "${STATE_DIR}"    || true

  # Remove dedicated service user (safe if no processes)
  if id "${SERVICE_USER}" >/dev/null 2>&1; then
    userdel "${SERVICE_USER}" >/dev/null 2>&1 || true
  fi

  # Final checks
  leftovers=0
  for p in "${SERVICE_UNIT_DST}" "${TIMER_UNIT_DST}" "${CODE_DST_DIR}" "${CONFIG_DIR}" "${STATE_DIR}"; do
    if [ -e "$p" ]; then
      echo "[!] Leftover path not removed: $p"
      leftovers=1
    fi
  done

  if [ "$leftovers" -eq 0 ]; then
    echo "[✓] ${APP_NAME} fully uninstalled. All artifacts removed."
  else
    die "Uninstall incomplete—see leftovers above."
  fi
}

main "$@"