#!/usr/bin/env bash
set -euo pipefail

# Fixed runtime names/paths (no env vars)
APP_NAME="timer-stash"
SERVICE_USER="timerstash"
SERVICE_GROUP="timerstash"

CODE_SRC_DIR="$(pwd)"                        # current repo
CODE_DST_DIR="/usr/libexec/${APP_NAME}"      # code for the service
CONFIG_DIR="/etc/${APP_NAME}"                # read-only config
STATE_DIR="/var/lib/${APP_NAME}"             # writable state (stash, logs)
UNIT_DIR="/etc/systemd/system"               # systemd unit directory

SERVICE_UNIT_SRC="${CODE_SRC_DIR}/systemd/timer-stache.service"
TIMER_UNIT_SRC="${CODE_SRC_DIR}/systemd/timer-stache.timer"
SERVICE_UNIT_DST="${UNIT_DIR}/${APP_NAME}.service"
TIMER_UNIT_DST="${UNIT_DIR}/${APP_NAME}.timer"

PYTHON_BIN="$(command -v python3 || true)"

die() { echo "[!] $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."; }
ensure_python() { [ -n "$PYTHON_BIN" ] || die "python3 not found."; }

usage() {
  cat <<EOF
Usage: sudo ./install.sh [--purge-source]

Installs ${APP_NAME} as a systemd service + timer:
 - Code      -> ${CODE_DST_DIR}
 - Config    -> ${CONFIG_DIR}/config.json  (created from config.example.json if present)
 - State     -> ${STATE_DIR}
 - Units     -> ${SERVICE_UNIT_DST}, ${TIMER_UNIT_DST}
 - User      -> ${SERVICE_USER}

Options:
  --purge-source   After successful install, delete the cloned repo directory to remove extra artifacts.
EOF
}

maybe_purge_source=false
if [ "${1-}" = "--help" ]; then usage; exit 0; fi
if [ "${1-}" = "--purge-source" ]; then maybe_purge_source=true; fi

main() {
  need_root
  ensure_python

  # 1) Create dedicated service user if missing
  if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
    echo "[i] Created service user: ${SERVICE_USER}"
  fi

  # 2) Create directories
  install -d -m 0755 "${CODE_DST_DIR}"
  install -d -m 0755 "${CONFIG_DIR}"
  install -d -m 0750 "${STATE_DIR}"
  chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${STATE_DIR}"

  # 3) Install code (only what's needed)
  install -m 0644 "${CODE_SRC_DIR}/timer_stash.py" "${CODE_DST_DIR}/timer_stash.py"
  chown -R root:root "${CODE_DST_DIR}"
  chmod 0755 "${CODE_DST_DIR}"

  # 4) Config: if none exists, seed from example; else leave user's config
  if [ -f "${CODE_SRC_DIR}/config.example.json" ] && [ ! -f "${CONFIG_DIR}/config.json" ]; then
    install -m 0644 "${CODE_SRC_DIR}/config.example.json" "${CONFIG_DIR}/config.json"
    echo "[i] Installed default config: ${CONFIG_DIR}/config.json"
  fi
  chown -R root:root "${CONFIG_DIR}"

  # 5) Install/rename units
  install -m 0644 "${SERVICE_UNIT_SRC}" "${SERVICE_UNIT_DST}"
  install -m 0644 "${TIMER_UNIT_SRC}"   "${TIMER_UNIT_DST}"

  # 6) Reload systemd and enable/start timer
  systemctl daemon-reload
  systemctl enable "${APP_NAME}.timer"
  systemctl start  "${APP_NAME}.timer"

  echo "[✓] ${APP_NAME} installed."
  systemctl status "${APP_NAME}.timer" --no-pager || true
  systemctl list-timers | grep "${APP_NAME}" || true

  # 7) Optional: remove repo (extra artifacts) AFTER successful install
  if $maybe_purge_source; then
    # Be careful: only delete if this looks like a git clone and not the code dir
    if [ -d "${CODE_SRC_DIR}/.git" ] && [ "${CODE_SRC_DIR}" != "${CODE_DST_DIR}" ]; then
      echo "[i] --purge-source requested; removing source directory: ${CODE_SRC_DIR}"
      rm -rf "${CODE_SRC_DIR}"
    else
      echo "[!] Skipping purge: source does not look like a safe git clone."
    fi
  else
    echo "[i] To remove leftover source artifacts, you can re-run: sudo ./install.sh --purge-source"
  fi
}

main "$@"