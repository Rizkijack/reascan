#!/usr/bin/env bash
# reascan adapter — one-command VM install.
#
# What this does (docs/vm-setup.md §3):
#   1. .env.example → .env (never overwrites an existing .env; generates API_KEY on first run)
#   2. installs cloudflared if missing (official release binary → /usr/local/bin)
#   3. writes two systemd units: reascan-adapter (this service) + reascan-tunnel (cloudflared)
#   4. enables and starts both, Restart=always
#
# Needs root for /usr/local/bin and /etc/systemd/system. Safe to re-run: an
# existing .env and an existing tunnel are left alone.

set -euo pipefail

ADAPTER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8787}"

log() { printf 'reascan-install: %s\n' "$*"; }
die() { printf 'reascan-install: ERROR: %s\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  die "run as root: sudo bash install.sh"
fi

command -v node >/dev/null 2>&1 || die "node not found — install Node 20+ first (see docs/vm-setup.md §1)"

# --- 1. .env ---------------------------------------------------------------
if [ ! -f "$ADAPTER_DIR/.env" ]; then
  API_KEY="$(node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))")"
  sed "s/^API_KEY=$/API_KEY=$API_KEY/" "$ADAPTER_DIR/.env.example" > "$ADAPTER_DIR/.env"
  chmod 600 "$ADAPTER_DIR/.env"
  log ".env created with a generated API_KEY — copy it to the Pages dashboard secret"
else
  log ".env exists — leaving it untouched"
fi

# The tunnel points at the adapter port. Read it from .env when present so the
# two services cannot drift apart.
ENV_PORT="$(sed -n 's/^PORT=//p' "$ADAPTER_DIR/.env" | tail -n1)"
PORT="${ENV_PORT:-$PORT}"

# --- 2. cloudflared ---------------------------------------------------------
if ! command -v cloudflared >/dev/null 2>&1; then
  case "$(uname -m)" in
    x86_64)          CF_ARCH=amd64 ;;
    aarch64 | arm64) CF_ARCH=arm64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
  log "installing cloudflared ($CF_ARCH)"
  curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$CF_ARCH" \
    -o /usr/local/bin/cloudflared
  chmod +x /usr/local/bin/cloudflared
else
  log "cloudflared already installed — leaving it untouched"
fi

# --- 3. systemd units -------------------------------------------------------
cat > /etc/systemd/system/reascan-adapter.service <<EOF
[Unit]
Description=reascan analysis adapter (Node)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$ADAPTER_DIR
EnvironmentFile=$ADAPTER_DIR/.env
ExecStart=$(command -v node) server.js
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/reascan-tunnel.service <<EOF
[Unit]
Description=Cloudflare Tunnel (reascan adapter)
After=network-online.target reascan-adapter.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cloudflared tunnel --url http://localhost:$PORT
Restart=always
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# --- 4. enable + start ------------------------------------------------------
systemctl daemon-reload
systemctl enable --now reascan-adapter reascan-tunnel

log "done. verify:"
log "  curl http://localhost:$PORT/health -H \"X-API-Key: <from vm-adapter/.env>\""
log "  journalctl -u reascan-tunnel -f   # quick-tunnel URL is printed there"
