#!/usr/bin/env bash
# Runs ON the VPS. Installs ServerManager panel + forward scripts.
# Usage: bash install-on-vps.sh
set -euo pipefail

ROOT="${SERVERMANAGER_ROOT:-/opt/servermanager}"
PANEL_DIR="$ROOT/panel"
SCRIPTS_DIR="$ROOT/scripts"
ENV_FILE="$ROOT/panel.env"

: "${VPS_PUBLIC_IP:?Set VPS_PUBLIC_IP}"
: "${PF_USER:=admin}"
: "${PF_PASS:?Set PF_PASS}"
: "${ROUTER_HOST:=192.168.8.1}"
: "${ROUTER_USER:=root}"
: "${ROUTER_PASS:?Set ROUTER_PASS}"
: "${PF_PORT:=5002}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 sshpass ufw iptables

mkdir -p "$PANEL_DIR/static" "$SCRIPTS_DIR"
# Files are expected next to this script (uploaded by Setup.exe)
HERE="$(cd "$(dirname "$0")" && pwd)"
cp -a "$HERE/../panel/." "$PANEL_DIR/"
cp -a "$HERE/../scripts/apply-lan-forwards.sh" "$SCRIPTS_DIR/"
chmod +x "$SCRIPTS_DIR/apply-lan-forwards.sh"
if [[ ! -f "$SCRIPTS_DIR/forwards.conf" ]]; then
  cp "$HERE/../scripts/forwards.conf.example" "$SCRIPTS_DIR/forwards.conf"
fi

# Base64 router password so special chars are safe in EnvironmentFile
ROUTER_PASS_B64="$(printf '%s' "$ROUTER_PASS" | base64 -w0 2>/dev/null || printf '%s' "$ROUTER_PASS" | base64)"

cat > "$ENV_FILE" <<EOF
PF_HOST=0.0.0.0
PF_PORT=${PF_PORT}
PF_USER=${PF_USER}
PF_PASS=${PF_PASS}
FORWARDS_CONF=${SCRIPTS_DIR}/forwards.conf
APPLY_SCRIPT=${SCRIPTS_DIR}/apply-lan-forwards.sh
ROUTER_HOST=${ROUTER_HOST}
ROUTER_USER=${ROUTER_USER}
ROUTER_PASS_B64=${ROUTER_PASS_B64}
ROUTER_CONF=/etc/config/port_forward
HOOKUPS_JSON=${PANEL_DIR}/hookups.json
VPS_PUBLIC_IP=${VPS_PUBLIC_IP}
DOCKER_HOST_GW=${DOCKER_HOST_GW:-172.18.0.1}
VPN_CLIENT_CIDRS=${VPN_CLIENT_CIDRS:-10.8.0.0/24 192.168.8.0/24}
VPN_UFW_FROM=${VPN_UFW_FROM:-10.8.0.0/24}
PANEL_TITLE=${PANEL_TITLE:-ServerManager}
PANEL_TAGLINE=${PANEL_TAGLINE:-Sign in to manage VPS forwards, GL.iNet, domains, and firewall.}
EOF
chmod 600 "$ENV_FILE"

# Optional Caddy integration (leave blank for stock installs)
if [[ -n "${CADDYFILE_PATH:-}" ]]; then
  printf 'CADDYFILE_PATH=%s\nCADDY_CONTAINER=%s\n' "$CADDYFILE_PATH" "${CADDY_CONTAINER:-}" >> "$ENV_FILE"
fi

install -m 644 "$HERE/../panel/servermanager-panel.service" /etc/systemd/system/servermanager-panel.service
systemctl daemon-reload
systemctl enable --now servermanager-panel.service

# Firewall: SSH + panel + WireGuard UDP (if used)
ufw allow OpenSSH comment 'SSH' || true
ufw allow "${PF_PORT}/tcp" comment 'ServerManager panel' || true
ufw allow 5000/udp comment 'WireGuard VPN tunnel' || true
ufw --force enable || true

# Persist forwards on boot
cat > /etc/systemd/system/servermanager-forwards.service <<EOF
[Unit]
Description=ServerManager LAN DNAT forwards
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=FORWARDS_CONF=${SCRIPTS_DIR}/forwards.conf
ExecStart=${SCRIPTS_DIR}/apply-lan-forwards.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable servermanager-forwards.service
systemctl start servermanager-forwards.service || true

# Quick router reachability check (best-effort over WG/LAN path)
set +e
sshpass -p "$ROUTER_PASS" ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 \
  -o UserKnownHostsFile="${PANEL_DIR}/router_known_hosts" \
  "${ROUTER_USER}@${ROUTER_HOST}" "echo ROUTER_OK; cat /etc/glversion 2>/dev/null || uname -a"
RC=$?
set -e

echo "==== ServerManager installed ===="
echo "Panel:  http://${VPS_PUBLIC_IP}:${PF_PORT}"
echo "User:   ${PF_USER}"
echo "Router check exit: ${RC}"
systemctl --no-pager --full status servermanager-panel.service | head -n 20
