#!/usr/bin/env bash
# Apply DNAT forwards from forwards.conf and open matching UFW allow rules.
# DNAT is scoped to the VPS public IP only so Caddy/Docker proxies to LAN
# destinations (e.g. 192.168.8.x:8080) are not hijacked by public port rules.
set -euo pipefail

CONF="${FORWARDS_CONF:-/opt/servermanager/scripts/forwards.conf}"
WG_IFACE="${WG_IFACE:-wg0}"
CHAIN="${DNAT_CHAIN:-SERVERMANAGER_DNAT}"
VPS_IP="${VPS_PUBLIC_IP:-}"

if [[ ! -f "$CONF" ]]; then
  echo "Missing $CONF" >&2
  exit 1
fi

if [[ -z "$VPS_IP" ]]; then
  VPS_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
fi
if [[ -z "$VPS_IP" ]]; then
  echo "VPS_PUBLIC_IP not set and could not detect public IP" >&2
  exit 1
fi

# Ensure chain exists and is hooked from PREROUTING
iptables -t nat -N "$CHAIN" 2>/dev/null || iptables -t nat -F "$CHAIN"
if ! iptables -t nat -C PREROUTING -j "$CHAIN" 2>/dev/null; then
  iptables -t nat -I PREROUTING 1 -j "$CHAIN"
fi
iptables -t nat -F "$CHAIN"

# Enable forwarding (needed for DNAT to WG LAN)
sysctl -w net.ipv4.ip_forward=1 >/dev/null

while read -r pub proto dest_ip dest_port name || [[ -n "${pub:-}" ]]; do
  [[ -z "${pub:-}" || "$pub" =~ ^# ]] && continue
  proto="${proto,,}"
  echo "forward ${pub}/${proto} -> ${dest_ip}:${dest_port} (${name}) [only ${VPS_IP}]"
  # ONLY traffic destined to the VPS public IP (not Docker/LAN hairpins)
  iptables -t nat -A "$CHAIN" -d "$VPS_IP" -p "$proto" --dport "$pub" \
    -j DNAT --to-destination "${dest_ip}:${dest_port}"
  # Accept traffic that will be forwarded
  iptables -C FORWARD -p "$proto" -d "$dest_ip" --dport "$dest_port" -j ACCEPT 2>/dev/null \
    || iptables -I FORWARD -p "$proto" -d "$dest_ip" --dport "$dest_port" -j ACCEPT
  # UFW allow public port (idempotent-ish)
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${pub}/${proto}" comment "SM forward ${name}" >/dev/null 2>&1 || true
  fi
done < <(grep -vE '^\s*(#|$)' "$CONF" || true)

echo "Applied forwards from $CONF"
