#!/usr/bin/env bash
# Apply DNAT forwards from forwards.conf and open matching UFW allow rules.
set -euo pipefail

CONF="${FORWARDS_CONF:-/opt/servermanager/scripts/forwards.conf}"
WG_IFACE="${WG_IFACE:-wg0}"
CHAIN="${DNAT_CHAIN:-SERVERMANAGER_DNAT}"

if [[ ! -f "$CONF" ]]; then
  echo "Missing $CONF" >&2
  exit 1
fi

# Ensure chain exists and is hooked from PREROUTING
iptables -t nat -N "$CHAIN" 2>/dev/null || iptables -t nat -F "$CHAIN"
if ! iptables -t nat -C PREROUTING -j "$CHAIN" 2>/dev/null; then
  iptables -t nat -A PREROUTING -j "$CHAIN"
fi
iptables -t nat -F "$CHAIN"

# Enable forwarding (needed for DNAT to WG LAN)
sysctl -w net.ipv4.ip_forward=1 >/dev/null

while read -r pub proto dest_ip dest_port name || [[ -n "${pub:-}" ]]; do
  [[ -z "${pub:-}" || "$pub" =~ ^# ]] && continue
  proto="${proto,,}"
  echo "forward ${pub}/${proto} -> ${dest_ip}:${dest_port} (${name})"
  iptables -t nat -A "$CHAIN" -p "$proto" --dport "$pub" -j DNAT --to-destination "${dest_ip}:${dest_port}"
  # Accept traffic that will be forwarded
  iptables -C FORWARD -p "$proto" -d "$dest_ip" --dport "$dest_port" -j ACCEPT 2>/dev/null \
    || iptables -I FORWARD -p "$proto" -d "$dest_ip" --dport "$dest_port" -j ACCEPT
  # UFW allow public port (idempotent-ish)
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${pub}/${proto}" comment "SM forward ${name}" >/dev/null 2>&1 || true
  fi
done < <(grep -vE '^\s*(#|$)' "$CONF" || true)

echo "Applied forwards from $CONF"
