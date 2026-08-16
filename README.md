# ServerManager
Blank control panel + Windows setup tool to deploy onto a VPS and manage a GL.iNet router (WireGuard LAN forwards, UFW firewall, optional Caddy domains).

## Features
- Custom **login page** (session cookie) — create username/password/title in Setup before deploy
- VPS DNAT forwards, GL.iNet port forwards, optional Caddy domains, UFW firewall + VPN-only toggles

## Requirements
- Ubuntu/Debian VPS with root SSH
- GL.iNet router (e.g. Flint 2) already linked with WireGuard so the VPS can reach the LAN (`192.168.8.1` by default)
- Windows PC with OpenSSH client (for source runs) or the Setup EXE

## Quick start (Setup EXE)
1. Download `ServerManager-Setup.exe` from Releases (or build below)
2. Run it
3. Enter VPS IP + root password
4. Enter GL.iNet LAN IP + admin password
5. Open `http://YOUR_VPS_IP:5002` and sign in with the panel password you chose

## Build Setup EXE (Windows)
Requires Python 3.12+ and OpenSSH Client. No extra SSH libraries needed.

```powershell
cd ServerManager
python -m pip install pyinstaller
pyinstaller --onefile --name ServerManager-Setup `
  --add-data "panel;panel" `
  --add-data "scripts;scripts" `
  --add-data "deploy;deploy" `
  setup\setup_wizard.py
```
Output: `dist\ServerManager-Setup.exe`
## Manual VPS install
```bash
# from repo root, after uploading files to the VPS:
export VPS_PUBLIC_IP=x.x.x.x
export PF_USER=admin
export PF_PASS='choose-a-strong-password'
export ROUTER_HOST=192.168.8.1
export ROUTER_USER=root
export ROUTER_PASS='your-glinet-password'
bash deploy/install-on-vps.sh
```

## Panel features
| Tab | Purpose |
|-----|---------|
| VPS forwards | Public port → LAN IP DNAT via WireGuard |
| GL.iNet router | Edit `/etc/config/port_forward` + DMZ over SSH |
| Domain hookups | Optional Caddy reverse proxies (`CADDYFILE_PATH`) |
| Firewall | UFW allow rules; **VPN** checkbox = WireGuard-only |

## Security notes
- Never commit `panel.env` or real passwords
- Prefer DNS-only (grey cloud) for admin domains if using Cloudflare
- Keep panel port / SSH / WireGuard UDP reachable; lock other services with the VPN checkbox

## License
MIT
