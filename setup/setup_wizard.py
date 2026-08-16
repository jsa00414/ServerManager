#!/usr/bin/env python3
"""
ServerManager Setup (Windows) — no third-party deps.
Uses OpenSSH (scp/ssh) + ASKPASS to upload the blank panel to a VPS
and connect it to a GL.iNet router.

Build:
  pyinstaller --onefile --name ServerManager-Setup ^
    --add-data "panel;panel" --add-data "scripts;scripts" --add-data "deploy;deploy" ^
    setup\\setup_wizard.py
"""

from __future__ import annotations

import base64
import getpass
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def repo_root() -> Path:
    if getattr(sys, "frozen", False):
        meipass = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
        here = Path(sys.executable).resolve().parent
        for candidate in (here, meipass):
            if (candidate / "panel" / "server.py").is_file():
                return candidate
        return meipass
    return Path(__file__).resolve().parents[1]


def prompt(label: str, default: str = "", secret: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    if secret:
        val = getpass.getpass(f"{label}{suffix}: ").strip()
    else:
        val = input(f"{label}{suffix}: ").strip()
    return val or default


def gen_password(n: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def find_ssh() -> tuple[str, str]:
    ssh = shutil.which("ssh") or r"C:\Windows\System32\OpenSSH\ssh.exe"
    scp = shutil.which("scp") or r"C:\Windows\System32\OpenSSH\scp.exe"
    if not Path(ssh).is_file() or not Path(scp).is_file():
        raise SystemExit("OpenSSH client not found. Install Optional Feature 'OpenSSH Client'.")
    return ssh, scp


def write_askpass(tmpdir: Path, password: str) -> Path:
    # Avoid spaces in path breaking OpenSSH argv
    ask = tmpdir / "askpass.cmd"
    # cmd echo of password; % special chars doubled carefully via caret-free base approach:
    # write password as a single line file read by askpass
    secret = tmpdir / "secret.txt"
    secret.write_text(password, encoding="utf-8", newline="\n")
    ask.write_text(
        "@echo off\r\ntype \"%~dp0secret.txt\"\r\n",
        encoding="ascii",
    )
    return ask


def ssh_run(
    ssh: str,
    host: str,
    user: str,
    port: int,
    ask: Path,
    kh: Path,
    remote_cmd: str,
    timeout: int = 600,
) -> int:
    env = os.environ.copy()
    env["DISPLAY"] = "localhost:0"
    env["SSH_ASKPASS"] = str(ask)
    env["SSH_ASKPASS_REQUIRE"] = "force"
    args = [
        ssh,
        "-o",
        f"UserKnownHostsFile={kh}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        f"ConnectTimeout=20",
        "-p",
        str(port),
        f"{user}@{host}",
        remote_cmd,
    ]
    print(f"$ ssh {user}@{host} …")
    # Start without console so ASKPASS is used
    creation = 0
    if os.name == "nt":
        creation = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    p = subprocess.run(args, env=env, capture_output=True, text=True, timeout=timeout, creationflags=creation)
    if p.stdout:
        print(p.stdout.rstrip())
    if p.stderr:
        print(p.stderr.rstrip())
    return p.returncode


def scp_upload(
    scp: str,
    host: str,
    user: str,
    port: int,
    ask: Path,
    kh: Path,
    local: Path,
    remote: str,
) -> None:
    env = os.environ.copy()
    env["DISPLAY"] = "localhost:0"
    env["SSH_ASKPASS"] = str(ask)
    env["SSH_ASKPASS_REQUIRE"] = "force"
    args = [
        scp,
        "-o",
        f"UserKnownHostsFile={kh}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        "-P",
        str(port),
        "-r",
        str(local),
        f"{user}@{host}:{remote}",
    ]
    print(f"upload {local.name} → {remote}")
    creation = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0  # type: ignore[attr-defined]
    p = subprocess.run(args, env=env, capture_output=True, text=True, timeout=300, creationflags=creation)
    if p.returncode != 0:
        raise SystemExit(f"scp failed ({p.returncode}): {p.stderr or p.stdout}")


def main() -> int:
    print("=" * 60)
    print(" ServerManager Setup — blank VPS + GL.iNet installer")
    print("=" * 60)
    root = repo_root()
    if not (root / "panel" / "server.py").is_file():
        print(f"ERROR: panel sources not found under {root}")
        return 1
    ssh, scp = find_ssh()

    print("\n-- VPS (Ubuntu/Debian) --")
    vps_host = prompt("VPS public IP or hostname")
    if not vps_host:
        print("VPS host is required")
        return 1
    vps_user = prompt("VPS SSH user", "root")
    vps_port = int(prompt("VPS SSH port", "22") or "22")
    vps_pass = prompt("VPS SSH password", secret=True)
    if not vps_pass:
        print("VPS password is required")
        return 1

    print("\n-- GL.iNet router (reachable from VPS via WireGuard/LAN) --")
    router_host = prompt("Router LAN IP", "192.168.8.1")
    router_user = prompt("Router SSH user", "root")
    router_pass = prompt("Router password", secret=True)
    if not router_pass:
        print("Router password is required")
        return 1

    print("\n-- Panel login --")
    pf_user = prompt("Panel username", "admin")
    pf_pass = prompt("Panel password (blank = generate)", secret=True) or gen_password()
    pf_port = prompt("Panel TCP port", "5002")

    # Work in a path WITHOUT spaces (OpenSSH on Windows breaks on spaced argv)
    tmp = Path(tempfile.mkdtemp(prefix="smsetup-", dir=os.environ.get("TEMP", tempfile.gettempdir())))
    # Prefer %TEMP%\smsetup if TEMP has no spaces; else C:\smsetup-tmp
    if " " in str(tmp):
        tmp = Path(r"C:\smsetup-tmp")
        tmp.mkdir(parents=True, exist_ok=True)
    ask = write_askpass(tmp, vps_pass)
    kh = tmp / "known_hosts"
    remote_tmp = f"/tmp/servermanager-setup-{int(time.time())}"

    print("\nPreparing remote folder…")
    rc = ssh_run(ssh, vps_host, vps_user, vps_port, ask, kh, f"rm -rf {remote_tmp} && mkdir -p {remote_tmp}")
    if rc != 0:
        print("SSH connection/upload prep failed")
        return rc

    for name in ("panel", "scripts", "deploy"):
        scp_upload(scp, vps_host, vps_user, vps_port, ask, kh, root / name, f"{remote_tmp}/{name}")

    router_b64 = base64.b64encode(router_pass.encode("utf-8")).decode("ascii")
    pf_b64 = base64.b64encode(pf_pass.encode("utf-8")).decode("ascii")
    run_sh = f"""#!/bin/bash
set -euo pipefail
export VPS_PUBLIC_IP='{vps_host}'
export PF_USER='{pf_user}'
export PF_PASS="$(printf '%s' '{pf_b64}' | base64 -d)"
export PF_PORT='{pf_port}'
export ROUTER_HOST='{router_host}'
export ROUTER_USER='{router_user}'
export ROUTER_PASS="$(printf '%s' '{router_b64}' | base64 -d)"
chmod +x {remote_tmp}/deploy/install-on-vps.sh {remote_tmp}/scripts/*.sh
bash {remote_tmp}/deploy/install-on-vps.sh
"""
    local_run = tmp / "run-install.sh"
    local_run.write_text(run_sh.replace("\r\n", "\n"), encoding="utf-8", newline="\n")
    scp_upload(scp, vps_host, vps_user, vps_port, ask, kh, local_run, f"{remote_tmp}/run-install.sh")

    print("\nRunning installer on VPS (apt + systemd)…")
    code = ssh_run(ssh, vps_host, vps_user, vps_port, ask, kh, f"bash {remote_tmp}/run-install.sh", timeout=900)

    # scrub secrets
    try:
        (tmp / "secret.txt").unlink(missing_ok=True)
    except Exception:
        pass

    print("\n" + "=" * 60)
    if code == 0:
        print("DONE")
        print(f"Open panel:  http://{vps_host}:{pf_port}")
        print(f"Username:    {pf_user}")
        print(f"Password:    {pf_pass}")
        print("WireGuard between VPS and GL.iNet must already be connected")
        print("so the VPS can reach the router LAN IP.")
        return 0
    print(f"Install finished with exit code {code}. See output above.")
    return code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nCancelled.")
        raise SystemExit(130)
