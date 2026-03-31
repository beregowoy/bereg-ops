#!/usr/bin/env python3
"""
add-node.py — Automated VPN node provisioning script.

Usage:
    python3 add-node.py --ip 1.2.3.4 --name DE-05 --type standard \\
        --domain de05.bopen.bond --root-password SECRET

Node types:
    standard  — RLT_RAW_SELF profile (Reality + Selfsteal on port 9443)
    ru-full   — RU_FULL_SLF profile  (Reality + Selfsteal on port 9443)
    bridge    — BRIDGE profile        (no Selfsteal)

Environment variables:
    REMNAWAVE_API_URL    — panel URL          (default: https://rem.bereg.bond)
    REMNAWAVE_API_TOKEN  — API bearer token   (required)
    CF_API_TOKEN         — Cloudflare token   (skip DNS if absent)
    CF_ZONE_ID           — Cloudflare Zone ID (skip DNS if absent)
    ANSIBLE_KEY_FILE     — path to ansible private key
                           (default: /home/ansible/.ssh/id_ed25519)

Execution order:
    1  Test SSH connectivity (root@IP:22)
    2  Install packages, set hostname
    3  Create ansible user + pubkey
    4  UFW firewall rules
    5  Install Docker
    6  Deploy node_exporter (port 9100)
    7  Deploy selfsteal/Caddy (port 9443) — standard/ru-full only
    8  Create Cloudflare DNS record
    9  Create node in Remnawave panel → get secret key
    10 Deploy remnanode with secret key
    11 Harden SSH (port 5125, key-only, no root)
    12 Verify ansible key connection
    13 Update Prometheus file_sd + reload whitebox targets
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import textwrap
import time
import urllib.request

# ─── Constants ────────────────────────────────────────────────────────────────

ANSIBLE_PUBKEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHL9z2FJS8RNAui84L4JzToLtJgOE+"
    "f3JJtKVzA23pg7 ansible@bereg-vpn-ops"
)

SSH_HARDENED_PORT = 5125
REMNANODE_PORT    = 2222
NODE_EXPORTER_PORT = 9100
SELFSTEAL_PORT    = 9443

CONFIG_PROFILES = {
    "standard": "52edd661-aed1-48ee-ab9e-47a784060f54",  # RLT_RAW_SELF
    "ru-full":  "45f37423-88fa-47c7-9426-0ca2fa0955f1",  # RU_FULL_SLF
    "bridge":   "16aa91e1-d872-4a2b-a973-4b397169be76",  # BRIDGE
}

SELFSTEAL_TYPES = {"standard", "ru-full"}

API_URL          = os.environ.get("REMNAWAVE_API_URL", "https://rem.bereg.bond")
API_TOKEN        = os.environ.get("REMNAWAVE_API_TOKEN", "")
CF_API_TOKEN     = os.environ.get("CF_API_TOKEN", "")
CF_ZONE_ID       = os.environ.get("CF_ZONE_ID", "")
ANSIBLE_KEY_FILE = os.environ.get("ANSIBLE_KEY_FILE", "/home/ops/.ssh/ansible_key")

PROMETHEUS_SD_FILE = "/opt/monitoring_server/node-exporter-sd.yml"
WHITEBOX_SCRIPT    = "/home/ops/bereg-ops/scripts/gen-whitebox-targets.py"
WHITEBOX_ENV       = "/opt/whitebox/.env"

# ─── Logging ──────────────────────────────────────────────────────────────────

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def log(msg: str, level: str = "info") -> None:
    icons = {"info": f"{BLUE}[*]{RESET}", "ok": f"{GREEN}[+]{RESET}",
             "warn": f"{YELLOW}[!]{RESET}", "error": f"{RED}[-]{RESET}"}
    if level == "section":
        print(f"\n{BOLD}{BLUE}═══ {msg} ═══{RESET}")
    else:
        print(f"{icons.get(level, '')} {msg}")


def die(msg: str) -> None:
    log(msg, "error")
    sys.exit(1)


# ─── SSH Helper ───────────────────────────────────────────────────────────────

class SSH:
    """SSH wrapper using sshpass (password) or key-based auth."""

    def __init__(self, ip: str, password: str = "", port: int = 22, user: str = "root"):
        self.ip       = ip
        self.password = password
        self.port     = port
        self.user     = user
        self.key_file: str | None = None

    def run(self, cmd: str, check: bool = True, timeout: int = 300) -> tuple:
        """Run command over SSH. Returns (stdout, stderr, returncode)."""
        ssh_opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=30",
            "-p", str(self.port),
        ]

        if self.key_file:
            ssh_opts += ["-o", "BatchMode=yes"]
            parts = ["ssh"] + ssh_opts + ["-i", self.key_file, f"{self.user}@{self.ip}", cmd]
        else:
            ssh_opts += ["-o", "BatchMode=no"]
            parts = ["sshpass", "-p", self.password, "ssh"] + ssh_opts + [f"{self.user}@{self.ip}", cmd]

        result = subprocess.run(parts, capture_output=True, text=True, timeout=timeout)
        if check and result.returncode != 0:
            raise RuntimeError(
                f"SSH failed (rc={result.returncode}): {cmd}\nSTDERR: {result.stderr.strip()}"
            )
        return result.stdout.strip(), result.stderr.strip(), result.returncode

    def write_file(self, content: str, remote_path: str) -> None:
        """Write string content to a remote file via base64 encoding."""
        b64 = base64.b64encode(content.encode()).decode()
        self.run(f"mkdir -p $(dirname {remote_path})")
        self.run(f"echo '{b64}' | base64 -d > {remote_path}")

    def switch_to_key(self, key_file: str, port: int, user: str = "ansible") -> None:
        """Switch to key-based auth (after SSH hardening)."""
        self.key_file = key_file
        self.port     = port
        self.user     = user

    def run_live(self, cmd: str, timeout: int = 600) -> int:
        """Run command over SSH, streaming output directly to terminal. Returns exit code."""
        ssh_opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=15",
            "-p", str(self.port),
            "-t",  # force TTY for colored output
        ]
        if self.key_file:
            parts = ["ssh"] + ssh_opts + ["-i", self.key_file, f"{self.user}@{self.ip}", cmd]
        else:
            parts = ["sshpass", "-p", self.password, "ssh"] + ssh_opts + [f"{self.user}@{self.ip}", cmd]

        result = subprocess.run(parts, timeout=timeout)
        return result.returncode

    def test_connection(self, timeout: int = 15) -> bool:
        try:
            out, _, rc = self.run("echo ok", check=False, timeout=timeout)
            return rc == 0 and "ok" in out
        except Exception:
            return False


# ─── Step 1: Connectivity Test ────────────────────────────────────────────────

def step_test(ssh: SSH) -> None:
    log("Test connectivity", "section")

    result = subprocess.run(
        ["ping", "-c", "3", "-W", "3", ssh.ip],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        log(f"Ping {ssh.ip} OK", "ok")
    else:
        log(f"Ping no reply — ICMP may be blocked, continuing", "warn")

    log(f"Testing SSH root@{ssh.ip}:22...")
    if not ssh.test_connection():
        die(f"Cannot SSH to root@{ssh.ip}:22 — verify IP and password")
    log("SSH OK", "ok")

    out, _, _ = ssh.run("grep PRETTY_NAME /etc/os-release 2>/dev/null || uname -s -r")
    log(f"OS: {out.split(chr(10))[0]}", "info")


# ─── Step 1b: Pre-flight benchmarks ───────────────────────────────────────────

def step_preflight(ssh: SSH, name: str) -> None:
    """Run bench.sh + IP quality check, then ask for confirmation."""
    log(f"Pre-flight benchmarks for {name} ({ssh.ip})", "section")
    print(f"{YELLOW}Это займёт 3-5 минут (speed test). Дождись результатов.{RESET}\n")

    # ── bench.sh ──────────────────────────────────────────────────────────────
    print(f"{BOLD}{'─' * 60}{RESET}")
    print(f"{BOLD}  bench.sh — железо и скорость{RESET}")
    print(f"{BOLD}{'─' * 60}{RESET}\n")
    ssh.run_live("wget -qO- bench.sh | bash", timeout=600)

    # ── IP Quality check ──────────────────────────────────────────────────────
    print(f"\n{BOLD}{'─' * 60}{RESET}")
    print(f"{BOLD}  IP Quality Check — репутация IP{RESET}")
    print(f"{BOLD}{'─' * 60}{RESET}\n")
    ssh.run_live("bash <(curl -sL ip.check.place)", timeout=120)

    # ── Confirmation ──────────────────────────────────────────────────────────
    print(f"\n{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}  Нода: {name}  IP: {ssh.ip}{RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}")
    answer = input(f"\n{GREEN}Продолжить установку?{RESET} [y/N]: ").strip().lower()
    if answer not in ("y", "yes", "д", "да"):
        log("Установка отменена.", "warn")
        sys.exit(0)


# ─── Step 2: Packages ─────────────────────────────────────────────────────────

def step_packages(ssh: SSH, name: str) -> None:
    log("Install packages & set hostname", "section")
    ssh.run(
        "export DEBIAN_FRONTEND=noninteractive && "
        "apt-get update -y -q && "
        "apt-get install -y -q sudo nano wget curl cron ufw nftables ca-certificates "
        "gnupg lsb-release apt-transport-https software-properties-common",
        timeout=360,
    )
    ssh.run(f"hostnamectl set-hostname {name}")
    log(f"Packages installed, hostname = {name}", "ok")


# ─── Step 3: Ansible User ─────────────────────────────────────────────────────

def step_user(ssh: SSH) -> None:
    log("Create ansible user", "section")
    ssh.run(
        "id ansible &>/dev/null || useradd -m -s /bin/bash ansible; "
        "usermod -aG sudo ansible; "
        "echo 'ansible ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ansible; "
        "chmod 440 /etc/sudoers.d/ansible"
    )
    ssh.run(
        "mkdir -p /home/ansible/.ssh && chmod 700 /home/ansible/.ssh; "
        f"grep -qxF '{ANSIBLE_PUBKEY}' /home/ansible/.ssh/authorized_keys 2>/dev/null || "
        f"echo '{ANSIBLE_PUBKEY}' >> /home/ansible/.ssh/authorized_keys; "
        "chmod 600 /home/ansible/.ssh/authorized_keys; "
        "chown -R ansible:ansible /home/ansible/.ssh"
    )
    log("ansible user ready with pubkey", "ok")


# ─── Step 4: UFW ──────────────────────────────────────────────────────────────

def step_ufw(ssh: SSH, node_type: str) -> None:
    log("Configure UFW", "section")
    rules = [
        "ufw --force reset",
        "ufw allow 22/tcp   comment 'SSH-temp'",
        f"ufw allow {SSH_HARDENED_PORT}/tcp comment 'SSH'",
        "ufw allow 80/tcp  comment 'HTTP'",
        "ufw allow 443/tcp comment 'HTTPS'",
        f"ufw allow {REMNANODE_PORT}/tcp comment 'remnanode'",
        f"ufw allow {NODE_EXPORTER_PORT}/tcp comment 'node_exporter'",
        "ufw default deny incoming",
        "ufw default allow outgoing",
        "echo y | ufw enable",
        "systemctl enable ufw --now",
    ]
    if node_type in SELFSTEAL_TYPES:
        rules.insert(4, f"ufw allow {SELFSTEAL_PORT}/tcp comment 'selfsteal'")
    ssh.run(" && ".join(rules))
    log("UFW configured", "ok")


# ─── Step 5: Docker ───────────────────────────────────────────────────────────

def step_docker(ssh: SSH) -> None:
    log("Install Docker", "section")
    ssh.run("curl -fsSL https://get.docker.com | sh", timeout=360)
    ssh.run("systemctl enable docker --now")
    log("Docker installed", "ok")


# ─── Step 6: node_exporter ────────────────────────────────────────────────────

def step_node_exporter(ssh: SSH) -> None:
    log("Deploy node_exporter", "section")

    compose = textwrap.dedent("""\
        services:
          node-exporter:
            image: prom/node-exporter:latest
            container_name: node-exporter
            restart: unless-stopped
            pid: "host"
            network_mode: host
            command:
              - --path.rootfs=/host
              - --web.listen-address=:9100
              - --collector.disable-defaults
              - --collector.cpu
              - --collector.meminfo
              - --collector.loadavg
              - --collector.filesystem
              - --collector.netdev
              - --collector.stat
              - --collector.diskstats
              - --collector.time
              - --collector.uname
              - --collector.os
            volumes:
              - /:/host:ro,rslave
    """)
    ssh.run("mkdir -p /opt/node-exporter")
    ssh.write_file(compose, "/opt/node-exporter/docker-compose.yml")
    ssh.run("cd /opt/node-exporter && docker compose up -d", timeout=120)
    log(f"node_exporter running on port {NODE_EXPORTER_PORT}", "ok")


# ─── Step 7: Selfsteal ────────────────────────────────────────────────────────

SELFSTEAL_HTML = """\
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Авторизация</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh;
      font-family: system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
      color: #e8e8e8; display: flex; align-items: center;
      justify-content: center; padding: 1rem;
    }
    .card {
      width: 100%; max-width: 380px; padding: 2rem;
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.3);
    }
    h1 { margin: 0 0 1.5rem; font-size: 1.5rem; font-weight: 600; text-align: center; }
    label { display: block; margin-bottom: 0.35rem; font-size: 0.9rem; color: #b0b0b0; }
    input {
      width: 100%; padding: 0.75rem 1rem; margin-bottom: 1rem;
      border: 1px solid rgba(255,255,255,0.2); border-radius: 8px;
      background: rgba(0,0,0,0.2); color: #fff; font-size: 1rem;
    }
    input:focus { outline: none; border-color: #4a9eff; }
    button {
      width: 100%; padding: 0.85rem; border: none; border-radius: 8px;
      background: linear-gradient(135deg, #4a9eff, #357abd);
      color: #fff; font-size: 1rem; font-weight: 600; cursor: pointer;
    }
    button:hover { opacity: 0.9; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Вход</h1>
    <form method="post" action="#" onsubmit="return false">
      <label>Логин</label>
      <input type="text" placeholder="Введите логин" autocomplete="username" required>
      <label>Пароль</label>
      <input type="password" placeholder="Введите пароль" autocomplete="current-password" required>
      <button type="submit">Войти</button>
    </form>
  </div>
</body>
</html>
"""


def step_selfsteal(ssh: SSH, domain: str) -> None:
    log("Deploy selfsteal (Caddy)", "section")

    caddyfile = f"""\
{{
    https_port {SELFSTEAL_PORT}
    default_bind 127.0.0.1
    servers {{
        listener_wrappers {{
            proxy_protocol {{
                allow 127.0.0.1/32
            }}
            tls
        }}
    }}
    auto_https disable_redirects
}}

http://{domain} {{
    bind 0.0.0.0
    redir https://{domain}{{uri}} permanent
}}

https://{domain} {{
    root * /var/www/html
    try_files {{path}} /index.html
    file_server
}}

:{SELFSTEAL_PORT} {{
    tls internal
    respond 204
}}

:80 {{
    bind 0.0.0.0
    respond 204
}}
"""

    compose = f"""\
services:
  caddy:
    image: caddy:latest
    container_name: caddy-selfsteal
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - /opt/html:/var/www/html:ro
      - ./logs:/var/log/caddy
      - caddy_data:/data
      - caddy_config:/config
volumes:
  caddy_data:
  caddy_config:
"""

    ssh.run("mkdir -p /opt/selfsteal/logs /opt/html")
    ssh.write_file(SELFSTEAL_HTML, "/opt/html/index.html")
    ssh.write_file(caddyfile, "/opt/selfsteal/Caddyfile")
    ssh.write_file(compose, "/opt/selfsteal/docker-compose.yml")
    ssh.run("cd /opt/selfsteal && docker compose up -d", timeout=120)
    log(f"Selfsteal running: {domain}:{SELFSTEAL_PORT}", "ok")


# ─── Step 8: Cloudflare DNS ───────────────────────────────────────────────────

def step_dns(ip: str, domain: str) -> None:
    log(f"Create CF DNS: {domain} → {ip}", "section")

    if not CF_API_TOKEN or not CF_ZONE_ID:
        log("CF_API_TOKEN / CF_ZONE_ID not set — skipping DNS", "warn")
        log(f"  Create manually: {domain}  A  {ip}", "warn")
        return

    def cf_req(method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            f"https://api.cloudflare.com/client/v4{path}",
            data=data, method=method,
            headers={"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())

    # Check existing
    resp = cf_req("GET", f"/zones/{CF_ZONE_ID}/dns_records?name={domain}&type=A")
    existing = resp.get("result", [])

    record = {"type": "A", "name": domain, "content": ip, "ttl": 60, "proxied": False}
    if existing:
        rid = existing[0]["id"]
        result = cf_req("PUT", f"/zones/{CF_ZONE_ID}/dns_records/{rid}", record)
        action = "updated"
    else:
        result = cf_req("POST", f"/zones/{CF_ZONE_ID}/dns_records", record)
        action = "created"

    if result.get("success"):
        log(f"DNS record {action}: {domain} A {ip}", "ok")
    else:
        raise RuntimeError(f"CF DNS failed: {result.get('errors')}")


# ─── Step 9: Remnawave API ────────────────────────────────────────────────────

def _get_inbound_uuids(profile_uuid: str) -> list:
    """Fetch activeInbounds UUIDs for a given profile from an existing node."""
    req = urllib.request.Request(
        f"{API_URL}/api/nodes",
        headers={"Authorization": f"Bearer {API_TOKEN}"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        nodes = json.loads(r.read()).get("response", [])

    for node in nodes:
        cp = node.get("configProfile", {})
        if cp.get("activeConfigProfileUuid") == profile_uuid:
            return [ib["uuid"] for ib in cp.get("activeInbounds", [])]
    return []


def _get_secret_key() -> str:
    """Generate a fresh APP_SECRET_KEY via /api/keygen/get."""
    req = urllib.request.Request(
        f"{API_URL}/api/keygen",
        method="GET",
        headers={"Authorization": f"Bearer {API_TOKEN}"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        result = json.loads(r.read())
    pub_key = result.get("response", {}).get("pubKey", "")
    if not pub_key:
        raise RuntimeError(f"No pubKey in keygen response: {result}")
    return pub_key


def step_remnawave(name: str, ip: str, node_type: str) -> tuple:
    """Create node in Remnawave. Returns (uuid, secret_key)."""
    log(f"Create Remnawave node: {name}", "section")

    profile_uuid = CONFIG_PROFILES[node_type]
    inbound_uuids = _get_inbound_uuids(profile_uuid)
    if not inbound_uuids:
        die(f"Could not find activeInbounds for profile {profile_uuid} — no existing node with this profile?")

    # Generate secret key before creating the node
    secret_key = _get_secret_key()
    log(f"Secret key generated: {secret_key[:12]}...", "ok")

    payload = {
        "name": name,
        "address": ip,
        "port": REMNANODE_PORT,
        "apiPort": REMNANODE_PORT,
        "isTrafficTrackingActive": True,
        "trafficLimitBytes": 0,
        "notifyPercent": 0,
        "trafficResetDay": 1,
        "excludedInbounds": [],
        "configProfile": {
            "activeConfigProfileUuid": profile_uuid,
            "activeInbounds": inbound_uuids,
        },
        "countryCode": _country(name),
        "isDisabled": False,
    }

    req = urllib.request.Request(
        f"{API_URL}/api/nodes",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        result = json.loads(r.read())

    node = result.get("response", result)
    node_uuid = node.get("uuid", "")

    if not node_uuid:
        log(f"Unexpected response: {json.dumps(node, indent=2)}", "warn")
        raise RuntimeError("No uuid in Remnawave response")

    log(f"Node UUID: {node_uuid}", "ok")
    log(f"Secret key: {secret_key[:8]}...", "ok")
    return node_uuid, secret_key


def _country(name: str) -> str:
    parts = name.upper().split("-")
    if parts and len(parts[0]) == 2 and parts[0].isalpha():
        return parts[0]
    return "XX"


# ─── Step 10: Deploy remnanode ────────────────────────────────────────────────

def step_remnanode(ssh: SSH, secret_key: str) -> None:
    log("Deploy remnanode", "section")

    env_file = f"""\
SECRET_KEY={secret_key}
NODE_PORT={REMNANODE_PORT}
PANEL_HOST_URL={API_URL}
SSL=true
"""

    compose = """\
services:
  remnanode:
    container_name: remnanode
    image: ghcr.io/remnawave/node:latest
    restart: unless-stopped
    network_mode: host
    env_file:
      - .env
    volumes:
      - remnanode_data:/app/data
      - ./logs:/app/logs
volumes:
  remnanode_data:
"""

    ssh.run("mkdir -p /opt/remnanode/logs")
    ssh.write_file(compose, "/opt/remnanode/docker-compose.yml")
    ssh.write_file(env_file, "/opt/remnanode/.env")
    ssh.run("chmod 600 /opt/remnanode/.env")
    ssh.run("cd /opt/remnanode && docker compose up -d", timeout=180)
    log("remnanode deployed", "ok")


# ─── Step 11: SSH Hardening ───────────────────────────────────────────────────

def step_harden_ssh(ssh: SSH) -> None:
    log(f"Harden SSH (port {SSH_HARDENED_PORT}, key-only, no root)", "section")

    sshd_cfg = textwrap.dedent(f"""\
        Port {SSH_HARDENED_PORT}
        PermitRootLogin no
        PasswordAuthentication no
        PubkeyAuthentication yes
        ChallengeResponseAuthentication no
        UsePAM yes
        X11Forwarding no
        PrintMotd no
        AcceptEnv LANG LC_*
        Subsystem sftp /usr/lib/openssh/sftp-server
    """)
    ssh.write_file(sshd_cfg, "/etc/ssh/sshd_config")
    ssh.run("mkdir -p /run/sshd && sshd -t")  # validate config
    # Fire-and-forget restart — connection drops, that's expected
    try:
        ssh.run("systemctl restart ssh || systemctl restart sshd || true", check=False, timeout=10)
    except subprocess.TimeoutExpired:
        pass  # Expected — SSH drops the connection when restarting
    log("SSH hardened", "ok")


# ─── Step 12: Verify key connection ──────────────────────────────────────────

def step_verify_key(ssh: SSH) -> None:
    log(f"Verify ansible key SSH on port {SSH_HARDENED_PORT}", "section")
    ssh.switch_to_key(ANSIBLE_KEY_FILE, SSH_HARDENED_PORT, "ansible")

    deadline = time.time() + 60
    while time.time() < deadline:
        if ssh.test_connection(timeout=10):
            out, _, _ = ssh.run("whoami", check=False)
            log(f"Connected as: {out} on port {SSH_HARDENED_PORT}", "ok")
            # Only now close port 22 — SSH on new port is confirmed working
            ssh.run("ufw delete allow 22/tcp 2>/dev/null || true", check=False)
            log("Port 22 closed in UFW", "ok")
            return
        time.sleep(3)

    log("Could not verify ansible key connection — check manually", "warn")
    log(f"  ssh -i {ANSIBLE_KEY_FILE} -p {SSH_HARDENED_PORT} ansible@{ssh.ip}", "warn")


# ─── Step 13: Prometheus & Whitebox ──────────────────────────────────────────

def step_prometheus(ip: str, name: str) -> None:
    log("Update Prometheus node_exporter targets", "section")

    entry = (
        f'- targets: ["{ip}:{NODE_EXPORTER_PORT}"]\n'
        f'  labels:\n'
        f'    nodename: "{name}"\n'
    )

    if os.path.exists(PROMETHEUS_SD_FILE):
        with open(PROMETHEUS_SD_FILE) as f:
            existing = f.read()
        if ip in existing:
            log(f"{ip} already in {PROMETHEUS_SD_FILE}", "warn")
            return
        with open(PROMETHEUS_SD_FILE, "a") as f:
            f.write(entry)
        log(f"Appended {name} ({ip}) to {PROMETHEUS_SD_FILE}", "ok")
    else:
        with open(PROMETHEUS_SD_FILE, "w") as f:
            f.write(entry)
        log(f"Created {PROMETHEUS_SD_FILE}", "ok")
        log(
            "  ACTION: add to prometheus.yml node_exporter job:\n"
            f"    file_sd_configs:\n"
            f"      - files: ['{PROMETHEUS_SD_FILE}']\n"
            f"  Then reload Prometheus.",
            "warn",
        )
        return

    # Reload Prometheus
    try:
        req = urllib.request.Request("http://localhost:9090/-/reload", method="POST")
        with urllib.request.urlopen(req, timeout=10):
            pass
        log("Prometheus reloaded", "ok")
    except Exception as e:
        log(f"Prometheus reload failed (do it manually): {e}", "warn")


def step_whitebox(ip: str, name: str) -> None:
    log("Reload whitebox targets", "section")
    if not os.path.exists(WHITEBOX_SCRIPT):
        log(f"Script not found at {WHITEBOX_SCRIPT}", "warn")
        return

    env = dict(os.environ)
    if os.path.exists(WHITEBOX_ENV):
        with open(WHITEBOX_ENV) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()

    result = subprocess.run(
        [sys.executable, WHITEBOX_SCRIPT],
        env=env, capture_output=True, text=True,
    )
    if result.returncode == 0:
        log("Whitebox targets updated", "ok")
    else:
        log(f"Whitebox update warning: {result.stderr.strip()}", "warn")


# ─── Main ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Automated VPN node provisioning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 add-node.py --ip 1.2.3.4 --name DE-05 --type standard \\
                  --domain de05.bopen.bond --root-password SECRET

              python3 add-node.py --ip 1.2.3.4 --name US-03 --type bridge \\
                  --root-password SECRET --skip-dns
        """),
    )
    p.add_argument("--ip",             required=True,  help="Server IP address")
    p.add_argument("--name",           required=True,  help="Node name, e.g. DE-05")
    p.add_argument("--type",           required=True,  choices=list(CONFIG_PROFILES))
    p.add_argument("--domain",         default="",     help="Per-node SNI domain, e.g. de05.bopen.bond")
    p.add_argument("--root-password",  required=True,  help="Current root SSH password")
    p.add_argument("--skip-dns",       action="store_true", help="Skip Cloudflare DNS")
    p.add_argument("--skip-remnawave", action="store_true", help="Skip Remnawave API step")
    p.add_argument("--skip-prometheus",action="store_true", help="Skip Prometheus/whitebox update")
    p.add_argument("--skip-preflight", action="store_true", help="Skip bench/IP-quality pre-flight checks")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if not API_TOKEN:
        die("REMNAWAVE_API_TOKEN is required")
    if args.type in SELFSTEAL_TYPES and not args.domain:
        die(f"--domain is required for type '{args.type}' (selfsteal needs an SNI domain)")

    log(f"Provisioning  {args.name}  ({args.ip})  type={args.type}", "section")
    if args.domain:
        log(f"Domain: {args.domain}")

    ssh = SSH(ip=args.ip, password=args.root_password)

    # ── Server setup (all as root, before SSH hardening) ────────────────────
    step_test(ssh)
    if not args.skip_preflight:
        step_preflight(ssh, args.name)
    step_packages(ssh, args.name)
    step_user(ssh)
    step_ufw(ssh, args.type)
    step_docker(ssh)
    step_node_exporter(ssh)
    if args.type in SELFSTEAL_TYPES:
        step_selfsteal(ssh, args.domain)

    # ── External API calls (local, no SSH needed) ───────────────────────────
    if not args.skip_dns and args.domain:
        step_dns(args.ip, args.domain)

    node_uuid = ""
    secret_key = ""
    if not args.skip_remnawave:
        node_uuid, secret_key = step_remnawave(args.name, args.ip, args.type)
    else:
        log("Skipping Remnawave API (--skip-remnawave)", "warn")
        secret_key = input("Enter APP_SECRET_KEY for remnanode: ").strip()

    # ── Deploy remnanode (still as root) ────────────────────────────────────
    step_remnanode(ssh, secret_key)

    # ── SSH hardening — LAST operation as root ──────────────────────────────
    step_harden_ssh(ssh)
    step_verify_key(ssh)

    # ── Monitoring update (runs locally on ops server) ───────────────────────
    if not args.skip_prometheus:
        step_prometheus(args.ip, args.name)
        step_whitebox(args.ip, args.name)

    # ── Summary ─────────────────────────────────────────────────────────────
    log("Done!", "section")
    print(f"\n  Node:        {args.name}")
    print(f"  IP:          {args.ip}")
    print(f"  Type:        {args.type} ({CONFIG_PROFILES[args.type]})")
    if args.domain:
        print(f"  Domain:      {args.domain}")
    if node_uuid:
        print(f"  RW UUID:     {node_uuid}")
    print(f"\n  SSH:         ssh -i {ANSIBLE_KEY_FILE} -p {SSH_HARDENED_PORT} ansible@{args.ip}")
    print(f"  Remnanode:   /opt/remnanode")
    if args.type in SELFSTEAL_TYPES:
        print(f"  Selfsteal:   /opt/selfsteal  (:{SELFSTEAL_PORT})")
    print(f"  Monitoring:  /opt/node-exporter  (:{NODE_EXPORTER_PORT})")
    print()


if __name__ == "__main__":
    main()
