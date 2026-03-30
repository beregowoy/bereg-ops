#!/usr/bin/env python3
"""
Generate whitebox-targets.yml for Prometheus from Remnawave API.

Fetches all nodes, builds vless:// or ss:// connection strings per node (by direct IP),
and writes a Prometheus file_sd_configs compatible YAML file.

Usage:
    python3 gen-whitebox-targets.py [--output /etc/prometheus/whitebox-targets.yml]

Environment variables:
    REMNAWAVE_API_URL   - Remnawave panel URL (default: https://rem.bereg.bond)
    REMNAWAVE_API_TOKEN - API bearer token (required)
    VLESS_UUID          - UUID for vless connections (from monitoring subscription)
    SS_PASSWORD         - Password for shadowsocks connections (from monitoring subscription)
    PROBE_TARGET        - URL to probe through VPN (default: https://google.com)
"""

import json
import os
import socket
import sys
import urllib.parse
import urllib.request

API_URL = os.environ.get("REMNAWAVE_API_URL", "https://rem.bereg.bond")
API_TOKEN = os.environ.get("REMNAWAVE_API_TOKEN", "")
VLESS_UUID = os.environ.get("VLESS_UUID", "")
SS_PASSWORD = os.environ.get("SS_PASSWORD", "")
PROBE_TARGET = os.environ.get("PROBE_TARGET", "https://google.com")
OUTPUT = "/etc/prometheus/whitebox-targets.yml"


def derive_public_key(private_key_b64):
    """Derive X25519 public key from private key (base64url-encoded)."""
    import base64

    padding = "=" * (4 - len(private_key_b64) % 4)
    pvk_bytes = base64.urlsafe_b64decode(private_key_b64 + padding)

    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        pk = X25519PrivateKey.from_private_bytes(pvk_bytes)
        pbk_bytes = pk.public_key().public_bytes_raw()
    except ImportError:
        try:
            import nacl.bindings

            pbk_bytes = nacl.bindings.crypto_scalarmult_base(pvk_bytes)
        except ImportError:
            return None

    return base64.urlsafe_b64encode(pbk_bytes).decode().rstrip("=")


def resolve_to_ip(address):
    """Resolve domain to IP, return as-is if already an IP."""
    try:
        socket.inet_aton(address)
        return address
    except OSError:
        try:
            return socket.getaddrinfo(address, None)[0][4][0]
        except Exception as e:
            print(f"  WARN: cannot resolve {address}: {e}", file=sys.stderr)
            return address


def fetch_nodes():
    """Fetch nodes from Remnawave API."""
    req = urllib.request.Request(
        f"{API_URL}/api/nodes",
        headers={"Authorization": f"Bearer {API_TOKEN}"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
    return data["response"]


def find_matching_sni(ip, server_names):
    """Find the SNI domain that resolves to the node's IP.

    For Reality with dest=self-hosted (e.g. port 9443), the SNI must be
    a domain pointing to this node's IP. If no match found, fall back
    to first serverName.
    """
    for sni in server_names:
        try:
            resolved = socket.getaddrinfo(sni, None)[0][4][0]
            if resolved == ip:
                return sni
        except Exception:
            continue
    # Fallback to first
    return server_names[0] if server_names else ""


def build_vless_uri(ip, port, inbound, node_name):
    """Build a vless:// URI from node inbound config."""
    raw = inbound.get("rawInbound", {})
    ss = raw.get("streamSettings", {})
    security = ss.get("security", "none")
    network = ss.get("network", "tcp")

    params = {
        "type": "tcp" if network == "raw" else network,
        "security": security,
        "flow": "xtls-rprx-vision" if security == "reality" else "",
    }

    if security == "reality":
        rs = ss.get("realitySettings", {})
        server_names = rs.get("serverNames", [])
        dest = str(rs.get("dest", "") or rs.get("target", "") or "")

        # If dest is self-hosted (just a port like "9443"), find SNI matching node IP
        if dest.isdigit() or dest.startswith("localhost"):
            sni = find_matching_sni(ip, server_names)
            if sni and sni != server_names[0]:
                print(f"  SNI for {node_name}: {sni} (matched by IP {ip})", file=sys.stderr)
        else:
            # dest is external (e.g. "vk.ru:443") — use first serverName
            sni = server_names[0] if server_names else ""

        params["sni"] = sni
        pbk = rs.get("publicKey") or ""
        if not pbk and rs.get("privateKey"):
            pbk = derive_public_key(rs["privateKey"]) or ""
            if pbk:
                print(f"  Derived pbk for {node_name} from privateKey", file=sys.stderr)
        params["pbk"] = pbk
        params["sid"] = rs.get("shortIds", [""])[0] if rs.get("shortIds") else ""
        params["fp"] = rs.get("fingerprint", "") or "chrome"
        params["spx"] = rs.get("spiderX", "") or "/"

    if network == "xhttp":
        params["security"] = "none"
        params["mode"] = "auto"

    # Remove empty params
    params = {k: v for k, v in params.items() if v}

    fragment = urllib.parse.quote(node_name)
    query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    return f"vless://{VLESS_UUID}@{ip}:{port}?{query}#{fragment}"


def build_ss_uri(ip, port, inbound, node_name):
    """Build an ss:// URI from node inbound config."""
    import base64

    raw = inbound.get("rawInbound", {})
    settings = raw.get("settings", {})
    method = settings.get("method", "chacha20-ietf-poly1305")

    userinfo = base64.urlsafe_b64encode(
        f"{method}:{SS_PASSWORD}".encode()
    ).decode().rstrip("=")

    fragment = urllib.parse.quote(node_name)
    return f"ss://{userinfo}@{ip}:{port}#{fragment}"


def generate_targets(nodes):
    """Generate whitebox-targets.yml entries."""
    entries = []

    for node in nodes:
        name = node["name"]
        address = node["address"]
        inbounds = node.get("configProfile", {}).get("activeInbounds", [])

        if not inbounds:
            print(f"  SKIP {name}: no inbounds", file=sys.stderr)
            continue

        ib = inbounds[0]
        proto = ib["type"]
        port = ib["port"]
        ip = resolve_to_ip(address)

        if node.get("isDisabled"):
            print(f"  SKIP {name}: disabled", file=sys.stderr)
            continue

        if proto == "vless":
            if not VLESS_UUID:
                print(f"  SKIP {name}: VLESS_UUID not set", file=sys.stderr)
                continue
            ctx = build_vless_uri(ip, port, ib, name)
        elif proto == "shadowsocks":
            if not SS_PASSWORD:
                print(f"  SKIP {name}: SS_PASSWORD not set", file=sys.stderr)
                continue
            ctx = build_ss_uri(ip, port, ib, name)
        else:
            print(f"  SKIP {name}: unsupported protocol {proto}", file=sys.stderr)
            continue

        entries.append({
            "target": PROBE_TARGET,
            "ctx": ctx,
            "client": name,
            "protocol": proto,
            "address": ip,
        })

    return entries


def write_yaml(entries, output_path):
    """Write Prometheus file_sd_configs YAML (no pyyaml dependency)."""
    lines = []
    for e in entries:
        lines.append(f'- targets: ["{e["target"]}"]')
        lines.append(f'  labels:')
        lines.append(f'    ctx: "{e["ctx"]}"')
        lines.append(f'    client: "{e["client"]}"')
        lines.append(f'    protocol: "{e["protocol"]}"')
        lines.append(f'    address: "{e["address"]}"')

    content = "\n".join(lines) + "\n"

    if output_path == "-":
        print(content)
    else:
        with open(output_path, "w") as f:
            f.write(content)
        print(f"Written {len(entries)} targets to {output_path}")


def main():
    output = OUTPUT
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        output = sys.argv[idx + 1]
    if "--dry-run" in sys.argv:
        output = "-"

    if not API_TOKEN:
        print("ERROR: REMNAWAVE_API_TOKEN is required", file=sys.stderr)
        sys.exit(1)

    print(f"Fetching nodes from {API_URL}...")
    nodes = fetch_nodes()
    print(f"Found {len(nodes)} nodes")

    entries = generate_targets(nodes)
    print(f"Generated {len(entries)} whitebox targets")

    write_yaml(entries, output)


if __name__ == "__main__":
    main()
