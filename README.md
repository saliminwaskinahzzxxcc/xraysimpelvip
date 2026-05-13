# Xray Simpel VIP

A small no-dependency Python web panel for Xray accounts on Ubuntu 22.04.

## Features

- VMess, VLESS, and Trojan over WebSocket
- Cloudflare domain support on ports 443 and 80 through Nginx
- Panel login on `http://SERVER-IP:1313`
- Add, delete, enable, disable, and reset accounts
- Per-account quota and expiry
- Active/idle account display using Xray Stats API
- Autoscript-style panel UI with sidebar menus, dashboard cards, service status, and user table
- Clipboard hotfix for Android Chrome on HTTP panels

## Fresh install

```bash
sudo apt update -y && sudo apt install -y git && rm -rf xraysimpelvip && git clone https://github.com/saliminwaskinahzzxxcc/xraysimpelvip.git && cd xraysimpelvip && sudo bash install.sh
```

The installer asks for:

1. Cloudflare domain/subdomain already pointed to the VPS
2. Email for Let's Encrypt
3. Panel username and password

Open the panel:

```text
http://YOUR-VPS-IP:1313
```

## Update an existing install

After replacing your GitHub repository files with this version, run:

```bash
sudo apt update -y && sudo apt install -y git && rm -rf /tmp/xraysimpelvip && git clone https://github.com/saliminwaskinahzzxxcc/xraysimpelvip.git /tmp/xraysimpelvip && cd /tmp/xraysimpelvip && sudo bash update.sh
```

This keeps your database/accounts, replaces only the panel code, removes the bad `Requires=xray.service` dependency, restarts the panel, and regenerates the Xray config.

## Cloudflare checklist

- DNS A record: your domain/subdomain -> VPS IPv4
- Proxy: orange cloud is supported
- SSL/TLS: Full strict if Let's Encrypt works, Full if fallback self-signed cert is used
- Network -> WebSockets: enabled

## Useful commands

```bash
systemctl status xray xraysimpelvip-panel xraysimpelvip-watcher --no-pager
journalctl -u xraysimpelvip-panel -n 100 --no-pager
journalctl -u xray -n 100 --no-pager
python3 /opt/xraysimpelvip/app.py sync
```

## Notes

Android Chrome may block `navigator.clipboard` on non-HTTPS panel pages. This version includes a fallback copy method and a manual-copy modal, so VMess/VLESS/Trojan links can still be copied from `http://IP:1313`.
