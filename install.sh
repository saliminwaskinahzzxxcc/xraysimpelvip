#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="Xray Simpel VIP"
APP_HOME="/opt/xraysimpelvip"
PANEL_PORT="1313"
WEB_ROOT="/var/www/xraysimpelvip"
NGINX_SITE="/etc/nginx/sites-available/xraysimpelvip.conf"
NGINX_LINK="/etc/nginx/sites-enabled/xraysimpelvip.conf"
SELF_CERT_DIR="/etc/ssl/xraysimpelvip"

info(){ printf '\033[1;36m[INFO]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
fail(){ printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

require_root(){
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Run as root: sudo bash install.sh"
  fi
}

valid_domain(){
  [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$ ]]
}

prompt_inputs(){
  echo "============================================================"
  echo " ${APP_NAME} installer for fresh Ubuntu 22.04 VPS"
  echo "============================================================"
  echo
  read -rp "Cloudflare domain/subdomain already pointed to this VPS: " DOMAIN
  DOMAIN="$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]' | xargs)"
  valid_domain "$DOMAIN" || fail "Invalid domain: $DOMAIN"

  read -rp "Email for Let's Encrypt certificate notices: " LE_EMAIL
  LE_EMAIL="$(echo "$LE_EMAIL" | xargs)"
  [[ "$LE_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || fail "Invalid email address"

  read -rp "Panel admin username [admin]: " ADMIN_USER
  ADMIN_USER="${ADMIN_USER:-admin}"
  [[ "$ADMIN_USER" =~ ^[A-Za-z0-9_-]{3,32}$ ]] || fail "Admin username must be 3-32 characters"

  while true; do
    read -rsp "Panel admin password: " ADMIN_PASS; echo
    read -rsp "Repeat admin password: " ADMIN_PASS2; echo
    [[ -n "$ADMIN_PASS" ]] || { warn "Password cannot be empty"; continue; }
    [[ "$ADMIN_PASS" == "$ADMIN_PASS2" ]] || { warn "Passwords do not match"; continue; }
    break
  done
}

install_packages(){
  info "Installing OS packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y curl wget unzip jq nginx python3 ca-certificates openssl certbot uuid-runtime
}

install_xray(){
  if command -v xray >/dev/null 2>&1 || [[ -x /usr/local/bin/xray ]]; then
    info "Xray already exists; keeping installed binary"
  else
    info "Installing Xray-core with the official XTLS installer"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  fi
  mkdir -p /usr/local/etc/xray /var/log/xray
  chmod 755 /var/log/xray
}

copy_app(){
  info "Copying panel files to ${APP_HOME}"
  mkdir -p "$APP_HOME"
  cp "$(dirname "$0")/app.py" "$APP_HOME/app.py"
  chmod 700 "$APP_HOME"
  chmod 700 "$APP_HOME/app.py"
}

write_landing(){
  mkdir -p "$WEB_ROOT"
  cat > "$WEB_ROOT/index.html" <<HTML
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${APP_NAME}</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f172a;color:#e5f3ff;font-family:system-ui,sans-serif}.box{max-width:560px;padding:34px;border:1px solid rgba(255,255,255,.12);border-radius:28px;background:rgba(255,255,255,.06);box-shadow:0 20px 80px rgba(0,0,0,.32)}h1{margin:0 0 8px;font-size:1.7rem}p{color:#9fb1c9;line-height:1.6}</style></head><body><div class="box"><h1>${APP_NAME}</h1><p>This domain is active. WebSocket proxy paths are ready for VMess, VLESS, and Trojan accounts.</p></div></body></html>
HTML
}

write_temp_nginx(){
  info "Writing temporary Nginx config for certificate challenge"
  rm -f /etc/nginx/sites-enabled/default
  cat > "$NGINX_SITE" <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    root ${WEB_ROOT};

    location /.well-known/acme-challenge/ {
        root ${WEB_ROOT};
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
NGINX
  ln -sf "$NGINX_SITE" "$NGINX_LINK"
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx || systemctl restart nginx
}

obtain_certificate(){
  CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
  KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
  if [[ -s "$CERT_PATH" && -s "$KEY_PATH" ]]; then
    info "Existing Let's Encrypt certificate found"
    return
  fi

  info "Requesting Let's Encrypt certificate for ${DOMAIN}"
  if certbot certonly --webroot -w "$WEB_ROOT" -d "$DOMAIN" --agree-tos -m "$LE_EMAIL" --non-interactive --keep-until-expiring; then
    info "Let's Encrypt certificate installed"
  else
    warn "Let's Encrypt failed. Creating self-signed fallback certificate."
    warn "Use Cloudflare SSL/TLS mode 'Full' with this fallback, or fix DNS and rerun the installer for Full (strict)."
    mkdir -p "$SELF_CERT_DIR"
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -keyout "$SELF_CERT_DIR/${DOMAIN}.key" \
      -out "$SELF_CERT_DIR/${DOMAIN}.crt" \
      -subj "/CN=${DOMAIN}" >/dev/null 2>&1
    CERT_PATH="$SELF_CERT_DIR/${DOMAIN}.crt"
    KEY_PATH="$SELF_CERT_DIR/${DOMAIN}.key"
  fi
}

write_final_nginx(){
  info "Writing final Nginx reverse proxy for WebSocket on ports 80 and 443"
  cat > "$NGINX_SITE" <<NGINX
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    '' close;
}

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    root ${WEB_ROOT};

    location /.well-known/acme-challenge/ {
        root ${WEB_ROOT};
    }

    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 300s;
    }

    location /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 300s;
    }

    location /trojan {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 300s;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};
    root ${WEB_ROOT};

    ssl_certificate ${CERT_PATH};
    ssl_certificate_key ${KEY_PATH};
    ssl_session_timeout 1d;
    ssl_session_cache shared:XRAYSSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;

    location /vmess {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 300s;
    }

    location /vless {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 300s;
    }

    location /trojan {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 300s;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
NGINX
  nginx -t
  systemctl reload nginx || systemctl restart nginx
}

init_panel(){
  info "Initializing panel database and Xray config"
  XRAY_SIMPLE_HOME="$APP_HOME" python3 "$APP_HOME/app.py" init --domain "$DOMAIN" --admin-user "$ADMIN_USER" --admin-pass "$ADMIN_PASS"
  chmod 600 "$APP_HOME/panel.db"* 2>/dev/null || true
}

write_services(){
  info "Writing systemd services"
  cat > /etc/systemd/system/xraysimpelvip-panel.service <<SERVICE
[Unit]
Description=Xray Simpel VIP web panel
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_HOME}
Environment=XRAY_SIMPLE_HOME=${APP_HOME}
ExecStart=/usr/bin/python3 ${APP_HOME}/app.py web --host 0.0.0.0 --port ${PANEL_PORT}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

  cat > /etc/systemd/system/xraysimpelvip-watcher.service <<SERVICE
[Unit]
Description=Xray Simpel VIP quota and traffic watcher
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_HOME}
Environment=XRAY_SIMPLE_HOME=${APP_HOME}
ExecStart=/usr/bin/python3 ${APP_HOME}/app.py watcher --interval 60
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

  systemctl daemon-reload
  systemctl enable --now xray
  systemctl restart xray
  systemctl enable --now xraysimpelvip-panel xraysimpelvip-watcher
}

open_firewall_if_needed(){
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -qi "Status: active"; then
    info "Opening UFW ports 80, 443, and ${PANEL_PORT}"
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow "${PANEL_PORT}/tcp"
  fi
}

print_done(){
  IPV4="$(curl -4 -fsS https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
  cat <<DONE

============================================================
 ${APP_NAME} installed
============================================================
Panel URL:      http://${IPV4}:${PANEL_PORT}
Admin user:     ${ADMIN_USER}
Domain:         ${DOMAIN}
Client ports:   443 TLS WebSocket and 80 plain WebSocket
WS paths:       /vmess  /vless  /trojan

Cloudflare checklist:
  1. DNS A record ${DOMAIN} -> ${IPV4}
  2. Proxy status can be orange-cloud enabled.
  3. SSL/TLS mode: Full (strict) if Let's Encrypt succeeded, Full if fallback cert was used.
  4. Network -> WebSockets: enabled.

Useful commands:
  systemctl status xray xraysimpelvip-panel xraysimpelvip-watcher --no-pager
  journalctl -u xraysimpelvip-panel -f
  python3 ${APP_HOME}/app.py sync
DONE
}

main(){
  require_root
  prompt_inputs
  install_packages
  install_xray
  copy_app
  write_landing
  write_temp_nginx
  obtain_certificate
  write_final_nginx
  init_panel
  write_services
  open_firewall_if_needed
  print_done
}

main "$@"
