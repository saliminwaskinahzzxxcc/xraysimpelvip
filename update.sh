#!/usr/bin/env bash
set -Eeuo pipefail
APP_HOME="/opt/xraysimpelvip"
PANEL_SERVICE="xraysimpelvip-panel.service"
WATCHER_SERVICE="xraysimpelvip-watcher.service"
info(){ printf '\033[1;32m[FIX]\033[0m %s\n' "$*"; }
fail(){ printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || fail "Run with sudo: sudo bash update.sh"
[[ -f "$(dirname "$0")/app.py" ]] || fail "app.py not found beside update.sh"
[[ -d "$APP_HOME" ]] || fail "$APP_HOME not found. Install first with install.sh"
info "Backing up current panel"
cp -a "$APP_HOME/app.py" "$APP_HOME/app.py.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
info "Installing autoscript-style v4 UI, sidebar menus, service status, user table, and clipboard fixes"
cp "$(dirname "$0")/app.py" "$APP_HOME/app.py"
chmod 700 "$APP_HOME/app.py"
python3 -m py_compile "$APP_HOME/app.py"
info "Fixing systemd dependency that killed the panel during Xray restart"
for svc in /etc/systemd/system/$PANEL_SERVICE /etc/systemd/system/$WATCHER_SERVICE; do
  [[ -f "$svc" ]] && sed -i '/Requires=xray.service/d' "$svc"
done
systemctl daemon-reload
info "Regenerating Xray config and restarting services"
XRAY_SIMPLE_HOME="$APP_HOME" python3 "$APP_HOME/app.py" regen || true
systemctl restart xraysimpelvip-panel xraysimpelvip-watcher
systemctl restart xray || true
sleep 1
systemctl --no-pager --full status xraysimpelvip-panel xray | sed -n '1,80p' || true
info "Done. Open http://YOUR-VPS-IP:1313 and hard refresh Chrome. The v4 UI has Dashboard, Status Service, Info Port, Vmess, Vless, Trojan, and Daftar User menus."
