#!/usr/bin/env bash
set -euo pipefail

# Lightweight GUI setup for VPS (Xfce + Xrdp)
# Usage:
#   sudo bash gui.sh install
#   sudo bash gui.sh start
#   sudo bash gui.sh stop
#   sudo bash gui.sh status

MODE="${1:-}"

install_gui() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y xfce4 xfce4-goodies xrdp dbus-x11
  systemctl enable xrdp
  systemctl restart xrdp

  # Configure Xfce for RDP sessions
  echo "startxfce4" > /etc/xrdp/startwm.sh
  chmod +x /etc/xrdp/startwm.sh

  echo "
✅ GUI installed.
RDP: use your VPS IP on port 3389.
Login with your VPS user.
"
}

start_gui() {
  systemctl start xrdp
  systemctl status xrdp --no-pager
}

stop_gui() {
  systemctl stop xrdp
  systemctl status xrdp --no-pager
}

status_gui() {
  systemctl status xrdp --no-pager
}

case "$MODE" in
  install)
    install_gui
    ;;
  start)
    start_gui
    ;;
  stop)
    stop_gui
    ;;
  status)
    status_gui
    ;;
  *)
    echo "Usage: sudo bash gui.sh install|start|stop|status"
    exit 1
    ;;
esac
