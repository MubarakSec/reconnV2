#!/usr/bin/env bash
set -euo pipefail

# noVNC setup for VPS (Xfce + VNC + noVNC)
# Usage:
#   sudo bash novnc.sh install
#   sudo bash novnc.sh start
#   sudo bash novnc.sh stop
#   sudo bash novnc.sh status

MODE="${1:-}"

install_novnc() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y xfce4 xfce4-goodies tightvncserver novnc websockify dbus-x11

  # Create default VNC startup
  mkdir -p /root/.vnc
  cat > /root/.vnc/xstartup <<'EOF'
#!/bin/sh
xrdb $HOME/.Xresources
startxfce4 &
EOF
  chmod +x /root/.vnc/xstartup

  echo "✅ Installed. Set VNC password now: vncserver"
}

start_novnc() {
  # Start VNC on :1 (port 5901)
  vncserver :1 -geometry 1280x720 -depth 24
  # Start noVNC on 6080
  nohup /usr/share/novnc/utils/novnc_proxy --vnc localhost:5901 --listen 6080 >/var/log/novnc.log 2>&1 &
  echo "✅ noVNC running: http://<VPS-IP>:6080/vnc.html"
}

stop_novnc() {
  vncserver -kill :1 || true
  pkill -f novnc_proxy || true
  echo "✅ noVNC stopped"
}

status_novnc() {
  pgrep -af novnc_proxy || echo "noVNC not running"
  vncserver -list || true
}

case "$MODE" in
  install)
    install_novnc
    ;;
  start)
    start_novnc
    ;;
  stop)
    stop_novnc
    ;;
  status)
    status_novnc
    ;;
  *)
    echo "Usage: sudo bash novnc.sh install|start|stop|status"
    exit 1
    ;;
esac
