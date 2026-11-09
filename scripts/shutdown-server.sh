#!/usr/bin/env bash
# ===========================================================================
#  shutdown-server.sh — take a server out of service.
#
#  Stops the L7 stack and disables it so it stays down across reboots.
#  The files are deliberately LEFT IN PLACE — flipping back on is then just
#  `systemctl start l7ddos-envoy l7ddos-origin l7dashboard`.
#
#  Run this on the OLD server once the new one is confirmed working.
#
#  Usage:
#    sudo ./scripts/shutdown-server.sh          # stop + disable
#    sudo ./scripts/shutdown-server.sh --purge  # stop + disable + remove
# ===========================================================================
set -euo pipefail

PURGE=false
[ "${1:-}" = "--purge" ] && PURGE=true

log()  { echo -e "\033[1;36m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m!!\033[0m $*" >&2; }
die()  { echo -e "\033[1;31mxx\033[0m $*" >&2; exit 1; }

[ "$EUID" -eq 0 ] || die "must run as root (use sudo)"

SERVICES="l7ddos-envoy l7ddos-origin l7dashboard"

# ---------------------------------------------------------------------------
log "Stopping services"
for svc in $SERVICES; do
  if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}.service"; then
    systemctl stop "$svc" 2>/dev/null || warn "could not stop $svc"
    systemctl disable "$svc" 2>/dev/null || warn "could not disable $svc"
    echo -e "  \033[1;32m✓\033[0m $svc stopped and disabled"
  fi
done

# ---------------------------------------------------------------------------
log "Closing the firewall to web traffic"
if command -v ufw >/dev/null 2>&1; then
  ufw --force delete allow 80/tcp 2>/dev/null || true
  ufw --force delete allow 443/tcp 2>/dev/null || true
  echo -e "  \033[1;32m✓\033[0m port 80/443 rules removed (SSH still open)"
  echo "  \033[1;33m!!\033[0m verify you can still SSH in before closing this window"
fi

# ---------------------------------------------------------------------------
if [ "$PURGE" = true ]; then
  log "Purging configs and data"
  rm -f /etc/systemd/system/l7ddos-envoy.service \
        /etc/systemd/system/l7ddos-origin.service \
        /etc/systemd/system/l7dashboard.service
  systemctl daemon-reload
  rm -rf /opt/l7dashboard
  echo -e "  \033[1;32m✓\033[0m units and /opt/l7dashboard removed"
  warn "the cert in /etc/letsencrypt was kept — delete it manually if unwanted"
  warn "  sudo rm -rf /etc/letsencrypt/live /etc/letsencrypt/renewal"
fi

echo
log "Server is out of service."
echo
echo "  To bring it back:"
echo "    sudo systemctl start l7ddos-envoy l7ddos-origin l7dashboard"
echo "    sudo systemctl enable l7ddos-envoy l7ddos-origin l7dashboard"
if command -v ufw >/dev/null 2>&1; then
  echo "    sudo ufw allow 80/tcp && sudo ufw allow 443/tcp"
fi
echo
echo "  Or just wipe the box and redeploy later — it's stateless."
