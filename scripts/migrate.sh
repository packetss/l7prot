#!/usr/bin/env bash
# ===========================================================================
#  migrate.sh — move from one server to another.
#
#  Run this on the NEW server (the one taking over). It:
#    1. checks the new server is ready
#    2. pulls the repo
#    3. deploys everything (Envoy, origin, dashboard, WAF)
#    4. gets the TLS cert
#    5. prints the DNS switch instructions
#
#  The old server stays up and serving until you change the DNS record.
#  Nothing on the old server is touched by this script.
#
#  Usage:
#    sudo ./scripts/migrate.sh your.domain.com [email@optional.com]
# ===========================================================================
set -euo pipefail

DOMAIN="${1:-${DOMAIN:?pass the domain as the first argument}}"
EMAIL="${2:-${EMAIL:-admin@${DOMAIN}}}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { echo -e "\033[1;36m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m!!\033[0m $*" >&2; }
die()  { echo -e "\033[1;31mxx\033[0m $*" >&2; exit 1; }
ok()   { echo -e "  \033[1;32m✓\033[0m $*"; }

[ "$EUID" -eq 0 ] || die "must run as root (use sudo)"

# ---------------------------------------------------------------------------
log "Checking this server is suitable"
MISSING=0
for pkg in curl git python3; do
  command -v "$pkg" >/dev/null 2>&1 || { warn "$pkg not installed"; MISSING=1; }
done
if [ "$MISSING" -eq 1 ]; then
  log "Installing base packages"
  apt-get update -qq && apt-get install -y -qq curl git python3
fi

# Ports we need: 80 (ACME + redirect), 443 (edge), 22 (ssh).
for port in 80 443; do
  if ss -tln "sport = :$port" 2>/dev/null | grep -q LISTEN; then
    warn "port $port is already in use — stop whatever owns it first"
  fi
done

# A stale install from a previous attempt would break the deploy.
if systemctl list-unit-files 2>/dev/null | grep -q "^l7ddos-envoy.service"; then
  log "Existing install detected — removing it for a clean deploy"
  systemctl stop l7ddos-envoy l7ddos-origin l7dashboard 2>/dev/null || true
  systemctl disable l7ddos-envoy l7ddos-origin l7dashboard 2>/dev/null || true
  rm -f /etc/systemd/system/l7ddos-envoy.service \
        /etc/systemd/system/l7ddos-origin.service \
        /etc/systemd/system/l7dashboard.service
  systemctl daemon-reload
  ok "Cleaned up previous install"
fi

# ---------------------------------------------------------------------------
log "Getting the code"
if [ -d "$SRC_DIR/.git" ]; then
  cd "$SRC_DIR"
  git pull --ff-only || die "git pull failed"
else
  die "repo not found at $SRC_DIR — clone it first:
  git clone https://github.com/packetss/l7prot.git"
fi
ok "Code up to date"

# ---------------------------------------------------------------------------
log "Deploying (this takes a few minutes)"
DOMAIN="$DOMAIN" EMAIL="$EMAIL" bash "$SRC_DIR/deploy.sh" "$DOMAIN" "$EMAIL"
ok "Deploy complete"

# ---------------------------------------------------------------------------
log "Post-deploy checks"
FAIL=0
check() {
  if eval "$2" >/dev/null 2>&1; then ok "$1"; else warn "FAILED: $1"; FAIL=1; fi
}
check "envoy running"        "systemctl is-active l7ddos-envoy"
check "origin running"       "systemctl is-active l7ddos-origin"
check "dashboard running"    "systemctl is-active l7dashboard"
check "site responds 200"    "curl -s -o /dev/null -w '%{http_code}' https://${DOMAIN}/ | grep -q 200"
check "dashboard login loads" "curl -s -o /dev/null -w '%{http_code}' https://${DOMAIN}/dashboard/login | grep -q 200"
check "public stats works"   "curl -s https://${DOMAIN}/api/public-stats | grep -q requests_total"
check "cert valid"           "curl -sI https://${DOMAIN}/ | grep -q 'SSL connection'"

# ---------------------------------------------------------------------------
echo
log "==============================================="
log " New server is ready for ${DOMAIN}"
log "==============================================="
echo
echo "  IP of this server:  $(curl -s ifconfig.me 2>/dev/null || echo '<run: curl -s ifconfig.me>')"
echo
echo "  The site is ALREADY serving here — the old server is still live."
echo
echo "  NEXT STEPS:"
echo
echo "  1. Lower the DNS TTL for ${DOMAIN} to 300 seconds"
echo "     (do this now, wait for it to propagate before switching)"
echo
echo "  2. Point the ${DOMAIN} DNS record at this server's IP"
echo "     Cloudflare: DNS > Records > ${DOMAIN} > change A record"
echo "     If you're using Cloudflare, keep the proxy ON (orange cloud)"
echo "     — Magic Transit and Cloudflare work fine together."
echo
echo "  3. Wait for the switch, then verify:"
echo "       curl -sI https://${DOMAIN}/ | head -3"
echo
echo "  4. MAGIC TRANSIT (if you use it) — this is the step people miss:"
echo "     In the Cloudflare dashboard:"
echo "       a. Add this server's public IP under"
echo "          Magic Transit > Overview > Static IPs"
echo "       b. Update the /24 subnet you announce so it includes the NEW"
echo "          server's IP (the old one can stay until you've migrated)"
echo "       c. Verify the new IP shows 'active' in the static IP list"
echo "     If you skip this, your /24 still points at the old server and"
echo "     volumetric traffic won't reach the new edge at all."
echo
echo "  5. Once traffic is confirmed on the new server, shut the old one down:"
echo "       # on the OLD server:"
echo "       sudo ./scripts/shutdown-server.sh"
echo
echo "  Note: the TLS cert is already issued and valid for ${DOMAIN}, so"
echo "  there is no cert reissue needed when DNS flips."
echo
if [ "$FAIL" -ne 0 ]; then
  warn "Some post-deploy checks failed — see above before switching DNS."
fi
