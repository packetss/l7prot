#!/usr/bin/env bash
# ===========================================================================
#  update.sh — pull new code onto a running server and redeploy it
#
#  This is the everyday "I pushed changes, pull them down" script.
#  It is idempotent and safe to run on a live server.
#
#  Usage:
#    sudo ./scripts/update.sh
# ===========================================================================
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { echo -e "\033[1;36m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m!!\033[0m $*"; }
die()  { echo -e "\033[1;31mxx\033[0m $*" >&2; exit 1; }
ok()   { echo -e "  \033[1;32m✓\033[0m $*"; }


# Bake the actual worker count into the Lua filter.
#
# Envoy runs one worker thread per CPU core by default, and the Lua token
# bucket lives in a separate VM per worker. Without this, the "per IP" rate
# limit silently multiplies by the core count (20 rps/worker = 80 rps on a
# 4-core box). The Lua file divides its global target by ENV_WORKERS so the
# limit means the same thing everywhere.
patch_envoy_workers() {
  local lua_file="$1"
  local workers
  workers=$(nproc 2>/dev/null || echo 1)
  case "$workers" in ''|*[!0-9]*) workers=1 ;; esac
  [ "$workers" -lt 1 ] && workers=1
  sed -i "s/^local ENV_WORKERS .*/local ENV_WORKERS       = ${workers}   -- patched by deploy.sh (nproc)/" "$lua_file"
  echo "  envoy workers: ${workers} (per-IP rate limit scaled accordingly)"
}

[ "$EUID" -eq 0 ] || die "must run as root (use sudo)"

# ---------------------------------------------------------------------------
log "Pulling latest code"
cd "$SRC_DIR"
git pull --ff-only || die "git pull failed — resolve conflicts manually"

# ---------------------------------------------------------------------------
log "Deploying origin app"
if [ -f /var/lib/l7ddos/origin.py ]; then
  cp "$SRC_DIR/origin/origin.py" /var/lib/l7ddos/origin.py
  mkdir -p /var/lib/l7ddos/site
  cp "$SRC_DIR/origin/site/index.html" /var/lib/l7ddos/site/index.html
  chown -R l7edge:l7edge /var/lib/l7ddos 2>/dev/null || true
  systemctl restart l7ddos-origin.service
  ok "Origin updated"
else
  warn "/var/lib/l7ddos not found — skipping origin (not installed?)"
fi

# ---------------------------------------------------------------------------
log "Deploying Envoy config"
if [ -f /etc/envoy/envoy.yaml ]; then
  # The repo copy ships with a placeholder domain for the TLS cert paths.
  # Copy the new config (so route/filter changes actually deploy), then
  # restore the cert paths from the live config so we don't clobber a
  # certificate that was issued for a different domain.
  CERT_LIVE=$(grep -oP 'certificate_chain: \{ filename: \K[^}]+' /etc/envoy/envoy.yaml | head -1)
  KEY_LIVE=$(grep -oP 'private_key: \{ filename: \K[^}]+' /etc/envoy/envoy.yaml | head -1)

  cp "$SRC_DIR/envoy/envoy.yaml" /etc/envoy/envoy.yaml

  if [ -n "$CERT_LIVE" ] && [ -n "$KEY_LIVE" ]; then
    python3 - "$CERT_LIVE" "$KEY_LIVE" <<'PYEOF'
import sys, pathlib, re
cert, key = sys.argv[1], sys.argv[2]
p = pathlib.Path("/etc/envoy/envoy.yaml")
t = p.read_text()
t = re.sub(r'certificate_chain: \{ filename: [^}]+\}',
           f'certificate_chain: {{ filename: {cert} }}', t)
t = re.sub(r'private_key: \{ filename: [^}]+\}',
           f'private_key: {{ filename: {key} }}', t)
p.write_text(t)
print(f"  restored cert paths: {cert}")
PYEOF
  else
    warn "Could not detect live cert paths — check /etc/envoy/envoy.yaml manually"
  fi

  cp "$SRC_DIR/envoy/lua/edge_guard.lua" /etc/envoy/lua/edge_guard.lua
  patch_envoy_workers /etc/envoy/lua/edge_guard.lua

  # Ensure the systemd unit carries a memory limit. Older installs predate
  # this, and without it the kernel OOM killer picks Envoy as the victim.
  if [ -f /etc/systemd/system/l7ddos-envoy.service ] \
     && ! grep -q '^MemoryMax=' /etc/systemd/system/l7ddos-envoy.service; then
    log "Adding MemoryMax to the Envoy unit"
    python3 - <<'PYEOF'
import pathlib
p = pathlib.Path("/etc/systemd/system/l7ddos-envoy.service")
t = p.read_text()
block = """# Bound Envoy's memory. Without a hard limit the kernel OOM killer picks
# the victim, which was Envoy (observed: status=9/KILL), taking the whole
# edge down. With MemoryMax set, systemd kills Envoy at a known threshold
# and restarts it cleanly instead.
MemoryMax=768M
MemoryHigh=600M
"""
if "LimitNOFILE=" in t:
    t = t.replace("LimitNOFILE=65536\n", "LimitNOFILE=65536\n" + block, 1)
else:
    t = t.replace("[Service]\n", "[Service]\n" + block, 1)
p.write_text(t)
print("  unit updated")
PYEOF
    systemctl daemon-reload
  fi

  if /usr/local/bin/envoy --mode validate -c /etc/envoy/envoy.yaml 2>/tmp/envoy_validate.log; then
    systemctl restart l7ddos-envoy.service
    ok "Envoy updated and restarted"
  else
    die "Envoy config invalid — not restarting. See /tmp/envoy_validate.log"
  fi
else
  warn "/etc/envoy/envoy.yaml not found — skipping Envoy"
fi

# ---------------------------------------------------------------------------
log "Deploying dashboard"
if systemctl list-unit-files | grep -q "^l7dashboard.service"; then
  bash "$SRC_DIR/dashboard/install-dashboard.sh"
  ok "Dashboard updated"
else
  warn "l7dashboard not installed — skipping"
fi

# ---------------------------------------------------------------------------
log "Applying L4 hardening"
if [ -f "$SRC_DIR/scripts/harden.sh" ]; then
  bash "$SRC_DIR/scripts/harden.sh" apply
  ok "L4 hardening applied (nftables + sysctl + connlimit)"
else
  warn "harden.sh not found — skipping L4 hardening"
fi

# ---------------------------------------------------------------------------
log "Verifying services"
for svc in l7ddos-origin l7ddos-envoy l7dashboard l7ddos-harden; do
  if systemctl is-active "$svc" >/dev/null 2>&1; then
    ok "$svc active"
  elif systemctl list-unit-files | grep -q "^${svc}.service"; then
    warn "$svc is NOT active — check: journalctl -u $svc -n 50"
  fi
done

echo
log "Update complete"
