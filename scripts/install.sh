#!/usr/bin/env bash
# ===========================================================================
#  install.sh — sets up the L7 edge on a Debian/Ubuntu VPS
#
#  Assumes:
#    - you are root
#    - DNS for your domain already points at this server
#    - ports 80/443 are free
#
#  Installs: envoy (contrib), coraza wasm plugin, the origin app, systemd units
# ===========================================================================
set -euo pipefail

DOMAIN="${DOMAIN:?set DOMAIN=your.domain.com}"
USER_NAME="${USER_NAME:-l7edge}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { echo -e "\033[1;36m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m!!\033[0m $*"; }
die()  { echo -e "\033[1;31mxx\033[0m $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
log "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  curl ca-certificates gnupg lsb-release \
  python3 python3-venv \
  ufw

# ---------------------------------------------------------------------------
log "Installing Envoy (contrib build — required for WASM/V8 and JA4)"
ENVOY_VER="${ENVOY_VER:-1.35.0}"

# Always use the contrib binary — standard envoy lacks V8 WASM runtime
# and JA4 fingerprinting support that this stack requires.
curl -fsSL -o /usr/local/bin/envoy \
  "https://github.com/envoyproxy/envoy/releases/download/v${ENVOY_VER}/envoy-contrib-${ENVOY_VER}-linux-x86_64" \
  || die "failed to download Envoy contrib ${ENVOY_VER}"
chmod +x /usr/local/bin/envoy

ENVOY_BIN="/usr/local/bin/envoy"
"$ENVOY_BIN" --version || die "envoy failed to install"

# ---------------------------------------------------------------------------
log "Installing Coraza WASM plugin"
CORAZA_VER="${CORAZA_VER:-0.6.0}"
mkdir -p /usr/local/lib
rm -f /tmp/coraza.zip
curl -fsSL -o /tmp/coraza.zip \
  "https://github.com/corazawaf/coraza-proxy-wasm/releases/download/${CORAZA_VER}/coraza-proxy-wasm-${CORAZA_VER}.zip" \
  || warn "could not fetch coraza wasm automatically - see README for manual step"

if [ -f /tmp/coraza.zip ]; then
  rm -rf /tmp/coraza-extract
  python3 -c "import zipfile; zipfile.ZipFile('/tmp/coraza.zip').extractall('/tmp/coraza-extract')"
  cp /tmp/coraza-extract/coraza-proxy-wasm.wasm /usr/local/lib/coraza-proxy-wasm.wasm
  rm -rf /tmp/coraza.zip /tmp/coraza-extract
  log "Coraza WASM plugin installed"
else
  warn "Coraza WASM plugin not installed — WAF filter will fail to load"
fi

# ---------------------------------------------------------------------------
log "Installing config"
mkdir -p /etc/envoy/lua /var/log/envoy /var/lib/l7ddos
cp "$SRC_DIR/envoy/envoy.yaml"          /etc/envoy/envoy.yaml
cp "$SRC_DIR/envoy/lua/edge_guard.lua"  /etc/envoy/lua/edge_guard.lua

# ---------------------------------------------------------------------------
log "Installing origin app"
id -u "$USER_NAME" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$USER_NAME"
cp "$SRC_DIR/origin/origin.py"      /var/lib/l7ddos/origin.py
cp -r "$SRC_DIR/origin/site"        /var/lib/l7ddos/site
chown -R "$USER_NAME":"$USER_NAME" /var/lib/l7ddos

# ---------------------------------------------------------------------------
log "Writing systemd units"

cat > /etc/systemd/system/l7ddos-origin.service <<EOF
[Unit]
Description=L7 protection POC - origin app
After=network.target

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=/var/lib/l7ddos
Environment=ORIGIN_PORT=8080
ExecStart=/usr/bin/python3 /var/lib/l7ddos/origin.py
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/l7ddos

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/l7ddos-envoy.service <<EOF
[Unit]
Description=Envoy L7 edge
After=network.target l7ddos-origin.service
Wants=l7ddos-origin.service

[Service]
Type=simple
User=root
ExecStart=${ENVOY_BIN} -c /etc/envoy/envoy.yaml --log-level warn
Restart=always
RestartSec=2
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now l7ddos-origin.service
systemctl enable --now l7ddos-envoy.service

# ---------------------------------------------------------------------------
log "Configuring firewall (origin must not be publicly reachable)"
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
log "ufw configured: only 22/80/443 open"

# ---------------------------------------------------------------------------
log "Capping journal size"
# The Envoy access log is extremely chatty under attack. Without a cap the
# journal grows without bound, which makes anything that reads it (stats
# scrapers, log tailers) progressively slower.
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/limit.conf <<EOF
[Journal]
SystemMaxUse=500M
MaxRetentionSec=1week
EOF
systemctl restart systemd-journald
log "journal capped at 500M / 1 week retention"

# ---------------------------------------------------------------------------
log "Waiting for Envoy to come up"
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:9901/ready" >/dev/null 2>&1; then
    log "Envoy is ready"
    break
  fi
  sleep 1
done

# ---------------------------------------------------------------------------
log "Installing dashboard"
bash "$SRC_DIR/dashboard/install-dashboard.sh"

echo
log "Done. Next steps:"
echo "  1. Get a TLS cert:  DOMAIN=$DOMAIN ./scripts/get-cert.sh"
echo "  2. Set dashboard password (if not already):"
echo "     sudo cp /etc/l7dashboard.env.example /etc/l7dashboard.env"
echo "     sudo nano /etc/l7dashboard.env && sudo systemctl restart l7dashboard"
echo "  3. Verify:          DOMAIN=$DOMAIN ./scripts/test.sh"
echo "  4. Read the guide:  cat README.md"
