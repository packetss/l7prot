#!/usr/bin/env bash
# ===========================================================================
#  deploy.sh — full automated deployment for L7 DDoS protection
#
#  Usage:
#    sudo ./deploy.sh your.domain.com [email@optional.com]
#
#  This script:
#    1. Installs all packages and Envoy
#    2. Sets up the origin app and configs
#    3. Gets a Let's Encrypt certificate
#    4. Runs all verification tests
#    5. You're done — your site is live
# ===========================================================================
set -euo pipefail

DOMAIN="${1:?Usage: sudo $0 your.domain.com [email]}"
EMAIL="${2:-admin@${DOMAIN}}"
USER_NAME="l7edge"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { echo -e "\033[1;36m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m!!\033[0m $*"; }
die()  { echo -e "\033[1;31mxx\033[0m $*" >&2; exit 1; }
ok()   { echo -e "  \033[1;32m✓\033[0m $*"; }

# Verify root
[ "$EUID" -eq 0 ] || die "This script must be run as root (use sudo)"

# ===========================================================================
log "Step 1/8: Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  curl ca-certificates gnupg lsb-release \
  python3 python3-venv \
  certbot \
  ufw

# ===========================================================================
log "Step 2/8: Installing Envoy (contrib) and Coraza WAF"
ENVOY_VER="${ENVOY_VER:-1.35.0}"
CORAZA_VER="${CORAZA_VER:-0.6.0}"

curl -fsSL -o /usr/local/bin/envoy \
  "https://github.com/envoyproxy/envoy/releases/download/v${ENVOY_VER}/envoy-contrib-${ENVOY_VER}-linux-x86_64" \
  || die "failed to download Envoy contrib ${ENVOY_VER}"
chmod +x /usr/local/bin/envoy
/usr/local/bin/envoy --version || die "envoy failed to install"
ok "Envoy installed"

mkdir -p /usr/local/lib
rm -f /tmp/coraza.zip
curl -fsSL -o /tmp/coraza.zip \
  "https://github.com/corazawaf/coraza-proxy-wasm/releases/download/${CORAZA_VER}/coraza-proxy-wasm-${CORAZA_VER}.zip" \
  || warn "could not fetch coraza wasm automatically"

if [ -f /tmp/coraza.zip ]; then
  python3 -c "import zipfile; zipfile.ZipFile('/tmp/coraza.zip').extractall('/tmp/coraza-extract')"
  cp /tmp/coraza-extract/coraza-proxy-wasm.wasm /usr/local/lib/coraza-proxy-wasm.wasm
  rm -rf /tmp/coraza.zip /tmp/coraza-extract
  ok "Coraza WASM installed"
else
  warn "Coraza WASM not installed — WAF may not work"
fi

# ===========================================================================
log "Step 3/8: Installing configs and origin app"

mkdir -p /etc/envoy/lua /etc/envoy/coraza /var/log/envoy /var/lib/l7ddos
cp "$SRC_DIR/envoy/envoy.yaml"          /etc/envoy/envoy.yaml
cp "$SRC_DIR/envoy/lua/edge_guard.lua"  /etc/envoy/lua/edge_guard.lua
cp "$SRC_DIR/envoy/coraza/rules.conf"   /etc/envoy/coraza/rules.conf
cp "$SRC_DIR/envoy/coraza/directives.conf" /etc/envoy/coraza/directives.conf
ok "Envoy config installed"

id -u "$USER_NAME" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$USER_NAME"
cp "$SRC_DIR/origin/origin.py"      /var/lib/l7ddos/origin.py
cp -r "$SRC_DIR/origin/site"        /var/lib/l7ddos/site
chown -R "$USER_NAME":"$USER_NAME" /var/lib/l7ddos
ok "Origin app installed"

# ===========================================================================
log "Step 4/8: Setting up systemd services"

cat > /etc/systemd/system/l7ddos-origin.service <<'EOF'
[Unit]
Description=L7 protection POC - origin app
After=network.target

[Service]
Type=simple
User=l7edge
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
ExecStart=/usr/local/bin/envoy -c /etc/envoy/envoy.yaml --log-level warn
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
ok "Services enabled and started"

# Wait for Envoy to be ready
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:9901/ready" >/dev/null 2>&1; then
    ok "Envoy is ready"
    break
  fi
  sleep 1
done

# ===========================================================================
log "Step 5/8: Getting TLS certificate"

systemctl stop l7ddos-envoy || true
sleep 2

certbot certonly \
  --standalone \
  --preferred-challenges http \
  --http-01-port 80 \
  -d "$DOMAIN" \
  --email "$EMAIL" \
  --agree-tos \
  --no-eff-email \
  --keep-until-expiring \
  || die "certbot failed — ensure DNS points to this IP and port 80 is accessible"

ok "Certificate obtained"

# Patch envoy.yaml with the certificate
ENVOY_YAML="/etc/envoy/envoy.yaml"
CERT="/etc/letsencrypt/live/${DOMAIN}"

python3 - "$ENVOY_YAML" "$DOMAIN" <<'PYEOF'
import sys, pathlib

path, domain = sys.argv[1], sys.argv[2]
text = pathlib.Path(path).read_text()

if "transport_socket:" in text:
    print("  transport_socket already present, skipping patch")
    sys.exit(0)

tls_block = (
    "      - transport_socket:\n"
    "          name: envoy.transport_sockets.tls\n"
    "          typed_config:\n"
    '            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext\n'
    "            common_tls_context:\n"
    "              tls_params:\n"
    "                tls_minimum_protocol_version: TLSv1_2\n"
    "              tls_certificates:\n"
    f"                - certificate_chain: {{ filename: /etc/letsencrypt/live/{domain}/fullchain.pem }}\n"
    f"                  private_key: {{ filename: /etc/letsencrypt/live/{domain}/privkey.pem }}\n"
    '              alpn_protocols: ["h2", "http/1.1"]\n'
    "        filters:\n"
)

marker = "    filter_chains:\n"
idx = text.find(marker)
if idx == -1:
    print("  !! could not find filter_chains - edit envoy.yaml manually")
    sys.exit(1)

idx2 = text.find(marker, idx + 1)
if idx2 == -1:
    print("  !! second filter_chains not found - edit envoy.yaml manually")
    sys.exit(1)

old_start = "      - filters:\n"
old_pos = text.find(old_start, idx2)
if old_pos == -1:
    print("  !! could not find '- filters:' after https filter_chains")
    sys.exit(1)

text = text[:old_pos] + tls_block + text[old_pos + len(old_start):]
pathlib.Path(path).write_text(text)
print("  patched envoy.yaml with TLS context")
PYEOF

ok "Certificate patched into envoy.yaml"

# Verify config
if /usr/local/bin/envoy --mode validate -c "$ENVOY_YAML" 2>/tmp/envoy_validate.log; then
  ok "Envoy config is valid"
else
  warn "Config validation FAILED:"
  cat /tmp/envoy_validate.log
  exit 1
fi

# Setup auto-renewal
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/reload-envoy.sh <<'EOF'
#!/bin/sh
systemctl reload l7ddos-envoy 2>/dev/null || systemctl restart l7ddos-envoy
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-envoy.sh
systemctl enable --now certbot.timer 2>/dev/null || true

systemctl start l7ddos-envoy
sleep 2

ok "Auto-renewal configured"

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
ok "Journal capped at 500M / 1 week retention"

# ---------------------------------------------------------------------------
log "Step 6/8: Capping journal size"
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
ok "Journal capped at 500M / 1 week retention"

# ---------------------------------------------------------------------------
log "Step 7/8: Installing dashboard"
bash "$SRC_DIR/dashboard/install-dashboard.sh"

# ===========================================================================
log "Step 8/8: Configuring firewall"

ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
ok "Firewall configured (22/80/443 open)"

# ===========================================================================
log "Running verification tests"

pass=0; fail=0
BASE="https://${DOMAIN}"

ok_test()   { echo -e "    \033[1;32mPASS\033[0m  $*"; pass=$((pass+1)); }
fail_test() { echo -e "    \033[1;31mFAIL\033[0m  $*"; fail=$((fail+1)); }
test_hdr()  { echo -e "\n  $*"; }

code() { curl -s -o /dev/null -w "%{http_code}" "$@" 2>/dev/null; }

test_hdr "1. Basic reachability"
c=$(code "$BASE/")
if [ "$c" = "200" ]; then ok_test "site returns 200"; else fail_test "site returned $c"; fi

test_hdr "2. Origin is NOT public"
c=$(timeout 5 bash -c "echo > /dev/tcp/${DOMAIN}/8080" 2>/dev/null && echo "open" || echo "closed")
if [ "$c" = "closed" ]; then ok_test "origin port 8080 is closed"; else fail_test "ORIGIN IS PUBLIC!"; fi

test_hdr "3. Rate limiting works"
counts=$(for i in $(seq 1 50); do
         curl -s -o /dev/null -w "%{http_code}\n" "$BASE/api/echo"
       done | sort | uniq -c | tr -s ' ')
if echo "$counts" | grep -q "429"; then ok_test "rate limiting active"; else fail_test "no 429s seen"; fi

test_hdr "4. Scanner User-Agents blocked"
c=$(code -A "sqlmap/1.7" "$BASE/")
if [ "$c" = "403" ]; then ok_test "sqlmap blocked"; else fail_test "sqlmap got $c"; fi

test_hdr "5. Dashboard reachable"
c=$(code "$BASE/dashboard/login")
if [ "$c" = "200" ]; then ok_test "dashboard login page loads"; else fail_test "dashboard got $c"; fi

test_hdr "6. Public stats endpoint works"
stats=$(curl -s --max-time 5 "$BASE/api/public-stats" 2>/dev/null)
if echo "$stats" | grep -q '"requests_total"'; then
  ok_test "public stats returns JSON"
else
  fail_test "public stats endpoint broken"
fi

test_hdr "7. Public stats responds quickly (not blocked on journal scan)"
t=$(curl -s -o /dev/null -w "%{time_total}" --max-time 10 "$BASE/api/public-stats" 2>/dev/null)
if [ -n "$t" ] && awk "BEGIN{exit !($t < 1.0)}"; then
  ok_test "public stats responded in ${t}s"
else
  fail_test "public stats took ${t}s (too slow)"
fi

test_hdr "8. Services enabled (survive reboot)"
for svc in l7ddos-origin l7ddos-envoy l7dashboard; do
  if systemctl is-enabled "$svc" >/dev/null 2>&1; then
    ok_test "$svc enabled"
  else
    fail_test "$svc not enabled"
  fi
done

echo
echo -e "\033[1;36m===== $pass passed, $fail failed =====\033[0m"

# ===========================================================================
echo
log "🎉 Deployment complete!"
echo
echo "Your site is live at: https://${DOMAIN}"
echo "Dashboard at:         https://${DOMAIN}/dashboard"
echo
if [ ! -f /etc/l7dashboard.env ]; then
  echo "IMPORTANT: set your dashboard password:"
  echo "  sudo cp /etc/l7dashboard.env.example /etc/l7dashboard.env"
  echo "  sudo nano /etc/l7dashboard.env   # set DASHBOARD_PASS"
  echo "  sudo systemctl restart l7dashboard"
  echo
fi
echo "Monitor stats:"
echo "  curl -s localhost:9901/stats | grep edge_guard"
echo "  curl -s ${DOMAIN}/api/public-stats"
echo
echo "Watch logs:"
echo "  journalctl -u l7ddos-envoy -f"
echo
echo "Tune thresholds:"
echo "  # Rate limit: 100 req/s, burst 200"
echo "  sed -i 's/local IP_RATE_LIMIT = .*/local IP_RATE_LIMIT = 100/' /etc/envoy/lua/edge_guard.lua"
echo "  sed -i 's/local IP_BURST = .*/local IP_BURST = 200/' /etc/envoy/lua/edge_guard.lua"
echo "  systemctl restart l7ddos-envoy"
echo
echo "Useful files:"
echo "  - /etc/envoy/envoy.yaml (main config)"
echo "  - /etc/envoy/lua/edge_guard.lua (your L7 filtering logic)"
echo "  - /var/lib/l7ddos/site/ (your website)"
echo
[ "$fail" -eq 0 ] && exit 0 || exit 1
