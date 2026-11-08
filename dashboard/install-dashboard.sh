#!/usr/bin/env bash
# ===========================================================================
#  install-dashboard.sh — Install / update the L7 protection dashboard
#
#  Idempotent: safe to re-run on an existing install to pick up code changes.
#
#  Usage:
#    sudo ./dashboard/install-dashboard.sh
# ===========================================================================
set -euo pipefail

DASHBOARD_DIR=/opt/l7dashboard
DASHBOARD_USER=l7dashboard
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cyan() { echo -e "\033[1;36m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m!!\033[0m $*"; }
die()  { echo -e "\033[1;31mxx\033[0m $*" >&2; exit 1; }

[ "$EUID" -eq 0 ] || die "must run as root (use sudo)"

# ---------------------------------------------------------------------------
cyan "Installing dashboard dependencies"
apt-get update -qq
apt-get install -y -qq python3-pip python3-venv

# ---------------------------------------------------------------------------
cyan "Creating dashboard user"
id -u "$DASHBOARD_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$DASHBOARD_USER"

# The dashboard reads the Envoy access log via journalctl, which requires
# membership in the systemd-journal group. Without this the stats counters
# stay at zero and no events show up.
usermod -aG systemd-journal "$DASHBOARD_USER" 2>/dev/null || \
  warn "could not add $DASHBOARD_USER to systemd-journal group"

# ---------------------------------------------------------------------------
cyan "Setting up dashboard directory"
mkdir -p "$DASHBOARD_DIR"
cp "$SRC_DIR/server.py" "$SRC_DIR/dashboard.html" "$SRC_DIR/requirements.txt" "$DASHBOARD_DIR/"

# ---------------------------------------------------------------------------
cyan "Installing Python dependencies"
cd "$DASHBOARD_DIR"
if [ ! -d venv ]; then
  python3 -m venv venv
fi
venv/bin/pip install --quiet --upgrade pip
venv/bin/pip install --quiet -r requirements.txt

# ---------------------------------------------------------------------------
cyan "Creating systemd service"
cat > /etc/systemd/system/l7dashboard.service <<EOF
[Unit]
Description=L7 Protection Dashboard
After=network.target l7ddos-envoy.service
Wants=l7ddos-envoy.service

[Service]
Type=simple
User=$DASHBOARD_USER
Group=$DASHBOARD_USER
WorkingDirectory=$DASHBOARD_DIR
Environment="DASHBOARD_USER=admin"
Environment="DASHBOARD_PASS=CHANGE_ME_ON_FIRST_RUN"
Environment="DASHBOARD_STATS_FILE=$DASHBOARD_DIR/stats.json"
EnvironmentFile=-/etc/l7dashboard.env
ExecStart=$DASHBOARD_DIR/venv/bin/python3 $DASHBOARD_DIR/server.py
Restart=always
RestartSec=5

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/
ReadWritePaths=$DASHBOARD_DIR

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
cyan "Creating environment file template"
if [ ! -f /etc/l7dashboard.env.example ]; then
cat > /etc/l7dashboard.env.example <<'EOF'
# Dashboard credentials - copy this to /etc/l7dashboard.env and set your password
DASHBOARD_USER=admin
DASHBOARD_PASS=your-secure-password-here
DASHBOARD_SECRET=your-secret-key-here
EOF
fi

# Generate a secret key if the env file exists but has no secret, otherwise
# every restart invalidates all sessions and logs everyone out.
if [ -f /etc/l7dashboard.env ] && ! grep -q '^DASHBOARD_SECRET=.' /etc/l7dashboard.env; then
  SECRET=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || openssl rand -base64 32)
  printf '\nDASHBOARD_SECRET=%s\n' "$SECRET" >> /etc/l7dashboard.env
  cyan "Generated DASHBOARD_SECRET"
fi

# ---------------------------------------------------------------------------
# Fix ownership after all file copies (venv is created above as root)
chown -R "$DASHBOARD_USER":"$DASHBOARD_USER" "$DASHBOARD_DIR"

systemctl daemon-reload
systemctl enable l7dashboard
systemctl restart l7dashboard

# ---------------------------------------------------------------------------
cyan "Waiting for dashboard to come up"
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:8888/dashboard/login" >/dev/null 2>&1; then
    cyan "Dashboard is up"
    break
  fi
  sleep 1
done

echo
cyan "Dashboard installed!"
echo
if [ -f /etc/l7dashboard.env ]; then
  echo "  Credentials are already configured in /etc/l7dashboard.env"
else
  echo "IMPORTANT: Set your dashboard password:"
  echo "  1. sudo cp /etc/l7dashboard.env.example /etc/l7dashboard.env"
  echo "  2. sudo nano /etc/l7dashboard.env  (set DASHBOARD_PASS)"
  echo "  3. sudo systemctl restart l7dashboard"
  echo
fi
echo "Access at: http://127.0.0.1:8888/dashboard"
echo "Via your site: https://<your-domain>/dashboard"
