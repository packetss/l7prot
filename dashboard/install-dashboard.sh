#!/usr/bin/env bash
# ===========================================================================
#  install-dashboard.sh — Install the L7 protection dashboard
# ===========================================================================
set -euo pipefail

cyan() { echo -e "\033[1;36m==>\033[0m $*"; }

cyan "Installing dashboard dependencies"
apt-get install -y python3-pip python3-venv

cyan "Creating dashboard user"
useradd -r -s /bin/false l7dashboard || true

cyan "Setting up dashboard directory"
mkdir -p /opt/l7dashboard
cp server.py dashboard.html requirements.txt /opt/l7dashboard/
chown -R l7dashboard:l7dashboard /opt/l7dashboard

cd /opt/l7dashboard
cyan "Installing Python dependencies"
python3 -m venv venv
venv/bin/pip install --quiet -r requirements.txt

cyan "Creating systemd service"
cat > /etc/systemd/system/l7dashboard.service <<'EOF'
[Unit]
Description=L7 Protection Dashboard
After=network.target l7ddos-envoy.service

[Service]
Type=simple
User=l7dashboard
WorkingDirectory=/opt/l7dashboard
Environment="DASHBOARD_USER=admin"
Environment="DASHBOARD_PASS=CHANGE_ME_ON_FIRST_RUN"
EnvironmentFile=-/etc/l7dashboard.env
ExecStart=/opt/l7dashboard/venv/bin/python3 /opt/l7dashboard/server.py
Restart=always
RestartSec=5

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/
ReadWritePaths=/opt/l7dashboard

[Install]
WantedBy=multi-user.target
EOF

cyan "Creating environment file template"
cat > /etc/l7dashboard.env.example <<'EOF'
# Dashboard credentials - copy this to /etc/l7dashboard.env and set your password
DASHBOARD_USER=admin
DASHBOARD_PASS=your-secure-password-here
DASHBOARD_SECRET=your-secret-key-here
EOF

echo
cyan "Dashboard installed!"
echo
echo "IMPORTANT: Set your dashboard password:"
echo "  1. sudo cp /etc/l7dashboard.env.example /etc/l7dashboard.env"
echo "  2. sudo nano /etc/l7dashboard.env  (set DASHBOARD_PASS)"
echo "  3. sudo systemctl start l7dashboard"
echo "  4. sudo systemctl enable l7dashboard"
echo
echo "Access at: http://127.0.0.1:8888"
echo "To expose externally, use SSH tunnel or reverse proxy"
