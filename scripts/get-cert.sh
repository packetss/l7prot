#!/usr/bin/env bash
# ===========================================================================
#  get-cert.sh — obtain a TLS certificate via ACME and wire it into Envoy.
#
#  We run certbot standalone on port 80 with Envoy stopped, which is the
#  simplest thing that cannot go wrong. Traffic downtime is ~5 seconds.
# ===========================================================================
set -euo pipefail

DOMAIN="${DOMAIN:?set DOMAIN=your.domain.com}"
EMAIL="${EMAIL:-admin@${DOMAIN}}"

cyan() { echo -e "\033[1;36m==>\033[0m $*"; }
red()  { echo -e "\033[1;31mxx\033[0m $*" >&2; }

# ---------------------------------------------------------------------------
cyan "Installing certbot"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq certbot

# ---------------------------------------------------------------------------
cyan "Stopping Envoy briefly to free port 80"
systemctl stop l7ddos-envoy || true

# ---------------------------------------------------------------------------
cyan "Requesting certificate for $DOMAIN"
certbot certonly \
  --standalone \
  --preferred-challenges http \
  --http-01-port 80 \
  -d "$DOMAIN" \
  --email "$EMAIL" \
  --agree-tos \
  --no-eff-email \
  --keep-until-expiring

# ---------------------------------------------------------------------------
cyan "Restarting Envoy"
systemctl start l7ddos-envoy

CERT="/etc/letsencrypt/live/${DOMAIN}"
if [ ! -f "${CERT}/fullchain.pem" ]; then
  red "certificate not found at $CERT"
  exit 1
fi

# ---------------------------------------------------------------------------
cyan "Patching envoy.yaml with the certificate"
ENVOY_YAML="/etc/envoy/envoy.yaml"

# The transport_socket block is a sibling of `filters` inside the filter_chain
# list item. Indentation: 8 spaces for transport_socket (peer of `filters`).
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

# Find the https listener's filter_chains. We look for the second occurrence
# of "filter_chains:" (the first is on the :80 listener).
marker = "    filter_chains:\n"
idx = text.find(marker)
if idx == -1:
    print("  !! could not find filter_chains - edit envoy.yaml manually")
    sys.exit(1)

idx2 = text.find(marker, idx + 1)
if idx2 == -1:
    print("  !! second filter_chains not found - edit envoy.yaml manually")
    sys.exit(1)

# Replace "    filter_chains:\n      - filters:\n" with our TLS block.
old_start = "      - filters:\n"
old_pos = text.find(old_start, idx2)
if old_pos == -1:
    print("  !! could not find '- filters:' after https filter_chains")
    sys.exit(1)

text = text[:old_pos] + tls_block + text[old_pos + len(old_start):]
pathlib.Path(path).write_text(text)
print("  patched envoy.yaml with TLS context")
PYEOF

# ---------------------------------------------------------------------------
ENVOY_BIN="$(command -v envoy || echo /usr/local/bin/envoy)"
cyan "Verifying Envoy config"
if "$ENVOY_BIN" --mode validate -c "$ENVOY_YAML" 2>/tmp/envoy_validate.log; then
  echo -e "  \033[1;32mconfig is valid\033[0m"
else
  red "config validation FAILED:"
  cat /tmp/envoy_validate.log
  exit 1
fi

systemctl restart l7ddos-envoy

# ---------------------------------------------------------------------------
cyan "Setting up auto-renewal"
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/reload-envoy.sh <<'EOF'
#!/bin/sh
systemctl reload l7ddos-envoy 2>/dev/null || systemctl restart l7ddos-envoy
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-envoy.sh

systemctl enable --now certbot.timer 2>/dev/null || true

echo
cyan "Done. Test it:"
echo "  curl -sI https://${DOMAIN}/ | head -5"
echo "  DOMAIN=${DOMAIN} ./scripts/test.sh"
