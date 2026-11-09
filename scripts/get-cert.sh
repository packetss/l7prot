#!/usr/bin/env bash
# ===========================================================================
#  get-cert.sh — obtain a TLS certificate via ACME and wire it into Envoy.
#
#  First issuance: certbot standalone on port 80 with Envoy stopped (Envoy
#  can't start yet without a cert). Downtime ~5 seconds, one time only.
#
#  Renewals: certbot webroot. The origin serves /.well-known/acme-challenge/
#  from /var/lib/l7ddos/acme and Envoy proxies port 80 challenges to it, so
#  renewals need no downtime at all.
# ===========================================================================
set -euo pipefail

DOMAIN="${DOMAIN:?set DOMAIN=your.domain.com}"
EMAIL="${EMAIL:-admin@${DOMAIN}}"
ACME_ROOT="${ACME_ROOT:-/var/lib/l7ddos/acme}"

cyan() { echo -e "\033[1;36m==>\033[0m $*"; }
red()  { echo -e "\033[1;31mxx\033[0m $*" >&2; }

# ---------------------------------------------------------------------------
cyan "Installing certbot"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq certbot

# ---------------------------------------------------------------------------
mkdir -p "$ACME_ROOT"

CERT="/etc/letsencrypt/live/${DOMAIN}"
HAVE_CERT=false
[ -f "${CERT}/fullchain.pem" ] && HAVE_CERT=true

# ---------------------------------------------------------------------------
if [ "$HAVE_CERT" = "true" ]; then
  cyan "Existing certificate found - renewing via webroot (no downtime)"
  certbot certonly \
    --webroot \
    --webroot-path "$ACME_ROOT" \
    --preferred-challenges http \
    -d "$DOMAIN" \
    --email "$EMAIL" \
    --agree-tos \
    --no-eff-email \
    --keep-until-expiring
else
  cyan "No existing certificate - requesting via standalone (Envoy stops briefly)"
  systemctl stop l7ddos-envoy || true

  certbot certonly \
    --standalone \
    --preferred-challenges http \
    --http-01-port 80 \
    -d "$DOMAIN" \
    --email "$EMAIL" \
    --agree-tos \
    --no-eff-email \
    --keep-until-expiring

  systemctl start l7ddos-envoy || true
fi

if [ ! -f "${CERT}/fullchain.pem" ]; then
  red "certificate not found at $CERT"
  exit 1
fi

# ---------------------------------------------------------------------------
cyan "Patching envoy.yaml with the certificate"
ENVOY_YAML="/etc/envoy/envoy.yaml"

# The shipped envoy.yaml already contains a transport_socket block (with
# placeholder cert paths), so we can't just skip when it exists — we must
# REPLACE the certificate paths with the ones for this domain.
python3 - "$ENVOY_YAML" "$DOMAIN" <<'PYEOF'
import sys, pathlib, re

path, domain = sys.argv[1], sys.argv[2]
text = pathlib.Path(path).read_text()
cert = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
key = f"/etc/letsencrypt/live/{domain}/privkey.pem"

if "transport_socket:" not in text:
    # No TLS block yet — insert one before the https listener's filters.
    tls_block = (
        "      - transport_socket:\n"
        "          name: envoy.transport_sockets.tls\n"
        "          typed_config:\n"
        '            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext\n'
        "            common_tls_context:\n"
        "              tls_params:\n"
        "                tls_minimum_protocol_version: TLSv1_2\n"
        "              tls_certificates:\n"
        f"                - certificate_chain: {{ filename: {cert} }}\n"
        f"                  private_key: {{ filename: {key} }}\n"
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
    print(f"  inserted TLS block for {domain}")
else:
    # TLS block exists — just repoint the cert paths to this domain.
    text, n1 = re.subn(r'certificate_chain: \{ filename: [^}]+\}',
                       f'certificate_chain: {{ filename: {cert} }}', text)
    text, n2 = re.subn(r'private_key: \{ filename: [^}]+\}',
                       f'private_key: {{ filename: {key} }}', text)
    if n1 == 0 or n2 == 0:
        print("  !! TLS block found but cert paths were not replaced - edit manually")
        sys.exit(1)
    print(f"  repointed cert paths to {domain}")

pathlib.Path(path).write_text(text)
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

# Switch the renewal method to webroot so renewals don't need to stop Envoy.
# The renewal config is per-domain, so rewrite the authenticator in place.
RENEWAL_CONF="/etc/letsencrypt/renewal/${DOMAIN}.conf"
if [ -f "$RENEWAL_CONF" ]; then
  if grep -q "authenticator = standalone" "$RENEWAL_CONF"; then
    sed -i 's/^authenticator = standalone$/authenticator = webroot/' "$RENEWAL_CONF"
  fi
  if grep -q "^webroot_path" "$RENEWAL_CONF"; then
    sed -i "s|^webroot_path = .*|webroot_path = ${ACME_ROOT}|" "$RENEWAL_CONF"
  else
    printf 'webroot_path = %s\n' "$ACME_ROOT" >> "$RENEWAL_CONF"
  fi
  cyan "Renewal switched to webroot (${ACME_ROOT}) — no downtime on renew"
else
  warn "Could not find $RENEWAL_CONF — renewals may still use standalone"
fi

echo
cyan "Done. Test it:"
echo "  curl -sI https://${DOMAIN}/ | head -5"
echo "  DOMAIN=${DOMAIN} ./scripts/test.sh"
echo
echo "Renewal check:"
echo "  sudo certbot renew --dry-run"
