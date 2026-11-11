#!/usr/bin/env bash
# Live post-nftables traffic monitor (like nload but shows what gets through)
set -euo pipefail

cyan() { echo -e "\033[1;36m$*\033[0m"; }
green() { echo -e "\033[1;32m$*\033[0m"; }
red() { echo -e "\033[1;31m$*\033[0m"; }
yellow() { echo -e "\033[1;33m$*\033[0m"; }

ENVOY_ADMIN="http://127.0.0.1:9901"

prev_conntrack=0
prev_envoy_conns=0
prev_envoy_reqs=0

clear
echo ""
cyan "═══════════════════════════════════════════════════════════════"
cyan "  L7 DDoS Protection — Live Traffic Monitor"
cyan "═══════════════════════════════════════════════════════════════"
echo ""

while true; do
  # Kernel layer
  conntrack_total=$(conntrack -C 2>/dev/null || echo 0)
  conntrack_rate=$((conntrack_total - prev_conntrack))
  prev_conntrack=$conntrack_total

  # nftables rate-limited IPs
  ratelimited_ips=$(nft list set inet l7edge per_ip_conn 2>/dev/null | grep -c "limit rate" || echo 0)

  # Envoy layer
  envoy_active=$(curl -s "$ENVOY_ADMIN/stats" 2>/dev/null | grep "http.https_edge.downstream_cx_active:" | awk '{print $2}' || echo 0)
  envoy_total_reqs=$(curl -s "$ENVOY_ADMIN/stats" 2>/dev/null | grep "http.https_edge.downstream_rq_total:" | awk '{print $2}' || echo 0)

  envoy_conn_rate=$((envoy_active - prev_envoy_conns))
  envoy_req_rate=$((envoy_total_reqs - prev_envoy_reqs))
  prev_envoy_conns=$envoy_active
  prev_envoy_reqs=$envoy_total_reqs

  # Socket stats
  ss_output=$(ss -s 2>/dev/null)
  tcp_estab=$(echo "$ss_output" | grep "TCP:" | grep -oP 'estab \K\d+' || echo 0)
  tcp_timewait=$(echo "$ss_output" | grep "TCP:" | grep -oP 'timewait \K\d+' || echo 0)

  # Display
  tput cup 5 0
  echo "$(yellow '┌─ Kernel Layer (conntrack)')                              "
  echo "  Total tracked connections: $(green "$conntrack_total")          "
  echo "  Rate (new/sec):            $(green "$conntrack_rate")          "
  echo "  TCP established:           $(green "$tcp_estab")          "
  echo "  TCP time-wait:             $(yellow "$tcp_timewait")          "
  echo ""
  echo "$(yellow '┌─ nftables (L4 filtering)')                              "
  echo "  IPs being rate-limited:    $(red "$ratelimited_ips")          "
  echo ""
  echo "$(yellow '┌─ Envoy (L7 filtering)')                              "
  echo "  Active connections:        $(green "$envoy_active")          "
  echo "  Connection rate (Δ/sec):   $(green "$envoy_conn_rate")          "
  echo "  Total requests:            $(green "$envoy_total_reqs")          "
  echo "  Request rate (Δ/sec):      $(green "$envoy_req_rate")          "
  echo ""
  echo "$(cyan '─────────────────────────────────────────────────────────────')"
  echo "  Press Ctrl+C to exit                                          "
  echo ""

  sleep 1
done
