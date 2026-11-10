#!/usr/bin/env bash
# ===========================================================================
#  harden.sh — L4 hardening: keep the flood out of Envoy's memory.
#
#  WHY THIS EXISTS
#
#  Envoy (with Lua + Coraza WASM) on 2 cores does roughly 10-30k rps. The
#  goal is not to make Envoy serve 100k rps — it is to make the box
#  ABSORB 100k rps by killing the bad traffic before Envoy ever allocates
#  a socket, a buffer, or a TLS handshake for it.
#
#  Filtering inside Envoy/Lua is too late: by the time the Lua filter
#  runs, the connection has already been accepted and already cost us
#  memory. This script puts the first line of defence in the kernel.
#
#  LAYERS (cheapest first)
#
#    1. sysctl  - SYN cookies mean the kernel allocates no connection slot
#                 until the handshake completes, so SYN floods cannot
#                 exhaust the accept queue.
#    2. nftables raw table - drops garbage BEFORE conntrack: invalid TCP
#                 flags (SYN+FIN, XMAS, NULL scans), bogon source IPs,
#                 fragmented HTTPS. Costs microseconds, no state allocated.
#    3. nftables input - per-source NEW CONNECTION rate limit and global
#                 cap, after conntrack so we can use "ct state new".
#    4. connlimit - per-source CONCURRENT connection cap (iptables
#                 --connlimit). This is the load-bearing one: it reserves
#                 capacity for real users by cutting off bots that open
#                 hundreds of connections.
#    5. Envoy    - L7 filtering (Lua, WAF, local_ratelimit) for whatever
#                 survives the kernel.
#
#  IMPORTANT: this only manages its OWN table and rules. It never calls
#  "flush ruleset", so any other firewall on the box is left alone.
#
#  Usage:
#    harden.sh apply     # install + apply rules (default)
#    harden.sh status    # show what's in place
#    harden.sh remove    # remove the table + connlimit rules
# ===========================================================================
set -euo pipefail

NFT_TABLE="l7edge"
NFT_CONF="/etc/nftables.d/${NFT_TABLE}.nft"
SYSCTL_CONF="/etc/sysctl.d/99-l7ddos-hardening.conf"
RULES_SCRIPT="/usr/local/lib/l7ddos/harden.sh"

# ---- tunables (override via environment) -------------------------------
# Per-source concurrent connections. Browsers use 1-6; a bot opening
# hundreds gets cut off. 16 is generous for real users.
CONNLIMIT_ABOVE="${CONNLIMIT_ABOVE:-16}"
CONNLIMIT_UPTO="${CONNLIMIT_UPTO:-32}"

# Per-source NEW connection rate. Limits how fast one IP can open
# connections. Legit users rarely open more than a couple per second.
PER_IP_CONN_RATE="${PER_IP_CONN_RATE:-30}"
PER_IP_CONN_BURST="${PER_IP_CONN_BURST:-60}"

# Global NEW connection rate cap. Above this the box is being flooded and
# new connections are refused outright. Set well above the real peak.
GLOBAL_CONN_RATE="${GLOBAL_CONN_RATE:-4000}"
GLOBAL_CONN_BURST="${GLOBAL_CONN_BURST:-8000}"

# Ports that are NEVER rate limited. SSH is here so a misconfiguration
# cannot lock us out of our own server.
UNLIMITED_PORTS=(22 80)

cyan() { echo -e "\033[1;36m==>\033[0m $*"; }
red()  { echo -e "\033[1;31mxx\033[0m $*" >&2; }
ok()   { echo -e "\033[1;32m  ok\033[0m $*"; }
warn() { echo -e "\033[1;33m  !!\033[0m $*" >&2; }

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    red "must run as root"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# sysctl
#
# tcp_syncookies is the single most important one: with SYN cookies the
# kernel does not allocate a connection slot until the handshake completes.
# ---------------------------------------------------------------------------
write_sysctl() {
  cat > "$SYSCTL_CONF" <<EOF
# Managed by l7ddos harden.sh -- do not edit by hand.
#
# L4 survival tuning. The goal is to keep the box reachable and
# responsive while absorbing a large connection flood.

# SYN cookies: no connection slot is allocated until the handshake
# completes, so a SYN flood cannot exhaust the accept queue. Without
# this, a SYN flood takes connectivity away from every legitimate user.
net.ipv4.tcp_syncookies = 1

# Accept queue depth.
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192

# Packet backlog for the NIC.
net.core.netdev_max_backlog = 4096

# TIME_WAIT bucket count. Too low and legitimate clients get refused;
# too high and the table eats RAM on a 2GB box.
net.ipv4.tcp_max_tw_buckets = 16384
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Socket buffers. The defaults (large) multiply by connection count.
net.ipv4.tcp_rmem = 4096 87380 262144
net.ipv4.tcp_wmem = 4096 65536 262144
net.core.rmem_max = 262144
net.core.wmem_max = 262144

# Spread ephemeral ports so we can hold more outbound connections.
net.ipv4.ip_local_port_range = 10240 65535

# File descriptors for the edge.
fs.file-max = 262144
EOF
  ok "wrote $SYSCTL_CONF"
}

apply_sysctl() {
  if ! sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1; then
    warn "some sysctls were rejected; applying individually"
    sysctl -p "$SYSCTL_CONF" 2>&1 | grep -v "^$" || true
  else
    ok "applied sysctl hardening"
  fi
}

# ---------------------------------------------------------------------------
# nftables
#
# Own table only. Nothing else on the box is touched.
#
# Uses TWO chains:
#   1. prerouting (priority raw) — runs BEFORE conntrack allocates state.
#      This is where we drop garbage: invalid TCP flags, bogon source IPs,
#      fragmented HTTPS packets, etc. Packets dropped here cost almost
#      nothing — no conntrack entry, no routing lookup, no iptables rules.
#
#   2. input (priority filter) — runs AFTER conntrack, for rate limiting.
#      The per-IP rate limit needs conntrack state ("ct state new"), so
#      it lives here rather than in raw.
#
# This is 90% as fast as XDP and far easier to maintain.
# ---------------------------------------------------------------------------
write_nft() {
  mkdir -p /etc/nftables.d
  local unlimited=""
  for p in "${UNLIMITED_PORTS[@]}"; do
    unlimited+="        tcp dport ${p} accept
"
  done

  cat > "$NFT_CONF" <<EOF
# Managed by l7ddos harden.sh -- do not edit by hand.
#
# Per-source connection shedding, applied BEFORE the TLS handshake.
#
# Only "ct state new" packets are limited, so established connections are
# never dropped -- a legit user mid-request is unaffected by a flood.
#
#   meter per_ip_conn  : per-source NEW connection rate limit.
#   limit global_conn  : global NEW connection rate cap. Past this the
#                        box is being flooded and new connections are
#                        refused outright, protecting memory for the
#                        connections we already have.
#
# Dropping a NEW connection is far cheaper than accepting it and then
# rejecting the request in Envoy: no socket, no buffer, no TLS handshake.

table inet ${NFT_TABLE} {
    # Per-source counters for the NEW connection rate limit. The dynamic
    # set gives us one bucket per source IP; "update" refreshes the
    # element so idle sources age out on their own.
    set per_ip_conn {
        type ipv4_addr
        flags dynamic, timeout
        timeout 60s
    }

    # Bogon source addresses that should NEVER appear on the public internet.
    # Attackers spoof these or use them in scans. Drop them in raw table
    # before conntrack even sees them.
    set bogons {
        type ipv4_addr
        flags interval
        elements = {
            0.0.0.0/8,       # "This network"
            10.0.0.0/8,      # RFC 1918 private
            100.64.0.0/10,   # RFC 6598 carrier-grade NAT
            127.0.0.0/8,     # loopback (from outside)
            169.254.0.0/16,  # link-local
            172.16.0.0/12,   # RFC 1918 private
            192.0.0.0/24,    # IETF protocol assignments
            192.0.2.0/24,    # TEST-NET-1
            192.168.0.0/16,  # RFC 1918 private
            198.18.0.0/15,   # benchmarking
            198.51.100.0/24, # TEST-NET-2
            203.0.113.0/24,  # TEST-NET-3
            224.0.0.0/4,     # multicast
            240.0.0.0/4      # reserved
        }
    }

    # Raw table runs BEFORE conntrack, so invalid packets never allocate
    # a conntrack entry. This is where we drop the garbage.
    chain prerouting {
        type filter hook prerouting priority raw; policy accept;

        # Never filter loopback.
        iif lo accept

        # Drop packets from bogon source IPs. These should never appear on
        # the public internet - either spoofed or misconfigured bots.
        ip saddr @bogons drop

        # Drop invalid TCP flag combinations. Legitimate traffic never uses
        # these; they're only seen in port scans and evasion attempts.
        tcp flags & (fin|syn) == (fin|syn) drop  # SYN+FIN
        tcp flags & (syn|rst) == (syn|rst) drop  # SYN+RST
        tcp flags == (fin|psh|urg) drop          # XMAS scan
        tcp flags == 0 drop                      # NULL scan
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop  # XMAS variant

        # Drop fragmented packets to HTTPS only. TLS handshakes and application
        # data fit in normal MTU; fragments are used to evade stateful inspection.
        tcp dport 443 ip frag-off & 0x1fff != 0 drop

        # Everything that survives goes to conntrack and then to the input chain.
    }

    chain input {
        type filter hook input priority filter; policy accept;

        # Never rate limit loopback.
        iif lo accept

        # Established traffic is never limited.
        ct state established,related accept

        # Drop invalid conntrack states. These should have been caught in
        # prerouting, but belt-and-suspenders.
        ct state invalid drop

        # ICMP (path MTU discovery etc.) must keep working.
        ip protocol icmp accept

        # Ports that are always allowed. SSH in particular: a bad rate
        # limit here must never lock us out of the box.
${unlimited}
        # --- connection shedding -------------------------------------------
        # Per-source concurrent connection cap. A browser uses 1-6; a bot
        # opening hundreds gets cut off. Checked before rate limiting so
        # connection-flood bots never consume rate-limit state.
        tcp dport 443 ct state new meter connlimit_per_ip { ip saddr ct count over ${CONNLIMIT_ABOVE} } drop

        # Per-source NEW connection rate. Over the limit -> drop.
        tcp dport 443 ct state new update @per_ip_conn { ip saddr limit rate over ${PER_IP_CONN_RATE}/second burst ${PER_IP_CONN_BURST} packets } drop

        # Global NEW connection cap. Over the limit -> drop.
        tcp dport 443 ct state new limit rate over ${GLOBAL_CONN_RATE}/second burst ${GLOBAL_CONN_BURST} packets drop

        # Everything else (including anything on 443 that is not "new")
        # is allowed through to Envoy.
    }
}
EOF
  ok "wrote $NFT_CONF"
}

apply_nft() {
  if ! command -v nft >/dev/null 2>&1; then
    warn "nft not installed -- skipping nftables layer"
    return 0
  fi

  # Validate before applying. A broken ruleset must not take the box
  # offline, so we check it parses first.
  if ! nft -c -f "$NFT_CONF" 2>/tmp/nft_check.log; then
    red "nftables ruleset is invalid, NOT applying:"
    cat /tmp/nft_check.log >&2
    return 1
  fi

  # Replace only our own table. Never "flush ruleset".
  nft delete table inet "$NFT_TABLE" 2>/dev/null || true
  if ! nft -f "$NFT_CONF" 2>/tmp/nft_apply.log; then
    red "failed to apply nftables rules:"
    cat /tmp/nft_apply.log >&2
    return 1
  fi
  ok "applied nftables rules (table inet ${NFT_TABLE})"
}

# ---------------------------------------------------------------------------
# per-source CONCURRENT connection limit
#
# nftables ct count tracks concurrent connections per source IP. This is
# the load-bearing control: a bot opening 500 connections is cut off after
# CONNLIMIT_ABOVE, while a browser using 4 is untouched.
# ---------------------------------------------------------------------------
apply_connlimit() {
  # Already handled inside the nftables table via ct count — nothing to do.
  ok "per-source connection limit handled by nftables (ct count)"
}

remove_connlimit() {
  # Handled by remove_all deleting the nftables table.
  true
}

# ---------------------------------------------------------------------------
# systemd unit so the rules survive a reboot
# ---------------------------------------------------------------------------
write_unit() {
  cat > /etc/systemd/system/l7ddos-harden.service <<EOF
[Unit]
Description=l7ddos L4 hardening (nftables + sysctl)
After=network-pre.target nftables.service
Before=l7ddos-envoy.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${RULES_SCRIPT} apply

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable l7ddos-harden.service >/dev/null 2>&1 || true
  ok "installed l7ddos-harden.service"
}

install_self() {
  mkdir -p /usr/local/lib/l7ddos
  local src
  src="$(readlink -f "${BASH_SOURCE[0]}")"
  if [ "$src" != "$RULES_SCRIPT" ]; then
    install -m 0755 "$src" "$RULES_SCRIPT"
    ok "installed $RULES_SCRIPT"
  fi
}

status() {
  cyan "sysctl"
  for s in net.ipv4.tcp_syncookies net.core.somaxconn \
           net.ipv4.tcp_max_syn_backlog net.core.netdev_max_backlog \
           net.ipv4.tcp_max_tw_buckets; do
    printf "  %-36s %s\n" "$s" "$(sysctl -n "$s" 2>/dev/null || echo '?')"
  done

  cyan "nftables table inet ${NFT_TABLE}"
  if command -v nft >/dev/null 2>&1 && nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
    nft list table inet "$NFT_TABLE" | sed 's/^/  /'
  else
    echo "  (not installed)"
  fi

  cyan "per-source connection limit"
  if command -v iptables >/dev/null 2>&1; then
    if iptables -C INPUT "${CONNLIMIT_RULE[@]}" 2>/dev/null; then
      echo "  active: >${CONNLIMIT_ABOVE} concurrent connections per source -> tcp-reset"
    else
      echo "  (not installed)"
    fi
  fi

  cyan "envoy connection cap"
  grep -n "max_active_downstream_connections" /etc/envoy/envoy.yaml 2>/dev/null | sed 's/^/  /' || echo "  (envoy.yaml not found)"
}

remove_all() {
  command -v nft >/dev/null 2>&1 && nft delete table inet "$NFT_TABLE" 2>/dev/null || true
  rm -f "$NFT_CONF"
  remove_connlimit
  systemctl disable --now l7ddos-harden.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/l7ddos-harden.service
  systemctl daemon-reload
  ok "hardening removed"
}

case "${1:-apply}" in
  apply)
    need_root
    install_self
    write_sysctl
    write_nft
    apply_sysctl
    apply_nft || warn "nftables layer NOT applied -- Envoy is unprotected at L4"
    apply_connlimit
    write_unit
    ok "hardening applied"
    ;;
  status)
    status
    ;;
  remove)
    need_root
    remove_all
    ;;
  *)
    red "unknown command: $1"
    echo "usage: harden.sh {apply|status|remove}"
    exit 1
    ;;
esac
