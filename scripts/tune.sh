#!/usr/bin/env bash
# ===========================================================================
#  tune.sh — change protection thresholds live.
#
#  Since edge_guard.lua uses hardcoded module-level constants (no runtime
#  API), tuning works by patching the Lua file and hot-restarting Envoy.
#  Envoy's hot restart replaces workers without dropping connections.
#
#  Usage:
#    ./tune.sh rate_limit 50 100        # 50 req/s per IP, burst 100
#    ./tune.sh enable | disable         # toggle rate limiting
#    ./tune.sh show                     # show current values
#    ./tune.sh reset                    # restore defaults
#
#  NOTE: rate_limit takes the GLOBAL per-IP target. Envoy runs one Lua VM
#  per worker thread, so the Lua file divides this by the worker count to
#  keep the limit identical no matter how many cores the box has.
# ===========================================================================
set -euo pipefail

LUA="${LUA:-/etc/envoy/lua/edge_guard.lua}"

cyan() { echo -e "\033[1;36m==>\033[0m $*"; }
red()  { echo -e "\033[1;31mxx\033[0m $*" >&2; }

set_lua_var() {
  local var="$1" value="$2"
  if ! grep -q "^local ${var} " "$LUA"; then
    red "variable ${var} not found in ${LUA}"
    return 1
  fi
  sed -i "s/^local ${var} .*$/local ${var} = ${value}/" "$LUA"
  echo "  ${var} = ${value}"
}

reload_envoy() {
  cyan "reloading Envoy"
  if systemctl is-active --quiet l7ddos-envoy; then
    systemctl restart l7ddos-envoy
    echo "  restarted"
  else
    echo "  (envoy not running via systemd)"
  fi
}

show() {
  cyan "current edge_guard.lua settings:"
  grep -E '^local (RATE_LIMIT_ENABLED|GLOBAL_RATE_LIMIT|GLOBAL_BURST|ENV_WORKERS|UA_BLOCKLIST_ENABLED|BLOCKLIST_ENABLED|SUSPICION_THRESHOLD) ' "$LUA" \
    | sed 's/^local /  /' || echo "  (could not read values)"
  local workers; workers=$(grep -E '^local ENV_WORKERS ' "$LUA" | grep -o '[0-9]*$' || echo 1)
  local rate;   rate=$(grep -E '^local GLOBAL_RATE_LIMIT ' "$LUA" | grep -o '[0-9]*' | tail -1 || echo 12)
  local burst;  burst=$(grep -E '^local GLOBAL_BURST ' "$LUA" | grep -o '[0-9]*' | tail -1 || echo 25)
  echo "  effective per-IP limit: ${rate} req/s, burst ${burst} (across ${workers} worker(s))"
}

case "${1:-show}" in
  rate_limit)
    RATE="${2:?usage: tune.sh rate_limit <req_per_sec> [burst]}"
    BURST="${3:-}"
    cyan "setting per-IP rate limit"
    set_lua_var GLOBAL_RATE_LIMIT "$RATE"
    [ -n "$BURST" ] && set_lua_var GLOBAL_BURST "$BURST"
    reload_envoy
    ;;
  enable)
    set_lua_var RATE_LIMIT_ENABLED "true"
    reload_envoy
    ;;
  disable)
    set_lua_var RATE_LIMIT_ENABLED "false"
    reload_envoy
    ;;
  show)
    show
    ;;
  reset)
    cyan "resetting to defaults"
    set_lua_var RATE_LIMIT_ENABLED "true"
    set_lua_var GLOBAL_RATE_LIMIT "12"
    set_lua_var GLOBAL_BURST "25"
    set_lua_var UA_BLOCKLIST_ENABLED "true"
    set_lua_var BLOCKLIST_ENABLED "true"
    set_lua_var SUSPICION_THRESHOLD "3"
    reload_envoy
    ;;
  *)
    red "unknown command: $1"
    echo "usage: tune.sh {rate_limit <rps> [burst]|enable|disable|show|reset}"
    exit 1
    ;;
esac
