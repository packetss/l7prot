#!/usr/bin/env bash
# ===========================================================================
#  test.sh — verify each protection layer actually fires.
#
#  Run this after install. Every check should PASS. If a check fails, that
#  layer is not protecting you, which is worse than not having it at all
#  because it gives false confidence.
# ===========================================================================
set -uo pipefail

DOMAIN="${DOMAIN:?set DOMAIN=your.domain.com}"
BASE="https://${DOMAIN}"
pass=0; fail=0

ok()   { echo -e "  \033[1;32mPASS\033[0m  $*"; pass=$((pass+1)); }
bad()  { echo -e "  \033[1;31mFAIL\033[0m  $*"; fail=$((fail+1)); }
hdr()  { echo -e "\n\033[1;36m== $*\033[0m"; }

code() { curl -s -o /dev/null -w "%{http_code}" "$@" 2>/dev/null; }

# ---------------------------------------------------------------------------
hdr "1. Basic reachability"
c=$(code "$BASE/")
if [ "$c" = "200" ]; then ok "site returns 200"; else bad "site returned $c (expected 200)"; fi

c=$(code "$BASE/healthz")
if [ "$c" = "200" ]; then ok "health check works"; else bad "health check returned $c"; fi

# ---------------------------------------------------------------------------
hdr "2. Origin must NOT be reachable directly"
# This is the most important check. If the origin answers on port 8080 from
# outside, your entire protection is decorative.
c=$(timeout 5 bash -c "echo > /dev/tcp/${DOMAIN}/8080" 2>/dev/null && echo "open" || echo "closed")
if [ "$c" = "closed" ]; then ok "origin port 8080 is closed to the world"; else bad "ORIGIN PORT 8080 IS OPEN — attackers can bypass Envoy!"; fi

# ---------------------------------------------------------------------------
hdr "3. Rate limiting (per IP)"
# Fire a burst CONCURRENTLY and count 429s. Sequential curls are too slow:
# each one pays a full TLS handshake, so a sequential loop never outruns the
# token bucket's refill rate and never trips the limit.
#
# The Lua token bucket is per-worker (one Lua VM per Envoy worker thread),
# so the effective burst is IP_BURST x worker_count. Size the burst from the
# actual worker count and add a healthy margin, otherwise a multi-core box
# absorbs the whole burst and we see no 429s.
# Envoy defaults to one worker per CPU core when concurrency isn't set.
WORKERS=$(nproc 2>/dev/null || echo 1)
case "$WORKERS" in ''|*[!0-9]*) WORKERS=1 ;; esac
[ "$WORKERS" -lt 1 ] && WORKERS=1
BURST_N=$(( (40 * WORKERS) * 3 ))
[ "$BURST_N" -gt 400 ] && BURST_N=400

burst_dir=$(mktemp -d)
for i in $(seq 1 "$BURST_N"); do
  ( curl -s -o /dev/null -w "%{http_code}\n" --max-time 10 \
      "$BASE/api/echo" > "$burst_dir/$i" 2>/dev/null ) &
done
wait
counts=$(cat "$burst_dir"/* 2>/dev/null | sort | uniq -c | tr -s ' ')
rm -rf "$burst_dir"
echo "     burst of ${BURST_N} concurrent requests (${WORKERS} envoy worker(s))"
echo "     status counts: ${counts}"
if echo "$counts" | grep -q "429"; then ok "rate limiting fires (429 seen)"; else bad "no 429s — rate limit not working"; fi

sleep 3  # let the bucket refill

# ---------------------------------------------------------------------------
hdr "4. Scanner User-Agent blocking"
c=$(code -A "sqlmap/1.7" "$BASE/")
if [ "$c" = "403" ]; then ok "sqlmap UA blocked (403)"; else bad "sqlmap UA got $c (expected 403)"; fi

c=$(code -A "python-requests/2.31.0" "$BASE/")
if [ "$c" = "403" ]; then ok "python-requests UA blocked (403)"; else bad "python-requests UA got $c (expected 403)"; fi

c=$(code -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36" "$BASE/")
if [ "$c" = "200" ]; then ok "real browser UA allowed (200)"; else bad "browser UA got $c — false positive!"; fi

# ---------------------------------------------------------------------------
hdr "5. JA4 fingerprinting"
ja4=$(curl -s "http://127.0.0.1:9901/stats" 2>/dev/null | grep -i "ja4" | head -3)
if [ -n "$ja4" ]; then ok "JA4 stats present in admin endpoint"; else bad "no JA4 stats — is the JA4 filter loaded?"; fi

# ---------------------------------------------------------------------------
hdr "6. WAF / malicious path"
c=$(code "$BASE/../../etc/passwd")
if [ "$c" = "400" ] || [ "$c" = "403" ] || [ "$c" = "404" ]; then ok "traversal path handled ($c)"; else bad "traversal got $c"; fi

c=$(code -X DELETE "$BASE/")
if [ "$c" = "405" ]; then ok "disallowed method rejected (405)"; else bad "DELETE got $c (expected 405)"; fi

# ---------------------------------------------------------------------------
hdr "7. Cache is working"
before=$(curl -s -o /dev/null -w "%{time_total}" "$BASE/")
sleep 1
after=$(curl -s -o /dev/null -w "%{time_total}" "$BASE/")
echo "     first=${before}s second=${after}s"
if [ "$before" != "$after" ]; then ok "response times differ (cache may be active)"; else echo "     note: identical timings — cache may not be engaging"; fi

# ---------------------------------------------------------------------------
hdr "8. Admin endpoint must be private"
c=$(timeout 5 bash -c "echo > /dev/tcp/${DOMAIN}/9901" 2>/dev/null && echo "open" || echo "closed")
if [ "$c" = "closed" ]; then ok "admin port 9901 not exposed"; else bad "ADMIN PORT IS PUBLIC — attackers can read your stats and change limits!"; fi

# ---------------------------------------------------------------------------
hdr "9. Live tuning works"
if curl -fsS -X POST "http://127.0.0.1:9901/runtime/static.edge_guard.ip_rate_limit?value=5" \
     >/dev/null 2>&1; then
  ok "runtime override accepted"
  curl -fsS -X POST "http://127.0.0.1:9901/runtime/static.edge_guard.ip_rate_limit?value=20" \
       >/dev/null 2>&1
else
  bad "cannot set runtime values — tune.sh will not work"
fi

# ---------------------------------------------------------------------------
echo
echo -e "\033[1;36m===== $pass passed, $fail failed =====\033[0m"
[ "$fail" -eq 0 ] || exit 1
