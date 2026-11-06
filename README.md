# Custom L7 DDoS Protection — POC

A self-hosted L7 protection edge. Envoy terminates TLS, runs a filter chain of
your own custom logic, and forwards to an origin that the outside world cannot
reach.

**No captcha. No managed CDN L7. You own the logic.**

---

## Architecture

```
Internet
   ↓
Magic Transit  (L3/L4 volumetric — your /24)
   ↓
[ Envoy :443 ]              ← THE EDGE
   │   tls_inspector          TLS/SNI + JA4 fingerprint (access log only)
   │   lua: edge_guard.lua    ← YOUR custom filtering logic
   │   local_ratelimit        per-connection backstop
   │   wasm: coraza           WAF + OWASP CRS
   │   cache                  in-memory GET cache
   │   router
   ↓
[ origin :8080 ]  127.0.0.1 only
```

The origin is bound to loopback and the firewall allows only 22/80/443. Nothing
can reach it except Envoy. **This is the load-bearing property of the whole
design** — if an attacker can hit the origin directly, everything else is
decoration.

---

## Layout

```
envoy/
  envoy.yaml            filter chain + listeners + clusters
  lua/edge_guard.lua    custom L7 logic  ← start reading here
  coraza/
    directives.conf     WAF engine behaviour
    rules.conf          custom rules + OWASP CRS include
origin/
  origin.py             minimal origin for testing
  site/index.html       the test site
scripts/
  install.sh            one-shot VPS setup
  tune.sh               change thresholds (edits Lua + restarts Envoy)
  test.sh               verifies each layer actually fires
test_edge_guard.lua     unit tests for the Lua filter (no Envoy needed)
```

### Running the unit tests

The Lua filter's logic is unit-tested against a mock of Envoy's Lua API, so
you can iterate on the filtering rules without deploying anything:

```bash
apt-get install -y lua5.4        # or brew install lua
lua5.4 test_edge_guard.lua
```

Expected output: `15 passed, 0 failed`. This is much faster than testing
through a live Envoy, and it's where you'll spend most of your time.

---

## Install

On your VPS (Debian/Ubuntu), as root:

```bash
git clone https://github.com/packetss/l7prot.git
cd l7prot
DOMAIN=your.domain.com ./scripts/install.sh
```

Then get a TLS cert:

```bash
DOMAIN=your.domain.com ./scripts/get-cert.sh
```

Add the cert to `envoy.yaml` under the listener's `transport_socket`, then:

```bash
systemctl restart l7ddos-envoy
DOMAIN=your.domain.com ./scripts/test.sh
```

`test.sh` should show all PASS. **If the "origin port 8080 is closed" check
fails, stop and fix that before anything else** — everything else depends on it.

---

## The interesting part: `edge_guard.lua`

This is where your protection actually lives. Currently it does:

| Check | Signal | Action |
|---|---|---|
| IP blocklist | per-worker table | 403 |
| UA blocklist | pattern match on `user-agent` | 403 |
| Per-IP rate limit | token bucket (per-worker) | 429 + `Retry-After` |
| Suspicion scoring | UA length + missing headers | 403 |

Thresholds are hardcoded constants at the top of the Lua file. Change them
with `tune.sh` which patches the file and restarts Envoy:

```bash
./scripts/tune.sh rate_limit 100 200    # 100 req/s per IP, burst 200
./scripts/tune.sh show
./scripts/tune.sh reset
```

The configurable values:

| Variable | Default | Meaning |
|---|---|---|
| `RATE_LIMIT_ENABLED` | true | master switch for rate limiting |
| `IP_RATE_LIMIT` | 20 | requests/sec per IP (per worker) |
| `IP_BURST` | 40 | bucket depth (burst tolerance) |
| `BLOCKLIST_ENABLED` | true | honour the IP blocklist |
| `UA_BLOCKLIST_ENABLED` | true | honour the UA blocklist |
| `SUSPICION_THRESHOLD` | 3 | combined score to block |

**Note on per-worker state:** Envoy runs one Lua VM per worker thread. Rate
limit buckets are NOT shared across workers, so effective per-IP limits are
multiplied by worker count. This is fine for L7 DDoS — you want
order-of-magnitude protection, not precise metering.

**JA4 fingerprinting** is computed by `tls_inspector` and available in access
logs via `%TLS_JA4_FINGERPRINT%`. It is NOT accessible from the Lua filter —
use it for offline log analysis and building reputation feeds.

### Things worth adding (and learning)

- **Per-ASN limits.** IP is cheap to spoof; getting an ASN with clean IPs is
  not. Needs an IP→ASN lookup table in `sharedDict`.
- **Per-endpoint limits.** `/api/login` deserves a much tighter limit than
  `/`. Currently only a WAF tag is set for those.
- **Adaptive thresholds.** Feed origin CPU/latency/5xx back into the edge and
  tighten limits automatically when the origin struggles.
- **JA4 reputation.** Count requests per JA4; a fingerprint doing 5k rps on
  one path is worth blocking even from 5k different IPs. This is the single
  most effective anti-bot signal you can build.
- **JS proof-of-work challenge.** Still no captcha, but costs the attacker
  real CPU per request. Served as a local reply from the Lua filter.

---

## What this is *not* yet

Being straight with you about the gaps:

1. **No distributed rate limiting.** The token buckets are per-worker Lua
   tables — not even shared across workers in one process, let alone across
   nodes. When you add a second node you need the `ratelimit` service + Valkey.
2. **The origin is on the same box as the edge.** A big enough L7 attack
   saturates CPU and hurts the origin too. Real deployments separate these.
3. **JA4 is trivially spoofable.** It is one signal among several, not a gate.
   Anyone who reads the spec can craft any fingerprint they want.
4. **No IP reputation feed.** The blocklist is empty until you populate it.
5. **Magic Transit still does the heavy lifting.** A true volumetric event
   (100s of Gbps) will exhaust your VPS long before Envoy can filter it. That
   is what your transit null-routing is for.

---

## Useful commands

```bash
# live stats (this is what the dashboard will read)
curl -s localhost:9901/stats | grep edge_guard

# edge log with JA4 per request
journalctl -u l7ddos-envoy -f | jq .

# all Envoy counters, for the future dashboard
curl -s localhost:9901/stats?format=json > /tmp/stats.json
curl -s localhost:9901/config_dump          # current live config
```

---

## Next steps, roughly in order

1. Get it running, `test.sh` green.
2. Put a real site behind it (replace `origin/site/`).
3. Tune thresholds against your real traffic baseline.
4. Add JA4 reputation scoring (highest-value custom filter).
5. Add per-endpoint rate limits.
6. Second edge node + Valkey + distributed ratelimit.
7. Move origin to a separate box over WireGuard.
8. Build the dashboard (stats endpoint is already there).

---

## Licence notes

Envoy, Coraza, and the OWASP CRS are all Apache 2.0. Your own code and config
are yours. If you later add Valkey, note that Redis moved to RSALv2/SSPL in
7.4 and AGPLv3 in 2024 — Valkey is the BSD-licensed drop-in fork.
