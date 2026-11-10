-- test_edge_guard.lua — unit tests for the rewritten edge_guard.lua
-- Run: lua5.4 test_edge_guard.lua

-- Mock clock in milliseconds
local clock_ms = 1000000

-- No globals needed — the new Lua script uses no envoy.* globals.
-- We just need handle:timestamp() to return our mock clock.

-- Load the filter
local chunk = assert(loadfile("envoy/lua/edge_guard.lua"))
chunk()

-- Mock request handle
local function make_handle(opts)
  local headers = opts.headers or {}
  headers[":path"] = opts.path or "/"
  headers["user-agent"] = opts.ua or "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"
  if opts.accept ~= nil then
    headers["accept"] = opts.accept
  elseif headers["accept"] == nil then
    headers["accept"] = "text/html,application/xhtml+xml"
  end

  local h = {}
  h.headers = function()
    return { get = function(_, k) return headers[k] end }
  end
  h.streamInfo = function()
    return {
      downstreamRemoteAddress = function() return opts.ip or "203.0.113.10" end,
    }
  end
  h.timestamp = function() return clock_ms end
  h.respond = function(_, hdrs, body)
    h.response_status = tonumber(hdrs[":status"])
    h.response_body = body
    h.responded = true
  end
  h.logWarn = function() end
  return h
end

-- Test harness
local passed, failed = 0, 0

local function check(name, cond, detail)
  if cond then
    passed = passed + 1
    print("  PASS  " .. name)
  else
    failed = failed + 1
    print("  FAIL  " .. name .. (detail and ("  [" .. detail .. "]") or ""))
  end
end

local function status_of(opts)
  local h = make_handle(opts)
  envoy_on_request(h)
  return h.response_status, h
end

print("\n== rate limiting ==")
local s = status_of({ ip = "198.51.100.1" })
check("first request allowed", s == nil, "got " .. tostring(s))

local saw429 = false
for i = 1, 100 do
  local st = status_of({ ip = "198.51.100.2" })
  if st == 429 then saw429 = true break end
end
check("rate limit produces 429", saw429)

clock_ms = clock_ms + 2000
local allowed = 0
for i = 1, 10 do
  local st = status_of({ ip = "198.51.100.3" })
  if st == nil then allowed = allowed + 1 end
end
check("bucket refills over time", allowed > 0, "allowed=" .. allowed)

print("\n== worker-count scaling ==")
-- The token bucket is per-worker, so the Lua file divides its global target
-- by ENV_WORKERS. Verify the per-worker values are what we expect and that
-- the effective global limit stays within a sensible band.
local cfg = _edge_guard_config
check("config exported", cfg ~= nil)
if cfg then
  check("ENV_WORKERS is set", cfg.env_workers ~= nil and cfg.env_workers >= 1,
        "tostring=" .. tostring(cfg.env_workers))
  check("GLOBAL_RATE_LIMIT is set", cfg.global_rate ~= nil and cfg.global_rate > 0)
  check("GLOBAL_BURST is set", cfg.global_burst ~= nil and cfg.global_burst > 0)

  local expect_rate  = math.max(1, math.floor(cfg.global_rate  / cfg.env_workers))
  local expect_burst = math.max(2, math.floor(cfg.global_burst / cfg.env_workers))
  check("per-worker rate matches global/workers",
        cfg.ip_rate_limit == expect_rate,
        "got " .. tostring(cfg.ip_rate_limit) .. " want " .. tostring(expect_rate))
  check("per-worker burst matches global/workers",
        cfg.ip_burst == expect_burst,
        "got " .. tostring(cfg.ip_burst) .. " want " .. tostring(expect_burst))

  local eff = cfg.ip_rate_limit * cfg.env_workers
  check("effective global rate stays near target",
        eff <= cfg.global_rate + cfg.env_workers,
        "effective=" .. tostring(eff) .. " target=" .. tostring(cfg.global_rate))

  -- A single IP must not be able to exceed the global burst, whatever
  -- the core count.
  check("effective burst is bounded", cfg.ip_burst * cfg.env_workers <= cfg.global_burst + cfg.env_workers,
        "effective=" .. tostring(cfg.ip_burst * cfg.env_workers) .. " target=" .. tostring(cfg.global_burst))
end

print("\n== UA blocking ==")
check("sqlmap blocked", status_of({ ip = "10.0.0.1", ua = "sqlmap/1.7" }) == 403)
check("python-requests blocked", status_of({ ip = "10.0.0.2", ua = "python-requests/2.31" }) == 403)
check("headlesschrome blocked", status_of({ ip = "10.0.0.3", ua = "Mozilla/5.0 HeadlessChrome/120" }) == 403)
check("normal chrome allowed", status_of({ ip = "10.0.0.4", ua = "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36" }) == nil)
check("curl allowed", status_of({ ip = "10.0.0.5", ua = "curl/8.0.0" }) == nil)

print("\n== IP blocklist ==")
-- blocked_ips is a module-level local in edge_guard.lua — we can't
-- access it directly. Instead test via the public API: the IP blocklist
-- is empty by default so no IPs are blocked. This test verifies the
-- blocklist check path doesn't error.
local st_clean = status_of({ ip = "203.0.113.99" })
check("unknown IP not blocked", st_clean == nil, "got " .. tostring(st_clean))

print("\n== healthz bypass ==")
local st = status_of({ ip = "127.0.0.1", path = "/healthz", ua = "", accept = "" })
check("healthz from loopback passes", st == nil, "got " .. tostring(st))

local st2 = status_of({ ip = "203.0.113.55", path = "/healthz", ua = "sqlmap/1.7" })
check("healthz from outside blocked by UA", st2 == 403, "got " .. tostring(st2))

print("\n== suspicion scoring ==")
-- short UA (+2) + missing accept (+1) = 3 -> blocked
local st3 = status_of({ ip = "10.0.1.1", ua = "x", accept = "" })
check("short UA + no accept -> blocked", st3 == 403, "got " .. tostring(st3))

-- short UA (+2) + has accept (+0) = 2 -> allowed
local st4 = status_of({ ip = "10.0.1.2", ua = "x", accept = "text/html" })
check("short UA + has accept -> allowed", st4 == nil, "got " .. tostring(st4))

-- normal UA (+0) + no accept (+1) = 1 -> allowed
local st5 = status_of({ ip = "10.0.1.3", ua = "Mozilla/5.0 Chrome/120", accept = "" })
check("normal UA + no accept -> allowed", st5 == nil, "got " .. tostring(st5))

print("\n== misc ==")
check("missing IP -> 400", status_of({ ip = "" }) == 400)

print("\n== memory growth (botnet rotating source IPs) ==")
-- Regression test: the per-IP auxiliary tables (rate-limit strikes and ban
-- history) used to grow without bound, and a botnet rotating source IPs
-- OOM-killed the Envoy worker (observed: status=9/KILL in the journal).
--
-- Hammer the filter with many distinct IPs, each tripping the rate limit,
-- then confirm the tables got cleaned back down instead of accumulating.
local function count_keys(t)
  local n = 0
  for _ in pairs(t) do n = n + 1 end
  return n
end

-- Does the filter expose its internals for inspection?
local probe = status_of({ ip = "198.18.0.1" })
local rate_strikes = cfg and cfg.rate_strikes or {}
local ban_history  = cfg and cfg.ban_history or {}
local MAX_STRIKE_KEYS = cfg and cfg.max_strike_keys or 20000

local before_strikes = count_keys(rate_strikes)
local before_history = count_keys(ban_history)

-- Hammer the filter with many distinct IPs, each tripping the rate limit,
-- which populates rate_strikes and ban_history.
--
-- The burst is IP_BURST tokens, so we need more than that to trigger a 429,
-- and more than RATE_LIMIT_STRIKES 429s to trigger an auto-ban. Send
-- burst+strikes+5 requests to be safely past both thresholds.
--
-- We deliberately drive past MAX_STRIKE_KEYS: the invariant being tested
-- is that the tables are CAPPED, not that they stay small.
local requests_per_ip = (cfg and cfg.ip_burst or 25) + 10
local num_ips = (cfg and cfg.max_strike_keys or 20000) + 5000
for i = 1, num_ips do
  -- Spread across the 3rd and 4th octets so every IP is genuinely distinct.
  local ip = string.format("198.%d.%d.%d",
    math.floor(i / 65536) % 256,
    math.floor(i / 256) % 256,
    i % 256)
  for _ = 1, requests_per_ip do
    status_of({ ip = ip })
  end
end

local after_strikes = count_keys(rate_strikes)
local after_history = count_keys(ban_history)

-- The tables must never exceed the hard cap, no matter how many distinct
-- source IPs hit us.
check("strike table stays under the cap",
      after_strikes <= MAX_STRIKE_KEYS,
      "after=" .. tostring(after_strikes) .. " cap=" .. tostring(MAX_STRIKE_KEYS))
check("ban history stays under the cap",
      after_history <= MAX_STRIKE_KEYS,
      "after=" .. tostring(after_history) .. " cap=" .. tostring(MAX_STRIKE_KEYS))
check("total auxiliary entries stay bounded",
      (after_strikes + after_history) <= 2 * MAX_STRIKE_KEYS,
      "total=" .. tostring(after_strikes + after_history))

-- The TTL path: once the offending IPs go quiet for longer than the
-- strike TTL, their records should be reclaimed. This is the mechanism
-- that bounds growth when the auto-ban table is saturated and
-- gc_auto_bans can no longer free anything.
clock_ms = clock_ms + 900000   -- 15 minutes
status_of({ ip = "203.0.113.200" })   -- any request triggers a GC pass

local ttl_strikes = count_keys(rate_strikes)
local ttl_history = count_keys(ban_history)
check("stale strike records are reclaimed after the TTL",
      ttl_strikes < after_strikes,
      "before=" .. tostring(after_strikes) .. " after=" .. tostring(ttl_strikes))
check("stale ban history is reclaimed after the TTL",
      ttl_history < after_history,
      "before=" .. tostring(after_history) .. " after=" .. tostring(ttl_history))

print("\n" .. string.rep("=", 40))
print(string.format("  %d passed, %d failed", passed, failed))
print(string.rep("=", 40))
if failed > 0 then os.exit(1) end
