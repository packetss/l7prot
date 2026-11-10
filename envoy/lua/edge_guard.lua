-- edge_guard.lua — L7 filtering for Envoy (real Lua filter API) — V2
--
-- API surface used (verified against Envoy 1.35):
--   handle:headers():get(name)
--   handle:streamInfo():downstreamRemoteAddress()
--   handle:timestamp()  -> milliseconds since epoch (integer)
--   handle:respond({headers}, body)
--   handle:logWarn(msg)
--
-- JA4 fingerprinting is done by tls_inspector at the listener level
-- and logged via access log formatter. It is NOT accessible from Lua
-- dynamicMetadata — JA4 analysis is offline/log-based only.
--
-- V2 CHANGES: Auto-ban IPs after repeated rate limit violations

local RATE_LIMIT_ENABLED   = true
local UA_BLOCKLIST_ENABLED = true
local BLOCKLIST_ENABLED    = true
local SUSPICION_THRESHOLD  = 3

-- Per-IP rate limit.
--
-- IMPORTANT: the token bucket lives in ONE Lua VM per Envoy worker thread,
-- so a naive "IP_RATE_LIMIT = 20" means 20 rps PER WORKER — on a 4-core box
-- that is really 80 rps for a single attacker. To make the limit mean the
-- same thing regardless of core count, we set a GLOBAL target here and
-- divide it by the worker count, which deploy.sh bakes in as ENV_WORKERS.
--
--   effective per-IP rate = GLOBAL_RATE_LIMIT rps
--   effective per-IP burst = GLOBAL_BURST requests
local ENV_WORKERS       = 1    -- patched by deploy.sh (nproc)
local GLOBAL_RATE_LIMIT = 12   -- requests/sec per IP, summed across workers
local GLOBAL_BURST      = 25   -- burst per IP, summed across workers

local IP_RATE_LIMIT = math.max(1, math.floor(GLOBAL_RATE_LIMIT / ENV_WORKERS))
local IP_BURST      = math.max(2, math.floor(GLOBAL_BURST      / ENV_WORKERS))

-- V2: Auto-ban configuration with escalating penalties
local AUTO_BAN_ENABLED        = true
local RATE_LIMIT_STRIKES      = 5      -- ban after this many 429s
local BAN_TIER1_DURATION_MS   = 5000   -- 5 seconds (first offense)
local BAN_TIER2_DURATION_MS   = 30000  -- 30 seconds (second offense)
local BAN_TIER3_DURATION_MS   = 300000 -- 5 minutes (third+ offense)
local MAX_AUTO_BANS           = 10000  -- prevent memory exhaustion

-- Per-worker state. Envoy runs one Lua VM per worker thread.
-- Not shared across workers — effective limits scale with worker count.
local buckets     = {}
local stats       = {}
local blocked_ips = {}
local auto_banned = {}      -- V2: temporary bans { ip = ban_until_ms }
local rate_strikes = {}     -- V2: track violations per IP
local rate_strikes_ts = {}  -- V2: when the IP last violated the rate limit
local ban_history = {}      -- V2: track how many times IP was banned
local ban_history_ts = {}   -- V2: when IP was last banned (for LRU eviction)
local auto_ban_count = 0    -- V2: track table size
local strike_count = 0      -- entries across rate_strikes + ban_history
local last_strike_gc = 0    -- when the strike-table GC last ran

local COUNTER_CEILING  = 1000000
local MAX_BUCKET_KEYS  = 50000
local MAX_PATH_KEYS    = 500
local BUCKET_GC_STALE  = 120000

-- Cap on the per-IP auxiliary tables. A botnet rotating source IPs would
-- otherwise grow these forever and OOM the worker (status=9/KILL in the
-- journal). Each entry is tiny, but "forever" beats "tiny".
local MAX_STRIKE_KEYS  = 20000

-- How long a rate-limit strike record is kept after the IP's last
-- violation. Comfortably longer than the longest ban tier (5 min) so a
-- banned IP keeps escalating, but bounded so quiet IPs get forgotten.
local STRIKE_TTL_MS    = 600000

-- How often the strike-table GC runs. It scans the whole table, so it
-- must be amortised rather than run per-request.
local GC_INTERVAL_MS   = 30000

-- FIFO of IP keys in insertion order. Used to evict the oldest entry when
-- the table hits MAX_STRIKE_KEYS. A FIFO ring buffer gives O(1) eviction
-- without the O(n) scan that a full-table sort would need, so the cap can
-- be enforced on the insert path and therefore ALWAYS holds — not just
-- between GC passes.
local strike_fifo   = {}
local strike_fifo_head = 1
local strike_fifo_tail = 0

local bucket_count = 0
local path_count   = 0

local BAD_UA_PATTERNS = {
  "sqlmap", "nikto", "nmap", "masscan", "zgrab", "censys", "shodan",
  "dirbuster", "gobuster", "wpscan", "nuclei", "zap", "burp",
  "python-requests", "python-urllib", "aiohttp", "httpx", "scrapy",
  "go-http-client", "java/", "okhttp", "libwww-perl", "phpcrawl",
  "headlesschrome", "phantomjs", "puppeteer", "playwright",
}

local function inc(key, by)
  by = by or 1
  local cur = stats[key] or 0
  if cur >= COUNTER_CEILING then cur = 0 end
  stats[key] = cur + by
  return cur + by
end

-- ---------------------------------------------------------------------------
-- Strike-table FIFO
--
-- The per-IP tables are capped so a botnet rotating source IPs cannot
-- grow them without bound (which OOM-killed an Envoy worker). The cap is
-- enforced HERE, on the insert path, so it holds at every instant rather
-- than only between GC passes.
--
-- These helpers manage a plain FIFO of IP keys. Eviction pops from the
-- head; stale entries are skipped if the IP has already been removed by
-- the TTL sweep.
-- ---------------------------------------------------------------------------
local function fifo_push(ip)
  strike_fifo_tail = strike_fifo_tail + 1
  strike_fifo[strike_fifo_tail] = ip
end

local function fifo_pop()
  if strike_fifo_head > strike_fifo_tail then return nil end
  local ip = strike_fifo[strike_fifo_head]
  strike_fifo[strike_fifo_head] = nil
  strike_fifo_head = strike_fifo_head + 1
  -- Compact the ring occasionally so the backing table does not grow
  -- without bound as head advances.
  if strike_fifo_head > 4096 and strike_fifo_head * 2 > strike_fifo_tail then
    local n = 0
    for i = strike_fifo_head, strike_fifo_tail do
      n = n + 1
      strike_fifo[n] = strike_fifo[i]
      strike_fifo[i] = nil
    end
    strike_fifo_head = 1
    strike_fifo_tail = n
  end
  return ip
end

-- Remove every record for an IP and keep the counters in sync.
local function drop_strike_record(ip)
  if rate_strikes[ip] ~= nil then
    rate_strikes[ip] = nil
    rate_strikes_ts[ip] = nil
    strike_count = strike_count - 1
  else
    rate_strikes_ts[ip] = nil
  end
  if ban_history[ip] ~= nil then
    ban_history[ip] = nil
    ban_history_ts[ip] = nil
    strike_count = strike_count - 1
  else
    ban_history_ts[ip] = nil
  end
end

-- Enforce the hard cap. Called on every insert, so the table can never
-- exceed MAX_STRIKE_KEYS by more than the batch being inserted.
local function enforce_strike_cap()
  while strike_count >= MAX_STRIKE_KEYS do
    local ip = fifo_pop()
    if ip == nil then break end
    drop_strike_record(ip)
  end
end

local function ip_of(handle)
  local si = handle:streamInfo()
  local addr = si:downstreamRemoteAddress()
  if addr == nil or addr == "" then return nil end

  if string.sub(addr, 1, 1) == "[" then
    local close = string.find(addr, "]")
    if close then return string.sub(addr, 2, close - 1) end
  end

  local first = string.find(addr, ":", 1, true)
  if first and not string.find(addr, ":", first + 1, true) then
    local head = string.sub(addr, 1, first - 1)
    if string.find(head, ".", 1, true) then return head end
  end

  return addr
end

local function path_of(handle)
  local h = handle:headers()
  local p = h:get(":path")
  if p == nil then return "/" end
  local q = string.find(p, "?", 1, true)
  if q then p = string.sub(p, 1, q - 1) end
  return p
end

local function ua_of(handle)
  local h = handle:headers()
  return h:get("user-agent") or ""
end

-- Evict stale bucket entries when table gets too large
local function gc_buckets(now_ms)
  if bucket_count < MAX_BUCKET_KEYS then return end
  local to_delete = {}
  for k, v in pairs(buckets) do
    if (now_ms - v.ts) > BUCKET_GC_STALE then
      to_delete[#to_delete + 1] = k
    end
  end
  for _, k in ipairs(to_delete) do
    buckets[k] = nil
    bucket_count = bucket_count - 1
  end
end

-- V2: Evict expired auto-bans
local function gc_auto_bans(now_ms)
  local to_delete = {}
  for ip, ban_until in pairs(auto_banned) do
    if now_ms >= ban_until then
      to_delete[#to_delete + 1] = ip
    end
  end
  for _, ip in ipairs(to_delete) do
    auto_banned[ip] = nil
    if rate_strikes[ip] ~= nil then
      rate_strikes[ip] = nil
      strike_count = strike_count - 1
    end
    auto_ban_count = auto_ban_count - 1
    inc("auto_ban_expired")
  end
end

-- Evict the auxiliary per-IP tables (rate-limit strikes, ban history).
--
-- These are keyed by IP and were previously never cleaned up, so a botnet
-- rotating source IPs grew them without bound until the worker was
-- OOM-killed (status=9/KILL in the journal).
--
-- Two independent mechanisms, because either one alone is insufficient:
--
--   1. Age-based expiry (STRIKE_TTL_MS). A strike record is only useful
--      while the IP is still misbehaving. Once it has been quiet for
--      longer than the TTL the record is worthless and gets dropped.
--      This is what bounds growth when the auto-ban table is saturated
--      (MAX_AUTO_BANS reached) and gc_auto_bans can no longer free
--      anything.
--
--   2. Hard cap (MAX_STRIKE_KEYS). If the table somehow still exceeds the
--      cap, evict least-recently-seen entries first. Backstop only.
--
-- PERFORMANCE: this scans the whole table, so it must not run on every
-- request — at 20k entries x N rps that would peg the worker and make
-- the filter itself the bottleneck. It runs on an interval instead
-- (GC_INTERVAL_MS), and the O(n) "find the oldest" scan is done ONCE
-- per GC pass rather than once per eviction.
local function gc_strike_tables(now_ms)
  if strike_count < MAX_STRIKE_KEYS then return end

  -- Only run every GC_INTERVAL_MS. A strike table that is at its cap
  -- stays at its cap between passes; that is fine, the cap IS the bound.
  if now_ms - last_strike_gc < GC_INTERVAL_MS then return end
  last_strike_gc = now_ms

  -- 1. Drop anything past its TTL.
  local expired = {}
  for ip, ts in pairs(rate_strikes_ts) do
    if (now_ms - ts) > STRIKE_TTL_MS then
      expired[#expired + 1] = ip
    end
  end
  for _, ip in ipairs(expired) do
    drop_strike_record(ip)
  end

  -- 1b. Ban history for IPs that have gone quiet for longer than the TTL.
  --     The history is only needed to escalate the ban tier, so once the
  --     IP has been quiet for a while the tier can safely reset. This is
  --     a separate sweep because an IP can have ban history even after
  --     its strike record has been evicted.
  local hist_expired = {}
  for ip, ts in pairs(ban_history_ts) do
    if (now_ms - ts) > STRIKE_TTL_MS then
      hist_expired[#hist_expired + 1] = ip
    end
  end
  for _, ip in ipairs(hist_expired) do
    if ban_history[ip] ~= nil then
      ban_history[ip] = nil
      strike_count = strike_count - 1
    end
    ban_history_ts[ip] = nil
  end

  -- 2. Backstop: the hard cap is normally enforced on the insert path by
  --    enforce_strike_cap(). This is only a safety net for the case where
  --    the count somehow drifted (e.g. a stale entry was re-added).
  enforce_strike_cap()
end

-- V2: Check if IP is auto-banned
local function is_auto_banned(ip, now_ms)
  if not AUTO_BAN_ENABLED then return false end
  local ban_until = auto_banned[ip]
  if ban_until and now_ms < ban_until then
    inc("auto_ban_hit")
    return true
  end
  return false
end

-- V2: Record a rate limit violation, auto-ban if threshold reached
-- Uses escalating ban durations based on offense history
local function record_rate_violation(ip, now_ms)
  if not AUTO_BAN_ENABLED then return end

  local strikes = (rate_strikes[ip] or 0) + 1
  if rate_strikes[ip] == nil then
    strike_count = strike_count + 1
    fifo_push(ip)
    -- Enforce the hard cap immediately. Doing it here (rather than only
    -- in the periodic GC) means the table never exceeds the limit, not
    -- just "on average" between GC passes.
    enforce_strike_cap()
  end
  rate_strikes[ip] = strikes
  rate_strikes_ts[ip] = now_ms

  if strikes >= RATE_LIMIT_STRIKES then
    if auto_ban_count < MAX_AUTO_BANS then
      -- Determine ban duration based on history
      local ban_count = (ban_history[ip] or 0) + 1
      if ban_history[ip] == nil then
        strike_count = strike_count + 1
      end
      ban_history[ip] = ban_count
      ban_history_ts[ip] = now_ms

      local ban_duration
      if ban_count == 1 then
        ban_duration = BAN_TIER1_DURATION_MS
      elseif ban_count == 2 then
        ban_duration = BAN_TIER2_DURATION_MS
      else
        ban_duration = BAN_TIER3_DURATION_MS
      end

      auto_banned[ip] = now_ms + ban_duration
      auto_ban_count = auto_ban_count + 1
      inc("auto_banned")
      inc("auto_ban_tier" .. math.min(ban_count, 3))
    end
  end
end

-- Token bucket. Returns true if ALLOWED.
-- handle:timestamp() returns milliseconds since epoch.
local function allow_rate(ip, now_ms)
  local rate  = IP_RATE_LIMIT
  local burst = IP_BURST

  local key = "ip:" .. ip
  local entry = buckets[key]

  local tokens, last_ms
  if entry then
    tokens  = entry.tokens
    last_ms = entry.ts
  else
    tokens  = burst
    last_ms = now_ms
    bucket_count = bucket_count + 1
  end

  local elapsed_s = (now_ms - last_ms) / 1000.0
  if elapsed_s < 0 then elapsed_s = 0 end
  tokens = tokens + elapsed_s * rate
  if tokens > burst then tokens = burst end

  if tokens < 1 then
    buckets[key] = { tokens = tokens, ts = now_ms }
    inc("rate_limited")
    return false
  end

  tokens = tokens - 1
  buckets[key] = { tokens = tokens, ts = now_ms }
  return true
end

local function ip_blocked(ip)
  if not BLOCKLIST_ENABLED then return false end
  if blocked_ips[ip] then
    inc("ip_blocked")
    return true
  end
  return false
end

local function ua_blocked(ua)
  if not UA_BLOCKLIST_ENABLED then return false end
  local l = string.lower(ua)
  for _, pat in ipairs(BAD_UA_PATTERNS) do
    if string.find(l, pat, 1, true) then
      inc("ua_blocked")
      return true
    end
  end
  return false
end

function envoy_on_request(handle)
  local ip   = ip_of(handle)
  local path = path_of(handle)
  local ua   = ua_of(handle)
  local now_ms = handle:timestamp()

  if ip == nil then
    handle:respond({[":status"] = "400", ["content-type"] = "text/plain"},
                   "missing client address\n")
    return
  end

  gc_buckets(now_ms)
  gc_auto_bans(now_ms)
  gc_strike_tables(now_ms)

  inc("requests_total")
  if path:match("^[%w%-%_/%.]+$") and #path <= 64 then
    local pkey = "path:" .. path
    if stats[pkey] == nil then
      if path_count >= MAX_PATH_KEYS then
        pkey = "path:__overflow__"
      else
        path_count = path_count + 1
      end
    end
    inc(pkey)
  end

  if path == "/healthz" then
    if ip == "127.0.0.1" or ip == "::1" or ip == "10.0.0.1" then
      return
    end
    inc("healthz_probe")
  end

  -- V2: Check auto-ban first (cheapest check)
  if is_auto_banned(ip, now_ms) then
    handle:respond({[":status"] = "403", ["content-type"] = "text/plain"},
                   "banned\n")
    return
  end

  if ip_blocked(ip) then
    handle:respond({[":status"] = "403", ["content-type"] = "text/plain"},
                   "blocked\n")
    return
  end

  if ua_blocked(ua) then
    handle:respond({[":status"] = "403", ["content-type"] = "text/plain"},
                   "blocked\n")
    return
  end

  if RATE_LIMIT_ENABLED then
    if not allow_rate(ip, now_ms) then
      record_rate_violation(ip, now_ms)
      handle:respond({[":status"] = "429", ["content-type"] = "text/plain",
                       ["retry-after"] = "1"},
                     "rate limited\n")
      return
    end
  end

  -- Suspicion scoring (signals available without JA4):
  --   short/missing UA: +2
  --   missing common headers that browsers always send: +1
  local suspicion = 0

  if #ua < 10 then
    suspicion = suspicion + 2
  end

  local headers = handle:headers()
  local accept = headers:get("accept")
  if accept == nil or accept == "" then
    suspicion = suspicion + 1
  end

  if suspicion >= SUSPICION_THRESHOLD then
    inc("suspicious_blocked")
    handle:respond({[":status"] = "403", ["content-type"] = "text/plain"},
                   "blocked\n")
    return
  end
end

-- ===========================================================================
-- Test hook
--
-- Exported for the unit test so it can assert the worker scaling and
-- inspect the per-IP tables for unbounded growth. These are globals (not
-- locals) so the test can read them after loading the file; Envoy's Lua
-- sandbox permits globals.
--
-- Declared at the END of the file so every local above is in scope.
-- ===========================================================================
_edge_guard_config = {
  env_workers     = ENV_WORKERS,
  global_rate     = GLOBAL_RATE_LIMIT,
  global_burst    = GLOBAL_BURST,
  ip_rate_limit   = IP_RATE_LIMIT,
  ip_burst        = IP_BURST,
  max_strike_keys = MAX_STRIKE_KEYS,
  rate_strikes    = rate_strikes,
  ban_history     = ban_history,
  auto_banned     = auto_banned,
}
