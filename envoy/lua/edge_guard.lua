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
local IP_RATE_LIMIT        = 20
local IP_BURST             = 40
local UA_BLOCKLIST_ENABLED = true
local BLOCKLIST_ENABLED    = true
local SUSPICION_THRESHOLD  = 3

-- V2: Auto-ban configuration
local AUTO_BAN_ENABLED        = true
local RATE_LIMIT_STRIKES      = 5      -- ban after this many 429s
local AUTO_BAN_DURATION_MS    = 300000 -- 5 minutes
local MAX_AUTO_BANS           = 10000  -- prevent memory exhaustion

-- Per-worker state. Envoy runs one Lua VM per worker thread.
-- Not shared across workers — effective limits scale with worker count.
local buckets     = {}
local stats       = {}
local blocked_ips = {}
local auto_banned = {}      -- V2: temporary bans
local rate_strikes = {}     -- V2: track violations per IP
local auto_ban_count = 0    -- V2: track table size

local COUNTER_CEILING  = 1000000
local MAX_BUCKET_KEYS  = 50000
local MAX_PATH_KEYS    = 500
local BUCKET_GC_STALE  = 120000

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
    rate_strikes[ip] = nil
    auto_ban_count = auto_ban_count - 1
    inc("auto_ban_expired")
  end
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
local function record_rate_violation(ip, now_ms)
  if not AUTO_BAN_ENABLED then return end

  local strikes = (rate_strikes[ip] or 0) + 1
  rate_strikes[ip] = strikes

  if strikes >= RATE_LIMIT_STRIKES then
    if auto_ban_count < MAX_AUTO_BANS then
      auto_banned[ip] = now_ms + AUTO_BAN_DURATION_MS
      auto_ban_count = auto_ban_count + 1
      inc("auto_banned")
      handle:logWarn("Auto-banned IP " .. ip .. " for " .. (AUTO_BAN_DURATION_MS/1000) .. "s after " .. strikes .. " violations")
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
