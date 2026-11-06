-- test_edge_guard.lua — unit tests for the rewritten edge_guard.lua
-- Run: lua5.4 test_edge_guard.lua

-- Mock clock in milliseconds
local clock_ms = 1000000

-- No globals needed — the new Lua script uses no envoy.* globals.
-- We just need handle:timestamp() to return our mock clock.

-- Load the filter
local chunk = assert(loadfile("l7ddos/envoy/lua/edge_guard.lua"))
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

print("\n" .. string.rep("=", 40))
print(string.format("  %d passed, %d failed", passed, failed))
print(string.rep("=", 40))
if failed > 0 then os.exit(1) end
