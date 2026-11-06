# Changelog

All notable changes to this project will be documented in this file.

## [v2.0.0] - 2026-11-06

### Added
- **Auto-ban feature with escalating penalties**: IPs are automatically banned after repeated rate limit violations
  - 1st offense: 5 seconds
  - 2nd offense: 30 seconds
  - 3rd+ offense: 5 minutes
  - Prevents resource exhaustion from persistent attackers
- New statistics counters:
  - `auto_banned` - Total IPs banned
  - `auto_ban_hit` - Requests blocked by active bans
  - `auto_ban_expired` - Bans that expired naturally
  - `auto_ban_tier1/2/3` - Ban counts by tier
- Ban expiration with automatic cleanup
- Memory protection with `MAX_AUTO_BANS` limit (10,000)
- Ban history tracking to determine escalation tier

### Changed
- Rate-limited IPs now tracked for violation strikes
- Auto-banned IPs get 403 (banned) instead of 429 (cheaper response)
- Added `gc_auto_bans()` function for automatic ban cleanup
- Ban duration escalates based on offense history

### Configuration
New tunable parameters in `edge_guard.lua`:
```lua
local AUTO_BAN_ENABLED        = true
local RATE_LIMIT_STRIKES      = 5      -- ban after this many 429s
local BAN_TIER1_DURATION_MS   = 5000   -- 5 seconds (first offense)
local BAN_TIER2_DURATION_MS   = 30000  -- 30 seconds (second offense)
local BAN_TIER3_DURATION_MS   = 300000 -- 5 minutes (third+ offense)
local MAX_AUTO_BANS           = 10000  -- prevent memory exhaustion
```

## [v1.0.0] - 2026-11-05

### Initial Release
- Envoy-based L7 DDoS protection edge
- Custom Lua filter with per-IP rate limiting
- User-agent pattern blocking
- IP blocklist support
- Suspicion scoring (UA length, missing headers)
- JA4 TLS fingerprinting (via access logs)
- Coraza WAF with OWASP CRS
- In-memory GET caching
- Single-node deployment scripts
- Self-signed certificate support for IP-based deployment
