#!/usr/bin/env python3
"""
L7 Protection Dashboard - Real-time attack monitoring
Reads from Envoy admin API and journal logs
"""

import os
import json
import time
import asyncio
import subprocess
import threading
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path

from aiohttp import web
import aiohttp_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from cryptography import fernet
import requests

# Auth credentials from environment
DASHBOARD_USER = os.getenv("DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.getenv("DASHBOARD_PASS")  # MUST be set
SECRET_KEY = os.getenv("DASHBOARD_SECRET", fernet.Fernet.generate_key().decode())

if not DASHBOARD_PASS:
    print("ERROR: DASHBOARD_PASS environment variable not set!")
    print("Set it with: export DASHBOARD_PASS='your-secure-password'")
    exit(1)

ENVOY_ADMIN = "http://127.0.0.1:9901"
STATS_CACHE_SECONDS = 2

# Persistent stats file — cumulative counters survive restarts.
# Defaults to the dashboard's own directory (the dashboard service runs as
# l7dashboard with ReadWritePaths=/opt/l7dashboard).
STATS_FILE = Path(os.getenv("DASHBOARD_STATS_FILE", "/opt/l7dashboard/stats.json"))
STATS_SAVE_INTERVAL = 5  # seconds between counter flushes to disk

# In-memory event storage
recent_events = deque(maxlen=1000)
stats_cache = {"data": {}, "timestamp": 0}
ip_counters = defaultdict(int)  # all requests
attacker_ip_counters = defaultdict(int)  # only 403/429
ja4_counters = defaultdict(int)

# Track hourly blocked requests with timestamps
hourly_blocked_events = deque()  # stores (timestamp, is_blocked) tuples

# Track peak values
peak_history_1min = deque()  # stores (timestamp, allowed_rps, blocked_rps) tuples
peak_history_1hour = deque()  # stores (timestamp, allowed_rps, blocked_rps) tuples

# Counters that persist across restarts
PERSISTED_COUNTERS = [
    "requests_total",
    "success_2xx",
    "ip_blocked",
    "ua_blocked",
    "suspicious_blocked",
    "rate_limited",
    "auto_banned",
    "peak_allowed_1min",
    "peak_blocked_1min",
    "peak_allowed_1hour",
    "peak_blocked_1hour",
]


def load_persisted_stats():
    """Load cumulative counters from disk so totals survive restarts"""
    try:
        if not STATS_FILE.exists():
            return {}
        with open(STATS_FILE, "r") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {}
        return {k: int(data.get(k, 0)) for k in PERSISTED_COUNTERS}
    except Exception as e:
        print(f"Could not load persisted stats: {e}")
        return {}


def save_persisted_stats():
    """Flush cumulative counters to disk"""
    try:
        STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {k: stats_cache.get(k, 0) for k in PERSISTED_COUNTERS}
        # Write to temp then rename so a crash mid-write can't corrupt the file
        tmp = STATS_FILE.with_suffix(".tmp")
        with open(tmp, "w") as fh:
            json.dump(data, fh)
        tmp.replace(STATS_FILE)
    except Exception as e:
        print(f"Could not save persisted stats: {e}")


async def get_envoy_stats():
    """Fetch stats from Envoy admin API with caching"""
    now = time.time()
    if now - stats_cache["timestamp"] < STATS_CACHE_SECONDS:
        return stats_cache["data"]

    try:
        resp = requests.get(f"{ENVOY_ADMIN}/stats?format=json", timeout=1)
        data = resp.json()

        # Parse relevant stats
        parsed = {
            "requests_total": 0,
            "rate_limited": 0,
            "auto_banned": 0,
            "auto_ban_hit": 0,
            "ip_blocked": 0,
            "ua_blocked": 0,
            "suspicious_blocked": 0,
        }

        for stat in data.get("stats", []):
            name = stat.get("name", "")
            value = stat.get("value", 0)

            if "http.https_edge" in name:
                if "downstream_rq_total" in name:
                    parsed["requests_total"] = value
                elif "downstream_rq_2xx" in name:
                    parsed["success_2xx"] = value
                elif "downstream_rq_4xx" in name:
                    parsed["client_errors_4xx"] = value
                elif "downstream_rq_5xx" in name:
                    parsed["server_errors_5xx"] = value

        stats_cache["data"] = parsed
        stats_cache["timestamp"] = now
        return parsed
    except Exception as e:
        print(f"Failed to fetch stats: {e}")
        return stats_cache.get("data", {})


_tailer_proc = None  # Global handle for cleanup

def calculate_peak_values():
    """Calculate and persist peak RPS for 1min and 1hour windows"""
    last_total = 0
    last_time = time.time()

    while True:
        time.sleep(5)
        try:
            now = time.time()
            elapsed = now - last_time

            if elapsed > 0:
                current_total = stats_cache.get("requests_total", 0)
                rps = int((current_total - last_total) / elapsed)

                last_total = current_total
                last_time = now

                # Track 1min peaks
                peak_history_1min.append((now, rps))
                cutoff_1min = now - 60
                while peak_history_1min and peak_history_1min[0][0] < cutoff_1min:
                    peak_history_1min.popleft()

                # Track 1hour peaks
                peak_history_1hour.append((now, rps))
                cutoff_1hour = now - 3600
                while peak_history_1hour and peak_history_1hour[0][0] < cutoff_1hour:
                    peak_history_1hour.popleft()

                if peak_history_1min:
                    stats_cache["peak_rps_1min"] = max(entry[1] for entry in peak_history_1min)

                if peak_history_1hour:
                    stats_cache["peak_rps_1hour"] = max(entry[1] for entry in peak_history_1hour)

        except Exception as e:
            print(f"Peak calculation error: {e}", flush=True)


def prune_old_events():
    """Remove events older than 1 hour (runs every 10 minutes)"""
    while True:
        time.sleep(600)  # 10 minutes
        try:
            cutoff_timestamp = time.time() - 3600  # 1 hour ago
            old_len = len(recent_events)

            # Filter events: keep only those newer than cutoff
            filtered = []
            for e in list(recent_events):
                try:
                    # Parse ISO timestamp from event
                    event_time = datetime.fromisoformat(e["ts"].replace("Z", "+00:00")).timestamp()
                    if event_time > cutoff_timestamp:
                        filtered.append(e)
                except (ValueError, KeyError):
                    # Keep events with unparseable timestamps
                    filtered.append(e)

            recent_events.clear()
            recent_events.extend(filtered)
            pruned = old_len - len(recent_events)
            if pruned > 0:
                print(f"Pruned {pruned} events older than 1 hour", flush=True)
        except Exception as e:
            print(f"Event pruning error: {e}", flush=True)


def tail_envoy_logs():
    """Tail Envoy logs and parse JSON events (threaded)"""
    global _tailer_proc

    # Seed counters from disk so cumulative totals survive restarts
    persisted = load_persisted_stats()
    for key, value in persisted.items():
        stats_cache[key] = value
    print(f"Loaded persisted stats: {persisted}", flush=True)

    # Start pruning thread
    prune_thread = threading.Thread(target=prune_old_events, daemon=True)
    prune_thread.start()

    # Start peak calculation thread
    peak_thread = threading.Thread(target=calculate_peak_values, daemon=True)
    peak_thread.start()

    last_save = time.time()

    while True:
        proc = None
        try:
            proc = subprocess.Popen(
                ["journalctl", "-u", "l7ddos-envoy", "-f", "--output=cat"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            _tailer_proc = proc

            for line in proc.stdout:
                try:
                    # Flush counters to disk periodically
                    if time.time() - last_save >= STATS_SAVE_INTERVAL:
                        save_persisted_stats()
                        last_save = time.time()

                    data = json.loads(line.strip())
                    # Skip dashboard API calls from event feed
                    uri = data.get("uri", "")
                    if uri.startswith("/dashboard/api/") or uri.startswith("/api/"):
                        continue
                    if "status" in data and "ip" in data:
                        status = data.get("status")
                        ip = data["ip"].split(":")[0]

                        event = {
                            "ts": data.get("ts", ""),
                            "ip": ip,
                            "status": status,
                            "method": data.get("method", ""),
                            "uri": data.get("uri", ""),
                            "ua": data.get("ua", "")[:50] if data.get("ua") else None,
                            "ja4": data.get("ja4", "")[:20],
                        }
                        recent_events.append(event)

                        # Update counters
                        ip_counters[ip] += 1
                        if event["ja4"]:
                            ja4_counters[event["ja4"]] += 1

                        # Only count as attacker if blocked or rate limited
                        if status in (403, 429):
                            attacker_ip_counters[ip] += 1

                        # Track stats by status code
                        stats_cache.setdefault("requests_total", 0)
                        stats_cache["requests_total"] += 1

                        # Track for hourly blocked count (rolling window)
                        now_ts = time.time()
                        is_blocked = status in (403, 429)
                        hourly_blocked_events.append((now_ts, is_blocked))

                        # Prune hourly events older than 1 hour
                        hourly_cutoff = now_ts - 3600
                        while hourly_blocked_events and hourly_blocked_events[0][0] < hourly_cutoff:
                            hourly_blocked_events.popleft()

                        if status == 200:
                            stats_cache.setdefault("success_2xx", 0)
                            stats_cache["success_2xx"] += 1
                        elif status == 403:
                            stats_cache.setdefault("ip_blocked", 0)
                            stats_cache["ip_blocked"] += 1
                        elif status == 429:
                            stats_cache.setdefault("rate_limited", 0)
                            stats_cache["rate_limited"] += 1

                        # Check for auto-ban in flags
                        flags = data.get("flags", "")
                        if "banned" in flags.lower():
                            stats_cache.setdefault("auto_banned", 0)
                            stats_cache["auto_banned"] += 1

                except (json.JSONDecodeError, KeyError, ValueError):
                    pass

        except Exception as e:
            print(f"Log tailer error: {e}, restarting in 5s...")
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except:
                    proc.kill()
            time.sleep(5)


# Web handlers
async def login_page(request):
    return web.Response(text="""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>L7 Protection - Login</title>
<style>
body { margin:0; font-family: system-ui; background: #0d1117; color: #e6edf3; display: flex; align-items: center; justify-content: center; height: 100vh; }
.login-box { background: #161b22; padding: 2rem; border-radius: 8px; border: 1px solid #30363d; max-width: 320px; width: 100%; }
h1 { margin: 0 0 1.5rem; font-size: 1.5rem; text-align: center; }
input { width: 100%; padding: 0.75rem; margin-bottom: 1rem; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 1rem; box-sizing: border-box; }
button { width: 100%; padding: 0.75rem; background: #238636; border: none; border-radius: 6px; color: white; font-size: 1rem; font-weight: 600; cursor: pointer; }
button:hover { background: #2ea043; }
.error { color: #f85149; margin-bottom: 1rem; text-align: center; }
</style>
</head>
<body>
<div class="login-box">
<h1>🛡️ L7 Protection</h1>
<form method="POST" action="/dashboard/login">
<input type="text" name="username" placeholder="Username" required autofocus>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Login</button>
</form>
</div>
</body>
</html>
""", content_type="text/html")


async def login_post(request):
    data = await request.post()
    username = data.get("username", "")
    password = data.get("password", "")

    if username == DASHBOARD_USER and password == DASHBOARD_PASS:
        session = await aiohttp_session.get_session(request)
        session["authenticated"] = True
        return web.HTTPFound("/dashboard")

    return web.Response(text="Invalid credentials", status=401)


async def require_auth(request):
    session = await aiohttp_session.get_session(request)
    if not session.get("authenticated"):
        raise web.HTTPFound("/dashboard/login")


async def dashboard(request):
    await require_auth(request)
    html_path = Path(__file__).parent / "dashboard.html"
    return web.FileResponse(html_path)


async def api_stats(request):
    await require_auth(request)

    # Use stats tracked from logs, not Envoy admin API
    stats = {
        "requests_total": stats_cache.get("requests_total", 0),
        "success_2xx": stats_cache.get("success_2xx", 0),
        "ip_blocked": stats_cache.get("ip_blocked", 0),
        "ua_blocked": stats_cache.get("ua_blocked", 0),
        "suspicious_blocked": stats_cache.get("suspicious_blocked", 0),
        "rate_limited": stats_cache.get("rate_limited", 0),
        "auto_banned": stats_cache.get("auto_banned", 0),
    }

    # Top attacker IPs (only 403/429)
    top_ips = sorted(attacker_ip_counters.items(), key=lambda x: x[1], reverse=True)[:10]

    # Top JA4s
    top_ja4 = sorted(ja4_counters.items(), key=lambda x: x[1], reverse=True)[:10]

    return web.json_response({
        "stats": stats,
        "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "top_ja4": [{"ja4": ja4, "count": count} for ja4, count in top_ja4],
        "timestamp": int(time.time())
    })


async def api_events(request):
    await require_auth(request)
    return web.json_response(list(recent_events)[-100:])


async def api_public_stats(request):
    """Public stats endpoint - no auth required.

    Reads the in-memory counters maintained by the log tailer thread.
    Deliberately does NOT scan the journal: that blocked the event loop
    and, as the journal grew, made every response take tens of seconds.
    """
    now = time.time()

    # Calculate hourly counts from events in the last hour
    hourly_cutoff = now - 3600
    hourly_blocked = sum(1 for ts, is_blocked in hourly_blocked_events if ts > hourly_cutoff and is_blocked)
    hour_total = sum(1 for ts, _ in hourly_blocked_events if ts > hourly_cutoff)

    # Get peak values from persisted stats
    peak_allowed_1min = stats_cache.get("peak_allowed_1min", 0)
    peak_blocked_1min = stats_cache.get("peak_blocked_1min", 0)
    peak_allowed_1hour = stats_cache.get("peak_allowed_1hour", 0)
    peak_blocked_1hour = stats_cache.get("peak_blocked_1hour", 0)

    return web.json_response(
        {
            "stats": {
                "requests_total": stats_cache.get("requests_total", 0),
                "success_2xx": stats_cache.get("success_2xx", 0),
                "ip_blocked": stats_cache.get("ip_blocked", 0),
                "ua_blocked": stats_cache.get("ua_blocked", 0),
                "suspicious_blocked": stats_cache.get("suspicious_blocked", 0),
                "rate_limited": stats_cache.get("rate_limited", 0),
                "auto_banned": stats_cache.get("auto_banned", 0),
                "hourly_blocked": hourly_blocked,
                "hour_total": hour_total,
                "peak_allowed_1min": peak_allowed_1min,
                "peak_blocked_1min": peak_blocked_1min,
                "peak_allowed_1hour": peak_allowed_1hour,
                "peak_blocked_1hour": peak_blocked_1hour,
            }
        },
        headers={"Cache-Control": "no-store"},
    )


async def logout(request):
    session = await aiohttp_session.get_session(request)
    session.clear()
    response = web.HTTPFound("/dashboard/login")
    response.del_cookie('AIOHTTP_SESSION')
    return response


def create_app():
    app = web.Application()

    # Setup encrypted sessions
    aiohttp_session.setup(app, EncryptedCookieStorage(SECRET_KEY.encode()[:32]))

    # Routes
    app.router.add_get("/dashboard/login", login_page)
    app.router.add_post("/dashboard/login", login_post)
    app.router.add_get("/dashboard/logout", logout)
    app.router.add_get("/dashboard", dashboard)
    app.router.add_get("/dashboard/", dashboard)
    app.router.add_get("/dashboard/api/stats", api_stats)
    app.router.add_get("/dashboard/api/events", api_events)
    # Also expose API routes without /dashboard prefix (for Envoy routing)
    app.router.add_get("/api/stats", api_stats)
    app.router.add_get("/api/events", api_events)
    # Public stats endpoint (no auth)
    app.router.add_get("/api/public-stats", api_public_stats)

    # Start log tailer in background thread (non-blocking)
    async def start_background_tasks(app):
        thread = threading.Thread(target=tail_envoy_logs, daemon=True)
        thread.start()

    app.on_startup.append(start_background_tasks)

    return app


if __name__ == "__main__":
    print(f"Starting dashboard on http://127.0.0.1:8888")
    print(f"Login: {DASHBOARD_USER} / [DASHBOARD_PASS from env]")
    web.run_app(create_app(), host="127.0.0.1", port=8888)
