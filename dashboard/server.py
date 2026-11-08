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

# In-memory event storage
recent_events = deque(maxlen=1000)
stats_cache = {"data": {}, "timestamp": 0}
ip_counters = defaultdict(int)
ja4_counters = defaultdict(int)


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


def tail_envoy_logs():
    """Tail Envoy logs and parse JSON events (threaded)"""
    while True:
        try:
            proc = subprocess.Popen(
                ["journalctl", "-u", "l7ddos-envoy", "-f", "--output=cat"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )

            for line in proc.stdout:
                try:
                    data = json.loads(line.strip())
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

                        # Track stats by status code
                        stats_cache.setdefault("requests_total", 0)
                        stats_cache["requests_total"] += 1

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

    # Top IPs
    top_ips = sorted(ip_counters.items(), key=lambda x: x[1], reverse=True)[:10]

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


async def logout(request):
    session = await aiohttp_session.get_session(request)
    session.clear()
    return web.HTTPFound("/dashboard/login")


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
