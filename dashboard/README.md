# L7 Protection Dashboard

Real-time attack monitoring dashboard with live stats, event feeds, and attacker tracking.

## Features

- 🔐 **Password-protected login** (credentials set via environment variables)
- 📊 **Real-time statistics**: requests, blocks, rate limits, bans
- 🔴 **Live event feed**: streaming attacks as they happen
- 🌍 **Top attacker IPs**: see who's hitting you the most
- 🔒 **JA4 fingerprint tracking**: identify bot patterns
- 📈 **Auto-updating**: polls every 1-2 seconds
- 🛡️ **Protected by Envoy**: routes through your L7 protection edge

## Installation

On your VPS:

```bash
cd l7prot/dashboard
sudo ./install-dashboard.sh
```

Set your password:

```bash
sudo cp /etc/l7dashboard.env.example /etc/l7dashboard.env
sudo nano /etc/l7dashboard.env
# Set DASHBOARD_PASS=your-secure-password
```

Start the dashboard:

```bash
sudo systemctl start l7dashboard
sudo systemctl enable l7dashboard
```

**Restart Envoy** to enable the `/dashboard` route:

```bash
sudo systemctl restart l7ddos-envoy
```

## Access

The dashboard is exposed at `https://your-domain-or-ip/dashboard` and protected by:
- Your L7 edge filters (rate limiting, auto-bans)
- Dashboard login (username/password)

Just visit: **https://your-server/dashboard**

Login with credentials from `/etc/l7dashboard.env`

## Environment Variables

Set in `/etc/l7dashboard.env`:

- `DASHBOARD_USER` - Login username (default: `admin`)
- `DASHBOARD_PASS` - Login password (**required**, no default)
- `DASHBOARD_SECRET` - Session encryption key (auto-generated if not set)

## Security Notes

- Dashboard runs on `127.0.0.1` only (not exposed to internet)
- Uses encrypted session cookies
- No credentials stored in code or git repo
- Access via SSH tunnel recommended for remote monitoring
- If using reverse proxy, enable IP whitelisting

## What You'll See

### Stats Cards
- Total requests
- Successful requests (200)
- Blocked requests (403)
- Rate limited requests (429)
- Auto-banned IPs

### Live Event Feed
Real-time stream showing:
- Timestamp
- Attacker IP
- HTTP status code
- Request method/URI
- Color-coded by status (green=success, red=blocked/limited)

### Top Lists
- **Top Attacker IPs**: Which IPs are hitting you the most
- **Top JA4 Fingerprints**: Most common TLS fingerprints (bot identification)

## Monitoring

Check dashboard status:
```bash
sudo systemctl status l7dashboard
sudo journalctl -u l7dashboard -f
```

## Troubleshooting

**Dashboard won't start:**
```bash
# Check if DASHBOARD_PASS is set
sudo cat /etc/l7dashboard.env | grep DASHBOARD_PASS

# Check logs
sudo journalctl -u l7dashboard -n 50
```

**Can't login:**
- Verify credentials in `/etc/l7dashboard.env`
- Restart dashboard: `sudo systemctl restart l7dashboard`

**No events showing:**
- Ensure `l7ddos-envoy` is running
- Check if events are in journal: `sudo journalctl -u l7ddos-envoy -n 10`

---

Built with Python (aiohttp), reads from Envoy admin API + systemd journal.
