# Complete Architecture Guide: Leak-Free AI & Gemini Geo-Unblocking on Windows

## 1. Overview & Threat Model

In geo-restricted regions (such as the Russian Federation), accessing generative AI platforms encounters two distinct layers of blocking:

1. **DNS-level censorship & ISP filtering**: Deep Packet Inspection (DPI) inspects plaintext DNS queries on port 53 and TCP SNI headers.
2. **Upstream Application Geoblocking**:
   - Services like ChatGPT, Claude, and Perplexity check client IP geolocation.
   - **Google Gemini & Google Accounts enforce strict anti-abuse rules**:
     - Generic reverse-proxy services (such as public unblock DNS resolvers) terminate TLS and forward the client request with an `X-Forwarded-For: <real_client_ip>` header. Google inspects this header, detects the domestic IP, and issues a block page: `Our systems have detected unusual traffic... IP: <Client-IP> and <Proxy-IP>`.
     - Connecting to different Google subdomains from different egress IPs during the same browser session (e.g., searching Google directly while chatting with Gemini through rotating proxies) triggers session invalidation and yields frontend runtime errors (such as **"Something went wrong. (1)"**).

### The Solution Architecture
- **Layer 1 (SmartDNS on Windows)**: Resolves non-Google AI domains (`chatgpt.com`, `claude.ai`, etc.) via encrypted DNS-over-HTTPS (DoH) targeting specialized unblocking resolvers, while routing all standard queries via encrypted DNS-over-TLS (DoT to Cloudflare/Quad9).
- **Layer 2 (Local Sticky PAC Egress Proxy on Windows)**: A lightweight Python background daemon (`127.0.0.1:8888`) implementing pure HTTP `CONNECT` tunneling.
  - Transparently fetches healthy public foreign HTTP/HTTPS proxies.
  - Enforces **Sticky Sessions** (holding a single reliable foreign egress IP per browsing session to prevent session invalidation).
  - Pure `CONNECT` byte-streaming guarantees no `X-Forwarded-For` injection.
- **Layer 3 (Chromium Enterprise Registry Policy)**: Chrome/Edge automatically queries `http://127.0.0.1:8888/pac`, sending all Google, Gemini, and AI Studio traffic through the clean egress tunnel while leaving ordinary domestic websites direct.

---

## 2. Windows Prerequisites

1. **Python 3.10+** (ensure `Add python.exe to PATH` is checked during installation).
2. **Administrative Privileges** in PowerShell.
3. **SmartDNS for Windows** (available as a standalone binary or Windows Service).

---

## 3. Step 1: Local SmartDNS Setup (Port 53)

### Configuration (`smartdns.conf`)
Place `smartdns.conf` in the SmartDNS working directory (e.g., `C:\ProgramData\smartdns\smartdns.conf`):

```conf
# Bind local loopback on DNS port
bind 127.0.0.1:53
cache-size 4096
prefetch-domain yes
serve-expired yes

# Default Group: Encrypted DNS-over-TLS (Cloudflare & Quad9)
# Protects against ISP SNI/DNS leaks; port 853 traffic is fully TLS-encrypted.
server-tls 1.1.1.1:853 -host-name cloudflare-dns.com
server-tls 9.9.9.9:853 -host-name dns.quad9.net
server-tls 8.8.8.8:853 -host-name dns.google

# Unblock Group: Comss DoH for standard AI endpoints (ChatGPT, Claude, Perplexity)
server-https https://dns.comss.one/dns-query -group unblock -exclude-default-group

# AI services routed through Comss DoH
nameserver /chatgpt.com/unblock
nameserver /openai.com/unblock
nameserver /oaistatic.com/unblock
nameserver /oaiusercontent.com/unblock
nameserver /claude.ai/unblock
nameserver /anthropic.com/unblock
nameserver /perplexity.ai/unblock

# NOTE: Google and Gemini domains MUST NOT be sent to Comss DoH,
# because Comss injects X-Forwarded-For which triggers Google's bot detection.
# Google domains will be handled by Layer 2 (Local Egress Proxy).
```

### Apply DNS to Network Interface (PowerShell as Administrator)
```powershell
# Identify your primary network adapter alias (e.g., "Wi-Fi" or "Ethernet")
Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

# Set Primary DNS to local SmartDNS
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses ("127.0.0.1")
```

---

## 4. Step 2: Local Egress Daemon (`gemini_egress.py`)

Create `C:\ProgramData\gemini-egress\gemini_egress.py`. This script runs on `127.0.0.1:8888`. It scrapes publicly validated proxies, performs automated health and latency checks, eliminates transparent proxies, and enforces a single **Sticky Upstream** to prevent Google account token invalidation.

```python
#!/usr/bin/env python3
"""
Local PAC proxy with Sticky Egress for Google/Gemini and AI endpoints.
Bypasses geo-blocks without X-Forwarded-For leaks.
Standard library only (no pip dependencies required).
"""

import concurrent.futures as cf
import json
import random
import re
import select
import socket
import threading
import time
import urllib.parse
import urllib.request

LISTEN = ("127.0.0.1", 8888)

# Domains routed through foreign egress
WHITELIST = (
    "google.com",
    "google.dev",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "recaptcha.net",
    "labs.google",
    "deepmind.google",
    "g.co",
    "clients6.google.com",
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "chatgpt.com",
    "openai.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "claude.ai",
    "anthropic.com",
    "perplexity.ai",
    "api.ipify.org",
)

LIST_SOURCES = (
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=3000&country=US,DE,NL,GB,FR,CA,SE,JP,SG,IE,FI&ssl=all",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

REFRESH_EVERY = 600
RECHECK_EVERY = 60
MAX_CANDIDATES = 600
KEEP_HEALTHY = 15
ORACLE = "https://www.google.com/?hl=en"

GEMINI_OK = frozenset("""
US CA MX GB IE IS NO CH AT BE BG HR CY CZ DK EE FI FR DE GR HU IT LV LT LU MT NL PL PT RO RS SK SI ES SE
BR AR CL CO JP KR SG IN ID MY TH PH VN TW IL AE QA SA TR AU NZ
""".split())

stop = threading.Event()
wake = threading.Event()
lock = threading.Lock()
healthy = []
candidates = []
last_refresh = 0.0
worked_at = {}
fails = {}

active_upstream = None
active_upstream_time = 0.0


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def fetch_candidates():
    out = set()
    for url in LIST_SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = r.read(2_000_000).decode("utf-8", "replace")
            for line in data.splitlines():
                line = line.strip()
                if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}:\d{2,5}", line):
                    out.add(line)
        except Exception:
            continue
    log("Fetched candidate proxies:", len(out))
    return list(out)


def check_proxy(hp):
    t0 = time.time()
    try:
        ph = urllib.request.ProxyHandler({"http": "http://" + hp, "https": "http://" + hp})
        op = urllib.request.build_opener(ph)
        req = urllib.request.Request(ORACLE, headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
        with op.open(req, timeout=4.0) as r:
            if r.status != 200 or "sorry" in r.geturl():
                return None
            body = r.read(8000).decode("utf-8", "replace")
        elapsed = round(time.time() - t0, 2)
        if elapsed > 3.0:
            return None
        if "sorry" in body.lower() or "unusual traffic" in body.lower():
            return None
        m = re.search(r'<html[^>]*\blang="([a-z]{2}(?:-[A-Za-z0-9]+)?)', body)
        lang = m.group(1) if m else ""
        if "-" not in lang:
            return None
        country = lang.split("-", 1)[1].upper()
        if country not in GEMINI_OK:
            return None
        return {"proxy": hp, "lang": lang, "t": elapsed}
    except Exception:
        return None


def health_loop():
    global candidates, last_refresh
    while not stop.is_set():
        now = time.time()
        if now - last_refresh > REFRESH_EVERY or not candidates:
            got = fetch_candidates()
            if got:
                random.shuffle(got)
                candidates = got[:MAX_CANDIDATES]
            last_refresh = now
        pool = list(candidates)
        res = []
        with cf.ThreadPoolExecutor(max_workers=40) as ex:
            for r in ex.map(check_proxy, pool):
                if r:
                    res.append(r)
        res.sort(key=lambda r: r["t"])
        with lock:
            healthy[:] = res[:KEEP_HEALTHY]
        log(f"Health check: {len(res)}/{len(pool)} usable proxies ->",
            ", ".join(f"{h['proxy']}({h['lang']},{h['t']}s)" for h in healthy[:5]))
        wake.wait(RECHECK_EVERY)
        wake.clear()


def pick_upstreams(n=KEEP_HEALTHY):
    global active_upstream, active_upstream_time
    with lock:
        pool = list(healthy)
    if not pool:
        return []
    now = time.time()
    sorted_pool = sorted(pool, key=lambda h: h.get("t", 99.0))
    proxies = [h["proxy"] for h in sorted_pool]

    # STICKY SESSION: Hold the same upstream proxy to preserve Google session integrity
    if active_upstream and active_upstream in proxies and (now - active_upstream_time < 1800):
        rest = [p for p in proxies if p != active_upstream]
        return ([active_upstream] + rest)[:n]

    active_upstream = proxies[0]
    active_upstream_time = now
    return proxies[:n]


def chain(hp, target, timeout=6):
    host, _, port = hp.rpartition(":")
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    head = buf.split(b"\r\n", 1)[0].decode("latin1", "replace")
    if " 200" not in head:
        s.close()
        raise OSError(f"Proxy {hp} refused: {head}")
    s.settimeout(None)
    worked_at[hp] = time.time()
    return s


def splice(a, b):
    try:
        while True:
            r, _, x = select.select([a, b], [], [a, b], 120)
            if x or not r:
                break
            for s in r:
                other = b if s is a else a
                data = s.recv(65536)
                if not data:
                    return
                other.sendall(data)
    except Exception:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except Exception:
                pass


def is_whitelisted(host):
    h = (host or "").lower().rstrip(".")
    for d in WHITELIST:
        if h == d or h.endswith("." + d):
            return True
    return False


def handle_connect(client, target):
    global active_upstream
    host = target.rpartition(":")[0]
    if is_whitelisted(host):
        upstreams = pick_upstreams()
        for hp in upstreams:
            try:
                s = chain(hp, target)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                splice(client, s)
                return
            except Exception:
                if hp == active_upstream:
                    active_upstream = None
                with lock:
                    fails[hp] = fails.get(hp, 0) + 1
                    if fails[hp] >= 3:
                        healthy[:] = [h for h in healthy if h.get("proxy") != hp]

        # Fail-closed Killswitch: prevent falling back directly to domestic IP
        client.sendall(b"HTTP/1.1 502 Bad Gateway (Proxy Egress Failed)\r\n\r\n")
        client.close()
        return

    # Direct connection for unlisted hosts
    h, _, p = target.rpartition(":")
    try:
        s = socket.create_connection((h, int(p)), timeout=10)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        splice(client, s)
    except Exception:
        client.close()


PAC_TEMPLATE = """function FindProxyForURL(url, host) {
  var wl = [%s];
  for (var i = 0; i < wl.length; i++) {
    if (host === wl[i] || dnsDomainIs(host, "." + wl[i]))
      return "PROXY 127.0.0.1:%d";
  }
  return "DIRECT";
}
""" % (", ".join(f'"{d}"' for d in WHITELIST), LISTEN[1])


def handle_client(client):
    try:
        client.settimeout(15)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = client.recv(4096)
            if not d:
                return
            buf += d
        first_line = buf.decode("latin1", "replace").split("\r\n")[0]
        parts = first_line.split(" ")
        if len(parts) >= 2 and parts[0] == "CONNECT":
            handle_connect(client, parts[1])
            return
        if len(parts) >= 2 and "/pac" in parts[1]:
            body = PAC_TEMPLATE.encode()
            client.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n"
                           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            client.close()
            return
        client.close()
    except Exception:
        try:
            client.close()
        except Exception:
            pass


def main():
    threading.Thread(target=health_loop, daemon=True).start()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    srv.listen(128)
    log(f"Listening on {LISTEN[0]}:{LISTEN[1]}")
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle_client, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
```

---

## 5. Step 3: Windows Startup Service / Task Scheduler

To make this daemon run persistently in the background on Windows without opening a command prompt window:

### Option A: Via PowerShell Task Scheduler (Recommended)
Open PowerShell as Administrator:
```powershell
$Action = New-ScheduledTaskAction -Execute "pythonw.exe" -Argument "C:\ProgramData\gemini-egress\gemini_egress.py"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "GeminiEgressProxy" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings
Start-ScheduledTask -TaskName "GeminiEgressProxy"
```
*(Using `pythonw.exe` ensures no terminal window ever appears on screen).*

---

## 6. Step 4: Chrome & Edge Enterprise Policy on Windows

To route Google, Gemini, and AI Studio traffic cleanly through the daemon without requiring browser proxy extensions:

### Create Registry Policy via PowerShell (Administrator)
```powershell
# Configure Google Chrome Proxy Policy
$ChromeRegPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if (-not (Test-Path $ChromeRegPath)) { New-Item -Path $ChromeRegPath -Force }
Set-ItemProperty -Path $ChromeRegPath -Name "ProxyMode" -Value "pac_script"
Set-ItemProperty -Path $ChromeRegPath -Name "ProxyPacUrl" -Value "http://127.0.0.1:8888/pac"

# Configure Microsoft Edge Proxy Policy (Optional)
$EdgeRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $EdgeRegPath)) { New-Item -Path $EdgeRegPath -Force }
Set-ItemProperty -Path $EdgeRegPath -Name "ProxyMode" -Value "pac_script"
Set-ItemProperty -Path $EdgeRegPath -Name "ProxyPacUrl" -Value "http://127.0.0.1:8888/pac"
```

---

## 7. Step 5: Verification & Testing

1. **Verify PAC Endpoint**:
   ```powershell
   Invoke-WebRequest -Uri "http://127.0.0.1:8888/pac" -UseBasicParsing
   ```
   Should return HTTP 200 with the PAC script defining `PROXY 127.0.0.1:8888`.

2. **Verify Gemini Egress IP (Pure Foreign IP without Russian Leaks)**:
   ```powershell
   curl.exe -x "http://127.0.0.1:8888" https://api.ipify.org
   ```
   Should return a non-RU IP address.

3. **Verify Header Integrity**:
   Open Chrome, navigate to `chrome://policy`, and verify that `ProxyPacUrl` is loaded and status is `OK`.
   Open [gemini.google.com](https://gemini.google.com). Chat interactions will operate smoothly without the "Something went wrong. (1)" error or "Unusual traffic" CAPTCHA blocks.
