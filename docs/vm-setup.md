# VM Setup — reascan adapter

Guide for the AI agent operating the VM. Installs the analysis engine (adapter + Cloudflare Tunnel) so the Cloudflare Pages deployment can reach it.

**Runtime:** Node 20+ or Bun (either works — adapter is zero-dependency, Node built-ins only).
**No Docker.** Two systemd services: `reascan-adapter` (analysis engine) + `reascan-tunnel` (cloudflared).

> **Status: belum dijalankan di VM sungguhan.** `install.sh` sudah ada di repo dan
> mengikuti langkah di bawah ini, tapi belum pernah dieksekusi di VM. Yang sudah
> terverifikasi: adapter lokal (`node server.js` → `/health` 200 dengan key yang benar,
> 401 tanpa key, 422 untuk URL privat). Jalankan `bash install.sh` sebagai langkah VM
> pertama (bagian dari tahap deploy — PLAN.md langkah 8).

---

## 1. Prerequisites on the VM

```bash
node --version     # v20+ required (or bun --version)
curl --version
systemctl --version
sudo access        # for systemd service files under /etc/systemd/system
```

If Node is missing:
```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### 1b. REA engine (for the `browserCapture` + `jsDeep` categories)

The adapter shells out to the `rea` CLI — no npm install needed, but the
binary must exist and the browser-capture prerequisites must be in place:

```bash
rea --version      # >= 6.x; install: npm install -g rea-agents --prefix ~/.local
```

`browserCapture` needs a headless Chromium with CDP on `127.0.0.1:9222`
(`lib/reaEnv.js` starts it on demand, so this is only for manual verification).
On this VM that Chromium is additionally launched through a **proxy forwarder**
on `127.0.0.1:18080`: REA strips proxy env vars from browsers it launches, and
the VM reaches the internet only through an authenticated egress proxy, so the
forwarder (`~/workspace/rea-proxy/proxy.mjs`) injects `Proxy-Authorization`
for the upstream, using `UPSTREAM_PROXY_*` env vars parsed out of
`$https_proxy`.

The forwarder is started **only when `https_proxy` actually names an upstream**.
A host with direct egress runs no forwarder and Chromium gets no proxy flags -
in particular it does **not** get `--ignore-certificate-errors`, which exists
because the VM's egress proxy terminates TLS with its own CA, and must not
follow the adapter onto a host whose certificates are valid.

If something already holds `127.0.0.1:9222` without speaking the DevTools HTTP
API, browser capture fails with an explicit port-collision reason instead of a
generic launch error. Free the port, or point `REA_CDP_PORT` elsewhere.

Env overrides: `REA_BIN` (rea binary path - on Windows npm installs only
`.cmd`/`.ps1` shims that `spawn` cannot use, so the adapter invokes the
package's own ESM entry through Node instead of through a shell), 
`REA_PROXY_SCRIPT`, `REA_PROXY_PORT`, `REA_CDP_PORT`, `REA_CHROME_BIN`,
`REA_CHROME_PROFILE`, `REA_IGNORE_CERT_ERRORS`.

`REA_IGNORE_CERT_ERRORS=1` is the explicit opt-in for `--ignore-certificate-errors`
on direct egress. Leave it unset there: a target with a self-signed or
hostname-mismatched certificate is a normal target for this tool, but a blanket
TLS bypass on every host is not a reasonable default.

Categories the engine cannot serve here degrade to limitations, not errors:
native binaries need Ghidra/IDA, APKs need JADX/JDK — none installed.

## 2. Get the code

The VM agent clones (or forks) the public repo:

```bash
git clone https://github.com/Rizkijack/reascan.git
cd reascan/vm-adapter
```

## 3. Install (one command)

```bash
bash install.sh
```

`install.sh` does:
1. Copies `.env.example` → `.env` (never overwrites an existing `.env`; generates a random API_KEY on first run, and checks the write landed so a half-written `.env` cannot strand the install)
2. Installs `cloudflared` if missing (official release binary → `/usr/local/bin`)
3. Writes + enables systemd units:
   - `reascan-adapter` — `node server.js` (WorkingDirectory = repo vm-adapter/, EnvironmentFile = .env)
   - `reascan-tunnel` — `cloudflared tunnel --url http://localhost:$PORT` (port read from .env, default 8787)
4. Starts both services with `Restart=always`

Must run as root (`sudo bash install.sh`) — it writes to `/usr/local/bin` and `/etc/systemd/system`.

## 4. Configure secrets

`install.sh` already generated a random `API_KEY` and printed it once
(`reascan-install:   API_KEY = …`). To rotate it, or if you created `.env` by hand, edit
`vm-adapter/.env`:

```
API_KEY=<long-random-string>
PORT=8787
HOST=127.0.0.1
```

The **same** `API_KEY` must be set as a secret in the Cloudflare Pages dashboard
(Settings → Environment variables → Add secret), together with `VM_ADAPTER_URL` (the tunnel
hostname). A deployed Pages function missing either one answers
`500 analysis engine is not configured` before it ever contacts the adapter:
that is a dashboard gap, not an adapter fault, and no adapter log will show it.
For local iteration both values come from `.dev.vars` at the repo root instead.
Generate one yourself:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

## 5. Cloudflare Tunnel

**Quick tunnel (test, no domain needed):**
```bash
cloudflared tunnel --url http://localhost:8787
# prints a random https://*.trycloudflare.com URL → put it in VM_ADAPTER_URL
```

**Named tunnel (production):**
```bash
cloudflared tunnel login                    # once, opens browser OAuth
cloudflared tunnel create reascan-vm
cloudflared tunnel route dns reascan-vm reascan-vm.<your-domain>
cloudflared tunnel run reascan-vm --url http://localhost:8787
```

The VM keeps **zero inbound ports** — cloudflared dials out. Nothing on the VM is scannable.

## 6. Verify

```bash
# adapter alive locally
curl http://localhost:8787/health
# → { "status": "ok", "tools_available": ["fingerprint", "jsBundle"] }

# adapter reachable through the tunnel
curl https://<tunnel-hostname>/health
# → same response

# end-to-end (needs Pages deployed with matching VM_ADAPTER_URL + API_KEY)
curl -X POST https://reascan.pages.dev/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","categories":["fingerprint","jsBundle"]}'
# → { "status": "done", "findings": { ... } }
```

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `connection refused` on /health | adapter not running | `sudo systemctl status reascan-adapter`; `journalctl -u reascan-adapter -f` |
| 502 "analysis engine unreachable" from Pages | `VM_ADAPTER_URL` wrong, tunnel down, or a quick-tunnel hostname went stale | check `systemctl status reascan-tunnel`; `install.sh` warns that a QUICK tunnel gets a new hostname on every restart — re-copy it, or switch to a named tunnel (§5) |
| 401/403 from adapter | API_KEY mismatch | `.env` on VM ≠ Pages secret — rotate both to the same value |
| Adapter returns 422 "url blocked" | SSRF guard working correctly — target resolves to a private IP | expected behavior; test with a public URL |
| Analysis times out | target site slow/dead, or bundle fetch hitting the 10s cap | check `verdict.limitations` in the response — failures are reported, not hidden |

## 8. Notes for the VM agent

- **MVP adapter is standalone** — fingerprint + JS bundle are implemented in-tree (Node built-ins). No REA installation needed for MVP.
- **REA integration = phase 2** — `lib/reaMcp.js` is a stub; heavy categories (ASAR/binary/APK) are out of MVP scope.
- **Never disable `lib/urlGuard.js`.** The redirect-hop validation blocks a malicious target from 302-redirecting the adapter into private network space. It is defense-in-depth layer 2 — layer 1 lives in the Pages Function, and both must stay.
- Restart after code changes: `sudo systemctl restart reascan-adapter`
- Logs: `journalctl -u reascan-adapter -f` (adapter), `journalctl -u reascan-tunnel -f` (tunnel)
