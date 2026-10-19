# reascan

**Web front for REA.** Paste a URL → analysis runs on a private VM → structured findings rendered on a single-page site.

Website = output layer only. VM = analysis engine. Zero compute on Cloudflare edge (Workers = pure I/O proxy). Total cost: $0 (Cloudflare free tier + existing VM).

---

## What it does

User pastes a target URL → the request is validated (SSRF guard) and forwarded through a Cloudflare Tunnel to the VM adapter → the adapter fingerprints the target (server/framework/CDN/TLS) and inventories its JS bundles (scripts, sourcemaps, endpoints, obfuscation) → findings come back as structured JSON and render in the same page.

Findings follow the **REA evidence standard** — not a numeric score:

```
each finding = { key, value, type, evidence, confidence }
type        ∈ observation (seen directly) | derivation (inferred from markers)
verdict     = { confidence, limitations[], unknowns[] }
```

Limitations and unknowns are displayed explicitly — they are the core of the methodology, not an afterthought.

## Architecture

```
[Browser] paste URL
     │
     ▼
[Cloudflare Pages — static 1 page + Pages Functions]   ← single deploy unit
     │ fetch /api/analyze (same origin)
     ▼
[Pages Functions — API + SSRF guard layer 1]           ← pure proxy, 10ms CPU limit
     │ POST /analyze (X-API-Key)
     │ via Cloudflare Tunnel (outbound-only)
     ▼
[VM — reascan-adapter (Node, systemd)]                 ← SSRF guard layer 2
     │ urlGuard re-validation + redirect-hop check
     ▼
[VM — fingerprint + jsBundle modules]                  ← all compute lives here
     │
     ▼
findings JSON → Pages Function (pass-through) → render + localStorage history
```

**Golden rule:** compute on the VM, I/O on the edge. Pages Functions never analyze anything — they validate and proxy.

## Repository layout

```
reascan/
├── DOCUMENT/
│   ├── PLAN.md              # architecture, phases, decisions
│   └── DESIGN.md            # technical blueprint, module contracts, deploy steps
├── docs/
│   └── vm-setup.md          # VM install guide (for the agent on the VM)
├── smoke-e2e.mjs            # end-to-end smoke: steps 1-6 as one chain
├── smoke-all.mjs            # feature smoke for every step 1-7 (local, no VM)
├── .dev.vars.example        # local dev vars template (VM_ADAPTER_URL, API_KEY)
├── functions/               # Pages Functions (auto-routed /api/*) — repo ROOT:
│   └── api/                 #   wrangler resolves functions/ from the working
│       ├── analyze.js       #   directory, and tests/dev-server/smoke import
│       ├── health.js        #   it root-relative (GET /api/health)
│       └── [[catchall]].js  # 404 JSON for unknown /api/* paths
├── frontend/                # Cloudflare Pages project (the deploy directory)
│   ├── index.html           # main page: hero + how it works + Open app CTA
│   ├── app.html             # the analyzer: form + results panel
│   ├── style.css            # Vercel-dark theme, vanilla
│   ├── app.js               # fetch + render + localStorage history
│   ├── package.json         # type: module (ESM for node --test)
│   └── test/                # tests (outside functions/ on purpose — see note)
│       ├── analyze.test.js  # validateUrl guard, offline via injected DNS
│       ├── proxy.test.js    # proxy round-trip + the /api 404/405 JSON contract
│       ├── integration.test.js # real edge function vs real adapter
│       └── health.test.js   # fixed health contract + wrong-method 405
├── vm-adapter/              # Node service — runs on the VM
│   ├── install.sh           # one-command VM install (systemd + cloudflared)
│   ├── package.json         # type: module, zero deps, node --test
│   ├── server.js            # POST /analyze, GET /health
│   ├── modules/
│   │   ├── fingerprint.js   # headers/TLS/framework detect
│   │   └── jsBundle.js      # script inventory + endpoint/obfuscation
│   ├── lib/
│   │   ├── urlGuard.js      # denylist + DNS + redirect-hop validation
│   │   ├── body.js          # bounded response reads
│   │   └── reaMcp.js        # REA MCP client (phase 2 stub)
│   └── .env.example         # API_KEY, PORT, HOST template
├── README.md
├── LICENSE                  # MIT
└── .gitignore
```

Zero framework. Zero build step. Zero dependencies (Node built-ins only).

## Development status

Fase 1, 8 of 8 steps done. Engine, server, install tooling, and the full frontend (page + Pages Functions) are built, tested, and whole-tree audited. Step 8 (deploy) is live: reascan.pages.dev serves the page and /api/* through a Cloudflare quick tunnel whose URL is kept in sync (secret + redeploy) by the Windows tunnel runner.

| # | Step | State |
|---|---|---|
| 1 | `lib/urlGuard.js` — SSRF guard | done, tested |
| 2 | `modules/fingerprint.js` | done, tested |
| 3 | `modules/jsBundle.js` | done, tested |
| 4 | `server.js` + verdict aggregation | done, tested |
| 5 | `install.sh`, `reaMcp.js`, `.env.example` | done, tested |
| 6 | `frontend/` + Pages Functions | done, tested |
| 7 | Whole-tree audit | done, clean |
| 8 | Deploy (Pages + Tunnel) | done — live at reascan.pages.dev |

`node --test` — **92 passing** inside `vm-adapter/` (the last three server tests reach the real network; everything else runs offline) and **29 passing** inside `frontend/`: guard tests offline through an injected DNS resolver, proxy round-trips against a local stand-in adapter (key forwarding, findings pass-through, status mapping, malformed engine replies), the fixed health response, and an integration test that drives the real Pages Function against the real adapter.

The adapter runs as Windows scheduled tasks (`reascan-adapter`, `reascan-tunnel`) on the operator's machine; `install.sh` remains the systemd path for a Linux VM. The full chain — page → edge → tunnel → adapter — is exercised live at reascan.pages.dev.

Two scripts cover the whole chain locally, no VM required: `node smoke-e2e.mjs` (steps 1-6 in one pass, 25 checks) and `node smoke-all.mjs` (every feature of steps 1-7, 186 checks). They touch the live network only where the guard itself is under test; everything else runs on injected dependencies or a local server.

## MVP scope

- **Sync analysis** (seconds): HTTP fingerprint + JS bundle inventory
- No login, no database — history lives in the user's own browser (localStorage)
- Open-source tooling only (no IDA/Hopper — per-seat licenses, not legal for a public service)
- Phase 2: async flow (D1), heavy categories (Electron/ASAR, APK, binary via Ghidra), R2 uploads

## API

```
POST /api/analyze      { url, categories } → 200 { status: "done", findings: {...} }
                                               422 { status: "error", error: "url blocked..." }
                                               502 { status: "error", error: "analysis engine unreachable" }
GET  /api/health       → 200 { status: "ok" }
GET  /api/analyze      → 405 { status: "error", error: "method not allowed" }
POST /api/health       → 405 (same shape)
any other /api/* path  → 404 { status: "error", error: "no such route" }
```

Full contract (findings shape, error mapping, adapter endpoints): `DOCUMENT/DESIGN.md` §5.

## Deploy summary

**Frontend (from the repo root, once):**
```
npx wrangler login
npx wrangler pages project create reascan   # sekali saja
npx wrangler pages deploy frontend --project-name reascan
→ https://reascan.pages.dev
```
Wrangler resolves `functions/` from the **working directory**, so the deploy must run
at the repo root (where `functions/` lives) with `frontend/` as the asset directory —
`cd frontend && wrangler pages deploy .` would ship the page without its API.

**VM (one command):**
```
bash vm-adapter/install.sh
```

Then set `VM_ADAPTER_URL` + `API_KEY` in the Pages dashboard, `nodejs_compat` compatibility flag ON, and verify. Full step-by-step: `DOCUMENT/DESIGN.md` §10 (deploy) and `docs/vm-setup.md` (VM).

## Documentation

| Doc | Contents |
|---|---|
| `DOCUMENT/PLAN.md` | Vision, architecture, SSRF checklist, phases, timeline, all decisions |
| `DOCUMENT/DESIGN.md` | Component specs, module contracts (function-level), API contract, deployment runbook |
| `docs/vm-setup.md` | VM install: install.sh → systemd → cloudflared → verify |

## License

MIT — see `LICENSE`.
