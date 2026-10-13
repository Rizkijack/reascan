# REA Web Platform — Technical Design

**Versi:** 1.0
**Tanggal:** 2026-10-13
**Status:** Blueprint untuk build. Complement PLAN.md (plan + arsitektur + fase). Dokumen ini = spec teknis: komponen, struktur kode, API contract, flow.
**Keputusan frontend:** static, single page, vanilla HTML/CSS/JS — nol framework, nol build step.

---

## 1. Ringkasan

Website 1 halaman: user paste URL → Pages Function validasi (SSRF guard) → forward ke VM adapter via Cloudflare Tunnel → adapter analisa (fingerprint + JS bundle) → hasil JSON → tampil di halaman yang sama. Semua compute di VM. Cloudflare free tier. Biaya $0 + VM existing.

---

## 2. Arsitektur

```
[Browser]
   paste URL
      │
      ▼
[Cloudflare Pages — static 1 halaman]
   index.html + style.css + app.js (vanilla, no build)
      │ fetch /api/analyze
      ▼
[Pages Functions — API + SSRF guard L1]
   100k req/hari, 10ms CPU — I/O proxy only
      │ POST /analyze (X-API-Key)
      │ via Cloudflare Tunnel
      ▼
[VM — cloudflared (outbound-only, nol port publik)]
      │
      ▼
[VM — REA Adapter (Node HTTP server)]
   POST /analyze → modul fingerprint + jsBundle → findings JSON
   (fase 2: dispatch ke REA MCP untuk ASAR/binary/APK)
      │
      ▼
[VM — REA MCP Server + open-source tools]  ← fase 2
      │
      ▼
findings JSON → Pages Function balas apa adanya → render di halaman
```

**Prinsip:** compute 100% di VM. Pages Functions = validate + proxy (nol storage MVP). Pages = tampilan statis.

---

## 3. Komponen

### 3.1 Frontend — static single page (Cloudflare Pages)

**File:** `index.html`, `style.css`, `app.js` — nol build, nol dependency, deploy = copy ke Pages.

**Elemen halaman:**
1. **Header** — brand "reascan", tema Vercel (background hitam #000, teks putih, border tipis #333, tipografi Geist-style/system sans, aksen minimal)
2. **Form** — input URL + checkbox kategori (MVP: Fingerprint, JS Bundles) + tombol Analyze
3. **Results panel** (muncul di halaman sama, di bawah form) — **standar evidence REA**:
   - Verdict badge: confidence summary (high/medium/low) — BUKAN skor numerik
   - Fingerprint table: server, framework, CDN, TLS — tiap baris = finding bertipe observation/derivation + evidence (sumber: header/marker) + confidence
   - JS bundle list: src, size, sourcemap?, endpoints (observation), obfuscated? (derivation)
   - **Limitations + unknowns ditampilkan eksplisit** (apa yang tidak bisa dipastikan + kenapa) — bagian inti metodologi REA
   - Error state: URL invalid / SSRF blocked / VM unreachable / timeout
   - Catatan: secret-pattern detection TIDAK dilakukan (REA AGENTS.md: "do not infer secrecy from names or text patterns")
4. **States:** idle → loading (spinner) → done / error
5. **History (localStorage):** setiap analisa tersimpan di localStorage browser pengguna — daftar riwayat (url + waktu + verdict) di bawah/atas form. Klik riwayat = re-render hasil tersimpan. Pure frontend, nol backend, per-browser.

**Catatan:**
- MVP sync: submit → tunggu → render. Async polling (fase 2) tinggal tambah interval fetch /api/status.
- Mobile-friendly dasar (viewport meta + flex layout).
- Vanilla JS — fetch API + DOM update. Nol framework.
- UI copy: **English** (brand universal, tema Vercel) — docs/chat tetap Indonesian.
- Nol backend storage di MVP: history = localStorage saja. D1 (job log) skip — masuk fase 2 bareng async.

### 3.2 API + SSRF guard — Pages Functions (Workers runtime)

**File:** `frontend/functions/api/analyze.js` (handler + SSRF guard inline; `validateUrl` di-export buat unit test). **MVP = pure proxy, nol DB** — D1 masuk fase 2 (async job storage).

**Deploy shape (penghindari bentrok):** Pages Functions hidup DI DALAM project Pages yang sama dengan frontend — satu folder, satu deploy (`wrangler pages deploy`), satu domain. Nol Worker terpisah, nol routing config, nol CORS. SSRF guard inline di analyze.js (MVP ~50 baris; split ke file terpisah kalau fase 2 butuh share dengan status/result).

**Routes:**
| Method | Path | Fungsi |
|---|---|---|
| POST | /api/analyze | Validasi → proxy ke VM → balas findings apa adanya (sync, nol storage) |
| GET | /api/status/:jobId | Status job (fase 2 — butuh D1) |
| GET | /api/result/:jobId | Ambil hasil dari D1 (fase 2) |
| GET | /api/health | Health check |

**SSRF guard (inline di `analyze.js`):**
- Parse URL → wajib scheme http/https
- Resolve DNS → cek IP hasil resolve (bukan hostname) terhadap denylist: 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16 (metadata), 0.0.0.0, ::1, fc00::/7
- Validasi redirect manual (follow + re-check tiap hop, max 3)
- Timeout 10s
- Rate limit: **skip MVP** (andal limit 100k req/hari free tier Workers; Cloudflare zone rate limiting rules bisa ditambah nanti kalau pakai custom domain)

**Proxy call:** fetch ke `VM_ADAPTER_URL` (env var = hostname tunnel) + header `X-API-Key` (wrangler secret). Timeout 60s (analisa bisa lama, tetap di bawah batas Workers I/O).

**D1 (`d1.js`):** prepare/bind/run helpers untuk jobs + results (schema di PLAN §8).

**Config:** env vars via Pages dashboard (Settings → Environment variables): `VM_ADAPTER_URL` = hostname tunnel. Secret `API_KEY` via dashboard (encrypted). Nol binding di MVP. Fase 2 tambah D1 binding kalau perlu.

### 3.3 VM Adapter — analysis engine (Node.js/Bun)

**File:** `server.js` (HTTP), `modules/fingerprint.js`, `modules/jsBundle.js`, `lib/reaMcp.js` (fase 2 stub).

**Endpoints:**
| Method | Path | Fungsi |
|---|---|---|
| POST | /analyze | body {url, categories} → jalankan modul → findings JSON |
| GET | /health | {status, tools_available} |

**Modul fingerprint (`modules/fingerprint.js`):**
- fetch(url) → baca response headers + redirect chain + TLS info (via undici socket / tls.connect)
- Deteksi: server (header Server), framework (X-Powered-By, HTML markers: __NEXT_DATA__, ng-, wp-, laravel), CDN (server header/headers: cf-ray, x-amz-cf-id, etc.)
- **Standar evidence REA:** tiap temuan = {key, value, type: observation|derivation, evidence: "<header/marker sumber>", confidence: high|medium|low}
- Output: {findings[], cdn, tls:{issuer, expiry}}

**Modul jsBundle (`modules/jsBundle.js`):**
- fetch(url) → parse HTML → ekstrak semua `<script src>`
- **Limit (keputusan user, 2x usulan awal):** max 40 bundle, max 1MB per bundle, timeout 10s per fetch. Bundle yang gagal/timeout/kelebihan limit → masuk limitations, bukan di-drop senyap
- tiap bundle: fetch → ukuran → deteksi sourcemap (comment `//# sourceMappingURL=` = observation) → extract endpoint (regex: /api/, /v1/, fetch(/axios paths → dedupe → observation) → deteksi obfuscation (eval(atob(, packed, entropy heuristic → derivation)
- **TIDAK ada secret-pattern detection** (REA: "do not infer secrecy from names or text patterns")
- Output: [{src, size_kb, sourcemap, endpoints[], obfuscated}]

**URL re-validation (defense in depth):** adapter re-validasi URL pakai denylist yang sama sebelum fetch — Worker boleh compromised, adapter tetap menolak IP privat.

**Redirect-hop validation (WAJIB — gap keamanan):** Node fetch follow redirect otomatis → target jahat bisa 302 → `169.254.169.254` (cloud metadata) atau IP internal. Semua fetch di adapter (fingerprint, HTML, tiap bundle) pakai `redirect: 'manual'` + loop max 3 hop; SETIAP hop: ambil Location header → resolve DNS → cek denylist → follow atau tolak (masuk limitations). Guard ini = `lib/urlGuard.js`, dipakai semua modul.

**Verdict (standar REA, bukan skor):** {confidence: high|medium|low, limitations: ["..."], unknowns: ["..."]} — confidence = agregasi confidence finding; limitations = yang gagal/tidak teramati; unknowns = pertanyaan terbuka yang tidak bisa dijawab dari observasi.

**REA MCP hook (fase 2):** `lib/reaMcp.js` — MCP client stdio; kalau REA terinstall & kategori berat diminta → dispatch tool REA. MVP = stub, tidak dipanggil.

**Auth:** semua request wajib header X-API-Key (env var). Nol request tanpa key.

**Port:** env PORT default 8787. Jalan di belakang cloudflared (nginx tidak perlu — cloudflared proxy langsung ke adapter, atau systemd service).

### 3.4 D1 — database (FASE 2)

MVP skip D1 — Worker pure proxy, history = localStorage. Fase 2 async butuh job storage: schema SQLite di PLAN §8, dibuat via `wrangler d1 create` + migration file saat fase 2 dimulai. JSON parse di Workers saat render.

### 3.5 Tunnel — cloudflared

- Install `cloudflared` di VM (binary tunggal, nol root perlu untuk quick tunnel / service mode)
- Named tunnel: `cloudflared tunnel create rea-vm` → hostname `rea-vm.<domain>` (atau trycloudflare quick tunnel untuk MVP tanpa domain)
- Config: route hostname → `http://localhost:8787` (adapter)
- Jalankan sebagai service (systemd) — auto-restart
- Nol inbound port di VM — semua outbound

---

## 3.6 Kontrak Modul (function-level) — spec eksekusi coding

Semua modul **ESM** (`"type": "module"`), **zero dependency** (Node built-ins saja: `http`, `tls`, `dns`, `fetch`, `crypto`), **async/await**, **error = return `{ok:false, reason}`, never throw across HTTP boundary**.

### `vm-adapter/lib/urlGuard.js` — security core

```js
// Pure function — unit testable tanpa network
export function ipInCidr(ip, cidr) → boolean
export const DENYLIST_CIDRS = [
  '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
  '169.254.0.0/16', '0.0.0.0/8', '::1/128', 'fc00::/7'
]

// Validasi URL awal: parse → scheme http/https → DNS resolve → cek IP hasil resolve
export async function validateUrl(rawUrl) → 
  { ok: true, url: URL } | { ok: false, reason: string }

// Fetch dengan redirect-hop validation:
// redirect:'manual' + loop max 3 hop; SETIAP hop: Location → validateUrl → follow atau tolak
// timeout default 10s (AbortController)
export async function safeFetch(url, { timeoutMs = 10000, maxRedirects = 3 } = {}) →
  { ok: true, response: Response, finalUrl: string } |
  { ok: false, reason: string }   // reason → masuk limitations di caller
```

### `vm-adapter/modules/fingerprint.js`

```js
// safeFetch di-inject (dependency injection — test bisa pakai mock)
export async function fingerprint(url, safeFetch) →
{
  findings: Finding[],   // tiap temuan: {key, value, type, evidence, confidence}
  cdn: string | null,
  tls: { issuer: string, expiry: string } | null
}

Deteksi:
- server       ← header Server          → observation, confidence high
- framework    ← X-Powered-By + HTML markers (__NEXT_DATA__, ng-, wp-, laravel, /_next/)
               → derivation, confidence medium
- cdn          ← cf-ray, x-amz-cf-id, server header
- tls          ← tls.connect() + getPeerCertificate()
Kegagalan fetch → {ok:false} dari safeFetch → finding di-skip + limitation ditambah
```

### `vm-adapter/modules/jsBundle.js`

```js
export async function analyzeBundles(url, safeFetch, limits = {}) →
{
  bundles: Bundle[],      // {src, size_kb, sourcemap, endpoints[], obfuscated}
  limitations: string[]   // bundle gagal/timeout/over-limit DICATAT di sini
}
// limits default: { maxBundles: 40, maxBytes: 1048576, timeoutMs: 10000 }

Alur:
1. safeFetch(url) → parse HTML → extract <script src> (absolute URL, dedupe)
2. Per bundle: safeFetch → ukuran → cek maxBytes
3. sourcemap      ← //# sourceMappingURL= comment  → boolean
4. endpoints      ← regex: /api/, /v1/, /v2/, fetch(, axios. → dedupe → array
5. obfuscated     ← eval(atob(, eval(function(p,a,c,k,e, signature → boolean (derivation)
```

### `vm-adapter/server.js`

```js
// http.createServer — nol framework
// POST /analyze: auth (X-API-Key, timing-safe compare via crypto.timingSafeEqual)
//   → validateUrl → Promise.all([fingerprint, jsBundle]) → verdict → 200 JSON
// GET /health → 200 { status: 'ok', tools_available: ['fingerprint', 'jsBundle'] }
// Error mapping:
//   401 auth gagal | 422 URL blocked | 502 fetch target gagal | 500 unexpected

// verdict (inline di server.js, ~20 baris):
function buildVerdict(findings, limitations) → {
  confidence: 'high'|'medium'|'low',   // agregasi: semua high → high; ada medium → medium; ada low → low
  limitations: string[],
  unknowns: string[]                   // template per kategori (mis. "endpoint auth requirement unknown")
}
```

### `frontend/functions/api/analyze.js` — Pages Function

```js
export async function onRequestPost(context) → Response
// 1. parse JSON body {url, categories}
// 2. validateUrl (inline guard — SAMA denylist dengan adapter, ~30 baris)
//    → gagal: 422 { status:'error', error: reason }
// 3. fetch(env.VM_ADAPTER_URL + '/analyze', { headers: { 'X-API-Key': env.API_KEY } })
//    → gagal/timeout: 502 { status:'error', error:'analysis engine unreachable' }
// 4. 200 { status:'done', findings: <dari adapter, apa adanya> }

export function validateUrl(rawUrl) → { ok, url } | { ok: false, reason }
// exported khusus untuk unit test (node:test import analyze.js)
// nodejs_compat ON — fetch + crypto.subtle tersedia
```

### `frontend/app.js` — vanilla, nol framework

```js
// State machine: 'idle' | 'loading' | 'done' | 'error' (satu variabel + render())
// Functions:
//   handleSubmit(e)        → validasi input dasar → fetch /api/analyze → setState + render
//   renderFindings(f)      → verdict badge, fingerprint table, bundle list, limitations/unknowns
//   renderHistory()        → list dari localStorage
//   saveToHistory(f)       → localStorage.setItem('reascan:history', ...)
//   loadHistory()          → JSON.parse atau [] kalau kosong/corrupt
// localStorage schema: [{ url, timestamp, confidence, findings }] — max 50 entri (shift lama)
```

### Konvensi lintas modul

- Nol `console.log` di path produksi — startup log ke stderr boleh
- Nol `TODO` tanpa owner
- JSON response: selalu `{ status, ... }` — status ∈ 'done' | 'error'
- Comment: hanya the why yang kode tidak bisa tunjukkan
- Test file naming: `<module>.test.js` sebelahan modul (node:test, `node --test`)

---

## 4. Struktur kode (repo tree)

```
reascan/                       # repo root (publik, MIT)
├── DOCUMENT/
│   ├── PLAN.md                    # plan + arsitektur + fase (v1.1)
│   └── DESIGN.md                  # blueprint teknis (v1.0)
├── README.md                      # overview + arsitektur + deploy guide (VM agent)
├── LICENSE                        # MIT
├── .gitignore                     # .env, node_modules, dist, *.log, .dev.vars
│
├── frontend/                  # Cloudflare Pages project (SATU deploy unit — no-conflict)
│   ├── index.html             # 1 halaman: form + results panel
│   ├── style.css              # tema Vercel dark (~100 baris)
│   ├── app.js                 # fetch + render + states + localStorage history
│   ├── .dev.vars.example      # VM_ADAPTER_URL + API_KEY buat wrangler pages dev lokal
│   └── functions/             # Pages Functions (Workers runtime, auto-route /api/*)
│       └── api/
│           ├── analyze.js     # handler + SSRF guard inline (export validateUrl buat test)
│           └── health.js      # GET /api/health (MVP, ~5 baris)
│   # fase 2 tambah: api/status.js, api/result.js
│
├── vm-adapter/                # Node service (dijalankan di VM via systemd)
│   ├── install.sh             # VM one-command: node check + systemd services (adapter + cloudflared)
│   ├── package.json           # type: module, zero deps, scripts.test = node --test
│   ├── server.js              # HTTP server: /analyze, /health
│   ├── modules/
│   │   ├── fingerprint.js     # headers/TLS/framework detect
│   │   └── jsBundle.js        # script inventory + endpoint/obfuscation
│   ├── lib/
│   │   ├── reaMcp.js          # REA MCP client (fase 2 stub)
│   │   └── urlGuard.js        # denylist + DNS + redirect-hop validation (dipakai semua fetch)
│   └── .env.example           # API_KEY, PORT
│
└── docs/
    └── vm-setup.md            # panduan install untuk AI agent di VM
```

**Total file kode MVP:** ~17 file. Nol framework, nol build step, nol Docker.

**Fallback Vercel (DARURAT saja — nol file di repo):** kalau Cloudflare 100% gagal → frontend statis host di Vercel + copy handler ke konvensi `api/` (Serverless Functions) + env vars dashboard. Tidak ada `vercel.json` di MVP — single deploy path = nol file yang harus di-sync manual.

---

## 5. API Contract

### POST /api/analyze (Pages Function → client)
```json
// request
{ "url": "https://example.com", "categories": ["fingerprint", "jsBundle"] }

// response 200 (sync)
{ "status": "done", "findings": { ...§5.3 findings... } }

// response 422 (SSRF blocked / invalid URL)
{ "status": "error", "error": "url blocked: resolves to private IP" }

// response 502 (VM unreachable)
{ "status": "error", "error": "analysis engine unreachable" }
```

### POST /analyze (Pages Function → VM adapter)
```json
// header: X-API-Key
{ "url": "...", "categories": [...], "jobId": "uuid" }
// response
{ "status": "ok", "findings": {...}, "duration_ms": 1234 }
```

### Findings shape (standar evidence REA — menggantikan skor numerik)
```json
{
  "url": "https://target.com",
  "timestamp": "ISO8601",
  "fingerprint": {
    "findings": [
      { "key": "server", "value": "nginx/1.x", "type": "observation",
        "evidence": "Server response header", "confidence": "high" },
      { "key": "framework", "value": ["Next.js", "React"], "type": "derivation",
        "evidence": "__NEXT_DATA__ marker in HTML", "confidence": "medium" }
    ],
    "cdn": "Cloudflare",
    "tls": { "issuer": "...", "expiry": "..." }
  },
  "js_bundles": [
    { "src": "/static/app.js", "size_kb": 245, "sourcemap": true,
      "endpoints": ["/api/v1/users"], "obfuscated": false }
  ],
  "verdict": {
    "confidence": "medium",
    "limitations": [
      "CDN menyembunyikan origin server — fingerprint server aktual tidak teramati",
      "2 dari 12 bundle gagal di-fetch (timeout) — tidak dianalisa"
    ],
    "unknowns": [
      "Apakah endpoint /api/v1/users memerlukan autentikasi — tidak bisa dipastikan dari statis"
    ]
  }
}
```

Aturan shape: setiap finding = {key, value, type, evidence, confidence}. Type ∈ observation (terlihat langsung) | derivation (disimpulkan dari marker) | inference (diduga, jarang dipakai). Limitation = kegagalan/ketidakcukupan observasi. Unknown = pertanyaan terbuka yang observasi tidak bisa jawab.

---

## 6. Sequence Flow (happy path)

```
1. User paste https://target.com → klik Analyze
2. app.js → POST /api/analyze {url, categories} (fetch ke origin yang sama — Pages Functions)
3. Pages Function: validateUrl (DNS resolve + denylist) → lolos
4. Pages Function: fetch VM_ADAPTER_URL/analyze + X-API-Key (via tunnel)
5. Adapter: urlGuard re-validate + redirect-hop check → fingerprint.js + jsBundle.js analisa target
6. Adapter: verdict (confidence + limitations + unknowns) → findings JSON
7. Pages Function: balas findings apa adanya (nol storage di MVP)
8. app.js: render verdict badge + fingerprint table + bundle list + limitations/unknowns + simpan ke localStorage history
```

---

## 7. Keputusan Teknis (+ alasan)

| Keputusan | Alasan |
|---|---|
| Frontend static vanilla, 1 halaman | Nol build, deploy = copy, Pages free. SPA framework = overkill untuk form + report |
| MVP sync (bukan async) | Fingerprint + JS analisa = detik. Async = kompleksitas tanpa manfaat di MVP |
| Async fase 2 = D1 polling | Skip Queues — polling sederhana, nol dependency, cukup |
| Adapter standalone (fingerprint + JS = implementasi sendiri) | MVP jalan tanpa REA di VM — install VM agent ringan. REA = fase 2 untuk kategori berat |
| cloudflared outbound-only | VM nol port publik — security tanpa firewall rule |
| Workers = pure proxy | Aturan emas free tier: 10ms CPU, compute di VM |
| JSON sebagai TEXT di D1 | SQLite tidak punya JSONB — parse di Workers saat render |
| nodejs_compat ON | npm package Node-style jalan di Workers |
| History = localStorage (bukan D1-only) | Per-browser, pure frontend, nol backend, klik riwayat = re-render. D1 skip di MVP — masuk fase 2 bareng async (job storage) |
| Tanpa login (MVP) | "User tinggal paste" — auth = friksi tanpa nilai di MVP. Fase 3: akun + history lintas device |
| Tema Vercel di frontend statis | bg #000, teks putih, border tipis #333, Geist-style sans — clean, nol CSS framework, ~100 baris style.css |
| Verdict = standar evidence REA | observation/derivation/inference/unknown + evidence + confidence + limitations — BUKAN skor numerik. Mengikuti metodologi resmi REA (morluto/rea, AGENTS.md) |
| Limit analisa 40 bundle / 1MB per bundle | Keputusan user (2x usulan awal). Kegagalan/timeout/over-limit → masuk limitations, bukan drop senyap |
| Adapter re-validasi URL | Defense in depth: Worker compromised pun adapter tetap tolak IP privat (denylist sama) |
| Rate limit skip (MVP) | Free tier 100k req/hari = pembatas alami; Cloudflare zone rules saat custom domain |
| Tanpa secret-pattern detection | REA AGENTS.md: "do not infer secrecy from names or text patterns" — endpoint = observation, obfuscation = derivation, secrets = tidak diklaim |
| Testing: SSRF unit + e2e curl | Guard security-critical — unit test wajib (mock URL privat ditolak); sisa manual curl ke situs nyata |
| Skip D1 di MVP | Worker pure proxy, nol storage — history = localStorage. D1 bareng fase 2 async (job storage) |
| Redirect-hop validation di adapter | Node fetch follow otomatis; semua fetch manual redirect max 3 hop, tiap hop divalidasi ke denylist — target jahat bisa 302 ke IP internal |
| UI copy English | Brand universal, tema Vercel; docs/chat tetap Indonesian |
| Test mechanics | adapter = node:test built-in (zero dep); Pages Function = node:test import analyze.js + curl manual via `wrangler pages dev` |
| Single Pages project (no Worker terpisah) | Frontend + functions/ = satu deploy unit, satu domain, nol routing/CORS bentrok. Worker terpisah butuh zone + routes = kompleksitas tanpa manfaat di free tier |

---

## 8. Build Checklist

- [ ] `frontend/` — index.html, style.css, app.js, .dev.vars.example + functions/api/analyze.js (handler + SSRF guard, export validateUrl) + functions/api/health.js
- [ ] `vm-adapter/` — install.sh, package.json, server.js, modules/fingerprint.js, modules/jsBundle.js, lib/urlGuard.js, lib/reaMcp.js (stub), .env.example
- [ ] repo root — README.md, LICENSE (MIT), .gitignore
- [ ] `docs/vm-setup.md` — panduan install VM agent (install.sh → systemd)
- [ ] Test: SSRF guard unit tests (mock URL privat ditolak — security-critical) → adapter standalone (curl /analyze) → wrangler pages dev + curl → e2e curl URL nyata
- [ ] (setelah selesai) git init + create GitHub repo (publik)

---

## 9. Keputusan (fix)

1. **Branding:** `reascan` — tema Vercel (bg #000, teks putih, border tipis #333, Geist-style/system sans, aksen minimal)
2. **Auth:** tanpa login (MVP). History = localStorage per browser (pure frontend, klik riwayat = re-render). Nol backend storage di MVP
3. **Domain:** `reascan.pages.dev` (Pages default Cloudflare, gratis). Custom domain bisa ditambah nanti tanpa ubah kode

---

## 10. Deployment — No-Conflict Path (Cloudflare Free Tier)

Prinsip: **SATU Pages project = frontend statis + Pages Functions (API) = satu folder, satu deploy, satu domain.** Nol Worker terpisah, nol routing config, nol CORS, nol D1 binding. VM di belakang cloudflared tunnel (outbound-only) — terpisah total dari deploy Pages.

### 10.1 Prasyarat
- Akun Cloudflare (gratis)
- VM existing + cloudflared bisa diinstall di sana
- `npm i -g wrangler` atau cukup `npx wrangler` (tanpa install global)

### 10.2 Deploy Pages (satu perintah)
```
cd frontend
npx wrangler login                          # OAuth sekali, buka browser
npx wrangler pages project create reascan   # sekali saja
npx wrangler pages deploy . --project-name reascan
```
Hasil: https://reascan.pages.dev — frontend + /api/analyze live dalam satu deploy.

### 10.3 Config Pages (dashboard, sekali)
- Settings → Functions → Runtime → Compatibility flags: tambah `nodejs_compat` (+ compatibility date terbaru)
- Settings → Environment variables → Production:
  - `VM_ADAPTER_URL` = hostname tunnel VM (contoh: https://rea-vm.your-tunnel.com)
  - Secret `API_KEY` = string acak panjang (dashboard "Add secret" — encrypted, tidak muncul di logs)

Catatan: nol binding D1 di MVP (skip DB). Nol routing rules — Pages Functions auto-handle /api/* dengan precedence di atas static files.

### 10.4 VM side (pisah dari deploy Pages — nol bentrok)
```bash
# 1. Install cloudflared
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared
chmod +x cloudflared && sudo mv cloudflared /usr/local/bin/

# 2. Named tunnel (butuh domain di Cloudflare) ATAU quick tunnel (tanpa domain, buat tes)
# Quick tunnel:
cloudflared tunnel --url http://localhost:8787     # dapat URL trycloudflare.com acak
# Named tunnel:
cloudflared tunnel login && cloudflared tunnel create rea-vm
cloudflared tunnel route dns rea-vm rea-vm.<domain>
cloudflared tunnel run rea-vm --url http://localhost:8787

# 3. systemd service cloudflared (auto-restart)
# 4. Jalankan vm-adapter (systemd, env API_KEY SAMA dengan Pages secret)
# 5. Health check: curl https://<hostname-tunnel>/health → 200
```

### 10.5 Yang TIDAK dilakukan di MVP (penghindari bentrok)
- Nol Worker terpisah — Pages Functions cukup (Worker terpisah butuh zone + routes + sync dua deploy = bentrok)
- Nol D1 binding — pure proxy
- Nol Queues / Cron / KV / R2
- Nol custom domain hari pertama — pages.dev dulu
- Nol firewall config — VM nol inbound port (cloudflared outbound-only)

### 10.6 Verifikasi sukses deploy
1. `curl https://reascan.pages.dev/api/health` → 200
2. Buka https://reascan.pages.dev → paste URL nyata → Analyze → findings render
3. localStorage history muncul setelah analisa pertama
4. Semua hijau = deployment sukses, nol bentrok

---

*DESIGN.md = blueprint build. Semua komponen spec lengkap — build bisa langsung jalan tanpa keputusan tambahan.*
