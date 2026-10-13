# REA Web Platform — Technical Plan

**Versi:** 1.4 — Fase 1: 6/8 langkah, engine + server + install tooling + frontend selesai, deploy belum
**Tanggal:** 2026-10-13
**Konsep:** Website lite + online REA. Website = layer output/tampilan. VM = engine analisa (skill REA utuh). User paste URL → diproses di VM → hasil ditampilkan sebagai data terstruktur.
**Keputusan deploy:** Cloudflare free tier (Pages + Workers + D1 + R2 + Tunnel). VM sudah ada (existing). Biaya Cloudflare: $0.

---

## 1. Visi & Scope

Website tempat user paste link website/app. Request diteruskan ke REA di VM, diproses, hasil analisa ditampilkan sebagai report bersih (data general: tech stack, endpoints, confidence + limitations + unknowns — standar evidence REA).

**MVP scope: kategori open-source saja** (lihat §10 License). Binary native via Ghidra opsional fase 2.

---

## 2. Arsitektur (Cloudflare Free Tier)

```
[Cloudflare Pages] frontend + Pages Functions (SATU deploy unit)            [FREE]
        │ HTTPS
        ▼
[Pages Functions] API + SSRF guard LAYER 1                                [FREE]
        │ 100k req/hari, 10ms CPU/req — I/O only, compute ZERO
        │ Cloudflare Tunnel (cloudflared, outbound-only, VM nol port publik)
        ▼
[VM: REA Adapter Service]  ← SSRF guard LAYER 2 (network policy VM)      [VM existing]
        │ MCP protocol (localhost)
        ▼
[REA MCP Server + tools]  (Ghidra, asar, binwalk, apktool, JS parser)    [VM]
        │
        ▼
findings JSON → Pages Function balas apa adanya (nol storage MVP) → render
        │
   [R2 upload binary/APK (fase 2)]                                        [FREE]
   [D1 jobs + results (fase 2 — async butuh job storage)]                 [FREE]
```

**Prinsip:** website tidak pernah sentuh tool analisa langsung. Semua compute di VM. Website bisa iterate/redesign tanpa ganggu REA. REA bisa di-update independen.

**Aturan emas free tier:** Pages Functions = pure I/O proxy (fetch ke VM = wait, tidak hitung CPU). Semua analisa/compute di VM. Kalau compute pindah ke Functions → 10ms CPU jebol → wajib paid.

**Deploy shape (no-conflict):** frontend + functions/ = satu Pages project = satu deploy, satu domain (reascan.pages.dev). Nol Worker terpisah. Detail langkah deploy: DESIGN.md §10.

---

## 3. Komponen

### 3.1 Frontend — Cloudflare Pages (STATIC, 1 halaman)
- **Keputusan: static single page, vanilla HTML/CSS/JS — nol framework, nol build step** (sesuai instruksi user; detail di DESIGN.md §3.1)
- Halaman tunggal: input URL + opsi kategori → results panel di halaman sama (verdict badge, fingerprint table, JS bundle list, error state)
- Stack: vanilla JS (fetch + DOM). Deploy = copy file ke Pages
- Free: unlimited requests/bandwidth (fair use), 500 build/bln, custom domain gratis

### 3.2 Backend API — Pages Functions (Workers runtime)
- **Satu deploy unit dengan frontend** (Pages Functions di dalam project Pages — no-conflict, detail DESIGN §3.2 + §10)
- Endpoint publik: submit analisa, cek status, ambil hasil
- SSRF guard + validasi input (rate limit skip MVP)
- Forward ke VM adapter via Cloudflare Tunnel (outbound dari VM, inbound via hostname CF)
- **MVP = pure proxy, nol storage** — D1 (jobs + results) masuk fase 2 bareng async
- **Batas free:** 100k req/hari, 10ms CPU/req, 50 subrequest/req — cukup karena cuma proxy+validasi
- nodejs_compat flag ON untuk npm package Node-style

### 3.3 VM: REA Adapter Service (KODE BARU — satu-satunya yang perlu ditulis)
- Thin HTTP wrapper (~300-500 baris total, zero dependency)
- **MVP = standalone**: fingerprint + JS bundle implementasi sendiri (Node built-ins: http, tls, dns, fetch) — NOL dependency REA. Fase 2: translate ke MCP tool call REA untuk kategori berat (ASAR/binary/APK)
- Terima request dari Pages Function → jalankan modul (urlGuard → fingerprint + jsBundle) → verdict → balas JSON
- Endpoint internal: `POST /analyze`, `GET /health`
- Jalankan `cloudflared tunnel` di VM — outbound-only, VM nol port publik, nol open inbound
- Stack: Node 20+ atau Bun; zero dependency MVP (MCP client library fase 2)

### 3.4 REA MCP Server
- Utuh, tidak dimodifikasi
- Tool yang dipakai MVP: JS bundle parser, fingerprint, asar extract (open-source saja)
- Update REA tidak require perubahan website

### 3.5 Results DB — Cloudflare D1 (FASE 2)
- **MVP skip D1** — Pages Function pure proxy, history = localStorage di frontend
- Fase 2 async butuh job storage: SQLite edge 5GB, 100k write/hari, 5M read/hari (free)
- Schema di §8 (SQLite flavor — JSON sebagai TEXT)
- Kalau butuh Postgres: Neon + Hyperdrive (free tier Neon starter)

### 3.6 Upload Storage — Cloudflare R2 (fase 2)
- 10GB free, egress gratis — untuk upload binary/APK
- Flow: Workers minta presigned URL → user upload langsung ke R2 → VM ambil dari R2 untuk analisa

---

## 4. Flow

### 4.1 Sync Flow (analisa cepat — detik)
```
User paste URL → FE submit → Pages Function validasi → tunnel → VM adapter → analisa
→ JSON hasil → Pages Function balas apa adanya (nol storage MVP) → render report + simpan localStorage
```
Kategori: HTTP fingerprint, tech stack detect, JS bundle inventory (scripts, sourcemap, endpoint regex, obfuscation detect)

### 4.2 Async Flow (analisa berat — menitan) — fase 2
```
User submit → Workers buat job (status: queued) → return job ID → FE polling /api/status
→ VM worker ambil dari D1 → REA analisa → hasil ke D1 (status: done)
→ FE polling deteksi done → render report
```
Kategori: Electron/ASAR download+extract, APK (upload), Ghidra binary (upload)

MVP: sync saja. Async = D1 polling (skip Cloudflare Queues — free tier kompleksitas tidak sepadan). Fase 2 bisa upgrade ke Queues kalau perlu.

---

## 5. API Schema

### 5.1 Website API (publik — Pages Functions)
```
POST /api/analyze                                    ← MVP (sync)
  body: { url: string, categories: string[] }
  response 200: { status: "done", findings: {...} }
  response 422: { status: "error", error: "url blocked: resolves to private IP" }
  response 502: { status: "error", error: "analysis engine unreachable" }
  rate limit: skip MVP (free tier 100k req/hari = pembatas alami)

GET /api/status/:jobId                               ← fase 2 (butuh D1)
  response: { status: "queued"|"processing"|"done"|"failed", result? }

GET /api/result/:jobId                               ← fase 2 (butuh D1)
  response: { report: {...} } (structured findings)

GET /api/health                                      ← MVP (pure proxy check)
  response: { status: "ok" }
```

### 5.2 VM Adapter API (via tunnel — API key wajib)
```
POST /analyze
  header: X-API-Key
  body: { url: string, categories: string[], jobId: string }
  response: { status, findings: {...}, duration_ms }

GET /health
  response: { status: "ok", tools_available: string[] }
```

### 5.3 Findings JSON (standar evidence REA — bukan skor numerik)
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
    "limitations": ["CDN menyembunyikan origin server", "2 dari 12 bundle gagal di-fetch"],
    "unknowns": ["Apakah /api/v1/users butuh auth"]
  }
}
```
Detail shape + aturan (type/evidence/confidence/limitation/unknown) di DESIGN.md §5.

---

## 6. Analysis Modules (pemetaan REA → fitur web)

| Kategori REA | Fitur web | Tool di VM | Sync/Async |
|---|---|---|---|
| Web stack fingerprint | §5.3 fingerprint | headers/TLS/HTML scan | Sync |
| JS/web bundle | §5.3 js_bundles | JS parser, regex endpoint/obfuscation | Sync |
| Electron/ASAR | extract + JS analisa | asar extract | Async (fase 2) |
| Managed PE/.NET | decompile summary | ilspycmd (opsional) | Async (fase 2) |
| Native binary | Ghidra summary | analyzeHeadless | Async (fase 2) |
| Mobile APK | apktool summary | apktool (opsional) | Async (fase 2) |
| Capture browser | screenshot + DOM | headless CDP | Sync (fase 2) |

**MVP: baris 1-2 saja.** Sisanya fase 2.

---

## 7. SSRF Guard Checklist (WAJIB — ini gate keamanan)

Layer 1 (Workers, sebelum forward ke VM):
- [ ] Denylist: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 (metadata!), 0.0.0.0, ::1, fc00::/7
- [ ] Resolve DNS dulu → cek IP hasil resolve bukan hostname (cegah DNS rebinding)
- [ ] Blokir scheme non-http(s): file://, gopher://, ftp://
- [ ] Blokir redirect ke internal: follow redirect manual, validasi tiap hop
- [x] ~~Rate limit per IP + global cap~~ — skip MVP (free tier 100k req/hari = pembatas alami; Cloudflare zone rules saat custom domain)
- [ ] Timeout fetch ketat (10 detik)

Layer 2 (VM network policy):
- [ ] VM egress: hanya keluar via proxy yang enforce denylist yang sama
- [ ] VM tidak punya route ke internal network website/host
- [ ] cloudflared = outbound-only: VM nol inbound port, tidak bisa discan/diakses langsung
- [ ] Adapter endpoint cuma bisa diakses via hostname tunnel + API key

Catatan: Workers/Pages Function IP dinamis → IP allowlist tidak relevan. Security = tunnel outbound-only + API key + (opsional) Cloudflare Access policy di depan hostname tunnel.

**Layer 3 — Adapter (semua fetch ke target):** adapter punya guard sendiri (`lib/urlGuard.js`): re-validasi URL awal + redirect-hop validation (`redirect: 'manual'`, max 3 hop, tiap hop resolve DNS + cek denylist). Node fetch follow redirect otomatis → tanpa guard ini target jahat bisa 302 ke `169.254.169.254` (cloud metadata). Worker boleh compromised, adapter tetap menolak.

**Implementasi Layer 3 (selesai, teruji):** guard menolak IPv4-mapped (`::ffff:a.b.c.d`) dan IPv4-compatible (`::a.b.c.d`) setelah di-unmap — tanpa itu `http://[::127.0.0.1]/` lolos. `tls.connect()` juga lewat `safeTlsInfo` di dalam `urlGuard` (raw socket tidak boleh dibuka modul pemanggil) dan dial ke IP yang sudah dicek dengan SNI tetap hostname — kaki TLS race rebinding-nya tertutup. Risiko tersisa ada di kaki HTTP: `validateUrl` resolve sekali, `fetch()` resolve lagi; menutupnya butuh IP pinning yang mengubah kontrak `validateUrl` di DESIGN §3.6.

---

## 8. DB Schema (D1 / SQLite) — FASE 2

MVP skip D1 (pure proxy). Schema ini dipakai saat fase 2 async (job storage):

```sql
CREATE TABLE jobs (
  id TEXT PRIMARY KEY,              -- UUID
  url TEXT NOT NULL,
  categories TEXT NOT NULL,         -- JSON array sebagai TEXT
  status TEXT NOT NULL DEFAULT 'queued',  -- queued|processing|done|failed
  created_at TEXT NOT NULL,         -- ISO8601
  completed_at TEXT,
  error TEXT
);

CREATE TABLE results (
  job_id TEXT PRIMARY KEY REFERENCES jobs(id),
  fingerprint TEXT,   -- JSON sebagai TEXT (SQLite)
  js_bundles TEXT,
  verdict TEXT,
  raw TEXT,           -- full REA output untuk debugging
  duration_ms INTEGER
);
```

Query D1 dari Workers: `env.DB.prepare(...).bind(...).run()`. JSON parse di Workers saat render.

---

## 9. Security

| Risiko | Mitigasi |
|---|---|
| SSRF → internal probe | §7 (dua layer) |
| VM exposure ke internet | cloudflared outbound-only — VM nol port publik, cuma bisa diakses via tunnel + API key |
| Abuse (mass scanning) | Free tier 100k req/hari = pembatas alami; Cloudflare zone rate-limiting rules saat pakai custom domain |
| Secret leakage ke public | Nol secret-pattern detection (REA: "do not infer secrecy from names or text patterns") — report tidak pernah menampilkan secret value |
| API key theft | Rotate berkala, `wrangler secret put`, tidak di repo |
| Workers compute abuse | Aturan emas §2: compute di VM; Workers 10ms CPU = pembatas alami |

---

## 10. License Constraints (WAJIB dibaca sebelum deploy)

| Tool | Cloud multi-tenant? | Keterangan |
|---|---|---|
| Ghidra | ✓ | Open-source, aman |
| apktool | ✓ | Open-source |
| binwalk | ✓ | Open-source |
| asar (npm) | ✓ | Open-source |
| ilspycmd | ✓ | Open-source |
| **IDA Pro** | ✗ | Lisensi per-seat — TIDAK legal untuk service publik |
| **Hopper** | ✗ | Sama, lisensi per-user |

**Aturan:** VM hanya install tool open-source. IDA/Hopper tidak ikut ke VM cloud. Fitur yang butuh IDA/Hopper = user-local only, bukan bagian web platform.

---

## 11. MVP Scope & Phases

### Fase 1 — MVP (~1 minggu)

**Status: 6 dari 8 langkah selesai. Engine + server + install tooling + frontend lengkap dan teruji, belum ada deploy.**

- [x] VM: modul `urlGuard.js` (denylist, DNS resolve, redirect-hop, TLS probe) + test
- [x] VM: modul `fingerprint.js` (headers/TLS/framework/CDN) + test
- [x] VM: modul `jsBundle.js` (script inventory, endpoint, obfuscation) + test
- [x] VM: `server.js` (`/analyze`, `/health`, auth, deadline, verdict) + test
- [x] VM: `install.sh` + systemd services (adapter + cloudflared), `reaMcp.js` stub, `.env.example`
- [x] Pages: `index.html`, `style.css`, `app.js` (form + report + history localStorage)
- [x] Pages Functions: `analyze.js` (SSRF guard layer 1) + `health.js`
- [ ] Audit menyeluruh seluruh tree, lalu deploy (Pages + tunnel)

**Deliverable:** user paste URL → dapat report tech stack + JS findings + verdict (standar evidence REA) dalam hitungan detik. Biaya Cloudflare: $0.

### Fase 2 — Async + kategori tambahan (~2 minggu)
- Async flow (D1 polling)
- Tambah modul: Electron/ASAR, capture browser
- R2 upload (binary/APK) + Ghidra/apktool summary

### Fase 3 — Polish (opsional)
- User accounts + history
- Scheduled re-scan + monitoring
- API publik untuk developer
- (Upgrade Workers paid $5/bln hanya jika traffic >100k req/hari)

---

## 12. Timeline Estimasi

| Task | Effort |
|---|---|
| VM adapter service (HTTP wrapper + urlGuard redirect-hop) | 1-2 hari |
| Pages Functions API + SSRF guard | 2-3 hari |
| Pages frontend (form + report + history localStorage) | 2 hari |
| cloudflared tunnel setup di VM | 0.5 hari |
| Integrasi + testing end-to-end | 1-2 hari |
| **Total Fase 1** | **~1 minggu** |

---

## 13. Keputusan

**Sudah fix:**
1. ~~VM provider~~ — VM existing (sudah ada)
2. ~~Website hosting~~ — Cloudflare free tier (Pages + Tunnel untuk MVP; D1/R2 fase 2), $0
3. ~~DB~~ — skip D1 di MVP (pure proxy); fase 2: D1 (SQLite edge), Neon + Hyperdrive kalau butuh Postgres
4. ~~Deploy model~~ — Hybrid: Cloudflare edge (proxy/tampilan) + VM (compute)
5. ~~Branding~~ — `reascan`, tema Vercel (bg #000, teks putih, border tipis, Geist-style)
6. ~~Auth~~ — tanpa login (MVP); history = localStorage per browser (nol backend storage)
7. ~~Domain~~ — `reascan.pages.dev` (Pages default), custom domain nanti tanpa ubah kode
8. ~~Deploy VM~~ — nol Docker: `install.sh` → systemd services (adapter + cloudflared)
9. ~~Fallback hosting~~ — Vercel hanya darurat kalau Cloudflare 100% gagal; nol file di repo (single deploy path)
10. ~~License~~ — MIT (repo publik)
11. ~~Agent configs (opencode/openagent/kilocode)~~ — skip: tooling mesin, bukan bagian proyek ~~→ dibalik sebagian 2026-10-13~~ — `AGENTS.md` dibuat di repo root tapi **local only** (masuk `.gitignore`, `git rm --cached`). Konvensi git + security invariant `urlGuard` harus stick di luar chat, tapi file-nya bukan bagian proyek publik. Nggak ada tooling/config di dalamnya, cuma instruksi
12. ~~Test e2e~~ — curl ke URL nyata (apapun yang aktif saat testing)

**Masih terbuka (fase 2, tidak block MVP):**
1. **REA setup di VM:** tool open-source mana yang sudah terinstall vs perlu install tambahan (fase 2 — ASAR/binary/APK). MVP fingerprint+JS = nol dependency eksternal

---

*Plan ini = fondasi arsitektur. Setiap fase bisa dikerjakan independen. REA di VM tidak pernah diubah — website dan REA terpisah penuh. Cloudflare free tier = $0 selama aturan emas §2 dipatuhi (compute di VM, Workers = I/O proxy).*

---

## 14. Build & Deploy Workflow

```
1. [Mesin lokal] Build project sampai selesai (frontend/ + vm-adapter/ + file repo root)
2. [Mesin lokal] Create repo (git init → GitHub repo, finalizer: push/commit + error analysis)
3. [VM] AI agent copy/fork repo
4. [VM] AI agent install: bash vm-adapter/install.sh (adapter + cloudflared systemd services, satu perintah)
5. [Mesin lokal] Deploy Pages (single project: wrangler pages deploy frontend/) + set env vars dashboard
6. Live
```

**Aturan build:**
- Semua kode di mesin lokal, portable — nol dependency pada mesin lokal (env var untuk semua path/keys)
- VM agent = consumer repo: README + docs/vm-setup.md jadi instruksi install-nya
- MVP decision: vm-adapter standalone (fingerprint + JS bundle = implementasi sendiri, nol dependency REA). REA MCP di VM = fase 2 (ASAR/binary/APK). Alasan: VM agent install lebih ringan, MVP jalan tanpa REA; REA tetap engine tunggal untuk kategori berat sesuai arsitektur.
- Repo dibuat SETELAH build selesai (instruksi user) — tapi git init lokal sejak awal untuk version safety

