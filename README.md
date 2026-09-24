<h1 align="center" style="border-bottom: none;">Domain Checker</h1>
<h3 align="center" style="margin-top: 0; font-weight: normal;">
  Private domain availability lookup across 12 TLDs
</h3>

<p align="center">
  <img src="docs/screenshot.png" width="700" alt="Domain Checker Screenshot">
</p>


<p align="center">
  <a href="https://opensource.org/licenses/mit">
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License">
  </a>
</p>



## What It Does

Type a domain name and instantly see availability across 12 TLDs. Lookups go directly to WHOIS/RDAP servers — your queries are never stored or shared, so there's zero risk of front-running.

**Supported TLDs:** `.com` `.net` `.org` `.io` `.dev` `.app` `.co` `.xyz` `.ai` `.shop` `.site` `.tech`

## How It Works

The backend uses a three-tier lookup strategy for authoritative results:

1. **WHOIS** (TCP port 43) — Primary method for 10 TLDs. Queries authoritative WHOIS servers directly.
2. **RDAP** (HTTP) — Used for TLDs without WHOIS servers (`.dev`, `.app`). Queries the registry's RDAP endpoint directly.
3. **DNS** (fallback) — Last resort if WHOIS/RDAP are unreachable. Queries A, AAAA, and NS. Less authoritative. `NXDOMAIN` is likely available. Any answer, including NS only, is taken. Other resolver results stay unknown.

All 12 TLDs are checked concurrently. Results are sorted with available domains first.

### UI Indicators

- **Green dot** — Available (WHOIS or RDAP confirmed). Click to copy domain to clipboard.
- **Yellow dot** — Likely available (DNS-inferred, less certain). Click to copy with "likely" label.
- **Red dot** — Taken.
- **Gray dot** — Unknown/loading.

## Quick Start

```bash
npm run install-all
npm run start
```

Frontend runs at `http://localhost:5173`, backend at `http://localhost:8000`.

## Development

```bash
npm run start             # Frontend (Vite on :5173)
npm run front             # Same as start
cd backend && cargo run   # Backend only (Rust on :8000)
npm run build             # Production frontend build
```

## Project Structure

```
domain-checker/
├── src/
│   ├── components/
│   │   └── HomeView.tsx    # Domain checker UI
│   ├── assets/
│   │   └── styles.css      # Theme overrides
│   ├── main.tsx            # Route config
│   └── constants.json      # App config
├── backend/
│   ├── src/check.rs        # WHOIS, RDAP, and DNS lookup
│   ├── src/routes.rs       # HTTP routes, including POST /api/check
│   ├── Cargo.toml          # Empty dependency list
│   └── config.json         # Backend config
├── package.json
└── vite.config.ts
```

## Tech Stack

| Technology | Purpose |
|---|---|
| React 19 | Frontend UI |
| Vite 8 | Build & dev server |
| Tailwind CSS 4 | Styling |
| skateboard-ui | Application shell framework |
| Rust (`std::net`) | Backend HTTP server, WHOIS, and DNS |
| system `curl` | RDAP lookups for `.dev` and `.app` |

## API

### `POST /api/check`

Check domain availability across all supported TLDs.

**Request body (JSON):**
- `domain` — Base domain name (alphanumeric + hyphens, max 63 chars)

**Response:**
```json
[
  {
    "tld": "com",
    "domain": "example.com",
    "available": false,
    "status": "taken",
    "method": "whois"
  },
  {
    "tld": "dev",
    "domain": "example.dev",
    "available": true,
    "status": "available",
    "method": "rdap"
  }
]
```

**Method values:** `whois`, `rdap`, `dns`

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
  Made with <a href="https://github.com/stevederico/skateboard">Skateboard</a> — a React boilerplate
</div>
