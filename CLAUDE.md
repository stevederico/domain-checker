# CLAUDE.md

Project guidance for Claude Code and AI agents working on Domain Checker.

## What This Project Does

Domain availability checker. User types a domain name, backend checks availability across 12 TLDs via WHOIS/RDAP, frontend displays results as a compact two-column list with colored dot indicators.

## Development Commands

```bash
npm run start          # Start both frontend and backend concurrently
npm run front          # Frontend only (Vite dev server on :5173)
npm run server         # Backend only (Hono server on :8000)
npm run build          # Production build
npm run install-all    # Install all dependencies (root + workspace)
```

## Architecture

### Frontend

- **`src/main.jsx`** — Single route (`home`) using `createSkateboardApp()`
- **`src/components/HomeView.jsx`** — Domain checker UI. Debounced input (300ms), concurrent API calls, two-column result grid with `DomainRow` component
- **`src/constants.json`** — App config. `noLogin: true` (no auth required)

### Backend (`backend/server.js`)

Hono server on port 8000. The domain check logic is the custom part; the rest is standard skateboard boilerplate (auth, Stripe, CSRF, etc.).

**Domain check endpoint:** `POST /api/check` with JSON body `{ "domain": "name" }`

**Three-tier lookup strategy:**

1. **RDAP** — For `.dev` and `.app` (no WHOIS server) via `pubapi.registry.google`. HTTP 200 = taken, 404 = available.
2. **WHOIS** — For 10 other TLDs via raw TCP port 43 queries using Node.js `net` module. Parses response for known available/taken patterns.
3. **DNS** — Fallback if WHOIS/RDAP fail. Checks A/AAAA/NS records via `dns.promises.resolve`. Less authoritative.

**Key constants and maps:**
- `WHOIS_SERVERS` — Maps 10 TLDs to their WHOIS server hostnames
- `RDAP_SERVERS` — Maps `.dev` and `.app` to `pubapi.registry.google/rdap/domain/`
- `WHOIS_AVAILABLE_PATTERNS` / `WHOIS_TAKEN_PATTERNS` — Text patterns for parsing WHOIS responses
- `WHOIS_TIMEOUT_MS` / `RDAP_TIMEOUT_MS` — 5 second timeouts

**Key functions:**
- `queryWhois(server, domain)` — Raw TCP WHOIS query
- `checkDomainWhois(tld, fqdn)` — WHOIS lookup + response parsing
- `checkDomainRdap(tld, fqdn)` — RDAP HTTP lookup (.dev, .app)
- `checkDomainDNS(fqdn)` — DNS resolution fallback
- `checkSingleDomain(tld, name)` — Orchestrates RDAP → WHOIS → DNS per TLD

**Response format:**
```json
{
  "tld": "com",
  "domain": "example.com",
  "available": false,
  "status": "taken",
  "method": "whois"
}
```

### UI Indicators (HomeView.jsx → DomainRow component)

- **Green dot** (`bg-emerald-500`) — WHOIS/RDAP confirmed available. Click to copy domain.
- **Yellow dot** (`bg-yellow-500`) — DNS-inferred available. Click to copy with "likely" label.
- **Red dot** (`bg-red-500`) — Taken. Non-clickable, muted text.
- **Gray dot** — Loading or unknown.

### Supported TLDs

`.com` `.net` `.org` `.io` `.dev` `.app` `.co` `.xyz` `.ai` `.shop` `.site` `.tech`

**WHOIS servers (10 TLDs):**
| TLD | Server |
|---|---|
| com, net | whois.verisign-grs.com |
| org | whois.pir.org |
| io | whois.nic.io |
| co | whois.registry.co |
| xyz | whois.nic.xyz |
| ai | whois.nic.ai |
| shop | whois.nic.shop |
| site | whois.nic.site |
| tech | whois.nic.tech |

**RDAP endpoints (2 TLDs):**
| TLD | Endpoint |
|---|---|
| dev, app | pubapi.registry.google/rdap/domain/ |

**Important:** `.dev` and `.app` have NO WHOIS server. The correct RDAP endpoint is `pubapi.registry.google`.

## Code Standards

### Documentation Requirements

**Documentation must always match code.**

When modifying functions, update JSDoc comments as part of the change. Update README.md if user-facing behavior changes. Update this file if architecture/patterns change.

### Naming Conventions

- Functions: `camelCase` verbs (`checkDomainWhois`, `queryWhois`)
- Components: `PascalCase` (`HomeView`, `DomainRow`)
- Constants: `UPPER_SNAKE_CASE` (`WHOIS_SERVERS`, `RDAP_TIMEOUT_MS`)

## UI Components — shadcn Primitives

Import from `@stevederico/skateboard-ui/shadcn/ui/<component>`. Currently used in HomeView: `Input`, `Spinner`, `Kbd`.

## Boilerplate (skateboard)

This project was scaffolded from skateboard v2.2.2. The boilerplate provides auth, Stripe, CSRF, database adapters, and the application shell. Domain checking logic is the only custom backend code.

## Environment

Backend requires `backend/.env` with `JWT_SECRET`, `STRIPE_KEY`, `STRIPE_ENDPOINT_SECRET`. Domain checking works without these — they're only needed for auth/payment features. Copy `backend/.env.example` to `backend/.env` to get started.

## Deployment

- Set `NODE_ENV=production` in all deployment environments (Dockerfile already does this)
- Place behind a reverse proxy (nginx, Cloudflare, etc.) that sets `x-forwarded-for` for accurate rate limiting
- Rate limit: 30 requests/min per IP on the domain check endpoint
