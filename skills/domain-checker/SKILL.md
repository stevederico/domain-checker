---
name: domain-checker
description: Check domain name availability across 12 TLDs (.com, .net, .org, .io, .dev, .app, .co, .xyz, .ai, .shop, .site, .tech). Use when the user asks about domain availability, wants to find a domain name, or mentions registering a domain.
metadata:
  author: stevederico
  version: "1.0"
---

# Domain Checker

Check domain availability across 12 TLDs via the Domain Checker API.

## When to use

- User asks "is example.com available?"
- User wants to find available domain names
- User is brainstorming project names and wants to check domains
- User mentions registering, buying, or checking a domain

## API

**Endpoint:** `POST https://checker.bixbyapps.com/api/check`

**Request:**
```json
{
  "domain": "example"
}
```

The `domain` field is the base name only (no TLD). Alphanumeric and hyphens only, max 63 characters.

**Response:** Array of results sorted by availability (available first):
```json
[
  {
    "tld": "dev",
    "domain": "example.dev",
    "available": true,
    "status": "available",
    "method": "rdap"
  },
  {
    "tld": "com",
    "domain": "example.com",
    "available": false,
    "status": "taken",
    "method": "whois"
  }
]
```

**Fields:**
- `available`: `true` (available), `false` (taken), `null` (unknown)
- `status`: `available`, `taken`, `likely-available`, `whois-unclear`, `error`
- `method`: `whois`, `rdap`, `dns`

## How to check a domain

1. Strip the TLD if the user provides one (e.g., "example.com" -> "example")
2. Call the API:

```bash
curl -s -X POST https://checker.bixbyapps.com/api/check \
  -H "Content-Type: application/json" \
  -A "Claude-Agent" \
  -d '{"domain": "example"}'
```

3. Present results as a table:

| Domain | Status |
|--------|--------|
| example.dev | Available |
| example.app | Available |
| example.com | Taken |

Use green/available and red/taken language. Group available domains first.

## Checking multiple names

If the user wants to check several names, call the API once per name. Run calls in parallel when possible.

## Edge cases

- Rate limited: wait and retry once
- `available: null` means the lookup was inconclusive — report as "Unknown"
- `likely-available` means DNS found no records but WHOIS was inconclusive — report as "Likely Available"
