---
name: domain-checker
author: stevederico
skills-sh: later
description: >
  Check domain name availability across 12 TLDs (.com, .net, .org, .io, .dev, .app, .co, .xyz, .ai, .shop, .site, .tech).
  Prefer the Domain Checker API; fall back to local WHOIS/RDAP via scripts/check.sh. Use when the user asks about domain
  availability, wants to find a domain name, or mentions registering a domain.
allowed-tools: Bash(curl:*), Bash(whois:*), Bash(*domain-checker/scripts/check.sh*)
metadata:
  version: "1.2"
---

# Domain Checker

Check domain availability across 12 TLDs. **One skill, two backends.**

| Backend | When |
|---|---|
| **API** (default) | Online: `POST https://checker.bixbyapps.com/api/check` |
| **Local WHOIS/RDAP** | API fails, offline, or user wants no external service |

## When to use

- “Is example.com available?”
- Brainstorming names / registering a domain

## Method 1 — API (preferred)

Strip TLD if provided (`example.com` → `example`), then:

```bash
curl -s -X POST https://checker.bixbyapps.com/api/check \
  -H "Content-Type: application/json" \
  -A "Claude-Agent" \
  -d '{"domain": "example"}'
```

Response is an array sorted available-first (`available` true/false/null, `status`, `method`).

Present as a table:

| Domain | Status |
|--------|--------|
| example.dev | Available |
| example.com | Taken |

## Method 2 — Local script (fallback)

Requires `whois` + `curl` (macOS has whois). From this skill directory:

```bash
# path when installed under agents skills:
~/.agents/skills/domain-checker/scripts/check.sh example
```

Or relative if cwd is the skill folder: `scripts/check.sh example`

Output: pipe-delimited, available first:

```
example.dev|Available
example.com|Taken
```

- 10 TLDs via `whois -h <server>`
- `.dev` / `.app` via RDAP
- Parallel lookups

## Multiple names

One call/script per base name; run in parallel when possible.

## Edge cases

- Rate limited: wait and retry once
- `available: null` / `Unknown` → inconclusive
- `likely-available` → no DNS, WHOIS unclear — say “Likely Available”
- API down → use local script automatically
