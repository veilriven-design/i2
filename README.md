# i2 — Passive Internet Intelligence

**i2** is a strictly passive, low-signal network analysis and reconnaissance tool written in C.

It extracts the maximum amount of legal, publicly available information from a **single interaction** with a web address or IP address.

## Core Principles

- **Strictly passive & analysis-only**
- **Minimal signal** — one primary interaction (TLS + HEAD) + public DNS/registry queries
- **Comprehensive** — DNS records, TLS certificate chain (deep parsed), HTTP headers, WHOIS/registry data
- **Readability first** — rich colored terminal output + clean Markdown report file as the primary artifact
- **Terminal-first** CLI tool

## What it collects

- Full DNS (A/AAAA, NS, MX, TXT including SPF/DMARC, SOA, CAA, PTR)
- The actual IP used in the connection
- TLS details (version, cipher) + full certificate chain with fingerprints, SANs, key details, validity, etc.
- HTTP response headers and basic analysis
- Public registry data via text WHOIS (domain registration dates, registrar, IP netblock, ASN, abuse contacts)

All from public data and one standard client-like request.

## Build & Run

```bash
make
./i2 example.com
./i2 https://www.example.com -o report.md
./i2 1.1.1.1
```

Requirements: gcc, libssl-dev (OpenSSL), libresolv (usually present).

See `make help` for other targets.

## Output

- Colored live terminal summary (cyan for hosts/IPs, magenta for technical values, green/red for security posture, etc.)
- Primary deliverable: `i2_<target>_<timestamp>.md` — well-structured Markdown report

## Legal & Ethics

Only public information and what a normal client would receive in one request. Use only on targets you are authorized to analyze.

## Project Structure

```
i2/
├── Makefile
├── include/
│   ├── colors.h
│   └── i2.h
├── src/
│   ├── main.c
│   ├── target.c
│   ├── dns.c
│   ├── interact.c      # raw sockets + OpenSSL single pull + cert parsing
│   ├── whois.c         # basic text WHOIS + parsing
│   ├── report.c        # Markdown report writer
│   └── utils.c
└── ...
```

## Philosophy

Classic systems/network engineering tool: correct, minimal, highly observable, and maximally informative from the least possible interaction.

Built for clarity. Built in C.
