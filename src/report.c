/*
 * i2 - Report writer
 * Produces the primary external artifact: a clean, highly readable Markdown file.
 * Terminal already gets the colored live view via the print_* functions.
 */

#include "../include/i2.h"
#include <sys/stat.h>
#include <errno.h>

static void fprint_escaped(FILE *f, const char *s) {
    if (!s) { fputs("(null)", f); return; }
    for (const char *p = s; *p; p++) {
        if (*p == '`') fputs("\\`", f);
        else if (*p == '*') fputs("\\*", f);
        else fputc(*p, f);
    }
}

static void write_section_header(FILE *f, const char *title) {
    fprintf(f, "\n## %s\n\n", title);
}

int write_report(const ReportContext *ctx) {
    if (!ctx) return -1;

    char path[512];
    if (ctx->report_path && ctx->report_path[0]) {
        strncpy(path, ctx->report_path, sizeof(path)-1);
        path[sizeof(path)-1] = 0;
    } else {
        // auto name
        char safe[128];
        const char *h = ctx->target.host ? ctx->target.host : "target";
        size_t j = 0;
        for (size_t i=0; h[i] && j < sizeof(safe)-1; i++) {
            char c = h[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
                safe[j++] = c;
            } else {
                safe[j++] = '_';
            }
        }
        safe[j] = 0;

        char ts[32];
        time_t now = time(NULL);
        struct tm *tm = gmtime(&now);
        strftime(ts, sizeof(ts), "%Y%m%d-%H%M%S", tm);

        snprintf(path, sizeof(path), "i2_%s_%s.md", safe, ts);
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        perror("fopen report");
        return -1;
    }

    // Header
    fprintf(f, "# i2 Passive Analysis Report\n\n");
    char *ts = timestamp_iso();
    fprintf(f, "**Target:** `%s`  \n", ctx->target.original);
    fprintf(f, "**Collected (UTC):** `%s`  \n", ts ? ts : "unknown");
    fprintf(f, "**Tool:** i2 v%s  \n\n", I2_VERSION);
    free(ts);

    fprintf(f, "> **Passive only.** Data from public DNS, public registration services, and **one standard client interaction** (TLS handshake + HTTP HEAD) with the target. No port scans or aggressive probes.\n\n");

    // Compact observed facts (for quick scanning)
    fprintf(f, "### Observed at a Glance\n\n");
    fprintf(f, "- Host: `%s` (port %d)\n", ctx->target.host, ctx->target.port);
    if (ctx->http.connected_ip) {
        fprintf(f, "- **Connected IP (the single low-signal pull):** `%s`\n", ctx->http.connected_ip);
    }
    if (ctx->tls.tls_version && ctx->tls.cipher) {
        fprintf(f, "- TLS: `%s` / `%s`\n", ctx->tls.tls_version, ctx->tls.cipher);
    }
    if (ctx->http.status) {
        fprintf(f, "- HTTP status from interaction: **%ld**\n", ctx->http.status);
    }
    fprintf(f, "\n");

    // Target
    write_section_header(f, "Target");
    fprintf(f, "- **Host:** `%s`\n", ctx->target.host);
    fprintf(f, "- **Scheme/Port:** %s / %d\n", ctx->target.scheme, ctx->target.port);
    fprintf(f, "- **Path:** `%s`\n", ctx->target.path);
    if (ctx->target.is_ip) fprintf(f, "- **Literal IP**\n");

    // DNS
    write_section_header(f, "DNS Records");
    if (ctx->dns.n_a + ctx->dns.n_aaaa > 0) {
        fprintf(f, "### Address Records (A / AAAA)\n\n");
        for (size_t i=0; i<ctx->dns.n_a; i++) fprintf(f, "- `%s`\n", ctx->dns.a[i]);
        for (size_t i=0; i<ctx->dns.n_aaaa; i++) fprintf(f, "- `%s`\n", ctx->dns.aaaa[i]);
    }
    if (ctx->dns.n_cname) {
        fprintf(f, "\n### CNAME(s)\n\n");
        for (size_t i=0; i<ctx->dns.n_cname; i++) fprintf(f, "- `%s`\n", ctx->dns.cname[i]);
    }
    if (ctx->dns.n_ns) {
        fprintf(f, "\n### Name Servers\n\n");
        for (size_t i=0; i<ctx->dns.n_ns; i++) fprintf(f, "- `%s`\n", ctx->dns.ns[i]);
    }
    if (ctx->dns.n_mx) {
        fprintf(f, "\n### MX\n\n");
        for (size_t i=0; i<ctx->dns.n_mx; i++) fprintf(f, "- `%s`\n", ctx->dns.mx[i]);
    }
    if (ctx->dns.n_txt) {
        fprintf(f, "\n### TXT Records\n\n");
        for (size_t i=0; i<ctx->dns.n_txt; i++) {
            fprintf(f, "```\n%s\n```\n\n", ctx->dns.txt[i]);
        }
    }
    if (ctx->dns.soa) {
        fprintf(f, "### SOA\n\n`%s`\n\n", ctx->dns.soa);
    }
    if (ctx->dns.n_caa) {
        fprintf(f, "### CAA (Certificate Authority Authorization)\n\n");
        for (size_t i=0; i<ctx->dns.n_caa; i++) fprintf(f, "- `%s`\n", ctx->dns.caa[i]);
    }
    if (ctx->dns.n_ptr) {
        fprintf(f, "\n### PTR (Reverse DNS)\n\n");
        for (size_t i=0; i<ctx->dns.n_ptr; i++) fprintf(f, "- `%s`\n", ctx->dns.ptr[i]);
    }

    // Network Ownership (newly wired basic WHOIS)
    int has_reg = ctx->reg.registrar || ctx->reg.ip_org || ctx->reg.ip_country || ctx->reg.created;
    if (has_reg) {
        write_section_header(f, "Network Ownership (Public Registry Data)");
        if (ctx->reg.registrar || ctx->reg.created || ctx->reg.expires) {
            fprintf(f, "### Domain Registration\n\n");
            if (ctx->reg.registrar) fprintf(f, "- **Registrar:** `%s`\n", ctx->reg.registrar);
            if (ctx->reg.created)  fprintf(f, "- **Created:**   `%s`\n", ctx->reg.created);
            if (ctx->reg.expires)  fprintf(f, "- **Expires:**   `%s`\n", ctx->reg.expires);
            if (ctx->reg.updated)  fprintf(f, "- **Updated:**   `%s`\n", ctx->reg.updated);
            if (ctx->reg.n_statuses > 0) {
                fprintf(f, "- **Status:**    ");
                for (size_t i = 0; i < ctx->reg.n_statuses; i++) {
                    fprintf(f, "`%s`%s", ctx->reg.statuses[i], (i + 1 < ctx->reg.n_statuses) ? ", " : "");
                }
                fprintf(f, "\n");
            }
            fprintf(f, "\n");
        }
        if (ctx->reg.ip_org || ctx->reg.ip_country || ctx->reg.ip_cidr || ctx->reg.ip_asn) {
            fprintf(f, "### IP Netblock (observed address)\n\n");
            if (ctx->http.connected_ip) fprintf(f, "- **Observed IP:** `%s`\n", ctx->http.connected_ip);
            if (ctx->reg.ip_cidr)     fprintf(f, "- **CIDR / Range:** `%s`\n", ctx->reg.ip_cidr);
            if (ctx->reg.ip_netname)  fprintf(f, "- **NetName:**      `%s`\n", ctx->reg.ip_netname);
            if (ctx->reg.ip_org)      fprintf(f, "- **Organization:** `%s`\n", ctx->reg.ip_org);
            if (ctx->reg.ip_country)  fprintf(f, "- **Country:**      `%s`\n", ctx->reg.ip_country);
            if (ctx->reg.ip_asn) {
                fprintf(f, "- **ASN:**          `%s`", ctx->reg.ip_asn);
                if (ctx->reg.ip_asn_desc) fprintf(f, " (%s)", ctx->reg.ip_asn_desc);
                fprintf(f, "\n");
            }
            if (ctx->reg.ip_abuse)    fprintf(f, "- **Abuse Contact:** `%s`\n", ctx->reg.ip_abuse);
            fprintf(f, "\n");
        }
    }

    // Interaction
    write_section_header(f, "Single Interaction Results");
    if (ctx->http.connected_ip) {
        fprintf(f, "- **Connected IP:** `%s` (the address used for the one low-signal pull)\n", ctx->http.connected_ip);
    }
    if (ctx->tls.tls_version) fprintf(f, "- **TLS Version:** `%s`\n", ctx->tls.tls_version);
    if (ctx->tls.cipher) fprintf(f, "- **Cipher:** `%s`\n", ctx->tls.cipher);
    fprintf(f, "- **HTTP Status:** %ld\n", ctx->http.status);

    if (ctx->http.server) fprintf(f, "- **Server header:** `%s`\n", ctx->http.server);

    // Certs
    if (ctx->tls.n_chain > 0) {
        write_section_header(f, "TLS Certificate Chain");
        for (size_t i = 0; i < ctx->tls.n_chain; i++) {
            Cert *c = &ctx->tls.chain[i];
            fprintf(f, "### Certificate %zu (%s)\n\n", i, i==0 ? "leaf" : "intermediate/root");
            fprintf(f, "- **Subject:** `%s`\n", c->subject ? c->subject : "");
            fprintf(f, "- **Issuer:** `%s`\n", c->issuer ? c->issuer : "");
            fprintf(f, "- **Validity:** %s → %s  (%s)\n",
                    c->not_before ? c->not_before : "?",
                    c->not_after ? c->not_after : "?",
                    c->is_valid ? "VALID at collection time" : "EXPIRED or not yet valid");
            if (c->serial) fprintf(f, "- **Serial:** `%s`\n", c->serial);
            if (c->sig_algo) fprintf(f, "- **Signature Algorithm:** `%s`\n", c->sig_algo);
            if (c->pubkey_type) {
                fprintf(f, "- **Public Key:** %s %d bits", c->pubkey_type, c->pubkey_bits);
                if (c->curve) fprintf(f, " (curve: %s)", c->curve);
                fprintf(f, "\n");
            }
            if (c->fingerprint_sha256) {
                fprintf(f, "- **SHA-256 Fingerprint:**\n  ```\n  %s\n  ```\n", c->fingerprint_sha256);
            }
            if (c->n_sans > 0) {
                fprintf(f, "- **Subject Alternative Names:**\n");
                for (size_t s=0; s < c->n_sans; s++) fprintf(f, "  - `%s`\n", c->sans[s]);
            }
            fprintf(f, "\n");
        }
    }

    // Raw-ish headers
    if (ctx->http.n_headers > 0) {
        write_section_header(f, "HTTP Response Headers (captured)");
        fprintf(f, "```\n");
        for (size_t i=0; i < ctx->http.n_headers; i++) {
            fprintf(f, "%s\n", ctx->http.headers[i]);
        }
        fprintf(f, "```\n");
    }

    // Footer
    fprintf(f, "\n---\n\n");
    fprintf(f, "*Report generated by i2 v%s — strictly passive collection.*\n", I2_VERSION);

    fclose(f);

    // Also store the path back if we auto-generated
    if (!ctx->report_path || !ctx->report_path[0]) {
        // we can't easily mutate const here without changing the struct usage; caller can print path
    }

    printf("Report written: %s\n", path);
    return 0;
}
