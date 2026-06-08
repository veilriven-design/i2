#ifndef I2_H
#define I2_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "colors.h"

#define I2_VERSION "0.1.0"
#define I2_NAME    "i2"

typedef struct {
    char *original;     // as provided by user
    char *host;         // normalized hostname or IP literal
    char *scheme;       // "https" or "http"
    int   port;         // 443, 80, or explicit
    char *path;         // usually "/"
    bool  is_ip;        // true if host is literal IP
} Target;

typedef struct {
    // Core DNS
    char  **a;          size_t n_a;
    char  **aaaa;       size_t n_aaaa;
    char  **cname;      size_t n_cname;
    char  **ns;         size_t n_ns;
    char  **mx;         size_t n_mx;
    char  **txt;        size_t n_txt;
    char   *soa;
    char  **caa;        size_t n_caa;
    char  **ptr;        size_t n_ptr;   // one per resolved address
} DNSInfo;

typedef struct {
    char *subject;
    char *issuer;
    char *not_before;
    char *not_after;
    int   days_valid;           // relative to now
    bool  is_valid;             // not expired at collection time
    char *serial;
    char *sig_algo;
    char *pubkey_type;
    int   pubkey_bits;
    char *curve;                // for EC
    char **sans;                size_t n_sans;
    char *fingerprint_sha256;
    bool  has_sct;              // Certificate Transparency evidence
    char *ocsp_uri;
    // add more interesting extensions as parsed
} Cert;

typedef struct {
    char *tls_version;
    char *cipher;
    Cert  *chain;               size_t n_chain; // leaf = [0]
} TLSInfo;

typedef struct {
    long   status;
    char  *effective_url;
    char **headers;             size_t n_headers;
    char  *server;
    char  *x_powered_by;
    char **cookies;             size_t n_cookies; // "name; Secure; HttpOnly; ..."
    double time_total;
    double time_connect;
    double time_appconnect;     // TLS
    char  *connected_ip;        // IP we actually spoke to during the single interaction
} HTTPInfo;

typedef struct {
    // Domain
    char *registrar;
    char *created;
    char *expires;
    char *updated;
    char **statuses;            size_t n_statuses;

    // IP / Netblock
    char *ip_netname;
    char *ip_org;
    char *ip_country;
    char *ip_cidr;
    char *ip_asn;
    char *ip_asn_desc;
    char *ip_abuse;
} RegistryInfo;

typedef struct {
    Target       target;
    DNSInfo      dns;
    TLSInfo      tls;
    HTTPInfo     http;
    RegistryInfo reg;

    time_t       collected_at;
    char        *report_path;
} ReportContext;

// Utility
void free_string_array(char **arr, size_t n);
void free_target(Target *t);
void free_dns(DNSInfo *d);
void free_tls(TLSInfo *t);
void free_http(HTTPInfo *h);
void free_reg(RegistryInfo *r);
void free_report(ReportContext *ctx);

char *safe_strdup(const char *s);
char *timestamp_iso(void);

// Target parsing (implemented in src/target.c)
int  parse_target(const char *input, Target *out);
void print_target(const Target *t);

// DNS collection (src/dns.c)
int  collect_dns(const char *host, DNSInfo *out);
void print_dns(const DNSInfo *d);

// Passive single interaction + TLS (src/interact.c)
int  perform_passive_interaction(const Target *t, TLSInfo *tls_out, HTTPInfo *http_out,
                                 char *connected_ip, size_t iplen);
void print_interaction_summary(const Target *t, const TLSInfo *tls, const HTTPInfo *http, const char *ip);

// Report writer (src/report.c)
int write_report(const ReportContext *ctx);

// Registry / WHOIS (src/whois.c) - basic text whois + parsing, public servers only
int  collect_registry(const char *host, const char *ip, RegistryInfo *out);
void print_registry(const RegistryInfo *r);

#endif // I2_H
