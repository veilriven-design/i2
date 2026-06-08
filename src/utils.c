#include "../include/i2.h"
#include <ctype.h>

char *safe_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *p = malloc(len);
    if (p) memcpy(p, s, len);
    return p;
}

void free_string_array(char **arr, size_t n) {
    if (!arr) return;
    for (size_t i = 0; i < n; i++) {
        free(arr[i]);
    }
    free(arr);
}

void free_target(Target *t) {
    if (!t) return;
    free(t->original);
    free(t->host);
    free(t->scheme);
    free(t->path);
    memset(t, 0, sizeof(*t));
}

void free_dns(DNSInfo *d) {
    if (!d) return;
    free_string_array(d->a, d->n_a);
    free_string_array(d->aaaa, d->n_aaaa);
    free_string_array(d->cname, d->n_cname);
    free_string_array(d->ns, d->n_ns);
    free_string_array(d->mx, d->n_mx);
    free_string_array(d->txt, d->n_txt);
    free(d->soa);
    free_string_array(d->caa, d->n_caa);
    free_string_array(d->ptr, d->n_ptr);
    memset(d, 0, sizeof(*d));
}

void free_tls(TLSInfo *t) {
    if (!t) return;
    free(t->tls_version);
    free(t->cipher);
    if (t->chain) {
        for (size_t i = 0; i < t->n_chain; i++) {
            Cert *c = &t->chain[i];
            free(c->subject);
            free(c->issuer);
            free(c->not_before);
            free(c->not_after);
            free(c->serial);
            free(c->sig_algo);
            free(c->pubkey_type);
            free(c->curve);
            free_string_array(c->sans, c->n_sans);
            free(c->fingerprint_sha256);
            free(c->ocsp_uri);
        }
        free(t->chain);
    }
    memset(t, 0, sizeof(*t));
}

void free_http(HTTPInfo *h) {
    if (!h) return;
    free(h->effective_url);
    free_string_array(h->headers, h->n_headers);
    free(h->server);
    free(h->x_powered_by);
    free_string_array(h->cookies, h->n_cookies);
    free(h->connected_ip);
    memset(h, 0, sizeof(*h));
}

void free_reg(RegistryInfo *r) {
    if (!r) return;
    free(r->registrar);
    free(r->created);
    free(r->expires);
    free(r->updated);
    free_string_array(r->statuses, r->n_statuses);
    free(r->ip_netname);
    free(r->ip_org);
    free(r->ip_country);
    free(r->ip_cidr);
    free(r->ip_asn);
    free(r->ip_asn_desc);
    free(r->ip_abuse);
    memset(r, 0, sizeof(*r));
}

void free_report(ReportContext *ctx) {
    if (!ctx) return;
    free_target(&ctx->target);
    free_dns(&ctx->dns);
    free_tls(&ctx->tls);
    free_http(&ctx->http);
    free_reg(&ctx->reg);
    free(ctx->report_path);
    memset(ctx, 0, sizeof(*ctx));
}

char *timestamp_iso(void) {
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm);
    return safe_strdup(buf);
}
