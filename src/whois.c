/*
 * i2 - Basic text WHOIS collection + parsing
 * Uses public registry servers (whois.iana.org + referrals).
 * This is third-party public data, zero additional signal to the target.
 */

#include "../include/i2.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static int fetch_whois(const char *server, const char *query, char **out_resp, int timeout_sec) {
    if (!server || !query || !out_resp) return -1;
    *out_resp = NULL;

    struct addrinfo hints = {0}, *res = NULL, *rp;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char portstr[8] = "43";

    if (getaddrinfo(server, portstr, &hints, &res) != 0) return -1;

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) {
            close(fd); fd = -1; continue;
        }

        fd_set wfds;
        FD_ZERO(&wfds); FD_SET(fd, &wfds);
        struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
        rc = select(fd + 1, NULL, &wfds, NULL, &tv);
        if (rc <= 0) { close(fd); fd = -1; continue; }

        int err = 0; socklen_t len = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err != 0) { close(fd); fd = -1; continue; }

        // restore blocking
        flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        break;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;

    // Send query\r\n
    char qbuf[512];
    snprintf(qbuf, sizeof(qbuf), "%s\r\n", query);
    if (write(fd, qbuf, strlen(qbuf)) < 0) {
        close(fd); return -1;
    }

    // Read response with timeout
    struct timeval rcv_tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcv_tv, sizeof(rcv_tv));

    size_t cap = 8192, len = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return -1; }

    while (1) {
        if (len + 1024 > cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); close(fd); return -1; }
            buf = nb;
        }
        ssize_t n = read(fd, buf + len, cap - len - 1);
        if (n <= 0) break;
        len += n;
        buf[len] = 0;
    }
    close(fd);

    *out_resp = buf;
    return 0;
}

static void append_status(RegistryInfo *r, const char *val) {
    if (!r || !val) return;
    r->statuses = realloc(r->statuses, (r->n_statuses + 1) * sizeof(char*));
    r->statuses[r->n_statuses++] = safe_strdup(val);
}

static void parse_whois_text(const char *text, RegistryInfo *r, int for_ip) {
    if (!text || !r) return;

    char line[1024];
    const char *p = text;
    while (*p) {
        // extract one line
        size_t i = 0;
        while (*p && *p != '\n' && *p != '\r' && i < sizeof(line)-1) {
            line[i++] = *p++;
        }
        line[i] = 0;
        while (*p == '\r' || *p == '\n') p++;

        // find key: value
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = 0;
        char *key = line;
        char *val = colon + 1;
        while (*val == ' ' || *val == '\t') val++;

        // trim trailing
        char *end = val + strlen(val);
        while (end > val && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) *--end = 0;
        if (!*val) continue;

        // lower key for matching (simple)
        for (char *k = key; *k; ++k) *k = tolower((unsigned char)*k);

        if (for_ip) {
            if (strstr(key, "netname") || strstr(key, "net name")) {
                free(r->ip_netname); r->ip_netname = safe_strdup(val);
            } else if (strstr(key, "organization") || strstr(key, "orgname") || strstr(key, "org-name")) {
                free(r->ip_org); r->ip_org = safe_strdup(val);
            } else if (strstr(key, "country")) {
                free(r->ip_country); r->ip_country = safe_strdup(val);
            } else if (strstr(key, "netrange") || strstr(key, "cidr")) {
                free(r->ip_cidr); r->ip_cidr = safe_strdup(val);
            } else if (strstr(key, "originas") || strstr(key, "asnumber") || strstr(key, "aut-num")) {
                free(r->ip_asn); r->ip_asn = safe_strdup(val);
            } else if (strstr(key, "asname") || strstr(key, "as-name")) {
                free(r->ip_asn_desc); r->ip_asn_desc = safe_strdup(val);
            } else if (strstr(key, "abuse") && strstr(key, "email")) {
                free(r->ip_abuse); r->ip_abuse = safe_strdup(val);
            } else if (strstr(key, "orgabuseemail")) {
                free(r->ip_abuse); r->ip_abuse = safe_strdup(val);
            }
        } else {
            // domain
            if (strstr(key, "registrar") && !strstr(key, "whois") && !strstr(key, "server")) {
                free(r->registrar); r->registrar = safe_strdup(val);
            } else if (strstr(key, "creation") || strstr(key, "created")) {
                free(r->created); r->created = safe_strdup(val);
            } else if (strstr(key, "expiry") || strstr(key, "expires")) {
                free(r->expires); r->expires = safe_strdup(val);
            } else if (strstr(key, "updated")) {
                free(r->updated); r->updated = safe_strdup(val);
            } else if (strstr(key, "status") || strstr(key, "domain status")) {
                // may be "clientTransferProhibited https://..." - take first token or whole
                char *sp = strchr(val, ' ');
                if (sp) *sp = 0;
                append_status(r, val);
            }
        }
    }
}

static int extract_referral_server(const char *text, char *server_out, size_t outlen) {
    if (!text || !server_out) return 0;
    const char *p = strcasestr(text, "whois:");
    if (!p) p = strcasestr(text, "Registrar WHOIS Server:");
    if (!p) p = strcasestr(text, "whois server:");
    if (!p) return 0;

    p = strchr(p, ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;

    char *end = strchr(p, '\n');
    if (!end) end = strchr(p, '\r');
    if (!end) end = (char*)p + strlen(p);

    size_t len = end - p;
    if (len >= outlen) len = outlen - 1;
    memcpy(server_out, p, len);
    server_out[len] = 0;

    // trim
    while (len > 0 && (server_out[len-1] == ' ' || server_out[len-1] == '\t' || server_out[len-1] == '\r')) {
        server_out[--len] = 0;
    }
    return server_out[0] ? 1 : 0;
}

int collect_registry(const char *host, const char *ip, RegistryInfo *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    // --- Domain side (use host) ---
    if (host && host[0]) {
        char *resp1 = NULL;
        if (fetch_whois("whois.iana.org", host, &resp1, 6) == 0 && resp1) {
            char referral[128] = {0};
            if (extract_referral_server(resp1, referral, sizeof(referral))) {
                char *resp2 = NULL;
                if (fetch_whois(referral, host, &resp2, 8) == 0 && resp2) {
                    parse_whois_text(resp2, out, 0);
                    free(resp2);
                } else {
                    parse_whois_text(resp1, out, 0); // fallback
                }
            } else {
                parse_whois_text(resp1, out, 0);
            }
            free(resp1);
        }
    }

    // --- IP / Netblock side ---
    if (ip && ip[0]) {
        char *ip_resp = NULL;
        // Try ARIN first for many cases, fall back to IANA
        if (fetch_whois("whois.arin.net", ip, &ip_resp, 6) != 0 || !ip_resp) {
            if (ip_resp) free(ip_resp);
            ip_resp = NULL;
            fetch_whois("whois.iana.org", ip, &ip_resp, 6);
        }
        if (ip_resp) {
            parse_whois_text(ip_resp, out, 1);
            free(ip_resp);
        }
    }

    return 0;
}

void print_registry(const RegistryInfo *r) {
    if (!r) return;
    printf("%sNetwork Ownership (Public Registry)%s\n", C_HEADER, C_RESET);

    int has_dom = r->registrar || r->created || r->expires;
    if (has_dom) {
        printf("  %sDomain Registration:%s\n", C_LABEL, C_RESET);
        if (r->registrar) printf("    Registrar: %s%s%s\n", C_VALUE, r->registrar, C_RESET);
        if (r->created)  printf("    Created:   %s%s%s\n", C_VALUE, r->created, C_RESET);
        if (r->expires)  printf("    Expires:   %s%s%s\n", C_VALUE, r->expires, C_RESET);
        if (r->updated)  printf("    Updated:   %s%s%s\n", C_VALUE, r->updated, C_RESET);
        if (r->n_statuses) {
            printf("    Status:    ");
            for (size_t i = 0; i < r->n_statuses; i++) {
                printf("%s%s%s%s", i ? ", " : "", C_TECH, r->statuses[i], C_RESET);
            }
            printf("\n");
        }
    }

    int has_ip = r->ip_org || r->ip_country || r->ip_cidr || r->ip_asn;
    if (has_ip) {
        printf("  %sIP Netblock:%s\n", C_LABEL, C_RESET);
        if (r->ip_cidr)     printf("    Range/CIDR: %s%s%s\n", C_SUBJECT, r->ip_cidr, C_RESET);
        if (r->ip_netname)  printf("    NetName:    %s%s%s\n", C_VALUE, r->ip_netname, C_RESET);
        if (r->ip_org)      printf("    Org:        %s%s%s\n", C_VALUE, r->ip_org, C_RESET);
        if (r->ip_country)  printf("    Country:    %s%s%s\n", C_VALUE, r->ip_country, C_RESET);
        if (r->ip_asn) {
            printf("    ASN:        %s%s%s", C_TECH, r->ip_asn, C_RESET);
            if (r->ip_asn_desc) printf(" (%s%s%s)", C_VALUE, r->ip_asn_desc, C_RESET);
            printf("\n");
        }
        if (r->ip_abuse)    printf("    Abuse:      %s%s%s\n", C_WARN, r->ip_abuse, C_RESET);
    }

    if (!has_dom && !has_ip) {
        printf("  (no registry data retrieved or query returned limited/redacted results)\n");
    }
}
