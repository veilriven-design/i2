#include "../include/i2.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>

// Helper: append to a string array (realloc style)
static void append_str(char ***arr, size_t *n, const char *s) {
    if (!s) return;
    *arr = realloc(*arr, (*n + 1) * sizeof(char*));
    (*arr)[*n] = safe_strdup(s);
    (*n)++;
}

static void append_str_unique(char ***arr, size_t *n, const char *s) {
    if (!s) return;
    for (size_t i = 0; i < *n; i++) {
        if (strcmp((*arr)[i], s) == 0) return;
    }
    append_str(arr, n, s);
}

// Get A and AAAA + basic info via getaddrinfo (reliable, follows CNAME for addresses)
static int collect_addresses(const char *host, DNSInfo *out) {
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0) {
        // not fatal for partial results
        return 0;
    }

    char buf[INET6_ADDRSTRLEN];
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        void *addr = NULL;
        if (ai->ai_family == AF_INET) {
            addr = &((struct sockaddr_in *)ai->ai_addr)->sin_addr;
        } else if (ai->ai_family == AF_INET6) {
            addr = &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
        }
        if (addr && inet_ntop(ai->ai_family, addr, buf, sizeof(buf))) {
            if (ai->ai_family == AF_INET) {
                append_str_unique(&out->a, &out->n_a, buf);
            } else {
                append_str_unique(&out->aaaa, &out->n_aaaa, buf);
            }
        }
        // Canonname can give us a hint of CNAME behavior
        if (ai->ai_canonname && strcmp(ai->ai_canonname, host) != 0) {
            append_str_unique(&out->cname, &out->n_cname, ai->ai_canonname);
        }
    }
    freeaddrinfo(res);
    return 0;
}

// Generic res_query based collector for a type. Returns number of records found.
static int query_rr(const char *host, int type, DNSInfo *out) {
    unsigned char answer[NS_PACKETSZ];
    int len = res_query(host, ns_c_in, type, answer, sizeof(answer));
    if (len <= 0) return 0;

    ns_msg msg;
    if (ns_initparse(answer, len, &msg) < 0) return 0;

    int count = ns_msg_count(msg, ns_s_an);
    for (int i = 0; i < count; i++) {
        ns_rr rr;
        if (ns_parserr(&msg, ns_s_an, i, &rr) < 0) continue;

        char namebuf[NS_MAXDNAME];
        if (ns_rr_type(rr) != type) continue;

        switch (type) {
        case ns_t_ns: {
            if (dn_expand(ns_msg_base(msg), ns_msg_end(msg),
                          ns_rr_rdata(rr), namebuf, sizeof(namebuf)) > 0) {
                append_str_unique(&out->ns, &out->n_ns, namebuf);
            }
            break;
        }
        case ns_t_mx: {
            if (ns_rr_rdlen(rr) >= 2) {
                uint16_t pref = ntohs(*(const uint16_t *)ns_rr_rdata(rr));
                if (dn_expand(ns_msg_base(msg), ns_msg_end(msg),
                              ns_rr_rdata(rr) + 2, namebuf, sizeof(namebuf)) > 0) {
                    char mxline[NS_MAXDNAME + 8];
                    snprintf(mxline, sizeof(mxline), "%u %s", pref, namebuf);
                    append_str(&out->mx, &out->n_mx, mxline);
                }
            }
            break;
        }
        case ns_t_txt: {
            const unsigned char *rdata = ns_rr_rdata(rr);
            int rdlen = ns_rr_rdlen(rr);
            int pos = 0;
            while (pos < rdlen) {
                int txtlen = rdata[pos];
                if (pos + 1 + txtlen > rdlen) break;
                char txt[256];
                memcpy(txt, rdata + pos + 1, txtlen);
                txt[txtlen] = 0;
                append_str(&out->txt, &out->n_txt, txt);
                pos += 1 + txtlen;
            }
            break;
        }
        case ns_t_soa: {
            // Just capture a simple string representation for the report
            if (out->soa) break; // one is enough
            const unsigned char *rdata = ns_rr_rdata(rr);
            int rdlen = ns_rr_rdlen(rr);
            char primary[NS_MAXDNAME], admin[NS_MAXDNAME];
            int off = 0;
            if (dn_expand(ns_msg_base(msg), ns_msg_end(msg), rdata, primary, sizeof(primary)) > 0) {
                off = dn_skipname(rdata, rdata + rdlen);
                if (off > 0 && dn_expand(ns_msg_base(msg), ns_msg_end(msg), rdata + off, admin, sizeof(admin)) > 0) {
                    char soabuf[512];
                    snprintf(soabuf, sizeof(soabuf), "%s %s", primary, admin);
                    out->soa = safe_strdup(soabuf);
                }
            }
            break;
        }
        case ns_t_caa: {
            // CAA: flags + tag + value
            if (ns_rr_rdlen(rr) > 2) {
                const unsigned char *r = ns_rr_rdata(rr);
                int flags = r[0];
                int taglen = r[1];
                if (2 + taglen < ns_rr_rdlen(rr)) {
                    char tag[32] = {0};
                    memcpy(tag, r + 2, taglen < 31 ? taglen : 31);
                    const char *val = (const char *)(r + 2 + taglen);
                    int vallen = ns_rr_rdlen(rr) - 2 - taglen;
                    char caastr[256];
                    snprintf(caastr, sizeof(caastr), "%d %s \"%.*s\"", flags, tag, vallen, val);
                    append_str(&out->caa, &out->n_caa, caastr);
                }
            }
            break;
        }
        default:
            break;
        }
    }
    return count;
}

// PTR for an IP string (works for v4 and v6)
static int collect_ptr(const char *ipstr, DNSInfo *out) {
    struct in_addr a4;
    struct in6_addr a6;
    char rev[128];

    if (inet_pton(AF_INET, ipstr, &a4) == 1) {
        // in-addr.arpa
        const unsigned char *b = (const unsigned char *)&a4.s_addr;
        snprintf(rev, sizeof(rev), "%u.%u.%u.%u.in-addr.arpa",
                 b[3], b[2], b[1], b[0]);
    } else if (inet_pton(AF_INET6, ipstr, &a6) == 1) {
        // Simple ip6.arpa (nibble format) - we do a basic one
        char *p = rev;
        for (int i = 15; i >= 0; i--) {
            unsigned char byte = a6.s6_addr[i];
            p += sprintf(p, "%x.%x.", byte & 0xf, (byte >> 4) & 0xf);
        }
        strcpy(p, "ip6.arpa");
    } else {
        return 0;
    }

    unsigned char answer[NS_PACKETSZ];
    int len = res_query(rev, ns_c_in, ns_t_ptr, answer, sizeof(answer));
    if (len <= 0) return 0;

    ns_msg msg;
    if (ns_initparse(answer, len, &msg) < 0) return 0;

    for (int i = 0; i < ns_msg_count(msg, ns_s_an); i++) {
        ns_rr rr;
        if (ns_parserr(&msg, ns_s_an, i, &rr) < 0) continue;
        if (ns_rr_type(rr) != ns_t_ptr) continue;

        char name[NS_MAXDNAME];
        if (dn_expand(ns_msg_base(msg), ns_msg_end(msg),
                      ns_rr_rdata(rr), name, sizeof(name)) > 0) {
            append_str_unique(&out->ptr, &out->n_ptr, name);
        }
    }
    return 1;
}

int collect_dns(const char *host, DNSInfo *out) {
    if (!host || !out) return -1;
    memset(out, 0, sizeof(*out));

    // Addresses (A/AAAA + some CNAME visibility)
    collect_addresses(host, out);

    // Other record types via resolver
    (void)query_rr(host, ns_t_ns, out);
    (void)query_rr(host, ns_t_mx, out);
    (void)query_rr(host, ns_t_txt, out);
    (void)query_rr(host, ns_t_soa, out);
    (void)query_rr(host, ns_t_caa, out);

    // PTRs for everything we resolved
    for (size_t i = 0; i < out->n_a; i++) {
        collect_ptr(out->a[i], out);
    }
    for (size_t i = 0; i < out->n_aaaa; i++) {
        collect_ptr(out->aaaa[i], out);
    }

    return 0;
}

void print_dns(const DNSInfo *d) {
    printf("%sDNS Records%s\n", C_HEADER, C_RESET);

    if (d->n_a || d->n_aaaa) {
        printf("  %sA/AAAA:%s\n", C_LABEL, C_RESET);
        for (size_t i = 0; i < d->n_a; i++)   printf("    %s%s%s\n", C_SUBJECT, d->a[i], C_RESET);
        for (size_t i = 0; i < d->n_aaaa; i++) printf("    %s%s%s\n", C_SUBJECT, d->aaaa[i], C_RESET);
    }
    if (d->n_cname) {
        printf("  %sCNAME chain:%s\n", C_LABEL, C_RESET);
        for (size_t i = 0; i < d->n_cname; i++) printf("    %s%s%s\n", C_VALUE, d->cname[i], C_RESET);
    }
    if (d->n_ns) {
        printf("  %sNS:%s\n", C_LABEL, C_RESET);
        for (size_t i = 0; i < d->n_ns; i++) printf("    %s%s%s\n", C_VALUE, d->ns[i], C_RESET);
    }
    if (d->n_mx) {
        printf("  %sMX:%s\n", C_LABEL, C_RESET);
        for (size_t i = 0; i < d->n_mx; i++) printf("    %s%s%s\n", C_VALUE, d->mx[i], C_RESET);
    }
    if (d->n_txt) {
        printf("  %sTXT:%s\n", C_LABEL, C_RESET);
        for (size_t i = 0; i < d->n_txt; i++) {
            printf("    %s\"%s\"%s\n", C_TECH, d->txt[i], C_RESET);
        }
    }
    if (d->soa) {
        printf("  %sSOA:%s %s\n", C_LABEL, C_RESET, d->soa);
    }
    if (d->n_caa) {
        printf("  %sCAA:%s\n", C_LABEL, C_RESET);
        for (size_t i = 0; i < d->n_caa; i++) printf("    %s%s%s\n", C_TECH, d->caa[i], C_RESET);
    }
    if (d->n_ptr) {
        printf("  %sPTR (reverse):%s\n", C_LABEL, C_RESET);
        for (size_t i = 0; i < d->n_ptr; i++) printf("    %s%s%s\n", C_VALUE, d->ptr[i], C_RESET);
    }

    if (!d->n_a && !d->n_aaaa && !d->n_ns && !d->n_txt) {
        printf("  (no DNS records retrieved or host not resolvable)\n");
    }
}
