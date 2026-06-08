/*
 * i2 - Passive single interaction (raw sockets + OpenSSL)
 * This is the "one pull" — as low signal as a normal HEAD request.
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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

static int connect_with_timeout(const char *host, int port, int timeout_sec, int *out_fd, char *ipbuf, size_t ipbuflen) {
    struct addrinfo hints = {0}, *res = NULL, *rp;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        // non-blocking for timeout
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) {
            // immediate
            break;
        }
        if (errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
        rc = select(fd + 1, NULL, &wfds, NULL, &tv);
        if (rc > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == 0) break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd < 0) return -1;

    // restore blocking
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    // capture the IP we actually connected to
    struct sockaddr_storage peer;
    socklen_t plen = sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &plen) == 0) {
        if (peer.ss_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)&peer)->sin_addr, ipbuf, ipbuflen);
        } else if (peer.ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&peer)->sin6_addr, ipbuf, ipbuflen);
        }
    }

    *out_fd = fd;
    return 0;
}

static void init_openssl(void) {
    static bool inited = false;
    if (!inited) {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        inited = true;
    }
}

static SSL_CTX *create_tls_ctx(void) {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) return NULL;

    // Reasonable modern options
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // analysis only; we still record what we see
    return ctx;
}

// Very small but useful X509 -> Cert parser
static void extract_name(X509_NAME *name, char *buf, size_t buflen) {
    if (!name) {
        strncpy(buf, "(none)", buflen);
        return;
    }
    X509_NAME_oneline(name, buf, buflen);
}

static char *x509_time_to_str(const ASN1_TIME *t) {
    if (!t) return safe_strdup("unknown");
    struct tm tm;
    if (ASN1_TIME_to_tm(t, &tm) == 1) {
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm);
        return safe_strdup(buf);
    }
    return safe_strdup("unparseable");
}

static void parse_one_cert(X509 *x, Cert *c) {
    if (!x || !c) return;

    char buf[1024];

    X509_NAME *subj = X509_get_subject_name(x);
    X509_NAME *iss  = X509_get_issuer_name(x);
    extract_name(subj, buf, sizeof(buf));
    c->subject = safe_strdup(buf);
    extract_name(iss, buf, sizeof(buf));

    c->not_before = x509_time_to_str(X509_get0_notBefore(x));
    c->not_after  = x509_time_to_str(X509_get0_notAfter(x));

    // crude validity
    time_t now = time(NULL);
    // We rely on OpenSSL's X509_cmp_current_time style logic via ASN1
    // For simplicity we just mark based on not_after for the report later.

    // Serial (hex)
    const ASN1_INTEGER *serial = X509_get0_serialNumber(x);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (bn) {
        char *hex = BN_bn2hex(bn);
        c->serial = safe_strdup(hex);
        OPENSSL_free(hex);
        BN_free(bn);
    }

    // Signature algo
    int sig_nid = X509_get_signature_nid(x);
    c->sig_algo = safe_strdup(OBJ_nid2ln(sig_nid));

    // Public key
    EVP_PKEY *pkey = X509_get_pubkey(x);
    if (pkey) {
        c->pubkey_bits = EVP_PKEY_bits(pkey);
        int ptype = EVP_PKEY_id(pkey);
        c->pubkey_type = safe_strdup(OBJ_nid2sn(ptype));

        if (ptype == EVP_PKEY_EC) {
            // curve name if available
            const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
            if (ec) {
                const EC_GROUP *grp = EC_KEY_get0_group(ec);
                int nid = EC_GROUP_get_curve_name(grp);
                c->curve = safe_strdup(OBJ_nid2sn(nid));
            }
        }
        EVP_PKEY_free(pkey);
    }

    // SANs
    STACK_OF(GENERAL_NAME) *san_stack = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
    if (san_stack) {
        int num = sk_GENERAL_NAME_num(san_stack);
        c->sans = calloc(num, sizeof(char*));
        c->n_sans = 0;
        for (int i = 0; i < num; i++) {
            GENERAL_NAME *gn = sk_GENERAL_NAME_value(san_stack, i);
            if (gn->type == GEN_DNS) {
                ASN1_IA5STRING *ia5 = gn->d.dNSName;
                char *s = safe_strdup((const char *)ia5->data);
                c->sans[c->n_sans++] = s;
            } else if (gn->type == GEN_IPADD) {
                // IP SAN
                char ipbuf[INET6_ADDRSTRLEN] = {0};
                const ASN1_OCTET_STRING *os = gn->d.iPAddress;
                if (os->length == 4) {
                    inet_ntop(AF_INET, os->data, ipbuf, sizeof(ipbuf));
                } else if (os->length == 16) {
                    inet_ntop(AF_INET6, os->data, ipbuf, sizeof(ipbuf));
                }
                if (ipbuf[0]) {
                    char with_prefix[64];
                    snprintf(with_prefix, sizeof(with_prefix), "IP:%s", ipbuf);
                    c->sans[c->n_sans++] = safe_strdup(with_prefix);
                }
            }
        }
        sk_GENERAL_NAME_pop_free(san_stack, GENERAL_NAME_free);
    }

    // Fingerprint (SHA-256 of the cert DER)
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    if (X509_digest(x, EVP_sha256(), md, &mdlen) == 1) {
        char fp[128] = {0};
        char *p = fp;
        for (unsigned int i = 0; i < mdlen; i++) {
            p += sprintf(p, "%02X%s", md[i], (i + 1 < mdlen) ? ":" : "");
        }
        c->fingerprint_sha256 = safe_strdup(fp);
    }

    // Basic CT / OCSP hints (extensions)
    // Look for SCT list extension (1.3.6.1.4.1.11129.2.4.2) or just note presence of OCSP
    int loc = X509_get_ext_by_NID(x, NID_info_access, -1);
    if (loc >= 0) {
        X509_EXTENSION *ext = X509_get_ext(x, loc);
        // crude: many certs have OCSP in AIA
        c->ocsp_uri = safe_strdup("present (see full chain in report)");
    }

    // Rough validity check
    c->is_valid = (X509_cmp_current_time(X509_get0_notAfter(x)) > 0);
}

static int extract_chain(SSL *ssl, TLSInfo *tls) {
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    if (!chain) {
        X509 *leaf = SSL_get_peer_certificate(ssl);
        if (leaf) {
            tls->n_chain = 1;
            tls->chain = calloc(1, sizeof(Cert));
            parse_one_cert(leaf, &tls->chain[0]);
            X509_free(leaf);
        }
        return 0;
    }

    int n = sk_X509_num(chain);
    tls->chain = calloc(n, sizeof(Cert));
    tls->n_chain = n;

    for (int i = 0; i < n; i++) {
        X509 *x = sk_X509_value(chain, i);
        parse_one_cert(x, &tls->chain[i]);
    }
    return 0;
}

int perform_passive_interaction(const Target *t, TLSInfo *tls_out, HTTPInfo *http_out, char *connected_ip, size_t iplen) {
    if (!t || !tls_out || !http_out) return -1;

    memset(tls_out, 0, sizeof(*tls_out));
    memset(http_out, 0, sizeof(*http_out));

    init_openssl();

    int fd = -1;
    char ip[INET6_ADDRSTRLEN] = {0};
    if (connect_with_timeout(t->host, t->port, 8, &fd, ip, sizeof(ip)) != 0) {
        return -1;
    }
    if (connected_ip && iplen > 0) strncpy(connected_ip, ip, iplen);

    // Store for the report / context (primary place for "what IP did we actually talk to")
    if (http_out && ip[0]) {
        http_out->connected_ip = safe_strdup(ip);
    }

    SSL_CTX *ctx = create_tls_ctx();
    if (!ctx) {
        close(fd);
        return -1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, t->host);   // SNI — important and low signal

    int ret = SSL_connect(ssl);
    if (ret != 1) {
        // Still try to extract what we can (some info may be available)
        ERR_print_errors_fp(stderr);
    }

    // Capture TLS version and cipher even on partial failure
    const char *ver  = SSL_get_version(ssl);
    const SSL_CIPHER *c = SSL_get_current_cipher(ssl);
    tls_out->tls_version = safe_strdup(ver ? ver : "unknown");
    if (c) {
        tls_out->cipher = safe_strdup(SSL_CIPHER_get_name(c));
    }

    // Extract cert chain (this is the gold)
    extract_chain(ssl, tls_out);

    // Now do the actual low-signal HTTP request (HEAD preferred)
    char req[1024];
    const char *meth = "HEAD";
    snprintf(req, sizeof(req),
             "%s %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: i2/%s (passive analysis; US legal public data only)\r\n"
             "Accept: */*\r\n"
             "Connection: close\r\n"
             "\r\n",
             meth, t->path, t->host, I2_VERSION);

    SSL_write(ssl, req, strlen(req));

    // Read headers only (stop at blank line)
    char buf[8192];
    size_t total = 0;
    int header_done = 0;
    char *headers_raw = NULL;
    size_t hcap = 0;

    struct timeval tv = { .tv_sec = 6, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (total < sizeof(buf) - 1) {
        int n = SSL_read(ssl, buf + total, sizeof(buf) - 1 - total);
        if (n <= 0) break;
        total += n;
        buf[total] = 0;

        // look for end of headers
        if (strstr(buf, "\r\n\r\n")) {
            header_done = 1;
            break;
        }
    }

    // Parse status and headers crudely but effectively
    char *line = strtok(buf, "\r\n");
    if (line && strncmp(line, "HTTP/", 5) == 0) {
        http_out->status = strtol(line + 9, NULL, 10); // rough "200 OK"
    }

    http_out->effective_url = safe_strdup(t->original); // simplistic; can be improved with Location following

    // Collect raw headers
    char **hlist = NULL;
    size_t nh = 0;
    while ((line = strtok(NULL, "\r\n"))) {
        if (strlen(line) == 0) break;
        // local small append to avoid static dependency
        hlist = realloc(hlist, (nh + 1) * sizeof(char*));
        hlist[nh] = safe_strdup(line);
        nh++;

        // quick interesting fields
        if (strncasecmp(line, "Server:", 7) == 0) {
            http_out->server = safe_strdup(line + 8);
        }
        if (strncasecmp(line, "X-Powered-By:", 13) == 0) {
            http_out->x_powered_by = safe_strdup(line + 14);
        }
    }
    http_out->headers = hlist;
    http_out->n_headers = nh;

    // Very rough timing (we can improve with BIO or clock_gettime around phases)
    http_out->time_total = 0.0; // placeholder for now

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);

    // Stash the IP we used
    if (connected_ip) {
        // already filled earlier
    }

    return 0;
}

// Minimal printer for the interaction results (will be replaced by the full report writer)
void print_interaction_summary(const Target *t, const TLSInfo *tls, const HTTPInfo *http, const char *ip) {
    printf("%sSingle Interaction (%s)%s\n", C_HEADER, t->scheme, C_RESET);
    if (ip && ip[0]) {
        printf("  %sConnected IP:%s %s%s%s\n", C_LABEL, C_RESET, C_SUBJECT, ip, C_RESET);
    }
    if (tls->tls_version || tls->cipher) {
        printf("  %sTLS:%s %s / %s%s%s\n",
               C_LABEL, C_RESET,
               tls->tls_version ? tls->tls_version : "?",
               C_TECH, tls->cipher ? tls->cipher : "?", C_RESET);
    }
    if (http->status) {
        const char *color = (http->status >= 200 && http->status < 400) ? C_GOOD : C_WARN;
        printf("  %sHTTP Status:%s %s%ld%s\n", C_LABEL, C_RESET, color, http->status, C_RESET);
    }
    if (http->server) {
        printf("  %sServer:%s %s\n", C_LABEL, C_RESET, http->server);
    }
    if (tls->n_chain > 0) {
        Cert *leaf = &tls->chain[0];
        printf("  %sLeaf Cert Subject:%s %s\n", C_LABEL, C_RESET, leaf->subject);
        printf("  %sIssuer:%s %s\n", C_LABEL, C_RESET, leaf->issuer);
        if (leaf->fingerprint_sha256) {
            printf("  %sSHA256 FP:%s %s%s%s\n", C_LABEL, C_RESET, C_TECH, leaf->fingerprint_sha256, C_RESET);
        }
        printf("  %sValid:%s %s%s%s\n", C_LABEL, C_RESET,
               leaf->is_valid ? C_GOOD : C_BAD,
               leaf->is_valid ? "yes" : "NO/EXPIRED",
               C_RESET);
        if (leaf->n_sans > 0) {
            printf("  %sSANs:%s\n", C_LABEL, C_RESET);
            for (size_t i = 0; i < leaf->n_sans; i++) {
                printf("    %s%s%s\n", C_VALUE, leaf->sans[i], C_RESET);
            }
        }
    }
    if (http->n_headers > 0) {
        printf("  %sHeaders captured:%s %zu\n", C_LABEL, C_RESET, http->n_headers);
    }
}
