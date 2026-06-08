#include "../include/i2.h"
#include <ctype.h>
#include <netdb.h>   // for getaddrinfo hints

// Very small URL / host parser for i2.
// Supports: example.com, 1.2.3.4, https://example.com, https://example.com:8443/foo

static bool looks_like_ip(const char *s) {
    // Very rough; good enough for our purposes. Real validation can be added.
    if (!s) return false;
    int dots = 0, colons = 0;
    for (const char *p = s; *p; ++p) {
        if (*p == '.') dots++;
        if (*p == ':') colons++;
        if (isalpha((unsigned char)*p)) return false;
    }
    return (dots == 3 && colons == 0) || (colons > 1);
}

int parse_target(const char *input, Target *out) {
    memset(out, 0, sizeof(*out));
    out->original = safe_strdup(input);

    const char *p = input;

    // scheme?
    if (strncmp(p, "http://", 7) == 0) {
        out->scheme = safe_strdup("http");
        p += 7;
    } else if (strncmp(p, "https://", 8) == 0) {
        out->scheme = safe_strdup("https");
        p += 8;
    } else {
        out->scheme = safe_strdup("https"); // default to https for web targets
    }

    // host + optional :port + path
    const char *host_start = p;
    const char *host_end = p;
    const char *path_start = "/";

    while (*host_end && *host_end != '/' && *host_end != ':') host_end++;

    if (*host_end == ':') {
        // port
        char *port_str = NULL;
        const char *port_start = host_end + 1;
        const char *port_end = port_start;
        while (*port_end && *port_end != '/') port_end++;
        size_t plen = port_end - port_start;
        port_str = malloc(plen + 1);
        memcpy(port_str, port_start, plen);
        port_str[plen] = 0;
        out->port = atoi(port_str);
        free(port_str);

        host_end = host_end; // host is before the :
        // path
        if (*port_end == '/') path_start = port_end;
    } else if (*host_end == '/') {
        path_start = host_end;
    }

    size_t hlen = host_end - host_start;
    out->host = malloc(hlen + 1);
    memcpy(out->host, host_start, hlen);
    out->host[hlen] = 0;

    out->path = safe_strdup(path_start);
    if (out->port == 0) {
        out->port = (strcmp(out->scheme, "https") == 0) ? 443 : 80;
    }

    out->is_ip = looks_like_ip(out->host);

    return 0;
}

// Simple pretty printer for debug / early terminal use
void print_target(const Target *t) {
    printf("%sTarget%s\n", C_HEADER, C_RESET);
    printf("  %soriginal:%s %s\n", C_LABEL, C_RESET, t->original);
    printf("  %shost:%s     %s%s%s\n", C_LABEL, C_RESET, C_SUBJECT, t->host, C_RESET);
    printf("  %sscheme:%s   %s\n", C_LABEL, C_RESET, t->scheme);
    printf("  %sport:%s     %d\n", C_LABEL, C_RESET, t->port);
    printf("  %spath:%s     %s\n", C_LABEL, C_RESET, t->path);
    printf("  %stype:%s     %s\n", C_LABEL, C_RESET, t->is_ip ? "IP literal" : "hostname");
}
