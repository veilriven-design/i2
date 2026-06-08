#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>   // for INET6_ADDRSTRLEN

#include "../include/i2.h"

static void usage(const char *prog) {
    printf("%s%s v%s%s - Passive Internet Intelligence\n\n", C_BOLD_CYAN, I2_NAME, I2_VERSION, C_RESET);
    printf("Usage: %s <target> [options]\n\n", prog);
    printf("  <target>             Domain, IP, or full URL (http/https)\n\n");
    printf("Options:\n");
    printf("  -o, --output FILE    Write Markdown report to FILE (default: auto-generated)\n");
    printf("  -m, --method M       Force method: head or get (default: head)\n");
    printf("  -c, --color          Force color even if not a tty\n");
    printf("  -h, --help           Show this help\n\n");
    printf("Examples:\n");
    printf("  %s example.com\n", prog);
    printf("  %s https://www.google.com -o google-report.md\n", prog);
    printf("  %s 1.1.1.1\n\n", prog);
    printf("i2 performs only passive collection from public sources and one standard\n");
    printf("client interaction with the target. See README for details and legal notes.\n");
}

static void print_banner(void) {
    i2_color(C_BOLD_CYAN);
    printf("i2");
    i2_reset();
    printf(" — passive analysis  |  v%s\n", I2_VERSION);
}

int main(int argc, char **argv) {
    char *target_str = NULL;
    char *output_path = NULL;
    char *method = NULL;
    bool force_color = false; (void)force_color; // placeholder for future use

    static struct option long_opts[] = {
        {"output", required_argument, 0, 'o'},
        {"method", required_argument, 0, 'm'},
        {"color",  no_argument,       0, 'c'},
        {"help",   no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "o:m:ch", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'o': output_path = safe_strdup(optarg); break;
            case 'm': method = safe_strdup(optarg); break;
            case 'c': force_color = true; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    if (optind < argc) {
        target_str = safe_strdup(argv[optind]);
    }

    if (!target_str) {
        usage(argv[0]);
        return 1;
    }

    print_banner();
    printf("Target: %s%s%s\n\n", C_SUBJECT, target_str, C_RESET);

    Target t = {0};
    if (parse_target(target_str, &t) != 0) {
        fprintf(stderr, "%sError:%s failed to parse target\n", C_BAD, C_RESET);
        free(target_str);
        free(output_path);
        free(method);
        return 1;
    }

    print_target(&t);

    printf("\n");

    DNSInfo dns = {0};
    collect_dns(t.host, &dns);
    print_dns(&dns);

    printf("\n%s[collection]%s Passive DNS + single interaction complete.\n\n", C_GOOD, C_RESET);

    // === The single low-signal pull (the core of "i2") ===
    TLSInfo  tls  = {0};
    HTTPInfo http = {0};
    char connected_ip[INET6_ADDRSTRLEN] = {0};

    if (perform_passive_interaction(&t, &tls, &http, connected_ip, sizeof(connected_ip)) == 0) {
        print_interaction_summary(&t, &tls, &http, connected_ip);
    } else {
        printf("%s[interaction]%s Could not complete TLS+HTTP pull (network, timeout, or handshake issue).\n", C_WARN, C_RESET);
    }

    // === Registry data (basic text WHOIS from public servers) ===
    RegistryInfo reg = {0};
    const char *ip_for_reg = (connected_ip[0] ? connected_ip : http.connected_ip);
    collect_registry(t.host, ip_for_reg, &reg);
    print_registry(&reg);

    // === Build context (shallow ownership for this version) and write the external file ===
    ReportContext ctx = {0};
    ctx.target = t;
    ctx.dns    = dns;
    ctx.tls    = tls;
    ctx.http   = http;
    ctx.reg    = reg;

    if (write_report(&ctx) != 0) {
        printf("%s[report]%s Failed to write the Markdown report file.\n", C_BAD, C_RESET);
    } else {
        // success message is printed inside write_report
    }

    // Now safe to free (report writer has already run)
    free_tls(&tls);
    free_http(&http);
    free_target(&t);
    free_dns(&dns);
    free_reg(&reg);

    // Cleanup
    free(target_str);
    free(output_path);
    free(method);
    return 0;
}
