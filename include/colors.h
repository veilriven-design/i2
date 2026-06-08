#ifndef I2_COLORS_H
#define I2_COLORS_H

// ANSI color codes for rich terminal output.
// Designed for visual identification of subjects, objects, and posture.

#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"

// Foreground
#define C_BLACK   "\033[30m"
#define C_RED     "\033[31m"
#define C_GREEN   "\033[32m"
#define C_YELLOW  "\033[33m"
#define C_BLUE    "\033[34m"
#define C_MAGENTA "\033[35m"
#define C_CYAN    "\033[36m"
#define C_WHITE   "\033[37m"

// Bright / bold variants (often more visible)
#define C_BOLD_RED     "\033[1;31m"
#define C_BOLD_GREEN   "\033[1;32m"
#define C_BOLD_YELLOW  "\033[1;33m"
#define C_BOLD_BLUE    "\033[1;34m"
#define C_BOLD_MAGENTA "\033[1;35m"
#define C_BOLD_CYAN    "\033[1;36m"
#define C_BOLD_WHITE   "\033[1;37m"

// Semantic mappings for i2 (tweak as needed for "subjects and objects")
#define C_SUBJECT   C_BOLD_CYAN      // hosts, domains, IPs, primary entities
#define C_VALUE     C_CYAN           // data values
#define C_TECH      C_MAGENTA        // ciphers, serials, fingerprints, raw blobs
#define C_GOOD      C_BOLD_GREEN     // strong security posture, valid
#define C_BAD       C_BOLD_RED       // missing controls, expired, weak
#define C_WARN      C_BOLD_YELLOW    // partial, interesting observations
#define C_HEADER    C_BOLD_BLUE      // section headers
#define C_LABEL     C_BOLD_WHITE     // "Label:" prefixes
#define C_NORMAL    C_WHITE

// Helper to conditionally color (simple version; can be extended with isatty)
static inline void i2_color(const char *code) {
    fputs(code, stdout);
}

static inline void i2_reset(void) {
    fputs(C_RESET, stdout);
}

#endif // I2_COLORS_H
