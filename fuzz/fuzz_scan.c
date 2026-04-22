#include <keytrawl/keytrawl.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FINDINGS 64

typedef struct {
    size_t n;
    unsigned long long fp[MAX_FINDINGS][5];
} log_t;

static int record(void *ctx, const ktw_finding_t *f)
{
    log_t *l = ctx;
    const char *e = ktw_finding_evidence(f);
    unsigned long long h = 1469598103934665603ull;

    for (; *e != '\0'; e++)
        h = (h ^ (unsigned char)*e) * 1099511628211ull;
    if (strlen(ktw_finding_evidence(f)) >= 256)
        abort();
    if (l->n < MAX_FINDINGS) {
        l->fp[l->n][0] = (unsigned long long)ktw_finding_kind(f) << 32 | (unsigned)ktw_finding_confidence(f);
        l->fp[l->n][1] = ktw_finding_offset(f);
        l->fp[l->n][2] = ktw_finding_length(f);
        l->fp[l->n][3] = ktw_finding_line(f) << 8 | ktw_finding_checks(f) << 4 | ktw_finding_flags(f);
        l->fp[l->n][4] = h;
    }
    l->n++;
    return 0;
}

static int user_check(void *ctx, const unsigned char *data, size_t data_len, size_t *out_len)
{
    (void)ctx;
    *out_len = data_len;
    return data_len > 6 && data[6] == '!' ? KTW_CONFIRMED : 0;
}

static ktw_catalog_t *catalog;
static ktw_scanner_t *scanner;
static const char *const names[] = {NULL, "/etc/config/wireless", "hostapd.conf", "authorized_keys", "libc.so.6"};

static void run(const uint8_t *data, size_t size, const char *name, unsigned seed, log_t *l)
{
    size_t at = 0;

    l->n = 0;
    if (ktw_scanner_reset(scanner, name, name == NULL ? 0 : strlen(name), seed & 1u) != KTW_OK)
        abort();
    while (at < size) {
        size_t piece = size - at;

        if (seed != 0) {
            seed = seed * 1103515245u + 12345u;
            piece = 1 + (seed >> 16) % (piece < 64 ? piece : 64);
        }
        if (ktw_feed(scanner, data + at, piece, record, l) != KTW_OK)
            abort();
        at += piece;
    }
    if (ktw_finish(scanner, record, l) != KTW_OK)
        abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static log_t whole, cut;
    const char *name;

    if (catalog == NULL) {
        if (ktw_catalog_create(KTW_GROUP_ALL, NULL, NULL, NULL, &catalog) != KTW_OK ||
            ktw_catalog_add(catalog, KTW_KIND_USER, "user", (const unsigned char *)"TOK", 3, 8, user_check, NULL) !=
                KTW_OK ||
            ktw_catalog_compile(catalog) != KTW_OK || ktw_scanner_create(catalog, NULL, NULL, NULL, &scanner) != KTW_OK)
            abort();
    }
    if (size < 2)
        return 0;
    name = names[data[0] % (sizeof(names) / sizeof(names[0]))];
    run(data + 2, size - 2, name, 0, &whole);
    run(data + 2, size - 2, name, 1u + data[1], &cut);
    if (whole.n != cut.n || memcmp(whole.fp, cut.fp, sizeof(whole.fp[0]) * (whole.n < MAX_FINDINGS ? whole.n : MAX_FINDINGS)) != 0)
        abort();
    return 0;
}
