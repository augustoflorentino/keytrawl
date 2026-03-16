#include <keytrawl/keytrawl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef KTW_TEST_DATA
#define KTW_TEST_DATA "tests/data"
#endif

static int failures;

#define GHP_VALID "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"
#define GHO_VALID "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"

#define CHECK(cond)                                                                                        \
    do {                                                                                                   \
        if (!(cond)) {                                                                                     \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond);                       \
            failures++;                                                                                    \
        }                                                                                                  \
    } while (0)

typedef struct {
    int kind;
    int confidence;
    int algorithm;
    unsigned checks;
    unsigned flags;
    unsigned long long offset;
    unsigned long long length;
    unsigned long long line;
    char name[64];
    char evidence[256];
} rec_t;

#define RECS_MAX 256

typedef struct {
    rec_t recs[RECS_MAX];
    size_t n;
    size_t stop_after;
} sink_t;

static sink_t sink, sink2;

static int collect(void *ctx, const ktw_finding_t *f)
{
    sink_t *k = ctx;
    rec_t *r;

    if (k->n < RECS_MAX) {
        r = &k->recs[k->n];
        memset(r, 0, sizeof(*r));
        r->kind = ktw_finding_kind(f);
        r->confidence = ktw_finding_confidence(f);
        r->algorithm = ktw_finding_algorithm(f);
        r->checks = ktw_finding_checks(f);
        r->flags = ktw_finding_flags(f);
        r->offset = (unsigned long long)ktw_finding_offset(f);
        r->length = (unsigned long long)ktw_finding_length(f);
        r->line = (unsigned long long)ktw_finding_line(f);
        snprintf(r->name, sizeof(r->name), "%s", ktw_finding_name(f));
        snprintf(r->evidence, sizeof(r->evidence), "%s", ktw_finding_evidence(f));
    }
    k->n++;
    return k->stop_after != 0 && k->n >= k->stop_after;
}

static ktw_catalog_t *catalog_all(void)
{
    ktw_catalog_t *c = NULL;

    if (ktw_catalog_create(KTW_GROUP_ALL, NULL, NULL, NULL, &c) != KTW_OK || ktw_catalog_compile(c) != KTW_OK) {
        fprintf(stderr, "catalog setup failed\n");
        exit(1);
    }
    return c;
}

static int scan_chunked(const ktw_catalog_t *c, const char *name, const unsigned char *data, size_t len,
                        size_t chunk, unsigned seed, sink_t *k)
{
    ktw_scanner_t *s = NULL;
    size_t at = 0;
    int st = ktw_scanner_create(c, NULL, NULL, NULL, &s);

    k->n = 0;
    if (st == KTW_OK)
        st = ktw_scanner_reset(s, name, name == NULL ? 0 : strlen(name));
    while (st == KTW_OK && at < len) {
        size_t piece = chunk;

        if (chunk == 0) {
            seed = seed * 1103515245u + 12345u;
            piece = 1 + (seed >> 8) % 777;
        }
        if (piece > len - at)
            piece = len - at;
        st = ktw_feed(s, data + at, piece, collect, k);
        at += piece;
    }
    if (st == KTW_OK)
        st = ktw_finish(s, collect, k);
    ktw_scanner_destroy(s);
    return st;
}

static int scan(const ktw_catalog_t *c, const char *name, const char *text, sink_t *k)
{
    return scan_chunked(c, name, (const unsigned char *)text, strlen(text), 4096, 0, k);
}

static unsigned char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf = NULL;
    long size;

    if (f == NULL)
        return NULL;
    if (fseek(f, 0, SEEK_END) == 0 && (size = ftell(f)) >= 0 && fseek(f, 0, SEEK_SET) == 0) {
        buf = malloc((size_t)size + 1);
        if (buf != NULL && fread(buf, 1, (size_t)size, f) != (size_t)size) {
            free(buf);
            buf = NULL;
        }
        *out_len = (size_t)size;
    }
    fclose(f);
    return buf;
}

static unsigned rng_state = 12345u;

static unsigned rng(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static void fill_random(unsigned char *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        p[i] = (unsigned char)(rng() >> 7);
}

static int leaks(const unsigned char *data, size_t from, size_t to, const char *evidence)
{
    size_t i, j, ev_len = strlen(evidence);

    for (i = from; i + 5 <= to; i++)
        for (j = 0; j + 5 <= ev_len; j++)
            if (memcmp(data + i, evidence + j, 5) == 0)
                return 1;
    return 0;
}

static int evidence_ok(const unsigned char *data, const rec_t *r)
{
    size_t from = (size_t)r->offset, to = (size_t)(r->offset + r->length);

    if (r->kind == KTW_KIND_AUTHORIZED_KEY)
        return 1;
    if (r->kind <= KTW_KIND_PEM_PKCS8_ENCRYPTED) {
        while (from < to && data[from] != '\n')
            from++;
        while (to > from && data[to - 1] != '\n')
            to--;
    }
    return !leaks(data, from, to, r->evidence);
}

static const rec_t *find_kind(const sink_t *k, int kind)
{
    size_t i;

    for (i = 0; i < k->n && i < RECS_MAX; i++)
        if (k->recs[i].kind == kind)
            return &k->recs[i];
    return NULL;
}

static void test_arguments(void)
{
    ktw_catalog_t *c = NULL;
    ktw_scanner_t *s = NULL;
    unsigned char lit[KTW_PATTERN_MAX + 1] = {0};
    char long_name[KTW_NAME_MAX + 2];

    memset(long_name, 'n', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';
    CHECK(ktw_catalog_create(KTW_GROUP_ALL, NULL, NULL, NULL, NULL) == KTW_ERR_ARG);
    CHECK(ktw_catalog_create(0x100, NULL, NULL, NULL, &c) == KTW_ERR_ARG);
    CHECK(ktw_catalog_create(KTW_GROUP_ALL, NULL, NULL, NULL, &c) == KTW_OK);
    CHECK(ktw_scanner_create(c, NULL, NULL, NULL, &s) == KTW_ERR_STATE);
    CHECK(ktw_catalog_add(c, KTW_KIND_USER - 1, "x", lit, 1, 0, NULL, NULL) == KTW_ERR_ARG);
    CHECK(ktw_catalog_add(c, KTW_KIND_USER, NULL, lit, 1, 0, NULL, NULL) == KTW_ERR_ARG);
    CHECK(ktw_catalog_add(c, KTW_KIND_USER, "x", NULL, 1, 0, NULL, NULL) == KTW_ERR_ARG);
    CHECK(ktw_catalog_add(c, KTW_KIND_USER, "x", lit, 0, 0, NULL, NULL) == KTW_ERR_LIMIT);
    CHECK(ktw_catalog_add(c, KTW_KIND_USER, "x", lit, KTW_PATTERN_MAX + 1, 0, NULL, NULL) == KTW_ERR_LIMIT);
    CHECK(ktw_catalog_add(c, KTW_KIND_USER, "x", lit, 1, KTW_TAIL_MAX + 1, NULL, NULL) == KTW_ERR_LIMIT);
    CHECK(ktw_catalog_add(c, KTW_KIND_USER, long_name, lit, 1, 0, NULL, NULL) == KTW_ERR_LIMIT);
    CHECK(ktw_catalog_compile(NULL) == KTW_ERR_ARG);
    CHECK(ktw_catalog_compile(c) == KTW_OK);
    CHECK(ktw_catalog_compile(c) == KTW_ERR_STATE);
    CHECK(ktw_catalog_add(c, KTW_KIND_USER, "x", lit, 1, 0, NULL, NULL) == KTW_ERR_STATE);
    CHECK(ktw_scanner_create(NULL, NULL, NULL, NULL, &s) == KTW_ERR_ARG);
    CHECK(ktw_scanner_create(c, NULL, NULL, NULL, NULL) == KTW_ERR_ARG);
    CHECK(ktw_scanner_create(c, NULL, NULL, NULL, &s) == KTW_OK);
    CHECK(ktw_feed(NULL, lit, 1, collect, &sink) == KTW_ERR_ARG);
    CHECK(ktw_feed(s, NULL, 1, collect, &sink) == KTW_ERR_ARG);
    CHECK(ktw_feed(s, NULL, 0, collect, &sink) == KTW_OK);
    CHECK(ktw_feed(s, lit, 1, NULL, NULL) == KTW_OK);
    CHECK(ktw_scanner_reset(NULL, NULL, 0) == KTW_ERR_ARG);
    CHECK(ktw_scanner_reset(s, NULL, 3) == KTW_ERR_ARG);
    CHECK(ktw_finish(NULL, collect, &sink) == KTW_ERR_ARG);
    CHECK(ktw_finish(s, collect, &sink) == KTW_OK);
    CHECK(ktw_feed(s, lit, 1, collect, &sink) == KTW_ERR_STATE);
    CHECK(ktw_finish(s, collect, &sink) == KTW_ERR_STATE);
    CHECK(ktw_scanner_reset(s, NULL, 0) == KTW_OK);
    CHECK(ktw_feed(s, lit, 1, collect, &sink) == KTW_OK);
    CHECK(ktw_scanner_dropped(s) == 0);
    ktw_scanner_destroy(s);
    ktw_scanner_destroy(NULL);
    ktw_catalog_destroy(c);
    ktw_catalog_destroy(NULL);
}

static void test_names(void)
{
    int i;

    for (i = KTW_KIND_PEM_RSA; i <= KTW_KIND_AUTHORIZED_KEY; i++)
        CHECK(strcmp(ktw_kind_name(i), "unknown") != 0);
    CHECK(strcmp(ktw_kind_name(0), "unknown") == 0);
    CHECK(strcmp(ktw_kind_name(-1), "unknown") == 0);
    CHECK(strcmp(ktw_kind_name(KTW_KIND_USER + 5), "user") == 0);
    for (i = KTW_ALG_NONE; i < KTW_ALG_UNKNOWN; i++)
        CHECK(strcmp(ktw_algorithm_name(i), "unknown") != 0);
    CHECK(strcmp(ktw_algorithm_name(99), "unknown") == 0);
    for (i = KTW_OK; i <= KTW_STOPPED; i++)
        CHECK(strcmp(ktw_strerror(i), "unknown status") != 0);
    CHECK(strcmp(ktw_strerror(99), "unknown status") == 0);
}

static void test_stop(const ktw_catalog_t *c)
{
    ktw_scanner_t *s = NULL;
    const char *text = GHP_VALID " " GHO_VALID " " GHP_VALID " ";

    sink.n = 0;
    sink.stop_after = 1;
    CHECK(ktw_scanner_create(c, NULL, NULL, NULL, &s) == KTW_OK);
    CHECK(ktw_feed(s, (const unsigned char *)text, strlen(text), collect, &sink) == KTW_STOPPED);
    CHECK(sink.n == 1);
    CHECK(ktw_feed(s, (const unsigned char *)text, 1, collect, &sink) == KTW_ERR_STATE);
    CHECK(ktw_finish(s, collect, &sink) == KTW_ERR_STATE);
    CHECK(ktw_scanner_reset(s, NULL, 0) == KTW_OK);
    sink.stop_after = 0;
    sink.n = 0;
    CHECK(ktw_feed(s, (const unsigned char *)text, strlen(text), collect, &sink) == KTW_OK);
    CHECK(ktw_finish(s, collect, &sink) == KTW_OK);
    CHECK(sink.n == 3);
    CHECK(ktw_scanner_reset(s, NULL, 0) == KTW_OK);
    sink.n = 0;
    sink.stop_after = 1;
    CHECK(ktw_feed(s, (const unsigned char *)GHP_VALID, 40, collect, &sink) == KTW_OK);
    CHECK(ktw_finish(s, collect, &sink) == KTW_STOPPED);
    sink.stop_after = 0;
    ktw_scanner_destroy(s);
}

typedef struct {
    long budget;
    long live;
    long calls;
} alloc_t;

static void *counting_alloc(void *ctx, size_t size)
{
    alloc_t *a = ctx;
    void *p;

    a->calls++;
    if (a->budget == 0)
        return NULL;
    if (a->budget > 0)
        a->budget--;
    p = malloc(size);
    if (p != NULL)
        a->live++;
    return p;
}

static void counting_free(void *ctx, void *ptr)
{
    alloc_t *a = ctx;

    if (ptr != NULL)
        a->live--;
    free(ptr);
}

static int noop_validate(void *ctx, const unsigned char *data, size_t data_len, size_t *out_len)
{
    (void)ctx;
    (void)data;
    *out_len = data_len;
    return KTW_LIKELY;
}

static int build_with_failure(long fail_at, alloc_t *a)
{
    ktw_catalog_t *c = NULL;
    ktw_scanner_t *s = NULL;
    int st;

    a->budget = fail_at;
    a->live = 0;
    a->calls = 0;
    st = ktw_catalog_create(KTW_GROUP_ALL, counting_alloc, counting_free, a, &c);
    if (st == KTW_OK)
        st = ktw_catalog_add(c, KTW_KIND_USER, "user", (const unsigned char *)"pw=", 3, 32, noop_validate, NULL);
    if (st == KTW_OK)
        st = ktw_catalog_compile(c);
    if (st == KTW_OK)
        st = ktw_scanner_create(c, counting_alloc, counting_free, a, &s);
    ktw_scanner_destroy(s);
    ktw_catalog_destroy(c);
    return st;
}

static void test_alloc_failure(void)
{
    alloc_t a;
    long i;
    int st = KTW_ERR_NOMEM;

    for (i = 0; i < 100 && st == KTW_ERR_NOMEM; i++) {
        st = build_with_failure(i, &a);
        CHECK(st == KTW_OK || st == KTW_ERR_NOMEM);
        CHECK(a.live == 0);
    }
    CHECK(st == KTW_OK);
    CHECK(i > 1);
    CHECK(ktw_catalog_create(KTW_GROUP_ALL, counting_alloc, NULL, &a, NULL) == KTW_ERR_ARG);
}

static void test_feed_does_not_allocate(const unsigned char *data, size_t len)
{
    alloc_t a = {-1, 0, 0};
    ktw_catalog_t *c = NULL;
    ktw_scanner_t *s = NULL;
    long calls;
    size_t at;

    CHECK(ktw_catalog_create(KTW_GROUP_ALL, counting_alloc, counting_free, &a, &c) == KTW_OK);
    CHECK(ktw_catalog_add(c, KTW_KIND_USER, "user", (const unsigned char *)"-----", 5, 64, noop_validate, NULL) ==
          KTW_OK);
    CHECK(ktw_catalog_compile(c) == KTW_OK);
    CHECK(ktw_scanner_create(c, counting_alloc, counting_free, &a, &s) == KTW_OK);
    calls = a.calls;
    sink.n = 0;
    CHECK(ktw_scanner_reset(s, "authorized_keys", 15) == KTW_OK);
    for (at = 0; at < len; at += 1000)
        CHECK(ktw_feed(s, data + at, len - at < 1000 ? len - at : 1000, collect, &sink) == KTW_OK);
    CHECK(ktw_finish(s, collect, &sink) == KTW_OK);
    CHECK(sink.n > 0);
    CHECK(a.calls == calls);
    ktw_scanner_destroy(s);
    ktw_catalog_destroy(c);
    CHECK(a.live == 0);
}

static void test_aws(const ktw_catalog_t *c)
{
    const rec_t *r;

    CHECK(scan(c, NULL, "id=AKIAIOSFODNN7EXAMPLE\nsecret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", &sink) ==
          KTW_OK);
    CHECK(sink.n == 1);
    r = find_kind(&sink, KTW_KIND_AWS_ACCESS_KEY);
    CHECK(r != NULL && r->offset == 3 && r->length == 20 && r->confidence == KTW_LIKELY);
    CHECK(r != NULL && (r->checks & KTW_CHECK_PAIRED) && strcmp(r->evidence, "AKIA\xe2\x80\xa6MPLE") == 0);
    CHECK(scan(c, NULL, "ASIAIOSFODNN7EXAMPLE", &sink) == KTW_OK && sink.n == 1);
    CHECK(sink.n == 1 && !(sink.recs[0].checks & KTW_CHECK_PAIRED));
    CHECK(scan(c, NULL, "xAKIAIOSFODNN7EXAMPLE ", &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, NULL, "AKIAIOSFODNN7EXAMPLE1 ", &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, NULL, "AKIAIOSFODNN7EXAMPL_ ", &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, NULL, "AKIAIOSFODNN7EXAMPLe ", &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, NULL, "-AKIAIOSFODNN7EXAMPLE-", &sink) == KTW_OK && sink.n == 1);
}

static void test_github(const ktw_catalog_t *c)
{
    char bad[64];
    const rec_t *r;
    size_t i;

    CHECK(scan(c, NULL, "token: " GHP_VALID "\n", &sink) == KTW_OK && sink.n == 1);
    r = find_kind(&sink, KTW_KIND_GITHUB_TOKEN);
    CHECK(r != NULL && r->confidence == KTW_CONFIRMED && (r->checks & KTW_CHECK_CHECKSUM) && r->offset == 7);
    CHECK(scan(c, NULL, GHO_VALID, &sink) == KTW_OK && sink.n == 1);
    for (i = 4; i < strlen(GHP_VALID); i++) {
        strcpy(bad, GHP_VALID);
        bad[i] = bad[i] == 'a' ? 'b' : 'a';
        CHECK(scan(c, NULL, bad, &sink) == KTW_OK && sink.n == 0);
    }
    CHECK(scan(c, NULL, GHP_VALID "x", &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, NULL, "github_pat_11ABCDEFG0123456789abc_0123456789abcdefghijABCDEFGHIJ0123456789abcdefghijABCDEFGHI",
               &sink) == KTW_OK);
    r = find_kind(&sink, KTW_KIND_GITHUB_TOKEN);
    CHECK(sink.n == 1 && r != NULL && r->confidence == KTW_LIKELY && r->length == 93);
    CHECK(scan(c, NULL, "github_pat_11ABCDEFG0123456789abc-0123456789abcdefghijABCDEFGHIJ0123456789abcdefghijABCDEFGHI",
               &sink) == KTW_OK && sink.n == 0);
}

static void test_other_tokens(const ktw_catalog_t *c)
{
    const rec_t *r;

    CHECK(scan(c, NULL, "key=AIzaSyD-1234567890abcdefghijklmnopqrstu;", &sink) == KTW_OK);
    r = find_kind(&sink, KTW_KIND_GOOGLE_API_KEY);
    CHECK(sink.n == 1 && r != NULL && r->offset == 4 && r->length == 39);
    CHECK(scan(c, NULL, "AIzaSyD-1234567890abcdefghijklmnopqrst", &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, NULL, "AIzaSyD-1234567890abcdefghijklmnopqrstuv", &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, NULL, "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx\"", &sink) == KTW_OK);
    r = find_kind(&sink, KTW_KIND_SLACK_TOKEN);
    CHECK(sink.n == 1 && r != NULL && r->length == 56);
    CHECK(scan(c, NULL, "xoxb-12345-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx ", &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, NULL, "xoxp-123456789012-1234567890123-short ", &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, NULL, "sk_live_4eC39HqLyjWDarjtT1zdp7dc", &sink) == KTW_OK);
    r = find_kind(&sink, KTW_KIND_STRIPE_KEY);
    CHECK(sink.n == 1 && r != NULL && r->length == 32);
    CHECK(scan(c, NULL, "sk_live_tooshort ", &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, NULL, "sk_live_4eC39HqLyjWDarjtT1zdp7dc_x", &sink) == KTW_OK && sink.n == 0);
}

static void test_pem_baits(const ktw_catalog_t *c)
{
    static const char empty[] = "-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\n";
    static const char junk[] = "-----BEGIN PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAA\n"
                               "-----END PRIVATE KEY-----\n";
    static const char enc[] = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAA\n"
                              "AAAAAAAAAAAAAAAAAAAAAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
    static const char mismatch[] = "-----BEGIN RSA PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAA\n"
                                   "AAAAAAAAAAAAAAAAAAAAAAAA\n-----END EC PRIVATE KEY-----\n";

    CHECK(scan(c, "libparse.so", empty, &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, NULL, junk, &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, NULL, mismatch, &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, NULL, enc, &sink) == KTW_OK && sink.n == 1);
    CHECK(sink.n == 1 && sink.recs[0].confidence == KTW_INDICATOR && (sink.recs[0].flags & KTW_FLAG_ENCRYPTED));
}

static unsigned char *load_key(const char *file, size_t *len)
{
    char path[512];

    snprintf(path, sizeof(path), "%s/keys/%s", KTW_TEST_DATA, file);
    return read_file(path, len);
}

static void test_pem_forms(const ktw_catalog_t *c)
{
    size_t len, i, j = 0;
    unsigned char *key = load_key("rsa2048-1.trad.pem", &len);
    unsigned char *crlf = key == NULL ? NULL : malloc(2 * len);

    CHECK(crlf != NULL);
    if (crlf == NULL)
        return;
    for (i = 0; i < len; i++) {
        if (key[i] == '\n')
            crlf[j++] = '\r';
        crlf[j++] = key[i];
    }
    CHECK(scan_chunked(c, NULL, crlf, j, 4096, 0, &sink) == KTW_OK);
    CHECK(sink.n == 1 && sink.recs[0].confidence == KTW_CONFIRMED && sink.recs[0].kind == KTW_KIND_PEM_RSA);
    CHECK(scan_chunked(c, "libssl.so.3", key, len, 4096, 0, &sink) == KTW_OK);
    CHECK(sink.n == 1 && sink.recs[0].confidence == KTW_INDICATOR && (sink.recs[0].flags & KTW_FLAG_IN_BINARY));
    free(crlf);
    free(key);
    key = load_key("rsa2048-1.legacyenc.pem", &len);
    CHECK(key != NULL && scan_chunked(c, NULL, key, len, 4096, 0, &sink) == KTW_OK);
    CHECK(sink.n == 1 && (sink.recs[0].flags & KTW_FLAG_ENCRYPTED) && sink.recs[0].confidence == KTW_CONFIRMED);
    free(key);
    key = load_key("ssh-ed25519-0-enc-1", &len);
    CHECK(key != NULL && scan_chunked(c, NULL, key, len, 4096, 0, &sink) == KTW_OK);
    CHECK(sink.n == 1 && (sink.recs[0].flags & KTW_FLAG_ENCRYPTED) && sink.recs[0].algorithm == KTW_ALG_ED25519);
    free(key);
}

static void test_der_inner(const ktw_catalog_t *c)
{
    size_t len;
    unsigned char *key = load_key("ec256-1.p8.der", &len);

    CHECK(key != NULL && len > 40);
    if (key == NULL)
        return;
    CHECK(scan_chunked(c, NULL, key, len, 4096, 0, &sink) == KTW_OK && sink.n == 1);
    CHECK(sink.n == 1 && sink.recs[0].confidence == KTW_CONFIRMED && sink.recs[0].algorithm == KTW_ALG_EC);
    CHECK(key[31] == 0x02 && key[32] == 0x01 && key[33] == 0x01);
    key[33] = 0x02;
    CHECK(scan_chunked(c, NULL, key, len, 4096, 0, &sink) == KTW_OK && sink.n == 0);
    free(key);
    key = load_key("ed25519-1.p8.der", &len);
    CHECK(key != NULL && len == 48);
    if (key == NULL)
        return;
    CHECK(scan_chunked(c, NULL, key, len, 4096, 0, &sink) == KTW_OK && sink.n == 1);
    CHECK(sink.n == 1 && sink.recs[0].algorithm == KTW_ALG_ED25519);
    key[15] = 0x1f;
    CHECK(scan_chunked(c, NULL, key, len, 4096, 0, &sink) == KTW_OK && sink.n == 0);
    free(key);
}

static void test_der_v2(const ktw_catalog_t *c)
{
    unsigned char k[16 + 32 + 4 + 35];
    size_t n = 0;
    unsigned i;

    memcpy(k, "\x30\x55\x02\x01\x01\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20", 16);
    n = 16;
    for (i = 0; i < 32; i++)
        k[n++] = (unsigned char)(i * 7 + 1);
    memcpy(k + n, "\xa0\x00\x81\x21\x00", 5);
    n += 5;
    for (i = 0; i < 32; i++)
        k[n++] = (unsigned char)(i * 5 + 3);
    k[1] = (unsigned char)(n - 2);
    CHECK(scan_chunked(c, NULL, k, n, 4096, 0, &sink) == KTW_OK && sink.n == 1);
    CHECK(sink.n == 1 && sink.recs[0].kind == KTW_KIND_DER_PKCS8 && sink.recs[0].length == n);
    k[48] = 0xa2;
    CHECK(scan_chunked(c, NULL, k, n, 4096, 0, &sink) == KTW_OK && sink.n == 0);
}

static void test_wifi(const ktw_catalog_t *c)
{
    static const char wireless[] = "config wifi-iface 'default_radio0'\n"
                                   "\toption key 'sup3rS3cretPass'\n"
                                   "\toption key '/etc/wifi.key'\n"
                                   "\toption  key \"another-secret\"  \n"
                                   "\toption key short\n";
    const rec_t *r;

    CHECK(scan(c, "/rootfs/etc/config/wireless", wireless, &sink) == KTW_OK && sink.n == 2);
    r = &sink.recs[0];
    CHECK(r->kind == KTW_KIND_WIFI_PASSPHRASE && r->line == 2 && r->offset == 48 && r->length == 15);
    CHECK(strcmp(r->evidence, "sup3\xe2\x80\xa6Pass") == 0);
    CHECK(sink.n == 2 && sink.recs[1].line == 4 && sink.recs[1].length == 14);
    CHECK(scan(c, "/usr/share/doc/example.txt", "wpa_passphrase=documentation-example\n", &sink) == KTW_OK);
    CHECK(sink.n == 0);
    CHECK(scan(c, "hostapd-wlan0.conf", "wpa_passphrase=documentation-example", &sink) == KTW_OK && sink.n == 1);
    CHECK(scan(c, "wpa_supplicant.conf", "network={\n psk=\"abcdefgh\"\n}\n", &sink) == KTW_OK && sink.n == 1);
    CHECK(sink.n == 1 && strcmp(sink.recs[0].evidence, "ab\xe2\x80\xa6") == 0);
    CHECK(scan(c, "hostapd.conf", "psk==========abc\n", &sink) == KTW_OK && sink.n == 1);
    CHECK(sink.n == 1 && sink.recs[0].offset == 8 && sink.recs[0].length == 8);
    CHECK(scan(c, "hostapd.conf", "psk=\r\npsk=abcdefgh\r\n", &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, "hostapd.conf", "psk=12345678901234567890123456789012345678901234567890123456789012345\n",
               &sink) == KTW_OK && sink.n == 0);
}

#define ED_PUB "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExJeoA/ZHc5NgshcUXHRYuKDCzlpGSQHZ1329ciZfSP"

static void test_authorized_keys(const ktw_catalog_t *c)
{
    static const char keys[] = "# admins\n\n" ED_PUB " me@host\n"
                               "command=\"echo a b\",no-pty " ED_PUB "\n"
                               "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExJ broken\n"
                               "ssh-rsa\n";

    CHECK(scan(c, "/root/.ssh/authorized_keys", keys, &sink) == KTW_OK && sink.n == 4);
    if (sink.n != 4)
        return;
    CHECK(sink.recs[0].confidence == KTW_CONFIRMED && sink.recs[0].line == 3 && sink.recs[0].offset == 10);
    CHECK(strcmp(sink.recs[0].evidence, "ssh-ed25519 key, comment 'me@host'") == 0);
    CHECK(sink.recs[0].algorithm == KTW_ALG_ED25519);
    CHECK(sink.recs[1].confidence == KTW_CONFIRMED && sink.recs[1].line == 4);
    CHECK(sink.recs[2].confidence == KTW_INDICATOR && sink.recs[3].confidence == KTW_INDICATOR);
    CHECK(strcmp(sink.recs[3].evidence, "ssh-rsa key, comment 'no comment'") == 0);
    CHECK(scan(c, "authorized_keys.bak", keys, &sink) == KTW_OK && sink.n == 0);
    CHECK(scan(c, "authorized_keys2", ED_PUB, &sink) == KTW_OK && sink.n == 1);
}

static int validate_digits(void *ctx, const unsigned char *data, size_t data_len, size_t *out_len)
{
    size_t n = 4;

    ++*(int *)ctx;
    while (n < data_len && data[n] >= '0' && data[n] <= '9')
        n++;
    *out_len = n;
    return n >= 4 + 6 ? KTW_CONFIRMED : 0;
}

static void test_user_patterns(void)
{
    ktw_catalog_t *c = NULL;
    int calls = 0;

    CHECK(ktw_catalog_create(0, NULL, NULL, NULL, &c) == KTW_OK);
    CHECK(ktw_catalog_add(c, KTW_KIND_USER, "pin", (const unsigned char *)"PIN:", 4, 12, validate_digits,
                          &calls) == KTW_OK);
    CHECK(ktw_catalog_add(c, KTW_KIND_USER + 1, "marker", (const unsigned char *)"XYZZY", 5, 0, NULL, NULL) ==
          KTW_OK);
    CHECK(ktw_catalog_compile(c) == KTW_OK);
    CHECK(scan(c, NULL, "a PIN:1234567 b PIN:12 XYZZY PIN:99999999", &sink) == KTW_OK);
    CHECK(sink.n == 3 && calls == 3);
    if (sink.n == 3) {
        CHECK(strcmp(sink.recs[0].name, "pin") == 0 && sink.recs[0].offset == 2 && sink.recs[0].length == 11);
        CHECK(sink.recs[0].confidence == KTW_CONFIRMED && (sink.recs[0].checks & KTW_CHECK_VALIDATOR));
        CHECK(sink.recs[1].kind == KTW_KIND_USER + 1 && sink.recs[1].confidence == KTW_INDICATOR);
        CHECK(sink.recs[2].length == 12);
    }
    CHECK(scan(c, NULL, "AKIAIOSFODNN7EXAMPLE", &sink) == KTW_OK && sink.n == 0);
    ktw_catalog_destroy(c);
}

static void test_dropped(void)
{
    ktw_catalog_t *c = NULL;
    ktw_scanner_t *s = NULL;

    CHECK(ktw_catalog_create(0, NULL, NULL, NULL, &c) == KTW_OK);
    CHECK(ktw_catalog_add(c, KTW_KIND_USER, "a", (const unsigned char *)"a", 1, 64, NULL, NULL) == KTW_OK);
    CHECK(ktw_catalog_compile(c) == KTW_OK);
    CHECK(ktw_scanner_create(c, NULL, NULL, NULL, &s) == KTW_OK);
    sink.n = 0;
    CHECK(ktw_feed(s, (const unsigned char *)"aaaaaaaaaaaaaaaaaaaa", 20, collect, &sink) == KTW_OK);
    CHECK(ktw_scanner_dropped(s) == 12);
    CHECK(ktw_finish(s, collect, &sink) == KTW_OK && sink.n == 8);
    CHECK(ktw_scanner_reset(s, NULL, 0) == KTW_OK && ktw_scanner_dropped(s) == 0);
    ktw_scanner_destroy(s);
    ktw_catalog_destroy(c);
}

typedef struct {
    char file[96];
    char kind[48];
    char alg[16];
} entry_t;

#define ENTRIES_MAX 256

static size_t load_manifest(entry_t *e)
{
    char path[512], line[256];
    FILE *f;
    size_t n = 0;

    snprintf(path, sizeof(path), "%s/keys/manifest.tsv", KTW_TEST_DATA);
    f = fopen(path, "r");
    if (f == NULL)
        return 0;
    while (n < ENTRIES_MAX && fgets(line, sizeof(line), f) != NULL)
        if (sscanf(line, "%95[^\t]\t%47[^\t]\t%15s", e[n].file, e[n].kind, e[n].alg) == 3)
            n++;
    fclose(f);
    return n;
}

static int embedded_found(const ktw_catalog_t *c, const entry_t *e, const unsigned char *host, size_t host_len)
{
    size_t len, at, total, i;
    unsigned char *key = load_key(e->file, &len), *buf;
    int found = 0;

    if (key == NULL)
        return 0;
    at = host != NULL ? rng() % host_len : rng() % 5000;
    total = (host != NULL ? host_len : at + rng() % 5000) + len;
    buf = malloc(total);
    if (buf != NULL) {
        if (host != NULL) {
            memcpy(buf, host, at);
            memcpy(buf + at + len, host + at, host_len - at);
        } else {
            fill_random(buf, total);
        }
        memcpy(buf + at, key, len);
        CHECK(scan_chunked(c, NULL, buf, total, 0, rng(), &sink) == KTW_OK);
        for (i = 0; i < sink.n && i < RECS_MAX; i++) {
            const rec_t *r = &sink.recs[i];

            if (r->offset == at && strcmp(r->name, e->kind) == 0 && strcmp(ktw_algorithm_name(r->algorithm), e->alg) == 0)
                found = 1;
            CHECK(evidence_ok(buf, r));
        }
    }
    free(buf);
    free(key);
    return found;
}

static void test_m2(const ktw_catalog_t *c, const char *host_path)
{
    static entry_t entries[ENTRIES_MAX];
    size_t n = load_manifest(entries), i, host_len = 0, in_random = 0, in_host = 0;
    unsigned char *host = read_file(host_path, &host_len);

    CHECK(n >= 200);
    CHECK(host != NULL && host_len > 0);
    for (i = 0; i < n; i++) {
        in_random += (size_t)embedded_found(c, &entries[i], NULL, 0);
        if (host != NULL)
            in_host += (size_t)embedded_found(c, &entries[i], host, host_len);
        if (!embedded_found(c, &entries[i], NULL, 0))
            fprintf(stderr, "m2: %s not found\n", entries[i].file);
    }
    printf("m2: %zu keys, %zu found in random bytes, %zu in %s\n", n, in_random, in_host, host_path);
    CHECK(in_random == n && in_host == n);
    free(host);
}

static int same_findings(const sink_t *a, const sink_t *b)
{
    size_t i;

    if (a->n != b->n)
        return 0;
    for (i = 0; i < a->n && i < RECS_MAX; i++)
        if (memcmp(&a->recs[i], &b->recs[i], sizeof(rec_t)) != 0)
            return 0;
    return 1;
}

static unsigned char *mixed_stream(size_t *out_len)
{
    static const char *const files[] = {"rsa1024-1.trad.pem", "ec256-1.trad.der", "ed25519-1.p8.der",
                                        "ssh-ecdsa-256-enc-1", "dsa1024-1.p8enc.der", "ec384-2.legacyenc.pem"};
    static const char tokens[] = "\nAKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY " GHP_VALID
                                 " xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx\n";
    unsigned char *buf = malloc(64 * 1024), *key;
    size_t n = 0, len, i;

    for (i = 0; buf != NULL && i < sizeof(files) / sizeof(files[0]); i++) {
        key = load_key(files[i], &len);
        if (key != NULL && n + len + 600 < 64 * 1024) {
            fill_random(buf + n, 300);
            memcpy(buf + n + 300, key, len);
            memcpy(buf + n + 300 + len, tokens, sizeof(tokens) - 1);
            n += 300 + len + sizeof(tokens) - 1;
        }
        free(key);
    }
    *out_len = n;
    return buf;
}

static void test_m5(const ktw_catalog_t *c)
{
    static const char wireless[] = "\toption key 'sup3rS3cretPass'\npsk==========abc\n";
    size_t len, chunk, bad = 0;
    unsigned char *data = mixed_stream(&len);
    unsigned seed;

    CHECK(data != NULL && scan_chunked(c, NULL, data, len, len, 0, &sink) == KTW_OK);
    CHECK(sink.n >= 12);
    for (chunk = 1; data != NULL && chunk <= 4096; chunk++) {
        CHECK(scan_chunked(c, NULL, data, len, chunk, 0, &sink2) == KTW_OK);
        bad += !same_findings(&sink, &sink2);
    }
    for (seed = 1; data != NULL && seed <= 200; seed++) {
        CHECK(scan_chunked(c, NULL, data, len, 0, seed, &sink2) == KTW_OK);
        bad += !same_findings(&sink, &sink2);
    }
    CHECK(bad == 0);
    if (data != NULL)
        test_feed_does_not_allocate(data, len);
    free(data);
    CHECK(scan(c, "hostapd.conf", wireless, &sink) == KTW_OK && sink.n == 2);
    for (chunk = 1; chunk <= sizeof(wireless); chunk++) {
        CHECK(scan_chunked(c, "hostapd.conf", (const unsigned char *)wireless, sizeof(wireless) - 1, chunk, 0,
                           &sink2) == KTW_OK);
        CHECK(same_findings(&sink, &sink2));
    }
}

int main(int argc, char **argv)
{
    ktw_catalog_t *c = catalog_all();

    test_arguments();
    test_names();
    test_stop(c);
    test_alloc_failure();
    test_aws(c);
    test_github(c);
    test_other_tokens(c);
    test_pem_baits(c);
    test_pem_forms(c);
    test_der_inner(c);
    test_der_v2(c);
    test_wifi(c);
    test_authorized_keys(c);
    test_user_patterns();
    test_dropped();
    test_m2(c, argc > 1 ? argv[1] : argv[0]);
    test_m5(c);
    ktw_catalog_destroy(c);
    if (failures != 0) {
        fprintf(stderr, "%d checks failed\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
