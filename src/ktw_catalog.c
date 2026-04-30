#include "ktw_internal.h"

#include <stdlib.h>

typedef struct {
    unsigned group;
    uint8_t handler;
    uint8_t sub;
    uint8_t len;
    const char *lit;
} ktw_builtin_t;

static const ktw_builtin_t ktw_builtins[] = {
    {KTW_GROUP_PEM, KTW_H_PEM, 0, 11, "-----BEGIN "},
    {KTW_GROUP_DER, KTW_H_DER, KTW_SCHEMA_TRAD, 5, "\x02\x01\x00\x02\x81"},
    {KTW_GROUP_DER, KTW_H_DER, KTW_SCHEMA_TRAD, 5, "\x02\x01\x00\x02\x82"},
    {KTW_GROUP_DER, KTW_H_DER, KTW_SCHEMA_PKCS8, 4, "\x02\x01\x00\x30"},
    {KTW_GROUP_DER, KTW_H_DER, KTW_SCHEMA_PKCS8, 4, "\x02\x01\x01\x30"},
    {KTW_GROUP_DER, KTW_H_DER, KTW_SCHEMA_SEC1, 4, "\x02\x01\x01\x04"},
    {KTW_GROUP_DER, KTW_H_DER, KTW_SCHEMA_EPKI, 11, "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0d"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_AWS, 4, "AKIA"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_AWS, 4, "ASIA"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_GOOGLE, 4, "AIza"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_GITHUB, 4, "ghp_"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_GITHUB, 4, "gho_"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_GITHUB, 4, "ghu_"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_GITHUB, 4, "ghs_"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_GITHUB, 4, "ghr_"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_GITHUB_PAT, 11, "github_pat_"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_SLACK, 5, "xoxb-"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_SLACK, 5, "xoxp-"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_SLACK, 5, "xoxa-"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_SLACK, 5, "xoxr-"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_SLACK, 5, "xoxs-"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_STRIPE, 8, "sk_live_"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_NPM, 4, "npm_"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_PYPI, 20, "pypi-AgEIcHlwaS5vcmc"},
    {KTW_GROUP_CLOUD, KTW_H_TOKEN, KTW_TOK_GITLAB, 6, "glpat-"},
    {KTW_GROUP_PAIRS, KTW_H_SPKI, 0, 11, "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"},
    {KTW_GROUP_PAIRS, KTW_H_SPKI, 1, 11, "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a"},
    {KTW_GROUP_PAIRS, KTW_H_SPKI, 2, 9, "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"},
    {KTW_GROUP_PAIRS, KTW_H_SPKI, 3, 9, "\x06\x07\x2a\x86\x48\xce\x38\x04\x01"},
    {KTW_GROUP_PAIRS, KTW_H_SPKI, 4, 5, "\x06\x03\x2b\x65\x70"},
    {KTW_GROUP_PAIRS, KTW_H_SSHPUB, 0, 14, "AAAAB3NzaC1yc2"},
    {KTW_GROUP_PAIRS, KTW_H_SSHPUB, 0, 14, "AAAAB3NzaC1kc3"},
    {KTW_GROUP_PAIRS, KTW_H_SSHPUB, 0, 20, "AAAAC3NzaC1lZDI1NTE5"},
    {KTW_GROUP_PAIRS, KTW_H_SSHPUB, 0, 27, "AAAAE2VjZHNhLXNoYTItbmlzdHA"},
};

#define KTW_NBUILTINS (sizeof(ktw_builtins) / sizeof(ktw_builtins[0]))

static void *ktw_default_alloc(void *ctx, size_t size)
{
    (void)ctx;
    return malloc(size);
}

static void ktw_default_free(void *ctx, void *ptr)
{
    (void)ctx;
    free(ptr);
}

static void *ktw_cat_alloc(ktw_catalog_t *c, size_t count, size_t size)
{
    if (size != 0 && count > SIZE_MAX / size)
        return NULL;
    return c->alloc_fn(c->alloc_ctx, count * size);
}

static void ktw_cat_free(ktw_catalog_t *c, void *ptr)
{
    if (ptr != NULL)
        c->free_fn(c->alloc_ctx, ptr);
}

int ktw_catalog_create(unsigned groups, ktw_alloc_fn alloc_fn, ktw_free_fn free_fn, void *alloc_ctx,
                       ktw_catalog_t **out_catalog)
{
    ktw_catalog_t *c;
    size_t max = KTW_NBUILTINS + KTW_USER_PATTERNS_MAX;
    size_t i;

    if (out_catalog == NULL || (alloc_fn == NULL) != (free_fn == NULL) || (groups & ~KTW_GROUP_ALL) != 0)
        return KTW_ERR_ARG;
    *out_catalog = NULL;
    if (alloc_fn == NULL) {
        alloc_fn = ktw_default_alloc;
        free_fn = ktw_default_free;
    }
    c = alloc_fn(alloc_ctx, sizeof(*c));
    if (c == NULL)
        return KTW_ERR_NOMEM;
    memset(c, 0, sizeof(*c));
    c->alloc_fn = alloc_fn;
    c->free_fn = free_fn;
    c->alloc_ctx = alloc_ctx;
    c->groups = groups;
    c->patterns = ktw_cat_alloc(c, max, sizeof(*c->patterns));
    c->users = ktw_cat_alloc(c, KTW_USER_PATTERNS_MAX, sizeof(*c->users));
    if (c->patterns == NULL || c->users == NULL) {
        ktw_catalog_destroy(c);
        return KTW_ERR_NOMEM;
    }
    for (i = 0; i < KTW_NBUILTINS; i++) {
        ktw_pattern_t *p;

        if ((ktw_builtins[i].group & groups) == 0)
            continue;
        p = &c->patterns[c->npatterns++];
        memset(p, 0, sizeof(*p));
        p->handler = ktw_builtins[i].handler;
        p->sub = ktw_builtins[i].sub;
        p->len = ktw_builtins[i].len;
        memcpy(p->lit, ktw_builtins[i].lit, p->len);
    }
    *out_catalog = c;
    return KTW_OK;
}

void ktw_catalog_destroy(ktw_catalog_t *c)
{
    if (c == NULL)
        return;
    ktw_cat_free(c, c->patterns);
    ktw_cat_free(c, c->users);
    ktw_cat_free(c, c->table);
    ktw_cat_free(c, c->own_start);
    ktw_cat_free(c, c->own);
    ktw_cat_free(c, c->dict);
    c->free_fn(c->alloc_ctx, c);
}

int ktw_catalog_add(ktw_catalog_t *c, int kind, const char *name, const unsigned char *literal, size_t literal_len,
                    size_t tail_max, ktw_validate_fn validate_fn, void *validate_ctx)
{
    ktw_user_t *u;
    ktw_pattern_t *p;
    size_t name_len;

    if (c == NULL || name == NULL || literal == NULL || kind < KTW_KIND_USER)
        return KTW_ERR_ARG;
    if (c->compiled)
        return KTW_ERR_STATE;
    name_len = strlen(name);
    if (literal_len == 0 || literal_len > KTW_PATTERN_MAX || tail_max > KTW_TAIL_MAX || name_len > KTW_NAME_MAX ||
        c->nusers == KTW_USER_PATTERNS_MAX)
        return KTW_ERR_LIMIT;
    u = &c->users[c->nusers];
    memset(u, 0, sizeof(*u));
    u->kind = kind;
    memcpy(u->name, name, name_len + 1);
    u->literal_len = literal_len;
    u->tail_max = tail_max;
    u->fn = validate_fn;
    u->ctx = validate_ctx;
    p = &c->patterns[c->npatterns++];
    memset(p, 0, sizeof(*p));
    p->handler = KTW_H_USER;
    p->len = (uint8_t)literal_len;
    p->user = (uint16_t)c->nusers++;
    memcpy(p->lit, literal, literal_len);
    if (literal_len + tail_max > c->user_buf)
        c->user_buf = literal_len + tail_max;
    return KTW_OK;
}

static unsigned ktw_build_trie(ktw_catalog_t *c, uint16_t *t, uint16_t *own_head, uint16_t *next_pat)
{
    unsigned n = 1;
    size_t i;
    unsigned j;

    for (i = 0; i < c->npatterns; i++) {
        const ktw_pattern_t *p = &c->patterns[i];
        unsigned st = 0;

        for (j = 0; j < p->len; j++) {
            uint16_t *cell = &t[(size_t)st * 256 + p->lit[j]];

            if (*cell == KTW_NONE16)
                *cell = (uint16_t)n++;
            st = *cell;
        }
        next_pat[i] = own_head[st];
        own_head[st] = (uint16_t)i;
    }
    return n;
}

static int ktw_build_links(ktw_catalog_t *c, uint16_t *t, unsigned n, const uint16_t *own_head, uint16_t *dict)
{
    uint16_t *fail = ktw_cat_alloc(c, n, sizeof(*fail));
    uint16_t *queue = ktw_cat_alloc(c, n, sizeof(*queue));
    unsigned qh = 0, qt = 0;
    unsigned b;

    if (fail == NULL || queue == NULL) {
        ktw_cat_free(c, fail);
        ktw_cat_free(c, queue);
        return KTW_ERR_NOMEM;
    }
    fail[0] = 0;
    dict[0] = KTW_NONE16;
    queue[qt++] = 0;
    while (qh < qt) {
        unsigned u = queue[qh++];

        for (b = 0; b < 256; b++) {
            uint16_t *cell = &t[(size_t)u * 256 + b];
            unsigned f = u == 0 ? 0 : t[(size_t)fail[u] * 256 + b];

            if (*cell == KTW_NONE16) {
                *cell = (uint16_t)f;
                continue;
            }
            fail[*cell] = (uint16_t)(u == 0 ? 0 : f);
            dict[*cell] = own_head[fail[*cell]] != KTW_NONE16 ? fail[*cell] : dict[fail[*cell]];
            queue[qt++] = *cell;
        }
    }
    ktw_cat_free(c, fail);
    ktw_cat_free(c, queue);
    return KTW_OK;
}

static int ktw_renumber(ktw_catalog_t *c, const uint16_t *t, unsigned n, const uint16_t *own_head,
                        const uint16_t *next_pat, uint16_t *dict)
{
    uint16_t *map = ktw_cat_alloc(c, n, sizeof(*map));
    unsigned k = 0, o, u, b, filled = 0;

    c->table = ktw_cat_alloc(c, (size_t)n * 256, sizeof(*c->table));
    c->own_start = ktw_cat_alloc(c, (size_t)n + 1, sizeof(*c->own_start));
    c->own = ktw_cat_alloc(c, c->npatterns + 1, sizeof(*c->own));
    c->dict = ktw_cat_alloc(c, n, sizeof(*c->dict));
    if (map == NULL || c->table == NULL || c->own_start == NULL || c->own == NULL || c->dict == NULL) {
        ktw_cat_free(c, map);
        return KTW_ERR_NOMEM;
    }
    for (u = 0; u < n; u++)
        if (own_head[u] == KTW_NONE16 && dict[u] == KTW_NONE16)
            map[u] = (uint16_t)k++;
    o = k;
    for (u = 0; u < n; u++)
        if (own_head[u] != KTW_NONE16 || dict[u] != KTW_NONE16)
            map[u] = (uint16_t)o++;
    for (u = 0; u < n; u++) {
        for (b = 0; b < 256; b++)
            c->table[(size_t)map[u] * 256 + b] = map[t[(size_t)u * 256 + b]];
        c->dict[map[u]] = dict[u] == KTW_NONE16 ? KTW_NONE16 : map[dict[u]];
    }
    for (u = 0; u < n; u++)
        dict[map[u]] = (uint16_t)u;
    for (o = 0; o < n; o++) {
        uint16_t i;

        c->own_start[o] = (uint16_t)filled;
        for (i = own_head[dict[o]]; i != KTW_NONE16; i = next_pat[i])
            c->own[filled++] = i;
    }
    c->own_start[n] = (uint16_t)filled;
    c->first_out = k;
    c->root = map[0];
    c->nstates = n;
    for (o = 0; o < 256; o++)
        c->leaves[o] = c->table[((size_t)c->root << 8) | o] != c->root;
    ktw_cat_free(c, map);
    return KTW_OK;
}

int ktw_catalog_compile(ktw_catalog_t *c)
{
    size_t total = 1, i;
    uint16_t *t, *own_head, *next_pat, *dict;
    unsigned n;
    int status;

    if (c == NULL)
        return KTW_ERR_ARG;
    if (c->compiled)
        return KTW_ERR_STATE;
    for (i = 0; i < c->npatterns; i++)
        total += c->patterns[i].len;
    t = ktw_cat_alloc(c, total * 256, sizeof(*t));
    own_head = ktw_cat_alloc(c, total, sizeof(*own_head));
    next_pat = ktw_cat_alloc(c, c->npatterns + 1, sizeof(*next_pat));
    dict = ktw_cat_alloc(c, total, sizeof(*dict));
    status = KTW_ERR_NOMEM;
    if (t != NULL && own_head != NULL && next_pat != NULL && dict != NULL) {
        memset(t, 0xFF, total * 256 * sizeof(*t));
        memset(own_head, 0xFF, total * sizeof(*own_head));
        n = ktw_build_trie(c, t, own_head, next_pat);
        status = ktw_build_links(c, t, n, own_head, dict);
        if (status == KTW_OK)
            status = ktw_renumber(c, t, n, own_head, next_pat, dict);
    }
    ktw_cat_free(c, t);
    ktw_cat_free(c, own_head);
    ktw_cat_free(c, next_pat);
    ktw_cat_free(c, dict);
    if (status == KTW_OK)
        c->compiled = 1;
    return status;
}
