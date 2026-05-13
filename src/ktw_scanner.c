#include "ktw_internal.h"

static const char ktw_ellipsis[] = "\xe2\x80\xa6";

int ktw_scanner_create(const ktw_catalog_t *cat, ktw_alloc_fn alloc_fn, ktw_free_fn free_fn, void *alloc_ctx,
                       ktw_scanner_t **out_scanner)
{
    ktw_scanner_t *s;
    unsigned char *bufs = NULL;
    size_t i;

    if (out_scanner == NULL || cat == NULL || (alloc_fn == NULL) != (free_fn == NULL))
        return KTW_ERR_ARG;
    *out_scanner = NULL;
    if (!cat->compiled)
        return KTW_ERR_STATE;
    if (alloc_fn == NULL) {
        alloc_fn = cat->alloc_fn;
        free_fn = cat->free_fn;
        alloc_ctx = cat->alloc_ctx;
    }
    s = alloc_fn(alloc_ctx, sizeof(*s));
    if (s == NULL)
        return KTW_ERR_NOMEM;
    if (cat->user_buf > 0) {
        bufs = alloc_fn(alloc_ctx, cat->user_buf * KTW_TOK_SLOTS);
        if (bufs == NULL) {
            free_fn(alloc_ctx, s);
            return KTW_ERR_NOMEM;
        }
    }
    memset(s, 0, sizeof(*s));
    s->cat = cat;
    s->alloc_fn = alloc_fn;
    s->free_fn = free_fn;
    s->alloc_ctx = alloc_ctx;
    for (i = 0; i < KTW_TOK_SLOTS; i++)
        s->tok[i].buf = bufs == NULL ? NULL : bufs + i * cat->user_buf;
    ktw_scanner_reset(s, NULL, 0, KTW_STREAM_AUTO);
    *out_scanner = s;
    return KTW_OK;
}

void ktw_scanner_destroy(ktw_scanner_t *s)
{
    if (s == NULL)
        return;
    if (s->tok[0].buf != NULL)
        s->free_fn(s->alloc_ctx, s->tok[0].buf);
    s->free_fn(s->alloc_ctx, s);
}

static int ktw_starts(const char *s, size_t len, const char *prefix)
{
    size_t n = strlen(prefix);

    return len >= n && memcmp(s, prefix, n) == 0;
}

static int ktw_ends(const char *s, size_t len, const char *suffix)
{
    size_t n = strlen(suffix);

    return len >= n && memcmp(s + len - n, suffix, n) == 0;
}

static int ktw_config_mode(const char *name, size_t len, const char *base, size_t base_len)
{
    if ((len == 19 && memcmp(name, "etc/config/wireless", 19) == 0) || ktw_ends(name, len, "/etc/config/wireless"))
        return KTW_CFG_WIFI;
    if ((ktw_starts(base, base_len, "hostapd") || ktw_starts(base, base_len, "wpa_supplicant")) &&
        ktw_ends(base, base_len, ".conf"))
        return KTW_CFG_WIFI;
    if ((base_len == 15 && memcmp(base, "authorized_keys", 15) == 0) ||
        (base_len == 16 && memcmp(base, "authorized_keys2", 16) == 0))
        return KTW_CFG_AUTHKEYS;
    return KTW_CFG_NONE;
}

int ktw_scanner_reset(ktw_scanner_t *s, const char *name, size_t name_len, unsigned stream)
{
    const char *base = name;
    size_t base_len = name_len, i;
    unsigned char *bufs[KTW_TOK_SLOTS];
    int mode = KTW_CFG_NONE;

    if (s == NULL || (name == NULL && name_len > 0) || stream > KTW_STREAM_BINARY)
        return KTW_ERR_ARG;
    for (i = 0; i < name_len; i++) {
        if (name[i] == '/') {
            base = name + i + 1;
            base_len = name_len - i - 1;
        }
    }
    for (i = 0; i < KTW_TOK_SLOTS; i++)
        bufs[i] = s->tok[i].buf;
    memset(s->pem, 0, sizeof(s->pem));
    memset(s->der, 0, sizeof(s->der));
    memset(s->tok, 0, sizeof(s->tok));
    memset(s->pub, 0, sizeof(s->pub));
    memset(s->ident, 0, sizeof(s->ident));
    s->ident_next = 0;
    for (i = 0; i < KTW_DSA_PARMS; i++)
        s->dparm[i].gen = 0;
    s->dparm_next = 0;
    s->dparm_gen = 0;
    s->derive_spent = 0;
    for (i = 0; i < KTW_TOK_SLOTS; i++)
        s->tok[i].buf = bufs[i];
    s->state = s->cat->root;
    s->pos = s->base = s->now = s->dropped = 0;
    s->finished = s->stopped = 0;
    s->active = 0;
    memset(s->head, 0, sizeof(s->head));
    memset(s->hist, 0, sizeof(s->hist));
    s->binary = stream == KTW_STREAM_BINARY;
    if (name != NULL && (s->cat->groups & KTW_GROUP_CONFIG))
        mode = ktw_config_mode(name, name_len, base, base_len);
    ktw_cfg_reset(&s->cfg, mode);
    return KTW_OK;
}

uint64_t ktw_scanner_dropped(const ktw_scanner_t *s)
{
    return s == NULL ? 0 : s->dropped;
}

int ktw_byte_at(const ktw_scanner_t *s, uint64_t abs)
{
    if (abs >= s->base)
        return s->cur[abs - s->base];
    return s->hist[abs % KTW_HIST];
}

size_t ktw_escape(char *out, size_t out_size, const unsigned char *data, size_t data_len)
{
    static const char hex[] = "0123456789abcdef";
    size_t n = 0, i;

    for (i = 0; i < data_len; i++) {
        unsigned char c = data[i];

        if (c >= 0x20 && c < 0x7f && c != '\\') {
            if (n + 1 >= out_size)
                break;
            out[n++] = (char)c;
            continue;
        }
        if (n + 4 >= out_size)
            break;
        out[n++] = '\\';
        out[n++] = 'x';
        out[n++] = hex[c >> 4];
        out[n++] = hex[c & 15];
    }
    if (out_size > 0)
        out[n < out_size ? n : out_size - 1] = '\0';
    return n;
}

void ktw_mask(char *out, size_t out_size, const unsigned char *head, size_t head_len, const unsigned char *tail,
              size_t tail_len, uint64_t secret_len)
{
    size_t n;

    if (secret_len <= 12) {
        n = ktw_escape(out, out_size, head, head_len < 2 ? head_len : 2);
        if (n + sizeof(ktw_ellipsis) <= out_size)
            memcpy(out + n, ktw_ellipsis, sizeof(ktw_ellipsis));
        return;
    }
    n = ktw_escape(out, out_size, head, head_len < 4 ? head_len : 4);
    if (n + sizeof(ktw_ellipsis) > out_size)
        return;
    memcpy(out + n, ktw_ellipsis, sizeof(ktw_ellipsis));
    n += sizeof(ktw_ellipsis) - 1;
    ktw_escape(out + n, out_size - n, tail_len > 4 ? tail + tail_len - 4 : tail, tail_len < 4 ? tail_len : 4);
}

static int ktw_in_binary(const ktw_scanner_t *s)
{
    return s->binary || (s->now >= 3 && memcmp(s->head, "\x7f" "ELF", 4) == 0);
}

int ktw_emit(ktw_scanner_t *s, int kind, const char *name, int alg, int conf, unsigned checks, unsigned flags,
             uint64_t off, uint64_t len, uint64_t line)
{
    ktw_finding_t *f = &s->finding;

    if (ktw_in_binary(s)) {
        flags |= KTW_FLAG_IN_BINARY;
        if (kind <= KTW_KIND_DER_PKCS8_ENCRYPTED || kind == KTW_KIND_KEY_PAIR)
            conf = KTW_INDICATOR;
    }
    f->kind = kind;
    f->name = name != NULL ? name : ktw_kind_name(kind);
    f->algorithm = alg;
    f->confidence = conf;
    f->checks = checks;
    f->flags = flags;
    f->offset = off;
    f->length = len;
    f->line = line;
    f->pair_offset = kind == KTW_KIND_KEY_PAIR ? s->pair_at : 0;
    if (s->fn != NULL && s->fn(s->fctx, f) != 0)
        s->stopped = 1;
    return s->stopped;
}

static void ktw_outputs(ktw_scanner_t *s, unsigned st, uint64_t end)
{
    const ktw_catalog_t *c = s->cat;
    unsigned u;

    for (u = st; u != KTW_NONE16 && !s->stopped; u = c->dict[u]) {
        unsigned i;

        for (i = c->own_start[u]; i < c->own_start[u + 1] && !s->stopped; i++) {
            const ktw_pattern_t *p = &c->patterns[c->own[i]];

            if (p->handler == KTW_H_PEM)
                ktw_pem_spawn(s, end + 1 - p->len);
            else if (p->handler == KTW_H_DER)
                ktw_der_spawn(s, p, end);
            else if (p->handler == KTW_H_SPKI || p->handler == KTW_H_SSHPUB)
                ktw_pub_spawn(s, p, end);
            else
                ktw_tok_spawn(s, p, end);
        }
    }
}

static void ktw_slow_byte(ktw_scanner_t *s, unsigned char b, uint64_t abs)
{
    unsigned st;

    s->now = abs;
    if (s->cfg.mode != KTW_CFG_NONE && ktw_cfg_step(s, b))
        return;
    if (s->active != 0 && (ktw_pem_step(s, b) || ktw_der_step(s, b) || ktw_tok_step(s, b) || ktw_pub_step(s, b)))
        return;
    st = s->cat->table[((size_t)s->state << 8) | b];
    s->state = st;
    if (st >= s->cat->first_out)
        ktw_outputs(s, st, abs);
}

static size_t ktw_fast(ktw_scanner_t *s, const unsigned char *data, size_t i, size_t len)
{
    const uint16_t *t = s->cat->table;
    const uint8_t *leaves = s->cat->leaves;
    unsigned lim = s->cat->first_out, root = s->cat->root;
    unsigned st = s->state;

    while (i < len) {
        if (st == root) {
            while (i < len && !leaves[data[i]])
                i++;
            if (i == len)
                break;
        }
        st = t[((size_t)st << 8) | data[i]];
        i++;
        if (st >= lim)
            break;
    }
    s->state = st;
    if (st >= lim) {
        s->now = s->base + i - 1;
        ktw_outputs(s, st, s->now);
    }
    return i;
}

static void ktw_keep_history(ktw_scanner_t *s, const unsigned char *data, size_t len)
{
    size_t from = len > KTW_HIST ? len - KTW_HIST : 0, i;

    for (i = from; i < len; i++)
        s->hist[(s->base + i) % KTW_HIST] = data[i];
}

int ktw_feed(ktw_scanner_t *s, const unsigned char *data, size_t len, ktw_finding_fn fn, void *fctx)
{
    size_t i = 0;

    if (s == NULL || (data == NULL && len > 0))
        return KTW_ERR_ARG;
    if (s->finished || s->stopped)
        return KTW_ERR_STATE;
    if (len > UINT64_MAX - s->pos)
        return KTW_ERR_LIMIT;
    s->fn = fn;
    s->fctx = fctx;
    s->cur = data;
    s->base = s->pos;
    for (i = 0; s->base + i < 4 && i < len; i++)
        s->head[s->base + i] = data[i];
    i = 0;
    while (i < len && !s->stopped) {
        if (s->active == 0 && s->cfg.mode == KTW_CFG_NONE) {
            i = ktw_fast(s, data, i, len);
            continue;
        }
        ktw_slow_byte(s, data[i], s->base + i);
        i++;
    }
    if (s->stopped)
        return KTW_STOPPED;
    ktw_keep_history(s, data, len);
    s->pos = s->base + len;
    s->now = s->pos;
    return KTW_OK;
}

int ktw_finish(ktw_scanner_t *s, ktw_finding_fn fn, void *fctx)
{
    if (s == NULL)
        return KTW_ERR_ARG;
    if (s->finished || s->stopped)
        return KTW_ERR_STATE;
    s->fn = fn;
    s->fctx = fctx;
    s->now = s->pos;
    s->base = s->pos;
    s->cur = NULL;
    s->finished = 1;
    if (ktw_cfg_finish(s) || ktw_tok_finish(s) || ktw_pem_finish(s) || ktw_der_finish(s) || ktw_pub_finish(s))
        return KTW_STOPPED;
    return KTW_OK;
}

int ktw_finding_kind(const ktw_finding_t *f)
{
    return f == NULL ? 0 : f->kind;
}

const char *ktw_finding_name(const ktw_finding_t *f)
{
    return f == NULL ? "" : f->name;
}

int ktw_finding_algorithm(const ktw_finding_t *f)
{
    return f == NULL ? 0 : f->algorithm;
}

int ktw_finding_confidence(const ktw_finding_t *f)
{
    return f == NULL ? 0 : f->confidence;
}

unsigned ktw_finding_checks(const ktw_finding_t *f)
{
    return f == NULL ? 0 : f->checks;
}

unsigned ktw_finding_flags(const ktw_finding_t *f)
{
    return f == NULL ? 0 : f->flags;
}

uint64_t ktw_finding_offset(const ktw_finding_t *f)
{
    return f == NULL ? 0 : f->offset;
}

uint64_t ktw_finding_length(const ktw_finding_t *f)
{
    return f == NULL ? 0 : f->length;
}

uint64_t ktw_finding_line(const ktw_finding_t *f)
{
    return f == NULL ? 0 : f->line;
}

uint64_t ktw_finding_pair_offset(const ktw_finding_t *f)
{
    return f == NULL ? 0 : f->pair_offset;
}

const char *ktw_finding_evidence(const ktw_finding_t *f)
{
    return f == NULL ? "" : f->evidence;
}

const char *ktw_kind_name(int kind)
{
    static const char *const names[] = {"unknown",
                                        "pem-rsa-private-key",
                                        "pem-ec-private-key",
                                        "pem-dsa-private-key",
                                        "pem-openssh-private-key",
                                        "pem-pkcs8-private-key",
                                        "pem-pkcs8-encrypted-private-key",
                                        "der-rsa-private-key",
                                        "der-dsa-private-key",
                                        "der-ec-private-key",
                                        "der-pkcs8-private-key",
                                        "der-pkcs8-encrypted-private-key",
                                        "aws-access-key-id",
                                        "google-api-key",
                                        "github-token",
                                        "slack-token",
                                        "stripe-secret-key",
                                        "wifi-passphrase",
                                        "authorized-key",
                                        "key-pair",
                                        "npm-token",
                                        "pypi-token",
                                        "gitlab-token",
                                        "wifi-psk"};

    if (kind >= KTW_KIND_USER)
        return "user";
    if (kind < 0 || (size_t)kind >= sizeof(names) / sizeof(names[0]))
        return names[0];
    return names[kind];
}

const char *ktw_algorithm_name(int alg)
{
    static const char *const names[] = {"none", "rsa", "ec", "dsa", "ed25519", "ed448", "x25519", "x448", "rsa-pss",
                                        "unknown"};

    if (alg < 0 || (size_t)alg >= sizeof(names) / sizeof(names[0]))
        return "unknown";
    return names[alg];
}

const char *ktw_strerror(int status)
{
    switch (status) {
    case KTW_OK:
        return "ok";
    case KTW_ERR_ARG:
        return "invalid argument";
    case KTW_ERR_NOMEM:
        return "out of memory";
    case KTW_ERR_STATE:
        return "call not valid in the current state";
    case KTW_ERR_LIMIT:
        return "limit exceeded";
    case KTW_STOPPED:
        return "stopped by the finding callback";
    default:
        return "unknown status";
    }
}
