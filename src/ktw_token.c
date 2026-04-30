#include "ktw_internal.h"

#define KTW_AWS_SEEK 240u
#define KTW_SLACK_MAX 200u
#define KTW_STRIPE_MAX 247u
#define KTW_PYPI_MIN 85u
#define KTW_PYPI_MAX 2048u
#define KTW_GITLAB_MAX 64u

static const char ktw_base62[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static int ktw_alnum(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

static int ktw_word(unsigned char c)
{
    return ktw_alnum(c) || c == '_';
}

static int ktw_b64url(unsigned char c)
{
    return ktw_word(c) || c == '-';
}

static int ktw_upper_digit(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

uint32_t ktw_crc32_update(uint32_t crc, unsigned char b)
{
    int i;

    crc ^= b;
    for (i = 0; i < 8; i++)
        crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    return crc;
}

static int ktw_glued(const ktw_scanner_t *s, uint64_t start, int dash)
{
    int prev;

    if (start == 0)
        return 0;
    prev = ktw_byte_at(s, start - 1);
    return ktw_word((unsigned char)prev) || (dash && prev == '-');
}

static void ktw_tok_free(ktw_scanner_t *s, ktw_tok_t *t)
{
    t->used = 0;
    s->active--;
}

static void ktw_tok_push(ktw_tok_t *t, unsigned char b)
{
    memmove(t->lastb, t->lastb + 1, 3);
    t->lastb[3] = b;
    t->n++;
}

static int ktw_tok_emit(ktw_scanner_t *s, ktw_tok_t *t, int kind, int conf, unsigned checks)
{
    size_t tail = t->n < 4 ? t->n : 4;

    ktw_mask(s->finding.evidence, sizeof(s->finding.evidence), t->first, 4, t->lastb + 4 - tail, tail, t->n);
    ktw_tok_free(s, t);
    return ktw_emit(s, kind, NULL, KTW_ALG_NONE, conf, checks, 0, t->start, t->n, 0);
}

static int ktw_user_done(ktw_scanner_t *s, ktw_tok_t *t)
{
    const ktw_user_t *u = &s->cat->users[t->user];
    size_t out_len = u->literal_len;
    int conf = KTW_INDICATOR;
    unsigned checks = 0;

    if (u->fn != NULL) {
        conf = u->fn(u->ctx, t->buf, t->n, &out_len);
        checks = KTW_CHECK_VALIDATOR;
        if (out_len < u->literal_len || out_len > t->n)
            out_len = t->n;
    }
    ktw_tok_free(s, t);
    if (conf != KTW_CONFIRMED && conf != KTW_LIKELY && conf != KTW_INDICATOR)
        return 0;
    ktw_mask(s->finding.evidence, sizeof(s->finding.evidence), t->buf, out_len,
             t->buf + (out_len > 4 ? out_len - 4 : 0), out_len > 4 ? 4 : out_len, out_len);
    return ktw_emit(s, u->kind, u->name, KTW_ALG_NONE, conf, checks, 0, t->start, out_len, 0);
}

static int ktw_github_ok(const ktw_tok_t *t)
{
    uint32_t v = t->crc ^ 0xFFFFFFFFu;
    int i;

    for (i = 5; i >= 0; i--) {
        if ((unsigned char)ktw_base62[v % 62] != t->tail6[i])
            return 0;
        v /= 62;
    }
    return 1;
}

static int ktw_slack_ok(const ktw_tok_t *t)
{
    return !t->fail && t->numsegs >= 2 && t->seglen >= 24 && t->seglen <= 48;
}

static int ktw_gitlab_done(ktw_scanner_t *s, ktw_tok_t *t)
{
    if (t->n == 6 + 20 && !t->fail)
        return ktw_tok_emit(s, t, KTW_KIND_GITLAB_TOKEN, KTW_LIKELY, KTW_CHECK_FORMAT);
    if (t->n > 6 + 20)
        return ktw_tok_emit(s, t, KTW_KIND_GITLAB_TOKEN, KTW_INDICATOR, 0);
    ktw_tok_free(s, t);
    return 0;
}

static int ktw_tok_complete(ktw_scanner_t *s, ktw_tok_t *t)
{
    switch (t->type) {
    case KTW_TOK_GOOGLE:
        return ktw_tok_emit(s, t, KTW_KIND_GOOGLE_API_KEY, KTW_LIKELY, KTW_CHECK_FORMAT);
    case KTW_TOK_GITHUB:
        if (!ktw_github_ok(t)) {
            ktw_tok_free(s, t);
            return 0;
        }
        return ktw_tok_emit(s, t, KTW_KIND_GITHUB_TOKEN, KTW_CONFIRMED, KTW_CHECK_FORMAT | KTW_CHECK_CHECKSUM);
    case KTW_TOK_GITHUB_PAT:
        return ktw_tok_emit(s, t, KTW_KIND_GITHUB_TOKEN, KTW_LIKELY, KTW_CHECK_FORMAT);
    case KTW_TOK_NPM:
        if (!ktw_github_ok(t)) {
            ktw_tok_free(s, t);
            return 0;
        }
        return ktw_tok_emit(s, t, KTW_KIND_NPM_TOKEN, KTW_CONFIRMED, KTW_CHECK_FORMAT | KTW_CHECK_CHECKSUM);
    case KTW_TOK_PYPI:
        return ktw_tok_emit(s, t, KTW_KIND_PYPI_TOKEN, KTW_LIKELY, KTW_CHECK_FORMAT);
    case KTW_TOK_GITLAB:
        return ktw_gitlab_done(s, t);
    case KTW_TOK_SLACK:
        if (!ktw_slack_ok(t)) {
            ktw_tok_free(s, t);
            return 0;
        }
        return ktw_tok_emit(s, t, KTW_KIND_SLACK_TOKEN, KTW_LIKELY, KTW_CHECK_FORMAT);
    default:
        if (t->n < 8 + 24) {
            ktw_tok_free(s, t);
            return 0;
        }
        return ktw_tok_emit(s, t, KTW_KIND_STRIPE_KEY, KTW_LIKELY, KTW_CHECK_FORMAT);
    }
}

static int ktw_aws_emit(ktw_scanner_t *s, ktw_tok_t *t, int paired)
{
    unsigned checks = (t->base32 ? KTW_CHECK_FORMAT : 0) | (paired ? KTW_CHECK_PAIRED : 0);

    return ktw_tok_emit(s, t, KTW_KIND_AWS_ACCESS_KEY, KTW_LIKELY, checks);
}

static int ktw_aws_run_ends(const ktw_tok_t *t, unsigned char b)
{
    return t->run == 40 && t->lower && t->upperdigit && b != '=';
}

static int ktw_aws_seek(ktw_scanner_t *s, ktw_tok_t *t, unsigned char b)
{
    t->seek++;
    if (ktw_alnum(b) || b == '/' || b == '+') {
        t->run++;
        t->lower = t->lower || (b >= 'a' && b <= 'z');
        t->upperdigit = t->upperdigit || ktw_upper_digit(b);
        return 0;
    }
    if (ktw_aws_run_ends(t, b))
        return ktw_aws_emit(s, t, 1);
    t->run = 0;
    t->lower = t->upperdigit = 0;
    if (t->seek > KTW_AWS_SEEK)
        return ktw_aws_emit(s, t, 0);
    return 0;
}

static int ktw_aws_char(ktw_scanner_t *s, ktw_tok_t *t, unsigned char b)
{
    if (t->phase == 1)
        return ktw_aws_seek(s, t, b);
    if (t->n < 20) {
        if (!ktw_upper_digit(b)) {
            ktw_tok_free(s, t);
            return 0;
        }
        t->base32 = t->base32 && ((b >= 'A' && b <= 'Z') || (b >= '2' && b <= '7'));
        ktw_tok_push(t, b);
        return 0;
    }
    if (ktw_word(b)) {
        ktw_tok_free(s, t);
        return 0;
    }
    t->phase = 1;
    return ktw_aws_seek(s, t, b);
}

static int ktw_slack_char(ktw_scanner_t *s, ktw_tok_t *t, unsigned char b)
{
    if (b == '-') {
        if (t->segdigits && t->seglen >= 8 && t->seglen <= 13)
            t->numsegs++;
        else
            t->fail = 1;
        t->seglen = 0;
        t->segdigits = 1;
    } else if (ktw_alnum(b)) {
        t->seglen++;
        t->segdigits = t->segdigits && b >= '0' && b <= '9';
    } else if (b == '_') {
        ktw_tok_free(s, t);
        return 0;
    } else {
        return ktw_tok_complete(s, t);
    }
    if (t->n - 5 >= KTW_SLACK_MAX) {
        ktw_tok_free(s, t);
        return 0;
    }
    ktw_tok_push(t, b);
    return 0;
}

static int ktw_fixed_char(ktw_scanner_t *s, ktw_tok_t *t, unsigned char b, uint32_t total)
{
    int ok;

    if (t->n == total) {
        if (ktw_word(b) || (t->type == KTW_TOK_GOOGLE && b == '-')) {
            ktw_tok_free(s, t);
            return 0;
        }
        return ktw_tok_complete(s, t);
    }
    if (t->type == KTW_TOK_GOOGLE)
        ok = ktw_word(b) || b == '-';
    else if (t->type == KTW_TOK_GITHUB_PAT && t->n == 11 + 22)
        ok = b == '_';
    else
        ok = ktw_alnum(b);
    if (!ok) {
        ktw_tok_free(s, t);
        return 0;
    }
    if ((t->type == KTW_TOK_GITHUB || t->type == KTW_TOK_NPM) && t->n < 4 + 30)
        t->crc = ktw_crc32_update(t->crc, b);
    else if (t->type == KTW_TOK_GITHUB || t->type == KTW_TOK_NPM)
        t->tail6[t->n - 34] = b;
    ktw_tok_push(t, b);
    return 0;
}

static int ktw_stripe_char(ktw_scanner_t *s, ktw_tok_t *t, unsigned char b)
{
    if (ktw_alnum(b) && t->n < 8 + KTW_STRIPE_MAX) {
        ktw_tok_push(t, b);
        return 0;
    }
    if (ktw_word(b)) {
        ktw_tok_free(s, t);
        return 0;
    }
    return ktw_tok_complete(s, t);
}

static int ktw_pypi_char(ktw_scanner_t *s, ktw_tok_t *t, unsigned char b)
{
    if (ktw_b64url(b) && t->n < 5 + KTW_PYPI_MAX) {
        ktw_tok_push(t, b);
        return 0;
    }
    if (ktw_b64url(b) || t->n < 5 + KTW_PYPI_MIN) {
        ktw_tok_free(s, t);
        return 0;
    }
    return ktw_tok_complete(s, t);
}

static int ktw_gitlab_char(ktw_scanner_t *s, ktw_tok_t *t, unsigned char b)
{
    if (t->phase == 1 && !ktw_b64url(b)) {
        t->phase = 0;
        return ktw_tok_complete(s, t);
    }
    if (b == '.' && t->phase == 0 && t->n > 6) {
        t->phase = 1;
        return 0;
    }
    if (!ktw_b64url(b))
        return ktw_tok_complete(s, t);
    if (t->phase == 1) {
        ktw_tok_push(t, '.');
        t->phase = 0;
        t->fail = 1;
    }
    if (t->n + 1 > 6 + KTW_GITLAB_MAX) {
        ktw_tok_free(s, t);
        return 0;
    }
    ktw_tok_push(t, b);
    return 0;
}

static int ktw_tok_char(ktw_scanner_t *s, ktw_tok_t *t, unsigned char b)
{
    const ktw_user_t *u;

    switch (t->type) {
    case 0:
        u = &s->cat->users[t->user];
        t->buf[t->n++] = b;
        return t->n == u->literal_len + u->tail_max ? ktw_user_done(s, t) : 0;
    case KTW_TOK_AWS:
        return ktw_aws_char(s, t, b);
    case KTW_TOK_GOOGLE:
        return ktw_fixed_char(s, t, b, 4 + 35);
    case KTW_TOK_GITHUB:
        return ktw_fixed_char(s, t, b, 4 + 36);
    case KTW_TOK_GITHUB_PAT:
        return ktw_fixed_char(s, t, b, 11 + 22 + 1 + 59);
    case KTW_TOK_NPM:
        return ktw_fixed_char(s, t, b, 4 + 36);
    case KTW_TOK_PYPI:
        return ktw_pypi_char(s, t, b);
    case KTW_TOK_GITLAB:
        return ktw_gitlab_char(s, t, b);
    case KTW_TOK_SLACK:
        return ktw_slack_char(s, t, b);
    default:
        return ktw_stripe_char(s, t, b);
    }
}

static ktw_tok_t *ktw_tok_slot(ktw_scanner_t *s)
{
    size_t i;

    for (i = 0; i < KTW_TOK_SLOTS; i++) {
        if (!s->tok[i].used) {
            unsigned char *buf = s->tok[i].buf;

            memset(&s->tok[i], 0, sizeof(s->tok[i]));
            s->tok[i].buf = buf;
            return &s->tok[i];
        }
    }
    s->dropped++;
    return NULL;
}

int ktw_tok_spawn(ktw_scanner_t *s, const ktw_pattern_t *p, uint64_t end)
{
    uint64_t start = end + 1 - p->len;
    ktw_tok_t *t;

    if (p->handler == KTW_H_TOKEN &&
        ktw_glued(s, start, p->sub == KTW_TOK_GOOGLE || p->sub == KTW_TOK_SLACK))
        return 0;
    t = ktw_tok_slot(s);
    if (t == NULL)
        return 0;
    t->used = 1;
    t->start = start;
    s->active++;
    if (p->handler == KTW_H_USER) {
        t->user = p->user;
        memcpy(t->buf, p->lit, p->len);
        t->n = p->len;
        return s->cat->users[p->user].tail_max == 0 ? ktw_user_done(s, t) : 0;
    }
    t->type = p->sub;
    memcpy(t->first, p->lit, 4);
    memcpy(t->lastb, p->lit + p->len - 4, 4);
    t->n = p->len;
    t->crc = 0xFFFFFFFFu;
    t->base32 = 1;
    t->segdigits = 1;
    return 0;
}

int ktw_tok_step(ktw_scanner_t *s, unsigned char b)
{
    size_t i;

    for (i = 0; i < KTW_TOK_SLOTS && !s->stopped; i++)
        if (s->tok[i].used)
            ktw_tok_char(s, &s->tok[i], b);
    return s->stopped;
}

static int ktw_tok_end(ktw_scanner_t *s, ktw_tok_t *t)
{
    switch (t->type) {
    case 0:
        return ktw_user_done(s, t);
    case KTW_TOK_AWS:
        if (t->phase == 1)
            return ktw_aws_emit(s, t, ktw_aws_run_ends(t, 0));
        if (t->n == 20)
            return ktw_aws_emit(s, t, 0);
        break;
    case KTW_TOK_GOOGLE:
        if (t->n == 4 + 35)
            return ktw_tok_complete(s, t);
        break;
    case KTW_TOK_GITHUB:
        if (t->n == 4 + 36)
            return ktw_tok_complete(s, t);
        break;
    case KTW_TOK_GITHUB_PAT:
        if (t->n == 11 + 22 + 1 + 59)
            return ktw_tok_complete(s, t);
        break;
    case KTW_TOK_NPM:
        if (t->n == 4 + 36)
            return ktw_tok_complete(s, t);
        break;
    case KTW_TOK_PYPI:
        if (t->n >= 5 + KTW_PYPI_MIN)
            return ktw_tok_complete(s, t);
        break;
    default:
        return ktw_tok_complete(s, t);
    }
    ktw_tok_free(s, t);
    return 0;
}

int ktw_tok_finish(ktw_scanner_t *s)
{
    size_t i;

    for (i = 0; i < KTW_TOK_SLOTS && !s->stopped; i++)
        if (s->tok[i].used)
            ktw_tok_end(s, &s->tok[i]);
    return s->stopped;
}
