#include "ktw_internal.h"

enum {
    KTW_W_LEAD,
    KTW_W_KW,
    KTW_W_OPTWS0,
    KTW_W_OPTWS,
    KTW_W_KEY,
    KTW_W_SEP0,
    KTW_W_SEP,
    KTW_W_U0,
    KTW_W_TOK,
    KTW_W_TAIL,
    KTW_W_DEAD
};

static const char *const ktw_wifi_kw[3] = {"option", "wpa_passphrase", "psk"};

static int ktw_is_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

static int ktw_is_quote(unsigned char c)
{
    return c == '\'' || c == '"';
}

static void ktw_cfg_line(ktw_cfg_t *c, uint64_t start)
{
    int mode = c->mode;
    uint64_t line = c->line;

    memset(c, 0, sizeof(*c));
    c->mode = (uint8_t)mode;
    c->line = line;
    c->line_start = start;
    c->blank = 1;
    c->blob_tok = 0xFF;
}

void ktw_cfg_reset(ktw_cfg_t *c, int mode)
{
    c->mode = (uint8_t)mode;
    c->line = 1;
    ktw_cfg_line(c, 0);
}

static void ktw_wifi_sep_end(ktw_cfg_t *c, unsigned char b, uint64_t abs)
{
    c->rs_pos = abs;
    if (ktw_is_quote(b)) {
        c->quote_at_s = 1;
        c->state = KTW_W_U0;
    } else if (ktw_is_space(b)) {
        c->state = KTW_W_DEAD;
    } else {
        c->tok_start = abs;
        c->tok[0] = b;
        c->t = 1;
        c->state = KTW_W_TOK;
    }
}

static void ktw_wifi_value(ktw_cfg_t *c, unsigned char b, uint64_t abs)
{
    switch (c->state) {
    case KTW_W_SEP0:
    case KTW_W_SEP:
        if (b == ' ' || b == '\t' || b == '=') {
            c->s++;
            c->e = b == '=' ? c->e + 1 : 0;
            c->state = KTW_W_SEP;
        } else if (c->state == KTW_W_SEP0) {
            c->state = KTW_W_DEAD;
        } else {
            ktw_wifi_sep_end(c, b, abs);
        }
        return;
    case KTW_W_U0:
        if (b == ' ' || b == '\t') {
            c->state = KTW_W_TAIL;
        } else if (ktw_is_space(b) || ktw_is_quote(b)) {
            c->state = KTW_W_DEAD;
        } else {
            c->tok_start = abs;
            c->tok[0] = b;
            c->t = 1;
            c->state = KTW_W_TOK;
        }
        return;
    case KTW_W_TOK:
        if (ktw_is_quote(b) || b == ' ' || b == '\t') {
            c->state = KTW_W_TAIL;
        } else if (ktw_is_space(b)) {
            c->state = KTW_W_DEAD;
        } else {
            if (c->t < sizeof(c->tok))
                c->tok[c->t] = b;
            c->t++;
        }
        return;
    default:
        if (b != ' ' && b != '\t')
            c->state = KTW_W_DEAD;
        return;
    }
}

static void ktw_wifi_char(ktw_cfg_t *c, unsigned char b, uint64_t abs)
{
    switch (c->state) {
    case KTW_W_LEAD:
        if (b == ' ' || b == '\t')
            return;
        c->kw = b == 'o' ? 0 : b == 'w' ? 1 : 2;
        c->idx = 1;
        c->state = (b == 'o' || b == 'w' || b == 'p') ? KTW_W_KW : KTW_W_DEAD;
        return;
    case KTW_W_KW:
        if ((unsigned char)ktw_wifi_kw[c->kw][c->idx] != b) {
            c->state = KTW_W_DEAD;
            return;
        }
        if (ktw_wifi_kw[c->kw][++c->idx] == '\0')
            c->state = c->kw == 0 ? KTW_W_OPTWS0 : KTW_W_SEP0;
        return;
    case KTW_W_OPTWS0:
    case KTW_W_OPTWS:
        if (b == ' ' || b == '\t')
            c->state = KTW_W_OPTWS;
        else
            c->state = c->state == KTW_W_OPTWS && b == 'k' ? KTW_W_KEY : KTW_W_DEAD;
        c->idx = 1;
        return;
    case KTW_W_KEY:
        if ("key"[c->idx] != (char)b)
            c->state = KTW_W_DEAD;
        else if (++c->idx == 3)
            c->state = KTW_W_SEP0;
        return;
    case KTW_W_DEAD:
        return;
    default:
        ktw_wifi_value(c, b, abs);
        return;
    }
}

static int ktw_wifi_capture(const ktw_cfg_t *c, uint32_t *out_g, int *out_tok)
{
    uint32_t room = c->e < c->s - 1 ? c->e : c->s - 1;
    uint32_t g;

    if (c->t >= 8 && c->t <= 63 && c->tok[0] != '/' && c->tok[0] != '$') {
        *out_g = 0;
        *out_tok = 1;
        return 1;
    }
    if (c->quote_at_s) {
        *out_g = 8;
        *out_tok = 0;
        return c->t == 0 && room >= 8;
    }
    g = c->t >= 7 ? 1 : 8 - c->t;
    *out_g = g;
    *out_tok = 1;
    return g <= room && g + c->t <= 63;
}

static int ktw_wifi_eol(ktw_scanner_t *s, uint64_t abs)
{
    ktw_cfg_t *c = &s->cfg;
    unsigned char cap[64];
    uint32_t g, len;
    int use_tok;

    if (c->state == KTW_W_SEP)
        c->rs_pos = abs;
    else if (c->state != KTW_W_U0 && c->state != KTW_W_TOK && c->state != KTW_W_TAIL)
        return 0;
    if (!ktw_wifi_capture(c, &g, &use_tok))
        return 0;
    len = g + (use_tok ? c->t : 0);
    memset(cap, '=', g);
    if (use_tok)
        memcpy(cap + g, c->tok, c->t);
    ktw_mask(s->finding.evidence, sizeof(s->finding.evidence), cap, len, cap + (len > 4 ? len - 4 : 0),
             len > 4 ? 4 : len, len);
    return ktw_emit(s, KTW_KIND_WIFI_PASSPHRASE, NULL, KTW_ALG_NONE, KTW_LIKELY,
                    KTW_CHECK_CONTEXT | KTW_CHECK_FORMAT, 0, g == 0 ? c->tok_start : c->rs_pos - g, len, c->line);
}

static int ktw_auth_space(unsigned char b)
{
    return b == ' ' || b == '\t' || b == 0x1f;
}

static int ktw_auth_break(unsigned char b)
{
    return b == '\n' || b == '\r' || b == '\v' || b == '\f' || (b >= 0x1c && b <= 0x1e);
}

static void ktw_auth_token_end(ktw_cfg_t *c)
{
    if (c->k == c->type_tok) {
        char type[sizeof(c->tok)];

        memcpy(type, c->tok, c->typelen);
        type[c->typelen] = '\0';
        c->typeknown = ktw_ssh_alg(type) != KTW_ALG_UNKNOWN;
        if (c->k == 0 && !c->typeknown) {
            c->type_tok = 1;
        } else {
            c->blob_tok = (uint8_t)(c->k + 1);
        }
    }
    if (c->k == c->blob_tok)
        c->blob_done = 1;
    if (c->k < 0xFE)
        c->k++;
}

static void ktw_auth_struct(ktw_cfg_t *c, unsigned char b)
{
    unsigned char out;

    if (!c->struct_in) {
        if (b == ' ' || b == '\t')
            return;
        c->struct_in = 1;
        c->inquote = 0;
        if (c->k == c->type_tok)
            c->typelen = 0;
        if (c->k == c->blob_tok) {
            ktw_b64_init(&c->b64);
            ktw_ssh_init(&c->ssh, KTW_SSH_PUBLIC);
        }
    } else if ((b == ' ' || b == '\t') && !c->inquote) {
        c->struct_in = 0;
        ktw_auth_token_end(c);
        return;
    }
    if (b == '"' && c->k == 0)
        c->inquote = !c->inquote;
    if (c->k == c->type_tok && c->typelen < sizeof(c->tok) - 1)
        c->tok[c->typelen++] = b;
    if (c->k == c->blob_tok && ktw_b64_put(&c->b64, b, &out))
        ktw_ssh_put(&c->ssh, out);
}

static void ktw_auth_plain(ktw_cfg_t *c, unsigned char b)
{
    if (ktw_auth_space(b)) {
        c->plain_in = 0;
        return;
    }
    if (!c->plain_in) {
        c->plain_in = 1;
        c->plain_count++;
        c->lastlen = 0;
    }
    if (c->plain_count == 1 && c->firstlen < sizeof(c->first) - 1)
        c->first[c->firstlen++] = (char)b;
    if (c->lastlen < sizeof(c->last) - 1)
        c->last[c->lastlen++] = (char)b;
}

static void ktw_auth_char(ktw_cfg_t *c, unsigned char b)
{
    if (c->comment)
        return;
    if (c->blank && !ktw_auth_space(b)) {
        c->blank = 0;
        if (b == '#') {
            c->comment = 1;
            return;
        }
    }
    ktw_auth_plain(c, b);
    ktw_auth_struct(c, b);
}

static void ktw_auth_evidence(ktw_scanner_t *s)
{
    const ktw_cfg_t *c = &s->cfg;
    char *ev = s->finding.evidence;
    size_t size = sizeof(s->finding.evidence), n;

    n = ktw_escape(ev, size, (const unsigned char *)c->first, c->firstlen);
    n += ktw_escape(ev + n, size - n, (const unsigned char *)" key, comment '", 15);
    if (c->plain_count > 2)
        n += ktw_escape(ev + n, size - n, (const unsigned char *)c->last, c->lastlen);
    else
        n += ktw_escape(ev + n, size - n, (const unsigned char *)"no comment", 10);
    ktw_escape(ev + n, size - n, (const unsigned char *)"'", 1);
}

static int ktw_auth_eol(ktw_scanner_t *s, uint64_t abs)
{
    ktw_cfg_t *c = &s->cfg;
    int valid;

    if (c->blank || c->comment)
        return 0;
    if (c->struct_in) {
        c->struct_in = 0;
        ktw_auth_token_end(c);
    }
    c->tok[c->typelen < sizeof(c->tok) ? c->typelen : sizeof(c->tok) - 1] = '\0';
    valid = c->typeknown && c->blob_done && ktw_b64_valid(&c->b64) && ktw_ssh_valid(&c->ssh) &&
            strcmp(c->ssh.type, (const char *)c->tok) == 0;
    ktw_auth_evidence(s);
    return ktw_emit(s, KTW_KIND_AUTHORIZED_KEY, NULL, valid ? ktw_ssh_alg(c->ssh.type) : KTW_ALG_NONE,
                    valid ? KTW_CONFIRMED : KTW_INDICATOR,
                    KTW_CHECK_CONTEXT | (valid ? KTW_CHECK_BASE64 | KTW_CHECK_STRUCTURE : 0), 0, c->line_start,
                    abs - c->line_start, c->line);
}

static int ktw_cfg_eol(ktw_scanner_t *s, uint64_t abs)
{
    return s->cfg.mode == KTW_CFG_WIFI ? ktw_wifi_eol(s, abs) : ktw_auth_eol(s, abs);
}

int ktw_cfg_step(ktw_scanner_t *s, unsigned char b)
{
    ktw_cfg_t *c = &s->cfg;
    int cr = c->cr;

    c->cr = 0;
    if (c->mode == KTW_CFG_AUTHKEYS && cr && b == '\n') {
        c->line_start = s->now + 1;
        return 0;
    }
    if (b == '\n' || (c->mode == KTW_CFG_AUTHKEYS && ktw_auth_break(b))) {
        if (ktw_cfg_eol(s, s->now))
            return 1;
        c->line++;
        ktw_cfg_line(c, s->now + 1);
        c->cr = b == '\r';
        return 0;
    }
    if (c->mode == KTW_CFG_WIFI)
        ktw_wifi_char(c, b, s->now);
    else
        ktw_auth_char(c, b);
    return 0;
}

int ktw_cfg_finish(ktw_scanner_t *s)
{
    if (s->cfg.mode == KTW_CFG_NONE)
        return 0;
    return ktw_cfg_eol(s, s->now);
}
