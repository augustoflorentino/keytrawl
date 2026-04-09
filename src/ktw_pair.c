#include "ktw_internal.h"

#include <stddef.h>
#include <stdio.h>

enum { KTW_KP_TAG, KTW_KP_LEN, KTW_KP_LENX, KTW_KP_CONTENT, KTW_KP_DONE };
enum { KTW_KA_END, KTW_KA_SKIP, KTW_KA_ENTER, KTW_KA_BITS, KTW_KA_INT, KTW_KA_QBITS };
enum { KTW_PG_RSA, KTW_PG_PSS, KTW_PG_EC, KTW_PG_DSA, KTW_PG_ED25519, KTW_PG_PKCS1, KTW_PG_COUNT };

#define KTW_SPKI_LEN_MAX 16384u
#define KTW_SSH_RUN_MAX 12000u

typedef struct {
    uint8_t tag;
    uint8_t act;
    uint8_t opt;
} ktw_kstep_t;

static const ktw_kstep_t ktw_progs[KTW_PG_COUNT][6] = {
    {{0x05, KTW_KA_SKIP, 1}, {0x03, KTW_KA_BITS, 0}, {0x30, KTW_KA_ENTER, 0}, {0x02, KTW_KA_INT, 0},
     {0x02, KTW_KA_SKIP, 0}, {0, KTW_KA_END, 0}},
    {{0x30, KTW_KA_SKIP, 1}, {0x03, KTW_KA_BITS, 0}, {0x30, KTW_KA_ENTER, 0}, {0x02, KTW_KA_INT, 0},
     {0x02, KTW_KA_SKIP, 0}, {0, KTW_KA_END, 0}},
    {{0x06, KTW_KA_SKIP, 0}, {0x03, KTW_KA_QBITS, 0}, {0, KTW_KA_END, 0}},
    {{0x30, KTW_KA_SKIP, 1}, {0x03, KTW_KA_BITS, 0}, {0x02, KTW_KA_INT, 0}, {0, KTW_KA_END, 0}},
    {{0x03, KTW_KA_QBITS, 0}, {0, KTW_KA_END, 0}},
    {{0x30, KTW_KA_ENTER, 0}, {0x02, KTW_KA_INT, 0}, {0x02, KTW_KA_SKIP, 0}, {0, KTW_KA_END, 0}},
};

static const uint8_t ktw_prog_alg[KTW_PG_COUNT] = {KTW_ALG_RSA, KTW_ALG_RSA, KTW_ALG_EC,
                                                   KTW_ALG_DSA, KTW_ALG_ED25519, KTW_ALG_RSA};

static const struct {
    uint8_t len;
    const char *tlv;
} ktw_spki_oids[KTW_PG_PKCS1] = {
    {11, "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"},
    {11, "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a"},
    {9, "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"},
    {9, "\x06\x07\x2a\x86\x48\xce\x38\x04\x01"},
    {5, "\x06\x03\x2b\x65\x70"},
};

void ktw_spki_init(ktw_spki_t *k, int mode)
{
    memset(k, 0, offsetof(ktw_spki_t, sha));
    k->mode = (uint8_t)mode;
    if (mode == KTW_SPKI_PKCS1) {
        k->prog = KTW_PG_PKCS1;
        k->alg = KTW_ALG_RSA;
        ktw_sha256_init(&k->sha);
    }
}

static void ktw_spki_start(ktw_spki_t *k, int prog)
{
    k->prog = (uint8_t)prog;
    k->alg = ktw_prog_alg[prog];
    k->oidlen = ktw_spki_oids[prog].len;
    k->phase = KTW_KP_TAG;
    k->step = 0;
    k->pos = k->params = k->bits_end = k->seq_end = 0;
    ktw_sha256_init(&k->sha);
}

static void ktw_spki_find(ktw_spki_t *k)
{
    int i;

    for (i = 0; i < KTW_PG_PKCS1; i++) {
        unsigned n = ktw_spki_oids[i].len;

        if (k->ringn >= n && memcmp(k->ring + k->ringn - n, ktw_spki_oids[i].tlv, n) == 0) {
            ktw_spki_start(k, i);
            return;
        }
    }
}

static void ktw_spki_keep(ktw_spki_t *k, unsigned char b)
{
    if (k->ringn == sizeof(k->ring)) {
        memmove(k->ring, k->ring + 1, sizeof(k->ring) - 1);
        k->ringn--;
    }
    k->ring[k->ringn++] = b;
}

static int ktw_spki_seq(const ktw_spki_t *k, unsigned at, uint32_t len, unsigned *hl)
{
    unsigned char h[4];
    unsigned n = 0;

    h[n++] = 0x30;
    if (len >= 0x100)
        h[n++] = 0x82, h[n++] = (unsigned char)(len >> 8);
    else if (len >= 0x80)
        h[n++] = 0x81;
    h[n++] = (unsigned char)len;
    *hl = n;
    return at >= n && memcmp(k->ring + at - n, h, n) == 0;
}

static int ktw_spki_frame(ktw_spki_t *k)
{
    unsigned at = k->ringn - k->oidlen, h1, h2;
    uint32_t algid = k->oidlen + k->params;

    if (!ktw_spki_seq(k, at, algid, &h1))
        return 0;
    if (!ktw_spki_seq(k, at - h1, h1 + algid + (k->bits_end - k->params), &h2))
        return 0;
    k->hdr = (uint8_t)(h1 + h2);
    return 1;
}

static void ktw_spki_next(ktw_spki_t *k)
{
    const ktw_kstep_t *st;

    k->step++;
    k->phase = KTW_KP_TAG;
    st = &ktw_progs[k->prog][k->step];
    if (st->act != KTW_KA_END)
        return;
    if (k->bits_end != 0 && k->pos != k->bits_end)
        k->failed = 1;
    else if (k->seq_end != 0 && k->seq_end != k->pos)
        k->failed = 1;
    else if (k->mode != KTW_SPKI_PKCS1 && !ktw_spki_frame(k))
        k->failed = 1;
    else
        k->done = 1;
    k->phase = KTW_KP_DONE;
}

static void ktw_spki_tag(ktw_spki_t *k, unsigned char b)
{
    const ktw_kstep_t *prog = ktw_progs[k->prog];

    while (prog[k->step].opt && prog[k->step].tag != b)
        k->step++;
    if (prog[k->step].act == KTW_KA_END || prog[k->step].tag != b) {
        k->failed = 1;
        return;
    }
    if (prog[k->step].act == KTW_KA_BITS || prog[k->step].act == KTW_KA_QBITS)
        k->params = k->pos - 1;
    k->tag = b;
    k->phase = KTW_KP_LEN;
}

static void ktw_spki_header(ktw_spki_t *k)
{
    uint8_t act = ktw_progs[k->prog][k->step].act;
    uint32_t lim = k->seq_end != 0 ? k->seq_end : k->bits_end;

    if (k->len > KTW_SPKI_LEN_MAX || (lim != 0 && k->pos + k->len > lim)) {
        k->failed = 1;
        return;
    }
    if (act == KTW_KA_ENTER) {
        k->seq_end = k->pos + k->len;
        ktw_spki_next(k);
        return;
    }
    if (act == KTW_KA_BITS || act == KTW_KA_QBITS) {
        k->bits_end = k->pos + k->len;
        k->unused = 1;
    }
    if ((act == KTW_KA_INT || act == KTW_KA_BITS || act == KTW_KA_QBITS) && k->len == 0) {
        k->failed = 1;
        return;
    }
    if (act == KTW_KA_QBITS && k->alg == KTW_ALG_ED25519 && k->len != 33) {
        k->failed = 1;
        return;
    }
    k->left = k->len;
    k->first = 1;
    k->phase = KTW_KP_CONTENT;
    if (k->left == 0)
        ktw_spki_next(k);
}

static void ktw_spki_length(ktw_spki_t *k, unsigned char b)
{
    if (k->phase == KTW_KP_LEN) {
        if (b < 0x80) {
            k->len = b;
            ktw_spki_header(k);
        } else if (b == 0x81 || b == 0x82) {
            k->lenleft = b & 0x7f;
            k->len = 0;
            k->phase = KTW_KP_LENX;
        } else {
            k->failed = 1;
        }
        return;
    }
    if (k->len == 0 && b == 0) {
        k->failed = 1;
        return;
    }
    k->len = (k->len << 8) | b;
    if (--k->lenleft > 0)
        return;
    if (k->len < 0x80)
        k->failed = 1;
    else
        ktw_spki_header(k);
}

static void ktw_spki_content(ktw_spki_t *k, unsigned char b)
{
    uint8_t act = ktw_progs[k->prog][k->step].act;

    if (k->unused) {
        k->unused = 0;
        if (b != 0 || (act == KTW_KA_QBITS && k->len < 2)) {
            k->failed = 1;
            return;
        }
        if (act == KTW_KA_BITS) {
            ktw_spki_next(k);
            return;
        }
        k->left--;
        return;
    }
    if (act == KTW_KA_INT && k->first && b >= 0x80)
        k->failed = 1;
    if (act == KTW_KA_QBITS && k->first && k->alg == KTW_ALG_EC && (b < 2 || b > 4))
        k->failed = 1;
    if ((act == KTW_KA_INT || act == KTW_KA_QBITS) && !(act == KTW_KA_INT && k->first && b == 0 && k->len > 1))
        ktw_sha256_byte(&k->sha, b);
    k->first = 0;
    if (--k->left == 0)
        ktw_spki_next(k);
}

void ktw_spki_put(ktw_spki_t *k, unsigned char b)
{
    if (k->done && k->mode == KTW_SPKI_PKCS1) {
        k->done = 0;
        k->failed = 1;
    }
    if (k->failed || k->done)
        return;
    if (k->mode == KTW_SPKI_FIND && k->oidlen == 0) {
        ktw_spki_keep(k, b);
        ktw_spki_find(k);
        return;
    }
    k->pos++;
    switch (k->phase) {
    case KTW_KP_TAG:
        ktw_spki_tag(k, b);
        break;
    case KTW_KP_LEN:
    case KTW_KP_LENX:
        ktw_spki_length(k, b);
        break;
    default:
        ktw_spki_content(k, b);
        break;
    }
    if (k->failed && k->mode == KTW_SPKI_FIND) {
        k->failed = 0;
        k->oidlen = 0;
        k->unused = 0;
        k->ringn = 0;
        ktw_spki_keep(k, b);
        ktw_spki_find(k);
    }
}

int ktw_spki_digest(ktw_spki_t *k, int *alg, unsigned char out[32])
{
    if (!k->done)
        return 0;
    *alg = k->alg;
    ktw_sha256_final(&k->sha, out);
    return 1;
}

static const char *ktw_pub_form(int form)
{
    switch (form) {
    case KTW_PUB_PEM:
        return "PEM public key";
    case KTW_PUB_PEM_RSA:
        return "PEM RSA public key";
    case KTW_PUB_CERT:
        return "certificate";
    case KTW_PUB_DER:
        return "DER public key";
    default:
        return "OpenSSH public key";
    }
}

static int ktw_pair_emit(ktw_scanner_t *s, const ktw_ident_t *pub, const ktw_ident_t *priv)
{
    snprintf(s->finding.evidence, sizeof(s->finding.evidence), "%s pairs with %s at offset %llu",
             ktw_pub_form(pub->kind), ktw_kind_name(priv->kind), (unsigned long long)priv->start);
    s->pair_at = priv->start;
    return ktw_emit(s, KTW_KIND_KEY_PAIR, NULL, pub->alg, KTW_CONFIRMED, KTW_CHECK_STRUCTURE | KTW_CHECK_KEY_MATCH,
                    priv->encrypted ? KTW_FLAG_ENCRYPTED : 0, pub->start, pub->len, 0);
}

int ktw_pair_add(ktw_scanner_t *s, int pub, int alg, const unsigned char digest[32], int kind, int encrypted,
                 uint64_t start, uint64_t len)
{
    ktw_ident_t me, other, *slot;
    int found = 0;
    unsigned k;

    for (k = 1; k <= KTW_IDENTS && !found; k++) {
        const ktw_ident_t *e = &s->ident[(s->ident_next + KTW_IDENTS - k) % KTW_IDENTS];

        if (e->used && e->pub != (pub != 0) && e->alg == alg && memcmp(e->digest, digest, 32) == 0) {
            other = *e;
            found = 1;
        }
    }
    memset(&me, 0, sizeof(me));
    me.used = 1;
    me.pub = (uint8_t)(pub != 0);
    me.alg = (uint8_t)alg;
    me.encrypted = (uint8_t)(encrypted != 0);
    me.kind = kind;
    me.start = start;
    me.len = len;
    memcpy(me.digest, digest, 32);
    slot = &s->ident[s->ident_next % KTW_IDENTS];
    *slot = me;
    s->ident_next = (s->ident_next + 1) % KTW_IDENTS;
    if (!found)
        return 0;
    return pub ? ktw_pair_emit(s, &me, &other) : ktw_pair_emit(s, &other, &me);
}

static void ktw_pub_free(ktw_scanner_t *s, ktw_pubslot_t *w)
{
    w->used = 0;
    s->active--;
}

static ktw_pubslot_t *ktw_pub_slot(ktw_scanner_t *s)
{
    size_t i;

    for (i = 0; i < KTW_PUB_SLOTS; i++)
        if (!s->pub[i].used)
            return &s->pub[i];
    s->dropped++;
    return NULL;
}

static void ktw_pub_spki(ktw_scanner_t *s, const ktw_pattern_t *p, uint64_t end)
{
    ktw_pubslot_t *w;
    uint64_t from = end + 1 >= sizeof(w->spki.ring) ? end + 1 - sizeof(w->spki.ring) : 0, a;

    if (end + 1 < (uint64_t)p->len + 4 || (w = ktw_pub_slot(s)) == NULL)
        return;
    ktw_spki_init(&w->spki, KTW_SPKI_TAIL);
    for (a = from; a <= end; a++)
        w->spki.ring[w->spki.ringn++] = (unsigned char)ktw_byte_at(s, a);
    ktw_spki_start(&w->spki, p->sub);
    w->used = 1;
    w->handler = KTW_H_SPKI;
    w->start = end + 1 - p->len;
    s->active++;
}

static int ktw_is_b64char(int c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
}

static void ktw_pub_ssh(ktw_scanner_t *s, const ktw_pattern_t *p, uint64_t end)
{
    uint64_t start = end + 1 - p->len, a;
    ktw_pubslot_t *w;
    unsigned char out;

    if ((start > 0 && ktw_is_b64char(ktw_byte_at(s, start - 1))) || (w = ktw_pub_slot(s)) == NULL)
        return;
    ktw_b64_init(&w->b64);
    ktw_ssh_init(&w->ssh, KTW_SSH_PUBLIC);
    for (a = start; a <= end; a++)
        if (ktw_b64_put(&w->b64, (unsigned char)ktw_byte_at(s, a), &out))
            ktw_ssh_put(&w->ssh, out);
    w->used = 1;
    w->handler = KTW_H_SSHPUB;
    w->start = start;
    w->run = p->len;
    s->active++;
}

int ktw_pub_spawn(ktw_scanner_t *s, const ktw_pattern_t *p, uint64_t end)
{
    if (p->handler == KTW_H_SPKI)
        ktw_pub_spki(s, p, end);
    else
        ktw_pub_ssh(s, p, end);
    return 0;
}

static int ktw_pub_report(ktw_scanner_t *s, ktw_pubslot_t *w, uint64_t end)
{
    unsigned char id[32];
    int alg, form = KTW_PUB_SSH, ok;
    uint64_t start = w->start;

    if (w->handler == KTW_H_SPKI) {
        ok = ktw_spki_digest(&w->spki, &alg, id);
        start -= w->spki.hdr;
        form = KTW_PUB_DER;
    } else {
        ok = ktw_b64_valid(&w->b64) && ktw_ssh_valid(&w->ssh) && ktw_pubid_digest(&w->ssh.id, &alg, id);
    }
    ktw_pub_free(s, w);
    return ok ? ktw_pair_add(s, 1, alg, id, form, 0, start, end - start) : 0;
}

static int ktw_pub_char(ktw_scanner_t *s, ktw_pubslot_t *w, unsigned char b, uint64_t *end)
{
    unsigned char out;

    if (w->handler == KTW_H_SPKI) {
        ktw_spki_put(&w->spki, b);
        *end = s->now + 1;
        return w->spki.done || w->spki.failed;
    }
    if (!ktw_is_b64char(b) && b != '=') {
        *end = s->now;
        return 1;
    }
    if (++w->run > KTW_SSH_RUN_MAX) {
        w->b64.error = 1;
        *end = s->now;
        return 1;
    }
    if (ktw_b64_put(&w->b64, b, &out))
        ktw_ssh_put(&w->ssh, out);
    return 0;
}

int ktw_pub_step(ktw_scanner_t *s, unsigned char b)
{
    size_t i;

    for (i = 0; i < KTW_PUB_SLOTS; i++) {
        ktw_pubslot_t *w = &s->pub[i];
        uint64_t end;

        if (w->used && ktw_pub_char(s, w, b, &end) && ktw_pub_report(s, w, end))
            return 1;
    }
    return 0;
}

int ktw_pub_finish(ktw_scanner_t *s)
{
    size_t i;

    for (i = 0; i < KTW_PUB_SLOTS; i++) {
        ktw_pubslot_t *w = &s->pub[i];

        if (!w->used)
            continue;
        if (w->handler == KTW_H_SPKI) {
            ktw_pub_free(s, w);
            continue;
        }
        if (ktw_pub_report(s, w, s->now))
            return 1;
    }
    return 0;
}
