#include "ktw_internal.h"

#include <stddef.h>
#include <stdio.h>

enum { KTW_DP_TAG, KTW_DP_LEN, KTW_DP_LENX, KTW_DP_CONTENT };
enum { KTW_ACT_FAIL, KTW_ACT_DESCEND, KTW_ACT_SKIP };

enum { KTW_IN_NONE, KTW_IN_RSA, KTW_IN_SEC1, KTW_IN_INT, KTW_IN_RAW };

enum { KTW_HT_NONE, KTW_HT_A, KTW_HT_B, KTW_HT_Q, KTW_HT_P, KTW_HT_G, KTW_HT_X, KTW_HT_SEED };
#define KTW_GOT_A 0x01u
#define KTW_GOT_B 0x02u
#define KTW_GOT_P 0x04u
#define KTW_GOT_G 0x08u
#define KTW_GOT_X 0x10u

#define KTW_BARE_MIN 32u
#define KTW_BARE_MAX 65536u

typedef struct {
    uint8_t len;
    uint8_t alg;
    const char *oid;
} ktw_oid_t;

static const ktw_oid_t ktw_key_oids[] = {
    {9, KTW_ALG_RSA, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"},
    {9, KTW_ALG_RSA_PSS, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a"},
    {7, KTW_ALG_EC, "\x2a\x86\x48\xce\x3d\x02\x01"},
    {7, KTW_ALG_DSA, "\x2a\x86\x48\xce\x38\x04\x01"},
    {3, KTW_ALG_ED25519, "\x2b\x65\x70"},
    {3, KTW_ALG_ED448, "\x2b\x65\x71"},
    {3, KTW_ALG_X25519, "\x2b\x65\x6e"},
    {3, KTW_ALG_X448, "\x2b\x65\x6f"},
};

void ktw_der_init(ktw_der_t *d, int schema, int bare)
{
    memset(d, 0, offsetof(ktw_der_t, plen));
    d->schema = (uint8_t)schema;
    d->bare = (uint8_t)bare;
    d->phase = KTW_DP_TAG;
}

int ktw_der_kind(const ktw_der_t *d)
{
    switch (d->schema) {
    case KTW_SCHEMA_TRAD:
        return d->count[1] == 9 ? KTW_KIND_DER_RSA : KTW_KIND_DER_DSA;
    case KTW_SCHEMA_SEC1:
        return KTW_KIND_DER_EC;
    case KTW_SCHEMA_PKCS8:
        return KTW_KIND_DER_PKCS8;
    default:
        return KTW_KIND_DER_PKCS8_ENCRYPTED;
    }
}

static int ktw_der_key_oid(const ktw_der_t *d)
{
    size_t i;

    for (i = 0; i < sizeof(ktw_key_oids) / sizeof(ktw_key_oids[0]); i++)
        if (d->clen == ktw_key_oids[i].len && memcmp(d->cap, ktw_key_oids[i].oid, d->clen) == 0)
            return ktw_key_oids[i].alg;
    return KTW_ALG_NONE;
}

static int ktw_der_pbe_oid(const ktw_der_t *d)
{
    static const unsigned char pkcs5[8] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05};
    static const unsigned char pkcs12[9] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01};

    if (d->clen == 9 && memcmp(d->cap, pkcs5, 8) == 0)
        return d->bare ? d->cap[8] == 0x0d : 1;
    return !d->bare && d->clen == 10 && memcmp(d->cap, pkcs12, 9) == 0;
}

static int ktw_der_inner(ktw_der_t *d)
{
    switch (d->alg) {
    case KTW_ALG_RSA:
    case KTW_ALG_RSA_PSS:
        d->inner = KTW_IN_RSA;
        break;
    case KTW_ALG_EC:
        d->inner = KTW_IN_SEC1;
        break;
    case KTW_ALG_DSA:
        d->inner = KTW_IN_INT;
        break;
    case KTW_ALG_ED25519:
    case KTW_ALG_X25519:
    case KTW_ALG_ED448:
    case KTW_ALG_X448:
        d->inner = KTW_IN_RAW;
        d->rawlen = d->alg == KTW_ALG_ED448 ? 57 : d->alg == KTW_ALG_X448 ? 56 : 32;
        break;
    default:
        return KTW_ACT_SKIP;
    }
    return KTW_ACT_DESCEND;
}

static int ktw_der_header_l1(ktw_der_t *d, int schema, unsigned idx)
{
    uint8_t t = d->tag;

    switch (schema) {
    case KTW_SCHEMA_TRAD:
        return t == 0x02 && idx < 9 ? KTW_ACT_SKIP : KTW_ACT_FAIL;
    case KTW_SCHEMA_SEC1:
        if (idx < 2)
            return t == (idx == 0 ? 0x02 : 0x04) ? KTW_ACT_SKIP : KTW_ACT_FAIL;
        if ((t == 0xA0 && d->extra == 0) || (t == 0xA1 && d->extra < 2)) {
            d->extra = t == 0xA0 ? 1 : 2;
            return KTW_ACT_DESCEND;
        }
        return KTW_ACT_FAIL;
    case KTW_SCHEMA_PKCS8:
        if (idx < 2)
            return t == (idx == 0 ? 0x02 : 0x30) ? (idx == 1 ? KTW_ACT_DESCEND : KTW_ACT_SKIP) : KTW_ACT_FAIL;
        if (idx == 2)
            return t == 0x04 ? ktw_der_inner(d) : KTW_ACT_FAIL;
        if ((t == 0xA0 && d->extra == 0) || ((t == 0x81 || t == 0xA1) && d->extra < 2)) {
            d->extra = t == 0xA0 ? 1 : 2;
            return KTW_ACT_SKIP;
        }
        return KTW_ACT_FAIL;
    default:
        if (idx == 0)
            return t == 0x30 ? KTW_ACT_DESCEND : KTW_ACT_FAIL;
        return idx == 1 && t == 0x04 ? KTW_ACT_SKIP : KTW_ACT_FAIL;
    }
}

static int ktw_der_header_l2(const ktw_der_t *d, int schema, unsigned idx)
{
    uint8_t t = d->tag;

    switch (schema) {
    case KTW_SCHEMA_SEC1:
        return idx == 0 && t == (d->ctag[d->depth - 1] == 0xA0 ? 0x06 : 0x03) ? KTW_ACT_SKIP : KTW_ACT_FAIL;
    case KTW_SCHEMA_PKCS8:
        if (idx == 0)
            return t == 0x06 ? KTW_ACT_SKIP : KTW_ACT_FAIL;
        if (idx == 1 && t == 0x30 && d->alg == KTW_ALG_DSA)
            return KTW_ACT_DESCEND;
        return idx == 1 ? KTW_ACT_SKIP : KTW_ACT_FAIL;
    case KTW_SCHEMA_EPKI:
        return t == (idx == 0 ? 0x06 : 0x30) && idx < 2 ? KTW_ACT_SKIP : KTW_ACT_FAIL;
    default:
        return KTW_ACT_FAIL;
    }
}

static int ktw_der_int_ok(const ktw_der_t *d)
{
    if (d->clen == 0 || d->cap[0] >= 0x80)
        return 0;
    return !(d->clen > 1 && d->cap[0] == 0 && d->cap[1] < 0x80);
}

static int ktw_der_header_wrap(const ktw_der_t *d, unsigned idx)
{
    static const uint8_t tags[] = {0, 0x30, 0x30, 0x02, 0x04};

    if (idx != 0 || d->tag != tags[d->inner])
        return KTW_ACT_FAIL;
    return d->inner == KTW_IN_RSA || d->inner == KTW_IN_SEC1 ? KTW_ACT_DESCEND : KTW_ACT_SKIP;
}

static int ktw_der_prim_l1(ktw_der_t *d, int schema, unsigned idx)
{
    switch (schema) {
    case KTW_SCHEMA_TRAD:
        if (idx == 0)
            return d->clen == 1 && d->cap[0] == 0;
        if (!ktw_der_int_ok(d))
            return 0;
        d->ilen[idx] = d->clen - (d->clen > 1 && d->cap[0] == 0);
        if ((d->last & 1) && idx < 8)
            d->odd |= (uint8_t)(1u << idx);
        return 1;
    case KTW_SCHEMA_SEC1:
        if (idx == 0)
            return d->clen == 1 && d->cap[0] == 1;
        if (d->schema == KTW_SCHEMA_SEC1)
            d->alg = KTW_ALG_EC;
        return d->clen >= 1 && d->clen <= 66;
    case KTW_SCHEMA_PKCS8:
        if (idx == 0)
            return d->clen == 1 && d->cap[0] <= 1;
        return idx != 2 || d->clen >= 16;
    default:
        d->aligned = d->clen >= 16 && d->clen % 8 == 0;
        return d->aligned;
    }
}

static int ktw_der_prim_l2(ktw_der_t *d, int schema, unsigned idx)
{
    if (schema == KTW_SCHEMA_PKCS8 && idx == 0) {
        d->alg = (uint8_t)ktw_der_key_oid(d);
        if (d->alg == KTW_ALG_NONE && d->bare)
            return 0;
        if (d->alg == KTW_ALG_NONE)
            d->alg = KTW_ALG_UNKNOWN;
        return 1;
    }
    if (schema == KTW_SCHEMA_EPKI && idx == 0)
        return ktw_der_pbe_oid(d);
    return schema != KTW_SCHEMA_SEC1 || d->clen > 0;
}

static int ktw_der_prim_wrap(const ktw_der_t *d)
{
    return d->inner == KTW_IN_INT ? ktw_der_int_ok(d) : d->clen == d->rawlen;
}

static int ktw_der_rules(const ktw_der_t *d, unsigned level, unsigned *rel)
{
    if (d->inner != KTW_IN_NONE && level >= 3) {
        *rel = level - 2;
        return d->inner == KTW_IN_SEC1 ? KTW_SCHEMA_SEC1 : KTW_SCHEMA_TRAD;
    }
    *rel = level;
    return d->schema;
}

static int ktw_near_half(uint32_t part, uint32_t whole)
{
    uint32_t twice = 2 * part;

    return twice + 2 >= whole && twice <= whole + 2;
}

static int ktw_der_trad_ok(ktw_der_t *d, unsigned n)
{
    const uint32_t *l = d->ilen;
    int top = d->schema == KTW_SCHEMA_TRAD;

    if (n == 9) {
        if (l[1] < 64 || !(d->odd & 2) || l[2] > l[1] || l[3] > l[1])
            return 0;
        if (!ktw_near_half(l[4], l[1]) || !ktw_near_half(l[5], l[1]) || !(d->odd & 0x30))
            return 0;
        if (top)
            d->alg = KTW_ALG_RSA;
        return l[6] <= l[4] && l[7] <= l[5] && l[8] <= l[4];
    }
    if (n == 6 && top) {
        if (l[1] < 64 || (l[2] != 20 && l[2] != 28 && l[2] != 32))
            return 0;
        d->alg = KTW_ALG_DSA;
        return l[3] <= l[1] && l[4] <= l[1] && l[5] <= l[2];
    }
    return 0;
}

static int ktw_der_close(ktw_der_t *d, unsigned level)
{
    unsigned n = d->count[level], rel;
    int schema;

    if (d->inner != KTW_IN_NONE && level == 2) {
        d->inner = KTW_IN_NONE;
        d->extra = 0;
        return n == 1;
    }
    schema = ktw_der_rules(d, level, &rel);
    if (rel == 1) {
        switch (schema) {
        case KTW_SCHEMA_TRAD:
            return ktw_der_trad_ok(d, n);
        case KTW_SCHEMA_SEC1:
            return n >= 2;
        case KTW_SCHEMA_PKCS8:
            return n >= 3;
        default:
            return n == 2;
        }
    }
    if (schema == KTW_SCHEMA_SEC1)
        return n == 1;
    if (rel == 3)
        return n == 3;
    return schema == KTW_SCHEMA_PKCS8 ? n >= 1 : n == 2;
}

static int ktw_der_header_act(ktw_der_t *d, unsigned level, unsigned idx)
{
    unsigned rel;
    int schema;

    if (d->inner != KTW_IN_NONE && level == 2)
        return ktw_der_header_wrap(d, idx);
    schema = ktw_der_rules(d, level, &rel);
    if (rel == 1)
        return ktw_der_header_l1(d, schema, idx);
    if (rel == 3)
        return d->tag == 0x02 && idx < 3 ? KTW_ACT_SKIP : KTW_ACT_FAIL;
    return rel == 2 ? ktw_der_header_l2(d, schema, idx) : KTW_ACT_FAIL;
}

static uint8_t ktw_der_target(const ktw_der_t *d, unsigned level, unsigned idx)
{
    unsigned rel;
    int schema;

    if (d->inner != KTW_IN_NONE && level == 2) {
        if (d->inner == KTW_IN_INT)
            return KTW_HT_X;
        return d->inner == KTW_IN_RAW && d->alg == KTW_ALG_ED25519 ? KTW_HT_SEED : KTW_HT_NONE;
    }
    schema = ktw_der_rules(d, level, &rel);
    if (schema == KTW_SCHEMA_TRAD && rel == 1 && (idx == 1 || idx == 4))
        return idx == 1 ? KTW_HT_A : KTW_HT_B;
    if (schema == KTW_SCHEMA_SEC1 && rel == 2 && d->ctag[level - 1] == 0xA1)
        return KTW_HT_Q;
    if (schema == KTW_SCHEMA_PKCS8 && rel == 3 && (idx == 0 || idx == 2))
        return idx == 0 ? KTW_HT_P : KTW_HT_G;
    return KTW_HT_NONE;
}

static void ktw_der_target_start(ktw_der_t *d, unsigned level, unsigned idx)
{
    d->hash = ktw_der_target(d, level, idx);
    switch (d->hash) {
    case KTW_HT_A:
    case KTW_HT_Q:
        ktw_sha256_init(&d->ha);
        d->got |= KTW_GOT_A;
        break;
    case KTW_HT_B:
        ktw_sha256_init(&d->hb);
        d->got |= KTW_GOT_B;
        break;
    case KTW_HT_P:
        d->plen = 0;
        d->got |= KTW_GOT_P;
        break;
    case KTW_HT_G:
        d->glen = 0;
        d->got |= KTW_GOT_G;
        break;
    case KTW_HT_X:
    case KTW_HT_SEED:
        d->xlen = 0;
        d->got |= KTW_GOT_X;
        break;
    default:
        break;
    }
}

static void ktw_der_keep(ktw_der_t *d, unsigned char b)
{
    unsigned char *buf = d->kx;
    uint16_t *n = &d->xlen;
    size_t cap = KTW_DSA_X_MAX;

    if (d->hash == KTW_HT_P || d->hash == KTW_HT_G) {
        buf = d->hash == KTW_HT_P ? d->kp : d->kg;
        n = d->hash == KTW_HT_P ? &d->plen : &d->glen;
        cap = KTW_DSA_P_MAX;
    }
    if (*n >= cap) {
        d->idbad = 1;
        return;
    }
    buf[(*n)++] = b;
}

static void ktw_der_absorb(ktw_der_t *d, unsigned char b)
{
    int first = d->left == d->clen;

    if (first && (d->hash == KTW_HT_Q || (b == 0 && d->clen > 1 && d->hash != KTW_HT_SEED)))
        return;
    if (d->hash == KTW_HT_A || d->hash == KTW_HT_Q)
        ktw_sha256_byte(&d->ha, b);
    else if (d->hash == KTW_HT_B)
        ktw_sha256_byte(&d->hb, b);
    else
        ktw_der_keep(d, b);
}

static void ktw_der_header(ktw_der_t *d)
{
    unsigned level = d->depth, idx = d->count[level]++;
    int act;

    if (level > 0 && (uint64_t)d->total + d->len > d->end[level - 1]) {
        d->failed = 1;
        return;
    }
    if (level == 0) {
        act = d->tag == 0x30 ? KTW_ACT_DESCEND : KTW_ACT_FAIL;
        if (d->bare && (d->len < KTW_BARE_MIN || d->len > KTW_BARE_MAX))
            act = KTW_ACT_FAIL;
        if ((uint64_t)d->total + d->len > UINT32_MAX)
            act = KTW_ACT_FAIL;
    } else {
        act = ktw_der_header_act(d, level, idx);
    }
    if (act == KTW_ACT_FAIL || (act == KTW_ACT_DESCEND && level + 1 > KTW_DER_DEPTH)) {
        d->failed = 1;
        return;
    }
    if (act == KTW_ACT_DESCEND) {
        d->end[level] = d->total + d->len;
        d->ctag[level] = d->tag;
        d->count[level + 1] = 0;
        d->depth++;
        d->phase = KTW_DP_TAG;
        return;
    }
    d->clen = d->left = d->len;
    d->caplen = 0;
    d->phase = KTW_DP_CONTENT;
    ktw_der_target_start(d, level, idx);
}

static void ktw_der_prim_end(ktw_der_t *d)
{
    unsigned level = d->depth, idx = d->count[level] - 1, rel;
    int schema, ok;

    if (d->inner != KTW_IN_NONE && level == 2) {
        ok = ktw_der_prim_wrap(d);
    } else {
        schema = ktw_der_rules(d, level, &rel);
        if (rel == 3)
            ok = ktw_der_int_ok(d);
        else
            ok = rel == 1 ? ktw_der_prim_l1(d, schema, idx) : ktw_der_prim_l2(d, schema, idx);
    }

    d->phase = KTW_DP_TAG;
    if (!ok)
        d->failed = 1;
}

static void ktw_der_closing(ktw_der_t *d)
{
    while (!d->failed && d->depth > 0 && d->total == d->end[d->depth - 1]) {
        if (d->phase != KTW_DP_TAG || !ktw_der_close(d, d->depth)) {
            d->failed = 1;
            return;
        }
        d->depth--;
        if (d->depth == 0)
            d->done = 1;
    }
}

static void ktw_der_length(ktw_der_t *d, unsigned char b)
{
    if (d->phase == KTW_DP_LEN) {
        if (b < 0x80) {
            d->len = b;
            ktw_der_header(d);
            return;
        }
        if (b == 0x80 || b > 0x84) {
            d->failed = 1;
            return;
        }
        d->lenleft = b & 0x7f;
        d->len = 0;
        d->phase = KTW_DP_LENX;
        return;
    }
    if (d->len == 0 && b == 0) {
        d->failed = 1;
        return;
    }
    d->len = (d->len << 8) | b;
    if (--d->lenleft > 0)
        return;
    if (d->len < 0x80)
        d->failed = 1;
    else
        ktw_der_header(d);
}

void ktw_der_put(ktw_der_t *d, unsigned char b)
{
    if (d->failed)
        return;
    if (d->done || d->total == UINT32_MAX) {
        d->failed = 1;
        return;
    }
    d->total++;
    switch (d->phase) {
    case KTW_DP_TAG:
        if ((b & 0x1f) == 0x1f) {
            d->failed = 1;
            return;
        }
        d->tag = b;
        d->phase = KTW_DP_LEN;
        return;
    case KTW_DP_LEN:
    case KTW_DP_LENX:
        ktw_der_length(d, b);
        if (d->phase == KTW_DP_CONTENT && d->left == 0)
            ktw_der_prim_end(d);
        break;
    default:
        if (d->caplen < sizeof(d->cap))
            d->cap[d->caplen++] = b;
        if (d->hash != KTW_HT_NONE)
            ktw_der_absorb(d, b);
        d->last = b;
        if (--d->left == 0)
            ktw_der_prim_end(d);
        break;
    }
    ktw_der_closing(d);
}

static int ktw_der_sha(ktw_sha256_t *c, int have, unsigned char out[32])
{
    if (have)
        ktw_sha256_final(c, out);
    return have;
}

static int ktw_der_bytes(const unsigned char *v, size_t n, unsigned char out[32])
{
    ktw_sha256_t c;

    while (n > 1 && *v == 0) {
        v++;
        n--;
    }
    ktw_sha256_init(&c);
    while (n-- > 0)
        ktw_sha256_byte(&c, *v++);
    ktw_sha256_final(&c, out);
    return 1;
}

static int ktw_der_pkcs8_identity(ktw_der_t *d, int *alg, unsigned char out[32])
{
    unsigned char y[KTW_DSA_P_MAX];
    size_t ylen;

    switch (d->alg) {
    case KTW_ALG_RSA:
    case KTW_ALG_RSA_PSS:
        *alg = KTW_ALG_RSA;
        return ktw_der_sha(&d->ha, d->got & KTW_GOT_A, out);
    case KTW_ALG_EC:
        *alg = KTW_ALG_EC;
        return ktw_der_sha(&d->ha, d->got & KTW_GOT_A, out);
    case KTW_ALG_ED25519:
        if (!(d->got & KTW_GOT_X) || d->xlen != 32)
            return 0;
        *alg = KTW_ALG_ED25519;
        ktw_ed25519_public(d->kx, y);
        return ktw_der_bytes(y, 32, out);
    case KTW_ALG_DSA:
        if ((d->got & (KTW_GOT_P | KTW_GOT_G | KTW_GOT_X)) != (KTW_GOT_P | KTW_GOT_G | KTW_GOT_X))
            return 0;
        if (!ktw_dsa_public(d->kp, d->plen, d->kg, d->glen, d->kx, d->xlen, y, &ylen))
            return 0;
        *alg = KTW_ALG_DSA;
        return ktw_der_bytes(y, ylen, out);
    default:
        return 0;
    }
}

int ktw_der_identity(ktw_der_t *d, int *alg, unsigned char out[32])
{
    if (d->failed || !d->done || d->idbad)
        return 0;
    switch (ktw_der_kind(d)) {
    case KTW_KIND_DER_RSA:
        *alg = KTW_ALG_RSA;
        return ktw_der_sha(&d->ha, d->got & KTW_GOT_A, out);
    case KTW_KIND_DER_DSA:
        *alg = KTW_ALG_DSA;
        return ktw_der_sha(&d->hb, d->got & KTW_GOT_B, out);
    case KTW_KIND_DER_EC:
        *alg = KTW_ALG_EC;
        return ktw_der_sha(&d->ha, d->got & KTW_GOT_A, out);
    case KTW_KIND_DER_PKCS8:
        return ktw_der_pkcs8_identity(d, alg, out);
    default:
        return 0;
    }
}

static uint64_t ktw_derslot_end(const ktw_derslot_t *w)
{
    return w->der.done ? w->end : w->start + w->der.end[0];
}

static void ktw_derslot_free(ktw_scanner_t *s, ktw_derslot_t *w)
{
    w->used = 0;
    s->active--;
}

static int ktw_der_report(ktw_scanner_t *s, ktw_derslot_t *w)
{
    int kind = ktw_der_kind(&w->der);
    unsigned checks = KTW_CHECK_STRUCTURE | (w->der.aligned ? KTW_CHECK_ALIGNED : 0);
    unsigned flags = kind == KTW_KIND_DER_PKCS8_ENCRYPTED ? KTW_FLAG_ENCRYPTED : 0;

    unsigned char id[32];
    int idalg;

    snprintf(s->finding.evidence, sizeof(s->finding.evidence), "DER %s (%llu bytes)", ktw_kind_name(kind),
             (unsigned long long)(w->end - w->start));
    if (ktw_emit(s, kind, NULL, w->der.alg, KTW_CONFIRMED, checks, flags, w->start, w->end - w->start, 0))
        return 1;
    if (!(s->cat->groups & KTW_GROUP_PAIRS) || !ktw_der_identity(&w->der, &idalg, id))
        return 0;
    return ktw_pair_add(s, 0, idalg, id, kind, 0, w->start, w->end - w->start);
}

static int ktw_der_resolve(ktw_scanner_t *s)
{
    for (;;) {
        ktw_derslot_t *pick = NULL;
        size_t i, j;

        for (i = 0; i < KTW_DER_SLOTS; i++) {
            ktw_derslot_t *w = &s->der[i];
            int blocked = 0;

            if (!w->used || !w->der.done || (pick != NULL && pick->start <= w->start))
                continue;
            for (j = 0; j < KTW_DER_SLOTS; j++) {
                const ktw_derslot_t *v = &s->der[j];

                if (v->used && !v->der.done && v->start < w->start && ktw_derslot_end(v) >= w->end)
                    blocked = 1;
            }
            if (!blocked)
                pick = w;
        }
        if (pick == NULL)
            return 0;
        if (ktw_der_report(s, pick))
            return 1;
        for (i = 0; i < KTW_DER_SLOTS; i++) {
            ktw_derslot_t *w = &s->der[i];

            if (w != pick && w->used && w->start >= pick->start && ktw_derslot_end(w) <= pick->end)
                ktw_derslot_free(s, w);
        }
        ktw_derslot_free(s, pick);
    }
}

static void ktw_der_try(ktw_scanner_t *s, int schema, uint64_t start, uint64_t end)
{
    ktw_derslot_t *slot = NULL;
    uint64_t a;
    size_t i;

    for (i = 0; i < KTW_DER_SLOTS; i++) {
        if (s->der[i].used && s->der[i].start == start && s->der[i].der.schema == schema)
            return;
        if (!s->der[i].used && slot == NULL)
            slot = &s->der[i];
    }
    if (slot == NULL) {
        s->dropped++;
        return;
    }
    ktw_der_init(&slot->der, schema, 1);
    for (a = start; a <= end && !slot->der.failed; a++)
        ktw_der_put(&slot->der, (unsigned char)ktw_byte_at(s, a));
    if (slot->der.failed)
        return;
    slot->used = 1;
    slot->held = 0;
    slot->start = start;
    s->active++;
}

static int ktw_der_seq_before(const ktw_scanner_t *s, uint64_t at, unsigned h)
{
    if (at < h)
        return 0;
    if (ktw_byte_at(s, at - h) != 0x30)
        return 0;
    if (h == 2)
        return ktw_byte_at(s, at - 1) < 0x80;
    if (h == 3)
        return ktw_byte_at(s, at - 2) == 0x81 && ktw_byte_at(s, at - 1) >= 0x80;
    return ktw_byte_at(s, at - 3) == 0x82 && ktw_byte_at(s, at - 2) != 0;
}

int ktw_der_spawn(ktw_scanner_t *s, const ktw_pattern_t *p, uint64_t end)
{
    uint64_t anchor = end + 1 - p->len;
    unsigned h, g;

    if (p->sub != KTW_SCHEMA_EPKI) {
        for (h = 4; h >= 2; h--)
            if (ktw_der_seq_before(s, anchor, h))
                ktw_der_try(s, p->sub, anchor - h, end);
        return s->stopped;
    }
    for (g = 3; g >= 2; g--) {
        if (!ktw_der_seq_before(s, anchor, g))
            continue;
        for (h = 4; h >= 2; h--)
            if (ktw_der_seq_before(s, anchor - g, h))
                ktw_der_try(s, p->sub, anchor - g - h, end);
    }
    return s->stopped;
}

int ktw_der_step(ktw_scanner_t *s, unsigned char b)
{
    size_t i;
    int changed = 0;

    for (i = 0; i < KTW_DER_SLOTS; i++) {
        ktw_derslot_t *w = &s->der[i];

        if (!w->used || w->der.done)
            continue;
        ktw_der_put(&w->der, b);
        if (w->der.failed) {
            ktw_derslot_free(s, w);
            changed = 1;
        } else if (w->der.done) {
            w->end = s->now + 1;
            changed = 1;
        }
    }
    return changed ? ktw_der_resolve(s) : 0;
}

int ktw_der_finish(ktw_scanner_t *s)
{
    size_t i;

    for (i = 0; i < KTW_DER_SLOTS; i++)
        if (s->der[i].used && !s->der[i].der.done)
            ktw_derslot_free(s, &s->der[i]);
    return ktw_der_resolve(s);
}
