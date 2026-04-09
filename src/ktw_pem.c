#include "ktw_internal.h"

#include <stdio.h>

enum {
    KTW_PS_LABEL = 1,
    KTW_PS_NL,
    KTW_PS_NLN,
    KTW_PS_HLS,
    KTW_PS_SEPCR,
    KTW_PS_DUAL,
    KTW_PS_HCOLON,
    KTW_PS_HVAL,
    KTW_PS_HVALCR,
    KTW_PS_BODY,
    KTW_PS_BCR,
    KTW_PS_END
};

enum {
    KTW_L_RSA,
    KTW_L_EC,
    KTW_L_DSA,
    KTW_L_OPENSSH,
    KTW_L_PKCS8,
    KTW_L_ENCRYPTED,
    KTW_L_PUBLIC,
    KTW_L_RSA_PUBLIC,
    KTW_L_CERT,
    KTW_L_COUNT
};

#define KTW_L_PRIVATE_MASK ((1u << KTW_L_PUBLIC) - 1)

static const char *const ktw_labels[KTW_L_COUNT] = {
    "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY", "PUBLIC KEY", "RSA PUBLIC KEY", "CERTIFICATE"};
static const int ktw_label_kind[KTW_L_COUNT] = {
    KTW_KIND_PEM_RSA, KTW_KIND_PEM_EC,    KTW_KIND_PEM_DSA,   KTW_KIND_PEM_OPENSSH, KTW_KIND_PEM_PKCS8,
    KTW_KIND_PEM_PKCS8_ENCRYPTED, KTW_PUB_PEM, KTW_PUB_PEM_RSA, KTW_PUB_CERT};

static const char ktw_proc_type[] = "Proc-Type: 4,ENCRYPTED";
static const uint8_t ktw_proc_fail[22] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0};

static const signed char ktw_b64_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55,
    56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

void ktw_b64_init(ktw_b64_t *b)
{
    memset(b, 0, sizeof(*b));
}

int ktw_b64_put(ktw_b64_t *b, unsigned char c, unsigned char *out_byte)
{
    int v;

    if (b->error)
        return 0;
    if (b->done) {
        b->error = 1;
        return 0;
    }
    if (c == '=') {
        b->padding = 1;
        if (b->quad == 0)
            b->error = 1;
        else if (b->quad >= 2 && b->quad + ++b->pads >= 4)
            b->done = 1;
        return 0;
    }
    v = ktw_b64_table[c];
    if (v < 0 || b->padding) {
        b->error = 1;
        return 0;
    }
    b->pads = 0;
    switch (b->quad) {
    case 0:
        b->quad = 1;
        b->left = (uint8_t)v;
        return 0;
    case 1:
        b->quad = 2;
        *out_byte = (unsigned char)((b->left << 2) | (v >> 4));
        b->left = (uint8_t)(v & 0x0f);
        break;
    case 2:
        b->quad = 3;
        *out_byte = (unsigned char)((b->left << 4) | (v >> 2));
        b->left = (uint8_t)(v & 0x03);
        break;
    default:
        b->quad = 0;
        *out_byte = (unsigned char)((b->left << 6) | v);
        b->left = 0;
        break;
    }
    b->count++;
    return 1;
}

int ktw_b64_valid(const ktw_b64_t *b)
{
    return !b->error && (b->done || b->quad == 0);
}

static int ktw_is_word(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

static int ktw_is_b64(unsigned char c)
{
    return ktw_b64_table[c] >= 0 || c == '=';
}

static int ktw_pem_encrypted(const ktw_pem_t *p)
{
    return p->label == KTW_L_ENCRYPTED || p->kmp == sizeof(ktw_proc_type) - 1;
}

static void ktw_pem_body_init(ktw_pem_t *p)
{
    ktw_b64_init(&p->b64);
    p->ohn = 0;
    if (ktw_pem_encrypted(p) && p->label != KTW_L_ENCRYPTED)
        return;
    if (p->label >= KTW_L_PUBLIC)
        ktw_spki_init(&p->spki, p->label == KTW_L_RSA_PUBLIC ? KTW_SPKI_PKCS1 : KTW_SPKI_FIND);
    else if (p->label == KTW_L_OPENSSH)
        ktw_ssh_init(&p->ssh, KTW_SSH_PRIVATE);
    else if (p->label == KTW_L_RSA || p->label == KTW_L_DSA)
        ktw_der_init(&p->der, KTW_SCHEMA_TRAD, 0);
    else if (p->label == KTW_L_EC)
        ktw_der_init(&p->der, KTW_SCHEMA_SEC1, 0);
    else if (p->label == KTW_L_PKCS8)
        ktw_der_init(&p->der, KTW_SCHEMA_PKCS8, 0);
    else
        ktw_der_init(&p->der, KTW_SCHEMA_EPKI, 0);
}

static void ktw_pem_decode(ktw_pem_t *p, unsigned char c)
{
    unsigned char out;

    if (!ktw_b64_put(&p->b64, c, &out))
        return;
    if (p->ohn < sizeof(p->ohdr))
        p->ohdr[p->ohn++] = out;
    if (ktw_pem_encrypted(p) && p->label != KTW_L_ENCRYPTED)
        return;
    if (p->label >= KTW_L_PUBLIC)
        ktw_spki_put(&p->spki, out);
    else if (p->label == KTW_L_OPENSSH)
        ktw_ssh_put(&p->ssh, out);
    else
        ktw_der_put(&p->der, out);
}

static void ktw_pem_kmp(ktw_pem_t *p, unsigned char c)
{
    const size_t n = sizeof(ktw_proc_type) - 1;

    if (p->kmp == n)
        return;
    while (p->kmp > 0 && (unsigned char)ktw_proc_type[p->kmp] != c)
        p->kmp = ktw_proc_fail[p->kmp - 1];
    if ((unsigned char)ktw_proc_type[p->kmp] == c)
        p->kmp++;
}

static int ktw_pem_label(ktw_pem_t *p, unsigned char c)
{
    unsigned i, mask = p->ok;

    for (i = 0; i < KTW_L_COUNT; i++) {
        size_t n = strlen(ktw_labels[i]);
        char want;

        if (!(mask & (1u << i)))
            continue;
        want = p->idx < n ? ktw_labels[i][p->idx] : "-----"[p->idx - n];
        if ((unsigned char)want != c)
            mask &= ~(1u << i);
        else if (p->idx + 1 == n + 5)
            p->label = (uint8_t)i;
    }
    p->ok = (uint16_t)mask;
    p->idx++;
    if (mask == 0)
        return 0;
    if (p->label != KTW_L_COUNT)
        p->state = KTW_PS_NL;
    return 1;
}

static int ktw_pem_line_start(ktw_pem_t *p, unsigned char c)
{
    if (c == '\r') {
        p->state = KTW_PS_SEPCR;
        return 1;
    }
    if (c == '\n') {
        ktw_pem_body_init(p);
        p->state = KTW_PS_BODY;
        p->linelen = 0;
        return 1;
    }
    p->maybe_hdr = ktw_is_word(c) || c == '-';
    p->maybe_body = (uint8_t)(ktw_is_b64(c) != 0);
    if (!p->maybe_hdr && !p->maybe_body)
        return 0;
    ktw_pem_body_init(p);
    if (p->maybe_body)
        ktw_pem_decode(p, c);
    p->hdrlen = 0;
    if (p->maybe_hdr)
        p->hdrkey[p->hdrlen++] = (char)c;
    p->linelen = 1;
    ktw_pem_kmp(p, c);
    p->state = KTW_PS_DUAL;
    return 1;
}

static int ktw_pem_to_end(ktw_pem_t *p)
{
    if (p->nfull < 1)
        return 0;
    p->short_body = p->nfull < 2;
    p->state = KTW_PS_END;
    p->idx = 0;
    return 1;
}

static int ktw_pem_body_eol(ktw_pem_t *p)
{
    if (p->linelen >= 16) {
        p->nfull++;
        p->linelen = 0;
        p->state = KTW_PS_BODY;
        return 1;
    }
    return ktw_pem_to_end(p);
}

static int ktw_pem_end_char(ktw_pem_t *p, unsigned char c)
{
    const char *label = ktw_labels[p->label];
    size_t n = strlen(label);
    char want;

    if (p->idx < 9)
        want = "-----END "[p->idx];
    else if (p->idx < 9 + n)
        want = label[p->idx - 9];
    else
        want = "-----"[p->idx - 9 - n];
    if ((unsigned char)want != c)
        return 0;
    p->idx++;
    return 1;
}

static int ktw_pem_body_char(ktw_pem_t *p, unsigned char c)
{
    if (ktw_is_b64(c)) {
        p->linelen++;
        ktw_pem_decode(p, c);
        return 1;
    }
    if (c == '\r') {
        p->state = KTW_PS_BCR;
        return 1;
    }
    if (c == '\n')
        return ktw_pem_body_eol(p);
    if (c == '-')
        return ktw_pem_to_end(p) && ktw_pem_end_char(p, c);
    return 0;
}

static int ktw_pem_dual(ktw_pem_t *p, unsigned char c)
{
    if (c == ':' && p->maybe_hdr) {
        p->dek = p->dek || (p->hdrlen == 8 && memcmp(p->hdrkey, "DEK-Info", 8) == 0);
        ktw_pem_kmp(p, c);
        p->state = KTW_PS_HCOLON;
        return 1;
    }
    if (c == '\r' || c == '\n') {
        if (!p->maybe_body)
            return 0;
        p->state = KTW_PS_BODY;
        return ktw_pem_body_char(p, c);
    }
    p->maybe_hdr = p->maybe_hdr && (ktw_is_word(c) || c == '-');
    p->maybe_body = p->maybe_body && ktw_is_b64(c);
    if (!p->maybe_hdr && !p->maybe_body)
        return 0;
    if (p->maybe_body) {
        p->linelen++;
        ktw_pem_decode(p, c);
    }
    if (p->maybe_hdr && p->hdrlen < sizeof(p->hdrkey))
        p->hdrkey[p->hdrlen++] = (char)c;
    else if (p->maybe_hdr)
        p->hdrlen = sizeof(p->hdrkey);
    ktw_pem_kmp(p, c);
    return 1;
}

static int ktw_pem_char(ktw_pem_t *p, unsigned char c)
{
    switch (p->state) {
    case KTW_PS_LABEL:
        return ktw_pem_label(p, c);
    case KTW_PS_NL:
        p->state = c == '\r' ? KTW_PS_NLN : KTW_PS_HLS;
        return c == '\r' || c == '\n';
    case KTW_PS_NLN:
        p->state = KTW_PS_HLS;
        return c == '\n';
    case KTW_PS_HLS:
        return ktw_pem_line_start(p, c);
    case KTW_PS_SEPCR:
        ktw_pem_body_init(p);
        p->state = KTW_PS_BODY;
        p->linelen = 0;
        return c == '\n' ? 1 : ktw_pem_body_char(p, c);
    case KTW_PS_DUAL:
        return ktw_pem_dual(p, c);
    case KTW_PS_HCOLON:
        ktw_pem_body_init(p);
        p->state = KTW_PS_HVAL;
        ktw_pem_kmp(p, c);
        return c == ' ';
    case KTW_PS_HVAL:
        if (c == '\r' || c == '\n') {
            p->kmp = ktw_pem_encrypted(p) ? p->kmp : 0;
            p->state = c == '\r' ? KTW_PS_HVALCR : KTW_PS_HLS;
            return 1;
        }
        ktw_pem_kmp(p, c);
        return 1;
    case KTW_PS_HVALCR:
        p->state = KTW_PS_HLS;
        return c == '\n';
    case KTW_PS_BODY:
        return ktw_pem_body_char(p, c);
    case KTW_PS_BCR:
        if (c == '\n')
            return ktw_pem_body_eol(p);
        return ktw_pem_to_end(p) && ktw_pem_end_char(p, c);
    default:
        if (!ktw_pem_end_char(p, c))
            return 0;
        return p->idx == 9 + strlen(ktw_labels[p->label]) + 5 ? 2 : 1;
    }
}

static int ktw_pem_outer(const ktw_pem_t *p)
{
    uint64_t total = p->b64.count, len = 0;
    unsigned count, i;

    if (total < 2 || p->ohdr[0] != 0x30)
        return 0;
    if (!(p->ohdr[1] & 0x80))
        return 2 + (uint64_t)p->ohdr[1] == total;
    count = p->ohdr[1] & 0x7f;
    if (count < 1 || count > 4 || total < 2 + (uint64_t)count)
        return 0;
    for (i = 0; i < count; i++)
        len = (len << 8) | p->ohdr[2 + i];
    return 2 + count + len == total;
}

static int ktw_pem_confidence(const ktw_pem_t *p, unsigned *checks, unsigned *flags, int *alg)
{
    int encrypted = ktw_pem_encrypted(p);

    if (p->label == KTW_L_OPENSSH) {
        if (ktw_ssh_valid(&p->ssh)) {
            *checks |= KTW_CHECK_STRUCTURE;
            *alg = ktw_ssh_alg(p->ssh.type);
            *flags |= strcmp(p->ssh.cipher, "none") != 0 ? KTW_FLAG_ENCRYPTED : 0;
            return KTW_CONFIRMED;
        }
        return (*checks & KTW_CHECK_BASE64) ? KTW_LIKELY : KTW_INDICATOR;
    }
    if (encrypted && p->label != KTW_L_ENCRYPTED) {
        *flags |= KTW_FLAG_ENCRYPTED;
        *alg = p->label == KTW_L_RSA ? KTW_ALG_RSA : p->label == KTW_L_EC ? KTW_ALG_EC : KTW_ALG_DSA;
        if ((*checks & KTW_CHECK_BASE64) && p->b64.count >= 8 && p->b64.count % 8 == 0)
            *checks |= KTW_CHECK_ALIGNED;
        if ((*checks & KTW_CHECK_ALIGNED) && p->dek)
            *checks |= KTW_CHECK_STRUCTURE;
        return (*checks & KTW_CHECK_STRUCTURE) ? KTW_CONFIRMED : (*checks & KTW_CHECK_BASE64) ? KTW_LIKELY
                                                                                               : KTW_INDICATOR;
    }
    if (encrypted)
        *flags |= KTW_FLAG_ENCRYPTED;
    if ((*checks & KTW_CHECK_BASE64) && p->der.done && !p->der.failed &&
        (p->label != KTW_L_RSA || ktw_der_kind(&p->der) == KTW_KIND_DER_RSA) &&
        (p->label != KTW_L_DSA || ktw_der_kind(&p->der) == KTW_KIND_DER_DSA)) {
        *checks |= KTW_CHECK_STRUCTURE | (p->der.aligned ? KTW_CHECK_ALIGNED : 0);
        *alg = ktw_der_kind(&p->der) == KTW_KIND_DER_DSA ? KTW_ALG_DSA : p->der.alg;
        return KTW_CONFIRMED;
    }
    return (*checks & KTW_CHECK_DER_OUTER) ? KTW_LIKELY : KTW_INDICATOR;
}

static int ktw_pem_public(ktw_scanner_t *s, ktw_pem_t *p)
{
    unsigned char id[32];
    int alg;

    if (!ktw_b64_valid(&p->b64) || ktw_pem_encrypted(p) || !ktw_spki_digest(&p->spki, &alg, id))
        return 0;
    return ktw_pair_add(s, 1, alg, id, ktw_label_kind[p->label], 0, p->start, p->end - p->start);
}

static int ktw_pem_identity(ktw_scanner_t *s, ktw_pem_t *p, unsigned checks, unsigned flags)
{
    unsigned char id[32];
    int alg, ok;

    if (!(s->cat->groups & KTW_GROUP_PAIRS) || !(checks & KTW_CHECK_STRUCTURE))
        return 0;
    if (p->label == KTW_L_OPENSSH)
        ok = ktw_pubid_digest(&p->ssh.id, &alg, id);
    else
        ok = !(flags & KTW_FLAG_ENCRYPTED) && ktw_der_identity(&p->der, &alg, id);
    if (!ok)
        return 0;
    return ktw_pair_add(s, 0, alg, id, ktw_label_kind[p->label], (flags & KTW_FLAG_ENCRYPTED) != 0, p->start,
                        p->end - p->start);
}

static int ktw_pem_report(ktw_scanner_t *s, ktw_pem_t *p)
{
    unsigned checks = 0, flags = 0;
    int alg = KTW_ALG_NONE, conf;

    if (p->label >= KTW_L_PUBLIC)
        return ktw_pem_public(s, p);
    if (ktw_b64_valid(&p->b64))
        checks |= KTW_CHECK_BASE64;
    if ((checks & KTW_CHECK_BASE64) && ktw_pem_outer(p))
        checks |= KTW_CHECK_DER_OUTER;
    if (!ktw_pem_encrypted(p) && p->label != KTW_L_OPENSSH && !(checks & KTW_CHECK_DER_OUTER))
        return 0;
    conf = ktw_pem_confidence(p, &checks, &flags, &alg);
    if (p->short_body && !(checks & KTW_CHECK_STRUCTURE))
        return 0;
    snprintf(s->finding.evidence, sizeof(s->finding.evidence), "-----BEGIN %s----- (%llu bytes)",
             ktw_labels[p->label], (unsigned long long)(p->end - p->start));
    if (ktw_emit(s, ktw_label_kind[p->label], NULL, alg, conf, checks, flags, p->start, p->end - p->start, 0))
        return 1;
    return ktw_pem_identity(s, p, checks, flags);
}

static void ktw_pem_free(ktw_scanner_t *s, ktw_pem_t *p)
{
    p->used = 0;
    s->active--;
}

static int ktw_pem_resolve(ktw_scanner_t *s)
{
    for (;;) {
        ktw_pem_t *best = NULL;
        uint64_t end;
        size_t i;

        for (i = 0; i < KTW_PEM_SLOTS; i++) {
            ktw_pem_t *p = &s->pem[i];

            if (p->used && (best == NULL || p->start < best->start))
                best = p;
        }
        if (best == NULL || !best->held)
            return 0;
        end = best->end;
        if (ktw_pem_report(s, best))
            return 1;
        for (i = 0; i < KTW_PEM_SLOTS; i++)
            if (s->pem[i].used && s->pem[i].start < end)
                ktw_pem_free(s, &s->pem[i]);
    }
}

int ktw_pem_spawn(ktw_scanner_t *s, uint64_t start)
{
    size_t i;

    for (i = 0; i < KTW_PEM_SLOTS; i++) {
        ktw_pem_t *p = &s->pem[i];

        if (p->used)
            continue;
        memset(p, 0, sizeof(*p));
        p->used = 1;
        p->state = KTW_PS_LABEL;
        p->label = KTW_L_COUNT;
        p->ok = (uint16_t)((s->cat->groups & KTW_GROUP_PAIRS) ? (1u << KTW_L_COUNT) - 1 : KTW_L_PRIVATE_MASK);
        p->start = start;
        s->active++;
        return 0;
    }
    s->dropped++;
    return 0;
}

int ktw_pem_step(ktw_scanner_t *s, unsigned char c)
{
    size_t i;
    int changed = 0;

    for (i = 0; i < KTW_PEM_SLOTS; i++) {
        ktw_pem_t *p = &s->pem[i];
        int r;

        if (!p->used || p->held)
            continue;
        r = ktw_pem_char(p, c);
        if (r == 0) {
            ktw_pem_free(s, p);
            changed = 1;
        } else if (r == 2) {
            p->held = 1;
            p->end = s->now + 1;
            changed = 1;
        }
    }
    return changed ? ktw_pem_resolve(s) : 0;
}

int ktw_pem_finish(ktw_scanner_t *s)
{
    size_t i;

    for (i = 0; i < KTW_PEM_SLOTS; i++)
        if (s->pem[i].used && !s->pem[i].held)
            ktw_pem_free(s, &s->pem[i]);
    return ktw_pem_resolve(s);
}
