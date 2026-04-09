#include "ktw_internal.h"

typedef int64_t ktw_gf[16];

static const ktw_gf ktw_gf0 = {0}, ktw_gf1 = {1};
static const ktw_gf ktw_d2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
                              0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
static const ktw_gf ktw_bx = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
                              0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
static const ktw_gf ktw_by = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                              0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};

static void ktw_gf_set(ktw_gf r, const ktw_gf a)
{
    memcpy(r, a, sizeof(ktw_gf));
}

static void ktw_gf_carry(ktw_gf o)
{
    int64_t c;
    int i;

    for (i = 0; i < 16; i++) {
        o[i] += 65536;
        c = o[i] >> 16;
        if (i < 15)
            o[i + 1] += c - 1;
        else
            o[0] += 38 * (c - 1);
        o[i] -= c * 65536;
    }
}

static void ktw_gf_select(ktw_gf p, ktw_gf q, int b)
{
    int64_t t, c = -(int64_t)b;
    int i;

    for (i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void ktw_gf_pack(unsigned char o[32], const ktw_gf n)
{
    ktw_gf m, t;
    int i, j, b;

    ktw_gf_set(t, n);
    ktw_gf_carry(t);
    ktw_gf_carry(t);
    ktw_gf_carry(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        ktw_gf_select(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
        o[2 * i] = (unsigned char)(t[i] & 0xff);
        o[2 * i + 1] = (unsigned char)(t[i] >> 8);
    }
}

static void ktw_gf_add(ktw_gf o, const ktw_gf a, const ktw_gf b)
{
    int i;

    for (i = 0; i < 16; i++)
        o[i] = a[i] + b[i];
}

static void ktw_gf_sub(ktw_gf o, const ktw_gf a, const ktw_gf b)
{
    int i;

    for (i = 0; i < 16; i++)
        o[i] = a[i] - b[i];
}

static void ktw_gf_mul(ktw_gf o, const ktw_gf a, const ktw_gf b)
{
    int64_t t[31] = {0};
    int i, j;

    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++)
        t[i] += 38 * t[i + 16];
    memcpy(o, t, sizeof(ktw_gf));
    ktw_gf_carry(o);
    ktw_gf_carry(o);
}

static void ktw_gf_inv(ktw_gf o, const ktw_gf in)
{
    ktw_gf c;
    int a;

    ktw_gf_set(c, in);
    for (a = 253; a >= 0; a--) {
        ktw_gf_mul(c, c, c);
        if (a != 2 && a != 4)
            ktw_gf_mul(c, c, in);
    }
    ktw_gf_set(o, c);
}

static void ktw_ed_add(ktw_gf p[4], ktw_gf q[4])
{
    ktw_gf a, b, c, d, t, e, f, g, h;

    ktw_gf_sub(a, p[1], p[0]);
    ktw_gf_sub(t, q[1], q[0]);
    ktw_gf_mul(a, a, t);
    ktw_gf_add(b, p[0], p[1]);
    ktw_gf_add(t, q[0], q[1]);
    ktw_gf_mul(b, b, t);
    ktw_gf_mul(c, p[3], q[3]);
    ktw_gf_mul(c, c, ktw_d2);
    ktw_gf_mul(d, p[2], q[2]);
    ktw_gf_add(d, d, d);
    ktw_gf_sub(e, b, a);
    ktw_gf_sub(f, d, c);
    ktw_gf_add(g, d, c);
    ktw_gf_add(h, b, a);
    ktw_gf_mul(p[0], e, f);
    ktw_gf_mul(p[1], h, g);
    ktw_gf_mul(p[2], g, f);
    ktw_gf_mul(p[3], e, h);
}

static void ktw_ed_swap(ktw_gf p[4], ktw_gf q[4], int b)
{
    int i;

    for (i = 0; i < 4; i++)
        ktw_gf_select(p[i], q[i], b);
}

void ktw_ed25519_public(const unsigned char seed[32], unsigned char out[32])
{
    unsigned char h[64], ex[32];
    ktw_gf p[4], q[4], zi, tx, ty;
    int i;

    ktw_sha512_short(seed, 32, h);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    ktw_gf_set(p[0], ktw_gf0);
    ktw_gf_set(p[1], ktw_gf1);
    ktw_gf_set(p[2], ktw_gf1);
    ktw_gf_set(p[3], ktw_gf0);
    ktw_gf_set(q[0], ktw_bx);
    ktw_gf_set(q[1], ktw_by);
    ktw_gf_set(q[2], ktw_gf1);
    ktw_gf_mul(q[3], ktw_bx, ktw_by);
    for (i = 255; i >= 0; i--) {
        int b = (h[i / 8] >> (i & 7)) & 1;

        ktw_ed_swap(p, q, b);
        ktw_ed_add(q, p);
        ktw_ed_add(p, p);
        ktw_ed_swap(p, q, b);
    }
    ktw_gf_inv(zi, p[2]);
    ktw_gf_mul(tx, p[0], zi);
    ktw_gf_mul(ty, p[1], zi);
    ktw_gf_pack(out, ty);
    ktw_gf_pack(ex, tx);
    out[31] ^= (unsigned char)((ex[0] & 1) << 7);
}

#define KTW_LIMBS (KTW_DSA_P_MAX / 4)

typedef struct {
    uint32_t p[KTW_LIMBS];
    uint32_t n0;
    unsigned n;
} ktw_mont_t;

static void ktw_bn_load(uint32_t *r, unsigned n, const unsigned char *be, size_t len)
{
    size_t i;

    memset(r, 0, n * sizeof(*r));
    for (i = 0; i < len && i / 4 < n; i++)
        r[i / 4] |= (uint32_t)be[len - 1 - i] << (8 * (i % 4));
}

static int ktw_bn_geq(const uint32_t *a, uint32_t a_top, const uint32_t *b, unsigned n)
{
    unsigned i;

    if (a_top != 0)
        return 1;
    for (i = n; i-- > 0;)
        if (a[i] != b[i])
            return a[i] > b[i];
    return 1;
}

static void ktw_bn_sub(uint32_t *a, const uint32_t *b, unsigned n)
{
    uint64_t borrow = 0;
    unsigned i;

    for (i = 0; i < n; i++) {
        uint64_t d = (uint64_t)a[i] - b[i] - borrow;

        a[i] = (uint32_t)d;
        borrow = (d >> 32) & 1;
    }
}

static void ktw_mont_mul(const ktw_mont_t *m, uint32_t *r, const uint32_t *a, const uint32_t *b)
{
    uint32_t t[KTW_LIMBS + 2] = {0};
    unsigned i, j, n = m->n;

    for (i = 0; i < n; i++) {
        uint64_t c = 0, s;
        uint32_t u;

        for (j = 0; j < n; j++) {
            s = (uint64_t)t[j] + (uint64_t)a[j] * b[i] + c;
            t[j] = (uint32_t)s;
            c = s >> 32;
        }
        s = (uint64_t)t[n] + c;
        t[n] = (uint32_t)s;
        t[n + 1] = (uint32_t)(s >> 32);
        u = t[0] * m->n0;
        c = ((uint64_t)t[0] + (uint64_t)u * m->p[0]) >> 32;
        for (j = 1; j < n; j++) {
            s = (uint64_t)t[j] + (uint64_t)u * m->p[j] + c;
            t[j - 1] = (uint32_t)s;
            c = s >> 32;
        }
        s = (uint64_t)t[n] + c;
        t[n - 1] = (uint32_t)s;
        t[n] = t[n + 1] + (uint32_t)(s >> 32);
    }
    if (ktw_bn_geq(t, t[n], m->p, n))
        ktw_bn_sub(t, m->p, n);
    memcpy(r, t, n * sizeof(*r));
}

static int ktw_mont_init(ktw_mont_t *m, const unsigned char *p, size_t p_len)
{
    uint32_t inv = 1;
    unsigned i;

    while (p_len > 0 && *p == 0) {
        p++;
        p_len--;
    }
    if (p_len == 0 || p_len > KTW_DSA_P_MAX || !(p[p_len - 1] & 1))
        return 0;
    m->n = (unsigned)((p_len + 3) / 4);
    ktw_bn_load(m->p, m->n, p, p_len);
    for (i = 0; i < 5; i++)
        inv *= 2 - m->p[0] * inv;
    m->n0 = 0u - inv;
    return 1;
}

static void ktw_mont_r2(const ktw_mont_t *m, uint32_t *r)
{
    unsigned i, j;

    memset(r, 0, m->n * sizeof(*r));
    r[0] = 1;
    for (i = 0; i < 64 * m->n; i++) {
        uint32_t top = r[m->n - 1] >> 31;

        for (j = m->n; j-- > 1;)
            r[j] = r[j] << 1 | r[j - 1] >> 31;
        r[0] <<= 1;
        if (ktw_bn_geq(r, top, m->p, m->n))
            ktw_bn_sub(r, m->p, m->n);
    }
}

int ktw_dsa_public(const unsigned char *p, size_t p_len, const unsigned char *g, size_t g_len, const unsigned char *x,
                   size_t x_len, unsigned char *out, size_t *out_len)
{
    ktw_mont_t m;
    uint32_t r2[KTW_LIMBS], gm[KTW_LIMBS], acc[KTW_LIMBS], one[KTW_LIMBS] = {1};
    size_t i;
    int bit;

    if (!ktw_mont_init(&m, p, p_len) || g_len > 4 * (size_t)m.n)
        return 0;
    ktw_bn_load(gm, m.n, g, g_len);
    if (ktw_bn_geq(gm, 0, m.p, m.n))
        return 0;
    ktw_mont_r2(&m, r2);
    ktw_mont_mul(&m, gm, gm, r2);
    ktw_mont_mul(&m, acc, one, r2);
    for (i = 0; i < x_len; i++)
        for (bit = 7; bit >= 0; bit--) {
            ktw_mont_mul(&m, acc, acc, acc);
            if ((x[i] >> bit) & 1)
                ktw_mont_mul(&m, acc, acc, gm);
        }
    ktw_mont_mul(&m, acc, acc, one);
    *out_len = 4 * (size_t)m.n;
    for (i = 0; i < *out_len; i++)
        out[i] = (unsigned char)(acc[(*out_len - 1 - i) / 4] >> (8 * ((*out_len - 1 - i) % 4)));
    return 1;
}
