#include "ktw_internal.h"

static const uint32_t ktw_k256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static const uint32_t ktw_h256[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

static const uint64_t ktw_k512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full,
    0xe9b5dba58189dbbcull, 0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
    0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 0xd807aa98a3030242ull,
    0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull,
    0xc19bf174cf692694ull, 0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
    0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull, 0x2de92c6f592b0275ull,
    0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full,
    0xbf597fc7beef0ee4ull, 0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull, 0x27b70a8546d22ffcull,
    0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull,
    0x92722c851482353bull, 0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
    0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 0xd192e819d6ef5218ull,
    0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull,
    0x34b0bcb5e19b48a8ull, 0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
    0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull, 0x748f82ee5defb2fcull,
    0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull,
    0xc67178f2e372532bull, 0xca273eceea26619cull, 0xd186b8c721c0c207ull,
    0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 0x06f067aa72176fbaull,
    0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull,
    0x431d67c49c100d4cull, 0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
    0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};

static const uint64_t ktw_h512[8] = {
    0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
    0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
    0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
    0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
};

static uint32_t ktw_ror32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static uint64_t ktw_ror64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64 - n));
}

static void ktw_sha256_block(ktw_sha256_t *c)
{
    uint32_t w[64], v[8], t1, t2;
    unsigned i;

    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)c->buf[4 * i] << 24 | (uint32_t)c->buf[4 * i + 1] << 16 | (uint32_t)c->buf[4 * i + 2] << 8 |
               c->buf[4 * i + 3];
    for (i = 16; i < 64; i++)
        w[i] = w[i - 16] + (ktw_ror32(w[i - 15], 7) ^ ktw_ror32(w[i - 15], 18) ^ (w[i - 15] >> 3)) + w[i - 7] +
               (ktw_ror32(w[i - 2], 17) ^ ktw_ror32(w[i - 2], 19) ^ (w[i - 2] >> 10));
    memcpy(v, c->h, sizeof(v));
    for (i = 0; i < 64; i++) {
        t1 = v[7] + (ktw_ror32(v[4], 6) ^ ktw_ror32(v[4], 11) ^ ktw_ror32(v[4], 25)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) +
             ktw_k256[i] + w[i];
        t2 = (ktw_ror32(v[0], 2) ^ ktw_ror32(v[0], 13) ^ ktw_ror32(v[0], 22)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        memmove(v + 1, v, 7 * sizeof(v[0]));
        v[4] += t1;
        v[0] = t1 + t2;
    }
    for (i = 0; i < 8; i++)
        c->h[i] += v[i];
}

void ktw_sha256_value(const unsigned char *v, size_t n, unsigned char out[32])
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
}

void ktw_sha256_init(ktw_sha256_t *c)
{
    memcpy(c->h, ktw_h256, sizeof(c->h));
    c->n = 0;
}

void ktw_sha256_byte(ktw_sha256_t *c, unsigned char b)
{
    c->buf[c->n++ % 64] = b;
    if (c->n % 64 == 0)
        ktw_sha256_block(c);
}

void ktw_sha256_final(ktw_sha256_t *c, unsigned char out[32])
{
    uint64_t bits = c->n * 8;
    unsigned i;

    ktw_sha256_byte(c, 0x80);
    while (c->n % 64 != 56)
        ktw_sha256_byte(c, 0);
    for (i = 0; i < 8; i++)
        ktw_sha256_byte(c, (unsigned char)(bits >> (56 - 8 * i)));
    for (i = 0; i < 32; i++)
        out[i] = (unsigned char)(c->h[i / 4] >> (24 - 8 * (i % 4)));
}

static void ktw_sha512_block(uint64_t h[8], const unsigned char *p)
{
    uint64_t w[80], v[8], t1, t2;
    unsigned i, j;

    for (i = 0; i < 16; i++)
        for (w[i] = 0, j = 0; j < 8; j++)
            w[i] = w[i] << 8 | p[8 * i + j];
    for (i = 16; i < 80; i++)
        w[i] = w[i - 16] + (ktw_ror64(w[i - 15], 1) ^ ktw_ror64(w[i - 15], 8) ^ (w[i - 15] >> 7)) + w[i - 7] +
               (ktw_ror64(w[i - 2], 19) ^ ktw_ror64(w[i - 2], 61) ^ (w[i - 2] >> 6));
    memcpy(v, h, sizeof(v));
    for (i = 0; i < 80; i++) {
        t1 = v[7] + (ktw_ror64(v[4], 14) ^ ktw_ror64(v[4], 18) ^ ktw_ror64(v[4], 41)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) +
             ktw_k512[i] + w[i];
        t2 = (ktw_ror64(v[0], 28) ^ ktw_ror64(v[0], 34) ^ ktw_ror64(v[0], 39)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        memmove(v + 1, v, 7 * sizeof(v[0]));
        v[4] += t1;
        v[0] = t1 + t2;
    }
    for (i = 0; i < 8; i++)
        h[i] += v[i];
}

void ktw_sha512_short(const unsigned char *data, size_t len, unsigned char out[64])
{
    unsigned char block[128] = {0};
    uint64_t h[8];
    unsigned i;

    memcpy(h, ktw_h512, sizeof(h));
    memcpy(block, data, len);
    block[len] = 0x80;
    block[126] = (unsigned char)((len * 8) >> 8);
    block[127] = (unsigned char)(len * 8);
    ktw_sha512_block(h, block);
    for (i = 0; i < 64; i++)
        out[i] = (unsigned char)(h[i / 8] >> (56 - 8 * (i % 8)));
}
