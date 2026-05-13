#ifndef KTW_INTERNAL_H
#define KTW_INTERNAL_H

#include "keytrawl/keytrawl.h"

#include <stdint.h>
#include <string.h>

#ifdef KTW_STATIC
#define KTW_INTERNAL static
#else
#define KTW_INTERNAL
#endif

#define KTW_NONE16 0xFFFFu
#define KTW_HIST 64
#define KTW_PEM_SLOTS 4
#define KTW_DER_SLOTS 8
#define KTW_TOK_SLOTS 8
#define KTW_DER_DEPTH 4
#define KTW_EVIDENCE_MAX 256
#define KTW_CAPTURE 64
#define KTW_DSA_P_MAX 384
#define KTW_DSA_X_MAX 32
#define KTW_PUB_SLOTS 4
#define KTW_IDENTS 32
#define KTW_DSA_PARMS 2
#define KTW_DERIVE_FREE 32
#define KTW_DERIVE_BYTES 131072u
#define KTW_ID_NOW 1
#define KTW_ID_LATER 2

enum { KTW_H_PEM = 1, KTW_H_DER, KTW_H_TOKEN, KTW_H_USER, KTW_H_SPKI, KTW_H_SSHPUB };
enum { KTW_SCHEMA_TRAD = 1, KTW_SCHEMA_SEC1, KTW_SCHEMA_PKCS8, KTW_SCHEMA_EPKI };
enum { KTW_TOK_AWS = 1, KTW_TOK_GOOGLE, KTW_TOK_GITHUB, KTW_TOK_GITHUB_PAT, KTW_TOK_SLACK, KTW_TOK_STRIPE, KTW_TOK_NPM, KTW_TOK_PYPI,
       KTW_TOK_GITLAB };
enum { KTW_CFG_NONE = 0, KTW_CFG_WIFI, KTW_CFG_AUTHKEYS };

typedef struct {
    uint8_t handler;
    uint8_t sub;
    uint8_t len;
    uint16_t user;
    unsigned char lit[KTW_PATTERN_MAX];
} ktw_pattern_t;

typedef struct {
    int kind;
    char name[KTW_NAME_MAX + 1];
    size_t literal_len;
    size_t tail_max;
    ktw_validate_fn fn;
    void *ctx;
} ktw_user_t;

struct ktw_catalog {
    ktw_alloc_fn alloc_fn;
    ktw_free_fn free_fn;
    void *alloc_ctx;
    unsigned groups;
    int compiled;
    ktw_pattern_t *patterns;
    size_t npatterns;
    ktw_user_t *users;
    size_t nusers;
    uint16_t *table;
    uint16_t *own_start;
    uint16_t *own;
    uint16_t *dict;
    unsigned nstates;
    unsigned first_out;
    unsigned root;
    uint8_t leaves[256];
    size_t user_buf;
};

struct ktw_finding {
    int kind;
    const char *name;
    int algorithm;
    int confidence;
    unsigned checks;
    unsigned flags;
    uint64_t offset;
    uint64_t length;
    uint64_t line;
    uint64_t pair_offset;
    char evidence[KTW_EVIDENCE_MAX];
};

typedef struct {
    uint32_t h[8];
    uint64_t n;
    unsigned char buf[64];
} ktw_sha256_t;

typedef struct {
    uint8_t quad;
    uint8_t pads;
    uint8_t padding;
    uint8_t done;
    uint8_t error;
    uint8_t left;
    uint64_t count;
} ktw_b64_t;

typedef struct {
    uint8_t schema;
    uint8_t bare;
    uint8_t phase;
    uint8_t depth;
    uint8_t tag;
    uint8_t lenleft;
    uint8_t caplen;
    uint8_t failed;
    uint8_t done;
    uint8_t alg;
    uint8_t aligned;
    uint8_t last;
    uint8_t odd;
    uint8_t extra;
    uint8_t inner;
    uint8_t rawlen;
    uint8_t hash;
    uint8_t got;
    uint8_t idbad;
    uint8_t ctag[KTW_DER_DEPTH + 1];
    uint16_t count[KTW_DER_DEPTH + 1];
    unsigned char cap[16];
    uint32_t len;
    uint32_t clen;
    uint32_t left;
    uint32_t total;
    uint32_t end[KTW_DER_DEPTH + 1];
    uint32_t ilen[9];
    uint16_t plen;
    uint16_t glen;
    uint16_t xlen;
    ktw_sha256_t ha;
    ktw_sha256_t hb;
    unsigned char kp[KTW_DSA_P_MAX];
    unsigned char kg[KTW_DSA_P_MAX];
    unsigned char kx[KTW_DSA_X_MAX];
} ktw_der_t;

typedef struct {
    uint8_t phase;
    uint8_t lenn;
    uint8_t failed;
    uint8_t alg;
    uint8_t target;
    uint8_t mpint;
    uint8_t fields;
    uint8_t typelen;
    uint8_t hashed;
    uint32_t field;
    uint32_t len;
    uint32_t left;
    char type[40];
    ktw_sha256_t sha;
} ktw_pubid_t;

typedef struct {
    uint8_t mode;
    uint8_t alg;
    uint8_t step;
    uint8_t phase;
    uint8_t lenleft;
    uint8_t tag;
    uint8_t first;
    uint8_t done;
    uint8_t failed;
    uint8_t oidlen;
    uint8_t ringn;
    uint8_t prog;
    uint8_t unused;
    uint8_t hdr;
    uint32_t len;
    uint32_t left;
    uint32_t pos;
    uint32_t params;
    uint32_t bits_end;
    uint32_t seq_end;
    unsigned char ring[20];
    ktw_sha256_t sha;
} ktw_spki_t;

typedef struct {
    uint8_t mode;
    uint8_t phase;
    uint8_t failed;
    uint8_t lenn;
    uint8_t caplen;
    uint8_t cipherlen;
    uint8_t typelen;
    uint32_t field;
    uint32_t len;
    uint32_t left;
    uint32_t nkeys;
    uint32_t key;
    uint32_t field2len;
    unsigned char cap[48];
    char cipher[33];
    char type[48];
    ktw_pubid_t id;
} ktw_ssh_t;

typedef struct {
    uint8_t used;
    uint8_t state;
    uint8_t label;
    uint8_t held;
    uint8_t maybe_hdr;
    uint8_t maybe_body;
    uint8_t encrypted;
    uint8_t dek;
    uint8_t kmp;
    uint8_t line_cr;
    uint8_t hdrlen;
    uint8_t ohn;
    uint16_t ok;
    uint8_t short_body;
    uint32_t idx;
    uint32_t nfull;
    uint64_t linelen;
    uint64_t start;
    uint64_t end;
    char hdrkey[12];
    unsigned char ohdr[6];
    ktw_b64_t b64;
    ktw_der_t der;
    ktw_ssh_t ssh;
    ktw_spki_t spki;
} ktw_pem_t;

typedef struct {
    uint8_t used;
    uint8_t held;
    uint64_t start;
    uint64_t end;
    ktw_der_t der;
} ktw_derslot_t;

typedef struct {
    uint8_t used;
    uint8_t handler;
    uint64_t start;
    uint64_t run;
    ktw_spki_t spki;
    ktw_b64_t b64;
    ktw_ssh_t ssh;
} ktw_pubslot_t;

typedef struct {
    uint8_t used;
    uint8_t pub;
    uint8_t alg;
    uint8_t encrypted;
    uint8_t later;
    uint8_t xlen;
    uint8_t parm;
    uint32_t parm_gen;
    int kind;
    uint64_t start;
    uint64_t len;
    unsigned char digest[32];
} ktw_ident_t;

typedef struct {
    uint32_t gen;
    uint16_t plen;
    uint16_t glen;
    unsigned char p[KTW_DSA_P_MAX];
    unsigned char g[KTW_DSA_P_MAX];
} ktw_dsaparm_t;

typedef struct {
    uint8_t used;
    uint8_t type;
    uint8_t phase;
    uint8_t fail;
    uint8_t segdigits;
    uint8_t numsegs;
    uint8_t base32;
    uint8_t lower;
    uint8_t upperdigit;
    uint16_t user;
    uint32_t n;
    uint32_t seglen;
    uint32_t crc;
    uint32_t seek;
    uint32_t run;
    uint64_t start;
    unsigned char first[4];
    unsigned char lastb[4];
    unsigned char tail6[6];
    unsigned char *buf;
} ktw_tok_t;

typedef struct {
    uint8_t mode;
    uint8_t state;
    uint8_t kw;
    uint8_t idx;
    uint8_t quote_at_s;
    uint8_t dead;
    uint8_t blank;
    uint8_t inquote;
    uint8_t ntok;
    uint8_t lastlen;
    uint8_t firstlen;
    uint8_t typeknown;
    uint8_t typelen;
    uint8_t comment;
    uint8_t plain_in;
    uint8_t struct_in;
    uint8_t k;
    uint8_t type_tok;
    uint8_t blob_tok;
    uint8_t blob_done;
    uint8_t cr;
    uint32_t plain_count;
    uint32_t s;
    uint32_t e;
    uint32_t t;
    uint64_t line;
    uint64_t line_start;
    uint64_t tok_start;
    uint64_t rs_pos;
    unsigned char tok[KTW_CAPTURE];
    char first[100];
    char last[100];
    ktw_b64_t b64;
    ktw_ssh_t ssh;
} ktw_cfg_t;

struct ktw_scanner {
    const ktw_catalog_t *cat;
    ktw_alloc_fn alloc_fn;
    ktw_free_fn free_fn;
    void *alloc_ctx;
    ktw_finding_fn fn;
    void *fctx;
    const unsigned char *cur;
    uint64_t base;
    uint64_t pos;
    uint64_t now;
    uint64_t dropped;
    unsigned state;
    int finished;
    int stopped;
    int binary;
    unsigned active;
    unsigned char head[4];
    unsigned char hist[KTW_HIST];
    ktw_pem_t pem[KTW_PEM_SLOTS];
    ktw_derslot_t der[KTW_DER_SLOTS];
    ktw_tok_t tok[KTW_TOK_SLOTS];
    ktw_cfg_t cfg;
    ktw_pubslot_t pub[KTW_PUB_SLOTS];
    ktw_ident_t ident[KTW_IDENTS];
    unsigned ident_next;
    uint64_t pair_at;
    ktw_dsaparm_t dparm[KTW_DSA_PARMS];
    unsigned dparm_next;
    uint32_t dparm_gen;
    uint64_t derive_spent;
    ktw_finding_t finding;
};

KTW_INTERNAL int ktw_byte_at(const ktw_scanner_t *s, uint64_t abs);
KTW_INTERNAL int ktw_emit(ktw_scanner_t *s, int kind, const char *name, int alg, int conf, unsigned checks,
                          unsigned flags, uint64_t off, uint64_t len, uint64_t line);
KTW_INTERNAL void ktw_mask(char *out, size_t out_size, const unsigned char *head, size_t head_len,
                           const unsigned char *tail, size_t tail_len, uint64_t secret_len);
KTW_INTERNAL size_t ktw_escape(char *out, size_t out_size, const unsigned char *data, size_t data_len);

KTW_INTERNAL void ktw_b64_init(ktw_b64_t *b);
KTW_INTERNAL int ktw_b64_put(ktw_b64_t *b, unsigned char c, unsigned char *out_byte);
KTW_INTERNAL int ktw_b64_valid(const ktw_b64_t *b);

KTW_INTERNAL void ktw_der_init(ktw_der_t *d, int schema, int bare);
KTW_INTERNAL void ktw_der_put(ktw_der_t *d, unsigned char b);
KTW_INTERNAL int ktw_der_kind(const ktw_der_t *d);
KTW_INTERNAL int ktw_der_spawn(ktw_scanner_t *s, const ktw_pattern_t *p, uint64_t end);
KTW_INTERNAL int ktw_der_step(ktw_scanner_t *s, unsigned char b);
KTW_INTERNAL int ktw_der_finish(ktw_scanner_t *s);
KTW_INTERNAL int ktw_der_identity(ktw_der_t *d, int *alg, unsigned char out[32]);

enum { KTW_SSH_PRIVATE = 1, KTW_SSH_PUBLIC };
KTW_INTERNAL void ktw_ssh_init(ktw_ssh_t *h, int mode);
KTW_INTERNAL void ktw_ssh_put(ktw_ssh_t *h, unsigned char b);
KTW_INTERNAL int ktw_ssh_valid(const ktw_ssh_t *h);
KTW_INTERNAL int ktw_ssh_alg(const char *type);
KTW_INTERNAL void ktw_pubid_init(ktw_pubid_t *id);
KTW_INTERNAL void ktw_pubid_put(ktw_pubid_t *id, unsigned char b);
KTW_INTERNAL int ktw_pubid_digest(ktw_pubid_t *id, int *alg, unsigned char out[32]);

enum { KTW_SPKI_FIND = 1, KTW_SPKI_TAIL, KTW_SPKI_PKCS1 };
enum { KTW_PUB_PEM = 1, KTW_PUB_PEM_RSA, KTW_PUB_CERT, KTW_PUB_DER, KTW_PUB_SSH };
KTW_INTERNAL void ktw_spki_init(ktw_spki_t *k, int mode);
KTW_INTERNAL void ktw_spki_put(ktw_spki_t *k, unsigned char b);
KTW_INTERNAL int ktw_spki_digest(ktw_spki_t *k, int *alg, unsigned char out[32]);
KTW_INTERNAL int ktw_pair_add(ktw_scanner_t *s, int pub, int alg, const unsigned char digest[32], int kind,
                              int encrypted, uint64_t start, uint64_t len);
KTW_INTERNAL int ktw_pair_private(ktw_scanner_t *s, ktw_der_t *d, int kind, int encrypted, uint64_t start,
                                  uint64_t len);
KTW_INTERNAL int ktw_pub_spawn(ktw_scanner_t *s, const ktw_pattern_t *p, uint64_t end);
KTW_INTERNAL int ktw_pub_step(ktw_scanner_t *s, unsigned char b);
KTW_INTERNAL int ktw_pub_finish(ktw_scanner_t *s);

KTW_INTERNAL int ktw_pem_spawn(ktw_scanner_t *s, uint64_t start);
KTW_INTERNAL int ktw_pem_step(ktw_scanner_t *s, unsigned char b);
KTW_INTERNAL int ktw_pem_finish(ktw_scanner_t *s);

KTW_INTERNAL int ktw_tok_spawn(ktw_scanner_t *s, const ktw_pattern_t *p, uint64_t end);
KTW_INTERNAL int ktw_tok_step(ktw_scanner_t *s, unsigned char b);
KTW_INTERNAL int ktw_tok_finish(ktw_scanner_t *s);
KTW_INTERNAL uint32_t ktw_crc32_update(uint32_t crc, unsigned char b);

KTW_INTERNAL void ktw_sha256_init(ktw_sha256_t *c);
KTW_INTERNAL void ktw_sha256_value(const unsigned char *v, size_t n, unsigned char out[32]);
KTW_INTERNAL void ktw_sha256_byte(ktw_sha256_t *c, unsigned char b);
KTW_INTERNAL void ktw_sha256_final(ktw_sha256_t *c, unsigned char out[32]);
KTW_INTERNAL void ktw_sha512_short(const unsigned char *data, size_t len, unsigned char out[64]);
KTW_INTERNAL void ktw_ed25519_public(const unsigned char seed[32], unsigned char out[32]);
KTW_INTERNAL int ktw_dsa_public(const unsigned char *p, size_t p_len, const unsigned char *g, size_t g_len,
                                const unsigned char *x, size_t x_len, unsigned char *out, size_t *out_len);

KTW_INTERNAL void ktw_cfg_reset(ktw_cfg_t *c, int mode);
KTW_INTERNAL int ktw_cfg_step(ktw_scanner_t *s, unsigned char b);
KTW_INTERNAL int ktw_cfg_finish(ktw_scanner_t *s);

#endif
