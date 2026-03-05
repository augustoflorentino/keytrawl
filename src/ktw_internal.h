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

enum { KTW_H_PEM = 1, KTW_H_DER, KTW_H_TOKEN, KTW_H_USER };
enum { KTW_SCHEMA_TRAD = 1, KTW_SCHEMA_SEC1, KTW_SCHEMA_PKCS8, KTW_SCHEMA_EPKI };
enum { KTW_TOK_AWS = 1, KTW_TOK_GOOGLE, KTW_TOK_GITHUB, KTW_TOK_GITHUB_PAT, KTW_TOK_SLACK, KTW_TOK_STRIPE };
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
    char evidence[KTW_EVIDENCE_MAX];
};

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
    uint8_t ctag[KTW_DER_DEPTH + 1];
    uint16_t count[KTW_DER_DEPTH + 1];
    unsigned char cap[16];
    uint32_t len;
    uint32_t clen;
    uint32_t left;
    uint32_t total;
    uint32_t end[KTW_DER_DEPTH + 1];
    uint32_t ilen[9];
} ktw_der_t;

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
    uint8_t ok;
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
    int so_name;
    unsigned active;
    unsigned char head[4];
    unsigned char hist[KTW_HIST];
    ktw_pem_t pem[KTW_PEM_SLOTS];
    ktw_derslot_t der[KTW_DER_SLOTS];
    ktw_tok_t tok[KTW_TOK_SLOTS];
    ktw_cfg_t cfg;
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

enum { KTW_SSH_PRIVATE = 1, KTW_SSH_PUBLIC };
KTW_INTERNAL void ktw_ssh_init(ktw_ssh_t *h, int mode);
KTW_INTERNAL void ktw_ssh_put(ktw_ssh_t *h, unsigned char b);
KTW_INTERNAL int ktw_ssh_valid(const ktw_ssh_t *h);
KTW_INTERNAL int ktw_ssh_alg(const char *type);

KTW_INTERNAL int ktw_pem_spawn(ktw_scanner_t *s, uint64_t start);
KTW_INTERNAL int ktw_pem_step(ktw_scanner_t *s, unsigned char b);
KTW_INTERNAL int ktw_pem_finish(ktw_scanner_t *s);

KTW_INTERNAL int ktw_tok_spawn(ktw_scanner_t *s, const ktw_pattern_t *p, uint64_t end);
KTW_INTERNAL int ktw_tok_step(ktw_scanner_t *s, unsigned char b);
KTW_INTERNAL int ktw_tok_finish(ktw_scanner_t *s);
KTW_INTERNAL uint32_t ktw_crc32_update(uint32_t crc, unsigned char b);

KTW_INTERNAL void ktw_cfg_reset(ktw_cfg_t *c, int mode);
KTW_INTERNAL int ktw_cfg_step(ktw_scanner_t *s, unsigned char b);
KTW_INTERNAL int ktw_cfg_finish(ktw_scanner_t *s);

#endif
