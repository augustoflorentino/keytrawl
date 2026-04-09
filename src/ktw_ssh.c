#include "ktw_internal.h"

#include <stddef.h>

enum { KTW_SP_MAGIC, KTW_SP_LEN, KTW_SP_DATA, KTW_SP_DONE };

#define KTW_SSH_MAGIC "openssh-key-v1"
#define KTW_SSH_MAGIC_LEN 15
#define KTW_SSH_FIELDS_MAX 8

typedef struct {
    const char *type;
    uint8_t fields;
    uint8_t key_len;
    uint8_t alg;
    uint8_t id_field;
    uint8_t mpint;
} ktw_ssh_type_t;

static const ktw_ssh_type_t ktw_ssh_types[] = {
    {"ssh-rsa", 3, 0, KTW_ALG_RSA, 2, 1},
    {"ssh-dss", 5, 0, KTW_ALG_DSA, 4, 1},
    {"ecdsa-sha2-nistp256", 3, 0, KTW_ALG_EC, 2, 0},
    {"ecdsa-sha2-nistp384", 3, 0, KTW_ALG_EC, 2, 0},
    {"ecdsa-sha2-nistp521", 3, 0, KTW_ALG_EC, 2, 0},
    {"ssh-ed25519", 2, 32, KTW_ALG_ED25519, 1, 0},
    {"ssh-ed448", 2, 57, KTW_ALG_ED448, 1, 0},
    {"sk-ssh-ed25519@openssh.com", 3, 32, KTW_ALG_ED25519, 1, 0},
    {"sk-ecdsa-sha2-nistp256@openssh.com", 4, 0, KTW_ALG_EC, 2, 0},
};

#define KTW_NSSH_TYPES (sizeof(ktw_ssh_types) / sizeof(ktw_ssh_types[0]))

static const ktw_ssh_type_t *ktw_ssh_find(const char *type)
{
    size_t i;

    for (i = 0; i < KTW_NSSH_TYPES; i++)
        if (strcmp(type, ktw_ssh_types[i].type) == 0)
            return &ktw_ssh_types[i];
    return NULL;
}

int ktw_ssh_alg(const char *type)
{
    const ktw_ssh_type_t *t = ktw_ssh_find(type);

    return t == NULL ? KTW_ALG_UNKNOWN : t->alg;
}

void ktw_pubid_init(ktw_pubid_t *id)
{
    memset(id, 0, offsetof(ktw_pubid_t, sha));
}

static void ktw_pubid_type(ktw_pubid_t *id)
{
    const ktw_ssh_type_t *t;

    id->type[id->typelen] = '\0';
    t = ktw_ssh_find(id->type);
    if (t == NULL) {
        id->failed = 1;
        return;
    }
    id->alg = t->alg;
    id->target = t->id_field;
    id->mpint = t->mpint;
    id->fields = t->fields;
}

static void ktw_pubid_length(ktw_pubid_t *id)
{
    id->lenn = 0;
    if (id->len > 16384 || (id->field > 0 && id->field >= id->fields)) {
        id->failed = 1;
        return;
    }
    if (id->field == 0 && id->len >= sizeof(id->type)) {
        id->failed = 1;
        return;
    }
    if (id->field > 0 && id->field == id->target)
        ktw_sha256_init(&id->sha);
    id->left = id->len;
    id->phase = 1;
}

static void ktw_pubid_end(ktw_pubid_t *id)
{
    if (id->field == 0)
        ktw_pubid_type(id);
    else if (id->field == id->target)
        id->hashed = 1;
    id->field++;
    id->phase = 0;
}

void ktw_pubid_put(ktw_pubid_t *id, unsigned char b)
{
    if (id->failed)
        return;
    if (id->phase == 0) {
        id->len = id->lenn == 0 ? b : (id->len << 8) | b;
        if (++id->lenn == 4) {
            ktw_pubid_length(id);
            if (!id->failed && id->left == 0)
                ktw_pubid_end(id);
        }
        return;
    }
    if (id->field == 0)
        id->type[id->typelen++] = (char)b;
    else if (id->field == id->target && !(id->mpint && b == 0 && id->left == id->len && id->len > 1))
        ktw_sha256_byte(&id->sha, b);
    if (--id->left == 0)
        ktw_pubid_end(id);
}

int ktw_pubid_digest(ktw_pubid_t *id, int *alg, unsigned char out[32])
{
    if (id->failed || !id->hashed || id->phase != 0 || id->lenn != 0 || id->field != id->fields)
        return 0;
    *alg = id->alg;
    ktw_sha256_final(&id->sha, out);
    return 1;
}

void ktw_ssh_init(ktw_ssh_t *h, int mode)
{
    memset(h, 0, offsetof(ktw_ssh_t, id));
    ktw_pubid_init(&h->id);
    h->mode = (uint8_t)mode;
    h->phase = mode == KTW_SSH_PRIVATE ? KTW_SP_MAGIC : KTW_SP_LEN;
}

static uint32_t ktw_ssh_private_max(const ktw_ssh_t *h)
{
    if (h->field <= 2)
        return h->field == 2 ? 4096 : 64;
    if (h->field < 4 + h->nkeys)
        return 16384;
    return 1u << 20;
}

static void ktw_ssh_capture(ktw_ssh_t *h, unsigned char b)
{
    if (h->caplen < sizeof(h->cap))
        h->cap[h->caplen++] = b;
}

static void ktw_ssh_private_end(ktw_ssh_t *h)
{
    if (h->field == 0) {
        memcpy(h->cipher, h->cap, h->caplen < 32 ? h->caplen : 32);
        h->cipher[h->caplen < 32 ? h->caplen : 32] = '\0';
    } else if (h->field == 4) {
        uint32_t n = 0;

        if (h->caplen >= 4)
            n = (uint32_t)h->cap[0] << 24 | (uint32_t)h->cap[1] << 16 | (uint32_t)h->cap[2] << 8 | h->cap[3];
        if (n <= sizeof(h->type) - 1 && 4 + n <= h->caplen) {
            memcpy(h->type, h->cap + 4, n);
            h->type[n] = '\0';
        }
    }
    if (h->field == 4 + h->nkeys) {
        if (h->len % 8 != 0)
            h->failed = 1;
        h->phase = KTW_SP_DONE;
        return;
    }
    h->field++;
    h->phase = KTW_SP_LEN;
}

static void ktw_ssh_data_end(ktw_ssh_t *h);

static void ktw_ssh_length_done(ktw_ssh_t *h)
{
    h->lenn = 0;
    h->caplen = 0;
    if (h->mode == KTW_SSH_PRIVATE && h->field == 3) {
        if (h->len < 1 || h->len > 16)
            h->failed = 1;
        h->nkeys = h->len;
        h->field++;
        return;
    }
    if (h->mode == KTW_SSH_PRIVATE && h->len > ktw_ssh_private_max(h)) {
        h->failed = 1;
        return;
    }
    if (h->mode == KTW_SSH_PUBLIC && (h->len > 16384 || h->field >= KTW_SSH_FIELDS_MAX)) {
        h->failed = 1;
        return;
    }
    if (h->mode == KTW_SSH_PUBLIC && h->field == 1)
        h->field2len = h->len;
    h->left = h->len;
    h->phase = KTW_SP_DATA;
    if (h->left == 0)
        ktw_ssh_data_end(h);
}

static void ktw_ssh_data_end(ktw_ssh_t *h)
{
    if (h->mode == KTW_SSH_PRIVATE) {
        ktw_ssh_private_end(h);
        return;
    }
    if (h->field == 0) {
        size_t n = h->caplen < sizeof(h->type) - 1 ? h->caplen : sizeof(h->type) - 1;

        memcpy(h->type, h->cap, n);
        h->type[n] = '\0';
    }
    h->field++;
    h->phase = KTW_SP_LEN;
}

void ktw_ssh_put(ktw_ssh_t *h, unsigned char b)
{
    if (h->failed)
        return;
    switch (h->phase) {
    case KTW_SP_MAGIC:
        if ((unsigned char)KTW_SSH_MAGIC[h->len] != b) {
            h->failed = 1;
            return;
        }
        if (++h->len == KTW_SSH_MAGIC_LEN) {
            h->len = 0;
            h->phase = KTW_SP_LEN;
        }
        return;
    case KTW_SP_LEN:
        if (h->mode == KTW_SSH_PUBLIC)
            ktw_pubid_put(&h->id, b);
        h->len = h->lenn == 0 ? b : (h->len << 8) | b;
        if (++h->lenn == 4)
            ktw_ssh_length_done(h);
        return;
    case KTW_SP_DATA:
        if (h->mode == KTW_SSH_PUBLIC || h->field == 4)
            ktw_pubid_put(&h->id, b);
        ktw_ssh_capture(h, b);
        if (--h->left == 0)
            ktw_ssh_data_end(h);
        return;
    default:
        h->failed = 1;
        return;
    }
}

int ktw_ssh_valid(const ktw_ssh_t *h)
{
    const ktw_ssh_type_t *t;

    if (h->failed)
        return 0;
    if (h->mode == KTW_SSH_PRIVATE)
        return h->phase == KTW_SP_DONE;
    if (h->phase != KTW_SP_LEN || h->lenn != 0)
        return 0;
    t = ktw_ssh_find(h->type);
    if (t == NULL || h->field != t->fields)
        return 0;
    return t->key_len == 0 || h->field2len == t->key_len;
}
