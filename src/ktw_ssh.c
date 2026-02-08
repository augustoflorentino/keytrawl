#include "ktw_internal.h"

enum { KTW_SP_MAGIC, KTW_SP_LEN, KTW_SP_DATA, KTW_SP_DONE };

#define KTW_SSH_MAGIC "openssh-key-v1"
#define KTW_SSH_MAGIC_LEN 15
#define KTW_SSH_FIELDS_MAX 8

typedef struct {
    const char *type;
    uint8_t fields;
    uint8_t key_len;
    uint8_t alg;
} ktw_ssh_type_t;

static const ktw_ssh_type_t ktw_ssh_types[] = {
    {"ssh-rsa", 3, 0, KTW_ALG_RSA},
    {"ssh-dss", 5, 0, KTW_ALG_DSA},
    {"ecdsa-sha2-nistp256", 3, 0, KTW_ALG_EC},
    {"ecdsa-sha2-nistp384", 3, 0, KTW_ALG_EC},
    {"ecdsa-sha2-nistp521", 3, 0, KTW_ALG_EC},
    {"ssh-ed25519", 2, 32, KTW_ALG_ED25519},
    {"ssh-ed448", 2, 57, KTW_ALG_ED448},
    {"sk-ssh-ed25519@openssh.com", 3, 32, KTW_ALG_ED25519},
    {"sk-ecdsa-sha2-nistp256@openssh.com", 4, 0, KTW_ALG_EC},
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

void ktw_ssh_init(ktw_ssh_t *h, int mode)
{
    memset(h, 0, sizeof(*h));
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
        h->len = h->lenn == 0 ? b : (h->len << 8) | b;
        if (++h->lenn == 4)
            ktw_ssh_length_done(h);
        return;
    case KTW_SP_DATA:
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
