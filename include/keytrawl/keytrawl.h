#ifndef KEYTRAWL_H
#define KEYTRAWL_H

#include <stddef.h>
#include <stdint.h>

#if defined(KTW_STATIC) && defined(__GNUC__)
#define KTW_API static __attribute__((unused))
#elif defined(KTW_STATIC)
#define KTW_API static
#elif defined(_WIN32) && defined(KTW_BUILD_SHARED)
#define KTW_API __declspec(dllexport)
#elif defined(_WIN32) && defined(KTW_SHARED)
#define KTW_API __declspec(dllimport)
#elif defined(__GNUC__) && defined(KTW_BUILD_SHARED)
#define KTW_API __attribute__((visibility("default")))
#else
#define KTW_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define KTW_OK 0
#define KTW_ERR_ARG 1
#define KTW_ERR_NOMEM 2
#define KTW_ERR_STATE 3
#define KTW_ERR_LIMIT 4
#define KTW_STOPPED 5

#define KTW_GROUP_PEM 0x01u
#define KTW_GROUP_DER 0x02u
#define KTW_GROUP_CLOUD 0x04u
#define KTW_GROUP_CONFIG 0x08u
#define KTW_GROUP_PAIRS 0x10u
#define KTW_GROUP_ALL 0x1Fu

#define KTW_KIND_PEM_RSA 1
#define KTW_KIND_PEM_EC 2
#define KTW_KIND_PEM_DSA 3
#define KTW_KIND_PEM_OPENSSH 4
#define KTW_KIND_PEM_PKCS8 5
#define KTW_KIND_PEM_PKCS8_ENCRYPTED 6
#define KTW_KIND_DER_RSA 7
#define KTW_KIND_DER_DSA 8
#define KTW_KIND_DER_EC 9
#define KTW_KIND_DER_PKCS8 10
#define KTW_KIND_DER_PKCS8_ENCRYPTED 11
#define KTW_KIND_AWS_ACCESS_KEY 12
#define KTW_KIND_GOOGLE_API_KEY 13
#define KTW_KIND_GITHUB_TOKEN 14
#define KTW_KIND_SLACK_TOKEN 15
#define KTW_KIND_STRIPE_KEY 16
#define KTW_KIND_WIFI_PASSPHRASE 17
#define KTW_KIND_AUTHORIZED_KEY 18
#define KTW_KIND_KEY_PAIR 19
#define KTW_KIND_NPM_TOKEN 20
#define KTW_KIND_PYPI_TOKEN 21
#define KTW_KIND_GITLAB_TOKEN 22
#define KTW_KIND_WIFI_PSK 23
#define KTW_KIND_USER 1024

#define KTW_ALG_NONE 0
#define KTW_ALG_RSA 1
#define KTW_ALG_EC 2
#define KTW_ALG_DSA 3
#define KTW_ALG_ED25519 4
#define KTW_ALG_ED448 5
#define KTW_ALG_X25519 6
#define KTW_ALG_X448 7
#define KTW_ALG_RSA_PSS 8
#define KTW_ALG_UNKNOWN 9

#define KTW_CONFIRMED 3
#define KTW_LIKELY 2
#define KTW_INDICATOR 1

#define KTW_CHECK_BASE64 0x0001u
#define KTW_CHECK_DER_OUTER 0x0002u
#define KTW_CHECK_STRUCTURE 0x0004u
#define KTW_CHECK_CHECKSUM 0x0008u
#define KTW_CHECK_FORMAT 0x0010u
#define KTW_CHECK_PAIRED 0x0020u
#define KTW_CHECK_CONTEXT 0x0040u
#define KTW_CHECK_ALIGNED 0x0080u
#define KTW_CHECK_VALIDATOR 0x0100u
#define KTW_CHECK_KEY_MATCH 0x0200u

#define KTW_FLAG_ENCRYPTED 0x01u
#define KTW_FLAG_IN_BINARY 0x02u

#define KTW_PATTERN_MAX 64
#define KTW_TAIL_MAX 256
#define KTW_NAME_MAX 63
#define KTW_USER_PATTERNS_MAX 256

typedef struct ktw_catalog ktw_catalog_t;
typedef struct ktw_scanner ktw_scanner_t;
typedef struct ktw_finding ktw_finding_t;

typedef void *(*ktw_alloc_fn)(void *ctx, size_t size);
typedef void (*ktw_free_fn)(void *ctx, void *ptr);

typedef int (*ktw_finding_fn)(void *ctx, const ktw_finding_t *finding);

typedef int (*ktw_validate_fn)(void *ctx, const unsigned char *data, size_t data_len, size_t *out_len);

KTW_API int ktw_catalog_create(unsigned groups, ktw_alloc_fn alloc_fn, ktw_free_fn free_fn, void *alloc_ctx,
                               ktw_catalog_t **out_catalog);
KTW_API void ktw_catalog_destroy(ktw_catalog_t *catalog);

KTW_API int ktw_catalog_add(ktw_catalog_t *catalog, int kind, const char *name, const unsigned char *literal,
                            size_t literal_len, size_t tail_max, ktw_validate_fn validate_fn, void *validate_ctx);
KTW_API int ktw_catalog_compile(ktw_catalog_t *catalog);

KTW_API int ktw_scanner_create(const ktw_catalog_t *catalog, ktw_alloc_fn alloc_fn, ktw_free_fn free_fn,
                               void *alloc_ctx, ktw_scanner_t **out_scanner);
KTW_API void ktw_scanner_destroy(ktw_scanner_t *scanner);

#define KTW_STREAM_AUTO 0u
#define KTW_STREAM_BINARY 1u

KTW_API int ktw_scanner_reset(ktw_scanner_t *scanner, const char *name, size_t name_len, unsigned stream);

KTW_API int ktw_feed(ktw_scanner_t *scanner, const unsigned char *data, size_t data_len, ktw_finding_fn finding_fn,
                     void *finding_ctx);

KTW_API int ktw_finish(ktw_scanner_t *scanner, ktw_finding_fn finding_fn, void *finding_ctx);

KTW_API uint64_t ktw_scanner_dropped(const ktw_scanner_t *scanner);

KTW_API int ktw_finding_kind(const ktw_finding_t *finding);
KTW_API const char *ktw_finding_name(const ktw_finding_t *finding);
KTW_API int ktw_finding_algorithm(const ktw_finding_t *finding);
KTW_API int ktw_finding_confidence(const ktw_finding_t *finding);
KTW_API unsigned ktw_finding_checks(const ktw_finding_t *finding);
KTW_API unsigned ktw_finding_flags(const ktw_finding_t *finding);
KTW_API uint64_t ktw_finding_offset(const ktw_finding_t *finding);
KTW_API uint64_t ktw_finding_length(const ktw_finding_t *finding);
KTW_API uint64_t ktw_finding_line(const ktw_finding_t *finding);
KTW_API uint64_t ktw_finding_pair_offset(const ktw_finding_t *finding);
KTW_API const char *ktw_finding_evidence(const ktw_finding_t *finding);

KTW_API const char *ktw_kind_name(int kind);
KTW_API const char *ktw_algorithm_name(int algorithm);
KTW_API const char *ktw_strerror(int status);

#ifdef __cplusplus
}
#endif

#endif
