#ifndef KEYTRAWL_H
#define KEYTRAWL_H

#include <stddef.h>

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

typedef struct ktw_buf ktw_buf_t;

typedef void *(*ktw_alloc_fn)(void *ctx, size_t size);
typedef void (*ktw_free_fn)(void *ctx, void *ptr);
typedef int (*ktw_piece_fn)(void *ctx, const unsigned char *piece, size_t piece_len);

KTW_API int ktw_buf_create(ktw_alloc_fn alloc_fn, ktw_free_fn free_fn, void *alloc_ctx, ktw_buf_t **out_buf);
KTW_API void ktw_buf_destroy(ktw_buf_t *buf);
KTW_API int ktw_buf_append(ktw_buf_t *buf, const unsigned char *data, size_t data_len);
KTW_API size_t ktw_buf_len(const ktw_buf_t *buf);
KTW_API const unsigned char *ktw_buf_data(const ktw_buf_t *buf);
KTW_API int ktw_buf_split(const ktw_buf_t *buf, unsigned char sep, ktw_piece_fn piece_fn, void *piece_ctx);
KTW_API const char *ktw_strerror(int status);

#ifdef __cplusplus
}
#endif

#endif
