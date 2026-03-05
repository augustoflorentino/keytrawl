#define _POSIX_C_SOURCE 200809L

#include <keytrawl/keytrawl.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MB (1024.0 * 1024.0)
#define INPUT_SIZE ((size_t)256 << 20)
#define CHUNK ((size_t)1 << 20)
#define THREADS 4

static const ktw_catalog_t *catalog;

static double now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int count(void *ctx, const ktw_finding_t *f)
{
    (void)f;
    ++*(unsigned long *)ctx;
    return 0;
}

static unsigned long scan(const unsigned char *data, size_t len)
{
    ktw_scanner_t *s = NULL;
    unsigned long found = 0;
    size_t at;

    if (ktw_scanner_create(catalog, NULL, NULL, NULL, &s) != KTW_OK) {
        fprintf(stderr, "bench: scanner_create failed\n");
        exit(1);
    }
    for (at = 0; at < len; at += CHUNK)
        if (ktw_feed(s, data + at, len - at < CHUNK ? len - at : CHUNK, count, &found) != KTW_OK)
            exit(1);
    if (ktw_finish(s, count, &found) != KTW_OK)
        exit(1);
    ktw_scanner_destroy(s);
    return found;
}

typedef struct {
    const unsigned char *data;
    size_t len;
} job_t;

static void *worker(void *arg)
{
    job_t *j = arg;

    scan(j->data, j->len);
    return NULL;
}

static unsigned char *load(const char *path, size_t *len)
{
    unsigned char *buf = malloc(INPUT_SIZE);
    size_t n = 0, got;
    unsigned x = 2463534242u;

    if (buf == NULL)
        return NULL;
    if (path == NULL) {
        for (; n < INPUT_SIZE; n++) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            buf[n] = (x & 0xF00) == 0 ? (unsigned char)(' ' + (x >> 16) % 95) : (unsigned char)(x >> 24);
        }
    }
    while (path != NULL && n < INPUT_SIZE) {
        FILE *f = fopen(path, "rb");

        if (f == NULL)
            break;
        while (n < INPUT_SIZE && (got = fread(buf + n, 1, INPUT_SIZE - n, f)) > 0)
            n += got;
        fclose(f);
    }
    *len = n;
    return buf;
}

static double single(const unsigned char *data, size_t len)
{
    double t = now(), mbs;
    unsigned long found = scan(data, len);

    mbs = (double)len / MB / (now() - t);
    printf("single   %.0f MB/s over %.0f MB, %lu findings\n", mbs, (double)len / MB, found);
    return mbs;
}

static void threads(const unsigned char *data, size_t len, double one)
{
    pthread_t th[THREADS];
    job_t jobs[THREADS];
    double t = now(), mbs;
    int i;

    for (i = 0; i < THREADS; i++) {
        jobs[i].data = data;
        jobs[i].len = len;
        if (pthread_create(&th[i], NULL, worker, &jobs[i]) != 0)
            exit(1);
    }
    for (i = 0; i < THREADS; i++)
        pthread_join(th[i], NULL);
    mbs = THREADS * (double)len / MB / (now() - t);
    printf("threads  %.0f MB/s with %d threads, %.2fx one thread\n", mbs, THREADS, mbs / one);
}

static double begins(size_t len)
{
    static unsigned char block[CHUNK];
    ktw_scanner_t *s = NULL;
    unsigned long found = 0;
    size_t i, at;
    double t;

    for (i = 0; i < CHUNK; i++)
        block[i] = (unsigned char)"-----BEGIN "[i % 11];
    if (ktw_scanner_create(catalog, NULL, NULL, NULL, &s) != KTW_OK)
        exit(1);
    t = now();
    for (at = 0; at < len; at += CHUNK)
        if (ktw_feed(s, block, CHUNK, count, &found) != KTW_OK)
            exit(1);
    ktw_finish(s, count, &found);
    t = now() - t;
    ktw_scanner_destroy(s);
    return t;
}

int main(int argc, char **argv)
{
    ktw_catalog_t *c = NULL;
    size_t len = 0;
    unsigned char *data;
    double one, small, big;

    if (ktw_catalog_create(KTW_GROUP_ALL, NULL, NULL, NULL, &c) != KTW_OK || ktw_catalog_compile(c) != KTW_OK)
        return 1;
    catalog = c;
    data = load(argc > 1 ? argv[1] : NULL, &len);
    if (data == NULL || len == 0) {
        fprintf(stderr, "bench: no input\n");
        return 1;
    }
    one = single(data, len);
    threads(data, len, one);
    small = begins((size_t)256 << 20);
    big = begins((size_t)1024 << 20);
    printf("begin    %.2f s for 256 MB, %.2f s for 1 GB, ratio %.2f\n", small, big, big / small);
    free(data);
    ktw_catalog_destroy(c);
    return 0;
}
