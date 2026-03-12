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
static size_t held, allocations;

static void *counting_alloc(void *ctx, size_t size)
{
    (void)ctx;
    held += size;
    allocations++;
    return malloc(size);
}

static void counting_free(void *ctx, void *ptr)
{
    (void)ctx;
    free(ptr);
}

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

static double cpu_now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
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
    double cpu;
} job_t;

static void *worker(void *arg)
{
    job_t *j = arg;
    double t = cpu_now();

    scan(j->data, j->len);
    j->cpu = cpu_now() - t;
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

static double single_cpu;

static double single(const unsigned char *data, size_t len)
{
    double t = now(), c = cpu_now(), mbs;
    unsigned long found = scan(data, len);

    single_cpu = (double)len / MB / (cpu_now() - c);
    mbs = (double)len / MB / (now() - t);
    printf("single   %.0f MB/s over %.0f MB, %lu findings (%.0f MB/s by CPU time)\n", mbs, (double)len / MB, found,
           single_cpu);
    return mbs;
}

static void threads(const unsigned char *data, size_t len, double one)
{
    double cpu = 0;

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
    for (i = 0; i < THREADS; i++)
        cpu += (double)len / MB / jobs[i].cpu;
    printf("threads  %.0f MB/s with %d threads, %.2fx one thread; %.2fx by CPU time\n", mbs, THREADS, mbs / one,
           cpu / single_cpu);
}

static double begins(size_t len)
{
    static unsigned char block[CHUNK];
    ktw_scanner_t *s = NULL;
    unsigned long found = 0;
    size_t i, at;
    size_t before;
    double t;

    for (i = 0; i < CHUNK; i++)
        block[i] = (unsigned char)"-----BEGIN "[i % 11];
    held = allocations = 0;
    if (ktw_scanner_create(catalog, counting_alloc, counting_free, NULL, &s) != KTW_OK)
        exit(1);
    before = allocations;
    t = now();
    for (at = 0; at < len; at += CHUNK)
        if (ktw_feed(s, block, CHUNK, count, &found) != KTW_OK)
            exit(1);
    ktw_finish(s, count, &found);
    t = now() - t;
    allocations -= before;
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
    printf("begin    %.2f s for 256 MB, %.2f s for 1 GB, ratio %.2f; scanner holds %zu bytes, %zu allocations "
           "while scanning\n",
           small, big, big / small, held, allocations);
    free(data);
    ktw_catalog_destroy(c);
    return 0;
}
