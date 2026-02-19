#include <keytrawl/keytrawl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *file;
    int all;
    unsigned long count;
} report_t;

static const char *confidence_name(int confidence)
{
    switch (confidence) {
    case KTW_CONFIRMED:
        return "confirmed";
    case KTW_LIKELY:
        return "likely";
    default:
        return "indicator";
    }
}

static int print_finding(void *ctx, const ktw_finding_t *f)
{
    report_t *r = ctx;

    if (!r->all && ktw_finding_confidence(f) == KTW_INDICATOR)
        return 0;
    r->count++;
    printf("%s\t%llu\t%llu\t%llu\t%s\t%s\t%s\t%s\n", r->file, (unsigned long long)ktw_finding_offset(f),
           (unsigned long long)ktw_finding_length(f), (unsigned long long)ktw_finding_line(f),
           ktw_finding_name(f), confidence_name(ktw_finding_confidence(f)),
           ktw_algorithm_name(ktw_finding_algorithm(f)), ktw_finding_evidence(f));
    return 0;
}

static int scan_stream(ktw_scanner_t *scanner, FILE *in, unsigned char *buf, size_t chunk, report_t *r)
{
    size_t got;
    int status = ktw_scanner_reset(scanner, r->file, strlen(r->file));

    while (status == KTW_OK && (got = fread(buf, 1, chunk, in)) > 0)
        status = ktw_feed(scanner, buf, got, print_finding, r);
    if (status == KTW_OK && ferror(in)) {
        fprintf(stderr, "keytrawl: %s: read error\n", r->file);
        return 1;
    }
    if (status == KTW_OK)
        status = ktw_finish(scanner, print_finding, r);
    if (status != KTW_OK) {
        fprintf(stderr, "keytrawl: %s: %s\n", r->file, ktw_strerror(status));
        return 1;
    }
    if (ktw_scanner_dropped(scanner) > 0)
        fprintf(stderr, "keytrawl: %s: %llu candidates dropped\n", r->file,
                (unsigned long long)ktw_scanner_dropped(scanner));
    return 0;
}

static int scan_path(ktw_scanner_t *scanner, const char *path, unsigned char *buf, size_t chunk, report_t *r)
{
    FILE *in = strcmp(path, "-") == 0 ? stdin : fopen(path, "rb");
    int failed;

    if (in == NULL) {
        perror(path);
        return 1;
    }
    r->file = path;
    failed = scan_stream(scanner, in, buf, chunk, r);
    if (in != stdin)
        fclose(in);
    return failed;
}

static int usage(void)
{
    fprintf(stderr, "usage: keytrawl [-c chunk] [-a] [file...]\n");
    return 2;
}

int main(int argc, char **argv)
{
    static char *stdin_only[] = {"-"};
    ktw_catalog_t *catalog = NULL;
    ktw_scanner_t *scanner = NULL;
    report_t report = {NULL, 0, 0};
    unsigned char *buf;
    size_t chunk = 65536;
    int i = 1, failed = 0, status;

    for (; i < argc && argv[i][0] == '-' && argv[i][1] != '\0'; i++) {
        if (strcmp(argv[i], "-a") == 0)
            report.all = 1;
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc && atol(argv[i + 1]) > 0)
            chunk = (size_t)atol(argv[++i]);
        else
            return usage();
    }
    if (i == argc) {
        argv = stdin_only;
        argc = 1;
        i = 0;
    }
    status = ktw_catalog_create(KTW_GROUP_ALL, NULL, NULL, NULL, &catalog);
    if (status == KTW_OK)
        status = ktw_catalog_compile(catalog);
    if (status == KTW_OK)
        status = ktw_scanner_create(catalog, NULL, NULL, NULL, &scanner);
    buf = malloc(chunk);
    if (status != KTW_OK || buf == NULL) {
        fprintf(stderr, "keytrawl: %s\n", ktw_strerror(status == KTW_OK ? KTW_ERR_NOMEM : status));
        failed = 1;
    }
    for (; status == KTW_OK && buf != NULL && i < argc; i++)
        failed |= scan_path(scanner, argv[i], buf, chunk, &report);
    free(buf);
    ktw_scanner_destroy(scanner);
    ktw_catalog_destroy(catalog);
    return failed ? 1 : report.count > 0 ? 3 : 0;
}
