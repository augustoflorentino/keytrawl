#define KTW_IMPLEMENTATION
#include "keytrawl/keytrawl.h"

#include <string.h>

typedef struct {
    int count;
    int kind;
    unsigned long long offset;
} seen_t;

static int remember(void *ctx, const ktw_finding_t *f)
{
    seen_t *seen = ctx;

    seen->count++;
    seen->kind = ktw_finding_kind(f);
    seen->offset = (unsigned long long)ktw_finding_offset(f);
    return 0;
}

int main(void)
{
    static const char data[] = "token = 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\n";
    ktw_catalog_t *catalog = NULL;
    ktw_scanner_t *scanner = NULL;
    seen_t seen = {0, 0, 0};
    size_t half = sizeof data / 2;
    int status;

    status = ktw_catalog_create(KTW_GROUP_ALL, NULL, NULL, NULL, &catalog);
    if (status == KTW_OK)
        status = ktw_catalog_compile(catalog);
    if (status == KTW_OK)
        status = ktw_scanner_create(catalog, NULL, NULL, NULL, &scanner);
    if (status == KTW_OK)
        status = ktw_feed(scanner, (const unsigned char *)data, half, remember, &seen);
    if (status == KTW_OK)
        status = ktw_feed(scanner, (const unsigned char *)data + half, strlen(data) - half, remember, &seen);
    if (status == KTW_OK)
        status = ktw_finish(scanner, remember, &seen);
    ktw_scanner_destroy(scanner);
    ktw_catalog_destroy(catalog);
    if (ktw_strerror(status) == NULL)
        return 1;
    return status == KTW_OK && seen.count == 1 && seen.kind == KTW_KIND_GITHUB_TOKEN && seen.offset == 8 ? 0 : 1;
}
