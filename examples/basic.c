#include <keytrawl/keytrawl.h>

#include <stdio.h>
#include <string.h>

static int print_finding(void *ctx, const ktw_finding_t *f)
{
    (void)ctx;
    printf("%s at %llu: %s\n", ktw_finding_name(f), (unsigned long long)ktw_finding_offset(f),
           ktw_finding_evidence(f));
    return 0;
}

int main(void)
{
    static const char data[] = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n";
    ktw_catalog_t *catalog = NULL;
    ktw_scanner_t *scanner = NULL;
    int status;

    status = ktw_catalog_create(KTW_GROUP_ALL, NULL, NULL, NULL, &catalog);
    if (status == KTW_OK)
        status = ktw_catalog_compile(catalog);
    if (status == KTW_OK)
        status = ktw_scanner_create(catalog, NULL, NULL, NULL, &scanner);
    if (status == KTW_OK)
        status = ktw_feed(scanner, (const unsigned char *)data, strlen(data), print_finding, NULL);
    if (status == KTW_OK)
        status = ktw_finish(scanner, print_finding, NULL);
    ktw_scanner_destroy(scanner);
    ktw_catalog_destroy(catalog);
    if (status != KTW_OK) {
        fprintf(stderr, "error: %s\n", ktw_strerror(status));
        return 1;
    }
    return 0;
}
