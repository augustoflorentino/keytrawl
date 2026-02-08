#define KTW_IMPLEMENTATION
#include "keytrawl/keytrawl.h"

static int count_piece(void *ctx, const unsigned char *piece, size_t piece_len)
{
    (void)piece;
    (void)piece_len;
    (*(int *)ctx)++;
    return 0;
}

int main(void)
{
    ktw_buf_t *buf = NULL;
    int pieces = 0;
    int status;

    status = ktw_buf_create(NULL, NULL, NULL, &buf);
    if (status == KTW_OK)
        status = ktw_buf_append(buf, (const unsigned char *)"a\nb", 3);
    if (status == KTW_OK)
        status = ktw_buf_split(buf, '\n', count_piece, &pieces);
    if (ktw_buf_len(buf) != 3 || ktw_buf_data(buf) == NULL || ktw_strerror(status) == NULL)
        status = KTW_ERR_ARG;
    ktw_buf_destroy(buf);
    return status == KTW_OK && pieces == 2 ? 0 : 1;
}
