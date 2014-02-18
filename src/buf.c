#include "../src/buf.h"

gjoll_buf_t gjoll_buf_init(void* data, size_t len) {
    gjoll_buf_t buf;
    buf.base = data;
    buf.len = len;
    return buf;
}

void gjoll_buf_free(gjoll_buf_t* buf) {
    if(buf->base != NULL) {
        free(buf->base);
        buf->base = NULL;
    }
    buf->len = 0;
}

uv_buf_t gjoll_to_uv(gjoll_buf_t buf)
{
    return (uv_buf_t){buf.base, buf.len};
}

gjoll_buf_t uv_to_gjoll(uv_buf_t buf)
{
    return (gjoll_buf_t){buf.base, buf.len};
}
