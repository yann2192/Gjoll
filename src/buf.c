#include "../src/buf.h"

gjoll_buf_t gjoll_buf_init(void* data, size_t len) {
    gjoll_buf_t buf;
    buf.data = data;
    buf.len = len;
    return buf;
}

void gjoll_free_buf(gjoll_buf_t* buf) {
    if(buf->data != NULL) {
        free(buf->data);
        buf->data = NULL;
    }
    buf->len = 0;
}

uv_buf_t gjoll_to_uv(gjoll_buf_t buf)
{
    return (uv_buf_t){buf.data, buf.len};
}

gjoll_buf_t uv_to_gjoll(uv_buf_t buf)
{
    return (gjoll_buf_t){buf.base, buf.len};
}
