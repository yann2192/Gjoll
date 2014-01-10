#include "../src/buf.h"

uv_buf_t gjoll_to_uv(gjoll_buf_t buf)
{
    return (uv_buf_t){buf.data, buf.len};
}

gjoll_buf_t uv_to_gjoll(uv_buf_t buf)
{
    return (gjoll_buf_t){buf.base, buf.len};
}
