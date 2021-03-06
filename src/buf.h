#ifndef GJOLL_BUF_H
#define GJOLL_BUF_H

#include "gjoll.h"
#include "uv.h"

gjoll_buf_t gjoll_buf_init(void* data, size_t len);
void gjoll_buf_free(gjoll_buf_t* buf);

uv_buf_t gjoll_to_uv(gjoll_buf_t buf);
gjoll_buf_t uv_to_gjoll(uv_buf_t buf);

#endif
