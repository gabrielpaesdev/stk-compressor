#include "buffer.h"
#include <stdlib.h>
#include <string.h>

void buf_init(ByteBuffer *buf) {
    buf->capacity = 1024;
    buf->size = 0;
    buf->data = malloc(buf->capacity);
}

void buf_append(ByteBuffer *buf, const void *data, size_t len) {
    if (buf->size + len > buf->capacity) {
        buf->capacity = (buf->size + len) * 2;
        buf->data = realloc(buf->data, buf->capacity);
    }
    memcpy(buf->data + buf->size, data, len);
    buf->size += len;
}

void buf_free(ByteBuffer *buf) {
    free(buf->data);
}
