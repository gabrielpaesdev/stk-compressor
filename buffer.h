#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>
#include <stddef.h>


typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} ByteBuffer;

void buf_init(ByteBuffer *buf);
void buf_append(ByteBuffer *buf, const void *data, size_t len);
void buf_free(ByteBuffer *buf);

#endif // BUFFER_H
