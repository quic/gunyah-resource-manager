// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

struct cbuf;
typedef struct cbuf cbuf_t;

cbuf_t *
cbuf_init(size_t capacity);

// Write write_len bytes from data into the circular buffer. If the write_len
// is larger than the buffer, then the write head will overwrite the tail and
// only the last <buffer size> will remain.
size_t
cbuf_write(cbuf_t *cbuf, const void *data, size_t write_len);

// Read up to read_len bytes from data into the output buffer. Returns the
// number of bytes read.
size_t
cbuf_read(cbuf_t *cbuf, void *output, size_t read_len);

// Returns the amount of data currently in the circular buffer.
size_t
cbuf_used(cbuf_t *cbuf);

// Returns the amount of space available in the circular buffer before
// overwrites will occur.
size_t
cbuf_available(cbuf_t *cbuf);

void
cbuf_deinit(cbuf_t *cbuf);
