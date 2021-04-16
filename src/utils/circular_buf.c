// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <utils/circular_buf.h>

struct cbuf {
	size_t capacity;

	// the index we can start reading
	index_t read_idx;
	// the index we can start writing
	index_t write_idx;

	uint8_t *data;
};

cbuf_t *
cbuf_init(size_t capacity)
{
	cbuf_t *ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		goto err;
	}

	ret->capacity = capacity;

	ret->read_idx  = 0U;
	ret->write_idx = 0U;

	ret->data = malloc(capacity);
	if (ret->data == NULL) {
		goto err1;
	}

	return ret;
err1:
	free(ret);
err:
	return NULL;
}

size_t
cbuf_write(cbuf_t *cbuf, const void *data, size_t data_len)
{
	const uint8_t *start	 = (const uint8_t *)data;
	size_t	       write_len = data_len;

	// check if whole buffer fits the data
	// NOTE: only writes the part which would not be overwriten. Check if
	// it's expected behavior.
	if (write_len > cbuf->capacity) {
		// if not, adjust data and write_len
		size_t offset = write_len - cbuf->capacity;
		start += offset;
		write_len = cbuf->capacity;
	}

	// check if overwrite occurs
	size_t remaining_sz =
		cbuf->read_idx < cbuf->write_idx
			? cbuf->capacity - (cbuf->write_idx - cbuf->read_idx)
			: cbuf->read_idx - cbuf->write_idx;
	// if so, mark it, set read idx after write_idx + 1 before return
	bool overwriten = remaining_sz < write_len;

	// check if remaining space (to the end of buf) fits the data
	size_t sz_to_buf_end = cbuf->capacity - cbuf->write_idx;
	if (sz_to_buf_end >= write_len) {
		// if so, write to the remaining space
		memcpy(cbuf->data + cbuf->write_idx, start, write_len);

		cbuf->write_idx += write_len;
	} else {
		// if not, write first part to the remaining space
		memcpy(cbuf->data + cbuf->write_idx, start, sz_to_buf_end);

		// write the second part to the wrap space
		size_t rest = write_len - sz_to_buf_end;
		memcpy(cbuf->data, start + sz_to_buf_end, rest);

		cbuf->write_idx = (index_t)rest;
	}

	// set read idx base on if overwrite
	if (overwriten) {
		cbuf->read_idx = cbuf->write_idx;
	}

	return write_len;
}

size_t
cbuf_read(cbuf_t *cbuf, void *output, size_t output_len)
{
	uint8_t *start	  = (uint8_t *)output;
	size_t	 read_len = output_len;

	// check if need output more than the size of content in buf
	size_t content_sz = cbuf_used(cbuf);
	// NOTE: can only reads no more than existing bytes.
	if (read_len > content_sz) {
		read_len = content_sz;
	}

	// check if need to wrap the buffer
	size_t sz_to_buf_end = cbuf->capacity - cbuf->read_idx;
	if (sz_to_buf_end >= read_len) {
		// if not, read to buffer
		memcpy(output, start + cbuf->read_idx, read_len);

		cbuf->read_idx += read_len;
	} else {
		// if so, read the fist part to the end of the buf
		memcpy(start, cbuf->data + cbuf->read_idx, sz_to_buf_end);

		// read the seconf part from the start of the buf
		size_t rest = read_len - sz_to_buf_end;
		memcpy(start + sz_to_buf_end, cbuf->data, rest);

		cbuf->read_idx = (index_t)rest;
	}

	return read_len;
}

size_t
cbuf_used(cbuf_t *cbuf)
{
	return cbuf->read_idx < cbuf->write_idx
		       ? cbuf->write_idx - cbuf->read_idx
		       : cbuf->capacity - (cbuf->read_idx - cbuf->write_idx);
}

size_t
cbuf_available(cbuf_t *cbuf)
{
	return cbuf->capacity - cbuf_used(cbuf);
}

void
cbuf_deinit(cbuf_t *cbuf)
{
	if (cbuf->data != NULL) {
		free(cbuf->data);
	}

	free(cbuf);
}
