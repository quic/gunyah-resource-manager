// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <util.h>

#include <errno.h>

static bool no_sys_mmap = false;

size_t
memscpy(void *s1, size_t s1_size, const void *s2, size_t s2_size)
{
	size_t copy_size = util_min(s1_size, s2_size);
	if (copy_size != (size_t)0) {
		(void)memcpy(s1, s2, copy_size);
	}
	return copy_size;
}

void *
util_alloc_pages(size_t size)
{
	void *ret;

	assert(util_is_baligned(size, PAGE_SIZE));

	if (!no_sys_mmap) {
		ret = mmap(NULL, size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (ret != MAP_FAILED) {
			goto out;
		} else if (errno == ENOSYS) {
			no_sys_mmap = true;
		} else {
			ret = NULL;
			goto out;
		}
	}

	ret = aligned_alloc(PAGE_SIZE, size);
	if (ret == NULL) {
		goto out;
	}

	(void)memset(ret, 0, size);

out:
	return ret;
}

void
util_free_pages(void *ptr, size_t size)
{
	assert(ptr != NULL);
	assert(util_is_baligned(size, PAGE_SIZE));

	if (!no_sys_mmap) {
		int ret = munmap(ptr, size);
		assert(ret == 0);
	} else {
		free(ptr);
	}
}
