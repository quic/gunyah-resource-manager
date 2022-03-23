// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <rm-rpc.h>

#include <resource-manager.h>

#include <log.h>
#include <unistd.h>
#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/vector.h>
#include <vm_config.h>
#include <vm_creation.h>
#include <vm_mgnt.h>

#define TIOCSETBUF 0x547f // Non-standard IOCTL!!

#if ((LOG_AREA_ALIGN - 1) & LOG_AREA_ALIGN) != 0
#error LOG_AREA_ALIGN must be a power of 2
#endif

// Our non-standard buffer control message
struct tty_set_buffer_req {
	uintptr_t buffer;
	size_t	  size;
};

static char *rm_log_area;

rm_error_t
log_reconfigure(uintptr_t *log_buf, size_t size)
{
	rm_error_t ret = RM_OK;

	assert(log_buf != NULL);
	assert(size >= 256);

	// Allocate a new buffer
	rm_log_area = aligned_alloc(LOG_AREA_ALIGN, size);
	if (rm_log_area != NULL) {
		memset(rm_log_area, 0, size);

		struct tty_set_buffer_req req = { (uintptr_t)rm_log_area,
						  LOG_AREA_SIZE };

		int result =
			ioctl(STDOUT_FILENO, TIOCSETBUF, (unsigned long)&req);
		if (result != 0) {
			ret = RM_ERROR_NORESOURCE;
		}

		*log_buf = (uintptr_t)rm_log_area;
	}

	return ret;
}

rm_error_t
log_expose_to_hlos(uintptr_t log_buf, size_t size)
{
	rm_error_t ret = RM_OK;

	assert(size >= 256);

	// need size aligned to page size for map
	assert(util_is_baligned(size, PAGE_SIZE));

	vm_t *hlos = vm_lookup(VMID_HLOS);
	assert(hlos != NULL);

	paddr_t paddr = rm_ipa_to_pa(log_buf);

	// assume it's always 1:1 mapping
	assert(paddr == log_buf);
	vmaddr_t ipa = paddr;

	// NOTE: assume it's safe to do 1:1 mapping for HLOS
	error_t map_ret = hlos_map_memory(paddr, ipa, size, PGTABLE_ACCESS_R,
					  PGTABLE_VM_MEMTYPE_NORMAL_WB);
	if (map_ret != OK) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

out:
	return ret;
}
