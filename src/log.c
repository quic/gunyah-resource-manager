// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <rm_types.h>
#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/vector.h>

#include <event.h>
#include <log.h>
#include <memextent.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <unistd.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_memory.h>
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
		(void)memset(rm_log_area, 0, size);

		struct tty_set_buffer_req req = { (uintptr_t)rm_log_area,
						  size };

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

	vm_address_range_result_t as_ret =
		vm_address_range_alloc(hlos, VM_MEMUSE_BOOTINFO, ipa, paddr,
				       size, ADDRESS_RANGE_NO_ALIGNMENT);
	if (as_ret.err != OK) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	size_t offset = log_buf - rm_get_me_ipa_base();

	cap_id_result_t cap_ret = vm_memory_create_and_map(
		hlos, VM_MEMUSE_BOOTINFO, rm_get_me(), offset, size, ipa,
		MEMEXTENT_MEMTYPE_ANY, PGTABLE_ACCESS_R,
		PGTABLE_VM_MEMTYPE_NORMAL_WB);
	if (cap_ret.e != OK) {
		vm_address_range_free(hlos, VM_MEMUSE_BOOTINFO, ipa, size);
		ret = RM_ERROR_DENIED;
		goto out;
	}

out:
	return ret;
}
