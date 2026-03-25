// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
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

#include <event.h>
#include <guest_interface.h>
#include <heap_mgnt.h>
#include <log.h>
#include <mem_region.h>
#include <memextent.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <unistd.h>
#include <vm_memory.h>
#include <vm_mgnt.h>

#define TIOCSETBUF 0x547f // Non-standard IOCTL!!

#define RM_GET_LOG_ID_RM_LOG 0U

// Our non-standard buffer control message
struct tty_set_buffer_req {
	uintptr_t buffer;
	size_t	  size;
};

static char  *rm_log_area;
static size_t rm_log_size;

bool
log_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num, void *buf,
		size_t len)
{
	bool		  handled = false;
	rm_error_t	  err	  = RM_OK;
	rm_get_log_req_t *req	  = (rm_get_log_req_t *)buf;

	if (msg_id != GET_LOG) {
		err = RM_ERROR_DENIED;
		goto skip;
	}

	if (len != sizeof(*req)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	if (req->log_id != RM_GET_LOG_ID_RM_LOG) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (client_id != VMID_HLOS) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	if (!platform_expose_log_to_hlos()) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	rm_get_log_resp_t resp = { .addr = (uint64_t)rm_log_area,
				   .size = rm_log_size };

	rm_reply(client_id, msg_id, seq_num, &resp, sizeof(resp));
	handled = true;

out:
	if (!handled) {
		rm_standard_reply(client_id, msg_id, seq_num, err);
	}
skip:
	return handled;
}

rm_error_t
log_reconfigure(uintptr_t *log_buf, size_t size)
{
	rm_error_t ret = RM_OK;

	assert(log_buf != NULL);
	assert(util_is_baligned(size, PAGE_SIZE));

	// Allocate a new buffer
	rm_log_area = util_alloc_pages(size);
	rm_log_size = size;
	if (rm_log_area != NULL) {
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

	assert(size >= 256U);

	// need size aligned to page size for map
	assert(util_is_baligned(size, PAGE_SIZE));

	vm_t *hlos = vm_lookup(VMID_HLOS);
	assert(hlos != NULL);

	heap_lookup_me_ret_t lookup_ret = heap_mgnt_lookup_rm_me(log_buf);
	assert(lookup_ret.err == OK);

	// Map 1:1 in HLOS.
	paddr_t	 paddr = lookup_ret.phys;
	vmaddr_t ipa   = paddr;

	vm_address_range_result_t as_ret =
		vm_address_range_alloc(hlos, VM_MEMUSE_BOOTINFO, ipa, paddr,
				       size, ADDRESS_RANGE_NO_ALIGNMENT);
	if (as_ret.err != OK) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	size_t	 offset = lookup_ret.offset;
	cap_id_t rm_me	= lookup_ret.me_cap;

	cap_id_result_t cap_ret = vm_memory_create_and_map(
		hlos, VM_MEMUSE_BOOTINFO, rm_me, offset, size, ipa,
		MEMEXTENT_MEMTYPE_ANY, PGTABLE_ACCESS_R,
		PGTABLE_VM_MEMTYPE_NORMAL_WB);
	if (cap_ret.e != OK) {
		error_t err = vm_address_range_free(hlos, VM_MEMUSE_BOOTINFO,
						    ipa, size);
		assert(err == OK);
		ret = RM_ERROR_DENIED;
		goto out;
	}

out:
	return ret;
}
