// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <rm_types.h>
#include <utils/address_range_allocator.h>
#include <utils/vector.h>

#include <event.h>
#include <log.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_ipa.h>
#include <vm_ipa_message.h>
#include <vm_memory.h>
#include <vm_mgnt.h>

#define MAX_LIST_ENTRIES 30U

static rm_error_t
reserve_alloc_list(vm_t *vm, ipa_reserve_req_alloc_list_t *list,
		   uint32_t entries, address_range_tag_t tag,
		   ipa_reserve_alloc_resp_t **resp, size_t *size)
{
	rm_error_t err = RM_OK;

	*size = sizeof(ipa_reserve_alloc_resp_t) + entries * sizeof(vmaddr_t);
	*resp = calloc(1U, *size);
	if (*resp == NULL) {
		LOG_LOC("alloc");
		err = RM_ERROR_NOMEM;
		goto out;
	}

	uintptr_t curr		= (uintptr_t)*resp;
	uintptr_t ipa_list_addr = curr + sizeof(ipa_reserve_alloc_resp_t);

	vmaddr_t *ipa_list = (vmaddr_t *)ipa_list_addr;

	uint32_t i = 0;
	for (i = 0; i < entries; i++) {
		vmaddr_t region_base = list[i].region_base;
		size_t	 region_size = list[i].region_size;
		size_t	 ipa_size    = list[i].size;
		size_t	 alignment   = list[i].alignment;

		vm_address_range_result_t tag_ret = vm_address_range_tag_any(
			vm, region_base, region_size, ipa_size, alignment, tag);
		if (tag_ret.err != OK) {
			LOG_ERR(tag_ret.err);
			err = RM_ERROR_DENIED;
			break;
		} else {
			ipa_list[i] = tag_ret.base;
		}
	}

	(*resp)->reserved_entires = entries;

	if (err != RM_OK) {
		for (; i > 0; i--) {
			vmaddr_t base	  = ipa_list[i - 1];
			size_t	 ipa_size = list[i - 1].size;
			error_t	 vm_err =
				vm_address_range_untag(vm, base, ipa_size, tag);
			assert(vm_err == OK);
		}
	}
out:
	return err;
}

static rm_error_t
reserve_fixed_list(vm_t *vm, ipa_reserve_req_fixed_list_t *list,
		   uint32_t entries, address_range_tag_t tag)
{
	rm_error_t err = RM_OK;

	uint32_t i = 0;
	for (i = 0; i < entries; ++i) {
		vmaddr_t base = list[i].base;
		size_t	 size = list[i].size;

		error_t tag_ret = vm_address_range_tag(vm, base, size, tag);
		if (tag_ret != OK) {
			LOG_ERR(tag_ret);
			err = RM_ERROR_DENIED;
			break;
		}
	}

	if (err != RM_OK) {
		while (i > 0) {
			vmaddr_t base = list[i - 1].base;
			size_t	 size = list[i - 1].size;
			error_t	 vm_err =
				vm_address_range_untag(vm, base, size, tag);
			assert(vm_err == OK);
		}
	}

	return err;
}

static void
reserve_ipa(vmid_t vmid, uint16_t seq_num, uint8_t *buf, size_t len)
{
	rm_error_t err;

	vm_t *vm = vm_lookup(vmid);
	assert(vm != NULL);

	if (vm->as_allocator == NULL) {
		LOG_LOC("no ipa allocator");
		err = RM_ERROR_DENIED;
		goto failed;
	}

	if (len < sizeof(ipa_reserve_req_t)) {
		LOG_LOC("short msg");
		err = RM_ERROR_MSG_INVALID;
		goto failed;
	}

	ipa_reserve_req_t *req = (ipa_reserve_req_t *)(uintptr_t)buf;

	ipa_reserve_req_type_t alloc_type = req->alloc_type;
	if ((alloc_type != IPA_RESERVE_REQ_ALLOC_LIST) &&
	    (alloc_type != IPA_RESERVE_REQ_FIXED_LIST)) {
		LOG_LOC("inv msg");
		err = RM_ERROR_MSG_INVALID;
		goto failed;
	}

	uint32_t generic_constraints  = req->generic_constraints;
	uint32_t platform_constraints = req->platform_constraints;

	address_range_tag_t ipa_tag = vm_memory_constraints_to_tag(
		vm, generic_constraints, platform_constraints);
	if (ipa_tag == ADDRESS_RANGE_NO_TAG) {
		LOG_LOC("constraints");
		LOG("%x, %x\n", generic_constraints, platform_constraints);
		err = RM_ERROR_ARGUMENT_INVALID;
		goto failed;
	}

	uint16_t  entries      = 0U;
	uintptr_t list_address = 0UL;
	uint8_t	 *next_buf     = NULL;

	size_t element_size = 0UL;
	if (alloc_type == IPA_RESERVE_REQ_FIXED_LIST) {
		element_size = sizeof(ipa_reserve_req_fixed_list_t);
	} else {
		// alloc_type == IPA_RESERVE_REQ_ALLOC_LIST
		element_size = sizeof(ipa_reserve_req_alloc_list_t);
	}

	size_t list_offset = offsetof(ipa_reserve_req_t, entries);
	err = rm_rpc_read_list(buf + list_offset, len - list_offset, &entries,
			       MAX_LIST_ENTRIES, &list_address, element_size,
			       &next_buf);
	if (err != RM_OK) {
		LOG_LOC("bad list");
		goto failed;
	}

	if (len != (size_t)(next_buf - buf)) {
		LOG_LOC("bad msg len");
		err = RM_ERROR_MSG_INVALID;
		goto failed;
	}

	ipa_reserve_alloc_resp_t *resp	    = NULL;
	size_t			  resp_size = 0UL;

	// reserve ipa ranges
	if (alloc_type == IPA_RESERVE_REQ_FIXED_LIST) {
		err = reserve_fixed_list(
			vm, (ipa_reserve_req_fixed_list_t *)list_address,
			entries, ipa_tag);
	} else {
		// alloc_type == IPA_RESERVE_REQ_ALLOC_LIST
		err = reserve_alloc_list(
			vm, (ipa_reserve_req_alloc_list_t *)list_address,
			entries, ipa_tag, &resp, &resp_size);
	}

	if (err != RM_OK) {
		goto failed;
	}

	rm_reply(vmid, IPA_RESERVE, seq_num, resp, resp_size);
	goto out;

failed:
	LOG("%s: err=%d\n", __func__, err);
	rm_standard_reply(vmid, IPA_RESERVE, seq_num, err);

out:
	return;
}

bool
vm_ipa_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		   void *buf, size_t len)
{
	bool handled = true;

	switch (msg_id) {
	case IPA_RESERVE:
		reserve_ipa(client_id, seq_num, buf, len);
		break;
	case IPA_UNRESERVE:
		LOG_LOC("IPA_UNRESERVE");
		handled = false;
		break;
	default:
		handled = false;
		break;
	}

	return handled;
}
