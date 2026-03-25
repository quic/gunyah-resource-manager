// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

// This file contains code which is not platform-specifc; these generic
// components should be moved so they can be used across platforms.
// FIXME: QC RM issue #19

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <rm_types.h>
#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/vector.h>

#include <event.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <mem_region.h>
#include <memextent.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <platform_vm_memory.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_ipa_message.h>
#include <vm_memory.h>
#include <vm_mgnt.h>

error_t
vm_memory_register_mem_acl(cap_id_t me_cap, size_t acl_entries,
			   const mem_acl_t *mem_acl)
{
	(void)me_cap;
	(void)acl_entries;
	(void)mem_acl;
	return OK;
}

vm_acl_info_result_t
vm_memory_get_acl_info(vm_t *vm, uint8_t mem_type, cap_id_t mp_me_cap,
		       uint8_t trans_type, acl_entry_t *acl,
		       uint32_t acl_entries, bool vm_init)
{
	(void)mem_type;
	(void)mp_me_cap;
	(void)trans_type;
	(void)acl;
	(void)acl_entries;
	(void)vm_init;
	(void)vm;

	return (vm_acl_info_result_t){ .err = OK };
}

bool
vm_memory_acl_can_map_exclusive(const vm_acl_info_t *acl_info)
{
	(void)acl_info;
	return true;
}

bool
vm_memory_handled_by_platform(vm_t *vm, vm_memuse_t memuse)
{
	(void)vm;
	(void)memuse;
	return false;
}

size_t
vm_memory_get_platform_addr_limit(void)
{
	return ADDR_LIMIT;
}

cap_id_t
vm_memory_get_platform_device_cap_override(void)
{
	return CSPACE_CAP_INVALID;
}

error_t
vm_memory_init_platform(const rm_env_data_t *env_data)
{
	(void)env_data;
	return OK;
}

cap_id_t
vm_memory_get_platform_parent_ddr_me_override(void)
{
	return CSPACE_CAP_INVALID;
}

bool
vm_memory_setup_platform_me_override(vm_t *vm)
{
	(void)vm;
	return false;
}

bool
vm_memory_get_source_extent_platform_override(const vm_t *vm, uint8_t mem_type,
					      acl_entry_t *acl,
					      uint32_t	   acl_entries,
					      cap_id_t	  *me_cap)
{
	(void)vm;
	(void)mem_type;
	(void)acl;
	(void)acl_entries;
	(void)me_cap;
	return false;
}

bool
vm_memory_donate_extent_platform_override(vm_t *vm, uint8_t mem_type,
					  vm_acl_info_t *acl_info,
					  cap_id_t mp_me_cap, paddr_t phys,
					  size_t size, bool to_mp, error_t *err,
					  cap_id_t *owner_me_cap_out)
{
	(void)vm;
	(void)mem_type;
	(void)acl_info;
	(void)mp_me_cap;
	(void)phys;
	(void)size;
	(void)to_mp;
	(void)err;
	(void)owner_me_cap_out;
	return false;
}

void
vm_memory_apply_platform_constraints_to_tag(uint32_t platform_constraints,
					    address_range_tag_t *tag)
{
	switch (platform_constraints) {
	case IPA_PLATFORM_CONSTRAINT_NONE:
		break;
	default:
		// Invalid platform constraints.
		*tag = ADDRESS_RANGE_NO_TAG;
		break;
	}
}

void
vm_memory_apply_platform_phys_address_rags(paddr_t phys, size_t size,
					   address_range_tag_t *tag)
{
	(void)phys;
	(void)size;
	(void)tag;
}
