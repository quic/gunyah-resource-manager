// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <asm/arm_smccc.h>

#include <rm_types.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#include <libfdt.h>

#pragma clang diagnostic pop

#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/list.h>
#include <utils/vector.h>

#include <dtb_parser.h>
#include <event.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <log.h>
#include <memextent.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_client.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_console.h>
#include <vm_creation.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_vcpu.h>

rm_error_t
vm_creation_config_image(vm_t *vm, vm_auth_type_t auth,
			 resource_handle_t image_mp_handle,
			 uint64_t image_offset, uint64_t image_size,
			 uint64_t dt_offset, uint64_t dt_size)
{
	rm_error_t rm_err = RM_OK;

	assert((vm != NULL) && vm_mgnt_state_change_valid(vm, VM_STATE_AUTH));

	cap_id_t rm_partition_cap = rm_get_rm_partition();
	cap_id_t rm_cspace_cap	  = rm_get_rm_cspace();

	// Validate and store the arguments. Note that not all auth types make
	// use of all of these, e.g. unauthenticated images ignore the image
	// size, but we still require them to be valid ranges.
	memparcel_t *image_mp =
		memparcel_lookup_by_target_vmid(vm->vmid, image_mp_handle);
	if (image_mp == NULL) {
		(void)printf("Error: vm %d failed to look up memparcel %d\n",
			     vm->vmid, image_mp_handle);
		rm_err = RM_ERROR_MEM_INVALID;
		goto out;
	}
	vm->mem_mp_handle = image_mp_handle;
	vm->mem_size	  = memparcel_get_size(image_mp);
	vm->mem_base_tag  = ADDRESS_RANGE_NO_TAG;

	count_t num_regions = memparcel_get_num_regions(image_mp);
	for (index_t i = 0U; i < num_regions; i++) {
		paddr_result_t pret = memparcel_get_phys(image_mp, i);
		assert(pret.e == OK);
		size_result_t sret = memparcel_get_region_size(image_mp, i);
		assert(sret.e == OK);

		address_range_tag_t tag =
			vm_memory_get_phys_address_tag(pret.r, sret.r);
		vm->mem_base_tag = (i == 0U) ? tag : (tag & vm->mem_base_tag);
	}

	if (vm->mem_base_tag == ADDRESS_RANGE_NO_TAG) {
		(void)printf("Error: invalid base tag for vm %d mp %d\n",
			     vm->vmid, image_mp_handle);
		rm_err = RM_ERROR_MEM_INVALID;
		goto out;
	}

	if (util_add_overflows(image_offset, image_size) ||
	    ((image_offset + image_size) > vm->mem_size) ||
	    util_add_overflows(dt_offset, dt_size) ||
	    ((dt_offset + dt_size) > vm->mem_size)) {
		(void)printf(
			"Error: vm %d image ranges are invalid: image %#zx+%#zx,"
			" DT %#zx+%#zx, mem size %#zx\n",
			vm->vmid, image_offset, image_size, dt_offset, dt_size,
			vm->mem_size);
		rm_err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	vm->image_offset = image_offset;
	vm->image_size	 = image_size;
	vm->dt_offset	 = dt_offset;
	vm->dt_size	 = dt_size;

	// Default entry point is the start of the image, unless overridden
	// later by auth-type-specific code
	vm->entry_offset = image_offset;

	// Create new cspace
	gunyah_hyp_partition_create_cspace_result_t cs;
	cs = gunyah_hyp_partition_create_cspace(rm_partition_cap,
						rm_cspace_cap);
	if (cs.error != OK) {
		(void)printf(
			"Error: vm %d failed to create cspace, error %" PRId32
			"\n",
			vm->vmid, (int32_t)cs.error);
		rm_err = rm_error_from_hyp(cs.error);
		goto out;
	}

	error_t err = gunyah_hyp_cspace_configure(cs.new_cap, MAX_CAPS);
	if (err != OK) {
		(void)printf(
			"Error: vm %d failed to configure cspace, error %" PRId32
			"\n",
			vm->vmid, (int32_t)err);
		rm_err = rm_error_from_hyp(err);
		goto out_destroy_cspace;
	}

	err = gunyah_hyp_object_activate(cs.new_cap);
	if (err != OK) {
		(void)printf(
			"Error: vm %d failed to activate cspace, error %" PRId32
			"\n",
			vm->vmid, (int32_t)err);
		rm_err = rm_error_from_hyp(err);
		goto out_destroy_cspace;
	}

	// Create VM config
	vm_config_t *vmcfg = vm_config_alloc(vm, cs.new_cap, rm_partition_cap);
	if (vmcfg == NULL) {
		(void)printf("Error: vm %d failed to allocate config\n",
			     vm->vmid);
		rm_err = RM_ERROR_NOMEM;
		goto out_destroy_cspace;
	}

	// Validate auth type and set type-specific config defaults & policies
	switch (auth) {
	case VM_AUTH_TYPE_NONE:
		vm->vm_config->mem_unsanitized = true;
		break;
	case VM_AUTH_TYPE_PLATFORM:
		vm->vm_config->mem_unsanitized	= false;
		vm->vm_config->watchdog_enabled = true;
		break;
	case VM_AUTH_TYPE_ANDROID:
		vm->vm_config->mem_unsanitized = false;
		vm->sensitive		       = true;
		break;
	default:
		(void)printf("Error: vm %d bad auth mode %d\n", vm->vmid,
			     (uint32_t)auth);
		rm_err = RM_ERROR_ARGUMENT_INVALID;
		break;
	}

	if (rm_err != RM_OK) {
		goto out_destroy_cspace;
	}

	vm->auth_type = auth;

	err = vm_memory_setup(vm);
	if (err != OK) {
		(void)printf("Error: vm %d memory setup failed, error %" PRId32
			     "\n",
			     vm->vmid, (int32_t)err);
		rm_err = rm_error_from_hyp(err);
		goto out_dealloc_vm_config;
	}

	err = platform_vm_create(vm, false);
	if (err != OK) {
		LOG_ERR(err);
		rm_err = rm_error_from_hyp(err);
		goto out_teardown_vm_memory;
	}

	rm_err = RM_OK;

	goto out;

out_teardown_vm_memory:
	vm_memory_teardown(vm);
out_dealloc_vm_config:
	vm_config_dealloc(vm);
out_destroy_cspace:
	err = gunyah_hyp_cspace_delete_cap_from(rm_cspace_cap, cs.new_cap);
	assert(err == OK);
out:
	return rm_err;
}

rm_error_t
vm_creation_init(vm_t *vm)
{
	rm_error_t err;

	// parse vm-config node & create first class object
	uintptr_result_t map_ret = map_dtb(vm->dt_offset, vm->dt_size,
					   vm->mem_mp_handle, vm->mem_size);
	(void)printf("DTB: offset:0x%lx, size:0x%zx\n", vm->dt_offset,
		     vm->dt_size);
	if (map_ret.e != OK) {
		(void)printf("Error: failed to map device tree\n");
		err = RM_ERROR_MEM_INVALID;
		goto out;
	}
	void *temp_dtb_ptr = (void *)map_ret.r;

	// parse it first
	dtb_parser_ops_t *ops = vm_config_parser_get_ops();
	assert(ops != NULL);

	vm_config_parser_params_t params = vm_config_parser_get_params(vm);

	dtb_parser_parse_dtb_ret_t parse_ret =
		dtb_parser_parse_dtb(temp_dtb_ptr, ops, (void *)&params);
	(void)unmap_dtb(vm->mem_mp_handle);

	if (parse_ret.err != OK) {
		(void)printf(
			"Error: failed to parse device tree, ret = %" PRId32
			"\n",
			(int32_t)parse_ret.err);
		error_t free_ret = dtb_parser_free(ops, parse_ret.r);
		assert(free_ret == OK);
		err = RM_ERROR_MEM_INVALID;
		goto out;
	}

	assert(vm->vm_config != NULL);
	assert(parse_ret.r != NULL);

	error_t update_ret =
		vm_config_update_parsed(vm->vm_config, parse_ret.r);
	if (update_ret != OK) {
		(void)printf("Error: failed to update vm_config, ret = %" PRId32
			     "\n",
			     (int32_t)update_ret);

		error_t free_ret = dtb_parser_free(ops, parse_ret.r);
		assert(free_ret == OK);

		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	error_t create_ret =
		vm_config_create_vdevices(vm->vm_config, parse_ret.r);
	if (create_ret != OK) {
		(void)printf("Error: failed to create vdevices, ret = %" PRId32
			     "\n",
			     (int32_t)create_ret);

		error_t free_ret = dtb_parser_free(ops, parse_ret.r);
		assert(free_ret == OK);

		err = RM_ERROR_NORESOURCE;
		goto out;
	}

	error_t free_ret = dtb_parser_free(ops, parse_ret.r);
	assert(free_ret == OK);

#if defined(GUEST_RAM_DUMP_ENABLE) && GUEST_RAM_DUMP_ENABLE
	// Override mem_unsanitized value with dtb parsed value
	// if the config is trusted and guest ram dump is allowed
	// for vm do not sanitize guest vm region
	if (!platform_get_security_state() && vm->vm_config->trusted_config &&
	    vm->vm_config->guestdump_allowed) {
		// disable sanitization of Guest VM region
		vm->vm_config->mem_unsanitized = true;
		printf("GUEST_RAM_DUMP: Sanitization disabled for VM %d region.\n",
		       vm->vmid);
	}
#endif // GUEST_RAM_DUMP_ENABLE

	err = platform_vm_init(vm);

out:
	return err;
}

void
svm_takedown(vmid_t vmid)
{
	error_t ret;

	vm_t *vm = vm_lookup(vmid);
	assert(vm != NULL);

	ret = platform_vm_takedown(vm);

	assert((error_t)ret == OK);
}

void
svm_destroy(vmid_t vmid)
{
	vm_t *vm = vm_lookup(vmid);
	assert(vm != NULL);

	error_t platform_vm_destroy_ret = platform_vm_destroy(vm, false);
	assert(platform_vm_destroy_ret == OK);

	vm_config_destroy_vm_objects(vm);

	irq_manager_vm_deinit(vm);

	vm_config_dealloc(vm);
}
