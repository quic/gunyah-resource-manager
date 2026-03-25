// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>
#include <utils/vector.h>

#include <cache.h>
#include <event.h>
#include <guest_interface.h>
#include <log.h>
#include <mem_region.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <panic.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_firmware.h>
#include <vm_firmware_arch.h>
#include <vm_firmware_message.h>
#include <vm_firmware_struct.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_vcpu.h>

#include "platform_vm_firmware.h"

// TODO: Move all architecture specific register handling to arch source

static bool vm_firmware_loading_disabled;

static error_t
vm_firwmare_fill_x_boot_context(const vm_config_t *vmcfg,
				const vcpu_t	  *boot_vcpu)
{
	error_t err = OK;

	assert(vmcfg->boot_ctx != NULL);
	vm_boot_context_t *ctx = vmcfg->boot_ctx;

	// Skip setting x0 because vcpu_poweron provides that
	for (index_t i = 1; i < BOOT_CONTEXT_GENERAL_REGS; i++) {
		err = gunyah_hyp_vcpu_register_write(boot_vcpu->master_cap,
						     VCPU_REGISTER_SET_X, i,
						     ctx->x[i]);
		if (err != OK) {
			goto out;
		}
	}

	err = gunyah_hyp_vcpu_register_write(boot_vcpu->master_cap,
					     VCPU_REGISTER_SET_SP_EL, 0,
					     ctx->sp_el[0]);
	if (err != OK) {
		goto out;
	}

	err = gunyah_hyp_vcpu_register_write(boot_vcpu->master_cap,
					     VCPU_REGISTER_SET_SP_EL, 1,
					     ctx->sp_el[1]);
	if (err != OK) {
		goto out;
	}
out:
	return err;
}

static rm_error_t
vm_firmware_vm_setup_boot_context_android(const vm_t *vm)
{
	vm_config_t *vmcfg = vm->vm_config;

	assert(vmcfg->boot_ctx != NULL);

	vmcfg->boot_ctx->pc   = vmcfg->fw_ipa_base + vm->fw_offset;
	vmcfg->boot_ctx->x[0] = vmcfg->mem_ipa_base + vm->vmm_dt_offset;
	vmcfg->boot_ctx->x[1] = vmcfg->mem_ipa_base + vm->entry_offset;
	vmcfg->boot_ctx->x[2] = vm->image_size;

	// Set the hyp boot protocol version to 0.
	vmcfg->boot_ctx->x[15] = 0U;

	return RM_OK;
}

static rm_error_t
vm_firmware_vm_set_boot_context_android(const vm_t	   *vm,
					arch_register_set_t reg_set,
					index_t reg_index, register_t reg_val)
{
	rm_error_t   ret   = RM_OK;
	vm_config_t *vmcfg = vm->vm_config;
	assert(vmcfg->boot_ctx != NULL);

	switch (reg_set) {
	case ARCH_REG_SET_X:
		if (reg_index >= util_array_size(vmcfg->boot_ctx->x)) {
			ret = RM_ERROR_ARGUMENT_INVALID;
			break;
		}
		// X0 is the DTB pointer, and X15-X30 are reserved for
		// communication between hyp and pvmfw. These must not be
		// modified from the initial boot context set by RM.
		if ((reg_index == 0U) || (reg_index >= 15U)) {
			ret = RM_ERROR_DENIED;
			break;
		}
		vmcfg->boot_ctx->x[reg_index] = reg_val;
		break;
	case ARCH_REG_SET_PC:
		// Entry point must be the pVM firmware.
		ret = RM_ERROR_DENIED;
		break;
	case ARCH_REG_SET_SP:
		vmcfg->boot_ctx->sp_el[reg_index] = reg_val;
		break;
	default:
		ret = RM_ERROR_DENIED;
		break;
	}

	return ret;
}

static rm_error_t
start_boot_vcpu(const vm_t *vm, const vcpu_t *boot_vcpu)
{
	rm_error_t rm_err;
	error_t	   err;

	err = vm_firwmare_fill_x_boot_context(vm->vm_config, boot_vcpu);
	if (err != OK) {
		rm_err = rm_error_from_hyp(err);
		goto out;
	}

	vm_config_t *vmcfg = vm->vm_config;
	assert(vmcfg->boot_ctx != NULL);

	// AArch64 Linux calling convention: DTB pointer in X0, all other
	// registers zero / undefined. Most non-Linux VMs will accept this too.
	err    = gunyah_hyp_vcpu_poweron(boot_vcpu->master_cap,
					 vmcfg->boot_ctx->pc,
					 vmcfg->boot_ctx->x[0],
					 vcpu_poweron_flags_default());
	rm_err = rm_error_from_hyp(err);
out:
	return rm_err;
}

static rm_error_t
vm_firmware_vm_set_boot_context_default(const vm_t	   *vm,
					arch_register_set_t reg_set,
					index_t reg_index, register_t reg_val)
{
	rm_error_t   err   = RM_OK;
	vm_config_t *vmcfg = vm->vm_config;
	assert(vmcfg->boot_ctx != NULL);

	// TODO: separate vm->protected from auth_type
	bool protected = vm->auth_type == VM_AUTH_TYPE_PLATFORM;

	switch (reg_set) {
	case ARCH_REG_SET_X:
		// x0 must be pointer to the DTB that RM parsed
		if (((reg_index == 0U) && protected) ||
		    (reg_index >= util_array_size(vmcfg->boot_ctx->x))) {
			err = RM_ERROR_DENIED;
			break;
		}
		vmcfg->boot_ctx->x[reg_index] = reg_val;
		break;
	case ARCH_REG_SET_PC:
		if (protected) {
			// Entry point is set by authenticated image
			err = RM_ERROR_DENIED;
			break;
		}
		vmcfg->boot_ctx->pc = reg_val;
		break;
	case ARCH_REG_SET_SP:
		vmcfg->boot_ctx->sp_el[reg_index] = reg_val;
		break;
	default:
		err = RM_ERROR_DENIED;
		break;
	}

	return err;
}

static rm_error_t
vm_firmware_handle_milestone(vmid_t client_id, void *buf, size_t len)
{
	rm_error_t err;

	if (vm_firmware_loading_disabled) {
		err = RM_ERROR_DENIED;
		LOG_ERR(err);
		goto out;
	}

	if (client_id != VMID_HLOS) {
		err = RM_ERROR_DENIED;
		LOG_ERR(err);
		goto out;
	}

	if (len != 0U) {
		err = RM_ERROR_MSG_INVALID;
		LOG_ERR(err);
		goto out;
	}
	(void)buf; // message has no contents

	LOG("FW_MILESTONE: from:%d\n", client_id);
	vm_firmware_loading_disabled = true;
	err			     = RM_OK;

out:
	return err;
}

static vm_firmware_image_data_t *
vm_firmware_find_image_data(vm_fw_type_t fw_type)
{
	vm_firmware_image_data_t *ret = NULL;

	static const vm_firmware_image_data_t vm_firmware_image_pvmfw = {
		.fw_type = VM_FW_TYPE_PVMFW,
	};
	static vm_firmware_image_data_t vm_firmware_image_data[] = {
		PLATFORM_FIRMWARE_IMAGE_DATA vm_firmware_image_pvmfw,
	};

	for (index_t i = 0U; i < util_array_size(vm_firmware_image_data); i++) {
		if (vm_firmware_image_data[i].fw_type == fw_type) {
			ret = &vm_firmware_image_data[i];
			break;
		}
	}

	return ret;
}

rm_error_t
vm_firmware_config(vm_t *vm)
{
	rm_error_t ret;

	static const vm_firmware_data_t vm_firmware_data[] = {
		{
			.auth_type = VM_AUTH_TYPE_NONE,
			.fw_type   = VM_FW_TYPE_NONE,
		},
		{
			.auth_type	  = VM_AUTH_TYPE_ANDROID,
			.fw_type	  = VM_FW_TYPE_PVMFW,
			.mandatory	  = true,
			.single_boot_vcpu = true,
			.setup_boot_context_handler =
				&vm_firmware_vm_setup_boot_context_android,
			.set_boot_context_handler =
				&vm_firmware_vm_set_boot_context_android,
		},
		PLATFORM_FIRMWARE_DATA
	};

	const vm_firmware_data_t *fw_data = NULL;

	for (index_t i = 0U; i < util_array_size(vm_firmware_data); i++) {
		if (vm_firmware_data[i].auth_type != vm->auth_type) {
			continue;
		}

		if (vm_firmware_data[i].fw_type == VM_FW_TYPE_NONE) {
			fw_data = &vm_firmware_data[i];
			break;
		}

		const vm_firmware_image_data_t *image_data =
			vm_firmware_find_image_data(
				vm_firmware_data[i].fw_type);
		assert(image_data != NULL);

		if (image_data->image != NULL) {
			fw_data = &vm_firmware_data[i];
			break;
		}
	}

	if (fw_data != NULL) {
		vm->vm_config->fw_data = fw_data;
		ret		       = RM_OK;
	} else {
		ret = RM_ERROR_ARGUMENT_INVALID;
	}

	return ret;
}

static rm_error_t
vm_firmware_set(vm_fw_type_t fw_type, resource_handle_t mp_handle,
		size_t fw_offset, size_t fw_size, size_t config_offset,
		size_t config_size)
{
	vm_t *rm_vm = vm_lookup(VMID_RM);
	assert(rm_vm != NULL);

	rm_error_t err;

	if (util_add_overflows(fw_offset, fw_size) ||
	    util_add_overflows(config_offset, config_size)) {
		err = RM_ERROR_ARGUMENT_INVALID;
		LOG_ERR(err);
		goto out;
	}

	vm_firmware_image_data_t *image_data =
		vm_firmware_find_image_data(fw_type);
	if (image_data == NULL) {
		err = RM_ERROR_ARGUMENT_INVALID;
		LOG_ERR(err);
		goto out;
	}

	if (image_data->image != NULL) {
		err = RM_ERROR_BUSY;
		LOG_ERR(err);
		goto out;
	}

	// Look up the memparcel and check that the given range is within it
	memparcel_t *mp = memparcel_lookup_by_target_vmid(VMID_RM, mp_handle);
	if (mp == NULL) {
		err = RM_ERROR_HANDLE_INVALID;
		LOG_ERR(err);
		goto out;
	}

	paddr_result_t phys_base = memparcel_get_phys(mp, 0U);
	if (phys_base.e != OK) {
		err = RM_ERROR_HANDLE_INVALID;
		LOG_ERR(err);
		goto out;
	}

	// The given memparcel must have been donated to the RM VM (and not yet
	// accepted, since donated memparcels don't exist after accept). This
	// call will implicitly accept it.
	memparcel_accept_rm_donation_ret_t donation_ret =
		memparcel_accept_rm_donation(mp_handle, MEM_RIGHTS_RWX,
					     MEM_TYPE_NORMAL);
	if (donation_ret.err != RM_OK) {
		err = donation_ret.err;
		(void)printf("Error: failed to accept firmware memparcel: %d\n",
			     err);
		goto out;
	}

	// The firmware and config ranges must be within the donated memparcel
	if (((fw_offset + fw_size) > donation_ret.size) ||
	    ((config_offset + config_size) > donation_ret.size)) {
		err = RM_ERROR_ARGUMENT_INVALID;
		LOG_ERR(err);
		goto out;
	}

	if (image_data->auth_image != NULL) {
		err = image_data->auth_image(image_data,
					     (uintptr_t)donation_ret.ptr,
					     donation_ret.size, phys_base.r,
					     fw_offset, fw_size, config_offset,
					     config_size);
	} else {
		// This is a generic binary image. Check the offset and size. We
		// don't permit offsets that are nonzero; it does not make
		// sense because it isn't possible to reuse the memparcel for
		// anything else (whether a different firmware or otherwise).
		if ((fw_size == 0U) || (fw_offset != 0U)) {
			err = RM_ERROR_ARGUMENT_INVALID;
			LOG_ERR(err);
			goto out;
		}

		// Calculate the necessary size to include the config when the
		// image is copied. For generic images, RM will not do any
		// further handling of the firmware config.
		size_t size = util_max(fw_size, config_offset + config_size);

		image_data->image = (uint8_t *)donation_ret.ptr;
		image_data->size  = size;
		err		  = RM_OK;
	}

out:
	return err;
}

static rm_error_t
vm_firmware_handle_set_vm_firmware(vmid_t client_id, void *buf, size_t len)
{
	rm_error_t err;

	if (vm_firmware_loading_disabled) {
		err = RM_ERROR_DENIED;
		LOG_ERR(err);
		goto out;
	}

	if (client_id != VMID_HLOS) {
		err = RM_ERROR_DENIED;
		LOG_ERR(err);
		goto out;
	}

	// Copy from the buffer into a zero-initialised struct so that the
	// extended fields at the end do not contain stale data
	fw_set_vm_firmware_req_t req = { 0 };
	if (len > sizeof(req)) {
		err = RM_ERROR_MSG_INVALID;
		LOG_ERR(err);
		goto out;
	}
	(void)memscpy(&req, sizeof(req), buf, len);

	uint16_t flags = req.flags;

	bool config_range_valid =
		(flags & util_bit(FW_SET_VM_FIRMWARE_FLAG_CONFIG_RANGE)) != 0U;
	flags &= (uint16_t)~util_bit(FW_SET_VM_FIRMWARE_FLAG_CONFIG_RANGE);

	// Reject any unknown flags
	if (flags != 0U) {
		err = RM_ERROR_UNIMPLEMENTED;
		LOG_ERR(err);
		goto out;
	}

	uint64_t config_offset = config_range_valid ? req.config_offset : 0U;
	uint64_t config_size   = config_range_valid ? req.config_size : 0U;

	LOG("FW_SET_VM_FIRMWARE: from:%d mp:%#" PRIx64
	    " offset:%#zx size:%#zx config_offset: %#zx\n",
	    client_id, (uint64_t)req.image_mp_handle, req.image_offset,
	    req.image_size, config_offset);
	err = vm_firmware_set((vm_fw_type_t)req.fw_type, req.image_mp_handle,
			      req.image_offset, req.image_size, config_offset,
			      config_size);

out:
	return err;
}

bool
vm_firmware_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len)
{
	bool	   handled;
	rm_error_t err = RM_ERROR_UNIMPLEMENTED;

	switch (msg_id) {
	case FW_MILESTONE:
		err	= vm_firmware_handle_milestone(client_id, buf, len);
		handled = true;
		break;
	case FW_SET_VM_FIRMWARE:
		err = vm_firmware_handle_set_vm_firmware(client_id, buf, len);
		handled = true;
		break;
	default:
		// Not a firmware command
		handled = false;
		break;
	}

	if (handled) {
		rm_standard_reply(client_id, msg_id, seq_num, err);
	}

	return handled;
}

rm_error_t
vm_firmware_vm_set_mem(vm_t *vm, resource_handle_t fw_mp_handle,
		       size_t fw_offset, size_t fw_size)
{
	rm_error_t ret;

	const vm_firmware_data_t *fw_data = vm->vm_config->fw_data;
	assert(fw_data != NULL);

	if (fw_data->fw_type == VM_FW_TYPE_NONE) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		LOG_ERR(ret);
		goto out;
	}

	memparcel_t *fw_mp =
		memparcel_lookup_by_target_vmid(vm->vmid, fw_mp_handle);
	if (fw_mp == NULL) {
		(void)printf("Error: VM %d failed to look up FW memparcel %d\n",
			     vm->vmid, fw_mp_handle);
		ret = RM_ERROR_MEM_INVALID;
		goto out;
	}

	size_t mp_size = memparcel_get_size(fw_mp);
	if (util_add_overflows(fw_offset, fw_size) ||
	    ((fw_offset + fw_size) > mp_size)) {
		(void)printf(
			"Error: vm %d firmware range is invalid: %#zx+%#zx,"
			" FW mem size %#zx\n",
			vm->vmid, vm->fw_offset, vm->fw_size, mp_size);
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	vm->fw_mp_handle = fw_mp_handle;
	vm->fw_size	 = fw_size;
	vm->fw_offset	 = fw_offset;
	ret		 = RM_OK;

out:
	return ret;
}

static rm_error_t
vm_firmware_copy_to_vm(vm_t *vm, const vm_firmware_data_t *fw_data)
{
	rm_error_t ret;

	if (!vm_firmware_loading_disabled) {
		ret = RM_ERROR_DENIED;
		LOG_ERR(ret);
		goto out;
	}

	if (fw_data->fw_type == VM_FW_TYPE_NONE) {
		ret = RM_ERROR_NORESOURCE;
		LOG_ERR(ret);
		goto out;
	}

	const vm_firmware_image_data_t *image_data =
		vm_firmware_find_image_data(fw_data->fw_type);
	assert(image_data != NULL);

	if (image_data->image == NULL) {
		ret = RM_ERROR_NORESOURCE;
		LOG_ERR(ret);
		goto out;
	}

	if (image_data->size > vm->fw_size) {
		ret = RM_ERROR_MEM_INVALID;
		LOG_ERR(ret);
		goto out;
	}

	uintptr_result_t addr_r =
		memparcel_map_rm(vm->fw_mp_handle, vm->fw_offset, vm->fw_size);
	if (addr_r.e != OK) {
		ret = rm_error_from_hyp(addr_r.e);
		LOG_ERR(ret);
		goto out;
	}

	uint8_t *temp_fw_ptr = (uint8_t *)addr_r.r;
	if (fw_data->copy_image != NULL) {
		ret = fw_data->copy_image(vm, image_data, temp_fw_ptr);
		if (ret != RM_OK) {
			LOG_ERR(ret);
			goto out;
		}
	} else {
		size_t copied_size = memscpy(temp_fw_ptr, vm->fw_size,
					     image_data->image,
					     image_data->size);
		if (copied_size < vm->fw_size) {
			(void)memset(temp_fw_ptr + copied_size, 0,
				     vm->fw_size - copied_size);
		}

		// If we don't have any specific copy handler for this firmware,
		// then we don't have a way to provide a DTBO to the firmware
		// and therefore must patch the DTB in place.
		error_t patch_err = vm_creation_patch_dtb(vm);
		if (patch_err != OK) {
			ret = rm_error_from_hyp(patch_err);
			goto out;
		}
	}

	// Ensure the whole firmware region is cache-coherent
	cache_clean_by_va(temp_fw_ptr, vm->fw_size);

	error_t err = memparcel_unmap_rm(vm->fw_mp_handle);
	assert(err == OK);

	ret = RM_OK;
out:
	return ret;
}

static rm_error_t
start_vm_boot_cpu(const vm_t *vm, vm_config_t *vmcfg, bool single_boot_vcpu)
{
	rm_error_t ret;
	size_t	   vcpu_count	   = vector_size(vmcfg->vcpus);
	bool	   found_boot_vcpu = false;

	for (index_t i = 0; i < vcpu_count; i++) {
		vcpu_t *vcpu = vector_at(vcpu_t *, vmcfg->vcpus, i);
		assert(vcpu != NULL);
		if (vcpu->boot_vcpu) {
			assert(!vcpu->defective);
			if (found_boot_vcpu && single_boot_vcpu) {
				// Multiple boot CPUs not allowed
				ret = RM_ERROR_DENIED;
				goto out;
			}
			found_boot_vcpu = true;
		}
	}

	if (!found_boot_vcpu) {
		// Couldn't find the boot VCPU
		ret = RM_ERROR_NORESOURCE;
		goto out;
	}

	ret = RM_OK;

	for (index_t i = 0; i < vcpu_count; i++) {
		vcpu_t *vcpu = vector_at(vcpu_t *, vmcfg->vcpus, i);
		assert(vcpu != NULL);
		if (vcpu->boot_vcpu) {
			ret = start_boot_vcpu(vm, vcpu);
			if (ret != RM_OK) {
				goto out;
			}
		}
	}

out:
	return ret;
}

rm_error_t
vm_firmware_vm_start(vm_t *vm)
{
	rm_error_t   ret;
	vm_config_t *vmcfg = vm->vm_config;
	assert(vmcfg != NULL);

	bool single_boot_vcpu;

	const vm_firmware_data_t *fw_data = vm->vm_config->fw_data;
	assert(fw_data != NULL);

	if ((vm->fw_size == 0U) && !fw_data->mandatory) {
		// Firmware region is unset and is optional. No need to copy.
		single_boot_vcpu = fw_data->single_boot_vcpu;

		// Since there is no firmware, we must generate a DTBO and apply
		// it to the VM's device tree ourselves.
		error_t patch_err = vm_creation_patch_dtb(vm);
		if (patch_err != OK) {
			ret = rm_error_from_hyp(patch_err);
			goto out;
		}
	} else {
		ret = vm_firmware_copy_to_vm(vm, fw_data);
		if (ret != RM_OK) {
			goto out;
		}
		single_boot_vcpu = fw_data->single_boot_vcpu;
	}

	error_t mp_err = memparcel_unprotect(vm->mem_mp_handle);
	if (mp_err != OK) {
		(void)printf("Memparcel unprotect failed..!!\n");
		ret = RM_ERROR_DENIED;
		goto out;
	}

	// Cache flush the whole VM region if it is not a platform VM and is
	// not a protected demand-paged VM.
	//
	// For protected demand-paged VMs, we use protected map operations for
	// normal memory, which implicitly flush the cache. For platform VMs,
	// the platform specific VM handling should perform any required cache
	// flushing.
	bool protected_vm = vm->vm_config->mem_demand_paging && vm->mem_private;
	if ((vm->auth_type != VM_AUTH_TYPE_PLATFORM) && !protected_vm) {
		error_t err = memparcel_cache_flush(vm->mem_mp_handle, 0U,
						    vm->mem_size);
		if (err != OK) {
			ret = rm_error_from_hyp(err);
			goto out;
		}
		cache_invalidate_inst_all();
	}

	ret = start_vm_boot_cpu(vm, vmcfg, single_boot_vcpu);
	if (ret != RM_OK) {
		goto out;
	}

	// Finally, for a dynamically paged VM, drop all of the memparcel
	// handles. Note that we do this after starting the VM because we don't
	// want it to happen if the start handler fails. The failure cases
	// should have already been excluded.
	if (vm->vm_config->mem_demand_paging) {
		ret = memparcel_drop_all_paged(vm->vmid);
		if (ret != RM_OK) {
			panic("Unable to drop paged memory parcels!");
		}
	}

	free(vmcfg->boot_ctx);
	vmcfg->boot_ctx = NULL;

out:
	return ret;
}

rm_error_t
vm_firmware_init_boot_context(const vm_t *vm)
{
	rm_error_t ret;

	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	const vm_firmware_data_t *fw_data = vm->vm_config->fw_data;

	vm_boot_context_t *ctx = calloc(1, sizeof(vm_boot_context_t));

	if (ctx == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}
	vm->vm_config->boot_ctx = ctx;

	if (((vm->fw_size == 0U) && !fw_data->mandatory) ||
	    (fw_data->setup_boot_context_handler == NULL)) {
		ctx->pc = vm->vm_config->mem_ipa_base + vm->entry_offset;
		if (vm->image_dt_size == 0U) {
			ctx->x[0] =
				vm->vm_config->mem_ipa_base + vm->vmm_dt_offset;
		} else {
			ctx->x[0] = vm->vm_config->mem_ipa_base +
				    vm->image_dt_offset;
		}
		ret = RM_OK;
	} else {
		ret = fw_data->setup_boot_context_handler(vm);
	}

out:
	return ret;
}

rm_error_t
vm_firmware_set_boot_context(const vm_t *vm, const vm_boot_ctx_req_t *req)
{
	rm_error_t ret;

	assert(req != NULL);

	vm_config_t *vmcfg = vm->vm_config;

	arch_register_set_t reg_set;

	// Sanity check register set indexes
	switch (req->arch_reg_set) {
	case (uint8_t)ARCH_REG_SET_X:
		if (req->reg_index >= util_array_size(vmcfg->boot_ctx->x)) {
			ret = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}
		reg_set = ARCH_REG_SET_X;
		break;
	case (uint8_t)ARCH_REG_SET_PC:
		if (req->reg_index != 0U) {
			ret = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}
		reg_set = ARCH_REG_SET_PC;
		break;
	case (uint8_t)ARCH_REG_SET_SP:
		if (req->reg_index >= util_array_size(vmcfg->boot_ctx->sp_el)) {
			ret = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}
		reg_set = ARCH_REG_SET_SP;
		break;
	default:
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	const vm_firmware_data_t *fw_data = vm->vm_config->fw_data;
	assert(fw_data != NULL);

	if (fw_data->set_boot_context_handler != NULL) {
		ret = fw_data->set_boot_context_handler(
			vm, reg_set, req->reg_index, req->value);
	} else {
		ret = vm_firmware_vm_set_boot_context_default(
			vm, reg_set, req->reg_index, req->value);
	}

out:
	return ret;
}
