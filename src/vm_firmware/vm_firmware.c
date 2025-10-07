// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
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
#include <vm_firmware.h>
#include <vm_firmware_arch.h>
#include <vm_firmware_message.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_vcpu.h>

// TODO: Move all architecture specific register handling to arch source

typedef rm_error_t (*vm_setup_boot_context_t)(const vm_t *vm);
typedef rm_error_t (*vm_set_boot_context_t)(const vm_t	       *vm,
					    arch_register_set_t reg_set,
					    index_t		reg_index,
					    register_t		reg_val);

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

	// Don't need to set pc or x0 because we force those to be
	// FW region and DTB, respectively when starting the VM.
	vmcfg->boot_ctx->pc   = vmcfg->fw_ipa_base + vm->fw_offset;
	vmcfg->boot_ctx->x[0] = vmcfg->mem_ipa_base + vm->dt_offset;
	vmcfg->boot_ctx->x[1] = vmcfg->mem_ipa_base + vm->entry_offset;
	vmcfg->boot_ctx->x[2] = vm->image_size;

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
		// x0 must be pointer to the DTB that RM parsed.
		if ((reg_index == 0U) ||
		    (reg_index >= util_array_size(vmcfg->boot_ctx->x))) {
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
vm_firmware_vm_start_default(const vm_t *vm, vcpu_t *boot_vcpu)
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

RM_PADDED(typedef struct vm_firmware_data_s {
	vm_auth_type_t		auth_type;
	bool			mandatory;
	bool			single_boot_vcpu;
	vm_setup_boot_context_t setup_boot_context_handler;
	vm_set_boot_context_t	set_boot_context_handler;

	const uint8_t *image;
	size_t	       size;
} vm_firmware_data_t)

static vm_firmware_data_t *
vm_firmware_lookup(vm_auth_type_t auth_type)
{
	static vm_firmware_data_t vm_firmware_data[] = {
		{
			.auth_type	  = VM_AUTH_TYPE_ANDROID,
			.mandatory	  = true,
			.single_boot_vcpu = true,
			.setup_boot_context_handler =
				&vm_firmware_vm_setup_boot_context_android,
			.set_boot_context_handler =
				&vm_firmware_vm_set_boot_context_android,
		},
	};
	vm_firmware_data_t *ret = NULL;

	for (index_t i = 0U; i < util_array_size(vm_firmware_data); i++) {
		if (vm_firmware_data[i].auth_type == auth_type) {
			ret = &vm_firmware_data[i];
			break;
		}
	}

	return ret;
}

static rm_error_t
vm_firmware_set(vm_auth_type_t auth_type, resource_handle_t mp_handle,
		size_t offset, size_t size)
{
	vm_t *rm_vm = vm_lookup(VMID_RM);
	assert(rm_vm != NULL);

	rm_error_t err;

	// Find the auth type's FW configuration structure
	vm_firmware_data_t *fw_data = vm_firmware_lookup(auth_type);
	if (fw_data == NULL) {
		err = RM_ERROR_ARGUMENT_INVALID;
		LOG_ERR(err);
		goto out;
	}

	if (fw_data->image != NULL) {
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

	// Check the offset and size. We currently don't support offsets that
	// are nonzero; it does not make sense because it isn't possible to
	// reuse the memparcel for anything else (whether a different firmware
	// or otherwise).
	size_t mp_size = memparcel_get_size(mp);
	if ((size == 0U) || (offset != 0U) || (size > mp_size)) {
		err = RM_ERROR_ARGUMENT_INVALID;
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

	fw_data->image = (uint8_t *)donation_ret.ptr;
	fw_data->size  = donation_ret.size;
	err	       = RM_OK;

	// Note that we don't read or validate the FW image; it's assumed that
	// the loader has done that before calling this API. Therefore we do not
	// need to do any cache maintenance.
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

	fw_set_vm_firmware_req_t *req = (fw_set_vm_firmware_req_t *)buf;
	if (len != sizeof(*req)) {
		err = RM_ERROR_MSG_INVALID;
		LOG_ERR(err);
		goto out;
	}

	if (req->res0 != 0U) {
		err = RM_ERROR_UNIMPLEMENTED;
		LOG_ERR(err);
		goto out;
	}

	LOG("FW_SET_VM_FIRMWARE: from:%d mp:%#" PRIx64
	    " offset:%#zx size:%#zx\n",
	    client_id, (uint64_t)req->image_mp_handle, req->image_offset,
	    req->image_size);
	err = vm_firmware_set((vm_auth_type_t)req->auth_type,
			      req->image_mp_handle, req->image_offset,
			      req->image_size);

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

	vm_firmware_data_t *fw_data = vm_firmware_lookup(vm->auth_type);
	if (fw_data == NULL) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		LOG_ERR(ret);
		goto out;
	}

	if (fw_data->image == NULL) {
		ret = RM_ERROR_DENIED;
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
vm_firmware_copy_to_vm(vm_t *vm)
{
	rm_error_t ret;

	if (!vm_firmware_loading_disabled) {
		ret = RM_ERROR_DENIED;
		LOG_ERR(ret);
		goto out;
	}

	vm_firmware_data_t *fw_data = vm_firmware_lookup(vm->auth_type);
	if (fw_data == NULL) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		LOG_ERR(ret);
		goto out;
	}

	if (fw_data->image == NULL) {
		ret = RM_ERROR_NORESOURCE;
		LOG_ERR(ret);
		goto out;
	}

	if (fw_data->size > vm->fw_size) {
		ret = RM_ERROR_MEM_INVALID;
		LOG_ERR(ret);
		goto out;
	}

	uintptr_result_t addr_r = memparcel_map_rm(
		vm->fw_mp_handle, vm->fw_offset, fw_data->size);
	if (addr_r.e != OK) {
		ret = rm_error_from_hyp(addr_r.e);
		LOG_ERR(ret);
		goto out;
	}

	uint8_t *temp_fw_ptr = (uint8_t *)addr_r.r;
	(void)memscpy(temp_fw_ptr, fw_data->size, fw_data->image,
		      fw_data->size);
	cache_clean_by_va(temp_fw_ptr, fw_data->size);

	error_t err = memparcel_unmap_rm(vm->fw_mp_handle);
	assert(err == OK);

	if (vm->fw_size > fw_data->size) {
		err = memparcel_sanitize(vm->fw_mp_handle,
					 vm->fw_offset + fw_data->size,
					 vm->fw_size - fw_data->size);
		assert(err == OK);
	}

	ret = RM_OK;
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

	vm_firmware_data_t *fw_data = vm_firmware_lookup(vm->auth_type);
	if (fw_data == NULL) {
		// VM has no firmware; call the default start handler.
		if (vm->fw_size != 0U) {
			(void)printf(
				"Warning: unused firmware region of size %zd\n",
				vm->fw_size);
		}
		single_boot_vcpu = false;
	} else if ((vm->fw_size == 0U) && !fw_data->mandatory) {
		// Firmware region is unset and is optional. Use the default
		// start handler.
		single_boot_vcpu = fw_data->single_boot_vcpu;
	} else {
		ret = vm_firmware_copy_to_vm(vm);
		if (ret != RM_OK) {
			goto out;
		}
		single_boot_vcpu = fw_data->single_boot_vcpu;
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

	size_t vcpu_count      = vector_size(vmcfg->vcpus);
	bool   found_boot_vcpu = false;
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
			ret = vm_firmware_vm_start_default(vm, vcpu);
			if (ret != RM_OK) {
				goto out;
			}
		}
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

	vm_firmware_data_t *fw_data = vm_firmware_lookup(vm->auth_type);

	vm_boot_context_t *ctx = calloc(1, sizeof(vm_boot_context_t));

	if (ctx == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}
	vm->vm_config->boot_ctx = ctx;

	if (fw_data == NULL) {
		ctx->pc	  = vm->vm_config->mem_ipa_base + vm->entry_offset;
		ctx->x[0] = vm->vm_config->mem_ipa_base + vm->dt_offset;
		ret	  = RM_OK;
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

	// Sanity check register set indexes
	switch (req->arch_reg_set) {
	case (uint8_t)ARCH_REG_SET_X:
		if (req->reg_index >= util_array_size(vmcfg->boot_ctx->x)) {
			ret = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}
		break;
	case (uint8_t)ARCH_REG_SET_PC:
		if (req->reg_index != 0U) {
			ret = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}
		break;
	case (uint8_t)ARCH_REG_SET_SP:
		if (req->reg_index >= util_array_size(vmcfg->boot_ctx->sp_el)) {
			ret = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}
		break;
	default:
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	vm_firmware_data_t   *fw_data = vm_firmware_lookup(vm->auth_type);
	vm_set_boot_context_t handler;

	if (fw_data == NULL) {
		handler = vm_firmware_vm_set_boot_context_default;
	} else {
		handler = fw_data->set_boot_context_handler;
	}

	ret = handler(vm, req->arch_reg_set, req->reg_index, req->value);

out:
	return ret;
}
