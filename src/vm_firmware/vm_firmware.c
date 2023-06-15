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
#include <utils/address_range_allocator.h>
#include <utils/vector.h>

#include <cache.h>
#include <event.h>
#include <guest_interface.h>
#include <log.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_firmware.h>
#include <vm_firmware_message.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_vcpu.h>

// Handler to start one boot VCPU. This can be called multiple times if the
// firmware type does not have the single_boot_vcpu flag set and the VM DT has
// multiple VCPUs configured as enabled at boot time.
typedef rm_error_t (*vm_start_handler_t)(const vm_t *vm, vcpu_t *boot_vcpu);

static bool vm_firmware_loading_disabled;

static rm_error_t
vm_firmware_vm_start_android(const vm_t *vm, vcpu_t *boot_vcpu)
{
	error_t	     err;
	vm_config_t *vmcfg = vm->vm_config;

	// The calling convention for pVM firmware requires X1 and X2 to be
	// set to the base and size of the bootloader image.
	//
	// No distinction is made between the entry offset and the image
	// offset, so we require them to be equal. This should be true by
	// default anyway.
	if (vm->entry_offset != vm->image_offset) {
		err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	err = gunyah_hyp_vcpu_register_write(
		boot_vcpu->master_cap, VCPU_REGISTER_SET_X, 1,
		vmcfg->mem_ipa_base + vm->entry_offset);
	if (err != OK) {
		goto out;
	}

	err = gunyah_hyp_vcpu_register_write(
		boot_vcpu->master_cap, VCPU_REGISTER_SET_X, 2, vm->image_size);
	if (err != OK) {
		goto out;
	}

	// The context in X0 is set to the DTB pointer like in the default start
	// handler, but the initial PC is the firmware entry rather than the
	// image entry.
	err = gunyah_hyp_vcpu_poweron(
		boot_vcpu->master_cap,
		vm->vm_config->fw_ipa_base + vm->fw_offset,
		vm->vm_config->mem_ipa_base + vm->dt_offset,
		vcpu_poweron_flags_default());

out:
	return rm_error_from_hyp(err);
}

static rm_error_t
vm_firmware_vm_start_default(const vm_t *vm, vcpu_t *boot_vcpu)
{
	// AArch64 Linux calling convention: DTB pointer in X0, all other
	// registers zero / undefined. Most non-Linux VMs will accept this too.
	error_t err = gunyah_hyp_vcpu_poweron(
		boot_vcpu->master_cap,
		vm->vm_config->mem_ipa_base + vm->entry_offset,
		vm->vm_config->mem_ipa_base + vm->dt_offset,
		vcpu_poweron_flags_default());

	return rm_error_from_hyp(err);
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
	vm_auth_type_t	   auth_type;
	bool		   mandatory;
	bool		   single_boot_vcpu;
	vm_start_handler_t start_handler;

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
			.start_handler	  = vm_firmware_vm_start_android,
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

	LOG("FW_SET_VM_FIRMWARE: from:%d mp:%#" PRIx64 " offset:%#zx size:%#zx",
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
	bool	   handled = false;
	rm_error_t err	   = RM_ERROR_UNIMPLEMENTED;

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

	address_range_tag_t fw_mem_tag	= ADDRESS_RANGE_NO_TAG;
	count_t		    num_regions = memparcel_get_num_regions(fw_mp);
	for (index_t i = 0U; i < num_regions; i++) {
		paddr_result_t pret = memparcel_get_phys(fw_mp, i);
		assert(pret.e == OK);
		size_result_t sret = memparcel_get_region_size(fw_mp, i);
		assert(sret.e == OK);

		address_range_tag_t tag =
			vm_memory_get_phys_address_tag(pret.r, sret.r);
		fw_mem_tag = (i == 0U) ? tag : (tag & fw_mem_tag);
	}

	if ((fw_mem_tag == ADDRESS_RANGE_NO_TAG) ||
	    (fw_mem_tag != vm->mem_base_tag)) {
		(void)printf("Error: invalid tag for vm %d fw mp %d\n",
			     vm->vmid, fw_mp_handle);
		ret = RM_ERROR_MEM_INVALID;
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
	}

	uintptr_result_t addr_r =
		memparcel_map_rm(vm->fw_mp_handle, vm->fw_offset, vm->fw_size);
	if (addr_r.e != OK) {
		ret = rm_error_from_hyp(addr_r.e);
		LOG_ERR(ret);
		goto out;
	}
	uint8_t *temp_fw_ptr = (uint8_t *)addr_r.r;

	(void)memcpy(temp_fw_ptr, fw_data->image, fw_data->size);
	if (vm->fw_size > fw_data->size) {
		(void)memset(temp_fw_ptr + fw_data->size, 0,
			     vm->fw_size - fw_data->size);
	}
	cache_clean_by_va(temp_fw_ptr, vm->fw_size);

	error_t err = memparcel_unmap_rm(vm->fw_mp_handle);
	assert(err == OK);

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

	vm_start_handler_t start_handler;
	bool		   single_boot_vcpu;

	vm_firmware_data_t *fw_data = vm_firmware_lookup(vm->auth_type);
	if (fw_data == NULL) {
		// VM has no firmware; call the default start handler.
		if (vm->fw_size != 0U) {
			(void)printf(
				"Warning: unused firmware region of size %zd\n",
				vm->fw_size);
		}
		start_handler	 = vm_firmware_vm_start_default;
		single_boot_vcpu = false;
	} else if ((vm->fw_size == 0U) && !fw_data->mandatory) {
		// Firmware region is unset and is optional. Use the default
		// start handler.
		start_handler	 = vm_firmware_vm_start_default;
		single_boot_vcpu = fw_data->single_boot_vcpu;
	} else {
		ret = vm_firmware_copy_to_vm(vm);
		if (ret != RM_OK) {
			goto out;
		}
		start_handler	 = fw_data->start_handler;
		single_boot_vcpu = fw_data->single_boot_vcpu;
	}

	// Cache flush the whole VM region if it is not a platform VM.
	// Platform specific VM handling should perform any required cache
	// flushing.
	if (vm->auth_type != VM_AUTH_TYPE_PLATFORM) {
		uintptr_result_t addr_r =
			memparcel_map_rm(vm->mem_mp_handle, 0U, vm->mem_size);
		if (addr_r.e != OK) {
			ret = rm_error_from_hyp(addr_r.e);
			goto out;
		}
		cache_clean_by_va((uint8_t *)addr_r.r, vm->mem_size);
		error_t err = memparcel_unmap_rm(vm->mem_mp_handle);
		if (err != OK) {
			ret = rm_error_from_hyp(err);
			goto out;
		}
	}

	size_t vcpu_count      = vector_size(vmcfg->vcpus);
	bool   found_boot_vcpu = false;
	for (index_t i = 0; i < vcpu_count; i++) {
		vcpu_t *vcpu = vector_at(vcpu_t *, vmcfg->vcpus, i);
		assert(vcpu != NULL);
		if (vcpu->boot_vcpu) {
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
			ret = start_handler(vm, vcpu);
			if (ret != RM_OK) {
				goto out;
			}
		}
	}

out:
	return ret;
}
