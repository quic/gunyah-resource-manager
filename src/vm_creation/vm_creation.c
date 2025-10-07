// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

#include <rm_types.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <util.h>
#include <utils/list.h>
#include <utils/vector.h>

#include <cache.h>
#include <cpio.h>
#include <ctype.h>
#include <dt_overlay.h>
#include <dtb_parser.h>
#include <event.h>
#include <guest_interface.h>
#include <log.h>
#include <mem_region.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_dt.h>
#include <platform_vm_config.h>
#include <random.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_creation_message.h>
#include <vm_firmware.h>
#include <vm_mgnt.h>
#include <vm_mgnt_message.h>
#include <vm_vcpu.h>

#include <platform_vm_config_parser.h>
#include <vm_config_parser.h>

#include "dto_construct.h"

#define MAX_DTB_ALLOC_SIZE (16U << 10)

#define VM_CREATION_VERBOSE_DEBUG 0

static error_t
process_dtb(vm_t *vm);

typedef struct {
	dto_t  *constructed_object;
	void   *dtbo;
	size_t	size;
	error_t err;
	uint8_t err_padding[4];
} create_dtbo_ret_t;

static create_dtbo_ret_t
create_dtbo(vm_t *vm, const void *base_dtb);

static error_t
create_dt_nodes(const void *base_dtb, dto_t *dto, vmid_t vmid);

static error_t
create_iomem_nodes(dto_t *dto, vmid_t vmid);

static error_t
accept_memparcel(vmid_t vmid, const memparcel_t *mp);

static error_t
accept_iomem_memparcel(vmid_t vmid, memparcel_t *mp,
		       struct vdevice_iomem *config);

static error_t
accept_memparcel_fixed(const vm_t *vm, const memparcel_t *mp, vmaddr_t ipa,
		       size_t sz);

static rm_error_t
accept_memparcel_private(vm_t *vm, const memparcel_t *mp);

static error_t
process_memparcels(vm_t *vm);

static error_t
process_cfgcpio(vm_t *vm);

static error_t
patch_chosen_node(dto_t *dto, vm_t *vm, const void *base_dtb);

error_t
vm_creation_process_resource(vm_t *vm)
{
	error_t ret = OK;
	assert(vm != NULL);

	ret = process_memparcels(vm);
	if (ret != OK) {
		(void)printf("process_memparcels: ret %d\n", ret);
		goto out;
	}

	ret = process_cfgcpio(vm);
	if (ret != OK) {
		(void)printf("process_cfgcpio: ret %d\n", ret);
		goto out;
	}

	ret = process_dtb(vm);
	if (ret != OK) {
		(void)printf("process_dtb: ret %d\n", ret);
		goto out;
	}

out:
	return ret;
}

static rm_error_t
vm_creation_handle_config(vmid_t client_id, void *buf, size_t len)
{
	rm_error_t ret;

	// FIXME: make these checks more generic
	if (client_id != VMID_HLOS) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	vm_config_image_req_t *req = (vm_config_image_req_t *)buf;
	if (len != sizeof(*req)) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	LOG("VM_CONFIG_IMAGE: from:%d vmid:%d auth:%d mp:%d img: %#zx/%#zx dt: %#zx/%#zx\n",
	    client_id, req->target, req->auth_type, req->image_mp_handle,
	    req->image_offset, req->image_size, req->dt_offset, req->dt_size);
	vm_t *vm = vm_lookup(req->target);
	if (vm == NULL) {
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if (client_id != vm->owner) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (!vm_mgnt_state_change_valid(vm, VM_STATE_AUTH)) {
		ret = RM_ERROR_VM_STATE;
		goto out;
	}
	vm_auth_type_t auth;
	if (req->auth_type == 0U) {
		auth = VM_AUTH_TYPE_NONE;
	} else if (req->auth_type == 1U) {
		auth = VM_AUTH_TYPE_PLATFORM;
	} else if (req->auth_type == 2U) {
		auth = VM_AUTH_TYPE_ANDROID;
	} else {
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	ret = vm_creation_config_image(vm, auth, req->image_mp_handle,
				       req->image_offset, req->image_size,
				       req->dt_offset, req->dt_size);
	if (ret != RM_OK) {
		vm->vm_state = VM_STATE_INIT_FAILED;
		goto out_send_state;
	}

	switch (req->auth_type) {
	case (uint8_t)VM_AUTH_TYPE_NONE:
		// Image is not authenticated at all.
		vm->vm_state = VM_STATE_INIT;
		break;
	case (uint8_t)VM_AUTH_TYPE_ANDROID:
		// Authentication is done via DICE in the firmware image;
		// nothing is needed from RM.
		vm->vm_state = VM_STATE_INIT;
		break;
	case (uint8_t)VM_AUTH_TYPE_PLATFORM:
		vm->vm_state = VM_STATE_AUTH;
		break;
	default:
		vm->vm_state = VM_STATE_INIT_FAILED;
		break;
	}

out_send_state:
	vm_mgnt_send_state(vm);
out:
	return ret;
}

rm_error_t
vm_creation_auth(vm_t *vm, count_t num_auth_params,
		 vm_auth_param_t *auth_params)
{
	rm_error_t ret;

	switch (vm->auth_type) {
	case VM_AUTH_TYPE_PLATFORM:
		ret = platform_vm_auth(vm, num_auth_params, auth_params);
		break;
	case VM_AUTH_TYPE_ANDROID:
	case VM_AUTH_TYPE_NONE:
	default:
		ret = RM_ERROR_ARGUMENT_INVALID;
		break;
	}

	return ret;
}

static rm_error_t
vm_creation_handle_auth(vmid_t client_id, void *buf, size_t len)
{
	rm_error_t ret;

	// FIXME: make these checks more generic
	if (client_id != VMID_HLOS) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	vm_auth_req_t *req = (vm_auth_req_t *)buf;
	if (len < sizeof(*req)) {
		LOG("VM_AUTH_IMAGE: from:%d truncated, length %zd < %zd\n",
		    client_id, len, sizeof(*req));
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_auth_param_t *auth_params = (vm_auth_param_t *)(void *)(req + 1U);
	size_t auth_params_size = req->num_auth_params * sizeof(auth_params[0]);
	if (len != (sizeof(*req) + auth_params_size)) {
		LOG("VM_AUTH_IMAGE: from:%d truncated, length %zd expected %zd (num %d)\n",
		    client_id, len, sizeof(*req) + auth_params_size,
		    req->num_auth_params);
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	LOG("VM_AUTH_IMAGE: from:%d vmid:%d\n", client_id, req->target);
	vm_t *vm = vm_lookup(req->target);
	if (vm == NULL) {
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if (client_id != vm->owner) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (vm->vm_state != VM_STATE_AUTH) {
		ret = RM_ERROR_VM_STATE;
		goto out;
	}

	ret = vm_creation_auth(vm, req->num_auth_params, auth_params);
	if (ret != RM_OK) {
		vm->vm_state = VM_STATE_INIT_FAILED;
	} else {
		vm->vm_state = VM_STATE_INIT;
	}
	vm_mgnt_send_state(vm);

out:
	return ret;
}

static rm_error_t
vm_creation_handle_init(vmid_t client_id, void *buf, size_t len)
{
	rm_error_t ret;

	// FIXME: make these checks more generic
	if (client_id != VMID_HLOS) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	vm_init_req_t *req = (vm_init_req_t *)buf;
	if ((len != sizeof(*req)) || (req->res0 != 0U)) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	LOG("VM_INIT: from:%d vmid:%d\n", client_id, req->target);
	vm_t *vm = vm_lookup(req->target);
	if (vm == NULL) {
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if (client_id != vm->owner) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (vm->vm_state != VM_STATE_INIT) {
		ret = RM_ERROR_VM_STATE;
		goto out;
	}

	ret = vm_creation_init(vm);
	if (ret != RM_OK) {
		vm->vm_state = VM_STATE_INIT_FAILED;
	} else {
		vm->vm_state = VM_STATE_READY;
	}

	vm_mgnt_send_state(vm);

out:
	return ret;
}

static rm_error_t
vm_creation_set_boot_context(vmid_t client_id, void *buf, size_t len)
{
	rm_error_t	   ret;
	vm_boot_ctx_req_t *req = (vm_boot_ctx_req_t *)buf;

	if ((len != sizeof(*req)) || (req->res0 != 0U)) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	LOG("VM_SET_CONTEXT: from:%d, vmid:%d, reg_set:%d, index:%d\n",
	    client_id, req->target, req->arch_reg_set, req->reg_index);

	vm_t *vm = vm_lookup(req->target);
	if (vm == NULL) {
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if (client_id != vm->owner) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (vm->vm_state != VM_STATE_READY) {
		ret = RM_ERROR_VM_STATE;
		goto out;
	}

	ret = vm_firmware_set_boot_context(vm, req);
out:
	if (ret != RM_OK) {
		LOG("VM_SET_CONTEXT: failed %d from:%d vmid:%d\n", ret,
		    client_id, req->target);
	}
	return ret;
}

bool
vm_reset_handle_destroy(vm_t *vm)
{
	svm_takedown(vm->vmid);
	svm_destroy(vm->vmid);

	return true;
}

bool
vm_reset_handle_cleanup(vm_t *vm)
{
	(void)strlcpy(vm->name, "", VM_MAX_NAME_LEN);
	vm->name_len = 0U;
	(void)strlcpy(vm->uri, "", VM_MAX_URI_LEN);
	vm->uri_len = 0U;
	(void)memset(vm->guid, 0, VM_GUID_LEN);

	vm->os_state   = OS_STATE_NONE;
	vm->app_status = 0U;

	assert(vm->vm_config == NULL);
	assert(vm->as_allocator == NULL);

	vm->mem_mp_handle = 0U;
	vm->mem_size	  = 0U;

	vm->ramfs_offset = 0U;
	vm->ramfs_size	 = 0U;

	vm->mem_mp_handle = 0U;

	vm->entry_offset = 0U;

	vm->dt_offset = 0U;
	vm->dt_size   = 0U;

	vm->chip_id	     = 0U;
	vm->chip_version     = 0U;
	vm->foundry_id	     = 0U;
	vm->platform_type    = 0U;
	vm->platform_version = 0U;
	vm->platform_subtype = 0U;
	vm->hlos_subtype     = 0U;

	vm->priority = SCHEDULER_DEFAULT_PRIORITY;

	assert(!event_is_registered(&vm->wdog_bite_event));

	vm_mgnt_clear_crash_msg(vm->vmid);

	// vm_reset_* should not be modified since we are currently handling it!

	return true;
}

bool
vm_creation_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len)
{
	bool	   handled = false;
	rm_error_t err	   = RM_ERROR_UNIMPLEMENTED;

	switch (msg_id) {
	case VM_CONFIG_IMAGE:
		err	= vm_creation_handle_config(client_id, buf, len);
		handled = true;
		break;
	case VM_AUTH_IMAGE:
		err	= vm_creation_handle_auth(client_id, buf, len);
		handled = true;
		break;
	case VM_INIT:
		err	= vm_creation_handle_init(client_id, buf, len);
		handled = true;
		break;
	case VM_SET_CONTEXT:
		err	= vm_creation_set_boot_context(client_id, buf, len);
		handled = true;
		break;
	default:
		// all VM creation msg_id handled
		break;
	}

	if (handled) {
		rm_standard_reply(client_id, msg_id, seq_num, err);
	}

	return handled;
}

uintptr_result_t
map_dtb(size_t dtb_offset, size_t dtb_size, uint32_t mp_handle, size_t ipa_size)
{
	uintptr_result_t ret;

	if (util_add_overflows(dtb_offset, dtb_size - 1U)) {
		ret = uintptr_result_error(ERROR_ADDR_OVERFLOW);
		goto out;
	}

	if ((dtb_offset > ipa_size) || (dtb_size > (ipa_size - dtb_offset))) {
		ret = uintptr_result_error(ERROR_ADDR_INVALID);
		goto out;
	}

	ret = memparcel_map_rm(mp_handle, dtb_offset, dtb_size);
	if (ret.e != OK) {
		(void)printf("map_dtb: memparcel_map_rm failed\n");
		goto out;
	}
	uintptr_t vaddr	       = ret.r;
	void	 *temp_dtb_ptr = (void *)vaddr;

	// Flush the cache, to ensure that the VM loader can't change the DT
	// structure underneath us by providing a deliberately cache-dirty DT
	cache_flush_by_va(temp_dtb_ptr, fdt_header_size(temp_dtb_ptr));

	if (fdt_check_header(temp_dtb_ptr) != 0) {
		(void)printf("map_dtb: invalid dtb\n");
		ret = uintptr_result_error(ERROR_ARGUMENT_INVALID);
		goto out_unmap;
	}

	size_t fdt_size = fdt_totalsize(temp_dtb_ptr);
	if (fdt_size > dtb_size) {
		(void)printf(
			"map_dtb: fdt_totalsize (%zu) > DTB region size(%zu)\n",
			fdt_size, dtb_size);
		ret = uintptr_result_error(ERROR_ARGUMENT_INVALID);
		goto out_unmap;
	}

	cache_flush_by_va(temp_dtb_ptr, fdt_size);

out_unmap:
	if (ret.e != OK) {
		error_t res = memparcel_unmap_rm(mp_handle);
		if (res != OK) {
			LOG_ERR(res);
		}
	}
out:
	if (ret.e != OK) {
		(void)printf("map_dtb(%zu, %zu) : failed, ret=%" PRId32 "\n",
			     dtb_offset, dtb_size, (int32_t)ret.e);
	}
	return ret;
}

error_t
unmap_dtb(uint32_t mp_handle)
{
	error_t unmap_err = memparcel_unmap_rm(mp_handle);
	return unmap_err;
}

static error_t
process_dtb(vm_t *vm)
{
	error_t ret;
	error_t err = OK;

	assert(vm != NULL);

	size_t	 ipa_size  = vm->mem_size;
	size_t	 dt_offset = vm->dt_offset;
	size_t	 dt_size   = vm->dt_size;
	uint32_t mp_handle = vm->mem_mp_handle;

	uintptr_result_t map_ret =
		map_dtb(dt_offset, dt_size, mp_handle, ipa_size);
	ret = map_ret.e;
	if (ret != OK) {
		(void)printf("map_dtb: ret %d\n", ret);
		goto out_unmapped;
	}
	uintptr_t temp_addr    = map_ret.r;
	void	 *temp_dtb_ptr = (void *)temp_addr;

	// NOTE: integrate with vm config, generate dtbo.
	create_dtbo_ret_t dtbo_ret = create_dtbo(vm, temp_dtb_ptr);
	if (dtbo_ret.err != OK) {
		ret = dtbo_ret.err;
		(void)printf("create_dtbo: ret %d\n", ret);
		goto out;
	}

	void *dtb_process_buf = NULL;
	bool  dtb_buf_alloc   = false;

	// Estimate a final dtb size after applying the overlay.
	size_t original_dtb_size =
		util_balign_up(fdt_totalsize(temp_addr), sizeof(uint32_t));
	size_t final_dtb_size = original_dtb_size + dtbo_ret.size;

	// If the estimated size is small enough, we can just allocate a buffer
	// for processing the DTB.
	size_t max_dtb_size = MAX_DTB_ALLOC_SIZE;
	if (final_dtb_size <= max_dtb_size) {
		dtb_process_buf = calloc(1U, max_dtb_size);
		if (dtb_process_buf != NULL) {
			dtb_buf_alloc = true;
		}
	}

	if (!dtb_buf_alloc) {
#if VM_CREATION_VERBOSE_DEBUG
		(void)printf("Unable to allocate DTB buffer, using DTB "
			     "region instead\n");
#endif

		// RM's heap is not large enough to allocate a buffer for DTB
		// processing, so we attempt to use the space in the VM's DTB
		// region following the original DTB.
		size_t offset = final_dtb_size;
		if (util_add_overflows(offset, final_dtb_size) ||
		    ((offset + final_dtb_size) > dt_size)) {
			(void)printf(
				"process_dtb: DTB region too small: %zu bytes, need %zu",
				dt_size, offset + final_dtb_size);
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}

		max_dtb_size	= offset;
		dtb_process_buf = (void *)(temp_addr + offset);
	}

	assert(final_dtb_size <= max_dtb_size);
	assert(dtb_process_buf != NULL);

	int open_ret =
		fdt_open_into(temp_dtb_ptr, dtb_process_buf, (int)max_dtb_size);
	if (open_ret != 0) {
		(void)printf("fdt_open_into ret=%d\n", open_ret);
		ret = ERROR_DENIED;
		goto out;
	}

	// apply dtbo to dt
	int apply_ret = fdt_overlay_apply(dtb_process_buf, dtbo_ret.dtbo);
	if (apply_ret != 0) {
		(void)printf("Error: Failed to apply DT overlay, ret=(%d)\n",
			     apply_ret);
		ret = ERROR_DENIED;
		goto out;
	}

	(void)fdt_pack(dtb_process_buf);

	size_t total_size = fdt_totalsize(dtb_process_buf);
	assert(total_size <= max_dtb_size);

	(void)memscpy(temp_dtb_ptr, dt_size, dtb_process_buf, total_size);
	cache_clean_by_va(temp_dtb_ptr, total_size);

	if (dtb_buf_alloc) {
		free(dtb_process_buf);
	}

	dto_deinit(dtbo_ret.constructed_object);

out:
	// unmap dtb from rm
	err = unmap_dtb(mp_handle);
	if ((ret == OK) && (err != OK)) {
		(void)printf("unmap_dtb: ret %d\n", ret);
		ret = err;
	}
out_unmapped:
	if (ret != OK) {
		(void)printf("process_dtb failed, ret = %" PRId32 "\n",
			     (int32_t)ret);
	}
	return ret;
}

static error_t
write_buffer_reg(dto_t *dto, memparcel_t *mp, vmid_t vmid, count_t addr_cells,
		 count_t size_cells)
{
	error_t ret = OK;

	count_result_t map_count = memparcel_get_num_mappings(mp, vmid);
	if (map_count.e != OK) {
		ret = map_count.e;
		goto out;
	}

	dto_addrrange_t *ranges = calloc(sizeof(dto_addrrange_t), map_count.r);
	if (ranges == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	for (index_t i = 0; i < map_count.r; ++i) {
		vmaddr_result_t ipa_ret = memparcel_get_mapped_ipa(mp, vmid, i);
		if (ipa_ret.e != OK) {
			ret = ipa_ret.e;
			goto out_free;
		}
		ranges[i].addr = ipa_ret.r;

		size_result_t size_ret = memparcel_get_mapped_size(mp, vmid, i);
		if (size_ret.e != OK) {
			ret = size_ret.e;
			goto out_free;
		}
		ranges[i].size = size_ret.r;
	}

	ret = dto_property_add_addrrange_array(dto, "reg", ranges, map_count.r,
					       addr_cells, size_cells);

out_free:
	free(ranges);
out:
	return ret;
}

static error_t
vdev_node_add_compatible_string(dto_t *dto, vmid_t vmid, label_t label)
{
	error_t ret;

	vm_t *cur_vm = vm_lookup(vmid);
	assert(cur_vm != NULL);
	assert(cur_vm->vm_config != NULL);

	count_t compatible_cnt = 0U;

	const char *compatibles[VDEVICE_MAX_PUSH_COMPATIBLES] = { NULL };

	vdevice_node_t *node = NULL;
	loop_list(node, &cur_vm->vm_config->vdevice_nodes, vdevice_)
	{
		if (!node->export_to_dt) {
			continue;
		}

		if (node->type == VDEV_SHM) {
			struct vdevice_shm *cfg = node->config.shm;
			if (cfg->label == label) {
				compatible_cnt = node->push_compatible_num;
				(void)memscpy(&compatibles, sizeof(compatibles),
					      &node->push_compatible,
					      sizeof(node->push_compatible));
				break;
			}
		} else if (node->type == VDEV_VIRTIO_MMIO) {
			struct vdevice_virtio_mmio *cfg =
				node->config.virtio_mmio;
			if (cfg->label == label) {
				compatible_cnt = node->push_compatible_num;
				(void)memscpy(&compatibles, sizeof(compatibles),
					      &node->push_compatible,
					      sizeof(node->push_compatible));
				break;
			}
		} else {
			// no other vdevice types to be considered
		}
	}

	if (compatible_cnt != 0U) {
		assert(compatible_cnt <= VDEVICE_MAX_PUSH_COMPATIBLES);
		ret = dto_property_add_stringlist(dto, "compatible",
						  compatibles, compatible_cnt);
	} else {
		(void)printf("warning: no vdevice found with label %x\n",
			     label);
		ret = OK;
	}

	return ret;
}

static error_t
create_reserved_buffer_node(dto_t *dto, vmid_t vmid, memparcel_t *mp,
			    count_t root_addr_cells, count_t root_size_cells)
{
	error_t ret = OK;

	// The mp should have been accepted
	if (!memparcel_is_shared(mp, vmid)) {
		(void)printf("%s: memparcel %#" PRIx32 " @ %#" PRIx64
			     " has not been mapped\n",
			     __func__, memparcel_get_handle(mp),
			     memparcel_get_phys(mp, 0U).r);
		goto out;
	}

	label_t label = memparcel_get_label(mp);

	mem_handle_t rm_handle = memparcel_get_handle(mp);

	vmaddr_result_t ipa_ret = memparcel_get_mapped_ipa(mp, vmid, 0);
	if (ipa_ret.e != OK) {
		ret = ipa_ret.e;
		goto out;
	}

	// create node now
	char	name[DTB_NODE_NAME_MAX];
	int32_t snprintf_ret =
		snprintf(name, DTB_NODE_NAME_MAX, "buffer@%lx", ipa_ret.r);

	if ((snprintf_ret < 0) ||
	    (snprintf_ret >= (int32_t)DTB_NODE_NAME_MAX)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	vector_t *vmids = vector_init(vmid_t, 1, 8);
	if (vmids == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	ret = memparcel_get_shared_vmids(mp, vmids);
	if (ret != OK) {
		goto out_vmids;
	}

	// create node here:
	ret = dto_node_begin(dto, name);
	if (ret != OK) {
		goto out_vmids;
	}

	ret = write_buffer_reg(dto, mp, vmid, root_addr_cells, root_size_cells);
	if (ret != OK) {
		goto out_node_end;
	}

	ret = dto_property_add_empty(dto, "qcom,shared-memory");
	if (ret != OK) {
		goto out_node_end;
	}

	ret = dto_property_add_empty(dto, "no-map");
	if (ret != OK) {
		goto out_node_end;
	}

	// static check?
	assert(sizeof(vmid_t) < sizeof(fdt32_t));

	size_t vmid_cnt = vector_size(vmids);

	uint8_t *blob = calloc(sizeof(fdt32_t), vmid_cnt);
	if (blob == NULL) {
		ret = ERROR_NOMEM;
		goto out_node_end;
	}

	uint8_t *cur = blob;
	for (index_t i = 0; i < vmid_cnt; ++i) {
		vmid_t id = vector_at(vmid_t, vmids, i);
		fdt32_st(cur, id);
		cur += sizeof(fdt32_t);
	}

	ret = dto_property_add_blob(dto, "peers", blob,
				    (count_t)(sizeof(fdt32_t) * vmid_cnt));
	if (ret != OK) {
		goto out_free_blob;
	}

	ret = dto_property_add_u32(dto, "qcom,rm-mem-handle", rm_handle);
	if (ret != OK) {
		goto out_free_blob;
	}

	uint32_t phandle = 0U;

	ret = dto_property_add_phandle(dto, &phandle);
	if (ret != OK) {
		goto out_free_blob;
	}

	ret = dto_property_add_u32(dto, "qcom,label", label);
	if (ret != OK) {
		goto out_free_blob;
	}

	memparcel_set_phandle(mp, vmid, phandle, false);

	// get pushed-compatibles and add it
	// Find the SHM node
	ret = vdev_node_add_compatible_string(dto, vmid, label);
	if (ret != OK) {
		goto out_free_blob;
	}

out_free_blob:
	free(blob);
out_node_end:
	// no way to recover it
	(void)0;
	error_t dto_ret = dto_node_end(dto, name);
	if (dto_ret != OK) {
		LOG_ERR(dto_ret);
	}
out_vmids:
	vector_deinit(vmids);
out:
	return ret;
}

static error_t
create_reserved_firmware_node(dto_t *dto, vm_t *vm, count_t root_addr_cells,
			      count_t root_size_cells)
{
	error_t ret = OK;

	vmaddr_t fw_ipa = vm->vm_config->fw_ipa_base + vm->fw_offset;

	// create node now
	char	name[DTB_NODE_NAME_MAX];
	int32_t snprintf_ret =
		snprintf(name, DTB_NODE_NAME_MAX, "firmware@%lx", fw_ipa);

	if ((snprintf_ret < 0) ||
	    (snprintf_ret >= (int32_t)DTB_NODE_NAME_MAX)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	ret = dto_node_begin(dto, name);
	if (ret != OK) {
		goto out;
	}

	ret = dto_property_add_addrrange(dto, "reg", root_addr_cells, fw_ipa,
					 root_size_cells, vm->fw_size);
	if (ret != OK) {
		goto out_node_end;
	}

	ret = dto_property_add_empty(dto, "no-map");
	if (ret != OK) {
		goto out_node_end;
	}

	const char *compatibles[] = { "qcom,vm-firmware" };

	ret = dto_property_add_stringlist(
		dto, "compatible", compatibles,
		(count_t)util_array_size(compatibles));
	if (ret != OK) {
		LOG_ERR(ret);
	}

out_node_end:
	// no way to recover it
	(void)0;
	error_t dto_ret = dto_node_end(dto, name);
	if (dto_ret != OK) {
		LOG_ERR(dto_ret);
	}
out:
	return ret;
}

static error_t
create_resmem_nodes(dto_t *dto, vmid_t vmid, count_t root_addr_cells,
		    count_t root_size_cells)
{
	error_t ret;

	vm_t *cur_vm = vm_lookup(vmid);
	assert(cur_vm != NULL);
	assert(cur_vm->vm_config != NULL);

	memparcel_t *mp;
	foreach_memparcel_by_target_vmid (mp, vmid) {
		assert(mp != NULL);

		// If this is the firmware memory memparcel, don't create a
		// reserved-memory node for it. The firmware's reserved-memory
		// node is created separately below, because it does not
		// necessarily cover a whole memparcel and may be within the
		// private memory range.
		if (memparcel_get_handle(mp) == cur_vm->fw_mp_handle) {
			continue;
		}

		// Auto-accept memparcel if it hasn't been accepted already.
		// Note that this will never choose an address within the
		// private memory IPA range.
		if (!memparcel_is_shared(mp, vmid)) {
			error_t accept_err = accept_memparcel(vmid, mp);
			if (accept_err != OK) {
				continue;
			}
		}

		// Skip any IO device memparcels
		bool		skip_iomem_mp = false;
		vdevice_node_t *node	      = NULL;
		loop_list(node, &cur_vm->vm_config->vdevice_nodes, vdevice_)
		{
			if (node->type == VDEV_IOMEM) {
				struct vdevice_iomem *cfg = node->config.iomem;
				if (memparcel_get_label(mp) == cfg->label) {
					skip_iomem_mp = true;
				}
			}
		}

		if (skip_iomem_mp) {
			continue;
		}

		// If this is a private normal memory memparcel, don't create a
		// reserved-memory node for it. The check for this is simple
		// because getting it wrong can't compromise the VM; it will
		// only reduce the available private memory.
		if (memparcel_is_private(mp, vmid)) {
#if VM_CREATION_VERBOSE_DEBUG
			vmaddr_result_t ipa_ret =
				memparcel_get_mapped_ipa(mp, vmid, 0U);
			assert(ipa_ret.e == OK);
			(void)printf("memparcel %#" PRIx32 " (%#" PRIx32 ")"
				     " is private memory: %#zx (%#zx)\n",
				     memparcel_get_handle(mp),
				     memparcel_get_label(mp), ipa_ret.r,
				     memparcel_get_size(mp));
#endif
			continue;
		}

		// If there was a node statically configured in the base
		// device tree, don't create a new one
		if (memparcel_get_phandle(mp, vmid, NULL) !=
		    DTO_PHANDLE_UNSET) {
#if VM_CREATION_VERBOSE_DEBUG
			(void)printf("resmem: memparcel label %#" PRIx32
				     " already has a node\n",
				     memparcel_get_label(mp));
#endif
			continue;
		}

		// create node
		error_t create_err = create_reserved_buffer_node(
			dto, vmid, mp, root_addr_cells, root_size_cells);
		if (create_err != OK) {
			ret = create_err;
			goto out;
		}

#if VM_CREATION_VERBOSE_DEBUG
		vmaddr_result_t ipa_ret =
			memparcel_get_mapped_ipa(mp, vmid, 0U);
		assert(ipa_ret.e == OK);
		(void)printf("resmem: memparcel %#" PRIx32 " (%#" PRIx32 ")"
			     " added: %#zx (%#zx)\n",
			     memparcel_get_handle(mp), memparcel_get_label(mp),
			     ipa_ret.r, memparcel_get_size(mp));
#endif
	}

	if (cur_vm->fw_size != 0U) {
		error_t create_err = create_reserved_firmware_node(
			dto, cur_vm, root_addr_cells, root_size_cells);
		if (create_err != OK) {
			ret = create_err;
			goto out;
		}
	}

	ret = OK;
out:
	return ret;
}

static error_t
merged_memory_ranges(dto_t *dto, vmid_t vmid, count_t root_addr_cells,
		     count_t root_size_cells, const dto_addrrange_t *ranges,
		     count_t range_count)
{
	error_t ret;

	// Merge contiguous or overlapping ranges into a single range.
	//
	// The device tree specification does not require this, but some VMs
	// rely on it, including the Android pVM firmware.
	dto_addrrange_t *merged_ranges =
		calloc(sizeof(dto_addrrange_t), range_count);
	if (merged_ranges == NULL) {
		ret = ERROR_NOMEM;
		goto out_merged;
	}
	count_t merged_range_count = 0U;

	if (range_count > 0U) {
		merged_ranges[0] = ranges[0];
		merged_range_count++;
	}

	dto_addrrange_t *merged_range = &merged_ranges[0];
	for (count_t i = 1U; i < range_count; i++) {
		if (util_add_overflows(merged_range->addr,
				       merged_range->size)) {
			// Should be impossible
			ret = ERROR_FAILURE;
		}

		// If the previous range extends to or past the next range, they
		// are contiguous or overlapping. We're relying here on the
		// ranges having been sorted above.
		if ((merged_range->addr + merged_range->size) >=
		    ranges[i].addr) {
			merged_range->size =
				util_max(merged_range->size,
					 ranges[i].addr + ranges[i].size -
						 merged_range->addr);
		} else {
			merged_range++;
			merged_range->addr = ranges[i].addr;
			merged_range->size = ranges[i].size;
			merged_range_count++;
		}
	}

	(void)printf("VM %d has %d contiguous memory range(s):\n", vmid,
		     merged_range_count);
	for (count_t i = 0U; i < merged_range_count; i++) {
		(void)printf("\tbase: %#08zx size: %#08zx\n",
			     (size_t)merged_ranges[i].addr,
			     (size_t)merged_ranges[i].size);
	}

	ret = dto_node_begin(dto, "memory");
	if (ret != OK) {
		goto out_merged;
	}

	ret = dto_property_add_string(dto, "device_type", "memory");
	if (ret != OK) {
		goto out_merged;
	}

	ret = dto_property_add_addrrange_array(dto, "reg", merged_ranges,
					       merged_range_count,
					       root_addr_cells,
					       root_size_cells);
	if (ret != OK) {
		goto out_merged;
	}

	ret = dto_node_end(dto, "memory");
	if (ret != OK) {
		goto out_merged;
	}

out_merged:
	free(merged_ranges);
	return ret;
}

static error_t
update_range_array(vmid_t vmid, const memparcel_t *mp, count_t *range_count_ptr,
		   count_t *ranges_size_ptr, dto_addrrange_t **ranges_ptr)
{
	error_t		 ret	     = OK;
	count_t		 range_count = *range_count_ptr;
	count_t		 ranges_size = *ranges_size_ptr;
	dto_addrrange_t *ranges	     = *ranges_ptr;

	count_result_t map_count = memparcel_get_num_mappings(mp, vmid);
	if (map_count.e != OK) {
		ret = map_count.e;
		goto out;
	}

	if (util_add_overflows(map_count.r, range_count)) {
		// Should be impossible
		ret = ERROR_FAILURE;
		goto out;
	}

	// Enlarge the range array if necessary
	if ((map_count.r + range_count) > ranges_size) {
		count_t new_size =
			util_max(ranges_size * 2U, (map_count.r + range_count));
		if (util_mult_integer_overflows(new_size,
						sizeof(dto_addrrange_t))) {
			ret = ERROR_NORESOURCES;
			goto out;
		}

		dto_addrrange_t *new_ranges =
			realloc(ranges, new_size * sizeof(dto_addrrange_t));
		if (new_ranges == NULL) {
			ret = ERROR_NOMEM;
			goto out;
		}
		for (count_t i = ranges_size; i < new_size; i++) {
			new_ranges[i] = (dto_addrrange_t){ 0 };
		}
		ranges_size = new_size;
		ranges	    = new_ranges;
	}

	// Fill in the range array
	for (count_t i = 0U; i < map_count.r; i++) {
		vmaddr_result_t ipa_ret = memparcel_get_mapped_ipa(mp, vmid, i);
		if (ipa_ret.e != OK) {
			ret = ipa_ret.e;
			goto out;
		}
		ranges[range_count + i].addr = ipa_ret.r;

		size_result_t size_ret = memparcel_get_mapped_size(mp, vmid, i);
		if (size_ret.e != OK) {
			ret = size_ret.e;
			goto out;
		}
		ranges[range_count + i].size = size_ret.r;
	}
	range_count += map_count.r;

out:
	*range_count_ptr = range_count;
	*ranges_size_ptr = ranges_size;
	*ranges_ptr	 = ranges;
	return ret;
}

static error_t
create_memory_node(dto_t *dto, vmid_t vmid, count_t root_addr_cells,
		   count_t root_size_cells)
{
	error_t ret;
	vm_t   *cur_vm = vm_lookup(vmid);
	assert(cur_vm != NULL);
	assert(cur_vm->vm_config != NULL);

	size_t paged_ranges =
		cur_vm->vm_config->mem_demand_paging
			? vector_size(
				  cur_vm->vm_config->mem_demand_paged_ranges)
			: 0U;
	count_t ranges_size = util_max((count_t)paged_ranges, 16U);

	dto_addrrange_t *ranges = calloc(sizeof(dto_addrrange_t), ranges_size);
	if (ranges == NULL) {
		ret = ERROR_NOMEM;
		goto out_nomem;
	}

	for (index_t i = 0U; i < paged_ranges; i++) {
		struct mem_range *r = vector_at_ptr(
			struct mem_range,
			cur_vm->vm_config->mem_demand_paged_ranges, i);
		ranges[i].addr = r->base;
		ranges[i].size = r->size;
	}
	count_t range_count = (count_t)paged_ranges;

	memparcel_t *mp;
	foreach_memparcel_by_target_vmid (mp, vmid) {
		// Skip anything not already accepted
		if (!memparcel_is_shared(mp, vmid)) {
			continue;
		}

		// Skip the firmware memparcel if it is separate
		if ((cur_vm->fw_mp_handle != cur_vm->mem_mp_handle) &&
		    (memparcel_get_handle(mp) == cur_vm->fw_mp_handle)) {
			continue;
		}

		// Skip any IO device memparcels
		bool		skip_iomem_mp = false;
		vdevice_node_t *node	      = NULL;
		loop_list(node, &cur_vm->vm_config->vdevice_nodes, vdevice_)
		{
			if (node->type == VDEV_IOMEM) {
				struct vdevice_iomem *cfg = node->config.iomem;
				if (memparcel_get_label(mp) == cfg->label) {
					skip_iomem_mp = true;
				}
			}
		}
		if (skip_iomem_mp) {
			continue;
		}

		ret = update_range_array(vmid, mp, &range_count, &ranges_size,
					 &ranges);
		if (ret != OK) {
			goto out;
		}
	}

	// Sort the range array by address. The number of ranges should be
	// relatively small, so we use a trivial bubble sort to keep the code
	// simple while avoiding qsort() (prohibited by MISRA rule 21.9).
	//
	// The device tree specification does not require this, but some VMs
	// rely on it, including the Android pVM firmware.
	for (count_t i = range_count; i > 1U; i--) {
		for (count_t j = 0U; j < (i - 1U); j++) {
			if (ranges[j].addr > ranges[j + 1U].addr) {
				dto_addrrange_t tmp = ranges[j];
				ranges[j]	    = ranges[j + 1U];
				ranges[j + 1U]	    = tmp;
			}
		}
	}

	ret = merged_memory_ranges(dto, vmid, root_addr_cells, root_size_cells,
				   ranges, range_count);

out:
	free(ranges);
out_nomem:
	return ret;
}

static bool
accept_memparcel_for_resmem_node(vmid_t vmid, memparcel_t *mp, const char *name,
				 sgl_entry_t *sgl, uint16_t sgl_len)
{
	bool success;

	uint8_t flags = MEM_ACCEPT_FLAG_DONE;

	vmid_t owner = memparcel_get_owner(mp);

	bool owner_is_sensitive = vm_mgnt_is_vm_sensitive(owner);

	uint8_result_t owner_rights_ret = memparcel_get_vm_rights(mp, owner);

	// owner doesn't need to access buffer if it's
	// not in the ACL
	bool owner_has_read =
		(owner_rights_ret.e == OK)
			? ((owner_rights_ret.r & MEM_RIGHTS_R) != 0U)
			: (bool)false;

	uint8_result_t vm_rights_ret = memparcel_get_vm_rights(mp, vmid);
	if (vm_rights_ret.e != OK) {
		(void)printf("error: %s: mp for %s has no VMID %d in ACL\n",
			     __func__, name, vmid);
		success = false;
		goto out;
	}

	bool vm_has_write = ((vm_rights_ret.r & MEM_RIGHTS_W) != 0U);

	bool vm_is_sensitive = vm_mgnt_is_vm_sensitive(vmid);

	if (vm_is_sensitive && vm_has_write &&
	    (!owner_has_read || owner_is_sensitive)) {
		flags |= MEM_ACCEPT_FLAG_SANITIZE;
	}

	rm_error_t rm_err = memparcel_accept(vmid, 0U, sgl_len, 0U, NULL, sgl,
					     NULL, 0U, memparcel_get_handle(mp),
					     0U, memparcel_get_mem_type(mp),
					     memparcel_get_trans_type(mp),
					     flags);
	if (rm_err != RM_OK) {
		(void)printf("error: %s: accept failed (%d)", __func__, rm_err);
		success = false;
		goto out;
	}

	success = true;

out:
	return success;
}

static memparcel_t *
find_memparcel_for_resmem_node_by_label(vmid_t vmid, const void *base_dtb,
					int region_node, const char *name,
					ctx_t ctx, label_t label)
{
	memparcel_t *ret = NULL;

	sgl_entry_t sgl[1]  = { 0 };
	uint16_t    sgl_len = 0U;

	// Read the address range. If not supplied, we allocate an address at
	// memparcel accept time.
	int	       len;
	const fdt32_t *reg = fdt_getprop(base_dtb, region_node, "reg", &len);
	if (reg != NULL) {
		assert(len >= 0);

		count_t cells = ctx.child_addr_cells + ctx.child_size_cells;
		size_t	expected_len = sizeof(fdt32_t) * cells;
		if ((size_t)len != expected_len) {
			// TODO: Support multiple-range reserved memory nodes
			(void)printf(
				"Bad \"reg\" in /reserved-memory/%s; len %zd != %zd\n",
				name, (size_t)len, expected_len);
			goto out;
		}

		// Reg property is valid. Parse the address and size.
		vmaddr_t base =
			(vmaddr_t)fdt_read_num(&reg[0], ctx.child_addr_cells);
		size_t size = (size_t)fdt_read_num(&reg[ctx.child_addr_cells],
						   ctx.child_size_cells);
		if ((size == 0U) || util_add_overflows(base, size - 1U)) {
			(void)printf(
				"Bad \"reg\" in /reserved-memory/%s; size %#zx\n",
				name, size);
			goto out;
		}

		sgl[0].ipa  = base;
		sgl[0].size = size;
		sgl_len	    = 1U;
	}

	(void)printf("Patching /reserved-memory/%s (label %#" PRIx32 ")\n",
		     name, label);

	// Search all memparcels by label
	memparcel_t *mp;
	foreach_memparcel_by_target_vmid (mp, vmid) {
		if (memparcel_get_label(mp) != label) {
			continue;
		}

		if (!memparcel_is_shared(mp, vmid)) {
			// Memparcel is not accepted yet; try to accept it with
			// the resmem node's specified address, or allocate an
			// address for it.
			if (accept_memparcel_for_resmem_node(vmid, mp, name,
							     sgl, sgl_len)) {
				ret = mp;
			}
		} else if (sgl_len != 0U) {
			// Ensure the memparcel was mapped at the given address.
			// TODO: support non-contiguous mappings.
			count_result_t map_count =
				memparcel_get_num_mappings(mp, vmid);
			if ((map_count.e != OK) || (map_count.r != 1U)) {
				goto out;
			}

			vmaddr_result_t ipa_ret =
				memparcel_get_mapped_ipa(mp, vmid, 0U);
			size_result_t size_ret =
				memparcel_get_mapped_size(mp, vmid, 0U);
			if ((ipa_ret.e == OK) && (ipa_ret.r == sgl[0].ipa) &&
			    (size_ret.e == OK) && (size_ret.r == sgl[0].size)) {
				// Memparcel is mapped at the specified address.
				ret = mp;
			}
		} else {
			// Memparcel is mapped and no address was specified.
			ret = mp;
		}

		break;
	}

	if (ret == NULL) {
		(void)printf("No memparcel with a matching label!\n");
	}

out:
	return ret;
}

static memparcel_t *
find_memparcel_for_resmem_node_by_address(vmid_t vmid, const char *name,
					  vmaddr_t base, size_t size)
{
	memparcel_t *ret = NULL;

	vmaddr_t end = base + size - 1U;

	(void)printf(
		"Patching /reserved-memory/%s (no label, range %#zx-%#zx)\n",
		name, (size_t)base, (size_t)end);

	// Search already-accepted memparcels by address and size
	memparcel_t *mp;
	foreach_memparcel_by_target_vmid (mp, vmid) {
		if (!memparcel_is_shared(mp, vmid)) {
			continue;
		}

		// TODO: support non-contiguous mappings.
		count_result_t map_count = memparcel_get_num_mappings(mp, vmid);
		if ((map_count.e != OK) || (map_count.r != 1U)) {
			goto out;
		}

		vmaddr_result_t ipa_ret =
			memparcel_get_mapped_ipa(mp, vmid, 0U);
		size_result_t size_ret =
			memparcel_get_mapped_size(mp, vmid, 0U);
		if ((ipa_ret.e == OK) && (ipa_ret.r == base) &&
		    (size_ret.e == OK) && (size_ret.r == size)) {
			// Memparcel is mapped at the specified address.
			ret = mp;
			goto out;
		}
	}

out:
	return ret;
}

RM_PADDED(typedef struct dt_addrrange_result_s {
	vmaddr_t base;
	size_t	 size;
	error_t	 error;
} dt_addrrange_result_t)

static dt_addrrange_result_t
parse_resmem_addrrange(const void *base_dtb, int region_node, const char *name,
		       ctx_t ctx)
{
	dt_addrrange_result_t ret;

	// Read the address range
	int	       len;
	const fdt32_t *reg = fdt_getprop(base_dtb, region_node, "reg", &len);
	if (reg == NULL) {
		(void)printf("No \"reg\" property in /reserved-memory/%s\n",
			     name);
		ret = (dt_addrrange_result_t){
			.error = ERROR_ARGUMENT_INVALID,
		};
		goto out;
	}
	assert(len >= 0);

	count_t cells	     = ctx.child_addr_cells + ctx.child_size_cells;
	size_t	expected_len = sizeof(fdt32_t) * cells;
	if ((size_t)len != expected_len) {
		// TODO: Support multiple-range reserved memory nodes
		(void)printf(
			"Bad \"reg\" in /reserved-memory/%s; len %zd != %zd\n",
			name, (size_t)len, expected_len);
		ret = (dt_addrrange_result_t){
			.error = ERROR_ARGUMENT_INVALID,
		};
		goto out;
	}

	// Reg property is valid. Parse the address and size.
	vmaddr_t base = (vmaddr_t)fdt_read_num(&reg[0], ctx.child_addr_cells);
	size_t	 size = (size_t)fdt_read_num(&reg[ctx.child_addr_cells],
					     ctx.child_size_cells);
	if ((size == 0U) || util_add_overflows(base, size - 1U)) {
		(void)printf("Bad \"reg\" in /reserved-memory/%s; size %#zx\n",
			     name, size);
		ret = (dt_addrrange_result_t){
			.error = ERROR_ARGUMENT_INVALID,
		};
		goto out;
	}

	ret = (dt_addrrange_result_t){
		.error = OK,
		.base  = base,
		.size  = size,
	};
out:
	return ret;
}

static error_t
resmem_enable_demand_paging(const vm_t *vm, const void *base_dtb,
			    int region_node, vmaddr_t base, size_t size)
{
	error_t ret;

	assert((vm != NULL) && (vm->vm_config != NULL) &&
	       vm->vm_config->mem_demand_paging);
	assert(vm->vm_config->mem_demand_paged_ranges != NULL);

	// If the VM is protected and the memory is marked reusable, it must
	// be registered as a private range. Otherwise, it will be registered as
	// VMMIO, so the host can emulate accesses or map shared memory.
	bool is_private = vm->mem_private &&
			  fdt_getprop_bool(base_dtb, region_node, "reusable");

	ret = gunyah_hyp_addrspace_configure_range(
		vm->vm_config->addrspace, base, size,
		is_private ? ADDRSPACE_RANGE_CONFIGURE_OP_ADD_PRIVATE
			   : ADDRSPACE_RANGE_CONFIGURE_OP_ADD_VMMIO);
	if (ret == OK) {
		// Reserved memory regions must be added to the /memory node.
		struct mem_range range = { .base = base, .size = size };
		vector_push_back(vm->vm_config->mem_demand_paged_ranges, range);
	}

	return ret;
}

RM_PADDED(typedef struct memparcel_ptr_result_s {
	memparcel_t *r;
	error_t	     e;
} memparcel_ptr_result_t)

static memparcel_ptr_result_t
find_memparcel_for_resmem_node(const vm_t *vm, vmid_t vmid,
			       const void *base_dtb, int region_node,
			       const char *name, ctx_t resmem_ctx,
			       bool have_reg)
{
	error_t	     ret;
	memparcel_t *mp = NULL;

	label_t label;
	bool have_label = (fdt_getprop_u32(base_dtb, region_node, "qcom,label",
					   &label) == OK);

	if (have_label) {
		mp = find_memparcel_for_resmem_node_by_label(
			vmid, base_dtb, region_node, name, resmem_ctx, label);

		if (mp == NULL) {
			(void)printf("No memparcel with a matching label!\n");
			ret = ERROR_DENIED;
			goto out;
		}
		ret = OK;
	} else if (fdt_getprop_bool(base_dtb, region_node, "size") &&
		   !have_reg) {
		// This region will be dynamically allocated by Linux
		// after boot; we can ignore it
		ret = OK;
		goto out;
	} else {
		dt_addrrange_result_t range_r = parse_resmem_addrrange(
			base_dtb, region_node, name, resmem_ctx);
		if (range_r.error != OK) {
			ret = range_r.error;
			goto out;
		}

		mp = find_memparcel_for_resmem_node_by_address(
			vmid, name, range_r.base, range_r.size);

		if ((mp == NULL) && vm->vm_config->mem_demand_paging) {
			ret = resmem_enable_demand_paging(vm, base_dtb,
							  region_node,
							  range_r.base,
							  range_r.size);
			if (ret != OK) {
				(void)printf(
					"Unable to enable demand paging: %" PRIu32
					"\n",
					ret);
				goto out;
			}
			goto out;
		}

		if (mp == NULL) {
			(void)printf("No memparcel with a matching address!\n");
			ret = ERROR_DENIED;
			goto out;
		}
		ret = OK;
	}
	assert(mp != NULL);

out:
	return (memparcel_ptr_result_t){ .r = mp, .e = ret };
}

static error_t
patch_resmem_nodes(const vm_t *vm, dto_t *dto, vmid_t vmid,
		   const void *base_dtb, int resmem_node_ofs, ctx_t resmem_ctx)
{
	int	region_node;
	error_t ret = OK;

	fdt_for_each_subnode (region_node, base_dtb, resmem_node_ofs) {
		const char *name = fdt_get_name(base_dtb, region_node, NULL);
		assert(name != NULL);

		bool have_reg = fdt_getprop_bool(base_dtb, region_node, "reg");
		memparcel_ptr_result_t mp_r = find_memparcel_for_resmem_node(
			vm, vmid, base_dtb, region_node, name, resmem_ctx,
			have_reg);
		if (mp_r.e != OK) {
			ret = mp_r.e;
			goto out;
		}
		if (mp_r.r == NULL) {
			continue;
		}
		memparcel_t *mp = mp_r.r;

		// If the memparcel is accessible to multiple VMs, the
		// region must not be marked reusable.
		if (!memparcel_is_exclusive(mp, vmid) &&
		    fdt_getprop_bool(base_dtb, region_node, "reusable")) {
			(void)printf(
				"/reserved-memory/%s is marked reusable, but the memparcel is not exclusive!\n ",
				name);
			ret = ERROR_DENIED;
			goto out;
		}

		// Patch the region node with the memparcel's RM handle
		char	path[128];
		int32_t snprintf_ret = snprintf(path, sizeof(path),
						"/reserved-memory/%s", name);

		if ((snprintf_ret < 0) || (snprintf_ret >= 128)) {
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}
		CHECK_DTO(ret, dto_modify_begin_by_path(dto, path));

		CHECK_DTO(ret, dto_property_add_u32(dto, "qcom,rm-mem-handle",
						    memparcel_get_handle(mp)));

		// Find or add the region node's phandle
		uint32_t phandle = fdt_get_phandle(base_dtb, region_node);
		if ((phandle != 0U) && (phandle != (uint32_t)-1)) {
			// Existing phandle; make a note of it
			memparcel_set_phandle(mp, vmid, phandle, true);
		} else {
			// No existing phandle; add one in the overlay
			CHECK_DTO(ret, dto_property_add_phandle(dto, &phandle));
			memparcel_set_phandle(mp, vmid, phandle, false);
		}

		// Add the reg property if it wasn't already supplied.
		if (!have_reg) {
			ret = write_buffer_reg(dto, mp, vmid,
					       resmem_ctx.child_addr_cells,
					       resmem_ctx.child_size_cells);
			if (ret != OK) {
				goto out;
			}
		}

		CHECK_DTO(ret, dto_modify_end_by_path(dto, path));
	}

out:
	return ret;
}

static error_t
patch_cpus_nodes(vm_config_t *vmcfg, dto_t *dto, const void *base_dtb)
{
	error_t ret = OK;

	size_t cnt = vector_size(vmcfg->vcpus);

	for (index_t i = 0; i < cnt; i++) {
		vcpu_t *vcpu = vector_at(vcpu_t *, vmcfg->vcpus, i);
		assert(vcpu != NULL);

		if (vcpu->patch == NULL) {
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		} else if ((vmcfg->vpm_group != CSPACE_CAP_INVALID) &&
			   vcpu->defective) {
			int node_ofs = fdt_path_offset(base_dtb, vcpu->patch);
			if (node_ofs < 0) {
				(void)printf(
					"CPUS: Can not find node %s in device tree",
					vcpu->patch);
				ret = ERROR_ARGUMENT_INVALID;
				goto out;
			}

			CHECK_DTO(ret,
				  dto_modify_begin_by_path(dto, vcpu->patch));

			ret = dto_property_add_string(dto, "enable-method",
						      "none");
			if (ret != OK) {
				(void)printf(
					"Failed to modify enable-method property\n");
				goto out;
			}

			// As per the DT specification, setting status to "fail"
			// indicates the CPU is not operational or does not
			// exist.
			ret = dto_property_add_string(dto, "status", "fail");
			if (ret != OK) {
				(void)printf(
					"Failed to modify status property\n");
				goto out;
			}

			CHECK_DTO(ret,
				  dto_modify_end_by_path(dto, vcpu->patch));
		} else if ((vmcfg->vpm_group == CSPACE_CAP_INVALID) &&
			   (!vcpu->defective)) {
			int node_ofs = fdt_path_offset(base_dtb, vcpu->patch);
			if (node_ofs < 0) {
				(void)printf(
					"CPUS: Can not find node %s in device tree",
					vcpu->patch);
				ret = ERROR_ARGUMENT_INVALID;
				goto out;
			}

			CHECK_DTO(ret,
				  dto_modify_begin_by_path(dto, vcpu->patch));
			ret = dto_property_add_u64(
				dto, "qcom,gunyah-capability", vcpu->vm_cap);
			if (ret != OK) {
				(void)printf(
					"Failed to add vcpu-capability property\n");
				goto out;
			}
			CHECK_DTO(ret,
				  dto_modify_end_by_path(dto, vcpu->patch));
		} else {
			// No need to do anything
		}
	}

out:
	return ret;
}

static error_t
create_vsoc_node(dto_t *dto, int32_t vsoc_node_ofs)
{
	error_t err = OK;
	if (vsoc_node_ofs < 0) {
		CHECK_DTO(err, dto_modify_begin_by_path(dto, "/"));
		CHECK_DTO(err, dto_node_begin(dto, "vsoc"));
		CHECK_DTO(err, dto_property_add_u32(dto, "#address-cells", 2));
		CHECK_DTO(err, dto_property_add_u32(dto, "#size-cells", 2));
		CHECK_DTO(err, dto_property_add_empty(dto, "ranges"));
		CHECK_DTO(err, dto_register_path_ctx(dto, "/vsoc", 2, 2, true));
		CHECK_DTO(err, dto_property_add_string(dto, "compatible",
						       "simple-bus"));
		CHECK_DTO(err, dto_node_end(dto, "vsoc"));
		CHECK_DTO(err, dto_modify_end_by_path(dto, "/"));
	}
out:
	return err;
}

static error_t
create_reserved_memory_dtbo(dto_t *dto, vmid_t vmid, int32_t root_addr_cells,
			    int32_t root_size_cells,
			    int32_t reserved_memory_node_ofs)
{
	error_t err = OK;

	if (reserved_memory_node_ofs < 0) {
		// No /reserved-memory node exists; create a new one
		CHECK_DTO(err, dto_node_begin(dto, "reserved-memory"));
		CHECK_DTO(err, dto_property_add_u32(dto, "#address-cells",
						    (count_t)root_addr_cells));
		CHECK_DTO(err, dto_property_add_u32(dto, "#size-cells",
						    (count_t)root_size_cells));
		CHECK_DTO(err, dto_property_add_empty(dto, "ranges"));

		// Accept any remaining memparcels and generate nodes for them
		CHECK_DTO(err, create_resmem_nodes(dto, vmid,
						   (count_t)root_addr_cells,
						   (count_t)root_size_cells));
		CHECK_DTO(err, dto_node_end(dto, "reserved-memory"));
	}

out:
	return err;
}

static error_t
modify_existing_reserved_memory_dtbo(const vm_t *vm, const void *base_dtb,
				     dto_t *dto, vmid_t vmid,
				     int32_t reserved_memory_node_ofs)
{
	error_t err = OK;

	if (reserved_memory_node_ofs >= 0) {
		ctx_t resmem_ctx =
			dtb_parser_get_ctx(base_dtb, reserved_memory_node_ofs);

		// For any existing reserved memory nodes accept based on the
		// reserved memory ranges and patch with the correct RM handles
		err = patch_resmem_nodes(vm, dto, vmid, base_dtb,
					 reserved_memory_node_ofs, resmem_ctx);
		if (err != OK) {
			goto out;
		}

		// Accept any remaining memparcels and generate nodes for them
		CHECK_DTO(err,
			  dto_modify_begin_by_path(dto, "/reserved-memory"));
		err = create_resmem_nodes(dto, vmid,
					  resmem_ctx.child_addr_cells,
					  resmem_ctx.child_size_cells);
		CHECK_DTO(err, dto_modify_end_by_path(dto, "/reserved-memory"));
	}

out:
	return err;
}

static create_dtbo_ret_t
create_dtbo(vm_t *vm, const void *base_dtb)
{
	create_dtbo_ret_t ret = { .err = OK, .dtbo = NULL, .size = 0UL };

	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	vmid_t	 vmid	  = vm->vmid;
	vmaddr_t ipa_base = vm->vm_config->mem_ipa_base;

	int32_t root_addr_cells = fdt_address_cells(base_dtb, 0);
	int32_t root_size_cells = fdt_size_cells(base_dtb, 0);

	(void)printf("DTB:IPA base address:0x%lx\n", (uint64_t)ipa_base);
	if ((root_addr_cells < 0) || (root_size_cells < 0)) {
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out_no_dt;
	}

	dto_t *dto = dto_init(NULL, 0UL, base_dtb);
	if (dto == NULL) {
		ret.err = ERROR_NOMEM;
		goto out_no_dt;
	}

	// There should not be any existing /hypervisor node.
	if (fdt_path_offset(base_dtb, "/hypervisor") >= 0) {
		ret.err = ERROR_DENIED;
		goto out;
	}

	// If a /reserved-memory node exists, we must add to it rather than
	// creating a new one
	int32_t reserved_memory_node_ofs =
		fdt_path_offset(base_dtb, "/reserved-memory");
	ret.err = modify_existing_reserved_memory_dtbo(
		vm, base_dtb, dto, vmid, reserved_memory_node_ofs);
	if (ret.err != OK) {
		goto out;
	}

	ret.err = create_iomem_nodes(dto, vmid);
	if (ret.err != OK) {
		goto out;
	}

	ret.err = patch_chosen_node(dto, vm, base_dtb);
	if (ret.err != OK) {
		goto out;
	}

	CHECK_DTO(ret.err, dto_modify_begin_by_path(dto, "/"));

	ret.err = create_reserved_memory_dtbo(dto, vmid, root_addr_cells,
					      root_size_cells,
					      reserved_memory_node_ofs);
	if (ret.err != OK) {
		goto out;
	}

	ret.err = create_memory_node(dto, vmid, (count_t)root_addr_cells,
				     (count_t)root_size_cells);
	if (ret.err != OK) {
		goto out;
	}

	CHECK_DTO(ret.err, dto_modify_end_by_path(dto, "/"));

	// Add the vsoc devices
	int32_t vsoc_node_ofs = fdt_path_offset(base_dtb, "/vsoc");

	// Create the vsoc node if it doesn't exist
	ret.err = create_vsoc_node(dto, vsoc_node_ofs);
	if (ret.err != OK) {
		goto out;
	}

	vm_config_t *vmcfg = vm->vm_config;

	ret.err = patch_cpus_nodes(vmcfg, dto, base_dtb);
	if (ret.err != OK) {
		goto out;
	}

	ret.err = create_dt_nodes(base_dtb, dto, vmid);
	if (ret.err != OK) {
		goto out;
	}

	error_t e = platform_dto_finalise(dto, vm, base_dtb);
	if (e != OK) {
		ret.err = e;
		goto out;
	}

	ret.err = dto_finalise(dto);
	if (ret.err != OK) {
		goto out;
	}

	ret.err		       = OK;
	ret.constructed_object = dto;
	ret.dtbo	       = dto_get_dtbo(dto);
	ret.size	       = dto_get_size(dto);

out:
	if (ret.err != OK) {
		dto_deinit(dto);
	}
out_no_dt:
	return ret;
}

static error_t
add_peers_id_list(dto_t *dto, vm_t *vm)
{
	error_t ret = OK;

	count_t cnt = 0U;

	const char **peers_id = NULL;

	vdevice_node_t *node = NULL;
	loop_list(node, &vm->vm_config->vdevice_nodes, vdevice_)
	{
		if ((!node->export_to_dt) ||
		    (node->type != VDEV_MSG_QUEUE_PAIR)) {
			continue;
		}

		struct vdevice_msg_queue_pair *cfg =
			node->config.msg_queue_pair;

		if (!cfg->has_peer_vdevice) {
			continue;
		}

		++cnt;
	}

	if (cnt == 0UL) {
		// no need to generate peer id list
		ret = OK;
		goto out;
	}

	peers_id = calloc(sizeof(peers_id[0]), cnt);
	if (peers_id == NULL) {
		(void)printf("Error: failed to allocate peers_id\n");
		ret = ERROR_NOMEM;
		goto out;
	}

	index_t i = 0;

	node = NULL;
	loop_list(node, &vm->vm_config->vdevice_nodes, vdevice_)
	{
		if ((!node->export_to_dt) ||
		    (node->type != VDEV_MSG_QUEUE_PAIR)) {
			continue;
		}

		struct vdevice_msg_queue_pair *cfg =
			node->config.msg_queue_pair;

		if (!cfg->has_peer_vdevice) {
			continue;
		}

		assert(cfg->peer_id != NULL);

		bool existed = false;
		for (int j = (int)i - 1; j >= 0; --j) {
			if (strcmp(peers_id[j], cfg->peer_id) == 0) {
				existed = true;
				break;
			}
		}

		if (existed) {
			continue;
		}

		peers_id[i] = cfg->peer_id;
		++i;
	}

	ret = dto_property_add_stringlist(dto, "qcom,peers", peers_id, i);

out:
	// free each peer_id
	free(peers_id);

	return ret;
}

static error_t
create_vdev_dt_nodes(const void *base_dtb, dto_t *dto, vmid_t vmid,
		     const vm_t *cur_vm)
{
	error_t ret = OK;

	vdevice_node_t *node = NULL;

	error_t dto_err = OK;
	loop_list(node, &cur_vm->vm_config->vdevice_nodes, vdevice_)
	{
		if (!node->export_to_dt) {
			continue;
		}

		if ((node->type == VDEV_MSG_QUEUE_PAIR) ||
		    (node->type == VDEV_RM_RPC)) {
			dto_err = dto_create_msg_queue_pair(node, dto);
		} else if (node->type == VDEV_MSG_QUEUE) {
			dto_err = dto_create_msg_queue(node, dto);
		} else if (node->type == VDEV_DOORBELL) {
			dto_err = dto_create_doorbell(node, dto, NULL);
		} else if (node->type == VDEV_SHM) {
			dto_err = dto_create_shm(node, dto, vmid);
		} else if (node->type == VDEV_WATCHDOG) {
			dto_err = dto_create_watchdog(node, dto);
		} else if (node->type == VDEV_VIRTIO_MMIO) {
			dto_err = dto_create_virtio_mmio(base_dtb, node, dto,
							 vmid);
		} else if (node->type == VDEV_IOMEM) {
			// no need to add IOMEM node under hypervisor node
			continue;
		} else if (node->type == VDEV_SMMU_V2) {
			// Pass. Will be patched separately.
			continue;
		} else if (node->type == VDEV_RTC) {
			dto_err = dto_create_vrtc(node, dto);
		} else if (node->type == VDEV_MEMORY_EXTENT) {
			// Not exported through the DT.
			continue;
		} else if (node->type == VDEV_ADDRESS_SPACE) {
			dto_err = dto_create_addrspace(node, dto);
		} else {
			dto_err = platform_dto_create(node, dto, vmid);
		}

		if (dto_err != OK) {
			(void)printf(
				"create_dt_nodes: vmid %d, %s (%d), error %d\n",
				(int)vmid, node->generate, (int)node->type,
				(int)dto_err);
			ret = dto_err;
		}
	}

	return ret;
}

static error_t
add_root_properties(dto_t *dto, vmid_t vmid, vm_t *cur_vm)
{
	error_t ret = OK;

	const char *id_compat[2] = { "qcom,gunyah-vm-id-1.0",
				     "qcom,gunyah-vm-id" };
	CHECK_DTO(ret,
		  dto_property_add_stringlist(dto, "compatible", id_compat, 2));
	CHECK_DTO(ret, dto_property_add_u32(dto, "qcom,vmid", vmid));
	CHECK_DTO(ret,
		  dto_property_add_u32(dto, "qcom,owner-vmid", cur_vm->owner));
	CHECK_DTO(ret, dto_property_add_string(dto, "qcom,vendor", "Qualcomm"));

	CHECK_DTO(ret, dto_property_add_string(dto, "qcom,image-name",
					       cur_vm->name));

	if (cur_vm->uri_len != 0U) {
		CHECK_DTO(ret, dto_property_add_string(dto, "qcom,vm-uri",
						       cur_vm->uri));
	}

	if (cur_vm->has_guid) {
		char guid[VM_MAX_GUID_STRING_LEN];
		ret = dto_guid_to_string(cur_vm->guid,
					 util_array_size(cur_vm->guid), guid,
					 util_array_size(guid));
		if (ret != OK) {
			(void)printf(
				"Error: failed to convert guid to string\n");
			goto out;
		}

		CHECK_DTO(ret,
			  dto_property_add_string(dto, "qcom,vm-guid", guid));
	}

	ret = add_peers_id_list(dto, cur_vm);
	if (ret != OK) {
		(void)printf("Error: failed to generate peers id list\n");
		goto out;
	}

	ret = platform_dto_add_platform_props(dto, cur_vm);
	if (ret != OK) {
		goto out;
	}

out:
	return ret;
}

static error_t
add_hyp_properties(dto_t *dto)
{
	error_t ret;

	CHECK_DTO(ret, dto_property_add_u32(dto, "#address-cells", 2));
	CHECK_DTO(ret, dto_property_add_u32(dto, "#size-cells", 0));
	CHECK_DTO(ret, dto_register_path_ctx(dto, "/hypervisor", 2, 0, false));
	const char *hyp_compat[4] = { "gunyah-hypervisor",
				      "qcom,gunyah-hypervisor-1.0",
				      "qcom,gunyah-hypervisor", "simple-bus" };
	CHECK_DTO(ret, dto_property_add_stringlist(
			       dto, "compatible", hyp_compat,
			       (count_t)util_array_size(hyp_compat)));

out:
	return ret;
}

static error_t
create_dt_nodes(const void *base_dtb, dto_t *dto, vmid_t vmid)
{
	vm_t *cur_vm = vm_lookup(vmid);
	assert(cur_vm != NULL);
	assert(cur_vm->vm_config != NULL);

	error_t ret = OK;

	CHECK_DTO(ret, dto_modify_begin_by_path(dto, "/"));
	CHECK_DTO(ret, dto_node_begin(dto, "hypervisor"));

	CHECK_DTO(ret, add_hyp_properties(dto));

	CHECK_DTO(ret, dto_node_begin(dto, "qcom,gunyah-vm"));

	ret = add_root_properties(dto, vmid, cur_vm);
	if (ret != OK) {
		goto out;
	}

	CHECK_DTO(ret, dto_node_end(dto, "qcom,gunyah-vm"));

	CHECK_DTO(ret, dto_node_end(dto, "hypervisor"));

	CHECK_DTO(ret, dto_modify_end_by_path(dto, "/"));

	ret = create_vdev_dt_nodes(base_dtb, dto, vmid, cur_vm);

out:
	return ret;
}

error_t
vm_creation_process_memparcel(vm_t *vm, memparcel_t *mp)
{
	error_t ret = OK;

	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	if (memparcel_is_shared(mp, vm->vmid)) {
		ret = OK;
		goto out;
	}

	label_t label = memparcel_get_label(mp);

	vdevice_node_t *node = NULL;
	loop_list(node, &vm->vm_config->vdevice_nodes, vdevice_)
	{
		label_t	 vlabel;
		bool	 need_allocate = false;
		vmaddr_t base_ipa      = 0U;

		if (node->type == VDEV_SHM) {
			struct vdevice_shm *cfg = node->config.shm;
			vlabel			= cfg->label;
			need_allocate		= cfg->need_allocate;
			base_ipa		= cfg->base_ipa;
		} else if (node->type == VDEV_IOMEM) {
			struct vdevice_iomem *cfg = node->config.iomem;
			vlabel			  = cfg->label;
			need_allocate		  = cfg->need_allocate;
			// FIXME: do we need to handle need allocate case?
		} else {
			continue;
		}

		if (vlabel != label) {
			continue;
		}

		if (node->type == VDEV_SHM) {
			if (!need_allocate) {
				if (!memparcel_is_shared(mp, vm->vmid)) {
					ret = accept_memparcel_fixed(
						vm, mp, base_ipa,
						memparcel_get_size(mp));
					if (ret != OK) {
						(void)printf(
							"accept mp fixed: failed %d\n",
							(int)ret);
					}
				} else {
					// in case the memparcel is not shared
					// by it needs allocation
					(void)printf(
						"Warning: SHM/VIRTIO_MMIO (label %d) "
						"requires allocation of IPA\n",
						label);
				}
			}
			goto out;
		} else {
			// node->type = VDEV_IOMEM
			struct vdevice_iomem *cfg = node->config.iomem;
			// here we ignore allocate-base option (assume it's
			// always true)
			ret = accept_iomem_memparcel(vm->vmid, mp, cfg);
			if (ret != OK) {
				(void)printf(
					"accept iomem mp (label %d) failed %d\n",
					label, (int)ret);
			}
			goto out;
		}
	}

out:
	return ret;
}

static rm_error_t
process_image_memparcel(vm_t *vm)
{
	rm_error_t err;

	sgl_entry_t sgl_accept[1U] = { { .ipa  = vm->vm_config->mem_ipa_base,
					 .size = vm->mem_size } };
	uint16_t    sgl_len	   = (uint16_t)util_array_size(sgl_accept);

	acl_entry_t acl[1U]	 = { { .vmid   = vm->vmid,
				       .rights = MEM_RIGHTS_RWX } };
	uint8_t	    trans_type	 = TRANS_TYPE_LEND;
	uint8_t	    accept_flags = MEM_ACCEPT_FLAG_DONE |
			       MEM_ACCEPT_FLAG_VALIDATE_ACL_ATTR;

	if (vm->vm_config->mem_map_direct) {
		// The memparcel may be scattered; ignore the SGL.
		sgl_len = 0U;
	} else {
		accept_flags |= MEM_ACCEPT_FLAG_MAP_CONTIGUOUS;
	}

	if (!vm->vm_config->mem_unsanitized) {
		accept_flags |= MEM_ACCEPT_FLAG_SANITIZE;
	}

#if defined(CONFIG_DEBUG) && defined(PLATFORM_VM_DEBUG_ACCESS_ALLOWED) &&      \
	PLATFORM_VM_DEBUG_ACCESS_ALLOWED
	if (!platform_get_security_state()) {
		// The owner VM may have shared the base memory for debug
		// purposes, so disable ACL validation. The ACL will be ignored
		// in this case, so we don't need to remove it from the accept
		// call below.
		memparcel_t *mp = memparcel_lookup_by_target_vmid(
			vm->vmid, vm->mem_mp_handle);
		if (mp == NULL) {
			err = RM_ERROR_HANDLE_INVALID;
			goto out;
		}

		trans_type = memparcel_get_trans_type(mp);
		if (trans_type == TRANS_TYPE_DONATE) {
			err = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		accept_flags &= ~MEM_ACCEPT_FLAG_VALIDATE_ACL_ATTR;
		(void)printf("Warning: ACL validation disabled for VM %d\n",
			     vm->vmid);
	}
#endif

	err = memparcel_accept(vm->vmid, (uint16_t)util_array_size(acl),
			       sgl_len, 0U, acl, sgl_accept, NULL, 0U,
			       vm->mem_mp_handle, 0U, MEM_TYPE_NORMAL,
			       trans_type, accept_flags);

#if defined(CONFIG_DEBUG) && defined(PLATFORM_VM_DEBUG_ACCESS_ALLOWED) &&      \
	PLATFORM_VM_DEBUG_ACCESS_ALLOWED
out:
#endif
	return err;
}

static rm_error_t
process_firmware_memparcel(vm_t *vm)
{
	rm_error_t err;

	if (vm->fw_size == 0U) {
		// No firmware region was configured; nothing more to do. Note
		// that if the firmware was mandatory for the VM's auth type, we
		// will fail later in vm_firmware_vm_start().
		err = RM_OK;
		goto out;
	}

	if ((vm->fw_offset > vm->vm_config->fw_size_max) ||
	    (vm->fw_size > (vm->vm_config->fw_size_max - vm->fw_offset))) {
		// The firmware does not lie within the configured region.
		err = RM_ERROR_MEM_INVALID;
		goto out;
	}

	if (vm->fw_mp_handle == vm->mem_mp_handle) {
		// FW is part of the main image; check that the configured
		// FW IPA range is within the already accepted image memparcel.
		if ((vm->vm_config->fw_ipa_base <
		     vm->vm_config->mem_ipa_base) ||
		    ((vm->vm_config->fw_ipa_base + vm->vm_config->fw_size_max) >
		     (vm->vm_config->mem_ipa_base + vm->mem_size))) {
			err = RM_ERROR_MEM_INVALID;
		} else {
			// Nothing more to do.
			err = RM_OK;
		}
		goto out;
	}

	sgl_entry_t sgl_accept[1U] = { { .ipa  = vm->vm_config->fw_ipa_base,
					 .size = vm->fw_size } };

	acl_entry_t acl_lend[] = {
		{ .vmid = vm->vmid, .rights = MEM_RIGHTS_RWX },
	};
	uint8_t accept_flags = MEM_ACCEPT_FLAG_DONE |
			       MEM_ACCEPT_FLAG_VALIDATE_ACL_ATTR |
			       MEM_ACCEPT_FLAG_SANITIZE;

	if (!vm->vm_config->mem_map_direct) {
		accept_flags |= MEM_ACCEPT_FLAG_MAP_CONTIGUOUS;
	}

	err = memparcel_accept(vm->vmid, (uint16_t)util_array_size(acl_lend),
			       (uint16_t)util_array_size(sgl_accept), 0U,
			       acl_lend, sgl_accept, NULL, 0U, vm->fw_mp_handle,
			       0U, MEM_TYPE_NORMAL, TRANS_TYPE_LEND,
			       accept_flags);
	if (err != RM_OK) {
		(void)printf("Error: failed to accept firmware memparcel: %d\n",
			     err);
	}

out:
	return err;
}

static error_t
process_memparcels(vm_t *vm)
{
	error_t ret = OK;
	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	// Find the image memparcel and accept it at the base IPA
	rm_error_t rm_ret = process_image_memparcel(vm);
	if (rm_ret != RM_OK) {
		(void)printf("Error: failed to accept image memparcel: %d\n",
			     rm_ret);
		ret = ERROR_FAILURE;
		goto out;
	}

	// If a firmware memparcel has been configured, find and accept it
	rm_ret = process_firmware_memparcel(vm);
	if (rm_ret != RM_OK) {
		ret = ERROR_FAILURE;
		goto out;
	}

	// Auto-accept labelled memparcels matching devices and shared buffers.
	// Note that these could potentially conflict with the remaining private
	// memory region if they have fixed addresses or if they consume all
	// the space below vm->mem_ipa_base. The former is a configuration
	// error; to avoid the latter, we should extend the allocator to allow
	// the range to be reserved without preventing fixed allocations.
	// FIXME:
	memparcel_t *mp = NULL;
	foreach_memparcel_by_target_vmid (mp, vm->vmid) {
		ret = vm_creation_process_memparcel(vm, mp);
		if (ret != OK) {
			(void)printf(
				"Error: failed to process memparcel %#" PRIx32
				": %d\n",
				memparcel_get_handle(mp), ret);
			goto out;
		}
	}

	// Auto-accept any memparcel that can be used as private memory
	foreach_memparcel_by_target_vmid (mp, vm->vmid) {
		if (!memparcel_is_shared(mp, vm->vmid) &&
		    memparcel_is_private(mp, vm->vmid)) {
			// This will be part of the VM's normal memory, so make
			// it a paged memparcel if the VM is demand-paged.
			if (vm->vm_config->mem_demand_paging) {
				rm_ret = memparcel_make_paged(
					vm->vmid, vm->fw_mp_handle, false);
				if (rm_ret != RM_OK) {
					(void)printf(
						"Warning: paging private mp %#" PRIx32
						" failed: %d\n",
						memparcel_get_handle(mp),
						rm_ret);
					continue;
				}
			}

			rm_ret = accept_memparcel_private(vm, mp);
			if (rm_ret != RM_OK) {
				(void)printf(
					"Warning: accept private mp %#" PRIx32
					" failed: %d\n",
					memparcel_get_handle(mp), rm_ret);
				ret = ERROR_FAILURE;
				goto out;
			}
		}
	}

	if (vm->mem_size < vm->vm_config->mem_size_min) {
		(void)printf(
			"Warning: memory size %zu is less than minimum %zu\n",
			vm->mem_size, vm->vm_config->mem_size_min);
	}

out:
	return ret;
}

static error_t
accept_memparcel(vmid_t vmid, const memparcel_t *mp)
{
	error_t ret = OK;

	// FIXME: should we allowed different rights?
	acl_entry_t acl[1U] = { { .vmid = vmid, .rights = MEM_RIGHTS_RWX } };

	count_t region_cnt = memparcel_get_num_regions(mp);
	assert(region_cnt > 0U);

	uint8_t flags = MEM_ACCEPT_FLAG_DONE;

	vmid_t owner = memparcel_get_owner(mp);

	bool owner_is_sensitive = vm_mgnt_is_vm_sensitive(owner);

	uint8_result_t owner_rights_ret = memparcel_get_vm_rights(mp, owner);

	// owner doesn't need to access buffer if it's not in
	// the ACL
	bool owner_has_read = (owner_rights_ret.e == OK) &&
			      ((owner_rights_ret.r & MEM_RIGHTS_R) != 0U);

	uint8_result_t vm_rights_ret = memparcel_get_vm_rights(mp, vmid);
	if (vm_rights_ret.e != OK) {
		(void)printf("Error: %s: mp(label %d) has no VM(%d) in ACL\n",
			     __func__, memparcel_get_label(mp), vmid);
		ret = vm_rights_ret.e;
		goto out;
	}

	bool vm_has_write = ((vm_rights_ret.r & MEM_RIGHTS_W) != 0U);

	bool vm_is_sensitive = vm_mgnt_is_vm_sensitive(vmid);

	if (vm_is_sensitive && vm_has_write &&
	    (!owner_has_read || owner_is_sensitive)) {
		flags |= MEM_ACCEPT_FLAG_SANITIZE;
	}

	rm_error_t rm_err = memparcel_accept(vmid, 1U, 0U, 0U, acl, NULL, NULL,
					     0U, memparcel_get_handle(mp), 0U,
					     memparcel_get_mem_type(mp),
					     memparcel_get_trans_type(mp),
					     flags);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
	}
out:
	return ret;
}

static error_t
accept_iomem_memparcel(vmid_t vmid, memparcel_t *mp,
		       struct vdevice_iomem *config)
{
	error_t ret = OK;

	uint8_t flags = 0U;

	uint16_t acl_entries = 0U;

	acl_entry_t *acl = NULL;
	acl_entry_t  rm_acl[IOMEM_VALIDATION_NUM_IDXS];

	if (config->validate_acl) {
		rm_acl[IOMEM_VALIDATION_SELF_IDX].vmid = vmid;
		rm_acl[IOMEM_VALIDATION_SELF_IDX].rights =
			(uint8_t)config->rm_acl[IOMEM_VALIDATION_SELF_IDX];

		rm_acl[IOMEM_VALIDATION_PEER_IDX].vmid = config->peer;
		rm_acl[IOMEM_VALIDATION_PEER_IDX].rights =
			(uint8_t)config->rm_acl[IOMEM_VALIDATION_PEER_IDX];

		acl = rm_acl;

		acl_entries = (uint16_t)util_array_size(config->rm_acl);

		flags |= MEM_ACCEPT_FLAG_VALIDATE_ACL_ATTR;
	}

	uint16_t attr_entries = 0U;

	attr_entry_t *attrs = NULL;
	attr_entry_t  rm_attrs[IOMEM_VALIDATION_NUM_IDXS];

	if (config->validate_attrs) {
		rm_attrs[IOMEM_VALIDATION_SELF_IDX].vmid = vmid;
		rm_attrs[IOMEM_VALIDATION_SELF_IDX].attr =
			(uint16_t)config->rm_attrs[IOMEM_VALIDATION_SELF_IDX];

		rm_attrs[IOMEM_VALIDATION_PEER_IDX].vmid = config->peer;
		rm_attrs[IOMEM_VALIDATION_PEER_IDX].attr =
			(uint16_t)config->rm_attrs[IOMEM_VALIDATION_PEER_IDX];

		attrs = rm_attrs;

		attr_entries = (uint16_t)util_array_size(config->rm_attrs);

		flags |= MEM_ACCEPT_FLAG_VALIDATE_ACL_ATTR;
	}

	count_t region_cnt = util_min(memparcel_get_num_regions(mp),
				      (count_t)config->rm_sglist_len);
	// validate physical address here
	// FIXME: do we allow to provide partial sgl list?
	if ((region_cnt != 0U) && (region_cnt != config->rm_sglist_len)) {
		ret = ERROR_DENIED;
		goto out;
	}

	// simple compare since it's a short list
	for (index_t i = 0; i < region_cnt; ++i) {
		paddr_result_t region_ret = memparcel_get_phys(mp, i);
		if (region_ret.e != OK) {
			// only happen if it's done, but shouldn't
			// happen here
			break;
		}

		size_result_t size_ret = memparcel_get_region_size(mp, i);
		if (size_ret.e != OK) {
			// only happen if it's done, but shouldn't
			// happen here
			break;
		}

		bool found = false;

		for (index_t j = 0; j < region_cnt; ++j) {
			if ((config->rm_sglist[i].ipa == region_ret.r) &&
			    (config->rm_sglist[i].size == size_ret.r)) {
				found = true;
				break;
			}
		}

		if (!found) {
			ret = ERROR_DENIED;
			goto out;
		}
	}

	rm_error_t rm_err = memparcel_accept(
		vmid, acl_entries, 0U, attr_entries, acl, NULL, attrs, 0U,
		memparcel_get_handle(mp), config->label,
		memparcel_get_mem_type(mp), memparcel_get_trans_type(mp),
		flags | MEM_ACCEPT_FLAG_DONE);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
	} else {
		if (config->mem_info_tag_set) {
			memparcel_set_mem_info_tag(mp, config->mem_info_tag);
		}
	}
out:
	return ret;
}

static error_t
accept_memparcel_fixed(const vm_t *vm, const memparcel_t *mp, vmaddr_t ipa,
		       size_t sz)
{
	error_t ret  = OK;
	vmid_t	vmid = vm->vmid;

	// FIXME: should we allowed different rights?
	acl_entry_t acl[1U] = { { .vmid = vmid, .rights = MEM_RIGHTS_RW } };

	count_t region_cnt = memparcel_get_num_regions(mp);
	assert(region_cnt > 0U);

	sgl_entry_t sgl[1]  = { { .ipa = ipa, .size = sz } };
	uint16_t    sgl_len = (uint16_t)util_array_size(sgl);

	uint8_t flags = MEM_ACCEPT_FLAG_DONE;

	if (vm->vm_config->mem_map_direct) {
		// Ignore the fixed IPA.
		sgl_len = 0U;
	} else {
		flags |= MEM_ACCEPT_FLAG_MAP_CONTIGUOUS;
	}

	vmid_t owner = memparcel_get_owner(mp);

	bool owner_is_sensitive = vm_mgnt_is_vm_sensitive(owner);

	uint8_result_t owner_rights_ret = memparcel_get_vm_rights(mp, owner);

	// owner doesn't need to access buffer if it's not in the ACL
	bool owner_has_read = (owner_rights_ret.e == OK) &&
			      ((owner_rights_ret.r & MEM_RIGHTS_R) != 0U);

	uint8_result_t vm_rights_ret = memparcel_get_vm_rights(mp, vmid);
	if (vm_rights_ret.e != OK) {
		(void)printf("Error: %s: mp(label %d) has no VM(%d) in ACL\n",
			     __func__, memparcel_get_label(mp), vmid);
		ret = vm_rights_ret.e;
		goto out;
	}

	bool vm_has_write = ((vm_rights_ret.r & MEM_RIGHTS_W) != 0U);

	bool vm_is_sensitive = vm_mgnt_is_vm_sensitive(vmid);

	if (vm_is_sensitive && vm_has_write &&
	    (!owner_has_read || owner_is_sensitive)) {
		flags |= MEM_ACCEPT_FLAG_SANITIZE;
	}

	rm_error_t rm_err = memparcel_accept(vmid, 1U, sgl_len, 0U, acl, sgl,
					     NULL, 0U, memparcel_get_handle(mp),
					     0U, memparcel_get_mem_type(mp),
					     memparcel_get_trans_type(mp),
					     flags);
	if (rm_err != RM_OK) {
		(void)printf("Error: %s: mp(label %d) failed to accept: %d\n",
			     __func__, memparcel_get_label(mp), rm_err);
		ret = ERROR_DENIED;
	}

out:
	return ret;
}

static rm_error_t
accept_memparcel_private(vm_t *vm, const memparcel_t *mp)
{
	size_t	   size = memparcel_get_size(mp);
	rm_error_t ret	= RM_OK;

	if (util_add_overflows(size, vm->mem_size) ||
	    ((size + vm->mem_size) > vm->vm_config->mem_size_max)) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		(void)printf("accept private mp: too large; %zu > %zu - %zu\n",
			     size, vm->vm_config->mem_size_max, vm->mem_size);
		goto out;
	}

	if (vm->mem_base_tag != ADDRESS_RANGE_NO_TAG) {
		address_range_tag_t tag = memparcel_get_phys_address_tag(mp);
		if ((vm->mem_base_tag & tag) != vm->mem_base_tag) {
			(void)printf("accept private mp %d invalid tag %x",
				     memparcel_get_handle(mp), tag);
			ret = RM_ERROR_DENIED;
			goto out;
		}
	}

	sgl_entry_t sgl_accept[1U] = { {
		.ipa  = vm->vm_config->mem_ipa_base + vm->mem_size,
		.size = size,
	} };
	uint16_t    sgl_len	   = (uint16_t)util_array_size(sgl_accept);

	acl_entry_t acl[1U]	 = { { .vmid   = vm->vmid,
				       .rights = MEM_RIGHTS_RWX } };
	uint8_t	    trans_type	 = TRANS_TYPE_LEND;
	uint8_t	    accept_flags = MEM_ACCEPT_FLAG_DONE |
			       MEM_ACCEPT_FLAG_VALIDATE_ACL_ATTR;

	if (vm->vm_config->mem_map_direct) {
		// The memparcel may be scattered and/or discontiguous with the
		// image memparcel; ignore the SGL.
		sgl_len = 0U;
	} else {
		accept_flags |= MEM_ACCEPT_FLAG_MAP_CONTIGUOUS;
	}

	if (!vm->vm_config->mem_unsanitized) {
		accept_flags |= MEM_ACCEPT_FLAG_SANITIZE;
	}

#if defined(CONFIG_DEBUG) && defined(PLATFORM_VM_DEBUG_ACCESS_ALLOWED) &&      \
	PLATFORM_VM_DEBUG_ACCESS_ALLOWED
	if (!platform_get_security_state()) {
		// See process_image_memparcel().
		trans_type = memparcel_get_trans_type(mp);
		if (trans_type == TRANS_TYPE_DONATE) {
			ret = RM_ERROR_ARGUMENT_INVALID;
			goto out;
		}

		accept_flags &= ~MEM_ACCEPT_FLAG_VALIDATE_ACL_ATTR;
	}
#endif

	ret = memparcel_accept(vm->vmid, 1U, sgl_len, 0U, acl, sgl_accept, NULL,
			       0U, memparcel_get_handle(mp), 0U,
			       MEM_TYPE_NORMAL, trans_type, accept_flags);
	if (ret == RM_OK) {
		vm->mem_size += size;
	}

out:
	return ret;
}

static uintptr_result_t
map_cfgcpio(size_t cfgcpio_offset, size_t cfgcpio_size, uint32_t mp_handle,
	    size_t ipa_size)
{
	uintptr_result_t ret;

	if (util_add_overflows(cfgcpio_offset, cfgcpio_size - 1U)) {
		ret = uintptr_result_error(ERROR_ADDR_OVERFLOW);
		goto out;
	}

	if ((cfgcpio_offset > ipa_size) ||
	    (cfgcpio_size > (ipa_size - cfgcpio_offset))) {
		ret = uintptr_result_error(ERROR_ADDR_INVALID);
		goto out;
	}

	ret = memparcel_map_rm(mp_handle, cfgcpio_offset, cfgcpio_size);
	if (ret.e != OK) {
		(void)printf("map_cfgcpio: memparcel_map_rm failed\n");
		goto out;
	}
	uintptr_t vaddr		= ret.r;
	void	 *temp_cpio_ptr = (void *)vaddr;

	// Flush the cache, to ensure that the VM loader can't change the CPIO
	// structure underneath us by providing a deliberately cache-dirty CPIO
	cache_flush_by_va(temp_cpio_ptr, cfgcpio_size);

out:
	if (ret.e != OK) {
		(void)printf("map_cfgcpio(%zu, %zu) : failed, ret=%d\n",
			     cfgcpio_offset, cfgcpio_size, (int)ret.e);
	}
	return ret;
}

static error_t
unmap_cfgcpio(uint32_t mp_handle)
{
	error_t unmap_err = memparcel_unmap_rm(mp_handle);
	return unmap_err;
}

static error_t
process_cfgcpio(vm_t *vm)
{
	error_t ret;

	assert(vm != NULL);

	size_t	 ipa_size	= vm->mem_size;
	size_t	 cfgcpio_offset = vm->cfgcpio_offset;
	size_t	 cfgcpio_size	= vm->cfgcpio_size;
	uint32_t mp_handle	= vm->mem_mp_handle;

	if (cfgcpio_size == 0U) {
		// No need to process cfgcpio
		ret = OK;
		goto out_unmapped;
	}

	if (cfgcpio_size > CPIO_FILE_MAXSIZE) {
		ret = ERROR_ARGUMENT_SIZE;
		goto out_unmapped;
	}

	size_t cfgcpio_size_align = util_balign_up(cfgcpio_size, PAGE_SIZE);
	uintptr_result_t map_ret  = map_cfgcpio(
		 cfgcpio_offset, cfgcpio_size_align, mp_handle, ipa_size);
	ret = map_ret.e;
	if (ret != OK) {
		(void)printf("map_cfgcpio: ret %d\n", ret);
		goto out_unmapped;
	}
	uintptr_t temp_addr = map_ret.r;

	size_t		    idx = 0;
	struct cpio_header *header;
	char		   *file_name;
	void		   *file_data;
	size_t		    name_len = 0;
	size_t		    file_len = 0;
	char		    str_to_int[9];

	vm->cfgcpio_cmdline = vector_init(char *, 2U, 2U);
	if (vm->cfgcpio_cmdline == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	while ((idx < cfgcpio_size) &&
	       ((idx + sizeof(struct cpio_header)) < cfgcpio_size)) {
		header = (struct cpio_header *)(temp_addr + idx);

		// ensure magic header exists
		if (memcmp((uint8_t *)(header->c_magic),
			   (const uint8_t *)CPIO_HEADER_MAGIC,
			   sizeof(CPIO_HEADER_MAGIC) - 1U) != 0) {
			(void)printf("%c%c%c%c%c%c\n", header->c_magic[0],
				     header->c_magic[1], header->c_magic[2],
				     header->c_magic[3], header->c_magic[4],
				     header->c_magic[5]);
			(void)printf("header magic error\n");
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}
		if (idx == 0U) {
			(void)printf("cfgcpio is found\n");
		}

		// get file related info
		file_name = ((char *)header) + sizeof(struct cpio_header);

		// Actually header->c_namesize includes terminator '\0'
		(void)memscpy(str_to_int, sizeof(str_to_int) - 1U,
			      header->c_namesize, sizeof(header->c_namesize));
		str_to_int[8] = '\0';
		name_len      = strtoul(str_to_int, NULL, 16);
		idx = util_balign_up(idx + sizeof(struct cpio_header) +
					     name_len,
				     CPIO_ALIGNMENT);
		if (idx > cfgcpio_size) {
			ret = ERROR_ARGUMENT_SIZE;
			goto out;
		}

		file_data = (void *)(temp_addr + idx);

		(void)memscpy(str_to_int, sizeof(str_to_int) - 1U,
			      header->c_filesize, sizeof(header->c_filesize));
		str_to_int[8] = '\0';
		file_len      = strtoul(str_to_int, NULL, 16);
		idx	      = util_balign_up(idx + file_len, CPIO_ALIGNMENT);
		if (idx > cfgcpio_size) {
			ret = ERROR_ARGUMENT_SIZE;
			goto out;
		}

		// Parse all filenames
		if ((name_len >= sizeof(CPIO_CMDLINE)) &&
		    (strncmp(file_name + name_len - sizeof(CPIO_CMDLINE),
			     CPIO_CMDLINE, sizeof(CPIO_CMDLINE)) == 0)) {
			if (file_len == 0U) {
				continue;
			}

			char *duplicate = strndup((char *)file_data, file_len);
			if (duplicate == NULL) {
				ret = ERROR_NOMEM;
				goto out;
			}

			// According to POSIX, a text file must end with at
			// least one '\n'. And the file which is created in
			// Windows might end with one or more "\r\n"s. In case
			// some unused whitespaces are added, we delete all of
			// them default.
			size_t i = file_len - 1U;
			while (isspace((int)duplicate[i])) {
				duplicate[i] = '\0';
				if (i == 0U) {
					break;
				}

				i--;
			}
			// (i + 1U) is the data length after strip. The last 1U
			// is an additional whitespace ' ' which is used to
			// separate different cmdlines when merge them.
			i += 1U + 1U;

			assert(!util_add_overflows(vm->cfgcpio_cmdline_len, i));
			vm->cfgcpio_cmdline_len += i;

			ret = vector_push_back(vm->cfgcpio_cmdline, duplicate);
			if (ret != OK) {
				goto out;
			}

			(void)printf("cmdline file: %s\n", file_name);
		} else if (strncmp(file_name, CPIO_FOOTER_MAGIC,
				   sizeof(CPIO_FOOTER_MAGIC)) == 0) {
			break;
		} else {
			// Ignore this file and continue to the next
		}
	}

out:
	// unmap cfgcpio from rm
	(void)unmap_cfgcpio(mp_handle);

out_unmapped:
	if (ret != OK) {
		(void)printf("process_cfgcpio failed, ret = %d\n", (int)ret);
	}
	return ret;
}

static error_t
add_iomem_dto_nodes_prop(dto_t *dto, vmid_t vmid, const vdevice_node_t *node,
			 memparcel_t *mp, const struct vdevice_iomem *cfg,
			 const ctx_t *ctx, dto_addrrange_t **regs_ptr)
{
	error_t ret = OK;

	dto_addrrange_t *regs = NULL;

	count_t compatible_cnt = 0U;

	const char *compatibles[VDEVICE_MAX_PUSH_COMPATIBLES];

	compatible_cnt = node->push_compatible_num;
	(void)memscpy(&compatibles, sizeof(compatibles), &node->push_compatible,
		      sizeof(node->push_compatible));

	CHECK_DTO(ret, dto_property_add_stringlist(
			       dto, "compatible", compatibles, compatible_cnt));

	count_t region_cnt = memparcel_get_num_regions(mp);
	assert(region_cnt > 0U);

	regs = calloc(region_cnt, sizeof(regs[0]));
	if (regs == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	for (index_t i = 0; i < region_cnt; ++i) {
		regs[i].addr = memparcel_get_phys(mp, i).r;
		regs[i].size = memparcel_get_region_size(mp, i).r;
	}

	CHECK_DTO(ret, dto_property_add_addrrange_array(
			       dto, "reg", regs, region_cnt,
			       ctx->child_addr_cells, ctx->child_size_cells));

	CHECK_DTO(ret, dto_property_add_u32(dto, "peer", cfg->peer));

	mem_handle_t mem_handle = memparcel_get_handle(mp);

	CHECK_DTO(ret,
		  dto_property_add_u64(dto, "qcom,rm-mem-handle", mem_handle));

	uint8_result_t self_rights = memparcel_get_vm_rights(mp, vmid);

	uint8_result_t peer_rights = memparcel_get_vm_rights(mp, cfg->peer);

	if ((self_rights.e == OK) && (peer_rights.e == OK)) {
		uint32_t acl[2];
		acl[0] = self_rights.r;
		acl[1] = peer_rights.r;
		CHECK_DTO(ret, dto_property_add_u32array(dto, "qcom,rm-acl",
							 acl, 2));
	}

	uint16_result_t self_attrs = memparcel_get_vm_attrs(mp, vmid);

	uint16_result_t peer_attrs = memparcel_get_vm_attrs(mp, cfg->peer);

	if ((self_attrs.e == OK) && (peer_attrs.e == OK)) {
		uint32_t attrs[2];
		attrs[0] = self_attrs.r;
		attrs[1] = peer_attrs.r;
		CHECK_DTO(ret, dto_property_add_u32array(
				       dto, "qcom,rm-attributes", attrs, 2));
	}

out:
	*regs_ptr = regs;
	return ret;
}

static error_t
create_iomem_nodes(dto_t *dto, vmid_t vmid)
{
	error_t ret = OK;

	vm_t *cur_vm = vm_lookup(vmid);
	assert(cur_vm != NULL);
	assert(cur_vm->vm_config != NULL);
	dto_addrrange_t *regs = NULL;

	vdevice_node_t *node = NULL;
	loop_list(node, &cur_vm->vm_config->vdevice_nodes, vdevice_)
	{
		if (node->type != VDEV_IOMEM) {
			continue;
		}
		struct vdevice_iomem *cfg = node->config.iomem;

		label_t vlabel;
		vlabel = cfg->label;

		memparcel_t *mp;
		foreach_memparcel_by_target_vmid (mp, vmid) {
			if (memparcel_get_label(mp) == vlabel) {
				break;
			}
		}

		if (mp == NULL) {
			(void)printf(
				"Warning: iomem (label %x) has no memory parcel\n",
				vlabel);
			continue;
		}

		ctx_t ctx;
		CHECK_DTO(ret,
			  dto_get_path_ctx(dto, node->generate, &ctx, true));

		if (!ctx.child_addr_is_phys) {
			(void)printf(
				"Warning: patching non-physical reg in %s!\n",
				node->generate);
		}

		CHECK_DTO(ret, dto_construct_begin_path(dto, node->generate));

		ret = add_iomem_dto_nodes_prop(dto, vmid, node, mp, cfg, &ctx,
					       &regs);
		if (ret != OK) {
			goto out;
		}

		CHECK_DTO(ret,
			  dto_property_add_u32(dto, "qcom,label", cfg->label));

		free(regs);
		regs = NULL;

		CHECK_DTO(ret, dto_construct_end_path(dto, node->generate));
	}

out:
	free(regs);
	return ret;
}

static error_t
parse_cfgcpio(dto_t *dto, vm_t *vm, const void *base_dtb, int chosen_ofs)
{
	error_t ret;

	char	   *bootargs_total = NULL;
	const char *bootargs;
	size_t	    bootargs_len;

	if (chosen_ofs >= 0) {
		int len;
		bootargs = fdt_stringlist_get(base_dtb, chosen_ofs, "bootargs",
					      0, &len);
		bootargs_len = (bootargs == NULL) ? 0U : (size_t)len;
	} else {
		bootargs     = NULL;
		bootargs_len = 0U;
	}

	// append cfgcpio_cmdline to bootargs
	assert(bootargs_len < (size_t)SIZE_MAX);
	size_t bootargs_total_size = bootargs_len + 1U;
	assert(!util_add_overflows(bootargs_total_size,
				   vm->cfgcpio_cmdline_len));
	bootargs_total_size += vm->cfgcpio_cmdline_len;

	bootargs_total = (char *)malloc(bootargs_total_size);
	if (bootargs_total == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	if (bootargs_len > 0U) {
		(void)memscpy(bootargs_total, bootargs_total_size, bootargs,
			      (size_t)bootargs_len);
		bootargs_total[bootargs_len] = '\0';
	}

	index_t idx	    = 0U;
	size_t	cmdline_len = 0;
	char   *cmdline	    = NULL;
	size_t	offset	    = (size_t)bootargs_len;
	foreach_vector(char *, vm->cfgcpio_cmdline, idx, cmdline)
	{
		if (cmdline != NULL) {
			cmdline_len = strlen(cmdline);
			assert(bootargs_total_size >
			       (offset + 1U + cmdline_len));

			bootargs_total[offset] = ' ';
			offset++;
			offset += memscpy(&bootargs_total[offset],
					  bootargs_total_size - offset - 1U,
					  cmdline, cmdline_len);
		}
	}
	assert(offset < bootargs_total_size);
	bootargs_total[offset] = '\0';

	ret = dto_property_add_string(dto, "bootargs", bootargs_total);
	// Firstly we free bootargs_total regardless of the value of
	// ret, and then check if ret equals OK.
	free(bootargs_total);

	ret = OK;
out:
	return ret;
}

static error_t
generate_chosen_props(dto_t *dto, vm_t *vm, const void *base_dtb,
		      int chosen_ofs)
{
	error_t ret;

	uint64_result_t seed = random_get_entropy64();
	if (seed.e != OK) {
		(void)printf("vm %d, failed to get random seed\n", vm->vmid);
		ret = seed.e;
		goto out;
	}

	CHECK_DTO(ret, dto_property_add_u64(dto, "kaslr-seed", seed.r));

	if (vm->ramfs_size > 0U) {
		assert(!util_add_overflows(vm->ramfs_offset,
					   vm->vm_config->mem_ipa_base));
		vmaddr_t ramfs_ipa_start =
			vm->ramfs_offset + vm->vm_config->mem_ipa_base;

		assert(!util_add_overflows(ramfs_ipa_start,
					   vm->ramfs_size - 1U));
		vmaddr_t ramfs_ipa_end =
			ramfs_ipa_start + (vm->ramfs_size - 1U);
		// update initrd ipa address
		CHECK_DTO(ret, dto_property_add_u32(dto, "linux,initrd-start",
						    (uint32_t)ramfs_ipa_start));
		CHECK_DTO(ret, dto_property_add_u32(dto, "linux,initrd-end",
						    (uint32_t)ramfs_ipa_end));
	}

	if ((vm->cfgcpio_cmdline != NULL) && (vm->cfgcpio_cmdline_len > 0U)) {
		ret = parse_cfgcpio(dto, vm, base_dtb, chosen_ofs);
		if (ret != OK) {
			goto out;
		}
	}

out:
	return ret;
}

static error_t
patch_chosen_node(dto_t *dto, vm_t *vm, const void *base_dtb)
{
	error_t ret = OK;

	int chosen_ofs = fdt_path_offset(base_dtb, "/chosen");

	if (chosen_ofs >= 0) {
		CHECK_DTO(ret, dto_modify_begin_by_path(dto, "/chosen"));
	} else {
		CHECK_DTO(ret, dto_modify_begin_by_path(dto, "/"));
		CHECK_DTO(ret, dto_node_begin(dto, "chosen"));
	}

	ret = generate_chosen_props(dto, vm, base_dtb, chosen_ofs);
	if (ret != OK) {
		goto out;
	}

	if (chosen_ofs >= 0) {
		CHECK_DTO(ret, dto_modify_end_by_path(dto, "/chosen"));
	} else {
		CHECK_DTO(ret, dto_node_end(dto, "chosen"));
		CHECK_DTO(ret, dto_modify_end_by_path(dto, "/"));
	}

out:
	return ret;
}
