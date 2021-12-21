// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>

#include <asm/arm_smccc.h>
#include <rm-rpc.h>

#include <guest_interface.h>
#include <inttypes.h>
#include <resource-manager.h>
#include <time.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <dt_overlay.h>
#include <dtb_parser.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <rm-rpc-fifo.h>
#include <util.h>
#include <utils/list.h>
#include <utils/vector.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_mgnt.h>
#include <vm_mgnt_message.h>

#include "dto_construct.h"

#define TEMP_DTB_MAP_VADDR (0xe0000000U)

static error_t
process_dtb(vm_t *vm);

typedef struct {
	dto_t * constructed_object;
	void *	dtbo;
	size_t	size;
	error_t err;
	uint8_t err_padding[4];
} create_dtbo_ret_t;

static create_dtbo_ret_t
create_dtbo(vm_t *vmid, const void *base_dtb);

static error_t
create_hypervisor_node(dto_t *dto, vmid_t vmid);

static error_t
accept_memparcel(vmid_t vmid, const memparcel_t *mp);

static error_t
accept_memparcel_fixed(vmid_t vmid, const memparcel_t *mp, vmaddr_t ipa,
		       size_t sz);

static error_t
process_memparcels(vmid_t vmid);

typedef struct {
	error_t err;
	uint8_t err_padding[4];

	uint64_t seed;
} get_random_seed_ret_t;

static get_random_seed_ret_t
get_random_seed(void);

static error_t
patch_chosen_node(dto_t *dto, vm_t *vm);

static error_t
map_dtb(uintptr_t vaddr, size_t dtb_offset, size_t dtb_size, uint32_t mp_handle,
	size_t ipa_size);

static error_t
unmap_dtb(uint32_t mp_handle);

error_t
vm_creation_process_resource(vmid_t vmid)
{
	error_t ret = OK;

	vm_t *vm = vm_lookup(vmid);
	assert(vm != NULL);

	ret = process_dtb(vm);
	if (ret != OK) {
		goto out;
	}

	ret = process_memparcels(vmid);

out:
	return ret;
}

bool
vm_creation_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len)
{
	bool handled = false;

	(void)len;
	(void)seq_num;
	(void)buf;

	if (client_id != VMID_HYP) {
		goto out;
	}

	switch (msg_id) {
	default:
		break;
	}

out:
	if (handled) {
		rm_standard_reply(client_id, msg_id, seq_num, RM_OK);
	}

	return handled;
}

error_t
map_dtb(uintptr_t vaddr, size_t dtb_offset, size_t dtb_size, uint32_t mp_handle,
	size_t ipa_size)
{
	error_t ret = OK;

	void * temp_dtb_ptr = (void *)vaddr;
	size_t mapped_size  = PAGE_SIZE + DTBO_MAX_SIZE;

	if ((dtb_offset > ipa_size) ||
	    (mapped_size > (ipa_size - dtb_offset))) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (util_add_overflows(dtb_offset, dtb_size - 1)) {
		ret = ERROR_ADDR_OVERFLOW;
		goto out;
	}

	if (util_add_overflows(vaddr, dtb_offset + dtb_size - 1)) {
		ret = ERROR_ADDR_OVERFLOW;
		goto out;
	}

	if ((dtb_offset > ipa_size) || (dtb_size > (ipa_size - dtb_offset))) {
		ret = ERROR_ADDR_INVALID;
		goto out;
	}

	ret = memparcel_map_rm(mp_handle, dtb_offset, vaddr, dtb_size);
	if (ret != OK) {
		printf("map_dtb: memparcel_map_rm failed\n");
		goto out;
	}

	if (fdt_check_header(temp_dtb_ptr) != 0) {
		printf("map_dtb: invalid dtb\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out_unmap;
	}

	size_t fdt_size = fdt_totalsize(temp_dtb_ptr);
	if (fdt_size > dtb_size) {
		printf("map_dtb: fdt_totalsize (%zu) > DTB region size(%zu)\n",
		       fdt_size, dtb_size);
		ret = ERROR_ARGUMENT_INVALID;
		goto out_unmap;
	}

out_unmap:
	if (ret != OK) {
		(void)memparcel_unmap_rm(mp_handle);
	}
out:
	if (ret != OK) {
		printf("map_dtb(%p, %zu, %zu) : failed, ret=%d\n", temp_dtb_ptr,
		       dtb_offset, dtb_size, (int)ret);
	}
	return ret;
}

error_t
unmap_dtb(uint32_t mp_handle)
{
	error_t unmap_err = memparcel_unmap_rm(mp_handle);
	return unmap_err;
}

error_t
process_dtb(vm_t *vm)
{
	error_t ret = OK;

	assert(vm != NULL);

	size_t	 ipa_size	   = vm->mem_size;
	size_t	 dtb_region_offset = vm->dtb_region_offset;
	size_t	 dtb_region_size   = vm->dtb_region_size;
	uint32_t mp_handle	   = vm->mem_mp_handle;

	// FIXME: this address needs to be allocated safely
	uintptr_t temp_addr    = TEMP_DTB_MAP_VADDR;
	void *	  temp_dtb_ptr = (void *)temp_addr;

	error_t map_ret = map_dtb(temp_addr, dtb_region_offset, dtb_region_size,
				  mp_handle, ipa_size);
	if (map_ret != OK) {
		ret = map_ret;
		goto out_unmapped;
	}

	// NOTE: integrate with vm config, generate dtbo.
	create_dtbo_ret_t dtbo_ret = create_dtbo(vm, temp_dtb_ptr);

	ret = dtbo_ret.err;
	if (ret == OK) {
		int apply_ret = -FDT_ERR_NOSPACE;

		void *final_dtb = NULL;

		size_t final_dtb_size = fdt_totalsize(temp_addr);
		// sanity check size is reasonable
		if ((final_dtb_size > dtb_region_size) ||
		    (final_dtb_size > (256 * 1024U))) {
			printf("process_dtb: dtb size (%zu) invalid\n",
			       final_dtb_size);
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}
		// guess a final dtb size after applying the overlay
		final_dtb_size += dtbo_ret.size;
		do {
			if (final_dtb_size > dtb_region_size) {
				final_dtb_size = dtb_region_size;
			}

			final_dtb = malloc(final_dtb_size);
			if (final_dtb == NULL) {
				ret = ERROR_NOMEM;
				goto out;
			}

			int open_ret = fdt_open_into(temp_dtb_ptr, final_dtb,
						     (int)final_dtb_size);
			if (open_ret != 0) {
				ret = RM_ERROR_DENIED;
				goto out;
			}

			// apply dtbo to dt
			apply_ret = fdt_overlay_apply(final_dtb, dtbo_ret.dtbo);
			if (apply_ret == -FDT_ERR_NOSPACE) {
				free(final_dtb);

				// break the loop if final dtb is too
				// big
				if (final_dtb_size == dtb_region_size) {
					apply_ret = -FDT_ERR_TRUNCATED;
				} else {
					final_dtb_size += dtbo_ret.size;
				}
			}
		} while (apply_ret == -FDT_ERR_NOSPACE);

		if (apply_ret != 0) {
			printf("Error: Failed to apply device tree overlay");
			ret = RM_ERROR_DENIED;
			goto out;
		}

		fdt_pack(final_dtb);

		size_t total_size = fdt_totalsize(final_dtb);
		if (total_size > dtb_region_size) {
			if (vm->segment_offset_after_dtb >=
			    total_size + dtb_region_offset) {
				printf("Warning: DTB region size(%zu) cannot "
				       "hold final DTB size (%zu), but it "
				       "seems there is a space to fit it. DTB "
				       "segment offset is (%zu), Next "
				       "segment offset at (%zu)\n",
				       total_size, dtb_region_size,
				       dtb_region_offset,
				       vm->segment_offset_after_dtb);
			} else {
				printf("Error: DTB region size(%zu) cannot "
				       "hold final DTB size (%zu), it will "
				       "overwrite the next segment, "
				       "the offset is at (%zu)\n",
				       total_size, dtb_region_size,
				       vm->segment_offset_after_dtb);
				ret = RM_ERROR_DENIED;
			}
		}

		memcpy(temp_dtb_ptr, final_dtb, total_size);
		free(final_dtb);
		dto_deinit(dtbo_ret.constructed_object);
	}

out:
	(void)0;

	// unmap dtb from rm
	error_t unmap_err = unmap_dtb(mp_handle);
	if (ret == OK) {
		ret = unmap_err;
	}
out_unmapped:
	if (ret != OK) {
		printf("process_dtb failed, ret = %d\n", (int)ret);
	}
	return ret;
}

static error_t
create_reserved_buffer_node(dto_t *dto, vmid_t vmid, memparcel_t *mp,
			    int root_addr_cells, int root_size_cells);

static void
store_cells(void *property, uint64_t val, int addr_cells);

void
store_cells(void *property, uint64_t val, int cells)
{
	assert((cells == 1) || (cells == 2));
	if (cells == 1) {
		fdt32_st(property, (uint32_t)val);
	} else if (cells == 2) {
		fdt64_st(property, val);
	}
}

static error_t
write_buffer_reg(dto_t *dto, memparcel_t *mp, vmid_t vmid, int addr_cells,
		 int size_cells)
{
	error_t ret = OK;

	count_t region_cnt = memparcel_get_num_regions(mp);

	count_t element_sz =
		(count_t)(addr_cells + size_cells) * sizeof(fdt32_t);
	count_t addr_stepping = (count_t)addr_cells * sizeof(fdt32_t);
	count_t size_stepping = (count_t)size_cells * sizeof(fdt32_t);

	uint8_t *blob = calloc(element_sz, sizeof(*blob));
	if (blob == NULL) {
		goto out;
	}

	uint8_t *cur = blob;
	for (index_t i = 0; i < region_cnt; ++i) {
		vmaddr_result_t ipa_ret = memparcel_get_mapped_ipa(mp, vmid, i);
		if (ipa_ret.e != OK) {
			ret = ipa_ret.e;
			goto out_free;
		}

		vmaddr_t ipa = ipa_ret.r;

		size_result_t size_ret = memparcel_get_size(mp, i);
		if (size_ret.e != OK) {
			ret = size_ret.e;
			goto out_free;
		}

		size_t size = size_ret.r;

		// record address/size
		store_cells(cur, ipa, addr_cells);
		cur += addr_stepping;

		store_cells(cur, size, size_cells);
		cur += size_stepping;
	}

	ret = dto_property_add_blob(dto, "reg", blob, element_sz);

out_free:
	free(blob);
out:
	return ret;
}

error_t
create_reserved_buffer_node(dto_t *dto, vmid_t vmid, memparcel_t *mp,
			    int root_addr_cells, int root_size_cells)
{
	error_t ret = OK;

	// The mp should have been accepted
	if (!memparcel_is_shared(mp, vmid)) {
		printf("%s: memparcel %#" PRIx32 " @ %#" PRIx64
		       " has not been mapped\n",
		       __func__, memparcel_get_handle(mp),
		       memparcel_get_phys(mp, 0U).r);
		goto out;
	}

	label_t label = memparcel_get_label(mp);

	mem_handle_t rm_handle = memparcel_get_handle(mp);

	paddr_result_t phys_ret = memparcel_get_phys(mp, 0);
	if (phys_ret.e != OK) {
		ret = phys_ret.e;
		goto out;
	}

	// create node now
	char name[DTB_NODE_NAME_MAX];
	(void)snprintf(name, DTB_NODE_NAME_MAX, "buffer@0x%lx", phys_ret.r);

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

	// get pushed-compaitbles and add it
	// Find the SHM node
	vm_t *cur_vm = vm_lookup(vmid);
	assert(cur_vm != NULL);
	assert(cur_vm->vm_config != NULL);

	count_t compatible_cnt = 0U;

	const char *compatibles[VDEVICE_MAX_PUSH_COMPATIBLES];

	vdevice_node_t *node = NULL;
	loop_list(node, &cur_vm->vm_config->vdevice_nodes, vdevice_)
	{
		if (!node->export_to_dt) {
			continue;
		}

		if (node->type == VDEV_SHM) {
			struct vdevice_shm *cfg =
				(struct vdevice_shm *)node->config;
			if (cfg->label == label) {
				compatible_cnt = node->push_compatible_num;
				memcpy(&compatibles, &node->push_compatible,
				       sizeof(node->push_compatible));
			}
		}
	}

	if (compatible_cnt == 0U) {
		ret = ERROR_DENIED;
		goto out_free_blob;
	}

	ret = dto_property_add_stringlist(dto, "compatible", compatibles,
					  compatible_cnt);

out_free_blob:
	free(blob);
out_node_end:
	// no way to recover it
	(void)dto_node_end(dto, name);
out_vmids:
	vector_deinit(vmids);
out:
	return ret;
}

static error_t
create_resmem_nodes(dto_t *dto, vmid_t vmid, vmaddr_t ipa_base,
		    int root_addr_cells, int root_size_cells,
		    bool static_config)
{
	error_t ret = OK;

	memparcel_t *mp;
	foreach_memparcel_by_target_vmid (mp, vmid) {
		assert(mp != NULL);

		// Auto-accept memparcel if it hasn't been accepted already
		if (!memparcel_is_shared(mp, vmid)) {
			ret = accept_memparcel(vmid, mp);
			if (ret != OK) {
				continue;
			}
		}

		// If this is the VM's main memory memparcel, don't create a
		// reserved-memory node for it
		vmaddr_result_t ipa_r = memparcel_get_mapped_ipa(mp, vmid, 0U);
		// TODO: also skip here if not mapped, once we are auto-mapping
		// everything
		if ((ipa_r.e == OK) && (ipa_r.r == ipa_base)) {
			printf("%s: memparcel labelled %#" PRIx32
			       " is the base memory at %#zx\n",
			       __func__, memparcel_get_label(mp), ipa_base);
			continue;
		}

		// If there was a node statically configured in the base
		// device tree, don't create a new one
		if (static_config &&
		    memparcel_get_phandle(mp, vmid, NULL) != 0U) {
			printf("%s: memparcel labelled %#" PRIx32
			       " already has a node\n",
			       __func__, memparcel_get_label(mp));
			continue;
		}

		// create node
		printf("%s: create node for memparcel labelled %#" PRIx32 "\n",
		       __func__, memparcel_get_label(mp));
		ret = create_reserved_buffer_node(
			dto, vmid, mp, root_addr_cells, root_size_cells);
		if (ret != OK) {
			break;
		}
	}

	return ret;
}

static error_t
patch_resmem_nodes(dto_t *dto, vmid_t vmid, const void *base_dtb,
		   int resmem_node_ofs, int root_addr_cells,
		   int root_size_cells)
{
	int	region_node;
	error_t ret = OK;

	fdt_for_each_subnode (region_node, base_dtb, resmem_node_ofs) {
		// Find the region's label
		int	    label_len;
		const void *label_prop = fdt_getprop(base_dtb, region_node,
						     "qcom,label", &label_len);
		if ((label_prop == NULL) || (label_len != sizeof(uint32_t))) {
			printf("%s: node %s has no label \n", __func__,
			       fdt_get_name(base_dtb, region_node, NULL));
			// Label is missing or is not a u32
			continue;
		}
		label_t label = fdt32_ld(label_prop);

		printf("%s: patching %s (label %#" PRIx32 ")\n", __func__,
		       fdt_get_name(base_dtb, region_node, NULL), label);

		// Look for a matching memparcel
		memparcel_t *mp;
		foreach_memparcel_by_target_vmid (mp, vmid) {
			if (memparcel_get_label(mp) == label) {
				break;
			}
		}
		if (mp == NULL) {
			printf("%s: no memparcel with label %#" PRIx32 "!\n",
			       __func__, label);
			ret = ERROR_NOMEM;
			goto out;
		}

		// Patch the region node with the memparcel's RM handle, and add
		// a phandle if none already exists
		const char *name = fdt_get_name(base_dtb, region_node, NULL);
		assert(name != NULL);

		// Accept the memparcel at the specified address and size, if it
		// wasn't already accepted
		if (!memparcel_is_shared(mp, vmid)) {
			int	    reg_len;
			const void *reg_prop = (const uint8_t *)fdt_getprop(
				base_dtb, region_node, "reg", &reg_len);
			// TODO: handle multiple-region memparcels and
			// RM-allocated mappings
			if ((reg_prop == NULL) ||
			    (memparcel_get_num_regions(mp) > 1)) {
				ret = ERROR_UNIMPLEMENTED;
				goto out;
			}
			count_t addr_bytes =
				(count_t)root_addr_cells * sizeof(fdt32_t);
			count_t size_bytes =
				(count_t)root_size_cells * sizeof(fdt32_t);
			count_t element_bytes = addr_bytes + size_bytes;
			if (element_bytes > (count_t)reg_len) {
				printf("error: %s: truncated reg property",
				       __func__);
			}

			acl_entry_t acl[1U] = { { .vmid	  = vmid,
						  .rights = MEM_RIGHTS_RWX } };
			sgl_entry_t sgl[1U];
			sgl[0].ipa =
				(root_addr_cells == 2)
					? fdt64_ld((const fdt64_t *)reg_prop)
					: fdt32_ld((const fdt32_t *)reg_prop);
			reg_prop = (void *)((uintptr_t)reg_prop + addr_bytes);
			sgl[0].size =
				(root_size_cells == 2)
					? fdt64_ld((const fdt64_t *)reg_prop)
					: fdt32_ld((const fdt32_t *)reg_prop);

			printf("%s: accepting %s @ %#" PRIx64 " ++ %#" PRIx64
			       "\n",
			       __func__,
			       fdt_get_name(base_dtb, region_node, NULL),
			       sgl[0].ipa, sgl[0].size);

			memparcel_accept_sgl_resp_t *sgl_resp = NULL;
			size_t			     sgl_resp_size;
			rm_error_t rm_err = memparcel_do_accept(
				vmid, 1U, 1U, 0U, acl, sgl, NULL, 0U,
				memparcel_get_handle(mp), 0U,
				memparcel_get_mem_type(mp),
				memparcel_get_trans_type(mp),
				MEM_ACCEPT_FLAG_DONE, &sgl_resp,
				&sgl_resp_size);
			if (rm_err != RM_OK) {
				printf("error: %s: accept failed (%d)",
				       __func__, rm_err);
				continue;
			}
		}

		// Finally, patch the DT
		char path[128];
		snprintf(path, sizeof(path), "/reserved-memory/%s", name);
		dto_modify_begin_by_path(dto, path);

		dto_property_add_u32(dto, "qcom,rm-mem-handle",
				     memparcel_get_handle(mp));

		// Find the region's phandle, if any
		int	    phandle_len;
		const void *phandle_prop = fdt_getprop(base_dtb, region_node,
						       "phandle", &phandle_len);
		if ((phandle_prop != NULL) &&
		    (phandle_len == sizeof(uint32_t))) {
			// Existing phandle; make a note of it
			memparcel_set_phandle(mp, vmid, fdt32_ld(phandle_prop),
					      true);
		} else {
			// No existing phandle; add one in the overlay
			uint32_t phandle;
			dto_property_add_phandle(dto, &phandle);
			memparcel_set_phandle(mp, vmid, phandle, false);
		}

		dto_modify_end_by_path(dto, path);
	}

out:
	return ret;
}

create_dtbo_ret_t
create_dtbo(vm_t *vm, const void *base_dtb)
{
	create_dtbo_ret_t ret = { .err = OK, .dtbo = NULL, .size = 0UL };

	assert(vm != NULL);

	vmid_t	 vmid	  = vm->vmid;
	vmaddr_t ipa_base = vm->ipa_base;
	size_t	 ipa_size = vm->mem_size;

	int root_addr_cells = fdt_address_cells(base_dtb, 0);
	int root_size_cells = fdt_size_cells(base_dtb, 0);

	if ((root_addr_cells < 0) || (root_size_cells < 0)) {
		ret.err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	dto_t *dto = dto_init(NULL, 0UL);
	if (dto == NULL) {
		ret.err = ERROR_NOMEM;
		goto out;
	}

	// if it contains /hypervisor node, leave the static configure there
	int hypervisor_node_ofs = fdt_path_offset(base_dtb, "/hypervisor");
	if (hypervisor_node_ofs < 0) {
		hypervisor_node_ofs =
			fdt_path_offset(base_dtb, "/soc/hypervisor");
	}
	bool static_config = (hypervisor_node_ofs >= 0);

	// If a /reserved-memory node exists, we must add to it rather than
	// creating a new one
	int reserved_memory_node_ofs =
		fdt_path_offset(base_dtb, "/reserved-memory");

	printf("%s: hyp %d resmem %d\n", __func__, hypervisor_node_ofs,
	       reserved_memory_node_ofs);

	if (reserved_memory_node_ofs >= 0) {
		// Patch any existing reserved memory nodes with the
		// correct RM handles
		ret.err = patch_resmem_nodes(dto, vmid, base_dtb,
					     reserved_memory_node_ofs,
					     root_addr_cells, root_size_cells);
		if (ret.err != OK) {
			dto_deinit(dto);
			goto out;
		}

		// Extend the existing /reserved-memory node
		dto_modify_begin_by_path(dto, "/reserved-memory");
		ret.err = create_resmem_nodes(dto, vmid, ipa_base,
					      root_addr_cells, root_size_cells,
					      true);
		if (ret.err != OK) {
			dto_deinit(dto);
			goto out;
		}
		dto_modify_end_by_path(dto, "/reserved-memory");
	}

	error_t chosen_patch_ret = patch_chosen_node(dto, vm);
	if (chosen_patch_ret != OK) {
		ret.err = chosen_patch_ret;
		dto_deinit(dto);
		goto out;
	}

	dto_modify_begin_by_path(dto, "/");

	// No /reserved-memory node exists, so create and populate a new one
	if (reserved_memory_node_ofs < 0) {
		dto_node_begin(dto, "reserved-memory");
		dto_property_add_u32(dto, "#address-cells",
				     (uint32_t)root_addr_cells);
		dto_property_add_u32(dto, "#size-cells",
				     (uint32_t)root_size_cells);
		dto_property_add_empty(dto, "ranges");

		ret.err = create_resmem_nodes(dto, vmid, ipa_base,
					      root_addr_cells, root_size_cells,
					      false);
		if (ret.err != OK) {
			dto_deinit(dto);
			goto out;
		}

		dto_node_end(dto, "reserved-memory");
	}

	if (!static_config) {
		ret.err = create_hypervisor_node(dto, vmid);
		if (ret.err != OK) {
			dto_deinit(dto);
			goto out;
		}
	}

	char node_name[DTB_NODE_NAME_MAX];
	snprintf(node_name, DTB_NODE_NAME_MAX, "memory@%lx", ipa_base);

	dto_node_begin(dto, node_name);
	dto_property_add_string(dto, "device_type", "memory");
	dto_property_add_addrrange(dto, "reg", (size_t)root_addr_cells,
				   ipa_base, (size_t)root_size_cells, ipa_size);
	dto_node_end(dto, node_name);

	dto_modify_end_by_path(dto, "/");

	error_t e = dto_finalise(dto);
	if (e != OK) {
		ret.err = ERROR_NOMEM;
		dto_deinit(dto);
		goto out;
	}

	ret.constructed_object = dto;

	ret.dtbo = dto_get_dtbo(dto);
	ret.size = dto_get_size(dto);
out:
	return ret;
}

error_t
create_hypervisor_node(dto_t *dto, vmid_t vmid)
{
	dto_node_begin(dto, "hypervisor");
	dto_property_add_u32(dto, "#address-cells", 2);
	dto_property_add_u32(dto, "#size-cells", 0);
	const char *hyp_compat[3] = { "qcom,gunyah-hypervisor-1.0",
				      "qcom,gunyah-hypervisor", "simple-bus" };
	dto_property_add_stringlist(dto, "compatible", hyp_compat, 3);

	dto_node_begin(dto, "qcom,gunyah-vm");
	const char *id_compat[2] = { "qcom,gunyah-vm-id-1.0",
				     "qcom,gunyah-vm-id" };
	dto_property_add_stringlist(dto, "compatible", id_compat, 2);
	dto_property_add_u32(dto, "qcom,vmid", vmid);
	dto_property_add_u32(dto, "qcom,owner-vmid", VMID_HLOS);
	dto_property_add_string(dto, "qcom,vendor", "QEMU");
	dto_node_end(dto, "qcom,gunyah-vm");

	vm_t *cur_vm = vm_lookup(vmid);
	assert(cur_vm != NULL);
	assert(cur_vm->vm_config != NULL);

	// Find the RM RPC node
	vdevice_node_t *node = NULL;

	error_t dto_err = OK;
	loop_list(node, &cur_vm->vm_config->vdevice_nodes, vdevice_)
	{
		if (!node->export_to_dt) {
			continue;
		}

		if ((node->type == VDEV_MSG_QUEUE_PAIR) |
		    (node->type == VDEV_RM_RPC)) {
			dto_err = dto_create_msg_queue_pair(node, dto);
		} else if (node->type == VDEV_MSG_QUEUE) {
			dto_err = dto_create_msg_queue(node, dto);
		} else if (node->type == VDEV_DOORBELL) {
			dto_err = dto_create_doorbell(node, dto, NULL);
		} else if (node->type == VDEV_SHM) {
			dto_err = dto_create_shm(node, dto, vmid);
		} else {
			dto_err = ERROR_UNIMPLEMENTED;
		}

		if (dto_err) {
			break;
		}
	}

	dto_node_end(dto, "hypervisor");

	return dto_err;
}

error_t
process_memparcels(vmid_t vmid)
{
	error_t ret = OK;

	vm_t *cur_vm = vm_lookup(vmid);
	assert(cur_vm != NULL);
	assert(cur_vm->vm_config != NULL);

	// find out vdevices related with memparcel
	// vdevices "0..*" -- 1 memparcel
	memparcel_t *mp = NULL;
	foreach_memparcel_by_target_vmid (mp, vmid) {
		// FIXME: does all memparcel must have a label?
		label_t label = memparcel_get_label(mp);

		vdevice_node_t *node = NULL;
		loop_list(node, &cur_vm->vm_config->vdevice_nodes, vdevice_)
		{
			label_t vlabel;
			if (node->type == VDEV_SHM) {
				struct vdevice_shm *cfg =
					(struct vdevice_shm *)node->config;
				vlabel = cfg->label;
			} else if (node->type == VDEV_DOORBELL) {
				struct vdevice_doorbell *cfg =
					(struct vdevice_doorbell *)node->config;
				vlabel = cfg->label;
			} else {
				continue;
			}

			if (vlabel != label) {
				continue;
			}

			if (node->type == VDEV_SHM) {
				struct vdevice_shm *cfg =
					(struct vdevice_shm *)node->config;
				cfg->mp = mp;
				break;
			} else if (node->type == VDEV_DOORBELL) {
				struct vdevice_doorbell *cfg =
					(struct vdevice_doorbell *)node->config;
				cfg->related_mp = mp;
				break;
			}
		}

		if ((node != NULL) && (node->type == VDEV_SHM)) {
			struct vdevice_shm *cfg =
				(struct vdevice_shm *)node->config;
			if (!cfg->need_allocate &&
			    !memparcel_is_shared(mp, vmid)) {
				// FIXME: might need to get size based on mp,
				// is that right? the size is also wrong.
				accept_memparcel_fixed(vmid, mp, cfg->base_ipa,
						       cfg->sz);
			}
		}
	}

	return ret;
}

error_t
accept_memparcel(vmid_t vmid, const memparcel_t *mp)
{
	error_t ret = OK;

	// FIXME: should we allowed different rights?
	acl_entry_t acl[1U] = { { .vmid = vmid, .rights = MEM_RIGHTS_RWX } };

	count_t region_cnt = memparcel_get_num_regions(mp);
	assert(region_cnt > 0);

	memparcel_accept_sgl_resp_t *sgl = NULL;
	size_t			     sgl_size;

	rm_error_t rm_err = memparcel_do_accept(
		vmid, 1U, 0U, 0U, acl, NULL, NULL, 0U, memparcel_get_handle(mp),
		0U, memparcel_get_mem_type(mp), memparcel_get_trans_type(mp),
		MEM_ACCEPT_FLAG_DONE, &sgl, &sgl_size);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
	}

	if (sgl != NULL) {
		free(sgl);
	}

	return ret;
}

error_t
accept_memparcel_fixed(vmid_t vmid, const memparcel_t *mp, vmaddr_t ipa,
		       size_t sz)
{
	error_t ret = OK;

	// FIXME: should we allowed different rights?
	acl_entry_t acl[1U] = { { .vmid = vmid, .rights = MEM_RIGHTS_RW } };

	count_t region_cnt = memparcel_get_num_regions(mp);
	assert(region_cnt > 0);

	memparcel_accept_sgl_resp_t *sgl_resp = NULL;
	size_t			     sgl_resp_size;

	sgl_entry_t sgl[1] = { { .ipa = ipa, .size = sz } };

	rm_error_t rm_err = memparcel_do_accept(
		vmid, 1U, 1U, 0U, acl, sgl, NULL, 0U, memparcel_get_handle(mp),
		0U, memparcel_get_mem_type(mp), memparcel_get_trans_type(mp),
		MEM_ACCEPT_FLAG_DONE, &sgl_resp, &sgl_resp_size);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
	}

	if (sgl_resp != NULL) {
		free(sgl_resp);
	}

	return ret;
}

get_random_seed_ret_t
get_random_seed(void)
{
	get_random_seed_ret_t ret = { .err = OK };

	__asm__ volatile("mrs %0, RNDR;" : "=r"(ret.seed));

	return ret;
}

error_t
patch_chosen_node(dto_t *dto, vm_t *vm)
{
	error_t ret = OK;

	get_random_seed_ret_t seed_ret = get_random_seed();
	if (seed_ret.err != OK) {
		printf("vm %d, failed to get random seed\n", vm->vmid);
		ret = seed_ret.err;
		goto out;
	}

#define CHECK_DTO(ret_val, dto_call)                                           \
	do {                                                                   \
		ret_val = (dto_call);                                          \
		if (ret_val != OK) {                                           \
			goto out;                                              \
		}                                                              \
	} while (0)

	CHECK_DTO(ret, dto_modify_begin_by_path(dto, "/chosen"));

	CHECK_DTO(ret, dto_property_add_u64(dto, "kaslr-seed", seed_ret.seed));

	if (vm->ramfs_size > 0U) {
		assert(!util_add_overflows(vm->ramfs_offset, vm->ipa_base));
		vmaddr_t ramfs_ipa_start = vm->ramfs_offset + vm->ipa_base;

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

	CHECK_DTO(ret, dto_modify_end_by_path(dto, "/chosen"));
#undef CHECK_DTO

out:
	return ret;
}
