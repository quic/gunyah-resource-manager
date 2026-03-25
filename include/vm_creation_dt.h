// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_VM_CREATION_DT_H_
#define INCLUDE_VM_CREATION_DT_H_

error_t
vm_creation_add_compatibles(const struct vdevice_node *node,
			    const char *const	       compatibles[],
			    count_t compatible_cnt, dto_t *dto);

error_t
vm_creation_add_symbol(const struct vdevice_node *node, dto_t *dto);

error_t
vm_creation_virtio_device_properties(const struct vdevice_node *node,
				     dto_t		       *dto);

error_t
vm_creation_replace_symbols(const vm_t *vm, dto_t *dto);

error_t
vm_creation_patch_vsoc_devices(vm_t *vm, dto_t *dto);

error_t
vm_creation_patch_reserved_memory(vm_t *vm, const void *base_dtb, dto_t *dto,
				  count_t root_addr_cells,
				  count_t root_size_cells);

error_t
vm_creation_generate_memory_node(dto_t *dto, vmid_t vmid,
				 count_t root_addr_cells,
				 count_t root_size_cells);

error_t
vm_creation_patch_chosen_node(dto_t *dto, vm_t *vm, const void *base_dtb);

char *
vm_creation_node_name_capid(const char *generate, cap_id_t cap_id);

#else

#error multiple include of vm_creation_dt.h

#endif
