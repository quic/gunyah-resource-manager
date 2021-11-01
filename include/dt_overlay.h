// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Wrappers for device tree binary overlay creation.
// This set of APIs are implmeneted based on libfdt library. It supports the
// basic operation to add/modify the existing device tree node/property.
// Most of the API use full path to refer a node/property.
// Due to the libfdt only support sequential write, the API are defined as a
// sequential write style.

#define DTB_NODE_NAME_MAX 128
#define DTBO_MAX_SIZE	  (4 * PAGE_SIZE)

typedef struct dto dto_t;

dto_t *
dto_init(void *external_memory, size_t memory_size);

// Start to modify a node, it will create a fragment for that target.
// And return it's path to buf
error_t
dto_modify_begin(dto_t *dto, const char *target);

error_t
dto_modify_end(dto_t *dto, const char *target);

error_t
dto_modify_begin_by_path(dto_t *dto, const char *target);

error_t
dto_modify_end_by_path(dto_t *dto, const char *target);

error_t
dto_node_begin(dto_t *dto, const char *name);

error_t
dto_node_end(dto_t *dto, const char *name);

error_t
dto_property_add_u32(dto_t *dto, const char *name, uint32_t val);

error_t
dto_property_add_u64(dto_t *dto, const char *name, uint64_t val);

error_t
dto_property_add_u32array(dto_t *dto, const char *name, uint32_t vals[],
			  count_t cnt);

error_t
dto_property_add_u64array(dto_t *dto, const char *name, uint64_t vals[],
			  count_t cnt);

// Blob is a user defined format, so the data size bigger than char needs to
// be converted to fdt order(endian) before adding.
error_t
dto_property_add_blob(dto_t *dto, const char *name, uint8_t vals[],
		      count_t cnt);

error_t
dto_property_add_string(dto_t *dto, const char *name, const char *val);

error_t
dto_property_add_stringlist(dto_t *dto, const char *name, const char *vals[],
			    count_t cnt);

// In order to be referred by others, a node must add a phandle property.
// It will generate a phandle under current node.
error_t
dto_property_add_phandle(dto_t *dto, uint32_t *pphandle);

// Add an address range property, given the values of the parent node's
// #addr-cells and #size-cells properties. Note that for overlays these might
// need to be obtained from a parent node in the base device tree.
error_t
dto_property_add_addrrange(dto_t *dto, const char *name, size_t addr_cells,
			   uint64_t addr, size_t size_cells, uint64_t size);

// Add an external reference, it's a phandle property, the value is set to
// 0xFFFFFFFF, and a fixup entry is added.
error_t
dto_property_ref_external(dto_t *dto, const char *property_name,
			  const char *target_label);

// Just helper utility to ref internal.
error_t
dto_property_ref_internal(dto_t *dto, const char *name, uint32_t phandle);

error_t
dto_property_add_empty(dto_t *dto, const char *name);

error_t
dto_finalise(dto_t *dto);

void *
dto_get_dtbo(dto_t *dto);

size_t
dto_get_size(dto_t *dto);

void
dto_deinit(dto_t *dto);
