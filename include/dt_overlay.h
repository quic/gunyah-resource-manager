// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Wrappers for device tree binary overlay creation.
// This set of APIs are implmeneted based on libfdt library. It supports the
// basic operation to add/modify the existing device tree node/property.
// Most of the API use full path to refer a node/property.
// Due to the libfdt only support sequential write, the API are defined as a
// sequential write style.

#define DTB_NODE_NAME_MAX 128U
#define DTBO_MAX_SIZE	  (4U * PAGE_SIZE)

// Mark unset phandles with only the high bit, because this is unlikely to
// silently turn into an incorrect valid phandle during overlay application due
// to local fixups. If we set it to -1 it would be replaced by the last valid
// phandle in the base DTB, which is not what we want.
//
// This is used for internal references. For external refererences, we use an
// invalid value of -1.
#define DTO_PHANDLE_UNSET (uint32_t)0x80000000U

typedef struct dto_s dto_t;

#define CHECK_DTO(ret_val, dto_call)                                           \
	do {                                                                   \
		ret_val = (dto_call);                                          \
		if (ret_val != OK) {                                           \
			goto out;                                              \
		}                                                              \
	} while (0)

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
dto_modify_begin_by_phandle(dto_t *dto, uint32_t target);

error_t
dto_modify_end_by_phandle(dto_t *dto, uint32_t target);

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
dto_property_add_addrrange(dto_t *dto, const char *name, count_t addr_cells,
			   uint64_t addr, count_t size_cells, uint64_t size);

// An address range for dto_property_add_addrrange_array().
typedef struct {
	uint64_t addr;
	uint64_t size;
} dto_addrrange_t;

// Add an array of address range properties, given the values of the parent
// node's #addr-cells and #size-cells properties. Note that for overlays these
// might need to be obtained from a parent node in the base device tree.
error_t
dto_property_add_addrrange_array(dto_t *dto, const char *name,
				 const dto_addrrange_t ranges[],
				 count_t entries, count_t addr_cells,
				 count_t size_cells);

// Add an array of interrupts, normally for the "interrupts" property.
error_t
dto_property_add_interrupts_array(dto_t *dto, const char *name,
				  const interrupt_data_t *interrupts,
				  count_t		  entries);

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

// Construct modification path node.
// This call starts a new overlay fragment at root '/', and then constructs the
// path nodes one by one.
// Note: dto_construct_begin_path cannot be nested.
error_t
dto_construct_begin_path(dto_t *dto, const char *path);

// This call ends the dto fragment node and finalizes the modification.
error_t
dto_construct_end_path(dto_t *dto, const char *path);

error_t
dto_finalise(dto_t *dto);

void *
dto_get_dtbo(dto_t *dto);

size_t
dto_get_size(dto_t *dto);

void
dto_deinit(dto_t *dto);
