// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_VM_MEMORY_H_
#define INCLUDE_VM_MEMORY_H_

// We limit the size of the address space so we can store page-aligned addresses
// in 32 bits.
#define ADDR_LIMIT util_bit(32U + PAGE_BITS)

// This enum gives information on the use of memory being mapped in a VM.
// The mapping behaviour of memory may differ depending on its usage.
typedef enum {
	// Used for mapping normal DDR memory.
	VM_MEMUSE_NORMAL,
	// Used for mapping physical devices.
	VM_MEMUSE_IO,
	// Used for purely virtual devices, such as virtio-mmio.
	// Must not overlap with the physical device range.
	VM_MEMUSE_VDEVICE,
	// Virtual devices based on real physical devices.
	// May overlap with the physical device range.
	VM_MEMUSE_PLATFORM_VDEVICE,
	// Used for VM boot info mapping.
	VM_MEMUSE_BOOTINFO,
	// Used for creating protected mappings of normal DDR memory; that is,
	// mappings that can be reclaimed by an untrusted host VM, but only
	// after they are explicitly released by the VM (or RM on its behalf).
	VM_MEMUSE_PROTECTED,
} vm_memuse_t;

error_t
vm_memory_init(void);

error_t
vm_memory_setup(vm_t *vm);

error_t
vm_memory_vm_start(vm_t *vm);

void
vm_memory_sanitise(const vm_t *vm);

void
vm_memory_teardown(vm_t *vm);

error_t
vm_memory_map(vm_t *vm, vm_memuse_t memuse, cap_id_t me_cap, vmaddr_t ipa,
	      pgtable_access_t access, pgtable_vm_memtype_t map_memtype);

error_t
vm_memory_map_partial(vm_t *vm, vm_memuse_t memuse, cap_id_t me_cap,
		      vmaddr_t ipa, size_t offset, size_t size,
		      pgtable_access_t	   access,
		      pgtable_vm_memtype_t map_memtype);

error_t
vm_memory_unmap(vm_t *vm, vm_memuse_t memuse, cap_id_t me_cap, vmaddr_t ipa);

error_t
vm_memory_unmap_partial(vm_t *vm, vm_memuse_t memuse, cap_id_t me_cap,
			vmaddr_t ipa, size_t offset, size_t size);

error_t
vm_memory_remap(vm_t *vm, vm_memuse_t memuse, cap_id_t me_cap, vmaddr_t ipa,
		pgtable_access_t old_access, pgtable_access_t new_access,
		pgtable_vm_memtype_t old_memtype,
		pgtable_vm_memtype_t new_memtype);

error_t
vm_memory_remap_partial(vm_t *vm, vm_memuse_t memuse, cap_id_t me_cap,
			vmaddr_t ipa, size_t offset, size_t size,
			pgtable_access_t     old_access,
			pgtable_access_t     new_access,
			pgtable_vm_memtype_t old_memtype,
			pgtable_vm_memtype_t new_memtype);

cap_id_result_t
vm_memory_create_and_map(vm_t *vm, vm_memuse_t memuse, cap_id_t parent_me,
			 size_t offset, size_t size, vmaddr_t ipa,
			 memextent_memtype_t  me_memtype,
			 pgtable_access_t     access,
			 pgtable_vm_memtype_t map_memtype);

// Start a batch job of memextent operations.
void
vm_memory_batch_start(cap_id_t me_cap);

// Finish a batch job of memextent operations and synchronize.
void
vm_memory_batch_end(void);

typedef struct {
	error_t		     err;
	uint8_t		     pad_to_phys[4];
	paddr_t		     phys;
	size_t		     size;
	pgtable_access_t     access;
	pgtable_vm_memtype_t map_memtype;
} vm_memory_result_t;

vm_memory_result_t
vm_memory_lookup(vm_t *vm, vm_memuse_t memuse, vmaddr_t ipa, size_t size);

size_result_t
vm_address_range_init(vm_t *vm);

void
vm_address_range_destroy(vm_t *vm);

typedef struct {
	error_t		    err;
	address_range_tag_t tag;
	vmaddr_t	    base;
	size_t		    size;
} vm_address_range_result_t;

vm_address_range_result_t
vm_address_range_alloc(vm_t *vm, vm_memuse_t memuse, vmaddr_t start_addr,
		       paddr_t phys, size_t size, size_t alignment);

error_t
vm_address_range_free(vm_t *vm, vm_memuse_t memuse, vmaddr_t base, size_t size);

error_t
vm_address_range_tag(vm_t *vm, vmaddr_t base, size_t size,
		     address_range_tag_t tag);

// Find and tag a region based on the given constraints.
vm_address_range_result_t
vm_address_range_tag_any(vm_t *vm, vmaddr_t start_addr, size_t addr_limit,
			 size_t size, size_t alignment,
			 address_range_tag_t tag);

error_t
vm_address_range_untag(vm_t *vm, vmaddr_t base, size_t size,
		       address_range_tag_t tag);

typedef struct vm_acl_info vm_acl_info_t;

typedef struct {
	error_t	       err;
	uint8_t	       pad_to_info[4];
	vm_acl_info_t *info;
} vm_acl_info_result_t;

// Set up a memparcel to transfer memory owned by the specified VM.
//
// Returns an ACL information pointer which will be stored in the memparcel and
// provided to vm_memory_donate_extent() calls, including during subsequent
// append operations. The pointer is opaque to the caller and may be NULL.
vm_acl_info_result_t
vm_memory_get_acl_info(vm_t *vm, uint8_t mem_type, cap_id_t mp_me_cap,
		       uint8_t trans_type, acl_entry_t *acl,
		       uint32_t acl_entries, bool vm_init);

// Free an ACL info struct if one was allocated by the above function.
void
vm_memory_free_acl_info(vm_acl_info_t *info);

// Create a memextent suitable for donation with a VM.
cap_id_result_t
vm_memory_create_extent(uint8_t mem_type);

// Get the memextent used for owned memory in a VM.
//
// This should only be used for mapping operations.
cap_id_t
vm_memory_get_owned_extent(const vm_t *vm, uint8_t mem_type);

// Get the memextent used for paged memory in a VM.
//
// This should only be used for mapping operations and to provide the VM's
// paging extent capability to its host VM. It returns CSPACE_CAP_INVALID if
// the VM does not have demand paging enabled, vm_memory_setup_paged_extents()
// has not been called yet, or is_private is true but the VM is not protected.
//
// The memory type for this API is always MEM_TYPE_NORMAL.
cap_id_t
vm_memory_get_paged_extent(const vm_t *vm, bool is_private);

// Create the memextents used for paged memory in a VM.
//
// This should be called once for each demand paged VM to create the paged
// memory extents. It must be done after acceptance of the image memparcel,
// as the parent extents for the paged memory extents may not have been created
// before that point. This function will return ERROR_BUSY if the paged extents
// have already been created.
//
// The memory type for this API is always MEM_TYPE_NORMAL.
error_t
vm_memory_setup_paged_extents(vm_t *vm);

// Get the memextent used to transfer memory to a specified ACL from a VM.
//
// This should only be used for dynamic paging setup for host VMs. Note that
// it may return the same capability as vm_memory_get_owned_extent(vm).
cap_id_t
vm_memory_get_source_extent(const vm_t *vm, uint8_t mem_type, acl_entry_t *acl,
			    uint32_t acl_entries);

// Donate memory between a VM's owned extent and a memparcel extent.
error_t
vm_memory_donate_extent(vm_t *vm, uint8_t mem_type, vm_acl_info_t *acl_info,
			cap_id_t mp_me_cap, paddr_t phys, size_t size,
			bool to_mp);

// Donate memory between a VM's paged extent and a memparcel extent.
//
// This should only be called after vm_memory_set_paged_extent(); it will fail
// if that function has not been called.
//
// The memory must be in an extent that is either exclusively mapped RWX to the
// VM (is_private = true), or mapped RWX to both the VM and its owner but to no
// other vm (is_private = false). In the latter case, the preceding call to
// vm_memory_set_paged_extent() must have had is_private set to false too.
error_t
vm_memory_add_to_paged_extent(const vm_t *vm, cap_id_t mp_me_cap, paddr_t phys,
			      size_t size, bool is_private, bool reclaim);

// Convert a set of IPA constraints to an address range tag.
address_range_tag_t
vm_memory_constraints_to_tag(vm_t *vm, uint32_t generic_constraints,
			     uint32_t platform_constraints);

// Get the compatible address range tag for a region of physical memory.
address_range_tag_t
vm_memory_get_phys_address_tag(paddr_t phys, size_t size);

#else

#error multiple include of vm_memory.h

#endif
