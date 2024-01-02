// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// We limit the size of the address space so we can store page-aligned addresses
// in 32 bits.
#define ADDR_LIMIT util_bit(32 + PAGE_BITS)

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
} vm_memuse_t;

error_t
vm_memory_init(void);

error_t
vm_memory_setup(vm_t *vm);

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
vm_memory_batch_start(void);

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

typedef uint32_t address_range_tag_t;

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
vm_address_range_tag_any(vm_t *vm, vmaddr_t constrain_base,
			 size_t constrain_size, size_t size, size_t alignment,
			 address_range_tag_t tag);

error_t
vm_address_range_untag(vm_t *vm, vmaddr_t base, size_t size,
		       address_range_tag_t tag);

typedef struct acl_entry   acl_entry_t;
typedef struct vm_acl_info vm_acl_info_t;

typedef struct {
	error_t	       err;
	uint8_t	       pad_to_info[4];
	vm_acl_info_t *info;
} vm_acl_info_result_t;

// Check if a particular memparcel ACL is valid for a VM. Returns ACL
// information required for transfer of memory between a memparcel and a VM.
vm_acl_info_result_t
vm_memory_get_acl_info(vm_t *vm, uint8_t mem_type, uint8_t trans_type,
		       acl_entry_t *acl, uint32_t acl_entries, bool vm_init);

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
vm_memory_get_owned_extent(vm_t *vm, uint8_t mem_type);

// Get the base physical address of a VM extent.
paddr_t
vm_memory_get_extent_base(uint8_t mem_type);

// Donate memory between a VM and a memparcel memextent.
error_t
vm_memory_donate_extent(vm_t *vm, uint8_t mem_type, vm_acl_info_t *acl_info,
			cap_id_t mp_me_cap, paddr_t phys, size_t size,
			bool to_mp);

// Convert a set of IPA constraints to an address range tag.
address_range_tag_t
vm_memory_constraints_to_tag(vm_t *vm, uint32_t generic_constraints,
			     uint32_t platform_constraints);

// Get the compatible address range tag for a region of physical memory.
address_range_tag_t
vm_memory_get_phys_address_tag(paddr_t phys, size_t size);
