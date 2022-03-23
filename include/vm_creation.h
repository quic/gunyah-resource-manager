// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define MAX_CAPS    1024
#define GIC_SPI_NUM 988
#define GIC_LPI_NUM 8192

typedef struct {
	cap_id_t *vic_hwirqs;
	cap_id_t *vic_msi_sources;
	count_t	  vic_hwirq_count;
	count_t	  vic_msi_source_count;
} hwirq_caps_t;

error_t
hlos_vm_create(hwirq_caps_t hwirq_caps, boot_env_data_t *env_data);

error_t
hlos_vm_start(void);

error_t
hlos_map_memory(paddr_t phys, vmaddr_t ipa, size_t size,
		pgtable_access_t access, pgtable_vm_memtype_t memtype);

error_t
hlos_map_io_memory(paddr_t phys, vmaddr_t ipa, size_t size, cap_id_t me_cap);

error_t
hlos_unmap_io_memory(vmaddr_t addr, size_t size, bool check_mapped,
		     cap_id_t me_cap);

typedef struct {
	error_t		     err;
	uint8_t		     pad_to_paddr[4];
	paddr_t		     paddr;
	pgtable_access_t     access;
	pgtable_vm_memtype_t memtype;
} hlos_memory_result_t;

hlos_memory_result_t
hlos_memory_is_mapped(vmaddr_t ipa, size_t size, bool io_memory);

typedef struct {
	error_t	 err;
	uint32_t mp_handle;
} svm_setup_ret_t;

error_t
svm_create(vmid_t vmid);

svm_setup_ret_t
svm_setup(vmid_t vmid);

error_t
svm_poweron(vmid_t vmid);

typedef struct vm_mem_range vm_mem_range_t;

struct vm_mem_range {
	cap_id_t	me;
	vmaddr_t	ipa;
	paddr_t		phys;
	size_t		size;
	vm_mem_range_t *node_next;
	vm_mem_range_t *node_prev;
};

rm_error_t
svm_add_mem_range(vm_t *svm, cap_id_t me, vmaddr_t ipa, paddr_t phys,
		  size_t size);

vm_mem_range_t *
svm_lookup_mem_range(vm_t *svm, vmaddr_t ipa, size_t size);

rm_error_t
svm_remove_mem_range(vm_t *svm, vm_mem_range_t *mem_range);

bool
vm_creation_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len);

error_t
vm_creation_process_resource(vmid_t vmid);

typedef struct memparcel memparcel_t;

error_t
vm_creation_process_memparcel(vmid_t vmid, memparcel_t *mp);

error_t
hlos_vm_setup(boot_env_data_t *env_data);
