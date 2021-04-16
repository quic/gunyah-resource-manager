// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define MAX_CAPS	   1024
#define PLATFORM_MAX_CORES 8
#define ROOT_VCPU_INDEX	   0
#define GIC_SPI_NUM	   988

// Secure domain IDs

#define AC_VM_HLOS		3
#define AC_VM_HLOS_UNMAPPED	14
#define AC_VM_TZ_UNMAPPED	20
#define AC_VM_KERNEL_PROTECTION 35
#define AC_VM_TRUSTED_UI	45

typedef struct {
	cap_id_t *vic_hwirqs;
	count_t	  count;
	char	  _pad[4];
} hwirq_cap_array_t;

error_t
hlos_vm_create(hwirq_cap_array_t hwirq_caps);

error_t
hlos_vm_setup(void);

error_t
hlos_vm_start(void);

error_t
hlos_map_io_memory(cap_id_t me_cap, vmaddr_t ipa);

error_t
hlos_unmap_io_memory(cap_id_t me_cap, vmaddr_t addr);

typedef struct {
	error_t	 err;
	uint32_t mp_handle;
} svm_setup_ret_t;

error_t
svm_create(vmid_t vmid);

typedef struct mem_region mem_region_t;

svm_setup_ret_t
svm_setup(vmid_t vmid);

error_t
svm_poweron(vmid_t vmid);

bool
vm_creation_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len);

error_t
vm_creation_process_resource(vmid_t vmid);
