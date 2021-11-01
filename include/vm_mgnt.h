// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define VM_MAX_NAME_LEN 80

typedef enum {
	VM_STATE_NONE = 0,
	VM_STATE_INIT,
	VM_STATE_READY,
	VM_STATE_RUNNING,
	VM_STATE_PAUSED,
	VM_STATE_SHUTDOWN,
	VM_STATE_SHUTOFF,
	VM_STATE_CRASHED,
	VM_STATE_INIT_FAILED,
} vm_state_t;

typedef enum {
	OS_STATE_NONE = 0,
	OS_STATE_EARLY_BOOT,
	OS_STATE_BOOT,
	OS_STATE_INIT,
	OS_STATE_RUN,
} os_state_t;

typedef uint16_t app_status_t;

struct address_range_allocator;
typedef struct address_range_allocator address_range_allocator_t;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

struct vm {
	vmid_t vmid;
	vmid_t owner;
	char   name[VM_MAX_NAME_LEN];

	vm_state_t   vm_state;
	os_state_t   os_state;
	app_status_t app_status;

	vm_config_t *vm_config;

	address_range_allocator_t *as_allocator;

	cap_id_t primary_vcpu_cap;

	paddr_t mem_base;
	size_t	mem_size;

	int	ramfs_idx;
	paddr_t ramfs_offset;
	size_t	ramfs_size;

	// VM memory region mp
	uint32_t mem_mp_handle;

	paddr_t entry_offset;

	paddr_t dtb_region_offset;
	size_t	dtb_region_size;
	paddr_t segment_offset_after_dtb;

	vmaddr_t ipa_base;

	uint32_t chip_id;
	uint32_t chip_version;
	uint32_t foundry_id;
	uint32_t platform_type;
	uint32_t platform_version;
	uint32_t platform_subtype;
	uint32_t hlos_subtype;
};
typedef struct vm vm_t;

#pragma clang diagnostic pop

void
vm_mgnt_init(void);

bool
vm_mgnt_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		    void *buf, size_t len);

rm_error_t
vm_mgnt_new_vm(vmid_t vmid, vmid_t owner);

vm_t *
vm_lookup(vmid_t vmid);

rm_error_t
vm_mgnt_send_state(vm_t *vm);
