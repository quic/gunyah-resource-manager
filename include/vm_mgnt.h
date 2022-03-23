// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define VM_MAX_NAME_LEN 80
#define VM_GUID_LEN	16
#define VM_MAX_URI_LEN	80

// 16 byte, each costs 2 char, 4 char for '-', 1 for terminator
#define VM_MAX_GUID_STRING_LEN (16 * 2 + 4 + 1)

typedef enum {
	VM_STATE_NONE	 = 0,
	VM_STATE_INIT	 = 1,
	VM_STATE_READY	 = 2,
	VM_STATE_RUNNING = 3,
	VM_STATE_PAUSED	 = 4,
	// 5, 6, 7 reserved
	VM_STATE_INIT_FAILED = 8,
	VM_STATE_EXITED	     = 9,
	VM_STATE_RESETTING   = 10,
	VM_STATE_RESET	     = 11,
} vm_state_t;

typedef enum {
	OS_STATE_NONE	    = 0,
	OS_STATE_EARLY_BOOT = 1,
	OS_STATE_BOOT	    = 2,
	OS_STATE_INIT	    = 3,
	OS_STATE_RUN	    = 4,
	OS_STATE_SHUTDOWN   = 5,
	OS_STATE_HALTED	    = 6,
	OS_STATE_CRASHED    = 7,
} os_state_t;

typedef uint16_t app_status_t;

struct address_range_allocator;
typedef struct address_range_allocator address_range_allocator_t;

struct vm_mem_range;
typedef struct vm_mem_range vm_mem_range_t;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

struct vm {
	vmid_t vmid;
	vmid_t owner;

	vector_t *peers;

	char	 name[VM_MAX_NAME_LEN];
	uint16_t name_len;

	bool	 has_uri;
	char	 uri[VM_MAX_URI_LEN];
	uint16_t uri_len;

	bool	has_guid;
	uint8_t guid[VM_GUID_LEN];

	vm_state_t   vm_state;
	os_state_t   os_state;
	app_status_t app_status;

	vm_config_t *vm_config;

	address_range_allocator_t *as_allocator;

	vm_mem_range_t *mem_list;

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

	uint32_t signer_info;

	priority_t priority;

	bool sensitive;
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

void
vm_mgnt_set_name(vm_t *vm, const char *name);

vm_t *
vm_lookup(vmid_t vmid);

bool
vm_is_secondary_vm(vmid_t vmid);

bool
vm_is_peripheral_vm(vmid_t vmid);

error_t
vm_register_peers(vm_t *vm1, vm_t *vm2);

void
vm_deregister_peers(vm_t *vm1, vm_t *vm2);

void
vm_deregister_all_peers(vm_t *vm);

vm_t *
vm_lookup_by_id(const char *peer_id);

rm_error_t
vm_mgnt_send_state(vm_t *vm);

bool
vm_mgnt_is_vm_sensitive(vmid_t vmid);
