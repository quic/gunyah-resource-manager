// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// 16 byte, each costs 2 char, 4 char for '-', 1 for terminator
#define VM_MAX_GUID_STRING_LEN (16 * 2 + 4 + 1)

#define VM_MAX_CRASH_MSG_LEN 192

typedef enum {
	VM_STATE_NONE	 = 0,
	VM_STATE_INIT	 = 1,
	VM_STATE_READY	 = 2,
	VM_STATE_RUNNING = 3,
	VM_STATE_PAUSED	 = 4,
	VM_STATE_LOAD	 = 5,
	VM_STATE_AUTH	 = 6,
	// 7 reserved
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

typedef enum {
	EXIT_TYPE_VM_EXIT	     = 0,
	EXIT_TYPE_PLATFORM_OFF	     = 1,
	EXIT_TYPE_PLATFORM_RESET     = 2,
	EXIT_TYPE_PSCI_SYSTEM_RESET2 = 3,
	EXIT_TYPE_WATCHDOG_BITE	     = 4,
	EXIT_TYPE_SOFTWARE_ERROR     = 5,
	EXIT_TYPE_ASYNC_HW_ERROR     = 6,
	EXIT_TYPE_VM_STOP_FORCED     = 7,
} exit_type_t;

// EXIT_FLAGS bit numbering
typedef enum {
	EXIT_FLAG_RESTART = 0,
} exit_flags_t;

typedef enum {
	EXIT_CODE_NORMAL	 = 0,
	EXIT_CODE_SOFTWARE_ERROR = 1,
	EXIT_CODE_UNKNOWN_ERROR	 = 2,
	EXIT_CODE_BUS_ERROR	 = 3,
	EXIT_CODE_DEVICE_ERROR	 = 4,
} exit_code_t;

typedef enum {
	VM_EVENT_SRC_WDOG_BITE = 0,
	VM_EVENT_SRC_VCPU_HALT = 1,
} vm_event_src_t;

typedef enum {
	VM_RESET_STAGE_INIT		  = 0,
	VM_RESET_STAGE_DESTROY_VDEVICES	  = 1,
	VM_RESET_STAGE_RELEASE_MEMPARCELS = 2,
	VM_RESET_STAGE_RELEASE_IRQS	  = 3,
	VM_RESET_STAGE_DESTROY_VM	  = 4,
	VM_RESET_STAGE_CLEANUP_VM	  = 5,
	VM_RESET_STAGE_COMPLETED	  = 6,
} vm_reset_stage_t;

struct address_range_allocator;
typedef struct address_range_allocator address_range_allocator_t;
typedef uint32_t		       address_range_tag_t;

struct vm_mem_range;
typedef struct vm_mem_range vm_mem_range_t;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

struct vm_s {
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
	paddr_t			   as_size;

	vm_mem_range_t *mem_list;

	vm_auth_type_t auth_type;
	// VM base memory
	uint32_t	    mem_mp_handle;
	address_range_tag_t mem_base_tag;

	paddr_t image_offset;
	size_t	image_size;

	paddr_t ramfs_offset;
	size_t	ramfs_size;

	paddr_t	  cfgcpio_offset;
	size_t	  cfgcpio_size;
	vector_t *cfgcpio_cmdline;
	size_t	  cfgcpio_cmdline_len;

	paddr_t entry_offset;

	paddr_t dt_offset;
	size_t	dt_size;

	vmaddr_t ipa_base;
	paddr_t	 mem_base;
	vmaddr_t mem_size;

	uint32_t fw_mp_handle;
	size_t	 fw_offset;
	size_t	 fw_size;

	vmaddr_t vm_info_area_ipa;
	size_t	 vm_info_area_size;
	vmaddr_t vm_info_area_rm_ipa;

	cap_id_t owned_ddr_me;
	cap_id_t owned_device_me;

	uint32_t chip_id;
	uint32_t chip_version;
	uint32_t foundry_id;
	uint32_t platform_type;
	uint32_t platform_version;
	uint32_t platform_subtype;
	uint32_t hlos_subtype;

	uint32_t signer_info;

	priority_t priority;
	event_t	   wdog_bite_event;

	count_t mp_count;

	char	*crash_msg;
	uint16_t crash_msg_len;

	bool sensitive;
	bool crash_fatal;
	bool no_shutdown;
	bool qtee_registered;

	vm_reset_stage_t reset_stage;
	event_t		 reset_event;
};

#pragma clang diagnostic pop

rm_error_t
vm_mgnt_init(void);

bool
vm_mgnt_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		    void *buf, size_t len);

void
vm_mgnt_set_name(vm_t *vm, const char *name);

vm_t *
vm_lookup(vmid_t vmid);

bool
vm_is_secondary_vm(vmid_t vmid);

bool
vm_is_peripheral_vm(vmid_t vmid);

bool
vm_is_dynamic_vm(vmid_t vmid);

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

bool
vm_mgnt_state_change_valid(const vm_t *vm, vm_state_t vm_state);

rm_error_t
vm_mgnt_register_event(vm_event_src_t event_src, event_t *event, void *data,
		       virq_t virq);

void
vm_mgnt_deregister_event(event_t *event, virq_t virq);

void
vm_mgnt_clear_crash_msg(vmid_t client_id);
