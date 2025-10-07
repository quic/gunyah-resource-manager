// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_VM_CONFIG_STRUCT_H_
#define INCLUDE_VM_CONFIG_STRUCT_H_

typedef enum {
	// two message queues to communicate with resource manager
	VDEV_RM_RPC = 0,
	// indicates the one to receive the doorbell
	VDEV_DOORBELL,
	// contains one direction message queue
	VDEV_MSG_QUEUE,
	// contains two direction message queue
	VDEV_MSG_QUEUE_PAIR,
	VDEV_SHM,
	VDEV_WATCHDOG,
	VDEV_VIRTUAL_PM,
	VDEV_VIRTIO_MMIO,
	VDEV_IOMEM,
	VDEV_SMMU_V2,
	VDEV_RTC,
	VDEV_MINIDUMP,
	VDEV_MEMORY_EXTENT,
	VDEV_ADDRESS_SPACE,
} vdevice_type_t;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

struct vdevice_msg_queue_pair {
	// TX msgq is from VM's perspective
	vmid_t peer;

	// Caps in RM's cspace
	cap_id_t tx_master_cap;
	cap_id_t rx_master_cap;

	cap_id_t	 tx_vm_cap;
	interrupt_data_t tx_vm_virq;
	cap_id_t	 rx_vm_cap;
	interrupt_data_t rx_vm_virq;

	// Note, peer tx == vm rx
	cap_id_t	 tx_peer_cap;
	interrupt_data_t tx_peer_virq;
	cap_id_t	 rx_peer_cap;
	interrupt_data_t rx_peer_virq;

	count_t tx_queue_depth;
	count_t rx_queue_depth;

	size_t tx_max_msg_size;
	size_t rx_max_msg_size;

	bool	 has_peer_vdevice;
	bool	 has_valid_peer;
	uint32_t label;

	char *peer_id;
};

struct vdevice_doorbell {
	vmid_t peer;
	bool   source;
	bool   source_can_clear;

	cap_id_t master_cap;

	cap_id_t	 vm_cap;
	interrupt_data_t vm_virq;
	cap_id_t	 peer_cap;
	interrupt_data_t peer_virq;

	bool	 has_peer_vdevice;
	bool	 has_valid_peer;
	uint32_t label;

	char *peer_id;
};

struct vdevice_virtual_pm {
	vmid_t peer;

	cap_id_t master_cap;

	cap_id_t	 peer_cap;
	interrupt_data_t peer_virq;

	uint32_t label;
};

struct vdevice_virtio_mmio {
	vmid_t backend;

	vmaddr_t backend_ipa;
	vmaddr_t frontend_ipa;

	cap_id_t master_cap;

	cap_id_t me_cap;
	size_t	 me_size;
	void	*rm_addr;

	interrupt_data_t frontend_virq;

	cap_id_t	 backend_cap;
	interrupt_data_t backend_virq;

	bool	 need_allocate;
	vmaddr_t base_ipa;

	uint64_t dma_base;
	bool	 dma_coherent;

	uint32_t label;
	char	*patch;
};

struct vdevice_msg_queue {
	vmid_t peer;
	bool   tx;

	cap_id_t master_cap;

	cap_id_t	 vm_cap;
	interrupt_data_t vm_virq;
	cap_id_t	 peer_cap;
	interrupt_data_t peer_virq;

	uint16_t queue_depth;
	uint16_t msg_size;

	uint32_t label;
};

struct vdevice_shm {
	vdevice_node_t *db;
	vdevice_node_t *db_src;

	vmid_t peer;

	label_t label;

	bool is_plain_shm;

	bool need_allocate;

	bool is_memory_optional;

	vmaddr_t base_ipa;

	uint64_t dma_base;
};

struct vdevice_watchdog {
	interrupt_data_t bark_virq;
	interrupt_data_t bite_virq;
#if defined(PLATFORM_SBSA_WDT) && PLATFORM_SBSA_WDT
	vmaddr_t ipa;
#endif

	vmid_t	 manager;
	cap_id_t manager_cap;
};

// index definition for iomem vdevice node validation member's index
enum iomem_validation_index {
	IOMEM_VALIDATION_SELF_IDX = 0,
	IOMEM_VALIDATION_PEER_IDX,
	IOMEM_VALIDATION_NUM_IDXS,
};

RM_PADDED(struct vdevice_iomem {
	uint32_t rm_acl[IOMEM_VALIDATION_NUM_IDXS];
	uint32_t rm_attrs[IOMEM_VALIDATION_NUM_IDXS];

	sgl_entry_t *rm_sglist;
	size_t	     rm_sglist_len;

	vmid_t peer;

	uint32_t label;

	uint32_t mem_info_tag;
	bool	 mem_info_tag_set;

	bool need_allocate;
	bool validate_acl;
	bool validate_attrs;
})

struct vdevice_rtc {
	vmaddr_t ipa;
	uint64_t ipa_size;
};

typedef enum {
	VDEVICE_MEMORY_EXTENT_LABEL_GUEST_PAGED	     = 0U,
	VDEVICE_MEMORY_EXTENT_LABEL_HOST_UNPROTECTED = 1U,
	VDEVICE_MEMORY_EXTENT_LABEL_HOST_PROTECTED   = 2U,
	VDEVICE_MEMORY_EXTENT_LABEL_GUEST_VMMIO	     = 3U,
} vdevice_memory_extent_label_t;

struct vdevice_memory_extent {
	vmid_t	 owner;
	cap_id_t owner_host_cap;

	vmid_t	 manager;
	cap_id_t manager_guest_cap;

	vdevice_memory_extent_label_t label;
};

struct vdevice_address_space {
	vmid_t	 owner;
	cap_id_t vm_cap;

	vmid_t	 manager;
	cap_id_t manager_map_cap;
};

struct vdevice_node {
	vdevice_type_t type;

	struct vdevice_node *vdevice_next;
	struct vdevice_node *vdevice_prev;

	// Indicates vdevice should be added to the VM's device tree overlay.
	bool export_to_dt;

	bool visible; // visible to queries

	count_t push_compatible_num;
	char   *push_compatible[VDEVICE_MAX_PUSH_COMPATIBLES];

	char *generate;

	// type specific configuration
	union {
		void			      *raw;
		struct vdevice_iomem	      *iomem;
		struct vdevice_shm	      *shm;
		struct vdevice_doorbell	      *doorbell;
		struct vdevice_msg_queue      *msg_queue;
		struct vdevice_msg_queue_pair *msg_queue_pair;
		struct vdevice_virtual_pm     *virtual_pm;
		struct vdevice_virtio_mmio    *virtio_mmio;
		struct vdevice_watchdog	      *watchdog;
		struct vdevice_memory_extent  *memory_extent;
		struct vdevice_address_space  *address_space;
		struct vdevice_smmu_v2	      *smmu_v2;
		struct vdevice_rtc	      *rtc;
	} config;

	resource_handle_t handle;
};

typedef enum vm_config_affinity_e {
	// default
	VM_CONFIG_AFFINITY_STATIC,
	VM_CONFIG_AFFINITY_STICKY,
	VM_CONFIG_AFFINITY_PINNED,
	VM_CONFIG_AFFINITY_PROXY,
} vm_config_affinity_t;

struct mem_range {
	vmaddr_t base;
	size_t	 size;
};

typedef struct vm_boot_context_s vm_boot_context_t;

struct vm_config_s {
	vm_t *vm;

	// True if the configuration data has been authenticated by the
	// platform, and therefore can be trusted to specify parameters that
	// would otherwise not be allowed, e.g. elevated priority.
	bool trusted_config;

	uint64_t swid;

	vector_t	    *vcpus;
	vm_config_affinity_t vm_affinity;

	vector_t *iomem_ranges;

	vdevice_node_t *vdevice_nodes;

	paddr_t mem_ipa_base;
	paddr_t mem_size_min;
	paddr_t mem_size_max;
	bool	mem_unsanitized;
#if defined(GUEST_RAM_DUMP_ENABLE) && GUEST_RAM_DUMP_ENABLE
	bool guestdump_allowed;
#endif // GUEST_RAM_DUMP_ENABLE
	bool mem_map_direct;
#if defined(PLATFORM_ALLOW_INSECURE_CONSOLE) && PLATFORM_ALLOW_INSECURE_CONSOLE
	bool insecure_console;
#endif // PLATFORM_ALLOW_INSECURE_CONSOLE

	bool	  mem_demand_paging;
	vector_t *mem_demand_paged_ranges;

	paddr_t fw_ipa_base;
	paddr_t fw_size_max;

	// FIXME: legacy - move
	cap_id_t partition;
	cap_id_t cspace;
	cap_id_t addrspace;
	cap_id_t vic;
	cap_id_t vpm_group;
	cap_id_t watchdog;
	cap_id_t rtc;
	cap_id_t vm_info_area_me_cap;

	bool minidump_allowed;
	bool watchdog_enabled;

	vm_console_t *console;

	platform_vm_config_t platform;
	vm_boot_context_t   *boot_ctx;

	vector_t *accepted_memparcels;
};

struct dtb_parser_alloc_params_s {
	vm_auth_type_t auth_type;
};

#pragma clang diagnostic pop

#else

#error multiple include of vm_config_struct.h

#endif
