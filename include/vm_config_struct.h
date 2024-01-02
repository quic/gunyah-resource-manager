// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef struct memparcel   memparcel_t;
typedef struct sgl_entry_s sgl_entry_t;

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
#if defined(CAP_RIGHTS_WATCHDOG_ALL)
	VDEV_WATCHDOG,
#endif
	VDEV_VIRTUAL_PM,
	VDEV_VIRTIO_MMIO,
	VDEV_IOMEM,
	VDEV_RTC,
	VDEV_MINIDUMP,
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

	vmid_t	 manager;
	cap_id_t manager_cap;
};

typedef struct sgl_entry_s sgl_entry_t;

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

struct vdevice_smmu_v2 {
	vmaddr_t	  ipa;
	uint64_t	  ipa_size;
	uint8_t		  num_cbs;
	cap_id_t	 *cb_me_caps;
	interrupt_data_t *irqs;
	char		 *patch;
};

struct vdevice_rtc {
	vmaddr_t ipa;
	uint64_t ipa_size;
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
	void *config;

	resource_handle_t handle;
};

struct vm_config {
	vm_t *vm;

	// for vm identification
	char *vendor;

	char *image_name;

	// True if the configuration data has been authenticated by the
	// platform, and therefore can be trusted to specify parameters that
	// would otherwise not be allowed, e.g. elevated priority.
	bool trusted_config;

	uint64_t swid;

	vector_t *vcpus;
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

	vector_t *accepted_memparcels;
};

struct dtb_parser_alloc_params_s {
	vm_auth_type_t auth_type;
};

#pragma clang diagnostic pop
