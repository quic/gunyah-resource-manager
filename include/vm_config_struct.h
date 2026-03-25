// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
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
	VDEV_VIRTIO,
	VDEV_IOMEM,
	VDEV_SMMU_V2,
	VDEV_RTC,
	VDEV_MINIDUMP,
	VDEV_MEMORY_EXTENT,
	VDEV_ADDRESS_SPACE,
	VDEV_PCI,
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

struct vdevice_virtio {
	cap_id_t master_cap;

	virtio_device_type_t device_type;

	char *patch;

	// Hypercall-driven VMM backends only (not EL2 backends)
	struct {
		bool	 valid;
		uint32_t label;
		cap_id_t cap;

		vmid_t	 vm;
		vmaddr_t ipa;
		size_t	 me_size;
		cap_id_t me_cap;
		void	*rm_addr;

		interrupt_data_t virq;
	} backend;

	// MMIO frontends only
	struct {
		uint32_t label;

		interrupt_data_t virq;

		vmaddr_t ipa;
		size_t	 size;

		bool	 have_shm;
		bool	 need_allocate;
		vmaddr_t dma_base_ipa;
		uint64_t dma_base;
		bool	 dma_coherent;
	} mmio;
};

struct vdevice_pci {
	char *patch;

	uint32_t linux_pci_domain;

	vmaddr_t config_ipa;
	size_t	 config_size;

	vmaddr_t npmem_ipa;
	size_t	 npmem_size;

	cap_id_t master_cap;

	bool	 msi_vdevices;
	bool	 msi_passthrough;
	uint32_t msi_passthrough_base;
	uint32_t msi_passthrough_length;
	uint32_t msi_parent_phandle;

	uint32_t	 irq_parent_phandle;
	interrupt_data_t legacy_virqs[32];

	bool	 dma_coherent;
	bool	 have_memory_region;
	bool	 need_allocate;
	vmaddr_t dma_base_ipa;
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

#if defined(PLATFORM_SBSA_WDT) && PLATFORM_SBSA_WDT
// ARM SBSA watchdog has two frames, put them 64KB apart
#define SBSA_WATCHDOG_FRAME_STRIDE 0x10000U
#define SBSA_WATCHDOG_SIZE	   (SBSA_WATCHDOG_FRAME_STRIDE * 2U)
#endif

typedef enum {
	WATCHDOG_UNSPECIFIED = 0,
	WATCHDOG_SMC_BASED,
#if defined(PLATFORM_SBSA_WDT) && PLATFORM_SBSA_WDT
	WATCHDOG_EMULATION_ARM_SBSA,
#elif defined(PLATFORM_QCOM_WDT_REG) && PLATFORM_QCOM_WDT_REG
	WATCHDOG_EMULATION_QCOM,
#else
// Nothing to do.
#endif
} watchdog_type_t;

struct vdevice_watchdog {
	watchdog_type_t type;
#if (defined(PLATFORM_SBSA_WDT) && PLATFORM_SBSA_WDT) ||                       \
	(defined(PLATFORM_QCOM_WDT_REG) && PLATFORM_QCOM_WDT_REG)
	bool	 defined_addr;
	vmaddr_t base;
	size_t	 size;
	count_t	 addr_cells;
	count_t	 size_cells;
#endif
	bool		 defined_bark_virq;
	interrupt_data_t bark_virq;
	interrupt_data_t bite_virq;
	char		*node_path;

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

RM_PADDED(typedef struct {
	vmaddr_t ipa_base;
	size_t	 size;

	uint32_t label;
	bool	 label_valid;

	bool is_reusable;

	bool match_found;
} resmem_range_t)

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
	vmid_t owner;

	vmid_t	 manager;
	cap_id_t manager_map_cap;
};

typedef enum {
	VDEVICE_BUS_NONE = 0, // capability / hypercall interfaces only
	VDEVICE_BUS_MMIO,
	VDEVICE_BUS_PCI,
} vdevice_bus_t;

struct vdevice_node {
	vdevice_type_t type;
	vdevice_bus_t  bus;

	// Bus specific configuration
	struct {
		// Set during function creation, used for bus attachment
		cap_id_t function_cap;

		// Set during virtual bus attachment. Initialised to
		// INVALID_ADDRESS to indicate no attachment yet.
		vmaddr_t bus_config_ipa;

		// Set during either DT parsing or virtual bus attachment. May
		// be set to ~0 during DT parsing to auto-select a slot during
		// bus attachment.
		index_t slot_index;

		// Set during DT parsing, used for bus attachment. May be
		// DTO_PHANDLE_UNSET to automatically select a bus.
		uint32_t bus_phandle;

		// Set during DT parsing if the function is capable of asserting
		// its legacy IRQ line.
		bool has_legacy_irq;
	} pci;

	struct vdevice_node *vdevice_next;
	struct vdevice_node *vdevice_prev;

	bool visible; // visible to queries

	// Generic device tree options
	bool export_to_dt;

	count_t push_compatible_num;
	char   *push_compatible[VDEVICE_MAX_PUSH_COMPATIBLES];
	char   *generate;

	bool  replace_symbol; // Steal the phandle from an existing symbol
	char *symbol;	      // Overlay symbol to replace

	// type specific configuration
	union {
		void			      *raw;
		struct vdevice_iomem	      *iomem;
		struct vdevice_shm	      *shm;
		struct vdevice_doorbell	      *doorbell;
		struct vdevice_msg_queue      *msg_queue;
		struct vdevice_msg_queue_pair *msg_queue_pair;
		struct vdevice_virtual_pm     *virtual_pm;
		struct vdevice_virtio	      *virtio;
		struct vdevice_watchdog	      *watchdog;
		struct vdevice_memory_extent  *memory_extent;
		struct vdevice_address_space  *address_space;
		struct vdevice_smmu_v2	      *smmu_v2;
		struct vdevice_rtc	      *rtc;
		struct vdevice_pci	      *pci;
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

typedef struct vm_boot_context_s  vm_boot_context_t;
typedef struct vm_firmware_data_s vm_firmware_data_t;

RM_PADDED(typedef struct vgic_its_s {
	cap_id_t msi_source_cap;
	cap_id_t vgic_its_cap;
	paddr_t	 phys_base;
	vmaddr_t ipa_base;
	cap_id_t xlate_me;
} vgic_its_t)

struct vm_config_s {
	vm_t *vm;

	// True if the configuration data has been authenticated by the
	// platform, and therefore can be trusted to specify parameters that
	// would otherwise not be allowed, e.g. elevated priority.
	//
	// Note that this does not necessarily apply to the whole config; any
	// value set by a "safe" DTB listener may have come from an untrusted
	// source regardless of this value.
	bool trusted_config;

	const vm_firmware_data_t *fw_data;

	uint64_t swid;

	vector_t	    *vcpus;
	vm_config_affinity_t vm_affinity;

	vector_t *resmem_fixed_ranges;
	vector_t *iomem_ranges;

	vdevice_node_t *vdevice_nodes;

	paddr_t mem_ipa_base;
	paddr_t mem_size_min;
	paddr_t mem_size_max;
	bool	mem_unsanitized;
#if defined(GUEST_RAM_DUMP_ENABLE) && GUEST_RAM_DUMP_ENABLE
	bool guestdump_allowed;
#endif // GUEST_RAM_DUMP_ENABLE
	bool vpm_explicit_wakeup;

	bool mem_map_direct;
#if defined(PLATFORM_ALLOW_INSECURE_CONSOLE) && PLATFORM_ALLOW_INSECURE_CONSOLE
	bool insecure_console;
#endif // PLATFORM_ALLOW_INSECURE_CONSOLE

	bool allow_unprotected;

	bool	  mem_demand_paging;
	vector_t *mem_demand_paged_ranges;

	paddr_t fw_ipa_base;
	paddr_t fw_size_max;

	// FIXME: legacy - move
	cap_id_t partition;
	cap_id_t cspace;
	cap_id_t addrspace;
	cap_id_t vic;
	cap_id_t vgic_its[16];
	cap_id_t vpm_group;
	cap_id_t watchdog;
	cap_id_t rtc;
	cap_id_t vm_info_area_me_cap;
	cap_id_t power_cap;
	cap_id_t addrspace_self_cap;
	cap_id_t vsmmuv2_cap;

	bool minidump_allowed;
	bool watchdog_allowed;

	vm_console_t *console;

	platform_vm_config_t platform;
	vm_boot_context_t   *boot_ctx;

	vector_t *accepted_memparcels;

	bool no_dtb_patch;

	// vector of platform_vgic_its_t
	vector_t *vgic_itss;
	vmaddr_t  vgic_gicd_base;
	vmaddr_t  vgic_gicr_base;
	vmaddr_t  vgic_gicr_stride;
	uint32_t  vgic_phandle;
	count_t	  vgic_addr_cells;
	count_t	  vgic_size_cells;
	count_t	  vgic_child_addr_cells;
	bool	  vgic_patch_dt;
	count_t	  map_addr_cells;

	int ramfs_idx;
	int cfgcpio_idx;
	int fallback_dt_idx;

	size_t		      segment_count;
	boot_env_phys_range_t segments[8];
};

struct dtb_parser_alloc_params_s {
	vm_auth_type_t auth_type;
};

#pragma clang diagnostic pop

#else

#error multiple include of vm_config_struct.h

#endif
