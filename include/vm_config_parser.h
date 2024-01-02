// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef enum {
	// default
	VM_CONFIG_VM_TYPE_AARCH64_GUEST,
} vm_config_vm_type_t;

typedef enum {
	// default
	VM_CONFIG_OS_TYPE_LINUX,
} vm_config_os_type_t;

typedef enum {
	// default
	VM_CONFIG_AFFINITY_STATIC,
	VM_CONFIG_AFFINITY_STICKY,
	VM_CONFIG_AFFINITY_PINNED,
	VM_CONFIG_AFFINITY_PROXY,
} vm_config_affinity_t;

typedef struct general_data {
	// it might be simpler to free it if string length is restricted
	char   *push_compatible[VDEVICE_MAX_PUSH_COMPATIBLES];
	count_t push_compatible_num;

	label_t label;

	char *generate;
} general_data_t;

// index definition for paired vdevice
enum irq_index {
	TX_IRQ_IDX = 0,
	RX_IRQ_IDX,
};

RM_PADDED(typedef struct doorbell_data {
	interrupt_data_t irq;

	general_data_t general;

	vmid_t peer;

	bool defined_irq;

	bool is_source;
	bool source_can_clear;

	char *peer_id;
} doorbell_data_t)

typedef struct msg_queue_data {
	general_data_t general;

	uint16_t msg_size;
	uint16_t queue_depth;

	interrupt_data_t irqs[1];

	vmid_t peer;

	bool defined_irq;

	bool is_sender;

} msg_queue_data_t;

typedef struct msg_queue_pair_data {
	general_data_t general;

	uint16_t msg_size;
	uint16_t queue_depth;

	// Contains tx and rx interrupt
	interrupt_data_t irqs[2];

	vmid_t peer;

	bool	defined_irq;
	uint8_t define_irq_padding[1];

	char *peer_id;
} msg_queue_pair_data_t;

typedef struct shm_data {
	general_data_t general;

	paddr_t	 mem_base_ipa;
	uint64_t dma_base;

	vmid_t peer;

	bool need_allocate;

	bool is_plain_shm;

	bool is_memory_optional;
	bool is_plain_shm_padding[3];
} shm_data_t;

typedef struct rm_rpc_data {
	general_data_t general;

	uint16_t msg_size;
	uint16_t queue_depth;

	interrupt_data_t irqs[2];

	bool defined_irq;

	bool is_console_dev;

	uint8_t is_console_dev_padding[2];
} rm_rpc_data_t;

RM_PADDED(typedef struct virtio_mmio_data {
	general_data_t general;

	paddr_t	 mem_base_ipa;
	uint64_t dma_base;

	vmid_t		     peer;
	count_t		     vqs_num;
	virtio_device_type_t device_type;
	bool		     valid_device_type;
	bool		     need_allocate;
	bool		     dma_coherent;
	uint8_t		     need_allocate_padding[2];
} virtio_mmio_data_t)

RM_PADDED(typedef struct iomem_data {
	general_data_t general;

	char *patch_node_path;

	label_t label;

	uint32_t mem_info_tag;
	bool	 mem_info_tag_set;

	bool validate_acl;
	bool validate_attrs;
	bool need_allocate;

	uint32_t rm_acl[IOMEM_VALIDATION_NUM_IDXS];
	uint32_t rm_attrs[IOMEM_VALIDATION_NUM_IDXS];

	sgl_entry_t *rm_sglist;
	size_t	     rm_sglist_len;

	vmid_t peer;
} iomem_data_t)

enum iomem_range_access {
	IOMEM_RANGE_RW = 0,
	IOMEM_RANGE_R,
	IOMEM_RANGE_RWX,
	IOMEM_RANGE_W,
	IOMEM_RANGE_X,
	IOMEM_RANGE_RX,
	IOMEM_RANGE_NONE,
	IOMEM_RANGE_ACCESS_MAX,
};

typedef struct iomem_range_data {
	paddr_t phys_base;

	vmaddr_t ipa_base;

	size_t size;

	enum iomem_range_access access;
	uint8_t			access_padding[4];
} iomem_range_data_t;

typedef struct {
	// FIXME: at this point assume the HLOS irq is mapped 1:1
	virq_t hw_irq;
	// the virtual irq which should be mapped
	virq_t virq;
} irq_range_data_t;

RM_PADDED(typedef struct smmu_v2_data {
	char	*patch;
	uint32_t smmu_handle;
	uint32_t num_cbs;
	uint32_t num_smrs;
} smmu_v2_data_t)

typedef struct rtc_data {
	vmaddr_t ipa_base;
	bool	 allocate_base;
	uint8_t	 padding[7];
} rtc_data_t;

// FIXME: move all minidump data to platform
typedef struct minidump_data {
	bool	       allowed;
	uint8_t	       padding[7];
	general_data_t general;
} minidump_data_t;

RM_PADDED(typedef struct vcpu_data_s {
	char *patch;
	bool  boot_vcpu;
} vcpu_data_t)

RM_PADDED_BEGIN

struct dtb_parser_data_s {
	vm_auth_type_t auth_type;

	vm_config_vm_type_t vm_type;
	vm_config_os_type_t os_type;

#if defined(GUEST_RAM_DUMP_ENABLE) && GUEST_RAM_DUMP_ENABLE
	bool guest_ram_dump;
#endif // GUEST_RAM_DUMP_ENABLE
	bool ras_error_handler;
	bool amu_counting_disabled;
	bool sensitive;
	bool crash_fatal;
	bool context_dump;
	bool no_shutdown;
	bool no_reset;

#if defined(PLATFORM_ALLOW_INSECURE_CONSOLE) && PLATFORM_ALLOW_INSECURE_CONSOLE
	bool insecure_console;
#endif

	char	*kernel_entry_segment;
	uint64_t kernel_entry_offset;

	char *vendor_name;
	char  vm_name[VM_MAX_NAME_LEN];

	char vm_uri[VM_MAX_URI_LEN];

	bool	has_guid;
	uint8_t vm_guid[VM_GUID_LEN];

	// memory
	paddr_t	 mem_base_ipa;
	size_t	 mem_size_min;
	size_t	 mem_size_max;
	bool	 mem_map_direct;
	bool	 mem_base_constraints_set;
	uint32_t mem_base_constraints[2];

	paddr_t fw_base_ipa;
	size_t	fw_size_max;

	vector_t *iomem_ranges;

	vector_t *irq_ranges;

	uint32_t sched_time_slice;
	int32_t	 sched_priority;

	vm_config_affinity_t affinity;

	size_t	     affinity_map_cnt;
	cpu_index_t *affinity_map;

	bool enable_vpm_psci_virq;
	bool enable_vpm_psci;

	vector_t *rm_rpcs;
	vector_t *doorbells;
	vector_t *msg_queues;
	vector_t *msg_queue_pairs;
	vector_t *shms;
	vector_t *virtio_mmios;
	vector_t *iomems;
	vector_t *smmus;
	vector_t *vcpus;
	vector_t *rtc;
	vector_t *minidump;
	vector_t *platform_data;

	platform_vm_config_parser_data_t platform;
};

RM_PADDED_END

typedef struct dtb_parser_data_s vm_config_parser_data_t;
