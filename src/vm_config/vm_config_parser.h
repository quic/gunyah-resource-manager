// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef enum {
	// default
	VM_CONFIG_VM_TYPE_AARCH64_GUEST,
} vm_config_vm_type_t;

typedef enum {
	// default
	VM_CONFIG_BOOT_CONFIG_FDT_UNIFIED,
} vm_config_boot_config_t;

typedef enum {
	// default
	VM_CONFIG_OS_TYPE_LINUX,
} vm_config_os_type_t;

typedef enum {
	// default
	VM_CONFIG_AFFINITY_STATIC,
	VM_CONFIG_AFFINITY_STICKY,
} vm_config_affinity_t;

typedef struct general_data {
	// it might be simpler to free it if string length is restricted
	char *	push_compatible[VDEVICE_MAX_PUSH_COMPATIBLES];
	count_t push_compatible_num;

	label_t label;

	char *generate;
} general_data_t;

typedef struct interrupt_data {
	virq_t virq;

	bool is_cpu_local;
	bool is_edge_triggerring;

	uint8_t is_edge_triggerring_padding[2];
} interrupt_data_t;

// index definition for paired vdevice
enum irq_index {
	TX_IRQ_IDX = 0,
	RX_IRQ_IDX,
};

typedef struct doorbell_data {
	interrupt_data_t irq;

	general_data_t general;

	vmid_t peer;

	bool defined_irq;

	bool is_source;

	uint8_t is_source_padding[4];
} doorbell_data_t;

typedef struct msg_queue_data {
	general_data_t general;

	uint16_t msg_size;
	uint16_t queue_depth;

	// if it's pair, then it contains tx and rx interrupt
	interrupt_data_t irqs[2];

	vmid_t peer;

	bool defined_irq;

	bool is_sender;
	bool is_pair;

	uint8_t is_pair_padding[7];
} msg_queue_data_t;

typedef struct shm_data {
	general_data_t general;

	paddr_t mem_base_ipa;

	vmid_t peer;

	bool need_allocate;

	bool is_plain_shm;

	uint8_t need_allocate_padding[4];
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

struct vm_config_parser_data {
	vm_config_vm_type_t	vm_type;
	vm_config_boot_config_t boot_config;
	vm_config_os_type_t	os_type;
	uint8_t			os_type_padding[4];

	char *	 kernel_entry_segment;
	uint64_t kernel_entry_offset;

	char *vendor_name;
	char *image_name;

	uint64_t swid;

	// memory
	paddr_t mem_base_ipa;
	size_t	mem_size_min;

	vector_t *iomem_ranges;

	vector_t *irq_ranges;

	// vgic
	paddr_t vgic_base_ipa;
	size_t	vgic_ipa_size;

	uint32_t sched_time_slice;
	uint32_t sched_priority;

	int ramfs_idx;

	vm_config_affinity_t affinity;

	size_t	     affinity_map_cnt;
	cpu_index_t *affinity_map;

	size_t vcpu_cnt;

	vector_t *rm_rpcs;
	vector_t *doorbells;
	vector_t *msg_queues;
	vector_t *shms;
};

typedef struct vm_config_parser_data vm_config_parser_data_t;
