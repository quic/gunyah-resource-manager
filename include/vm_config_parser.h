// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_VM_CONFIG_PARSER_H_
#define INCLUDE_VM_CONFIG_PARSER_H_

typedef enum {
	// default
	VM_CONFIG_VM_TYPE_AARCH64_GUEST,
} vm_config_vm_type_t;

typedef enum {
	// default
	VM_CONFIG_OS_TYPE_LINUX,
} vm_config_os_type_t;

RM_PADDED(typedef struct {
	vmaddr_t ipa_base;
	size_t	 size;

	uint32_t label;
	bool	 label_valid;

	bool is_reusable;
} resmem_range_data_t)

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

	bool	is_console_dev;
	uint8_t is_console_dev_padding[2];
	char   *console_owner;
} rm_rpc_data_t;

RM_PADDED(typedef struct virtio_common_data {
	general_data_t general;

	// Common
	vmid_t	peer;
	count_t vqs_num;
	char   *patch;

	virtio_device_type_t device_type;
	bool		     sync_reset;
} virtio_common_data_t)

RM_PADDED(typedef struct virtio_mmio_data {
	virtio_common_data_t common;
	bool		     have_shm;
	bool		     need_allocate;
	bool		     dma_coherent;
	uint64_t	     dma_base;
	paddr_t		     dma_base_ipa;
} virtio_mmio_data_t)

RM_PADDED(typedef struct virtio_pci_data {
	virtio_common_data_t common;
	index_t		     pci_slot_index;
	uint32_t	     pci_bus_phandle;
	bool		     per_queue_irqs;
} virtio_pci_data_t)

RM_PADDED(typedef struct pci_data {
	general_data_t general;

	char *patch;

	vmaddr_t config_base_ipa;
	count_t	 config_bits;
	vmaddr_t npmem_base_ipa;
	count_t	 npmem_bits;

	uint32_t bus_phandle;

	bool	 msi_vdevices;
	bool	 msi_passthrough;
	uint32_t msi_passthrough_base;
	uint32_t msi_passthrough_length;
	uint32_t msi_parent_phandle;

	bool	 irq_vdevices;
	uint32_t irq_parent_phandle;

	bool	dma_coherent;
	bool	have_memory_region;
	bool	need_allocate;
	paddr_t dma_base_ipa;

	uint32_t linux_pci_domain;
} pci_data_t)

RM_PADDED(typedef struct virtio_iommu_data {
	uint64_t smmu_handle;
	index_t	 pci_slot_index;
	count_t	 max_streams;
} virtio_iommu_data_t)

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
	char	*patch;
	uint64_t address; // MPIDR for AArch64
	index_t	 address_index;
	bool	 boot_vcpu;
} vcpu_data_t)

RM_PADDED_BEGIN

typedef struct watchdog_data {
	watchdog_type_t	 type;
	bool		 defined_irq;
	interrupt_data_t bark_virq;
#if (defined(PLATFORM_SBSA_WDT) && PLATFORM_SBSA_WDT) ||                       \
	(defined(PLATFORM_QCOM_WDT_REG) && PLATFORM_QCOM_WDT_REG)
	bool	 defined_addr;
	vmaddr_t base;
	size_t	 size;
	size_t	 alignment;
	count_t	 addr_cells;
	count_t	 size_cells;
#endif
	char *node_path;
} watchdog_data_t;

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
	bool bite_fatal;
	bool context_dump;
	bool no_shutdown;
	bool no_reset;
	bool crash_restart;
	bool sve_not_allowed;
	bool sme_allowed;
	bool allow_unprotected;
	bool no_dtb_patch;
	bool sdei_allowed;

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
	bool	 mem_base_set;
	bool	 mem_base_constraints_set;
	uint32_t mem_base_constraints[2];

	vector_t *resmem_fixed_ranges;

	paddr_t fw_base_ipa;
	size_t	fw_size_max;
	bool	fw_base_set;

	vector_t *iomem_ranges;
	vector_t *irq_ranges;
	vector_t *vmmio_ranges;
	bool	  vmmio_ranges_set;

	uint64_t allowed_periph_vmids;
	uint64_t used_periph_vmids;

	uint32_t sched_time_slice;
	int32_t	 sched_priority;

	vm_config_affinity_t affinity;

	size_t	     affinity_map_cnt;
	cpu_index_t *affinity_map;

	bool enable_vpm_psci_virq;
	bool enable_vpm_psci;
	bool disable_vpm_aggregation;

	count_t idle_state_count;
	count_t psci_enable_count;
	count_t enabled_cpu_count;

	// These are ARMv8-specific and should be in arch code.
	// FIXME: QC RM issue #38
	count_t	 vcpu_addr_shifts[4];
	uint64_t vcpu_addr_mask;
	uint64_t vcpu_used_indices;

	bool have_default_pci_bus;

	virq_t el1_phys_timer_irq;
	virq_t el1_virt_timer_irq;

	vector_t *rm_rpcs;
	vector_t *doorbells;
	vector_t *msg_queues;
	vector_t *msg_queue_pairs;
	vector_t *shms;
	vector_t *virtio_mmios;
	vector_t *virtio_pcis;
	vector_t *iomems;
	vector_t *smmus;
	vector_t *virtio_iommus;
	vector_t *vcpus;
	vector_t *rtc;
	vector_t *minidump;
	vector_t *watchdog;
	vector_t *pci_buses;

	vmaddr_t vgic_gicd_base;
	vmaddr_t vgic_gicr_base;
	vmaddr_t vgic_gicr_stride;
	uint32_t vgic_phandle;
	count_t	 vgic_addr_cells;
	count_t	 vgic_size_cells;
	count_t	 vgic_child_addr_cells;
	bool	 vgic_patch_dt;
	count_t	 map_addr_cells;

	int ramfs_idx;
	int cfgcpio_idx;
	int fallback_dt_idx;

	platform_vm_config_parser_data_t platform;
};

RM_PADDED_END

error_t
read_interrupts_config(const void *fdt, int node_ofs, const char *property,
		       interrupt_data_t *irqs, count_t count);
bool
read_sdei_event_interrupt_config(const void *fdt, int node_ofs,
				 interrupt_data_t *irq);

#else

#error multiple include of vm_config_parser.h

#endif
