// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// This structure is used only locally in RM as shared temporary data
RM_PADDED(struct rm_env_data_s {
	platform_env_data_t *platform_env;

	cap_id_t	      addrspace_capid;
	paddr_t		      uart_address;
	count_t		      num_reserved_dev_irqs;
	virq_t		      reserved_dev_irq[8];
	count_t		      free_ranges_count;
	boot_env_phys_range_t free_ranges[32];
	cap_id_t	      vcpu_capid;
	vmaddr_t	      entry_hlos;
	cap_id_t	      device_me_capid;
	paddr_t		      device_me_base;
	size_t		      device_me_size;
	vmaddr_t	      mpd_region_addr;
	size_t		      mpd_region_size;
	paddr_t		      wdt_address;
	cap_id_t	      partition_capid;
	cap_id_t	      cspace_capid;
	cap_id_t	      me_capid;
	vmaddr_t	      me_ipa_base;
	size_t		      me_size;
	uintptr_t	      ipa_offset;
	uint64_t	      usable_cores;
	paddr_t		      hlos_dt_base;
	paddr_t		      hlos_vm_base;
	size_t		      hlos_vm_size;
	paddr_t		      hlos_ramfs_base;
	cap_id_t	      smc_wqs[2];
	cap_id_t	      vic;
	cap_id_t	      vic_hwirq[1020];
	cap_id_t	      vic_msi_source[16];

	cap_id_t gic_xlate_me[16];

	cap_id_t    uart_me_capid;
	cpu_index_t boot_core;
	bool	    sve_supported;
	bool	    watchdog_supported;
	bool	    hlos_handles_ras;
})

typedef struct rm_env_data_s rm_env_data_t;
