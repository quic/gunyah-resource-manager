// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_RM_ENV_DATA_H_
#define INCLUDE_RM_ENV_DATA_H_

#define VIC_HWIRQ_SIZE 5120U

typedef struct rm_irq_env_data_s {
	cap_id_t *vic_hwirq;
} rm_irq_env_data_t;

typedef struct rm_smmu_env_data_s {
	paddr_t	 smmu_addr;
	cap_id_t smmuv2_cap;
} rm_smmu_env_data_t;

// This structure is used only locally in RM as shared temporary data
RM_PADDED_BEGIN

struct rm_env_data_s {
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
	count_t		      device_ranges_count;
	boot_env_phys_range_t device_ranges[16];
	vmaddr_t	      mpd_region_addr;
	size_t		      mpd_region_size;
	paddr_t		      wdt_address;
	cap_id_t	      partition_capid;
	cap_id_t	      cspace_capid;
	cap_id_t	      me_capid;
	vmaddr_t	      me_ipa_base;
	size_t		      me_size;
	uintptr_t	      ipa_offset;
	paddr_t		      hlos_dt_base;
	paddr_t		      hlos_vm_base;
	size_t		      hlos_vm_size;
	paddr_t		      hlos_ramfs_base;
	count_t		      smc_wqs_count;
	cap_id_t	      smc_wqs[1];
	cap_id_t	      vic;
	count_t		      vic_max_virqs;
	nanoseconds_t	      scheduler_default_timeslice;
	cap_id_t	      trace_dbl_capid;
	cap_id_t	      trace_me_capid;
	paddr_t		      trace_phys;
	size_t		      trace_size;
	cap_id_t	      system_power_capid;
	bool		      system_suspend;

	// We're currently limited to supporting cpu ids 0..63.
	// The cores 64..127 here are included for CBOR parsing only.
	// FIXME: QC RM issue #51
	uint64_t usable_cores[2];
	count_t	 max_cores;

	rm_irq_env_data_t  *irq_env;
	count_t		    num_v2_smmu;
	rm_smmu_env_data_t *smmuv2_env;
	cap_id_t	    its_caps[16];
	cap_id_t	    smmuv3_caps[1];

	cap_id_t		 uart_me_capid;
	cpu_index_t		 boot_core;
	bool			 sve_supported;
	bool			 sme_supported;
	bool			 watchdog_supported;
	bool			 hlos_handles_ras;
	bool			 sdei_supported;
	vm_device_assignments_t *device_assignments;

	paddr_t	     gicd_base;
	size_t	     gicr_stride;
	count_t	     gicr_ranges_count;
	rm_range64_t gicr_ranges[2];
	size_t	     gits_stride;
	count_t	     gits_ranges_count;
	rm_range64_t gits_ranges[2];
	count_t	     gic_xlate_me_count;
	cap_id_t     gic_xlate_me[16];
};

RM_PADDED_END

typedef struct rm_env_data_s rm_env_data_t;

#else

#error multiple include of rm_env_data.h

#endif
