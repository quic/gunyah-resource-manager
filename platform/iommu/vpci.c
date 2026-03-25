// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>

#include <rm_types.h>

#include <platform_vm_config.h>

#include "platform_iommu.h"

#if defined(PLATFORM_HLOS_NEEDS_VPCI) && PLATFORM_HLOS_NEEDS_VPCI
error_t
platform_add_vpci_devices(vm_config_t *vmcfg)
{
	error_t ret;
	assert(vmcfg != NULL);

	// Create and attach the vPCI devices before we activate the vPCI bus
	ret = platform_iommu_init(vmcfg);
	if (ret != OK) {
		goto out;
	}

	ret = platform_iommu_vpci_add(vmcfg);
out:
	return ret;
}
#endif
