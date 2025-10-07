// © 2024 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <platform_psci.h>

bool
platform_psci_get_vm_clean_shutdown(uint32_t reset_type, uint64_t cookie)
{
	(void)reset_type;
	(void)cookie;

	// No support for any PSCI_SYSTEM_RESET2 handling
	return false;
}
