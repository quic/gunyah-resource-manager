// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdint.h>

#include <rm_types.h>
#include <util.h>

#include <event.h>
#include <vm_mgnt.h>
#include <vm_mgnt_arch.h>

static bool
platform_psci_get_vm_clean_shutdown(uint32_t reset_type, uint64_t cookie)
{
	bool clean;

	uint32_t type = reset_type & (uint32_t)util_mask(31U);

	if ((reset_type & util_bit(31)) != 0U) {
		// Type field is not used.
		if (type != 0U) {
			clean = false;
			goto out;
		}
		switch (cookie) {
		case 0U:
			clean = true;
			break;
		default:
			clean = false;
			break;
		}
	} else {
		// Architectural reset types are not treated as clean
		// Only type=0 is defined (SYSTEM_WARM_RESET)
		clean = false;
	}

out:
	return clean;
}

void
vm_mgnt_arch_set_cleanup_type(vm_t *vm, const uint32_t *extra_reason)
{
	assert(vm != NULL);

	switch (vm->exit_type) {
	// VM shutdown
	case EXIT_TYPE_PLATFORM_OFF:
	// VM reboot
	case EXIT_TYPE_PLATFORM_RESET:
		vm->clean_shutdown = true;
		break;
	case EXIT_TYPE_PSCI_SYSTEM_RESET2: {
		assert(extra_reason != NULL);
		uint32_t reset_type = extra_reason[0];
		uint64_t cookie	    = ((uint64_t)extra_reason[2] << 32) |
				  extra_reason[1];
		vm->clean_shutdown =
			platform_psci_get_vm_clean_shutdown(reset_type, cookie);
		break;
	}
	// VM crash
	case EXIT_TYPE_WATCHDOG_BITE:
		vm->clean_shutdown = vm->crash_restart;
		break;
	// Unexpected cases
	case EXIT_TYPE_VM_EXIT:
	case EXIT_TYPE_SOFTWARE_ERROR:
	case EXIT_TYPE_ASYNC_HW_ERROR:
	case EXIT_TYPE_VM_STOP_FORCED:
	default:
		vm->clean_shutdown = false;
		break;
	}
}
