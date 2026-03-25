// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <rm_types.h>

#include <platform.h>

void
platform_exit_handler(int exit_code)
{
	(void)exit_code;

	// TODO: Trigger the HW watchdog to reset the system
}
