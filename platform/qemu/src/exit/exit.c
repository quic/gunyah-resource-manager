// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <rm_types.h>

#include <platform.h>
#include <rm-rpc.h>
#include <rm_env_data.h>

void
platform_exit_handler(int exit_code)
{
	(void)exit_code;

	// TODO: Trigger the HW watchdog to reset the system
}
