
// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <platform.h>
#include <vendor_hyp_call.h>

void
platform_exit_handler(int exit_code)
{
	(void)exit_code;
}
