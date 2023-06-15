// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <asm/arm_smccc.h>

#include <rm_types.h>

#include <guest_interface.h>
#include <platform.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>

bool
platform_has_vrtc_support(void)
{
	bool ret = false;

	return ret;
}

error_t
platform_vrtc_attach_addrspace(cap_id_t rtc_cap, cap_id_t addrspace_cap)
{
	(void)rtc_cap;
	(void)addrspace_cap;

	return ERROR_UNIMPLEMENTED;
}

error_t
platform_rtc_set_time_base(cap_id_t rtc_cap, uint64_t time_base,
			   uint64_t sys_timer_ref)
{
	error_t err = ERROR_UNIMPLEMENTED;

	(void)rtc_cap;
	(void)time_base;
	(void)sys_timer_ref;
	return err;
}

cap_id_result_t
platform_vrtc_create_and_configure(cap_id_t p_cap, cap_id_t cs_cap,
				   vmaddr_t ipa)
{
	cap_id_result_t ret = { .e = ERROR_UNIMPLEMENTED,
				.r = CSPACE_CAP_INVALID };

	(void)p_cap;
	(void)cs_cap;
	(void)ipa;
	return ret;
}
