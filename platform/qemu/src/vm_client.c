// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <rm-rpc.h>

#include <platform.h>
#include <platform_vm_config.h>
#include <utils/vector.h>
#include <vm_client.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_mgnt.h>

// Must be last
#include <platform_vm_config_parser.h>
#include <vm_config_parser.h>

const char *
platform_get_sign_authority_string(vm_sign_t sign)
{
	(void)sign;

	return NULL;
}
