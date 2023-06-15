// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <rm_types.h>
#include <utils/vector.h>

#include <platform.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_client.h>
#include <vm_config.h>
#include <vm_config_struct.h>

// Must be last
#include <platform_vm_config_parser.h>

error_t
platform_config_update_parsed(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	(void)vmcfg;
	(void)data;
	return OK;
}

const char *
platform_get_sign_authority_string(vm_sign_t sign)
{
	char *ret = NULL;

	switch (sign) {
	case VM_SIGN_INIT:
		ret = "N/A";
		break;
	case VM_SIGN_UNAUTHORIZED:
		ret = "None";
		break;
	default:
		printf("Error: invalid sign %d\n", sign);
		ret = NULL;
		break;
	}

	return ret;
}
