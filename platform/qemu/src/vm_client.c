// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <rm_types.h>

#include <guest_interface.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_client.h>
#include <vm_config.h>
#include <vm_config_struct.h>

#include <platform_vm_config_parser.h>

error_t
platform_config_update_parsed(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	(void)vmcfg;
	(void)data;
	return OK;
}

const char *
platform_get_sign_authority_string(uint32_t signer_info)
{
	char *ret = NULL;

	switch (signer_info) {
	case (uint32_t)VM_SIGN_INIT:
		ret = "N/A";
		break;
	case (uint32_t)VM_SIGN_UNAUTHORIZED:
		ret = "None";
		break;
	default:
		(void)printf("Error: invalid signer_info %d\n", signer_info);
		ret = NULL;
		break;
	}

	return ret;
}
