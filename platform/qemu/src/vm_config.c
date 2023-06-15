// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <stdio.h>

#include <rm_types.h>

#include <dt_overlay.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vgic.h>

error_t
platform_vm_config_create_vdevices(vm_config_t		   *vmcfg,
				   vm_config_parser_data_t *data)
{
	error_t ret = OK;

	ret = vgic_vm_config_add(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle virtual GIC\n");
		goto out;
	}

out:
	return ret;
}

error_t
platform_vm_config_hlos_vdevices_setup(vm_config_t *vmcfg)
{
	error_t ret = OK;
	(void)vmcfg;

	ret = vgic_vm_config_add(vmcfg, NULL);
	if (ret != OK) {
		printf("Error: failed to handle virtual GIC\n");
		goto out;
	}

out:
	return ret;
}
