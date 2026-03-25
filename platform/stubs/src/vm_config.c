// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <rm_types.h>

#include <platform_vm_config.h>

error_t
platform_vm_config_create_vdevices(vm_config_t		   *vmcfg,
				   vm_config_parser_data_t *data)
{
	(void)vmcfg;
	(void)data;
	return OK;
}

error_t
platform_vm_config_hlos_vdevices_setup(vm_config_t *vmcfg)
{
	(void)vmcfg;
	return OK;
}
