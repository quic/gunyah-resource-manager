// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>

#include <rm-rpc.h>

#include <resource-manager.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <dt_linux.h>
#include <dt_overlay.h>
#include <dtb_parser.h>
#include <memparcel_msg.h>
#include <platform_dt.h>
#include <platform_dt_parser.h>
#include <platform_vm_config.h>
#include <util.h>
#include <utils/list.h>
#include <utils/vector.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_mgnt.h>

// Late include
#include <platform_vm_config_parser.h>
#include <vm_config_parser.h>

error_t
platform_dto_finalise(dto_t *dto, vm_t *vm)
{
	(void)dto;
	(void)vm;

	return OK;
}
