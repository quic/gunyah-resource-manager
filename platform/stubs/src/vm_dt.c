// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <rm_types.h>
#include <util.h>
#include <utils/vector.h>

#include <dt_linux.h>
#include <dt_overlay.h>
#include <dtb_parser.h>
#include <guest_interface.h>
#include <platform_dt.h>
#include <platform_dt_parser.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <vgic.h>
#include <vm_config.h>
#include <vm_config_struct.h>

#include <platform_vm_config_parser.h>

// Late include
#include <vm_config_parser.h>

error_t
platform_dto_finalise(dto_t *dto, vm_t *vm, const void *base_dtb)
{
	(void)dto;
	(void)vm;
	(void)base_dtb;
	return OK;
}

error_t
platform_dto_add_platform_props(dto_t *dto, vm_t *cur_vm)
{
	error_t dto_err = OK;

	(void)dto;
	(void)cur_vm;

	return dto_err;
}

error_t
platform_dto_create(struct vdevice_node *node, dto_t *dto, vmid_t self)
{
	error_t dto_err = ERROR_UNIMPLEMENTED;

	(void)node;
	(void)dto;
	(void)self;

	return dto_err;
}
