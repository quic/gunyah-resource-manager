// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <rm_types.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <dtb_parser.h>
#include <platform.h>
#include <platform_dt_parser.h>

#include <platform_vm_config_parser.h>

listener_return_t
platform_parse_vm_config(void *data, void *fdt, int node_ofs, ctx_t *ctx);

rm_error_t
platform_alloc_parser_data(vm_config_parser_data_t *vd)
{
	(void)vd;
	return RM_OK;
}

void
platform_free_parser_data(vm_config_parser_data_t *vd)
{
	(void)vd;
}

listener_return_t
platform_parse_vm_config(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	(void)data;
	(void)fdt;
	(void)node_ofs;
	(void)ctx;
	return RET_CLAIMED;
}
