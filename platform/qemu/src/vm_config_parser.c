// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>

#include <rm_types.h>

#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <utils/vector.h>

#include <dtb_parser.h>
#include <event.h>
#include <guest_interface.h>
#include <platform_dt_parser.h>
#include <platform_vm_config.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_mgnt.h>

// Must be last
#include <platform_vm_config_parser.h>
#include <vm_config_parser.h>

listener_return_t
platform_parse_vm_config(void *data, void *fdt, int node_ofs, ctx_t *ctx);

static error_t
parse_segments(vm_config_parser_data_t *vd, void *fdt, int node_ofs);

listener_return_t
platform_parse_vm_config(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)(data);

	error_t segments_ret = parse_segments(vd, fdt, node_ofs);
	if (segments_ret != OK) {
		ret = RET_ERROR;
		goto out;
	}

	// put remaining vm_config's platform parsers here!

out:
	if (ret == RET_ERROR) {
		vd->platform.primary_vm_index = 0U;
	}

	(void)data;
	(void)fdt;
	(void)node_ofs;
	(void)ctx;
	return ret;
}

error_t
parse_segments(vm_config_parser_data_t *vd, void *fdt, int node_ofs)
{
	error_t ret = OK;

	int segments_ofs = fdt_subnode_offset(fdt, node_ofs, "segments");
	if (segments_ofs < 0) {
		goto out;
	}

	if (fdt_getprop_s32(fdt, segments_ofs, "ramdisk",
			    &vd->platform.ramfs_idx) != OK) {
		(void)printf("Warning: ramdisk segment index\n");

		vd->platform.ramfs_idx = -1;
	}

out:
	return ret;
}
