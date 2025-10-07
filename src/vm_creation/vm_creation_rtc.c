// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>
#include <utils/list.h>

#include <dt_linux.h>
#include <dt_overlay.h>
#include <event.h>
#include <guest_interface.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation_dt.h>
#include <vm_mgnt.h>

#include "dto_construct.h"

error_t
dto_create_vrtc(const struct vdevice_node *node, dto_t *dto)
{
	error_t	 ret;
	error_t	 e	 = OK;
	uint32_t phandle = 0U;

	struct vdevice_rtc *cfg = node->config.rtc;

	size_t sz   = strlen(node->generate) + DTB_NODE_NAME_MAX;
	char  *path = (char *)malloc(sz);
	if (path == NULL) {
		(void)printf("Error: failed to allocate path for RTC\n");
		e = ERROR_NOMEM;
		goto err_begin;
	}

	// The kernel driver for PL031 needs a clock node associated with the
	// AMBA device or it will fail to probe, so we create a dummy clock node
	// with a unique phandle value to associate with the RTC node.
	int32_t sz_ret;
	sz_ret = snprintf(path, sz, "%s/vrtc-pclk", node->generate);
	assert(sz_ret >= 0);
	e = dto_construct_begin_path(dto, path);
	if (e != OK) {
		goto err_free;
	}
	e = dto_property_add_u32(dto, "#clock-cells", 0);
	if (e != OK) {
		goto err;
	}
	e = dto_property_add_string(dto, "compatible", "fixed-clock");
	if (e != OK) {
		goto err;
	}
	e = dto_property_add_u32(dto, "clock-frequency", 1);
	if (e != OK) {
		goto err;
	}
	e = dto_property_add_phandle(dto, &phandle);
	if (e != OK) {
		goto err;
	}
	e = dto_construct_end_path(dto, path);
	if (e != OK) {
		goto err_free;
	}

	// Now create the vRTC node
	sz_ret = snprintf(path, sz, "%s/vrtc", node->generate);
	assert(sz_ret >= 0);
	e = dto_construct_begin_path(dto, path);
	if (e != OK) {
		goto err_free;
	}

	const char *c[] = { "arm,pl031", "arm,primecell" };
	e = vm_creation_add_compatibles(node, c, (count_t)util_array_size(c),
					dto);
	if (e != OK) {
		goto err;
	}

	uint64_t reg[2] = { cfg->ipa, cfg->ipa_size };
	e		= dto_property_add_u64array(dto, "reg", reg, 2);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_string(dto, "clock-names", "apb_pclk");
	if (e != OK) {
		goto err;
	}

	e = dto_property_ref_internal(dto, "clocks", phandle);

err:
	ret = dto_construct_end_path(dto, path);
	if (e == OK) {
		e = ret;
	}
err_free:
	free(path);
err_begin:
	return e;
}
