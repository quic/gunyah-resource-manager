// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.

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

static uint32_result_t
dto_create_vrtc_pclk(dto_t *dto)
{
	error_t	 e;
	uint32_t phandle = DTO_PHANDLE_UNSET;

	// The kernel driver for PL031 needs a clock node associated with the
	// AMBA device or it will fail to probe, so we create a dummy clock node
	// with a unique phandle value to associate with the RTC node.
	CHECK_DTO(e, dto_node_begin(dto, "vrtc-pclk"));
	CHECK_DTO(e, dto_property_add_u32(dto, "#clock-cells", 0));
	CHECK_DTO(e, dto_property_add_string(dto, "compatible", "fixed-clock"));
	CHECK_DTO(e, dto_property_add_u32(dto, "clock-frequency", 1));
	CHECK_DTO(e, dto_property_add_phandle(dto, &phandle));
	CHECK_DTO(e, dto_node_end(dto, "vrtc-pclk"));

out:
	return (e == OK) ? uint32_result_ok(phandle) : uint32_result_error(e);
}

error_t
dto_create_vrtc(const struct vdevice_node *node, dto_t *dto)
{
	error_t e = OK;

	struct vdevice_rtc *cfg = node->config.rtc;

	// We're called from /vsoc generation, so we can just start the node
	// without creating an overlay fragment, and we can assume that the
	// address / size cell counts are 2.

	uint32_result_t phandle_r = dto_create_vrtc_pclk(dto);
	if (phandle_r.e != OK) {
		e = phandle_r.e;
		goto out;
	}

	const char *c[] = { "arm,pl031", "arm,primecell" };
	CHECK_DTO(e, dto_node_begin(dto, "vrtc"));
	CHECK_DTO(e, vm_creation_add_compatibles(
			     node, c, (count_t)util_array_size(c), dto));
	CHECK_DTO(e, dto_property_add_addrrange(dto, "reg", 2U, cfg->ipa, 2U,
						cfg->ipa_size));
	CHECK_DTO(e, dto_property_add_string(dto, "clock-names", "apb_pclk"));
	CHECK_DTO(e, dto_property_ref_internal(dto, "clocks", phandle_r.r));
	CHECK_DTO(e, dto_node_end(dto, "vrtc"));

out:
	return e;
}
