// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
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

#include <dt_linux.h>
#include <dt_overlay.h>
#include <dtb_parser.h>
#include <platform_dt.h>
#include <platform_dt_parser.h>
#include <platform_vm_config.h>
#include <platform_vm_config_parser.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <vgic.h>
#include <vm_config.h>
#include <vm_config_struct.h>

// Late include
#include <vm_config_parser.h>

static error_t
platform_parse_gic(vm_config_parser_data_t *vd, const void *fdt,
		   uint32_t phandle)
{
	error_t ret;
	int	vgic_ofs = fdt_node_offset_by_phandle(fdt, phandle);

	if (vgic_ofs < 0) {
		(void)printf("Interrupt controller phandle is invalid\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	ctx_t ctx = dtb_parser_get_ctx(fdt, vgic_ofs);

	if (!ctx.addr_is_phys) {
		char path[256];
		if (fdt_get_path(fdt, vgic_ofs, path, (int)sizeof(path)) != 0) {
			(void)strlcpy(path, "<unknown path>", sizeof(path));
		}
		(void)printf("Warning: addresses in %s are not 1:1 physical!\n",
			     path);
	}

	// check vgic compatible
	if (fdt_node_check_compatible(fdt, vgic_ofs, "arm,gic-v3") != 0) {
		(void)printf("Interrupt controller is not a GIC\n");
		ret = ERROR_UNIMPLEMENTED;
		goto out;
	}

	if (!fdt_getprop_bool(fdt, vgic_ofs, "interrupt-controller")) {
		(void)printf("Missing \"interrupt-controller\" property\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	vd->platform.vgic_addr_cells = ctx.addr_cells;
	vd->platform.vgic_size_cells = ctx.size_cells;

	uint32_t gicr_regions;
	if ((fdt_getprop_u32(fdt, vgic_ofs, "#redistributor-regions",
			     &gicr_regions) == OK) &&
	    (gicr_regions != 1U)) {
		(void)printf("Can't support multiple GICR regions\n");
		ret = ERROR_ADDR_INVALID;
		goto out;
	}

	uint32_t int_cells;
	if ((fdt_getprop_u32(fdt, vgic_ofs, "#interrupt-cells", &int_cells) !=
	     OK) ||
	    (int_cells != 3U)) {
		(void)printf(
			"GIC node does not specify #interrupt-cells = 3\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	int	       len;
	const fdt32_t *reg =
		(const fdt32_t *)fdt_getprop(fdt, vgic_ofs, "reg", &len);
	uint32_t reg_cells = ctx.addr_cells + ctx.size_cells;
	if (reg == NULL) {
		// No reg property; patch DT and allocate addresses
		vd->platform.vgic_gicd_base = INVALID_ADDRESS;
		vd->platform.vgic_gicr_base = INVALID_ADDRESS;
		vd->platform.vgic_patch_dt  = true;
	} else if ((size_t)len >= (sizeof(fdt32_t) * 2U * reg_cells)) {
		// Reg property is valid. Parse GICD and GICR addresses, and
		// don't patch the DT.
		index_t i = 0;
		vd->platform.vgic_gicd_base =
			fdt_read_num(&reg[i], ctx.addr_cells);
		i += reg_cells;
		vd->platform.vgic_gicr_base =
			fdt_read_num(&reg[i], ctx.addr_cells);
		vd->platform.vgic_patch_dt = false;
	} else {
		(void)printf("Truncated \"reg\" property in GIC node\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	// Virtual GICR is always GICv3, with no VLPIS, so size is 128K
	const size_t gicr_size = (size_t)2U << 16;

	if (fdt_getprop_u64(fdt, vgic_ofs, "redistributor-stride",
			    &vd->platform.vgic_gicr_stride) == OK) {
		if ((vd->platform.vgic_gicr_stride < gicr_size) ||
		    !util_is_p2aligned(vd->platform.vgic_gicr_stride, 16)) {
			(void)printf(
				"GIC node's \"redistributor-stride\" value (%#zx) is too small or misaligned\n",
				vd->platform.vgic_gicr_stride);
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}
	} else {
		// No stride property; default to the size of the GICR.
		vd->platform.vgic_gicr_stride = gicr_size;
	}

	ret = OK;

out:
	if (ret != OK) {
		vd->platform.vgic_gicr_stride = 0U;
		vd->platform.vgic_phandle     = ~0U;
	} else {
		vd->platform.vgic_phandle = phandle;
	}
	return ret;
}

listener_return_t
platform_parse_interrupts(vm_config_parser_data_t *vd, const void *fdt,
			  int node_ofs, const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;
	(void)ctx;

	// Try to find the GIC from the explicit config path.
	uint32_t    phandle = ~0U;
	int	    len;
	const char *path = fdt_stringlist_get(fdt, node_ofs, "config", 0, &len);
	if ((path != NULL) && (len > 1) && (path[0] == '/')) {
		int gic_ofs = fdt_path_offset(fdt, path);
		if (gic_ofs < 0) {
			(void)printf(
				"Error: couldn't find GIC node \"%s\": %d\n",
				path, gic_ofs);
			ret = RET_ERROR;
			goto out;
		}
		phandle = fdt_get_phandle(fdt, gic_ofs);
	} else if ((len == -FDT_ERR_NOTFOUND) &&
		   (vd->platform.vgic_phandle != ~0U)) {
		// Property was missing (not invalid) and we already found the
		// GIC from the root node; no error.
		ret = RET_CONTINUE;
		goto out;
	} else if (fdt_getprop_u32(fdt, node_ofs, "config", &phandle) == OK) {
		(void)printf(
			"Warning: interrupts \"config\" property looks like a phandle (%#x), but should be a path\n",
			phandle);
	} else {
		// Property is present, but doesn't look like either a path or
		// a phandle
		(void)printf("Error: couldn't read \"config\" property\n");
		ret = RET_ERROR;
		goto out;
	}

	if (phandle != vd->platform.vgic_phandle) {
		// Config specified a GIC, and it's not the same as the root
		// interrupt-parent (or the latter was missing or invalid).
		error_t err = platform_parse_gic(vd, fdt, phandle);
		if (err != OK) {
			(void)printf("Parsing GIC node failed: %d\n", err);
			ret = RET_ERROR;
			goto out;
		}
	}

out:
	return ret;
}

listener_return_t
platform_parse_root(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		    const ctx_t *ctx)
{
	(void)ctx;

	// Since the root node is the first node visited, we should not have
	// already parsed the vm-config interrupts node.
	assert(vd->platform.vgic_phandle == 0U);
	vd->platform.vgic_phandle = ~0U;

	// Try to find the GIC from the root interrupt-parent.
	uint32_t phandle;
	if (fdt_getprop_u32(fdt, node_ofs, "interrupt-parent", &phandle) ==
	    OK) {
		// Try to parse the GIC node. Ignore any failures at this point;
		// wait for the vm-config.
		(void)platform_parse_gic(vd, fdt, phandle);
	}

	return RET_CONTINUE;
}

error_t
platform_dto_finalise(dto_t *dto, vm_t *vm, const void *base_dtb)
{
	error_t err;

	(void)base_dtb;
	err = vgic_dto_finalise(dto, vm);
	if (err != OK) {
		goto out;
	}

out:
	return err;
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
