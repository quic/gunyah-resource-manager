// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>

#include <rm_types.h>

#include <guest_interface.h>
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

#include <util.h>
#include <utils/vector.h>

#include <dt_overlay.h>
#include <dtb_parser.h>
#include <event.h>
#include <log.h>
#include <memextent.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <rm_env_data.h>
#include <vgic.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_vcpu.h>

#include <platform_vm_config_parser.h>
#include <vm_config_parser.h>

// This is set to a nonzero value if the HLOS VM should be constructed with
// virtual GICRs matching the physical GICR addresses. This is needed if the
// physical GICRs implement GICv4, so they have 256KB stride, and the platform
// device tree has that stride hard-coded instead of allowing the driver to
// probe it. Otherwise, we use the natural 128KB stride of a GICv3 GICR.
#if !defined(PLATFORM_VGIC_USE_PHYS_STRIDE)
#define PLATFORM_VGIC_USE_PHYS_STRIDE 0
#endif

static vector_t *hlos_vgic_itss = NULL;
static paddr_t	 hlos_vgic_gicd_base;
#if PLATFORM_VGIC_USE_PHYS_STRIDE
static size_t hlos_vgic_gicr_stride;
#endif
static paddr_t hlos_vgic_gicr_base;
static count_t hlos_vgic_gicr_count;

error_t
vgic_init(const rm_env_data_t *env_data)
{
	count_t		    gits_count	      = 0U;
	const rm_range64_t *gits_ranges	      = env_data->gits_ranges;
	count_t		    gits_ranges_count = env_data->gits_ranges_count;
	assert(gits_ranges_count <= util_array_size(env_data->gits_ranges));
	for (index_t i = 0; i < gits_ranges_count; i++) {
		assert(gits_ranges[i].size > 0U);
		gits_count += gits_ranges[i].size;
	}
	assert(gits_count <= util_array_size(env_data->its_caps));
	assert(gits_count == env_data->gic_xlate_me_count);
	assert(gits_count <= util_array_size(env_data->gic_xlate_me));

	hlos_vgic_itss = vector_init(vgic_its_t, gits_count, 1u);
	assert(hlos_vgic_itss != NULL);

	index_t range = 0U, range_index = 0U;
	for (index_t i = 0U; i < gits_count; i++) {
		assert(range < gits_ranges_count);
		assert(range_index < gits_ranges[range].size);

		vgic_its_t its = {
			.msi_source_cap = env_data->its_caps[i],
			.phys_base	= gits_ranges[range].base +
				     (range_index * env_data->gits_stride),
			.xlate_me = env_data->gic_xlate_me[i],
		};

		if (its.msi_source_cap != CSPACE_CAP_INVALID) {
			error_t err = vector_push_back(hlos_vgic_itss, its);
			assert(err == OK);
		}

		range_index++;
		if (range_index == gits_ranges[range].size) {
			range++;
			range_index = 0U;
		}
	}

	hlos_vgic_gicd_base = env_data->gicd_base;

	assert(env_data->gicr_ranges_count == 1U);
	hlos_vgic_gicr_base  = env_data->gicr_ranges[0].base;
	hlos_vgic_gicr_count = (uint32_t)env_data->gicr_ranges[0].size;
#if PLATFORM_VGIC_USE_PHYS_STRIDE
	hlos_vgic_gicr_stride = env_data->gicr_stride;
#endif

	return OK;
}

static error_t
vm_config_alloc_vgic_its(vm_t *vm)
{
	error_t	    err = OK;
	vgic_its_t *vgic_its;
	index_t	    i;
	// GITSs: 128k each, attached with MSI source cap and index 0.
	// Second 64K page is normally shadowed by a mapping of the
	// real ITS's translate register (which must be mapped so
	// devices behind SMMUs can access it), so we don't reserve
	// the address range for that page.
	foreach_vector_ptr (vgic_its_t, vm->vm_config->vgic_itss, i, vgic_its) {
		if ((vgic_its->ipa_base != INVALID_ADDRESS) &&
		    util_add_overflows(vgic_its->ipa_base,
				       vgic_gits_size - 1U)) {
			err = ERROR_ADDR_OVERFLOW;
			goto out;
		}
		if ((vgic_its->ipa_base != INVALID_ADDRESS) &&
		    !util_is_baligned(vgic_its->ipa_base, vgic_alignment)) {
			err = ERROR_ADDR_INVALID;
			goto out;
		}

		vm_address_range_result_t alloc_ret = vm_address_range_alloc(
			vm, VM_MEMUSE_PLATFORM_VDEVICE, vgic_its->ipa_base,
			INVALID_ADDRESS, vgic_gits_size - vgic_gits_xlate_size,
			vgic_gits_size);
		if (alloc_ret.err == OK) {
			vgic_its->ipa_base = alloc_ret.base;
		} else {
			err = alloc_ret.err;
			LOG_LOC("alloc ITS");
			goto out;
		}

		err = gunyah_hyp_addrspace_attach_vdevice(
			vm->vm_config->addrspace, vgic_its->vgic_its_cap, 0U,
			vgic_its->ipa_base, vgic_gits_size,
			(addrspace_attach_vdevice_flags_t){ 0U });
		if (err != OK) {
			LOG_LOC("attach ITS");
			goto out;
		}

		err = memextent_map(vgic_its->xlate_me,
				    vm->vm_config->addrspace,
				    vgic_its->ipa_base + 0x10000U,
				    PGTABLE_ACCESS_RW,
				    PGTABLE_VM_MEMTYPE_DEVICE_NGRE, false);
		if (err != OK) {
			LOG_LOC("map ITS xlate");
			goto out;
		}
	}

out:
	return err;
}

static error_t
vm_config_attach_gicr(const vm_t *vm, const count_t gicr_cnt)
{
	error_t err = OK;

	index_t gicr_slot  = 0U;
	size_t	vcpu_count = vector_size(vm->vm_config->vcpus);

	for (index_t i = 0U; i < vcpu_count; i++) {
		vcpu_t *vcpu = vector_at(vcpu_t *, vm->vm_config->vcpus, i);
		assert(vcpu != NULL);

		if (vcpu->defective) {
			continue;
		}

		vgic_gicr_attach_flags_t flags =
			vgic_gicr_attach_flags_default();
		vgic_gicr_attach_flags_set_last(&flags,
						gicr_slot == (gicr_cnt - 1U));
		vgic_gicr_attach_flags_set_last_valid(&flags, true);
		err = gunyah_hyp_addrspace_attach_vdevice(
			vm->vm_config->addrspace, vm->vm_config->vic,
			vcpu->address_index + 1U,
			vm->vm_config->vgic_gicr_base +
				(gicr_slot * vm->vm_config->vgic_gicr_stride),
			vgic_gicr_size,
			(addrspace_attach_vdevice_flags_t){ .vgic_gicr =
								    flags });
		if (err != OK) {
			LOG_LOC("attach GICR");
			goto out;
		}
		gicr_slot++;
	}

out:
	return err;
}

error_t
vgic_vm_config_add(vm_config_t *vmcfg, const vm_config_parser_data_t *data)
{
	error_t err;

	count_t gicr_cnt = 0U;

	// Count the number of gicrs to create. Note that this must be exactly
	// correct because the setting of the GICR_TYPER.Last bit in the
	// highest-addressed GICR is conditional on it, and Linux will crash
	// at boot if that bit is not set.
	size_t vcpu_count = vector_size(vmcfg->vcpus);
	for (index_t i = 0U; i < vcpu_count; i++) {
		vcpu_t *vcpu = vector_at(vcpu_t *, vmcfg->vcpus, i);
		assert(vcpu != NULL);

		if (!vcpu->defective) {
			gicr_cnt++;
		}
	}
	assert(gicr_cnt != 0U);

	if (data == NULL) {
		// This is the primary VM.

		// ITSs must be attached at the same address as the underlying
		// physical ITS, to avoid having to remap the translate
		// register.
		if (vmcfg->vgic_itss != NULL) {
			vgic_its_t *vgic_its;
			index_t	    i;

			foreach_vector_ptr (vgic_its_t, vmcfg->vgic_itss, i,
					    vgic_its) {
				vgic_its_t *its;

				its = vector_at_ptr(vgic_its_t, hlos_vgic_itss,
						    i);
				assert(its != NULL);
				vgic_its->ipa_base = (vmaddr_t)its->phys_base;
				vgic_its->xlate_me = its->xlate_me;
			}
		}

		// We need to attach at the platform address range taken from
		// the boot environment.
		assert(gicr_cnt <= hlos_vgic_gicr_count);
		vmcfg->vgic_gicd_base = hlos_vgic_gicd_base;
		vmcfg->vgic_gicr_base = hlos_vgic_gicr_base;
#if PLATFORM_VGIC_USE_PHYS_STRIDE
		vmcfg->vgic_gicr_stride = hlos_vgic_gicr_stride;
#else
		vmcfg->vgic_gicr_stride = vgic_gicr_size;
#endif

		// Patching the DT is not possible.
		vmcfg->vgic_phandle  = ~0U;
		vmcfg->vgic_patch_dt = false;

		// We need to make a guess at the #address-cells property of
		// the GIC node since it determines the format of interrupt-map
		// properties in the PCI nodes.
#if defined(PLATFORM_HLOS_NEEDS_VPCI) && PLATFORM_HLOS_NEEDS_VPCI
		vmcfg->vgic_child_addr_cells = PLATFORM_HLOS_GIC_ADDRESS_CELLS;
		vmcfg->map_addr_cells	     = vmcfg->vgic_child_addr_cells;
#endif
	} else if (data->vgic_gicr_stride == 0U) {
		// If the stride wasn't initialised in the parser data,
		// we need to allocate addresses and generate a DT node
		// from scratch.
		vmcfg->vgic_gicd_base	= INVALID_ADDRESS;
		vmcfg->vgic_gicr_base	= INVALID_ADDRESS;
		vmcfg->vgic_gicr_stride = vgic_gicr_size;
		vmcfg->vgic_phandle	= ~0U;
		vmcfg->vgic_patch_dt	= true;
	} else {
		// Copy the parser data. This may or may not trigger
		// generation or patching of the DT node.
		vmcfg->vgic_gicd_base	     = data->vgic_gicd_base;
		vmcfg->vgic_gicr_base	     = data->vgic_gicr_base;
		vmcfg->vgic_gicr_stride	     = data->vgic_gicr_stride;
		vmcfg->vgic_phandle	     = data->vgic_phandle;
		vmcfg->vgic_patch_dt	     = data->vgic_patch_dt;
		vmcfg->vgic_addr_cells	     = data->vgic_addr_cells;
		vmcfg->vgic_size_cells	     = data->vgic_size_cells;
		vmcfg->vgic_child_addr_cells = data->vgic_child_addr_cells;
		vmcfg->map_addr_cells	     = data->map_addr_cells;
	}

	// Allocate and attach the GIC vdevice address ranges
	vm_t *vm = vmcfg->vm;
	assert(vm != NULL);

	// GICD: 64K, attachment index 0
	if ((vm->vm_config->vgic_gicd_base != INVALID_ADDRESS) &&
	    util_add_overflows(vm->vm_config->vgic_gicd_base,
			       vgic_gicd_size - 1U)) {
		err = ERROR_ADDR_OVERFLOW;
		LOG_LOC("overflow GICD");
		goto out;
	}
	if ((vm->vm_config->vgic_gicd_base != INVALID_ADDRESS) &&
	    !util_is_baligned(vm->vm_config->vgic_gicd_base, vgic_alignment)) {
		err = ERROR_ADDR_INVALID;
		LOG_LOC("align GICD");
		goto out;
	}

	vm_address_range_result_t alloc_ret = vm_address_range_alloc(
		vm, VM_MEMUSE_PLATFORM_VDEVICE, vm->vm_config->vgic_gicd_base,
		INVALID_ADDRESS, vgic_gicd_size, vgic_gicd_size);
	if (alloc_ret.err == OK) {
		vm->vm_config->vgic_gicd_base = alloc_ret.base;
	} else {
		err = alloc_ret.err;
		LOG_LOC("alloc GICD");
		goto out;
	}

	err = gunyah_hyp_addrspace_attach_vdevice(
		vm->vm_config->addrspace, vm->vm_config->vic, 0U,
		vm->vm_config->vgic_gicd_base, vgic_gicd_size,
		(addrspace_attach_vdevice_flags_t){ 0U });
	if (err != OK) {
		LOG_LOC("attach GICD");
		goto out;
	}

	// GICRs: one contiguous region, 128K each (possibly with 256K stride),
	// attachment indices n + 1
	if ((vm->vm_config->vgic_gicr_stride < vgic_gicr_size) ||
	    util_mult_integer_overflows(vm->vm_config->vgic_gicr_stride,
					gicr_cnt)) {
		err = ERROR_ARGUMENT_SIZE;
		goto out;
	}
	const size_t gicr_total_size =
		vm->vm_config->vgic_gicr_stride * gicr_cnt;
	if ((vm->vm_config->vgic_gicr_base != INVALID_ADDRESS) &&
	    util_add_overflows(vm->vm_config->vgic_gicr_base,
			       gicr_total_size - 1U)) {
		err = ERROR_ADDR_OVERFLOW;
		LOG_LOC("overflow GICR");
		goto out;
	}
	if ((vm->vm_config->vgic_gicr_base != INVALID_ADDRESS) &&
	    !util_is_baligned(vm->vm_config->vgic_gicr_base, vgic_alignment)) {
		err = ERROR_ADDR_INVALID;
		LOG_LOC("align GICR");
		goto out;
	}

	alloc_ret = vm_address_range_alloc(vm, VM_MEMUSE_PLATFORM_VDEVICE,
					   vm->vm_config->vgic_gicr_base,
					   INVALID_ADDRESS, gicr_total_size,
					   vm->vm_config->vgic_gicr_stride);
	if (alloc_ret.err == OK) {
		vm->vm_config->vgic_gicr_base = alloc_ret.base;
	} else {
		err = alloc_ret.err;
		LOG_LOC("alloc GICR");
		goto out;
	}

	err = vm_config_attach_gicr(vm, gicr_cnt);
	if (err != OK) {
		goto out;
	}

	if (vm->vm_config->vgic_itss != NULL) {
		err = vm_config_alloc_vgic_its(vm);
		if (err != OK) {
			goto out;
		}
	}

out:
	return err;
}

error_t
vgic_dto_finalise(dto_t *dto, const vm_t *vm)
{
	assert(dto != NULL);
	assert(vm != NULL);

	vm_config_t *vmcfg = vm->vm_config;
	assert(vmcfg != NULL);

	error_t ret;

	if (!vmcfg->vgic_patch_dt) {
		ret = OK;
		goto out;
	}

	if (vmcfg->vgic_phandle == ~0U) {
		// Creating a VGIC node from scratch is not yet implemented
		(void)printf("Invalid or missing VGIC node in DT\n");
		ret = ERROR_UNIMPLEMENTED;
		goto out;
	}

	(void)printf("vgic_dto_finalise: patching node %#x\n",
		     vmcfg->vgic_phandle);
	ret = dto_modify_begin_by_phandle(dto, vmcfg->vgic_phandle);
	if (ret != OK) {
		goto out;
	}

	ret = dto_property_add_string(dto, "compatible", "arm,gic-v3");
	if (ret != OK) {
		goto out;
	}

	ret = dto_property_add_u32(dto, "#redistributor-regions", 1U);
	if (ret != OK) {
		goto out;
	}

	ret = dto_property_add_u64(dto, "redistributor-stride",
				   vmcfg->vgic_gicr_stride);
	if (ret != OK) {
		goto out;
	}

	size_t num_vcpus = vector_size(vmcfg->vcpus);
	if (num_vcpus == 0U) {
		(void)printf("VGIC cannot be generated for 0 VCPUs\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	dto_addrrange_t reg[2] = {
		{ .addr = vmcfg->vgic_gicd_base, .size = vgic_gicd_size },
		{ .addr = vmcfg->vgic_gicr_base,
		  .size = vmcfg->vgic_gicr_stride * num_vcpus },
	};
	ret = dto_property_add_addrrange_array(dto, "reg", reg,
					       (count_t)util_array_size(reg),
					       vmcfg->vgic_addr_cells,
					       vmcfg->vgic_size_cells);
	if (ret != OK) {
		goto out;
	}

	ret = dto_modify_end_by_phandle(dto, vmcfg->vgic_phandle);

out:
	return ret;
}
