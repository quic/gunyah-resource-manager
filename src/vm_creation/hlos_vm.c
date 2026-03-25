// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <rm_types.h>
#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/vector.h>

#if defined(CONFIG_DEVICE_MANAGER) && CONFIG_DEVICE_MANAGER
#include <device_manager.h>
#endif
#include <event.h>
#include <guest_interface.h>
#include <guest_rights.h>
#include <irq_arch.h>
#include <irq_manager.h>
#include <log.h>
#include <mem_region.h>
#include <memextent.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_msi.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <virq.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_creation_addrspace.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_passthrough_config.h>
#include <vm_vcpu.h>

#define HLOS_VCPU_PRIORITY ROOTVM_PRIORITY

static error_t
hlos_vm_create_secondary_vcpus(const vm_config_t *vmcfg, cap_id_t partition_cap,
			       cap_id_t cspace_cap, cap_id_t new_cspace_cap,
			       cap_id_t addrspace_cap, cap_id_t vg_cap,
			       cap_id_t		  *vcpu_caps,
			       vcpu_option_flags_t vcpu_options)
{
	error_t ret;

	cpu_index_t i;
	for (i = 0; i < rm_get_platform_max_cores(); i++) {
		if ((i == rm_get_platform_root_vcpu_index()) ||
		    (!rm_is_core_usable(i))) {
			continue;
		}

		gunyah_hyp_partition_create_thread_result_t vcpu;
		vcpu = gunyah_hyp_partition_create_thread(partition_cap,
							  cspace_cap);
		if (vcpu.error != OK) {
			ret = vcpu.error;
			LOG_ERR(ret);
			goto out;
		}

		vcpu_caps[i] = vcpu.new_cap;

		ret = gunyah_hyp_vcpu_configure(vcpu.new_cap, vcpu_options);
		if (ret != OK) {
			LOG_ERR(ret);
			goto out;
		}

		ret = gunyah_hyp_vcpu_set_affinity(
			vcpu.new_cap, i, VCPU_AFFINITY_TYPE_CPU_INDEX);
		if (ret != OK) {
			LOG_ERR(ret);
			goto out;
		}

		ret = gunyah_hyp_vcpu_set_priority(vcpu.new_cap,
						   HLOS_VCPU_PRIORITY);
		if (ret != OK) {
			LOG_ERR(ret);
			goto out;
		}

		ret = gunyah_hyp_cspace_attach_thread(new_cspace_cap,
						      vcpu.new_cap);
		if (ret != OK) {
			LOG_ERR(ret);
			goto out;
		}

		ret = gunyah_hyp_addrspace_attach_thread(addrspace_cap,
							 vcpu.new_cap);
		if (ret != OK) {
			LOG_ERR(ret);
			goto out;
		}

		if (vmcfg->watchdog != CSPACE_CAP_INVALID) {
			ret = gunyah_hyp_watchdog_attach_vcpu(vmcfg->watchdog,
							      vcpu.new_cap);
			if (ret != OK) {
				LOG_ERR(ret);
				goto out;
			}
		}

		ret = gunyah_hyp_vpm_group_attach_vcpu(vg_cap, vcpu.new_cap, i);
		if (ret != OK) {
			LOG_ERR(ret);
			goto out;
		}
	}
	ret = OK;

out:
	if (ret != OK) {
		(void)printf("Error creating vCPU %d\n", i);
	}
	return ret;
}

static error_t
hlos_vm_get_rm_vcpu_cap(const vm_config_t *vmcfg)
{
	error_t ret;

	vm_t *rm = vm_lookup(VMID_RM);
	assert(rm != NULL);

	vm_config_t *rmcfg = rm->vm_config;
	assert(rmcfg != NULL);

	size_t cnt = vector_size(rmcfg->vcpus);
	assert(cnt == 1U);

	vcpu_t *vcpu = vector_at(vcpu_t *, rmcfg->vcpus, 0U);
	if (vcpu == NULL) {
		ret = ERROR_FAILURE;
		LOG_ERR(ret);
		goto out;
	}

	// Copy RM vcpu cap to hlos VM cspace
	gunyah_hyp_cspace_copy_cap_from_result_t copy_ret;
	cap_rights_t rights = CAP_RIGHTS_THREAD_AFFINITY;

	copy_ret = gunyah_hyp_cspace_copy_cap_from(
		rmcfg->cspace, vcpu->master_cap, vmcfg->cspace, rights);
	if (copy_ret.error != OK) {
		(void)printf("Failed: copy vcpu cap from rm cspace\n");
		ret = copy_ret.error;
		goto out;
	}

	vcpu->owner_cap = copy_ret.new_cap;
	ret		= OK;

out:
	return ret;
}

static error_t
hlos_vm_create_vic(vm_config_t *vmcfg, cap_id_t partition_cap,
		   cap_id_t cspace_cap, cap_id_t addrspace_cap,
		   cap_id_t root_thread_cap, cap_id_t *vcpus_caps,
		   const cap_id_t *its_caps, count_t its_caps_count)
{
	error_t		err;
	cap_id_result_t ret;

	gunyah_hyp_partition_create_vic_result_t v;
	v = gunyah_hyp_partition_create_vic(partition_cap, cspace_cap);
	if (v.error != OK) {
		ret = cap_id_result_error(v.error);
		LOG_ERR(v.error);
		goto out;
	}

	vic_option_flags_t vic_options	  = vic_option_flags_default();
	count_t		   hlos_max_virqs = rm_get_vic_max_virqs();

	// Try configuring the VIC with the maximum number of IRQ numbers
	// reserved for MSIs; if that fails, retry with no IRQs reserved for
	// MSIs. This is a stand-in for proper probing of MSI support. Note that
	// this is orthogonal to whether any of the msi_src_caps are valid.
	//
	// Currently, we hard-code the maximum number of MSI reserved IRQs to
	// that defined by the virtual GIC (8192).
	err = gunyah_hyp_vic_configure(v.new_cap, rm_get_platform_max_cores(),
				       hlos_max_virqs, vic_options,
				       GIC_LPI_NUM);
	if (err == ERROR_ARGUMENT_INVALID) {
		err = gunyah_hyp_vic_configure(v.new_cap,
					       rm_get_platform_max_cores(),
					       hlos_max_virqs, vic_options, 0U);
	}
	if (err != OK) {
		ret = cap_id_result_error(err);
		LOG_ERR(err);
		goto out;
	}

	err = gunyah_hyp_object_activate(v.new_cap);
	if (err != OK) {
		ret = cap_id_result_error(err);
		LOG_ERR(err);
		goto out;
	}

	// Attach primary VCPU to the VIC
	err = gunyah_hyp_vic_attach_vcpu(v.new_cap, root_thread_cap,
					 rm_get_platform_root_vcpu_index());
	if (err != OK) {
		ret = cap_id_result_error(err);
		(void)printf(
			"HLOS: Failed to attach VIC to vCPU 0, error %" PRId32
			"\n",
			(int32_t)err);
		goto out;
	}

	// Attach all secondary VCPUs to the VIC
	for (cpu_index_t i = 0; i < rm_get_platform_max_cores(); i++) {
		if ((i == rm_get_platform_root_vcpu_index()) ||
		    (!rm_is_core_usable(i))) {
			continue;
		}

		err = gunyah_hyp_vic_attach_vcpu(v.new_cap, vcpus_caps[i], i);
		if (err != OK) {
			ret = cap_id_result_error(err);
			(void)printf(
				"HLOS: Failed to attach VIC to vCPU %d, error %" PRId32
				"\n",
				i, (int32_t)err);
			goto out;
		}
	}

	assert(its_caps_count <= (count_t)util_array_size(vmcfg->vgic_its));
	vmcfg->vgic_itss = vector_init(vgic_its_t, 0, 0);
	assert(vmcfg->vgic_itss != NULL);

	// Create and bind all ITS sources (if any) to the VIC.
	for (count_t i = 0U; i < its_caps_count; i++) {
		vic_msi_source_config_t source_config =
			vic_msi_source_config_default();
		vgic_its_t vgic_its;

		if (its_caps[i] == CSPACE_CAP_INVALID) {
			continue;
		}

		gunyah_hyp_partition_create_vgic_its_result_t vgic_its_ret;
		vgic_its_ret = gunyah_hyp_partition_create_vgic_its(
			partition_cap, cspace_cap);
		if (vgic_its_ret.error != OK) {
			ret = cap_id_result_error(vgic_its_ret.error);
			LOG_ERR(vgic_its_ret.error);
			goto out;
		}

		err = gunyah_hyp_object_activate(vgic_its_ret.new_cap);
		if (err != OK) {
			ret = cap_id_result_error(err);
			LOG_ERR(err);
			goto out;
		}

		// A VGIC ITS will need an attachment to the VM's address space
		// before it can be bound to the VIC.
		err = gunyah_hyp_addrspace_attach_vdma(
			addrspace_cap, vgic_its_ret.new_cap, 0U);
		if ((err != OK) && (err != ERROR_CSPACE_WRONG_OBJECT_TYPE)) {
			ret = cap_id_result_error(err);
			(void)printf(
				"HLOS: Failed to attach VDMA for VGIC ITS %d, error %" PRId32
				"\n",
				i, (int32_t)err);
			goto out;
		}

		vic_msi_source_config_set_index(&source_config, (uint16_t)i);
		err = gunyah_hyp_vic_bind_msi_source(
			v.new_cap, vgic_its_ret.new_cap, source_config);

		if (err != OK) {
			ret = cap_id_result_error(err);
			(void)printf(
				"HLOS: Failed to bind VGIC ITS %d, error %" PRId32
				"\n",
				i, (int32_t)err);
			goto out;
		}

		vmcfg->vgic_its[i]	= vgic_its_ret.new_cap;
		vgic_its.msi_source_cap = its_caps[i];
		vgic_its.vgic_its_cap	= vgic_its_ret.new_cap;
		err = vector_push_back(vmcfg->vgic_itss, vgic_its);
		if (err != OK) {
			LOG_ERR(err);
			ret = cap_id_result_error(err);
			goto out;
		}

		// All devices are bound to HLOS on all ITSs.
		const platform_msi_controller_t *ctrl =
			platform_get_msi_controller((index_t)i);
		if (ctrl != NULL) {
			count_t ctrl_count =
				platform_get_msi_ctrl_device_count(ctrl);
			// Assumption: idx zero always contains CPU device
			for (index_t idx = 0; idx < ctrl_count; idx++) {
				platform_msi_device_id_t dev_id =
					platform_get_msi_ctrl_device_id(ctrl,
									idx);
				err = gunyah_hyp_vgic_its_bind_devices(
					vgic_its_ret.new_cap, its_caps[i],
					dev_id, 1);
				if (err != OK) {
					ret = cap_id_result_error(err);
					(void)printf(
						"HLOS: Failed to bind device %d to vgic_its[%d], err %" PRId32
						"\n",
						dev_id, i, (int32_t)err);
					goto out;
				}
			}
		}
	}

	ret = cap_id_result_ok(v.new_cap);

	vmcfg->vic = ret.r;

out:
	if ((ret.e != OK) && (v.error == OK)) {
		err = gunyah_hyp_cspace_delete_cap_from(cspace_cap, v.new_cap);
		assert(err == OK);
	}

	return ret.e;
}

static error_t
hlos_vm_create_irq(vm_t *hlos, vm_config_t *vmcfg)
{
	error_t ret;

	ret = irq_manager_vm_init(hlos, vmcfg->vic, PLATFORM_IRQ_MAX);
	if (ret != OK) {
		goto out;
	}

	ret = irq_manager_vm_hwirq_map_all_direct(hlos);
	if (ret != OK) {
		goto out;
	}

out:
	return ret;
}

static error_t
hlos_vm_activate_vcpus(vm_config_t *vmcfg, const cap_id_t *vcpu_caps,
		       count_t max_cores, cpu_index_t root_vcpu_idx)
{
	error_t ret;

	// Activate all vcpus except those that are defective
	for (cpu_index_t i = 0; i < max_cores; i++) {
		if (!rm_is_core_usable(i)) {
			ret = vm_config_add_defective_vcpu(vmcfg, NULL);
			if (ret != OK) {
				LOG_ERR(ret);
				goto out;
			}
			continue;
		}

		ret = gunyah_hyp_object_activate(vcpu_caps[i]);
		if (ret != OK) {
			LOG_ERR(ret);
			goto out;
		}

		ret = vm_config_add_vcpu(vmcfg, vcpu_caps[i], i, i,
					 i == root_vcpu_idx, NULL);
		if (ret != OK) {
			LOG_ERR(ret);
			goto out;
		}
	}
	ret = OK;

out:
	return ret;
}

static error_t
hlos_vm_do_create(const rm_env_data_t *env_data, vm_t *hlos, vm_config_t *vmcfg)
{
	error_t ret;

	// Platform specific VM creation setup
	ret = platform_vm_create(hlos, true);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	// Setup default vdevices
	ret = vm_config_hlos_vdevices_setup(vmcfg, vmcfg->vic);
	if (ret != OK) {
		goto out;
	}

	// Add RM RPC link
	rm_error_t rm_err = rm_rpc_server_add_link(VMID_HLOS);
	if (rm_err != RM_OK) {
		LOG_ERR(rm_err);
		ret = ERROR_DENIED;
		goto out;
	}

	// Create RM RPC FIFO
	rm_err = rm_rpc_fifo_create(VMID_HLOS);
	if (rm_err != RM_OK) {
		LOG_ERR(rm_err);
		ret = ERROR_DENIED;
		goto out;
	}

	// Platform specific HLOS setup
	ret = platform_hlos_create(hlos, env_data);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	// Set RM vCPU cap to HLOS cspace with affinity right
	// so that HLOS can set RM vCPU to specific Core.
	ret = hlos_vm_get_rm_vcpu_cap(vmcfg);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	// Unmap IO address ranges which are part of device passthrough
	// configuration
	ret = vm_passthrough_config_unmap_ioranges(env_data);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

out:
	return ret;
}

static error_t
hlos_vm_create_watchdog(vm_config_t *vmcfg, cap_id_t root_vcpu_cap,
			cap_id_t rm_partition_cap, cap_id_t rm_cspace_cap)
{
	error_t ret;

	vmcfg->watchdog_allowed = rm_get_watchdog_supported();
	if (vmcfg->watchdog_allowed) {
		gunyah_hyp_partition_create_watchdog_result_t wdt;
		wdt = gunyah_hyp_partition_create_watchdog(rm_partition_cap,
							   rm_cspace_cap);
		if (wdt.error != OK) {
			ret = wdt.error;
			goto out;
		}

		watchdog_option_flags_t watchdog_options =
			watchdog_option_flags_default();

		watchdog_option_flags_set_critical_bite(&watchdog_options,
							true);

		ret = gunyah_hyp_watchdog_configure(wdt.new_cap,
						    watchdog_options);
		if (ret != OK) {
			goto out;
		}

		ret = gunyah_hyp_object_activate(wdt.new_cap);
		if (ret != OK) {
			goto out;
		}

		vmcfg->watchdog = wdt.new_cap;

		// Attach the watchdog to the root vCPU
		ret = gunyah_hyp_watchdog_attach_vcpu(wdt.new_cap,
						      root_vcpu_cap);
		if (ret != OK) {
			goto out;
		}
	} else {
		vmcfg->watchdog = CSPACE_CAP_INVALID;
		ret		= OK;
	}

out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

static error_t
hlos_vm_create_psci_group(vm_config_t *vmcfg, cap_id_t root_vcpu_cap,
			  cap_id_t rm_partition_cap, cap_id_t rm_cspace_cap,
			  cap_id_t *psci_ret)
{
	error_t ret;

	gunyah_hyp_partition_create_vpm_group_result_t vg;
	vg = gunyah_hyp_partition_create_vpm_group(rm_partition_cap,
						   rm_cspace_cap);
	if (vg.error != OK) {
		ret = vg.error;
		goto out;
	}
	vmcfg->vpm_group = vg.new_cap;

	// Enable explicit wakeup if another VM Is the power owner
	if (rm_get_has_system_suspend() &&
	    (platform_get_power_owner_vmid() != VMID_HLOS)) {
		vmcfg->vpm_explicit_wakeup = true;
	}

	ret = vm_config_configure_vpm_group(vmcfg, NULL);
	if (ret != OK) {
		goto out;
	}

	ret = gunyah_hyp_object_activate(vg.new_cap);
	if (ret != OK) {
		goto out;
	}

	// Attach the root vcpu to the vpm group

	ret = gunyah_hyp_vpm_group_attach_vcpu(
		vmcfg->vpm_group, root_vcpu_cap,
		rm_get_platform_root_vcpu_index());
	if (ret != OK) {
		goto out;
	}

	*psci_ret = vmcfg->vpm_group;
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

static error_t
hlos_vm_create_address_space(vm_config_t *vmcfg, cap_id_t rm_partition_cap,
			     cap_id_t rm_cspace_cap, cap_id_t root_vcpu_cap,
			     cap_id_t *as_ret)
{
	error_t ret;

	gunyah_hyp_partition_create_addrspace_result_t as;
	as = gunyah_hyp_partition_create_addrspace(rm_partition_cap,
						   rm_cspace_cap);
	if (as.error != OK) {
		ret = as.error;
		goto out;
	}

	ret = gunyah_hyp_addrspace_configure(as.new_cap, VMID_HLOS);
	if (ret != OK) {
		goto out;
	}

	ret = vm_creation_config_vm_info_area(as.new_cap, vmcfg);
	if (ret != OK) {
		goto out;
	}

	ret = gunyah_hyp_object_activate(as.new_cap);
	if (ret != OK) {
		goto out;
	}
	vmcfg->addrspace = as.new_cap;

	ret = vm_creation_map_vm_info_area(vmcfg);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = gunyah_hyp_addrspace_attach_thread(as.new_cap, root_vcpu_cap);
	if (ret != OK) {
		goto out;
	}

	ret	= OK;
	*as_ret = as.new_cap;

out:
	if (ret != OK) {
		vm_creation_vm_info_area_teardown(vmcfg);
		LOG_ERR(ret);
	}
	return ret;
}

static error_t
hlos_vm_setup_addrspace_info_area(const rm_env_data_t *env_data,
				  vm_config_t	      *vmcfg)
{
	error_t ret;
	error_t err;

	if (!platform_expose_log_to_hlos() ||
	    (env_data->trace_me_capid == CSPACE_CAP_INVALID) ||
	    (env_data->trace_dbl_capid == CSPACE_CAP_INVALID)) {
		(void)printf("info: live trace collection disabled\n");
		ret = OK;
		goto out;
	}

	vmaddr_t trace_ipa = env_data->trace_phys;

	vm_address_range_result_t as_ret = vm_address_range_alloc(
		vmcfg->vm, VM_MEMUSE_BOOTINFO, trace_ipa, env_data->trace_phys,
		env_data->trace_size, ADDRESS_RANGE_NO_ALIGNMENT);
	if (as_ret.err != OK) {
		ret = as_ret.err;
		goto out;
	}

	// Map trace buffer to hlos read-only
	ret = vm_memory_map(vmcfg->vm, VM_MEMUSE_BOOTINFO,
			    env_data->trace_me_capid, trace_ipa,
			    PGTABLE_ACCESS_R, PGTABLE_VM_MEMTYPE_NORMAL_WB);
	if (ret != OK) {
		goto out_free;
	}

	// Allocate and map the virq to HLOS
	uint32_result_t db_irq = irq_manager_vm_alloc_global(vmcfg->vm);
	if (db_irq.e != OK) {
		ret = db_irq.e;
		goto out_unmap_trace;
	}
	ret = irq_manager_vm_virq_map(vmcfg->vm, db_irq.r, false);
	if (ret != OK) {
		goto out_free_irq;
	}

	interrupt_data_t dbl_virq = virq_edge(db_irq.r);

	// Bind VIRQ to recv VM's VIC
	ret = gunyah_hyp_doorbell_bind_virq(env_data->trace_dbl_capid,
					    vmcfg->vic, db_irq.r);
	if (ret != OK) {
		goto out_unmap_irq;
	}

	// Add the trace buffer info_area entry
	gunyah_hyp_addrspace_info_area_add_entry_result_t add_ret;
	addrspace_info_area_entry_type_t		  entry_type =
		addrspace_info_area_entry_type_default();

	addrspace_info_area_entry_type_set_owner(
		&entry_type, ADDRSPACE_INFO_AREA_ID_OWNER_ROOTVM);
	addrspace_info_area_entry_type_set_id(
		&entry_type, ADDRSPACE_INFO_AREA_ROOTVM_TRACE_INFO);

	struct addrspace_info_area_rootvm_trace_info_s trace_info = { 0U };

	trace_info.trace_ipa  = trace_ipa;
	trace_info.trace_size = env_data->trace_size;

	addrspace_info_area_interrupt_result_t interrupt_result =
		vm_creation_addrspace_info_area_interrupt(dbl_virq);
	assert(interrupt_result.e == OK);
	trace_info.trace_dbl_irq = interrupt_result.r;

	addrspace_info_area_entry_data_info_t data_info =
		addrspace_info_area_entry_data_info_default();
	addrspace_info_area_entry_data_info_set_size(&data_info,
						     sizeof(trace_info));
	addrspace_info_area_entry_data_info_set_alignment(&data_info,
							  sizeof(uint64_t));

	add_ret = gunyah_hyp_addrspace_info_area_add_entry(
		vmcfg->addrspace, entry_type, (user_ptr_t)&trace_info,
		data_info);
	if (add_ret.error != OK) {
		ret = add_ret.error;
		LOG_ERR(ret);
		goto out_unbind_virq;
	}

	ret = OK;
	goto out;

out_unbind_virq:
	err = gunyah_hyp_doorbell_unbind_virq(env_data->trace_dbl_capid);
	assert(err == OK);
out_unmap_irq:
	err = irq_manager_vm_virq_unmap(vmcfg->vm, db_irq.r, true);
	assert(err == OK);
out_free_irq:
	err = irq_manager_vm_free_global(vmcfg->vm, db_irq.r);
	assert(err == OK);
out_unmap_trace:
	err = vm_memory_unmap(vmcfg->vm, VM_MEMUSE_NORMAL,
			      env_data->trace_me_capid, trace_ipa);
	assert(err == OK);
out_free:
	err = vm_address_range_free(vmcfg->vm, VM_MEMUSE_NORMAL, trace_ipa,
				    env_data->trace_size);
	assert(err == OK);
out:
	return ret;
}

static error_t
hlos_vm_set_attributes(vm_t					  *hlos,
		       gunyah_hyp_partition_create_cspace_result_t cs,
		       cap_id_t root_vcpu_cap, cpu_index_t root_vcpu_idx)
{
	error_t ret;

	ret = gunyah_hyp_vcpu_set_affinity(root_vcpu_cap, root_vcpu_idx,
					   VCPU_AFFINITY_TYPE_CPU_INDEX);
	if (ret != OK) {
		goto out;
	}

	ret = gunyah_hyp_vcpu_set_priority(root_vcpu_cap, HLOS_VCPU_PRIORITY);
	if (ret != OK) {
		goto out;
	}
	hlos->priority = HLOS_VCPU_PRIORITY;

	ret = gunyah_hyp_cspace_attach_thread(cs.new_cap, root_vcpu_cap);
	if (ret != OK) {
		goto out;
	}

	ret = vm_memory_setup(hlos);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

out:
	if (ret != OK) {
		LOG_ERR(ret);
	}

	return ret;
}

static vcpu_option_flags_t
hlos_vm_get_vcpu_options(const rm_env_data_t *env_data)
{
	vcpu_option_flags_t vcpu_options = vcpu_option_flags_default();

	vcpu_option_flags_set_hlos_vm(&vcpu_options, true);
	vcpu_option_flags_set_critical(&vcpu_options, true);
	vcpu_option_flags_set_amu_counting_disabled(&vcpu_options, false);
	vcpu_option_flags_set_sve_allowed(&vcpu_options,
					  env_data->sve_supported);
	vcpu_option_flags_set_sme_allowed(&vcpu_options,
					  env_data->sme_supported);
	vcpu_option_flags_set_sdei_allowed(&vcpu_options,
					   env_data->sdei_supported);
#if defined(PLATFORM_MPAM_DIRECT) && PLATFORM_MPAM_DIRECT
	vcpu_option_flags_set_mpam_allowed(&vcpu_options, true);
#endif

	if (env_data->hlos_handles_ras) {
		// Set HLOS as the VM that handles RAS errors
		vcpu_option_flags_set_ras_error_handler(&vcpu_options, true);
		ras_handler_vm = VMID_HLOS;
	}
	// Pin vcpus as required for HLOS VM
	vcpu_option_flags_set_pinned(&vcpu_options, true);

	return vcpu_options;
}

static error_t
hlos_vm_set_cspace(gunyah_hyp_partition_create_cspace_result_t cs)
{
	error_t ret;

	ret = gunyah_hyp_cspace_configure(cs.new_cap, MAX_CAPS);
	if (ret != OK) {
		goto out;
	}

	ret = gunyah_hyp_object_activate(cs.new_cap);

out:
	if (ret != OK) {
		LOG_ERR(ret);
	}

	return ret;
}

error_t
hlos_vm_create(const rm_env_data_t *env_data)
{
	error_t ret;

	assert(env_data != NULL);
	assert(env_data->irq_env != NULL);

	vm_t *hlos = vm_lookup(VMID_HLOS);
	assert(hlos != NULL);

	cap_id_t rm_partition_cap = rm_get_rm_partition();
	cap_id_t rm_cspace_cap	  = rm_get_rm_cspace();

	cap_id_t *vcpu_caps = NULL;

	// Create new cspace
	gunyah_hyp_partition_create_cspace_result_t cs;
	cs = gunyah_hyp_partition_create_cspace(rm_partition_cap,
						rm_cspace_cap);
	if (cs.error != OK) {
		ret = cs.error;
		LOG_ERR(ret);
		goto out;
	}

	ret = hlos_vm_set_cspace(cs);
	if (ret != OK) {
		goto out;
	}

	// Create VM config
	vm_config_t *vmcfg =
		vm_config_alloc(hlos, cs.new_cap, rm_partition_cap);
	if (vmcfg == NULL) {
		ret = ERROR_NOMEM;
		LOG_ERR(ret);
		goto out;
	}

	// Create and configure root thread
	cap_id_t    root_vcpu_cap;
	cpu_index_t root_vcpu_idx;
	{
		gunyah_hyp_partition_create_thread_result_t vcpu;
		vcpu = gunyah_hyp_partition_create_thread(rm_partition_cap,
							  rm_cspace_cap);
		if (vcpu.error != OK) {
			ret = vcpu.error;
			LOG_ERR(ret);
			goto out;
		}
		root_vcpu_cap = vcpu.new_cap;
		root_vcpu_idx = (cpu_index_t)rm_get_platform_root_vcpu_index();
	}

	vcpu_option_flags_t vcpu_options = hlos_vm_get_vcpu_options(env_data);

	// Set trace allowed for HLOS
	vcpu_option_flags_set_trace_allowed(&vcpu_options, true);

	ret = gunyah_hyp_vcpu_configure(root_vcpu_cap, vcpu_options);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = hlos_vm_set_attributes(hlos, cs, root_vcpu_cap, root_vcpu_idx);
	if (ret != OK) {
		goto out;
	}

	// Setup IPA allocator for HLOS
	size_result_t ar_ret = vm_address_range_init(hlos);
	if (ar_ret.e != OK) {
		ret = ar_ret.e;
		LOG_ERR(ret);
		goto out;
	}

	// Create, configure, activate, and attach address space
	cap_id_t as_cap;
	ret = hlos_vm_create_address_space(
		vmcfg, rm_partition_cap, rm_cspace_cap, root_vcpu_cap, &as_cap);
	if (ret != OK) {
		goto out;
	}

	// Create the watchdog
	ret = hlos_vm_create_watchdog(vmcfg, root_vcpu_cap, rm_partition_cap,
				      rm_cspace_cap);
	if (ret != OK) {
		goto out;
	}

	// Create the PSCI group
	cap_id_t psci_cap;
	ret = hlos_vm_create_psci_group(vmcfg, root_vcpu_cap, rm_partition_cap,
					rm_cspace_cap, &psci_cap);
	if (ret != OK) {
		goto out;
	}

	count_t max_cores = rm_get_platform_max_cores();

	vcpu_caps = calloc(max_cores, sizeof(vcpu_caps[0]));
	if (vcpu_caps == NULL) {
		ret = ERROR_NOMEM;
		LOG_ERR(ret);
		goto out;
	}
	for (cpu_index_t i = 0; i < max_cores; i++) {
		vcpu_caps[i] = CSPACE_CAP_INVALID;
	}

	vcpu_caps[root_vcpu_idx] = root_vcpu_cap;

	ret = hlos_vm_create_secondary_vcpus(vmcfg, rm_partition_cap,
					     rm_cspace_cap, cs.new_cap, as_cap,
					     psci_cap, vcpu_caps, vcpu_options);
	if (ret != OK) {
		goto out;
	}

	const cap_id_t *its_caps = env_data->its_caps;
	count_t its_caps_count	 = (count_t)util_array_size(env_data->its_caps);

	ret = hlos_vm_create_vic(vmcfg, rm_partition_cap, rm_cspace_cap, as_cap,
				 root_vcpu_cap, vcpu_caps, its_caps,
				 its_caps_count);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = hlos_vm_activate_vcpus(vmcfg, vcpu_caps, max_cores,
				     root_vcpu_idx);
	if (ret != OK) {
		goto out;
	}

	// Create IRQ manager for HLOS VM
	ret = hlos_vm_create_irq(hlos, vmcfg);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	// Setup addrspace_info_area, make sure all components prepared for a VM
	// were created already before call this function
	ret = hlos_vm_setup_addrspace_info_area(env_data, vmcfg);
	if (ret != OK) {
		goto out;
	}

	ret = hlos_vm_do_create(env_data, hlos, vmcfg);
	if (ret != OK) {
		goto out;
	}

#if defined(CONFIG_DEVICE_MANAGER) && CONFIG_DEVICE_MANAGER
	ret = device_manager_init_vm(vmcfg->vm);
	if (ret != OK) {
		(void)printf(
			"Error: failed to initialize HLOS device management\n");
		// TODO: revert vdevices_setup
		goto out;
	}
#endif

	ret = OK;
out:
	if (ret != OK) {
		free(vcpu_caps);
	}

	return ret;
}

error_t
hlos_vm_start(void)
{
	vm_t *hlos = vm_lookup(VMID_HLOS);
	assert(hlos != NULL);
	vm_config_t *vmcfg = hlos->vm_config;
	assert(vmcfg != NULL);
	error_t	 err = ERROR_IDLE;
	uint64_t os_arg;

	// Activate root vcpu by setting entry point and context
	os_arg = platform_get_os_boot_arg(hlos);

	size_t cnt = vector_size(vmcfg->vcpus);
	for (index_t i = 0; i < cnt; i++) {
		vcpu_t *vcpu = vector_at(vcpu_t *, vmcfg->vcpus, i);
		assert(vcpu != NULL);

		if (vcpu->boot_vcpu) {
			err = gunyah_hyp_vcpu_poweron(
				vcpu->master_cap, rm_get_hlos_entry(), os_arg,
				vcpu_poweron_flags_default());
			if (err != OK) {
				LOG_ERR(err);
				break;
			}
		}
	}

	if (err == OK) {
		hlos->vm_state = VM_STATE_RUNNING;
	}

	return err;
}
