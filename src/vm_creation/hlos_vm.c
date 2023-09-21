// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
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

#include <event.h>
#include <guest_interface.h>
#include <guest_rights.h>
#include <irq_manager.h>
#include <log.h>
#include <memextent.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_passthrough_config.h>
#include <vm_vcpu.h>

#define HLOS_VCPU_PRIORITY  ROOTVM_PRIORITY
#define HLOS_VCPU_TIMESLICE (SCHEDULER_DEFAULT_TIMESLICE)

static error_t
hlos_vm_create_secondary_vcpus(const vm_config_t *vmcfg, cap_id_t partition_cap,
			       cap_id_t cspace_cap, cap_id_t new_cspace_cap,
			       cap_id_t addrspace_cap, cap_id_t vg_cap,
			       cap_id_t		  *vcpu_caps,
			       vcpu_option_flags_t vcpu_options)
{
	error_t ret = OK;

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

		ret = gunyah_hyp_vcpu_set_affinity(vcpu.new_cap, i);
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

		ret = gunyah_hyp_vcpu_set_timeslice(vcpu.new_cap,
						    HLOS_VCPU_TIMESLICE);
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

#if defined(CAP_RIGHTS_WATCHDOG_ALL)
		if (vmcfg->watchdog != CSPACE_CAP_INVALID) {
			ret = gunyah_hyp_watchdog_attach_vcpu(vmcfg->watchdog,
							      vcpu.new_cap);
			if (ret != OK) {
				LOG_ERR(ret);
				goto out;
			}
		}
#else
		(void)vmcfg;
#endif

		ret = gunyah_hyp_vpm_group_attach_vcpu(vg_cap, vcpu.new_cap, i);
		if (ret != OK) {
			LOG_ERR(ret);
			goto out;
		}
	}

out:
	if (ret != OK) {
		(void)printf("Error creating vCPU %d\n", i);
	}
	return ret;
}

static error_t
hlos_vm_get_rm_vcpu_cap(vm_config_t *hlos_cfg)
{
	error_t ret = OK;

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
		rmcfg->cspace, vcpu->master_cap, hlos_cfg->cspace, rights);
	if (copy_ret.error != OK) {
		(void)printf("Failed: copy vcpu cap from rm cspace\n");
		ret = copy_ret.error;
		goto out;
	}

	vcpu->owner_cap = copy_ret.new_cap;

out:
	return ret;
}

static cap_id_result_t
hlos_vm_create_vic(cap_id_t partition_cap, cap_id_t cspace_cap,
		   cap_id_t addrspace_cap, cap_id_t root_thread_cap,
		   cap_id_t *vcpus_caps, const cap_id_t *msi_src_caps,
		   count_t msi_src_count)
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

	vic_option_flags_t vic_options = vic_option_flags_default();
	// Try configuring the VIC with the maximum number of IRQ numbers
	// reserved for MSIs; if that fails, retry with no IRQs reserved for
	// MSIs. This is a stand-in for proper probing of MSI support. Note that
	// this is orthogonal to whether any of the msi_src_caps are valid.
	//
	// Currently, we hard-code the maximum numbers of both regular IRQ
	// sources and MSI reserved IRQs to those defined by the virtual GIC
	// (988 and 8192 respectively).
	err = gunyah_hyp_vic_configure(v.new_cap, rm_get_platform_max_cores(),
				       GIC_SPI_NUM, vic_options, GIC_LPI_NUM);
	if (err == ERROR_ARGUMENT_INVALID) {
		err = gunyah_hyp_vic_configure(v.new_cap,
					       rm_get_platform_max_cores(),
					       GIC_SPI_NUM, vic_options, 0);
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

	// Bind all MSI sources (if any) to the VIC.
	//
	// In future this might need to be subject to finer-grained management.
	for (count_t i = 0U; i < msi_src_count; i++) {
		if (msi_src_caps[i] == CSPACE_CAP_INVALID) {
			continue;
		}

		// If the MSI source is an ITS, it will need an attachment
		// to the VM's address space before it can be bound to the VIC.
		err = gunyah_hyp_addrspace_attach_vdma(addrspace_cap,
						       msi_src_caps[i], 0U);
		if ((err != OK) && (err != ERROR_CSPACE_WRONG_OBJECT_TYPE)) {
			ret = cap_id_result_error(err);
			(void)printf(
				"HLOS: Failed to attach VDMA for MSI %d, error %" PRId32
				"\n",
				i, (int32_t)err);
			goto out;
		}

		err = gunyah_hyp_vic_bind_msi_source(v.new_cap,
						     msi_src_caps[i]);
		if (err != OK) {
			ret = cap_id_result_error(err);
			(void)printf(
				"HLOS: Failed to bind MSI %d, error %" PRId32
				"\n",
				i, (int32_t)err);
			goto out;
		}
	}

	ret = cap_id_result_ok(v.new_cap);

out:
	if ((ret.e != OK) && (v.error == OK)) {
		err = gunyah_hyp_cspace_delete_cap_from(cspace_cap, v.new_cap);
		assert(err == OK);
	}

	return ret;
}

error_t
hlos_vm_create(const rm_env_data_t *env_data)
{
	error_t ret = OK;

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

	ret = gunyah_hyp_cspace_configure(cs.new_cap, MAX_CAPS);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = gunyah_hyp_object_activate(cs.new_cap);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	// Create VM config
	vm_config_t *vmcfg =
		vm_config_alloc(hlos, cs.new_cap, rm_partition_cap);
	if (vmcfg == NULL) {
		ret = RM_ERROR_NOMEM;
		LOG_ERR(ret);
		goto out;
	}

	// Create and configure root thread

	gunyah_hyp_partition_create_thread_result_t vcpu;
	vcpu = gunyah_hyp_partition_create_thread(rm_partition_cap,
						  rm_cspace_cap);
	if (vcpu.error != OK) {
		ret = vcpu.error;
		LOG_ERR(ret);
		goto out;
	}

	vcpu_option_flags_t vcpu_options = vcpu_option_flags_default();

	vcpu_option_flags_set_hlos_vm(&vcpu_options, true);
	vcpu_option_flags_set_critical(&vcpu_options, true);
	vcpu_option_flags_set_amu_counting_disabled(&vcpu_options, false);
	vcpu_option_flags_set_sve_allowed(&vcpu_options,
					  env_data->sve_supported);
#if defined(PLATFORM_MPAM_DIRECT) && PLATFORM_MPAM_DIRECT
	vcpu_option_flags_set_mpam_allowed(&vcpu_options, true);
#endif

	if (env_data->hlos_handles_ras) {
		(void)printf("HLOS is RAS handler\n");
		// Set HLOS as the VM that handles RAS errors
		vcpu_option_flags_set_ras_error_handler(&vcpu_options, true);
		ras_handler_vm = VMID_HLOS;
	}
	// Pin vcpus as required for HLOS VM
	vcpu_option_flags_set_pinned(&vcpu_options, true);

	ret = gunyah_hyp_vcpu_configure(vcpu.new_cap, vcpu_options);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	cpu_index_t root_vcpu = (cpu_index_t)rm_get_platform_root_vcpu_index();
	ret = gunyah_hyp_vcpu_set_affinity(vcpu.new_cap, root_vcpu);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = gunyah_hyp_vcpu_set_priority(vcpu.new_cap, HLOS_VCPU_PRIORITY);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}
	hlos->priority = HLOS_VCPU_PRIORITY;

	ret = gunyah_hyp_vcpu_set_timeslice(vcpu.new_cap, HLOS_VCPU_TIMESLICE);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = gunyah_hyp_cspace_attach_thread(cs.new_cap, vcpu.new_cap);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = vm_memory_setup(hlos);
	if (ret != OK) {
		LOG_ERR(ret);
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
	gunyah_hyp_partition_create_addrspace_result_t as;
	as = gunyah_hyp_partition_create_addrspace(rm_partition_cap,
						   rm_cspace_cap);
	if (as.error != OK) {
		ret = as.error;
		LOG_ERR(ret);
		goto out;
	}

	ret = gunyah_hyp_addrspace_configure(as.new_cap, VMID_HLOS);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = vm_creation_config_vm_info_area(vmcfg);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}
	ret = gunyah_hyp_addrspace_configure_info_area(
		as.new_cap, vmcfg->vm_info_area_me_cap,
		vmcfg->vm->vm_info_area_ipa);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = gunyah_hyp_object_activate(as.new_cap);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}
	vmcfg->addrspace = as.new_cap;

	ret = vm_creation_map_vm_info_area(vmcfg);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = gunyah_hyp_addrspace_attach_thread(as.new_cap, vcpu.new_cap);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = platform_vm_create(hlos, true);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

#if defined(CAP_RIGHTS_WATCHDOG_ALL)
	// Create the watchdog
	vmcfg->watchdog_enabled = rm_get_watchdog_supported();
	if (vmcfg->watchdog_enabled) {
		gunyah_hyp_partition_create_watchdog_result_t wdt;
		wdt = gunyah_hyp_partition_create_watchdog(rm_partition_cap,
							   rm_cspace_cap);
		if (wdt.error != OK) {
			ret = wdt.error;
			LOG_ERR(ret);
			goto out;
		}

		watchdog_option_flags_t watchdog_options =
			watchdog_option_flags_default();

		watchdog_option_flags_set_critical_bite(&watchdog_options,
							true);

		ret = gunyah_hyp_watchdog_configure(wdt.new_cap,
						    watchdog_options);
		if (ret != OK) {
			LOG_ERR(ret);
			goto out;
		}

		ret = gunyah_hyp_object_activate(wdt.new_cap);
		if (ret != OK) {
			LOG_ERR(ret);
			goto out;
		}

		vmcfg->watchdog = wdt.new_cap;

		// Attach the watchdog to the root vCPU
		ret = gunyah_hyp_watchdog_attach_vcpu(wdt.new_cap,
						      vcpu.new_cap);
		if (ret != OK) {
			LOG_ERR(ret);
			goto out;
		}
	} else {
		vmcfg->watchdog = CSPACE_CAP_INVALID;
	}
#endif

	// Create the PSCI group

	gunyah_hyp_partition_create_vpm_group_result_t vg;
	vg = gunyah_hyp_partition_create_vpm_group(rm_partition_cap,
						   rm_cspace_cap);
	if (vg.error != OK) {
		ret = vg.error;
		LOG_ERR(ret);
		goto out;
	}

	ret = gunyah_hyp_object_activate(vg.new_cap);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	vmcfg->vpm_group = vg.new_cap;

	// Attach the root vcpu to the vpm group

	ret = gunyah_hyp_vpm_group_attach_vcpu(
		vg.new_cap, vcpu.new_cap, rm_get_platform_root_vcpu_index());
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	count_t max_cores = rm_get_platform_max_cores();

	vcpu_caps = calloc(max_cores, sizeof(vcpu_caps[0]));
	if (vcpu_caps == NULL) {
		ret = ERROR_NOMEM;
		LOG_ERR(ret);
		goto out;
	}

	ret = hlos_vm_create_secondary_vcpus(vmcfg, rm_partition_cap,
					     rm_cspace_cap, cs.new_cap,
					     as.new_cap, vg.new_cap, vcpu_caps,
					     vcpu_options);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	const cap_id_t *vic_msi_sources = env_data->irq_env->vic_msi_source;
	count_t		vic_msi_source_count =
		util_array_size(env_data->irq_env->vic_msi_source);

	cap_id_result_t vic_ret;
	vic_ret = hlos_vm_create_vic(rm_partition_cap, rm_cspace_cap,
				     as.new_cap, vcpu.new_cap, vcpu_caps,
				     vic_msi_sources, vic_msi_source_count);
	if (vic_ret.e != OK) {
		ret = vic_ret.e;
		LOG_ERR(ret);
		goto out;
	}

	vmcfg->vic = vic_ret.r;

	// Activate secondary vcpus
	for (cpu_index_t i = 0; i < max_cores; i++) {
		if ((i == rm_get_platform_root_vcpu_index()) ||
		    (!rm_is_core_usable(i))) {
			continue;
		}

		ret = gunyah_hyp_object_activate(vcpu_caps[i]);
		if (ret != OK) {
			(void)printf(
				"HLOS: Failed to activate vCPU %d, error %" PRId32
				"\n",
				i, (int32_t)ret);
			goto out;
		}

		ret = vm_config_add_vcpu(vmcfg, vcpu_caps[i], i, false, NULL);
		if (ret != OK) {
			goto out;
		}
	}

	// Activate root thread
	ret = gunyah_hyp_object_activate(vcpu.new_cap);
	if (ret != OK) {
		LOG_ERR(ret);
		goto out;
	}

	ret = vm_config_add_vcpu(vmcfg, vcpu.new_cap, root_vcpu, true, NULL);
	if (ret != OK) {
		goto out;
	}

	// Create IRQ manager for HLOS VM
	ret = irq_manager_vm_init(hlos, vic_ret.r, PLATFORM_IRQ_MAX);
	if (ret != OK) {
		goto out;
	}

	ret = irq_manager_vm_hwirq_map_all_direct(hlos);
	if (ret != OK) {
		goto out;
	}

	vm_config_hlos_vdevices_setup(vmcfg, vic_ret.r);

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
	free(vcpu_caps);

	if (ret != OK) {
		LOG_ERR(ret);
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
