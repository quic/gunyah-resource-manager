// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <rm-rpc.h>

#include <resource-manager.h>

#include <event.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <memextent.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <rm-rpc-fifo.h>
#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/vector.h>
#include <vendor_hyp_call.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_mgnt.h>
#include <vm_vcpu.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

#define HLOS_ADDRESS_SPACE_BITS 32

#define HLOS_VCPU_PRIORITY  (SCHEDULER_MIN_PRIORITY + 2U)
#define HLOS_VCPU_TIMESLICE (SCHEDULER_DEFAULT_TIMESLICE)

#pragma clang diagnostic pop

static error_t
hlos_vm_create_secondary_vcpus(vm_config_t *vmcfg, cap_id_t partition_cap,
			       cap_id_t cspace_cap, cap_id_t new_cspace_cap,
			       cap_id_t addrspace_cap, cap_id_t vg_cap,
			       cap_id_t		*vcpu_caps,
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
			goto out;
		}

		vcpu_caps[i] = vcpu.new_cap;

		ret = gunyah_hyp_vcpu_configure(vcpu.new_cap, vcpu_options);
		if (ret != OK) {
			goto out;
		}

		ret = gunyah_hyp_vcpu_set_affinity(vcpu.new_cap, i);
		if (ret != OK) {
			goto out;
		}

		ret = gunyah_hyp_vcpu_set_priority(vcpu.new_cap,
						   HLOS_VCPU_PRIORITY);
		if (ret != OK) {
			goto out;
		}

		ret = gunyah_hyp_vcpu_set_timeslice(vcpu.new_cap,
						    HLOS_VCPU_TIMESLICE);
		if (ret != OK) {
			goto out;
		}

		ret = vm_config_add_vcpu(vmcfg, vcpu.new_cap, i, false, NULL);
		if (ret != OK) {
			goto out;
		}

		ret = gunyah_hyp_cspace_attach_thread(new_cspace_cap,
						      vcpu.new_cap);
		if (ret != OK) {
			goto out;
		}

		ret = gunyah_hyp_addrspace_attach_thread(addrspace_cap,
							 vcpu.new_cap);
		if (ret != OK) {
			goto out;
		}

		if (vmcfg->watchdog != CSPACE_CAP_INVALID) {
		}

		ret = gunyah_hyp_vpm_group_attach_vcpu(vg_cap, vcpu.new_cap, i);
		if (ret != OK) {
			goto out;
		}
	}

out:
	return ret;
}

static cap_id_result_t
hlos_vm_create_vic(cap_id_t partition_cap, cap_id_t cspace_cap,
		   cap_id_t addrspace_cap, cap_id_t root_thread_cap,
		   cap_id_t *vcpus_caps, cap_id_t *msi_src_caps,
		   count_t msi_src_count)
{
	error_t		err;
	cap_id_result_t ret;

	gunyah_hyp_partition_create_vic_result_t v;
	v = gunyah_hyp_partition_create_vic(partition_cap, cspace_cap);
	if (v.error != OK) {
		ret = cap_id_result_error(v.error);
		goto out;
	}

	// Try configuring the VIC with the maximum number of IRQ numbers
	// reserved for MSIs; if that fails, retry with no IRQs reserved for
	// MSIs. This is a stand-in for proper probing of MSI support. Note that
	// this is orthogonal to whether any of the msi_src_caps are valid.
	//
	// Currently, we hard-code the maximum numbers of both regular IRQ
	// sources and MSI reserved IRQs to those defined by the virtual GIC
	// (988 and 8192 respectively).
	err = gunyah_hyp_vic_configure(v.new_cap, rm_get_platform_max_cores(),
				       GIC_SPI_NUM, vic_option_flags_default(),
				       GIC_LPI_NUM);
	if (err == ERROR_ARGUMENT_INVALID) {
		err = gunyah_hyp_vic_configure(v.new_cap,
					       rm_get_platform_max_cores(),
					       GIC_SPI_NUM,
					       vic_option_flags_default(), 0);
	}
	if (err != OK) {
		ret = cap_id_result_error(err);
		goto out;
	}

	err = gunyah_hyp_object_activate(v.new_cap);
	if (err != OK) {
		ret = cap_id_result_error(err);
		goto out;
	}

	// Attach primary VCPU to the VIC
	err = gunyah_hyp_vic_attach_vcpu(v.new_cap, root_thread_cap,
					 rm_get_platform_root_vcpu_index());
	if (err != OK) {
		ret = cap_id_result_error(err);
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
			goto out;
		}

		err = gunyah_hyp_vic_bind_msi_source(v.new_cap,
						     msi_src_caps[i]);
		if (err != OK) {
			ret = cap_id_result_error(err);
			goto out;
		}
	}

	ret = cap_id_result_ok(v.new_cap);

out:
	if ((ret.e != OK) && (v.error == OK)) {
		gunyah_hyp_cspace_delete_cap_from(cspace_cap, v.new_cap);
	}

	return ret;
}

error_t
hlos_vm_create(hwirq_caps_t hwirq_caps, boot_env_data_t *env_data)
{
	(void)env_data;
	error_t ret = OK;

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
		goto out;
	}

	ret = gunyah_hyp_cspace_configure(cs.new_cap, MAX_CAPS);
	if (ret != OK) {
		goto out;
	}

	ret = gunyah_hyp_object_activate(cs.new_cap);
	if (ret != OK) {
		goto out;
	}

	// Create VM config
	vm_config_t *vmcfg =
		vm_config_alloc(hlos, cs.new_cap, rm_partition_cap);
	if (vmcfg == NULL) {
		goto out;
	}

	// Create and configure root thread

	gunyah_hyp_partition_create_thread_result_t vcpu;
	vcpu = gunyah_hyp_partition_create_thread(rm_partition_cap,
						  rm_cspace_cap);
	if (vcpu.error != OK) {
		ret = vcpu.error;
		goto out;
	}

	vcpu_option_flags_t vcpu_options = vcpu_option_flags_default();

	vcpu_option_flags_set_hlos_vm(&vcpu_options, true);

	// Pin vcpus as required for HLOS VM
	vcpu_option_flags_set_pinned(&vcpu_options, true);

	ret = gunyah_hyp_vcpu_configure(vcpu.new_cap, vcpu_options);
	if (ret != OK) {
		goto out;
	}

	cpu_index_t root_vcpu = (cpu_index_t)rm_get_platform_root_vcpu_index();
	ret = gunyah_hyp_vcpu_set_affinity(vcpu.new_cap, root_vcpu);
	if (ret != OK) {
		goto out;
	}

	ret = gunyah_hyp_vcpu_set_priority(vcpu.new_cap, HLOS_VCPU_PRIORITY);
	if (ret != OK) {
		goto out;
	}
	hlos->priority = HLOS_VCPU_PRIORITY;

	ret = gunyah_hyp_vcpu_set_timeslice(vcpu.new_cap, HLOS_VCPU_TIMESLICE);
	if (ret != OK) {
		goto out;
	}

	ret = vm_config_add_vcpu(vmcfg, vcpu.new_cap, root_vcpu, true, NULL);
	if (ret != OK) {
		goto out;
	}

	ret = gunyah_hyp_cspace_attach_thread(cs.new_cap, vcpu.new_cap);
	if (ret != OK) {
		goto out;
	}

	vmaddr_t ipa_range_base = 0U;
	size_t	 ipa_range_size = 0U;

	ret = platform_hlos_get_free_addr_range(&ipa_range_base,
						&ipa_range_size);
	if (ret != OK) {
		goto out;
	}

	// Setup IPA allocator for HLOS - in a safe range
	// above the device memory for now
	hlos->as_allocator = address_range_allocator_init(
		0x40000000U, 1UL << HLOS_ADDRESS_SPACE_BITS);

	if (hlos->as_allocator == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	// Create, configure, activate, and attach address space
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

	ret = gunyah_hyp_object_activate(as.new_cap);
	if (ret != OK) {
		goto out;
	}

	vmcfg->addrspace = as.new_cap;

	ret = gunyah_hyp_addrspace_attach_thread(as.new_cap, vcpu.new_cap);
	if (ret != OK) {
		goto out;
	}

	ret = platform_vm_create(hlos, true);
	if (ret != OK) {
		goto out;
	}

	// Create the PSCI group

	gunyah_hyp_partition_create_vpm_group_result_t vg;
	vg = gunyah_hyp_partition_create_vpm_group(rm_partition_cap,
						   rm_cspace_cap);
	if (vg.error != OK) {
		ret = vg.error;
		goto out;
	}

	ret = gunyah_hyp_object_activate(vg.new_cap);
	if (ret != OK) {
		goto out;
	}

	vmcfg->vpm_group = vg.new_cap;

	// Attach the root vcpu to the vpm group

	ret = gunyah_hyp_vpm_group_attach_vcpu(
		vg.new_cap, vcpu.new_cap, rm_get_platform_root_vcpu_index());
	if (ret != OK) {
		goto out;
	}

	count_t max_cores = rm_get_platform_max_cores();

	vcpu_caps = calloc(max_cores, sizeof(vcpu_caps[0]));
	if (vcpu_caps == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	ret = hlos_vm_create_secondary_vcpus(vmcfg, rm_partition_cap,
					     rm_cspace_cap, cs.new_cap,
					     as.new_cap, vg.new_cap, vcpu_caps,
					     vcpu_options);
	if (ret != OK) {
		goto out;
	}

	cap_id_result_t vic_ret;
	vic_ret = hlos_vm_create_vic(rm_partition_cap, rm_cspace_cap,
				     as.new_cap, vcpu.new_cap, vcpu_caps,
				     hwirq_caps.vic_msi_sources,
				     hwirq_caps.vic_msi_source_count);
	if (vic_ret.e != OK) {
		ret = vic_ret.e;
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
			goto out;
		}
	}

	// Activate root thread
	ret = gunyah_hyp_object_activate(vcpu.new_cap);
	if (ret != OK) {
		goto out;
	}

	// Create IRQ manager for HLOS VM
	vm_irq_manager_t *irq_manager = irq_manager_create(
		vic_ret.r, hwirq_caps.vic_hwirq_count, hwirq_caps.vic_hwirqs);
	assert(irq_manager != NULL);
	vm_config_set_irq_manager(vmcfg, irq_manager);

	vm_config_hlos_vdevices_setup(vmcfg, vic_ret.r);

	// Add RM RPC link
	rm_error_t rm_err = rm_rpc_server_add_link(VMID_HLOS);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
		goto out;
	}

	// Create RM RPC FIFO
	rm_err = rm_rpc_fifo_create(VMID_HLOS);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
		goto out;
	}

	// Platform specific HLOS setup
	ret = platform_hlos_create(as.new_cap);

out:
	free(vcpu_caps);

	return ret;
}

error_t
hlos_vm_setup(boot_env_data_t *env_data)
{
	error_t ret = OK;

	vmid_t vmid = VMID_HLOS;

	vm_t *vm = vm_lookup(vmid);
	if (vm == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	// Create and map a memparcel for the VM's DRAM range.
	acl_entry_t acl[1U] = { { .vmid = vmid, .rights = MEM_RIGHTS_RWX } };
	sgl_entry_t sgl_construct[1U] = { { .ipa  = vm->mem_base,
					    .size = vm->mem_size } };

	// We make RM owner of the memparcel
	memparcel_construct_ret_t mp_r = memparcel_construct(
		VMID_RM, 1U, 1U, 0U, acl, sgl_construct, NULL, 0U, true,
		MEM_TYPE_NORMAL, TRANS_TYPE_LEND, true, false);
	if (mp_r.err != RM_OK) {
		ret = ERROR_DENIED;
		goto out;
	}

	vm->mem_mp_handle = mp_r.handle;

	sgl_entry_t sgl_accept[1U] = { { .ipa  = vm->ipa_base,
					 .size = vm->mem_size } };

	memparcel_accept_sgl_resp_t *sgl_resp;
	size_t			     sgl_resp_size;

	rm_error_t rm_err = memparcel_do_accept(
		vmid, 1U, 1U, 0U, acl, sgl_accept, NULL, 0U, mp_r.handle, 0U,
		MEM_TYPE_NORMAL, TRANS_TYPE_LEND, MEM_ACCEPT_FLAG_DONE,
		&sgl_resp, &sgl_resp_size);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
		goto out;
	}

	// Create HLOS overlay DT and apply it to input DT
	ret = vm_creation_process_resource(vmid);
	if (ret != OK) {
		printf("hlos_vm: failed to apply overlay DT\n");
		goto out;
	}

	// Map all device memory except the regions already derived by the
	// hypervisor
	ret = memextent_map(rm_get_device_me(), vm->vm_config->addrspace,
			    rm_get_device_me_base(), PGTABLE_ACCESS_RW,
			    PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
	if (ret != OK) {
		printf("hlos_vm: failed to map device memory\n");
		goto out;
	}

	ret = memextent_map(rm_get_uart_me(), vm->vm_config->addrspace,
			    env_data->uart_address, PGTABLE_ACCESS_RW,
			    PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);

	// ret = platform_uart_map(vm->vm_config->addrspace);
	if (ret != OK) {
		printf("hlos_vm: failed to map UART memory\n");
		goto out;
	}
out:
	return ret;
}

error_t
hlos_vm_start()
{
	vm_t *hlos = vm_lookup(VMID_HLOS);
	assert(hlos != NULL);
	vm_config_t *vmcfg = hlos->vm_config;
	assert(vmcfg != NULL);

	cap_id_t boot_vcpu = CSPACE_CAP_INVALID;

	size_t cnt = vector_size(vmcfg->vcpus);
	for (index_t i = 0; i < cnt; i++) {
		vcpu_t *vcpu = vector_at_ptr(vcpu_t, vmcfg->vcpus, i);

		if (vcpu->boot_vcpu) {
			boot_vcpu = vcpu->master_cap;
			break;
		}
	}
	assert(boot_vcpu != CSPACE_CAP_INVALID);

	// Activate root vcpu by setting entry point and context
	// the context should be the DT base address
	error_t err = gunyah_hyp_vcpu_poweron(boot_vcpu, rm_get_hlos_entry(),
					      rm_get_hlos_dt_base());

	return err;
}

error_t
hlos_map_memory(paddr_t phys, vmaddr_t ipa, size_t size,
		pgtable_access_t access, pgtable_vm_memtype_t memtype)
{
	error_t ret;

	(void)phys;
	(void)ipa;
	(void)size;
	(void)access;
	(void)memtype;

	ret = ERROR_UNIMPLEMENTED;
	return ret;
}

error_t
hlos_map_io_memory(paddr_t phys, vmaddr_t ipa, size_t size, cap_id_t me_cap)
{
	error_t ret;

	(void)phys;
	(void)size;

	vm_t *vm = vm_lookup(VMID_HLOS);
	if (vm == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	ret = memextent_map(me_cap, vm->vm_config->addrspace, ipa,
			    PGTABLE_ACCESS_RW, PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
out:

	return ret;
}

error_t
hlos_unmap_io_memory(vmaddr_t addr, size_t size, bool check_mapped,
		     cap_id_t me_cap)
{
	error_t ret;

	(void)size;
	(void)check_mapped;

	vm_t *vm = vm_lookup(VMID_HLOS);
	if (vm == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	ret = gunyah_hyp_addrspace_unmap(vm->vm_config->addrspace, me_cap,
					 addr);

out:

	return ret;
}

hlos_memory_result_t
hlos_memory_is_mapped(vmaddr_t ipa, size_t size, bool io_memory)
{
	hlos_memory_result_t ret;

	(void)ipa;
	(void)size;
	(void)io_memory;

	ret.err = ERROR_UNIMPLEMENTED;

	return ret;
}
