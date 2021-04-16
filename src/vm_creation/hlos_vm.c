// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <asm/arm_smccc.h>
#include <rm-rpc.h>

#include <guest_interface.h>
#include <irq_manager.h>
#include <memextent.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/vector.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_mgnt.h>
#include <vm_vcpu.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

#define HLOS_ADDRESS_SPACE_BITS 32

typedef struct {
	error_t	 error;
	cap_id_t caps[PLATFORM_MAX_CORES];
} hlos_vm_create_secondary_vcpus_result_t;

#pragma clang diagnostic pop

static hlos_vm_create_secondary_vcpus_result_t
hlos_vm_create_secondary_vcpus(vm_config_t *vmcfg, cap_id_t partition_cap,
			       cap_id_t cspace_cap, cap_id_t new_cspace_cap,
			       cap_id_t addrspace_cap, cap_id_t vg_cap)
{
	hlos_vm_create_secondary_vcpus_result_t ret = { OK, { 0 } };

	for (cpu_index_t i = 0; i < PLATFORM_MAX_CORES; i++) {
		if (i == ROOT_VCPU_INDEX) {
			continue;
		}

		gunyah_hyp_partition_create_thread_result_t vcpu;
		vcpu = gunyah_hyp_partition_create_thread(partition_cap,
							  cspace_cap);
		if (vcpu.error != OK) {
			ret.error = vcpu.error;
			goto out;
		}

		ret.caps[i] = vcpu.new_cap;

		vcpu_option_flags_t vcpu_options = vcpu_option_flags_default();
		vcpu_option_flags_set_hlos_vm(&vcpu_options, true);

		ret.error =
			gunyah_hyp_vcpu_configure(vcpu.new_cap, vcpu_options);
		if (ret.error != OK) {
			goto out;
		}

		ret.error = gunyah_hyp_vcpu_set_affinity(vcpu.new_cap, i);
		if (ret.error != OK) {
			goto out;
		}

		vm_config_add_vcpu(vmcfg, vcpu.new_cap, i, false);

		ret.error = gunyah_hyp_cspace_attach_thread(new_cspace_cap,
							    vcpu.new_cap);
		if (ret.error != OK) {
			goto out;
		}

		ret.error = gunyah_hyp_addrspace_attach_thread(addrspace_cap,
							       vcpu.new_cap);
		if (ret.error != OK) {
			goto out;
		}

		ret.error = gunyah_hyp_vpm_group_attach_vcpu(vg_cap,
							     vcpu.new_cap, i);
		if (ret.error != OK) {
			goto out;
		}
	}

out:
	return ret;
}

static cap_id_result_t
hlos_vm_create_vic(cap_id_t partition_cap, cap_id_t cspace_cap,
		   cap_id_t root_thread_cap,
		   cap_id_t vcpus_caps[PLATFORM_MAX_CORES])
{
	error_t		err;
	cap_id_result_t ret;

	gunyah_hyp_partition_create_vic_result_t v;
	v = gunyah_hyp_partition_create_vic(partition_cap, cspace_cap);
	if (v.error != OK) {
		ret = cap_id_result_error(v.error);
		goto out;
	}

	err = gunyah_hyp_vic_configure(v.new_cap, PLATFORM_MAX_CORES,
				       GIC_SPI_NUM);
	if (err != OK) {
		ret = cap_id_result_error(err);
		goto out;
	}

	err = gunyah_hyp_object_activate(v.new_cap);
	if (err != OK) {
		ret = cap_id_result_error(err);
		goto out;
	}

	err = gunyah_hyp_vic_attach_vcpu(v.new_cap, root_thread_cap,
					 ROOT_VCPU_INDEX);
	if (err != OK) {
		ret = cap_id_result_error(err);
		goto out;
	}

	// Attach all secondary VCPUs to the VIC
	for (cpu_index_t i = 0; i < PLATFORM_MAX_CORES; i++) {
		if (i == ROOT_VCPU_INDEX) {
			continue;
		}

		err = gunyah_hyp_vic_attach_vcpu(v.new_cap, vcpus_caps[i], i);
		if (err != OK) {
			ret = cap_id_result_error(err);
			goto out;
		}
	}

	ret = cap_id_result_ok(v.new_cap);

out:
	return ret;
}

error_t
hlos_vm_create(hwirq_cap_array_t hwirq_caps)
{
	error_t ret = OK;

	vm_t *hlos = vm_lookup(VMID_HLOS);
	assert(hlos != NULL);

	cap_id_t rm_partition_cap = rm_get_rm_partition();
	cap_id_t rm_cspace_cap	  = rm_get_rm_cspace();

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

	ret = gunyah_hyp_vcpu_configure(vcpu.new_cap, vcpu_options);
	if (ret != OK) {
		goto out;
	}

	ret = gunyah_hyp_vcpu_set_affinity(vcpu.new_cap, ROOT_VCPU_INDEX);
	if (ret != OK) {
		goto out;
	}

	vm_config_add_vcpu(vmcfg, vcpu.new_cap, ROOT_VCPU_INDEX, true);

	ret = gunyah_hyp_cspace_attach_thread(cs.new_cap, vcpu.new_cap);
	if (ret != OK) {
		goto out;
	}

	// Setup IPA allocator for HLOS in a safe range, above the device
	// memory for now
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

	ret = gunyah_hyp_vpm_group_attach_vcpu(vg.new_cap, vcpu.new_cap,
					       ROOT_VCPU_INDEX);
	if (ret != OK) {
		goto out;
	}

	hlos_vm_create_secondary_vcpus_result_t ret_vcpus;
	ret_vcpus = hlos_vm_create_secondary_vcpus(vmcfg, rm_partition_cap,
						   rm_cspace_cap, cs.new_cap,
						   as.new_cap, vg.new_cap);
	if (ret_vcpus.error != OK) {
		goto out;
	}

	cap_id_result_t vic_ret;
	vic_ret = hlos_vm_create_vic(rm_partition_cap, rm_cspace_cap,
				     vcpu.new_cap, ret_vcpus.caps);
	if (vic_ret.e != OK) {
		ret = vic_ret.e;
		goto out;
	}

	vmcfg->vic = vic_ret.r;

	// Activate secondary vcpus
	for (index_t i = 0; i < PLATFORM_MAX_CORES; i++) {
		if (i == ROOT_VCPU_INDEX) {
			continue;
		}

		ret = gunyah_hyp_object_activate(ret_vcpus.caps[i]);
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
		vic_ret.r, hwirq_caps.count, hwirq_caps.vic_hwirqs);
	assert(irq_manager != NULL);
	vm_config_set_irq_manager(vmcfg, irq_manager);

	ret = vm_config_hlos_vdevices_setup(vmcfg, vic_ret.r);
	if (ret != OK) {
		goto out;
	}

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

out:
	return ret;
}

error_t
hlos_vm_setup(void)
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
			    MEMEXTENT_MEMTYPE_DEVICE);
	if (ret != OK) {
		printf("hlos_vm: failed to map device memory\n");
		goto out;
	}

	ret = platform_uart_map(vm->vm_config->addrspace);
	if (ret != OK) {
		printf("hlos_vm: failed to map UART memory\n");
		goto out;
	}
out:
	return ret;
}

error_t
hlos_vm_start(void)
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

	// Activate root vcpu by setting entry point and specifying DT base
	// address
	error_t err = gunyah_hyp_vcpu_poweron(boot_vcpu, rm_get_hlos_entry(),
					      rm_get_hlos_dt_base());

	return err;
}

error_t
hlos_map_io_memory(cap_id_t me_cap, vmaddr_t ipa)
{
	error_t ret = OK;

	vm_t *vm = vm_lookup(VMID_HLOS);
	if (vm == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	ret = memextent_map(me_cap, vm->vm_config->addrspace, ipa,
			    PGTABLE_ACCESS_RW, MEMEXTENT_MEMTYPE_DEVICE);

out:
	return ret;
}

error_t
hlos_unmap_io_memory(cap_id_t me_cap, vmaddr_t addr)
{
	error_t ret = OK;

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
