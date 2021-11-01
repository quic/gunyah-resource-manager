// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm-rpc.h>

#include <guest_interface.h>
#include <irq_manager.h>
#include <memextent.h>
#include <memparcel_msg.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <utils/address_range_allocator.h>
#include <utils/vector.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_console.h>
#include <vm_creation.h>
#include <vm_mgnt.h>

#define SVM_ADDRESS_SPACE_BITS 32

RM_PADDED(typedef struct {
	error_t	 error;
	cap_id_t caps[PLATFORM_MAX_CORES];
} svm_create_vcpus_result_t)

static cap_id_result_t
svm_create_vic(vm_config_t *vmcfg)
{
	error_t		err;
	cap_id_result_t ret;

	gunyah_hyp_partition_create_vic_result_t v;
	v = gunyah_hyp_partition_create_vic(vmcfg->partition,
					    rm_get_rm_cspace());
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

	vmcfg->vic = v.new_cap;
	ret	   = cap_id_result_ok(v.new_cap);

out:
	return ret;
}

error_t
svm_create(vmid_t vmid)
{
	error_t err;

	vm_t *svm = vm_lookup(vmid);
	if (svm == NULL) {
		printf("Error: no VM for vmid %d\n", vmid);
		err = ERROR_ARGUMENT_INVALID;
		goto out_no_vm;
	}
	if (svm->vm_state != VM_STATE_INIT) {
		printf("Error: vm_state %d != %d\n", svm->vm_state,
		       VM_STATE_INIT);
		err = ERROR_ARGUMENT_INVALID;
		goto out_no_vm;
	}

	cap_id_t rm_partition_cap = rm_get_rm_partition();
	cap_id_t rm_cspace_cap	  = rm_get_rm_cspace();

	// Create new cspace
	gunyah_hyp_partition_create_cspace_result_t cs;
	cs = gunyah_hyp_partition_create_cspace(rm_partition_cap,
						rm_cspace_cap);
	if (cs.error != OK) {
		err = cs.error;
		goto out;
	}

	err = gunyah_hyp_cspace_configure(cs.new_cap, MAX_CAPS);
	if (err != OK) {
		goto out;
	}

	err = gunyah_hyp_object_activate(cs.new_cap);
	if (err != OK) {
		goto out;
	}

	// Create VM config
	vm_config_t *vmcfg = vm_config_alloc(svm, cs.new_cap, rm_partition_cap);
	if (vmcfg == NULL) {
		goto out;
	}

	// Create the VIC
	cap_id_result_t vic_ret = svm_create_vic(vmcfg);
	if (vic_ret.e != OK) {
		err = vic_ret.e;
		goto out;
	}

	// Setup IPA allocator for SVM in a safe range, above the device
	// memory for now
	svm->as_allocator = address_range_allocator_init(
		0x40000000U, 1UL << SVM_ADDRESS_SPACE_BITS);
	if (svm->as_allocator == NULL) {
		err = ERROR_NOMEM;
		goto out;
	}

	// Create, configure, activate, and attach address space
	gunyah_hyp_partition_create_addrspace_result_t as;
	as = gunyah_hyp_partition_create_addrspace(rm_partition_cap,
						   rm_cspace_cap);
	if (as.error != OK) {
		err = as.error;
		goto out;
	}

	err = gunyah_hyp_addrspace_configure(as.new_cap, vmid);
	if (err != OK) {
		goto out;
	}

	err = gunyah_hyp_object_activate(as.new_cap);
	if (err != OK) {
		goto out;
	}
	vmcfg->addrspace = as.new_cap;

out:
	// FIXME: if err != OK, cleanup resource allocations above!
	svm->vm_state = (err == OK) ? VM_STATE_READY : VM_STATE_INIT_FAILED;
out_no_vm:
	return err;
}

svm_setup_ret_t
svm_setup(vmid_t vmid)
{
	(void)vmid;
	return (svm_setup_ret_t){ .err = ERROR_UNIMPLEMENTED };
}

error_t
svm_poweron(vmid_t vmid)
{
	error_t ret = OK;
	vm_t *	svm = vm_lookup(vmid);
	if (svm == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	ret = gunyah_hyp_vcpu_poweron(svm->primary_vcpu_cap,
				      svm->ipa_base + svm->entry_offset,
				      svm->ipa_base + svm->dtb_region_offset);
out:
	return ret;
}
