// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>

#include <event.h>
#include <memparcel_msg.h>
#include <panic.h>
#include <platform.h>
#include <resource-manager.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_creation.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_passthrough_config.h>

// This API validates whether the VMIDs configured in the passthrough
// configuration for which the device assignments are to be done are valid
// secondary VMIDs or not. Returns true if the VMID configured is a valid
// secondary VMID, false otherwise.
static bool
vm_passthrough_config_validate_vmids(const rm_env_data_t *env_data)
{
	uint64_t static_secondary_vmids_supported =
		platform_get_secondary_vmids();
	bool res = true;

	for (index_t i = 0; i < env_data->device_assignments->num_devices;
	     i++) {
		uint32_t vmid = env_data->device_assignments->devices[i].vmid;
		if ((util_bit(vmid) & static_secondary_vmids_supported) == 0U) {
			(void)printf(
				"vm_passthrough_config: Unsupported VMID:%u\n",
				vmid);
			res = false;
			break;
		}
	}
	return res;
}

// Right now just has a function call to validate VMs. Can be used for any other
// validations of the passthrough configuration.
void
vm_passthrough_config_validate(const rm_env_data_t *env_data)
{
	if (!vm_passthrough_config_validate_vmids(env_data)) {
		panic("vm_passthrough_config: Invalid vmid configured");
	}
}

void
vm_passthrough_config_deinit(const rm_env_data_t *env_data)
{
	for (index_t i = 0; i < env_data->device_assignments->num_devices;
	     i++) {
		free(env_data->device_assignments->devices[i].irqs);
		env_data->device_assignments->devices[i].irqs = NULL;
	}
}

// Loops through all the IO address ranges from the passthrough configuration
// and does a partial unmap from the overall device memextent created for the
// primary VM. The unmap operation is done within vm_memory_batch_start() and
// vm_memory_batch_end() to avoid rcu_sync delays.
error_t
vm_passthrough_config_unmap_ioranges(const rm_env_data_t *env_data)
{
	error_t err = OK;

	vm_t *hlos_vm = vm_lookup(VMID_HLOS);
	assert(hlos_vm != NULL);

	vm_memory_batch_start();
	for (index_t i = 0; i < env_data->device_assignments->num_devices;
	     i++) {
		for (index_t j = 0;
		     j <
		     env_data->device_assignments->devices[i].num_mmio_ranges;
		     j++) {
			root_env_mmio_range_descriptor_t io_range =
				env_data->device_assignments->devices[i]
					.mmio_ranges[j];
			// For IO range the IPA will be same as the physical
			// address
			vmaddr_t ipa = io_range.address;
			size_t	 size =
				(size_t)PAGE_SIZE *
				root_env_mmio_range_properties_get_num_pages(
					&io_range.attrs);
			vm_memory_result_t ret = vm_memory_lookup(
				hlos_vm, VM_MEMUSE_DEVICE, ipa, size);
			if (ret.err != OK) {
				(void)printf(
					"vm_passthrough_config: Lookup of %lx %lx failed %d\n",
					ipa, size, ret.err);
				err = ret.err;
				goto loop_break;
			}
			size_t offset =
				io_range.address - rm_get_device_me_base();
			err = vm_memory_unmap_partial(
				hlos_vm, VM_MEMUSE_DEVICE,
				vm_memory_get_owned_extent(hlos_vm,
							   MEM_TYPE_IO),
				ipa, offset, size);
			if (err != OK) {
				(void)printf(
					"vm_passthrough_config: Unmapping of %lx %lx failed %d\n",
					ipa, size, err);
			}
		}
	loop_break:
		if (err != OK) {
			break;
		}
	}
	vm_memory_batch_end();
	return err;
}

// Loops through all the IO address ranges from the passthrough configuration
// and verifies whether the ipa passed and the size of the address to be mapped
// is within any of the IO ranges from the passthrough configuration, access
// requested matches with the configure IO access and also if the vmid is same
// as the vmid as per the passthrough configuration.
// Returns true if the above mentioned condition is met else
// returns false.
bool
vm_passthrough_config_is_addr_in_range(vmid_t vmid, vmaddr_t ipa, size_t size,
				       pgtable_access_t access)
{
	bool	 ret	     = false;
	vmaddr_t ipa_start   = ipa;
	vmaddr_t ipa_end     = ipa_start + size;
	count_t	 num_devices = vm_passthrough_get_num_devices();

	for (index_t i = 0; i < num_devices; i++) {
		if (vm_passthrough_device_get_vmid(i) != vmid) {
			continue;
		}
		count_t num_ranges =
			vm_passthrough_device_get_num_mmio_ranges(i);
		const root_env_mmio_range_descriptor_t *mmio_ranges =
			vm_passthrough_get_device_mmio_ranges(i);
		assert(mmio_ranges != NULL);

		for (index_t j = 0; j < num_ranges; j++) {
			root_env_mmio_range_descriptor_t io_range =
				mmio_ranges[j];
			vmaddr_t ipa_end_configured =
				io_range.address +
				((size_t)PAGE_SIZE *
				 root_env_mmio_range_properties_get_num_pages(
					 &io_range.attrs));
			if ((ipa_start >= io_range.address) &&
			    (ipa_end <= ipa_end_configured) &&
			    (access ==
			     root_env_mmio_range_properties_get_access(
				     &io_range.attrs))) {
				ret = true;
				break;
			}
		}
		if (ret == true) {
			break;
		}
	}
	return ret;
}

// Getter functions to read passthrough configuration data.

// Returns the number of configured passthrough devices
count_t
vm_passthrough_get_num_devices(void)
{
	return rm_get_vm_device_assignments()->num_devices;
}

// Returns the number of configured passthrough device mmio_ranges
// for the mentioned 'dev_id'
count_t
vm_passthrough_device_get_num_mmio_ranges(index_t dev_id)
{
	return rm_get_vm_device_assignments()->devices[dev_id].num_mmio_ranges;
}

// Returns the pointer to the array of mmio_ranges configured
// for the mentioned 'dev_id'
const root_env_mmio_range_descriptor_t *
vm_passthrough_get_device_mmio_ranges(index_t dev_id)
{
	const vm_device_assignments_t *assignments =
		rm_get_vm_device_assignments();

	assert(dev_id < assignments->num_devices);
	return assignments->devices[dev_id].mmio_ranges;
}

// Returns the VMID for which the device 'dev_id' configuration to be applied
vmid_t
vm_passthrough_device_get_vmid(index_t dev_id)
{
	const vm_device_assignments_t *assignments =
		rm_get_vm_device_assignments();

	assert(dev_id < assignments->num_devices);
	return assignments->devices[dev_id].vmid;
}
