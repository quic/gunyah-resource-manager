// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

RM_PADDED(struct vm_device_descriptor_s {
	vmid_t				  vmid;
	count_t				  num_irqs;
	count_t				  num_mmio_ranges;
	uint32_t			 *irqs;
	root_env_mmio_range_descriptor_t *mmio_ranges;
})

RM_PADDED(struct vm_device_assignments_s {
	count_t			num_devices;
	vm_device_descriptor_t *devices;
})

error_t
vm_passthrough_config_unmap_ioranges(const rm_env_data_t *env_data);

void
vm_passthrough_config_validate(const rm_env_data_t *env_data);

void
vm_passthrough_config_deinit(const rm_env_data_t *env_data);

bool
vm_passthrough_config_is_addr_in_range(vmid_t vmid, vmaddr_t ipa, size_t size,
				       pgtable_access_t access);

count_t
vm_passthrough_get_num_devices(void);

count_t
vm_passthrough_device_get_num_mmio_ranges(index_t dev_id);

const root_env_mmio_range_descriptor_t *
vm_passthrough_get_device_mmio_ranges(index_t dev_id);

vmid_t
vm_passthrough_device_get_vmid(index_t dev_id);
