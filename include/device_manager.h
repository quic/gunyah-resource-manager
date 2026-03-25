// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_DEVICE_MANAGER_H_
#define INCLUDE_DEVICE_MANAGER_H_

// Resource descriptors

typedef enum {
	RESOURCE_DESCR_TYPE_MMIO = 1,
	RESOURCE_DESCR_TYPE_IRQ,
	RESOURCE_DESCR_TYPE_IOMMU,
	RESOURCE_DESCR_TYPE_MSI,
	RESOURCE_DESCR_TYPE_PCIE
} resource_descr_type_t;

typedef union {
	struct {
		uint32_t descriptor0;
		uint32_t descriptor1;
		uint32_t descriptor2;
		uint32_t descriptor3;
	} descriptors;

	struct {
		uint8_t	 type;
		uint8_t	 res0[3];
		uint32_t size;
		uint32_t base_addr_lo;
		uint32_t base_addr_hi;
	} mmio_reg;

	struct {
		uint8_t	 type;
		uint8_t	 res0[3];
		virq_t	 irq_number;
		uint32_t res0_1[2];
	} irq;

	struct {
		uint8_t	 type;
		uint8_t	 res0[3];
		uint32_t iommu_handle;
		uint32_t endpoint_id_base;
		uint32_t endpoint_id_count;
	} iommu_endpoint;

	struct {
		uint8_t	 type;
		uint8_t	 res0[3];
		uint32_t msi_router_handle;
		uint32_t endpoint_id_base;
		uint32_t endpoint_id_count;
	} msi_endpoint;

	struct {
		uint8_t	 type;
		uint8_t	 res0;
		uint16_t pcei_responder_id;
		uint32_t pcie_rc_handle;
		uint32_t res0_1[2];
	} pcie_function;

	struct {
		uint8_t	 type;
		uint8_t	 pad[3];
		uint32_t descriptor1;
		uint32_t descriptor2;
		uint32_t descriptor3;
	} type_selector;
} resource_descriptor_t;

// Initialize the device_manager globally
error_t
device_manager_init(const rm_env_data_t *env_data);

// De-initialize the device_manager
void
device_manager_deinit(void);

// Device manager message handling
bool
device_manager_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			   void *buf, size_t len);

// Release all devices on VM reset
bool
vm_reset_handle_release_devices(vm_t *vm);

// Initialize device manager-related VM structures
error_t
device_manager_init_vm(vm_t *vm);

// Free device manager-related VM structures
void
device_manager_deinit_vm(vm_t *vm);

// Attach all devices currently offered for lending/donation to a VM
error_t
device_manager_attach_vm(vm_t *vm);

// Check if a memory range is belongs to a device
bool
device_manager_is_device_mmio(paddr_t addr, size_t size);

#else // INCLUDE_DEVICE_MANAGER_H_

#error multiple include of device_manager.h

#endif // INCLUDE_DEVICE_MANAGER_H_
