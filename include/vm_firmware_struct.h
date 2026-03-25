// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_VM_FIRMWARE_STRUCT_H_
#define INCLUDE_VM_FIRMWARE_STRUCT_H_

typedef struct vm_firmware_image_data_s vm_firmware_image_data_t;

// Authenticate a loaded FW image.
//
// The fw_offset/fw_size range specifies the location of the firmware executable
// within the image.
//
// The config_offset/config_size range specifies the location of the bootloader-
// provided configuration data, stored in a structure of firmware-specific type.
// Not all firmware types use this; if not, the size will be zero.
//
// If this callback is not specified, the userspace loader is presumed to have
// authenticated the image before passing it to RM. In this case, the firmware
// offset must be zero, the entry point offset is presumed to be zero, and the
// configuration data (if present) is simply copied along with the firmware
// image.
typedef rm_error_t (*vm_firmware_auth_t)(vm_firmware_image_data_t *image_data,
					 uintptr_t		   image_base,
					 size_t image_size, paddr_t phys_base,
					 size_t fw_offset, size_t fw_size,
					 size_t config_offset,
					 size_t config_size);

// Copy the firmware into a VM's FW region.
//
// This should always write the entire region (up to vm->fw_size) to ensure
// there is no stale data from the host. The caller will cache-clean the region
// afterwards.
//
// If not specified, the image data will be copied unchanged from the FW image
// to offset 0 of the mapping, and the remainder of the region will be zeroed.
typedef rm_error_t (*vm_firmware_copy_t)(
	vm_t *vm, const vm_firmware_image_data_t *image_data,
	uint8_t *fw_mapping);

RM_PADDED(struct vm_firmware_image_data_s {
	vm_fw_type_t	   fw_type;
	const void	  *image;
	size_t		   size;
	size_t		   config_offset;
	size_t		   config_size;
	vm_firmware_auth_t auth_image;
})

typedef rm_error_t (*vm_setup_boot_context_t)(const vm_t *vm);
typedef rm_error_t (*vm_set_boot_context_t)(const vm_t	       *vm,
					    arch_register_set_t reg_set,
					    index_t		reg_index,
					    register_t		reg_val);

RM_PADDED(struct vm_firmware_data_s {
	vm_auth_type_t auth_type;
	vm_fw_type_t   fw_type;

	bool mandatory;
	bool single_boot_vcpu;

	vm_firmware_copy_t	copy_image;
	vm_setup_boot_context_t setup_boot_context_handler;
	vm_set_boot_context_t	set_boot_context_handler;
})

#else

#error multiple include of vm_firmware_struct.h

#endif
