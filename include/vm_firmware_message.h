// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define FW_MILESTONE	   0x51000020
#define FW_SET_VM_FIRMWARE 0x51000021

typedef struct {
	uint16_t auth_type;
	uint16_t res0;

	resource_handle_t image_mp_handle;
	uint64_t	  image_offset;
	uint64_t	  image_size;
} fw_set_vm_firmware_req_t;
