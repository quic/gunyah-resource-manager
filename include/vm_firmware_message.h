// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_VM_FIRMWARE_MESSAGE_H_
#define INCLUDE_VM_FIRMWARE_MESSAGE_H_

#define FW_MILESTONE	   0x51000020
#define FW_SET_VM_FIRMWARE 0x51000021

#define FW_SET_VM_FIRMWARE_FLAG_CONFIG_RANGE 1U

typedef struct {
	uint16_t fw_type;
	uint16_t flags;

	resource_handle_t image_mp_handle;
	uint64_t	  image_offset;
	uint64_t	  image_size; // excludes config if CONFIG_RANGE is set

	// Only valid if the CONFIG_RANGE flag is set
	uint64_t config_offset;
	uint64_t config_size;
} fw_set_vm_firmware_req_t;

#else

#error multiple include of vm_firmware_message.h

#endif
