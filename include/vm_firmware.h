// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_VM_FIRMWARE_H_
#define INCLUDE_VM_FIRMWARE_H_

typedef struct {
	vmid_t	 target;
	uint8_t	 arch_reg_set;
	uint8_t	 reg_index;
	uint32_t res0;
	uint64_t value;
} vm_boot_ctx_req_t;

bool
vm_firmware_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len);

rm_error_t
vm_firmware_vm_set_mem(vm_t *vm, resource_handle_t fw_mp_handle,
		       size_t fw_offset, size_t fw_size);

rm_error_t
vm_firmware_vm_start(vm_t *vm);

rm_error_t
vm_firmware_init_boot_context(const vm_t *vm);

rm_error_t
vm_firmware_set_boot_context(const vm_t *vm, const vm_boot_ctx_req_t *req);

#else

#error multiple include of vm_firmware.h

#endif
