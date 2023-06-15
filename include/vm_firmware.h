// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

bool
vm_firmware_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len);

rm_error_t
vm_firmware_vm_set_mem(vm_t *vm, resource_handle_t fw_mp_handle,
		       size_t fw_offset, size_t fw_size);

rm_error_t
vm_firmware_vm_start(vm_t *vm);
