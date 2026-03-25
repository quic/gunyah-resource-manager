// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_VM_CONSOLE_H_
#define INCLUDE_VM_CONSOLE_H_

rm_error_t
vm_console_init(void);

vm_console_t *
vm_console_create(vm_t *vm, vmid_t owner);

bool
vm_console_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		       void *buf, size_t len);

void
vm_console_destroy(vm_console_t *console);

void
vm_console_deinit(void);

#else

#error multiple include of vm_console.h

#endif
