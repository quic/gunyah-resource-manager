// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define VM_CONSOLE_OPEN	 0x56000081
#define VM_CONSOLE_CLOSE 0x56000082
#define VM_CONSOLE_WRITE 0x56000083
#define VM_CONSOLE_FLUSH 0x56000084

#define NOTIFY_VM_CONSOLE_CHARS 0x56100080

typedef struct {
	vmid_t	 target;
	uint16_t res0;
} vm_console_open_req_t;

typedef struct {
	vmid_t	 target;
	uint16_t res0;
} vm_console_close_req_t;

typedef struct {
	vmid_t	 target;
	uint16_t num_bytes;

	// with content tailing
} vm_console_write_req_t;

typedef struct {
	vmid_t	 target;
	uint16_t res0;
} vm_console_flush_req_t;

typedef struct {
	vmid_t from;

	uint16_t num_bytes;

	// with content tailing
} vm_console_chars_notify_t;
