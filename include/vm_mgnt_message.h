// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define VM_ALLOCATE   0x56000001
#define VM_DEALLOCATE 0x56000002
#define VM_SET_NAME   0x56000003
#define VM_START      0x56000004
#define VM_STOP	      0x56000005
#define VM_SHUTDOWN   0x56000006
#define VM_SUSPEND    0x56000007
#define VM_RESUME     0x56000008

#define VM_GET_ID      0x56000010
#define VM_LOOKUP_URI  0x56000011
#define VM_LOOKUP_GUID 0x56000012
#define VM_LOOKUP_NAME 0x56000013

#define VM_GET_STATE 0x56000017

#define VM_GET_HYP_RESOURCES 0x56000020
#define VM_GET_HYP_CAPIDS    0x56000021
#define VM_GET_HYP_IRQS	     0x56000022

#define VM_SET_STATUS	 0x56000080
#define VM_HOST_GET_TYPE 0x560000A0

#define NOTIFY_VM_STATUS 0x56100008

typedef struct rm_notify_vm_status {
	uint16_t vm_vmid;
	uint16_t res0;
	uint8_t	 vm_status;
	uint8_t	 os_status;
	uint16_t app_status;
} rm_notify_vm_status_t;
