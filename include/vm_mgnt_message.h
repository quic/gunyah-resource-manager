// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define VM_ALLOCATE   0x56000001U
#define VM_DEALLOCATE 0x56000002U
#define VM_START      0x56000004U
#define VM_STOP	      0x56000005U
#define VM_RESET      0x56000006U
// #define VM_SUSPEND    0x56000007
// #define VM_RESUME     0x56000008

#define VM_GET_ID      0x56000010U
#define VM_LOOKUP_URI  0x56000011U
#define VM_LOOKUP_GUID 0x56000012U
#define VM_LOOKUP_NAME 0x56000013U
#define VM_GET_OWNER   0x56000015U

#define VM_GET_STATE	     0x56000017U
#define VM_GET_CRASH_MSG     0x56000019U
#define VM_GET_HYP_RESOURCES 0x56000020U
#define VM_GET_HYP_CAPIDS    0x56000021U
#define VM_GET_HYP_IRQS	     0x56000022U
#define VM_GET_VMID	     0x56000024U
#define VM_GET_PEERS	     0x56000025U

#define VM_SET_TIME_BASE    0x56000030U
#define VM_SET_CONTEXT	    0x56000031U
#define VM_SET_FIRMWARE_MEM 0x56000032U

#define VM_SET_STATUS	 0x56000080U
#define VM_EXIT		 0x56000085U
#define VM_SET_CRASH_MSG 0x56000086U
#define VM_HOST_GET_TYPE 0x560000A0U

#define NOTIFY_VM_EXITED   0x56100001U
#define NOTIFY_VM_SHUTDOWN 0x56100002U
#define NOTIFY_VM_STATUS   0x56100008U

typedef struct rm_notify_vm_status {
	uint16_t vm_vmid;
	uint16_t res0;
	uint8_t	 vm_status;
	uint8_t	 os_status;
	uint16_t app_status;
} rm_notify_vm_status_t;

typedef struct {
	vmid_t	 target;
	uint16_t res0;

	resource_handle_t fw_mp_handle;
	uint64_t	  fw_offset;
	uint64_t	  fw_size;
} vm_set_firmware_mem_t;

typedef struct rm_notify_vm_exited {
	uint16_t vmid;
	uint16_t exit_type;
	uint32_t exit_reason_size;
	// exit_reason
} rm_notify_vm_exited_t;

#define VM_STOP_FLAG_FORCE 1U
