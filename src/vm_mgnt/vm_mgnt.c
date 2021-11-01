// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm-rpc.h>

#include <compiler.h>
#include <guest_interface.h>
#include <rm-rpc-fifo.h>
#include <util.h>
#include <utils/vector.h>
#include <vm_config.h>
#include <vm_creation.h>
#include <vm_mgnt.h>
#include <vm_mgnt_message.h>

// Bitmap of free vmids - set bit means VMID is free.
// Only 64 VMIDs for now!
static uint64_t free_vmids;

static vector_t *all_vms;

rm_error_t
vm_mgnt_send_state(vm_t *vm)
{
	vmid_t owner = vm->owner;
	assert(owner != VMID_RM);

	rm_notify_vm_status_t msg = { 0 };

	msg.vm_vmid    = vm->vmid;
	msg.vm_status  = (uint8_t)vm->vm_state;
	msg.os_status  = (uint8_t)vm->os_state;
	msg.app_status = (uint16_t)vm->app_status;

	printf("NOTIFY_VM_STATUS: to:%d [%d: %d/%d/%d]\n", owner, vm->vmid,
	       vm->vm_state, vm->os_state, vm->app_status);
	// Send VM state notification
	rm_notify(owner, NOTIFY_VM_STATUS, &msg, sizeof(msg));

	return RM_OK;
}

rm_error_t
vm_mgnt_new_vm(vmid_t vmid, vmid_t owner)
{
	rm_error_t ret = RM_OK;
	vm_t *	   vm  = NULL;

#if STATIC_SVM
	// Special case since SVM is created early
	if (vmid == VMID_SVM) {
		vm = vm_lookup(vmid);

		// Only create SVM once
		if (vm != NULL) {
			if (owner != vm->owner) {
				ret = RM_ERROR_ARGUMENT_INVALID;
			}
			goto out;
		}
	}
#endif

	vm = calloc(1, sizeof(vm_t));

	if (vm == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}

	vm->vmid     = vmid;
	vm->owner    = owner;
	vm->vm_state = VM_STATE_INIT;

	if (vmid == VMID_HLOS) {
		strlcpy(vm->name, "HLOS", VM_MAX_NAME_LEN);
	} else if (vmid == VMID_SVM) {
		// FIXME: get this from VM device-tree
		strlcpy(vm->name, "SVM", VM_MAX_NAME_LEN);
	} else {
		exit(1);
	}

	error_t vec_err = vector_push_back(all_vms, vm);
	if (vec_err != OK) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}

out:
	if (ret != RM_OK) {
		free(vm);
	}
	return ret;
}

void
vm_mgnt_init(void)
{
	// Only VMID_SVM is available in current implementation

	assert(VMID_SVM < 64);
	free_vmids = util_bit(VMID_SVM);

	all_vms = vector_init(vm_t *, 1U, 1U);
	if (all_vms == NULL) {
		printf("Error no mem for vm mgnt init\n");
		exit(1);
	}

	rm_error_t ret = vm_mgnt_new_vm(VMID_HLOS, VMID_RM);
	if (ret != RM_OK) {
		printf("failed to create hlos vm: %d\n", ret);
		exit(1);
	}
}

vm_t *
vm_lookup(vmid_t vmid)
{
	vm_t *ret = NULL;

	size_t cnt = vector_size(all_vms);
	for (index_t i = 0; i < cnt; i++) {
		vm_t **vm = vector_at_ptr(vm_t *, all_vms, i);
		if ((*vm)->vmid == vmid) {
			ret = *vm;
			break;
		}
	}

	return ret;
}

static void
vm_mgnt_handle_allocate(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len)
{
	bool	   allocated = false;
	rm_error_t ret;
	vmid_t	   vmid = 0;

	// FIXME: make these checks more generic
	if (client_id != VMID_HLOS) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (len == 4) {
		uint8_t *buf8 = (uint8_t *)buf;
		vmid	      = buf8[0] | (vmid_t)((vmid_t)buf8[1] << 8);
	} else {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	printf("VM_ALLOCATE: %d vmid=%d\n", client_id, vmid);
	if (vmid == 0) {
		// Choose a free VMID
		index_t bit = compiler_ffs(free_vmids);
		if (bit != 0) {
			vmid	  = (vmid_t)(bit - 1);
			allocated = true;
			printf("allocated vmid=%d\n", vmid);
		}
	}

	if ((vmid > 0) && (vmid < 64)) {
		// Try allocate VMID
		if ((util_bit(vmid) & free_vmids) != 0) {
			// Allocate vmid and clear free_vmids bit
			free_vmids &= ~util_bit(vmid);
		} else {
			vmid = 0;
		}
	} else {
		// Out of range vmid requested
		vmid = 0;
	}

	if (vmid == 0) {
		ret = RM_ERROR_NORESOURCE;
		goto out;
	}

	ret = vm_mgnt_new_vm(vmid, client_id);
	if (ret != RM_OK) {
		goto out;
	}

	if (allocated) {
		uint32_t vmid_ret = vmid;
		rm_reply(client_id, msg_id, seq_num, &vmid_ret,
			 sizeof(vmid_ret));
	} else {
		rm_standard_reply(client_id, msg_id, seq_num, RM_OK);
	}

out:
	printf("VM_ALLOCATE: ret=%d\n", ret);
	if (ret != RM_OK) {
		if (vmid != 0) {
			// Deallocate vmid
			free_vmids |= util_bit(vmid);
		}
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static void
vm_mgnt_handle_start(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		     void *buf, size_t len)
{
	rm_error_t ret;

	if (client_id == VMID_HYP) {
		printf("ignored legacy VM_START\n");
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (len != 4) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *buf8 = (uint8_t *)buf;
	vmid_t	 vmid = buf8[0] | (vmid_t)((vmid_t)buf8[1] << 8);

	printf("VM_START: from:%d vmid:%d\n", client_id, vmid);
	vm_t *vm = vm_lookup(vmid);
	if (vm == NULL) {
		printf("VM_START: invalid vmid\n");
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if (client_id != vm->owner) {
		printf("VM_START: not owner\n");
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if (vm->vm_state != VM_STATE_READY) {
		printf("VM_START: not ready\n");
		ret = RM_ERROR_BUSY;
		goto out;
	}

	error_t hyp_ret;
	hyp_ret = vm_creation_process_resource(vmid);
	if (hyp_ret != OK) {
		printf("vm_creation_process_resource: ret %d\n", hyp_ret);
		ret	     = RM_ERROR_NORESOURCE;
		vm->vm_state = VM_STATE_INIT_FAILED;
		goto out_state_change;
	}

	hyp_ret = svm_poweron(vmid);
	if (hyp_ret != OK) {
		ret	     = RM_ERROR_NORESOURCE;
		vm->vm_state = VM_STATE_INIT_FAILED;
		goto out_state_change;
	}

	vm->vm_state = VM_STATE_RUNNING;
	ret	     = RM_OK;

out_state_change:
	if (vm_mgnt_send_state(vm) != RM_OK) {
		printf("vm_mgnt_send_state error\n");
	}

out:
	printf("VM_START: ret=%d\n", ret);
	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static void
vm_mgnt_handle_get_state(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			 void *buf, size_t len)
{
	rm_error_t ret;
	vmid_t	   vmid = 0;

	if (len == 4) {
		uint8_t *buf8 = (uint8_t *)buf;
		vmid	      = buf8[0] | (vmid_t)((vmid_t)buf8[1] << 8);

		vm_t *vm = vm_lookup(vmid);
		if (vm == NULL) {
			ret = RM_ERROR_NORESOURCE;
			goto out;
		}

		if ((vmid != client_id) && (vm->owner != client_id)) {
			ret = RM_ERROR_DENIED;
			goto out;
		}

		uint32_t status_ret = vm->vm_state |
				      ((uint32_t)vm->os_state << 8) |
				      ((uint32_t)vm->app_status << 16);

		rm_reply(client_id, msg_id, seq_num, &status_ret, 4);
		ret = RM_OK;
	} else {
		ret = RM_ERROR_MSG_INVALID;
	}

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static void
vm_mgnt_handle_set_state(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			 void *buf, size_t len)
{
	rm_error_t ret;

	if (client_id != VMID_SVM) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (len == 4) {
		vm_state_t   vm_state;
		os_state_t   os_state;
		app_status_t app_status;

		uint8_t *buf8 = (uint8_t *)buf;

		vm_state   = (vm_state_t)buf8[0];
		os_state   = (os_state_t)buf8[1];
		app_status = (app_status_t)buf8[2] |
			     (app_status_t)((app_status_t)buf8[3] << 8);

		vm_t *vm = vm_lookup(client_id);
		if (vm == NULL) {
			ret = RM_ERROR_NORESOURCE;
			goto out;
		}

		// validate arguments
		switch (vm_state) {
		case VM_STATE_NONE:
			// treated as no-change
			vm_state = vm->vm_state;
			ret	 = RM_OK;
			break;
		case VM_STATE_SHUTDOWN:
		case VM_STATE_SHUTOFF:
		case VM_STATE_CRASHED:
			ret = RM_OK;
			break;
		case VM_STATE_INIT:
		case VM_STATE_READY:
		case VM_STATE_RUNNING:
		case VM_STATE_PAUSED:
		case VM_STATE_INIT_FAILED:
		default:
			ret = RM_ERROR_ARGUMENT_INVALID;
			break;
		}
		if (ret != RM_OK) {
			goto out;
		}

		switch (os_state) {
		case OS_STATE_NONE:
			// treated as no-change
			os_state = vm->os_state;
			break;
		case OS_STATE_EARLY_BOOT:
		case OS_STATE_BOOT:
		case OS_STATE_INIT:
		case OS_STATE_RUN:
			break;
		default:
			ret = RM_ERROR_ARGUMENT_INVALID;
			break;
		}
		if (ret != RM_OK) {
			goto out;
		}

		// update statuses
		vm->vm_state   = vm_state;
		vm->os_state   = os_state;
		vm->app_status = app_status;

		ret = vm_mgnt_send_state(vm);
		if (ret != RM_OK) {
			printf("error sending update\n");
		}

		rm_standard_reply(client_id, msg_id, seq_num, RM_OK);
		ret = RM_OK;
	} else {
		ret = RM_ERROR_MSG_INVALID;
	}

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static void
vm_mgnt_handle_get_type(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			size_t len)
{
	rm_error_t ret;

	if (len != 0) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint32_t host_ret = 0x64 |	    // AArch64
			    (0x1U << 8) |   // Gunyah + RM
			    (0x00U << 16) | // Res 0
			    (0x01U << 24);  // Ver 1

	rm_reply(client_id, msg_id, seq_num, &host_ret, 4);
	ret = RM_OK;

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

bool
vm_mgnt_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		    void *buf, size_t len)
{
	bool handled = false;

	if ((client_id == VMID_HYP) && (msg_id != VM_START)) {
		goto out;
	}

	switch (msg_id) {
	case VM_ALLOCATE:
		vm_mgnt_handle_allocate(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_DEALLOCATE:
	case VM_SET_NAME:
		// Not supported in v1
		break;
	case VM_START:
		vm_mgnt_handle_start(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_STOP:
	case VM_SHUTDOWN:
	case VM_SUSPEND:
	case VM_RESUME:
		// Not supported in v1
		break;
	case VM_GET_STATE:
		vm_mgnt_handle_get_state(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_SET_STATUS:
		vm_mgnt_handle_set_state(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_HOST_GET_TYPE:
		vm_mgnt_handle_get_type(client_id, msg_id, seq_num, len);
		handled = true;
		break;
	default:
		break;
	}

out:
	return handled;
}
