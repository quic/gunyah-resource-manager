// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>
#include <utils/dict.h>
#include <utils/guid_parser.h>
#include <utils/vector.h>

#include <compiler.h>
#include <event.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <log.h>
#include <mem_region.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <panic.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <uapi/interrupt.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_firmware.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_mgnt_arch.h>
#include <vm_mgnt_message.h>
#include <vm_vcpu.h>
#ifdef HYPVM_WITH_COVERAGE
#include <uart.h>

#include "cpptest.h"
#endif

// Bitmap of secondary VM VMIDs. These are VMIDs which are managed by RM but
// have specific roles in the platform, and should only be given to
// authenticated VMs.
static uint64_t secondary_vmids;

// Bitmap of unallocated secondary VMIDs - set bit means VMID is free.
static uint64_t free_secondary_vmids;

// Bitmap of peripheral VMIDs, which are not controlled by RM.
static uint64_t peripheral_vmids;

// Bitmap of unallocated dynamic VMIDs, offset by VMID_DYNAMIC_BASE.
static uint64_t free_dynamic_vmids;

static dict_t *all_vms;

RM_PADDED(typedef struct peer_info {
	uint16_t     id_len;
	const char  *id_buf;
	vm_id_type_t id_type;
} peer_info_t)

static error_t
vm_mgnt_parse_peer_id(const char *peer_id, peer_info_t *info);

void
vm_mgnt_send_state(vm_t *vm)
{
	vmid_t owner = vm->owner;
	assert(owner != VMID_RM);

	rm_notify_vm_status_t msg = { 0 };

	msg.vm_vmid    = vm->vmid;
	msg.vm_status  = (uint8_t)vm->vm_state;
	msg.os_status  = (uint8_t)vm->os_state;
	msg.app_status = (uint16_t)vm->app_status;

	// Send VM state notification to all peer VMs
	size_t cnt = vector_size(vm->peers);
	for (index_t i = 0; i < cnt; i++) {
		vm_t *peer_vm = vector_at(vm_t *, vm->peers, i);
		assert(peer_vm != NULL);

		if (!rm_can_rpc(peer_vm->vmid) ||
		    (peer_vm->vm_state != VM_STATE_RUNNING)) {
			continue;
		}

		LOG("NOTIFY_VM_STATUS: to: %d [%d: %d/%d/%d]\n", peer_vm->vmid,
		    vm->vmid, vm->vm_state, vm->os_state, vm->app_status);
		rm_notify(peer_vm->vmid, NOTIFY_VM_STATUS, &msg, sizeof(msg));
	}
}

bool
vm_mgnt_state_change_valid(const vm_t *vm, vm_state_t vm_new_state)
{
	bool	   valid;
	vm_state_t vm_old_state = vm->vm_state;

	switch (vm_new_state) {
	case VM_STATE_INIT:
		valid = (vm_old_state == VM_STATE_LOAD) ||
			(vm_old_state == VM_STATE_AUTH) ||
			(vm_old_state == VM_STATE_RESET);
		break;
	case VM_STATE_READY:
		valid = vm_old_state == VM_STATE_INIT;
		break;
	case VM_STATE_RUNNING:
		valid = (vm_old_state == VM_STATE_READY) ||
			(vm_old_state == VM_STATE_PAUSED);
		break;
	case VM_STATE_PAUSED:
		valid = !vm->no_shutdown && (vm_old_state == VM_STATE_RUNNING);
		break;
	case VM_STATE_LOAD:
		valid = vm_old_state == VM_STATE_NONE;
		break;
	case VM_STATE_AUTH:
		valid = (vm_old_state == VM_STATE_LOAD) ||
			(vm_old_state == VM_STATE_RESET);
		break;
	case VM_STATE_INIT_FAILED:
		valid = (vm_old_state == VM_STATE_INIT) ||
			(vm_old_state == VM_STATE_READY) ||
			(vm_old_state == VM_STATE_LOAD) ||
			(vm_old_state == VM_STATE_AUTH) ||
			(vm_old_state == VM_STATE_RESET);
		break;
	case VM_STATE_EXITED:
		valid = (!vm->no_shutdown && !vm->crash_fatal) &&
			((vm_old_state == VM_STATE_RUNNING) ||
			 (vm_old_state == VM_STATE_PAUSED));
		break;
	case VM_STATE_RESETTING:
		valid = !vm->no_reset &&
			((vm_old_state == VM_STATE_EXITED) ||
			 (vm_old_state == VM_STATE_READY) ||
			 (vm_old_state == VM_STATE_INIT_FAILED));
		break;
	case VM_STATE_RESET:
	case VM_STATE_DEFUNCT:
		valid = vm_old_state == VM_STATE_RESETTING;
		break;
	case VM_STATE_NONE:
		valid = vm_old_state == VM_STATE_RESET;
		break;
	default:
		valid = false;
		break;
	}

	return valid;
}

static void
vm_mgnt_set_exit_type(vm_t *vm, exit_type_t exit_type)
{
	assert(vm->vm_state == VM_STATE_EXITED);

	vm->exit_type = exit_type;
}

static void
vm_mgnt_update_vm_state(vm_t *vm, vm_state_t vm_state)
{
	// State transition should have already been validated.
	assert(vm_mgnt_state_change_valid(vm, vm_state));

	vm->vm_state = vm_state;

	// XXX Only send state for certain transitions?
	vm_mgnt_send_state(vm);
}

static void
vm_mgnt_set_cleanup_type(vm_t *vm, const uint32_t *extra_reason)
{
	assert(vm->vm_state == VM_STATE_EXITED);

	switch (vm->exit_type) {
	// arch specific
	case EXIT_TYPE_PLATFORM_OFF:
	case EXIT_TYPE_PLATFORM_RESET:
	case EXIT_TYPE_PSCI_SYSTEM_RESET2:
	case EXIT_TYPE_VM_EXIT:
	case EXIT_TYPE_WATCHDOG_BITE:
		vm_mgnt_arch_set_cleanup_type(vm, extra_reason);
		break;
	case EXIT_TYPE_SOFTWARE_ERROR:
	case EXIT_TYPE_ASYNC_HW_ERROR:
	case EXIT_TYPE_VM_STOP_FORCED:
	default:
		vm->clean_shutdown = false;
		break;
	}

	// Ensure that IO memory borrowed from HLOS was released.
	if (vm->clean_shutdown) {
		// The VM directly controls the devices it has access to. For a
		// clean shutdown, it has to guarantee that it only releases the
		// IO memory after sanitizing the device at VM state RUNNING.
		// Hypervisor should not check IO memory here, because 1) an IO
		// memory might have never been zero, e.g., GIC register 2)
		// reading a IO device might have side-effects, e.g., memcpy
		// might raise external aborts due to incorrect access sizes.
		// 3) no R/W access
		if (memparcel_vm_has_accepted_io_memparcels(vm->vmid)) {
			vm->clean_shutdown = false;
			(void)printf(
				"Warning: VM %d has unreleased IO memparcels\n",
				vm->vmid);
		}
	}

	(void)printf("VM %d clean shutdown %d\n", vm->vmid,
		     vm->clean_shutdown ? 1 : 0);
}

static rm_error_t
vm_mgnt_send_exited(const vm_t *vm, uint16_t exit_reason_flags,
		    exit_code_t exit_code, count_t extra_reason_words,
		    const uint32_t *extra_reason)
{
	rm_error_t err;

	assert(vm->vm_state == VM_STATE_EXITED);

	vmid_t owner = vm->owner;
	assert(owner != VMID_RM);

	assert((extra_reason_words == 0U) || (extra_reason != NULL));

	rm_notify_vm_exited_t msg = { 0 };

	msg.vmid      = vm->vmid;
	msg.exit_type = (uint16_t)vm->exit_type;
	msg.exit_reason_size =
		((uint32_t)(sizeof(uint32_t))) * (extra_reason_words + 1U);

	size_t	  len = sizeof(msg) + msg.exit_reason_size;
	uint32_t *buf = calloc(1, len);
	if (buf == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	uint32_t common_reason = exit_reason_flags;
	common_reason |= (uint32_t)exit_code << 16;

	static_assert(sizeof(msg) == sizeof(uint64_t),
		      "rm_notify_vm_exited_t size changed");
	(void)memscpy((void *)&buf[0], len, (void *)&msg, sizeof(msg));
	buf[2] = common_reason;
	for (count_t i = 0U; i < extra_reason_words; i++) {
		buf[3U + i] = extra_reason[i];
	}

	err = rm_rpc_fifo_send_notification(owner, NOTIFY_VM_EXITED, buf, len,
					    true);
	if (err != RM_OK) {
		free(buf);
		panic("vm_mgnt: Failed to send exited notification\n");
	}

out:
	return err;
}

static void
vm_reset_callback(event_t *event, void *data)
{
	vm_t *vm = (vm_t *)data;

	bool state_completed = false;
	bool trigger	     = false;

	switch (vm->reset_stage) {
	case VM_RESET_STAGE_INIT:
		state_completed = vm_reset_handle_init(vm);
		if (state_completed) {
			vm->reset_stage = VM_RESET_STAGE_DESTROY_VDEVICES;
		}
		trigger = true;
		break;
	case VM_RESET_STAGE_DESTROY_VDEVICES:
		state_completed = vm_reset_handle_destroy_vdevices(vm);
		if (state_completed) {
			vm->reset_stage = VM_RESET_STAGE_RELEASE_MEMPARCELS;
		}
		trigger = true;
		break;
	case VM_RESET_STAGE_RELEASE_MEMPARCELS:
		state_completed = vm_reset_handle_release_memparcels(vm->vmid);
		if (state_completed) {
			vm->reset_stage = VM_RESET_STAGE_RELEASE_IRQS;
		}
		trigger = true;
		break;
	case VM_RESET_STAGE_RELEASE_IRQS:
		state_completed = vm_reset_handle_release_irqs(vm->vmid);
		if (state_completed) {
			vm->reset_stage = VM_RESET_STAGE_DESTROY_VM;
		}
		trigger = true;
		break;
	case VM_RESET_STAGE_DESTROY_VM:
		state_completed = vm_reset_handle_destroy(vm);
		if (state_completed) {
			vm->reset_stage = VM_RESET_STAGE_CLEANUP_VM;
		}
		trigger = true;
		break;
	case VM_RESET_STAGE_CLEANUP_VM:
		state_completed = vm_reset_handle_cleanup(vm);
		if (state_completed) {
			vm->reset_stage = VM_RESET_STAGE_COMPLETED;
		}
		trigger = true;
		break;
	case VM_RESET_STAGE_COMPLETED: {
		vm_state_t vm_state;

		if (vm->restart_allowed) {
			vm_state = VM_STATE_RESET;
		} else {
			// Do not allow VM restart, we don't support cleanup.
			vm_state = VM_STATE_DEFUNCT;
			(void)printf("Warning: VM %d is defunct\n", vm->vmid);
		}
		vm_mgnt_update_vm_state(vm, vm_state);
		vm_deregister_all_peers(vm);
#ifdef HYPVM_WITH_COVERAGE
		CppTest_SendCoverage_fdx();
		// c-runtime coverage ioctl
		uart_send_coverage();
#endif
		break;
	}
	default:
		(void)printf("VM_RESET: Invalid state: %d\n", vm->reset_stage);
		break;
	}

	if (trigger) {
		(void)event_trigger(event);
	}

	return;
}

rm_error_t
vm_mgnt_new_vm(vmid_t vmid, vmid_t owner)
{
	rm_error_t ret = RM_OK;
	vm_t	  *vm;

	vm = calloc(1, sizeof(vm_t));

	if (vm == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}

	vm->vmid	  = vmid;
	vm->owner	  = owner;
	vm->vm_state	  = VM_STATE_LOAD;
	vm->mem_mp_handle = MEMPARCEL_INVALID_HANDLE;
	vm->fw_mp_handle  = MEMPARCEL_INVALID_HANDLE;

	vm->peers = vector_init(vm_t *, 2U, 2U);
	if (vm->peers == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}

	if (owner != VMID_RM) {
		// Add owner VM as peer
		vm_t *owner_vm = vm_lookup(owner);
		assert(owner_vm != NULL);

		error_t reg_err = vm_register_peers(vm, owner_vm);
		if (reg_err != OK) {
			ret = RM_ERROR_NOMEM;
			goto out;
		}
	}

	// Register VM_RESET event
	error_t err = event_register(&vm->reset_event, vm_reset_callback, vm);
	if (err != OK) {
		ret = RM_ERROR_NORESOURCE;
		goto out;
	}

	err = dict_add(all_vms, vmid, vm);
	if (err != OK) {
		if (err == ERROR_NOMEM) {
			ret = RM_ERROR_NOMEM;
		} else {
			ret = RM_ERROR_DENIED;
		}
		goto out;
	}

out:
	if ((ret != RM_OK) && (vm != NULL)) {
		if (vm->peers != NULL) {
			vm_deregister_all_peers(vm);
			vector_deinit(vm->peers);
		}
		free(vm);
	}

	return ret;
}

static rm_error_t
vm_mgnt_delete_vm(vmid_t vmid)
{
	rm_error_t ret = RM_OK;

	vm_t *vm = vm_lookup(vmid);
	if (vm == NULL) {
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if ((vm->vm_state != VM_STATE_LOAD) &&
	    (vm->vm_state != VM_STATE_RESET)) {
		ret = RM_ERROR_VM_STATE;
		goto out;
	}

	(void)event_deregister(&vm->reset_event);

	// Delete VM from all_vms
	error_t err = dict_remove(all_vms, vmid, NULL);
	assert(err == OK);

	vm_deregister_all_peers(vm);
	vector_deinit(vm->peers);
	free(vm);

out:
	return ret;
}

void
vm_mgnt_set_name(vm_t *vm, const char *name)
{
	(void)strlcpy(vm->name, name, VM_MAX_NAME_LEN);
	vm->name_len = (uint16_t)strlen(vm->name);
}

rm_error_t
vm_mgnt_init(void)
{
	rm_error_t ret	     = RM_OK;
	secondary_vmids	     = platform_get_secondary_vmids();
	free_secondary_vmids = secondary_vmids;

	peripheral_vmids = platform_get_peripheral_vmids();

	free_dynamic_vmids = util_mask(VMID_DYNAMIC_END - VMID_DYNAMIC_BASE);

	assert(all_vms == NULL);
	static_assert(VMID_HYP == 0U, "VMID_HYP != 0");

	all_vms = dict_init(1U, VMID_LAST);
	if (all_vms == NULL) {
		(void)printf("Error no mem for vm mgnt init");
		ret = RM_ERROR_NOMEM;
		goto out;
	}

	ret = vm_mgnt_new_vm(VMID_RM, VMID_RM);
	if (ret != RM_OK) {
		(void)printf("failed to create RM vm_t");
		goto out;
	}

	vm_t *rm = vm_lookup(VMID_RM);
	assert(rm != NULL);
	vm_mgnt_set_name(rm, "RM");

	// TODO: possibly move this to hlos_vm_create()
	ret = vm_mgnt_new_vm(VMID_HLOS, VMID_RM);
	if (ret != RM_OK) {
		(void)printf("failed to create hlos vm_t");
		goto out;
	}

	vm_t *hlos = vm_lookup(VMID_HLOS);
	assert(hlos != NULL);
	vm_mgnt_set_name(hlos, "HLOS");
out:
	return ret;
}

vm_t *
vm_lookup(vmid_t vmid)
{
	assert(all_vms != NULL);

	return dict_get(all_vms, vmid);
}

bool
vm_is_secondary_vm(vmid_t vmid)
{
	return (vmid < 64U) && ((secondary_vmids & util_bit(vmid)) != 0U);
}

bool
vm_is_peripheral_vm(vmid_t vmid)
{
	return (vmid < 64U) && ((peripheral_vmids & util_bit(vmid)) != 0U);
}

bool
vm_is_dynamic_vm(vmid_t vmid)
{
	return (vmid >= VMID_DYNAMIC_BASE) && (vmid < VMID_DYNAMIC_END) &&
	       ((free_dynamic_vmids & util_bit(vmid - VMID_DYNAMIC_BASE)) ==
		0U);
}

static bool
is_vm_query_allowed(vm_t *vm, vmid_t client_id)
{
	assert(vm != NULL);

	bool ret = (client_id == vm->vmid) || (client_id == vm->owner);
	if (ret) {
		goto out;
	}

	size_t cnt = vector_size(vm->peers);
	for (index_t i = 0; i < cnt; i++) {
		vm_t **peer_vm = vector_at_ptr(vm_t *, vm->peers, i);
		if ((*peer_vm) == NULL) {
			continue;
		}
		if ((*peer_vm)->vmid == client_id) {
			ret = true;
			goto out;
		}
	}

out:
	return ret;
}

static void
vm_mgnt_handle_allocate(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len)
{
	bool	   allocated = false;
	rm_error_t ret;
	vmid_t	   vmid = 0;

	assert(all_vms != NULL);

	// FIXME: make these checks more generic
	if (client_id != VMID_HLOS) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (len == 4U) {
		uint8_t *buf8 = (uint8_t *)buf;
		vmid	      = buf8[0] | (vmid_t)((vmid_t)buf8[1] << 8);
	} else {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	if (vmid == 0U) {
		// Choose a free dynamic VMID
		if (free_dynamic_vmids != 0U) {
			index_t bit = compiler_ctz(free_dynamic_vmids);
			free_dynamic_vmids &= ~util_bit(bit);
			vmid	  = (vmid_t)(bit + VMID_DYNAMIC_BASE);
			allocated = true;
			(void)printf("allocated vmid=%d\n", vmid);
		}
	} else if (vmid < 64U) {
		// Try to allocate the specified VMID
		if ((util_bit(vmid) & free_secondary_vmids) != 0U) {
			// Allocate vmid and clear free_secondary_vmids bit
			free_secondary_vmids &= ~util_bit(vmid);
		} else {
			vmid = 0;
		}
	} else {
		// Out of range vmid requested
		vmid = 0;
	}

	if (vmid == 0U) {
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
	LOG("VM_ALLOCATE: %d vmid=%d, ret=%d\n", client_id, vmid, ret);

	if (ret != RM_OK) {
		if (vmid != 0U) {
			// Deallocate vmid
			if (allocated) {
				assert(vmid >= VMID_DYNAMIC_BASE);
				free_dynamic_vmids |=
					util_bit(vmid - VMID_DYNAMIC_BASE);
			} else {
				assert(vmid < 64U);
				free_secondary_vmids |= util_bit(vmid);
			}
		}
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static void
vm_mgnt_handle_deallocate(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			  void *buf, size_t len)
{
	rm_error_t ret;
	vmid_t	   vmid = 0;

	if (len == 4U) {
		uint8_t *buf8 = (uint8_t *)buf;
		vmid	      = buf8[0] | (vmid_t)((vmid_t)buf8[1] << 8);
	} else {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_t *vm = vm_lookup(vmid);
	assert(vm != NULL);
	if (client_id != vm->owner) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	ret = vm_mgnt_delete_vm(vmid);
	if (ret != RM_OK) {
		goto out;
	}

	if (vmid >= VMID_DYNAMIC_BASE) {
		vmid_t vmid_dynamic = vmid - VMID_DYNAMIC_BASE;
		// A dynamic VMID can be 0.
		assert(vmid_dynamic < 64U);
		free_dynamic_vmids |= util_bit(vmid_dynamic);
	} else {
		assert(vmid < 64U);
		free_secondary_vmids |= util_bit(vmid);
	}

out:
	LOG("VM_DEALLOCATE: %d vmid=%d, ret=%d\n", client_id, vmid, ret);

	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static void
vm_mgnt_handle_start(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		     void *buf, size_t len)
{
	rm_error_t ret;
	vm_state_t vm_state;
	vmid_t	   vmid = 0U;

	if (client_id == VMID_HYP) {
		(void)printf("ignored legacy VM_START\n");
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (len != 4U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *buf8 = (uint8_t *)buf;
	vmid	      = buf8[0] | (vmid_t)((vmid_t)buf8[1] << 8);

	vm_t *vm = vm_lookup(vmid);
	if (vm == NULL) {
		(void)printf("invalid vmid\n");
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if (client_id != vm->owner) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (vm->vm_state != VM_STATE_READY) {
		(void)printf("not in ready state\n");
		ret = RM_ERROR_VM_STATE;
		goto out;
	}

	error_t hyp_ret = vm_memory_vm_start(vm);
	if (hyp_ret != OK) {
		(void)printf("vm_memory_vm_start: ret %d\n", hyp_ret);
		ret = RM_ERROR_NORESOURCE;
		goto out_state_change;
	}

	hyp_ret = vm_creation_process_resource(vm);
	if (hyp_ret != OK) {
		(void)printf("vm_creation_process_resource: ret %d\n", hyp_ret);
		ret = RM_ERROR_NORESOURCE;
		goto out_state_change;
	}

	// Copy the firmware image and start the VM.
	ret = vm_firmware_vm_start(vm);
	if (ret != RM_OK) {
		goto out_state_change;
	}

	ret = RM_OK;

out_state_change:
	vm_state = (ret == RM_OK) ? VM_STATE_RUNNING : VM_STATE_INIT_FAILED;
	vm_mgnt_update_vm_state(vm, vm_state);

out:
	LOG("VM_START: from:%d vmid:%d, ret=%d\n", client_id, vmid, ret);
	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static void
vm_mgnt_handle_stop(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		    void *buf, size_t len)
{
	rm_error_t ret;

	if (len != 8U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *buf8 = (uint8_t *)buf;
	vmid_t	 vmid = buf8[0] | (vmid_t)((vmid_t)buf8[1] << 8);

	vm_t *vm = vm_lookup(vmid);
	if (vm == NULL) {
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if (client_id != vm->owner) {
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if (!vm_mgnt_state_change_valid(vm, VM_STATE_EXITED) ||
	    vm->no_shutdown) {
		ret = RM_ERROR_VM_STATE;
		goto out;
	}

	if (vm->vm_config->watchdog != CSPACE_CAP_INVALID) {
		// Freeze the watchdog to prevent a bark if the VM is
		// proxy-scheduled.
		error_t e = gunyah_hyp_watchdog_manage(
			vm->vm_config->watchdog, WATCHDOG_MANAGE_OP_FREEZE);
		if (e != OK) {
			panic("Hyp watchdog failed\n");
		}
	}

	uint8_t flags = buf8[2];
	if ((flags & VM_STOP_FLAG_FORCE) != 0U) {
		vm_config_handle_exit(vm);

		vm_mgnt_update_vm_state(vm, VM_STATE_EXITED);
		vm_mgnt_set_exit_type(vm, EXIT_TYPE_VM_STOP_FORCED);
		vm_mgnt_set_cleanup_type(vm, NULL);

		ret = vm_mgnt_send_exited(vm, 0U, EXIT_CODE_NORMAL, 0U, NULL);
	} else {
		uint32_t stop_reason;
		(void)memscpy((uint8_t *)&stop_reason, sizeof(stop_reason),
			      &buf8[4], sizeof(uint8_t) * 4U);

		rm_notify(vmid, NOTIFY_VM_SHUTDOWN, &stop_reason,
			  sizeof(stop_reason));
		ret = RM_OK;
	}

out:
	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static void
vm_mgnt_handle_exit(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		    void *buf, size_t len)
{
	rm_error_t err;

	if (len != 4U) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_t *vm = vm_lookup(client_id);
	assert(vm != NULL);

	if (vm->crash_fatal) {
		(void)printf("crash_fatal VM %d called VM_EXIT", vm->vmid);
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	uint8_t *buf8 = (uint8_t *)buf;

	uint8_t res0 = buf8[3];

	uint16_t exit_flags;
	(void)memscpy((uint8_t *)&exit_flags, sizeof(exit_flags), &buf8[0],
		      sizeof(uint8_t) * 4U);
	uint8_t exit_code8 = buf8[2];

	bool valid = res0 == 0U;

	exit_code_t exit_code;

	switch ((exit_code_t)exit_code8) {
	case EXIT_CODE_NORMAL:
		exit_code = EXIT_CODE_NORMAL;
		break;
	case EXIT_CODE_SOFTWARE_ERROR:
		exit_code = EXIT_CODE_SOFTWARE_ERROR;
		break;
	case EXIT_CODE_BUS_ERROR:
		exit_code = EXIT_CODE_BUS_ERROR;
		break;
	case EXIT_CODE_DEVICE_ERROR:
		exit_code = EXIT_CODE_DEVICE_ERROR;
		break;
	case EXIT_CODE_UNKNOWN_ERROR:
	default:
		exit_code = EXIT_CODE_UNKNOWN_ERROR; // compiler required
		valid	  = false;
		break;
	}
	if (!valid) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}
	// Self requested shutdown is allowed
	if (vm->no_shutdown) {
		vm->no_shutdown = false;
	}

	(void)printf("VM_EXIT: VM %d exit_flags = %x, exit_code %d\n", vm->vmid,
		     exit_flags, exit_code);

	assert(vm_mgnt_state_change_valid(vm, VM_STATE_EXITED));

	vm_config_handle_exit(vm);

	vm_mgnt_update_vm_state(vm, VM_STATE_EXITED);
	vm_mgnt_set_exit_type(vm, EXIT_TYPE_VM_EXIT);
	vm_mgnt_set_cleanup_type(vm, NULL);

	err = vm_mgnt_send_exited(vm, exit_flags, exit_code, 0U, NULL);
	if (err != RM_OK) {
		(void)printf("VM_EXIT: Failed to send exited notification\n");
	}

out:
	rm_standard_reply(client_id, msg_id, seq_num, err);
}

static void
vm_mgnt_handle_reset(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		     void *buf, size_t len)
{
	rm_error_t ret;

	if (len != 4U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *buf8 = (uint8_t *)buf;
	vmid_t	 vmid = buf8[0] | (vmid_t)((vmid_t)buf8[1] << 8);

	vm_t *vm = vm_lookup(vmid);
	if (vm == NULL) {
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if (client_id != vm->owner) {
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if (vm->no_reset) {
		(void)printf("VM_RESET: of VM %d not allowed\n", vmid);
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (vm->qtee_registered) {
		(void)printf("VM_RESET: of registered VM %d\n", vmid);
	}

	vm_config_t *vmcfg = vm->vm_config;
	if (vmcfg->trusted_config) {
#if defined(PLATFORM_ENABLE_TRUSTEDVM_RESTART) &&                              \
	PLATFORM_ENABLE_TRUSTEDVM_RESTART
		(void)printf("VM_RESET: of trusted VM %d\n", vmid);
#else
		(void)printf("Error: reset of trusted VMs is not supported\n");
		ret = RM_ERROR_DENIED;
		goto out;
#endif
	}

	if (!vm_mgnt_state_change_valid(vm, VM_STATE_RESETTING)) {
		ret = RM_ERROR_VM_STATE;
		goto out;
	}

	if ((vm->vm_state != VM_STATE_EXITED) && (vm->vm_config != NULL)) {
		vm_config_handle_exit(vm);
	}

	vm_mgnt_update_vm_state(vm, VM_STATE_RESETTING);

	// Trigger cleanup of VM resources
	(void)event_trigger(&vm->reset_event);

	ret = RM_OK;
out:
	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static void
vm_mgnt_handle_get_state(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			 void *buf, size_t len)
{
	rm_error_t ret;
	vmid_t	   vmid = 0;

	if (len == 4U) {
		uint8_t *buf8 = (uint8_t *)buf;
		vmid	      = buf8[0] | (vmid_t)((vmid_t)buf8[1] << 8);
		if (vmid == 0U) {
			vmid = client_id;
		}

		vm_t *vm = vm_lookup(vmid);
		if (vm == NULL) {
			ret = RM_ERROR_NORESOURCE;
			goto out;
		}
		if (!is_vm_query_allowed(vm, client_id)) {
			ret = RM_ERROR_DENIED;
			goto out;
		}

		uint32_t status_ret = (uint32_t)vm->vm_state |
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
	rm_error_t ret = RM_OK;

	if (!vm_is_secondary_vm(client_id)) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (len == 4U) {
		os_state_t   os_state;
		app_status_t app_status;

		uint8_t *buf8 = (uint8_t *)buf;

		os_state   = (os_state_t)buf8[1];
		app_status = (app_status_t)buf8[2] |
			     (app_status_t)((app_status_t)buf8[3] << 8);

		vm_t *vm = vm_lookup(client_id);
		if (vm == NULL) {
			ret = RM_ERROR_NORESOURCE;
			goto out;
		}

		// validate arguments
		switch (os_state) {
		case OS_STATE_NONE:
			// treated as no-change
			os_state = vm->os_state;
			break;
		case OS_STATE_EARLY_BOOT:
		case OS_STATE_BOOT:
		case OS_STATE_INIT:
		case OS_STATE_RUN:
		case OS_STATE_SHUTDOWN:
		case OS_STATE_HALTED:
		case OS_STATE_CRASHED:
			break;
		default:
			ret = RM_ERROR_ARGUMENT_INVALID;
			break;
		}
		if (ret != RM_OK) {
			goto out;
		}

		// update statuses
		vm->os_state   = os_state;
		vm->app_status = app_status;

		vm_mgnt_send_state(vm);
	} else {
		ret = RM_ERROR_MSG_INVALID;
	}

out:
	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static void
vm_mgnt_handle_get_crash_msg(vmid_t client_id, uint32_t msg_id,
			     uint16_t seq_num, void *buf, size_t len)
{
	rm_error_t ret;

	if (len != 4U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *buf8 = (uint8_t *)buf;
	vmid_t	 vmid = buf8[0] | (vmid_t)((vmid_t)buf8[1] << 8);

	vm_t *vm = vm_lookup(vmid);
	if (vm == NULL) {
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	if (client_id != vm->owner) {
		ret = RM_ERROR_VMID_INVALID;
		goto out;
	}

	uint16_t crash_msg_len = vm->crash_msg_len;

	size_t	 out_len = (size_t)8 + util_balign_up(crash_msg_len, 4U);
	uint8_t *out	 = calloc(1, out_len);
	if (out == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}

	ret = RM_OK;
	(void)memscpy(&out[0], out_len, (uint8_t *)&ret, sizeof(ret));
	(void)memscpy(&out[4], out_len - sizeof(uint32_t),
		      (uint8_t *)&crash_msg_len, sizeof(crash_msg_len));
	if (vm->crash_msg != NULL) {
		(void)memscpy(&out[8], out_len - sizeof(uint64_t),
			      (uint8_t *)vm->crash_msg, crash_msg_len);
	}

	ret = rm_rpc_fifo_reply(client_id, msg_id, seq_num, out, out_len);
	if (ret != RM_OK) {
		free(out);
		(void)printf(
			"vm_mgnt_handle_get_crash_msg: error sending reply %u",
			ret);
	}

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

void
vm_mgnt_clear_crash_msg(vmid_t client_id)
{
	vm_t *vm = vm_lookup(client_id);
	assert(vm != NULL);

	if (vm->crash_msg != NULL) {
		free(vm->crash_msg);
	}

	vm->crash_msg	  = NULL;
	vm->crash_msg_len = 0U;
}

static void
vm_mgnt_handle_set_crash_msg(vmid_t client_id, uint32_t msg_id,
			     uint16_t seq_num, void *buf, size_t len)
{
	rm_error_t ret;

	if (len < 4U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_t *vm = vm_lookup(client_id);
	assert(vm != NULL);

	uint8_t *buf8	 = (uint8_t *)buf;
	uint16_t msg_len = buf8[0] | (uint16_t)((uint16_t)buf8[1] << 8);

	size_t msg_align_len = util_balign_up(msg_len, 4U);
	if (((msg_align_len + 4U)) != len) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *msg_buf = buf8 + 4;
	uint32_t pad	 = 0;
	if (memcmp(msg_buf + msg_len, (uint8_t *)&pad,
		   (msg_align_len - (size_t)msg_len)) != 0) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	// Truncate if message is too big
	if (msg_len > (uint16_t)VM_MAX_CRASH_MSG_LEN) {
		msg_len = (uint16_t)VM_MAX_CRASH_MSG_LEN;
	}

	char *crash_msg = calloc(1, msg_len);
	if (crash_msg == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}

	if (vm->crash_msg != NULL) {
		free(vm->crash_msg);
	}

	(void)memscpy((uint8_t *)crash_msg, msg_len, msg_buf, msg_len);

	vm->crash_msg	  = crash_msg;
	vm->crash_msg_len = msg_len;
	ret		  = RM_OK;

out:
	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static void
vm_mgnt_handle_get_type(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			size_t len)
{
	rm_error_t ret;

	if (len != 0U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint32_t host_ret = 0x64U |		      // AArch64
			    ((uint32_t)0x1 << 8U) |   // Gunyah + RM
			    ((uint32_t)0x00 << 16U) | // Res 0
			    ((uint32_t)0x01 << 24U);  // Ver 1

	rm_reply(client_id, msg_id, seq_num, &host_ret, 4);
	ret = RM_OK;

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static void
vm_mgnt_handle_get_id(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		      void *buf, size_t len)
{
	rm_error_t ret;

	if (len != 4U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *buf8 = (uint8_t *)buf;
	vmid_t	 vmid = buf8[0] | (vmid_t)((vmid_t)buf8[1] << 8);
	if (vmid == 0U) {
		vmid = client_id;
	}

	vm_t *vm = vm_lookup(vmid);
	if (vm == NULL) {
		ret = RM_ERROR_NORESOURCE;
		goto out;
	}

	if ((vm->vm_state != VM_STATE_READY) &&
	    (vm->vm_state != VM_STATE_RUNNING) &&
	    (vm->vm_state != VM_STATE_PAUSED)) {
		ret = RM_ERROR_VM_STATE;
		goto out;
	}

	if (!is_vm_query_allowed(vm, client_id)) {
		ret = RM_ERROR_NORESOURCE;
		goto out;
	}

	// The reply always returns at least the VM's GUID.
	uint32_t id_entries  = 1U;
	size_t	 id_msg_size = 12U + (size_t)VM_GUID_LEN;
	uint16_t id_size;

	size_t name_len	      = vm->name_len;
	size_t name_align_len = util_balign_up(name_len, 4U);
	if (name_len != 0U) {
		id_entries++;
		id_msg_size += 4U + name_align_len;
	}

	size_t uri_len	     = vm->uri_len;
	size_t uri_align_len = util_balign_up(uri_len, 4U);
	if (uri_len != 0U) {
		id_entries++;
		id_msg_size += 4U + uri_align_len;
	}

	// add VM signing authority
	const char *sign_auth =
		platform_get_sign_authority_string(vm->signer_info);
	if (sign_auth == NULL) {
		// sign auth is mandatory
		ret = RM_ERROR_VALIDATE_FAILED;
		goto out;
	}

	size_t sign_auth_len	   = strlen(sign_auth);
	size_t sign_auth_align_len = util_balign_up(sign_auth_len, 4U);
	id_entries++;
	id_msg_size += 4U + sign_auth_align_len;

	uint8_t *id_msg = calloc(1, id_msg_size);
	if (id_msg == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}

	ret	      = RM_OK;
	size_t offset = 0U;
	offset += memscpy(&id_msg[offset], id_msg_size - offset,
			  (uint8_t *)&ret, sizeof(rm_error_t));
	offset += memscpy(&id_msg[offset], id_msg_size - offset,
			  (uint8_t *)&id_entries, sizeof(id_entries));

	id_msg[offset] = (uint8_t)VM_ID_TYPE_GUID;
	offset += 2U;
	id_size = VM_GUID_LEN;
	offset += memscpy(&id_msg[offset], id_msg_size - offset,
			  (uint8_t *)&id_size, sizeof(id_size));
	offset += memscpy(&id_msg[offset], id_msg_size - offset, vm->guid,
			  sizeof(vm->guid));

	if (name_len != 0U) {
		id_msg[offset] = (uint8_t)VM_ID_TYPE_NAME;
		offset += 2U;
		id_size = (uint16_t)name_len;
		offset += memscpy(&id_msg[offset], id_msg_size - offset,
				  (uint8_t *)&id_size, sizeof(uint16_t));
		offset += memscpy(&id_msg[offset], id_msg_size - offset,
				  (uint8_t *)vm->name, name_len);
		offset += (name_align_len - name_len);
	}

	if (uri_len != 0U) {
		id_msg[offset] = (uint8_t)VM_ID_TYPE_URI;
		offset += 2U;
		id_size = (uint16_t)uri_len;
		offset += memscpy(&id_msg[offset], id_msg_size - offset,
				  (uint8_t *)&id_size, sizeof(uint16_t));
		offset += memscpy(&id_msg[offset], id_msg_size - offset,
				  (uint8_t *)vm->uri, uri_len);
		offset += (uri_align_len - uri_len);
	}

	id_msg[offset] = (uint8_t)VM_ID_TYPE_SIGN_AUTH;
	offset += 2U;
	offset += memscpy(&id_msg[offset], id_msg_size - offset,
			  (uint8_t *)&sign_auth_len, sizeof(uint16_t));
	offset += memscpy(&id_msg[offset], id_msg_size - offset,
			  (const uint8_t *)sign_auth, sign_auth_len);
	offset += (sign_auth_align_len - sign_auth_len);

	assert(offset == id_msg_size);

	ret = rm_rpc_fifo_reply(client_id, msg_id, seq_num, id_msg,
				id_msg_size);
	if (ret != RM_OK) {
		free(id_msg);
		panic("rm_rpc_fifo_reply failed");
	}

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static bool
cmp_uri(const vm_t *vm, const uint8_t *uri, size_t uri_len)
{
	return (vm->uri_len == uri_len) &&
	       (memcmp((const uint8_t *)(vm->uri), uri, uri_len) == 0);
}

static bool
cmp_guid(const vm_t *vm, const uint8_t *guid, size_t guid_len)
{
	assert(guid_len == VM_GUID_LEN);

	return memcmp(vm->guid, guid, VM_GUID_LEN) == 0;
}

static bool
cmp_name(const vm_t *vm, const uint8_t *name, size_t name_len)
{
	return (vm->name_len == name_len) &&
	       (memcmp((const uint8_t *)vm->name, name, name_len) == 0);
}

error_t
vm_register_peers(vm_t *vm1, vm_t *vm2)
{
	error_t ret = OK;

	// Add to peer list only if it has not been previously registered
	size_t cnt = vector_size(vm1->peers);
	for (index_t i = 0; i < cnt; i++) {
		vm_t **vm = vector_at_ptr(vm_t *, vm1->peers, i);
		if ((*vm) == vm2) {
			goto already_registered;
		}
	}

	ret = vector_push_back(vm1->peers, vm2);
	if (ret != OK) {
		ret = ERROR_NOMEM;
		goto err_register;
	}

	ret = vector_push_back(vm2->peers, vm1);
	if (ret != OK) {
		(void)vector_pop_back(vm_t *, vm1->peers);
		ret = ERROR_NOMEM;
		goto err_register;
	}

err_register:
already_registered:
	return ret;
}

void
vm_deregister_all_peers(vm_t *vm)
{
	while (!vector_is_empty(vm->peers)) {
		// Delete peers from VM list
		vm_t  *peer    = NULL;
		vm_t **temp_vm = vector_pop_back(vm_t *, vm->peers);
		if (temp_vm != NULL) {
			peer = *temp_vm;
		}

		if (peer == NULL) {
			continue;
		}

		// Delete VM from peers list
		size_t cnt = vector_size(peer->peers);
		for (index_t i = 0; i < cnt; i++) {
			vm_t **vm_search =
				vector_at_ptr(vm_t *, peer->peers, i);
			if ((*vm_search) == vm) {
				vector_delete(peer->peers, i);
				break;
			}
		}
	}
}

void
vm_deregister_peers(vm_t *vm1, vm_t *vm2)
{
	size_t cnt = vector_size(vm1->peers);
	for (index_t i = 0; i < cnt; i++) {
		vm_t **vm_search = vector_at_ptr(vm_t *, vm1->peers, i);
		if ((*vm_search) == vm2) {
			vector_delete(vm1->peers, i);
			break;
		}
	}

	cnt = vector_size(vm2->peers);
	for (index_t i = 0; i < cnt; i++) {
		vm_t **vm_search = vector_at_ptr(vm_t *, vm2->peers, i);
		if ((*vm_search) == vm1) {
			vector_delete(vm2->peers, i);
			break;
		}
	}
}

typedef bool (*id_cmp_t)(const vm_t *vm, const uint8_t *id_buf, size_t id_len);

RM_PADDED(struct check_vm_data {
	vm_t	      *vm;
	const uint8_t *id_buf;
	id_cmp_t       id_cmp;
	uint16_t       id_len;
})

static bool
check_vm_id(dict_key_t key, void *d, void *x)
{
	struct check_vm_data *c = (struct check_vm_data *)x;
	assert(c != NULL);

	vm_t *vm = (vm_t *)d;
	(void)key;

	assert(vm != NULL);
	assert(c->id_cmp != NULL);

	bool ret;
	if (c->id_cmp(vm, c->id_buf, c->id_len)) {
		c->vm = vm;
		// Found a matching VM, stop iteration
		ret = true;
	} else {
		ret = false;
	}
	return ret;
}

vm_t *
vm_lookup_by_id(const char *peer_id)
{
	vm_t *ret;
	assert(all_vms != NULL);

	peer_info_t info;

	if (peer_id == NULL) {
		(void)printf("Error: Null peer_id for vm_lookup_by_id\n");
		ret = NULL;
		goto out;
	}

	error_t parse_ret = vm_mgnt_parse_peer_id(peer_id, &info);
	if (parse_ret != OK) {
		// It may be dangerous to print peer_id here
		size_t len = strnlen(peer_id, 80U);
		(void)printf("Error: failed to parse peer id:\n");
		if ((len > 0U) && (len < 80U)) {
			(void)printf("%s\n", peer_id);
		}
		ret = NULL;
		goto out;
	}

	uint8_t		     guid[VM_GUID_LEN];
	struct check_vm_data c = { 0 };
	bool		     valid;

	switch (info.id_type) {
	case VM_ID_TYPE_GUID: {
		error_t parse_guid_ret = parse_guid_string(info.id_buf, &guid);
		if (parse_guid_ret == OK) {
			c.id_cmp = cmp_guid;
			c.id_buf = guid;
			c.id_len = VM_GUID_LEN;
			valid	 = true;
		} else {
			(void)printf("Error: failed to parse guid from %s\n",
				     info.id_buf);
			valid = false;
		}
		break;
	}
	case VM_ID_TYPE_URI:
		c.id_cmp = cmp_uri;
		c.id_buf = (const uint8_t *)info.id_buf;
		c.id_len = info.id_len;
		valid	 = true;
		break;
	case VM_ID_TYPE_NAME:
		c.id_cmp = cmp_name;
		c.id_buf = (const uint8_t *)info.id_buf;
		c.id_len = info.id_len;
		valid	 = true;
		break;
	case VM_ID_TYPE_SIGN_AUTH:
	default:
		(void)printf("Error: Invalid ID type %d\n", info.id_type);
		valid = false;
		break;
	}
	if (valid) {
		c.vm = NULL;
		(void)dict_iterate(all_vms, &check_vm_id, &c);
		ret = c.vm;
	} else {
		ret = NULL;
	}

out:
	return ret;
}

static rm_error_t
vm_mgnt_lookup_by_id(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		     uint8_t *id_buf, uint16_t id_len, id_cmp_t id_cmp)
{
	rm_error_t err;

	assert(all_vms != NULL);
	assert(id_buf != NULL);

	// Use a bitmap to track matching VMs.
	uint32_t vm_count = 0;

	// It isn't best that we have to iterate the dict twice.
	// Consider optimizing this.
	dict_key_t key;
	vm_t	  *vm;
	dict_foreach(vm, key, all_vms)
	{
		if ((vm == NULL) || !is_vm_query_allowed(vm, client_id)) {
			continue;
		}

		if (id_cmp(vm, id_buf, id_len)) {
			vm_count++;
		}
	}

	size_t	 ret_size = 8U + (4U * (size_t)vm_count);
	uint8_t *ret_buf  = calloc(1, ret_size);
	if (ret_buf == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	uint8_t *buf8 = ret_buf;
	err	      = RM_OK;
	(void)memscpy(buf8, ret_size, (uint8_t *)&err, sizeof(rm_error_t));
	buf8 += 4;
	(void)memscpy(buf8, ret_size - sizeof(uint32_t), (uint8_t *)&vm_count,
		      sizeof(uint32_t));
	buf8 += 4;

	dict_foreach(vm, key, all_vms)
	{
		if ((vm == NULL) || !is_vm_query_allowed(vm, client_id) ||
		    !id_cmp(vm, id_buf, id_len)) {
			continue;
		}

		(void)memscpy(buf8, ret_size - sizeof(uint64_t),
			      (uint8_t *)&vm->vmid, sizeof(vmid_t));
		buf8 += 4;
		assert(buf8 <= (ret_buf + ret_size));
	}

	err = rm_rpc_fifo_reply(client_id, msg_id, seq_num, ret_buf, ret_size);
	if (err != RM_OK) {
		free(ret_buf);
		panic("rm_rpc_fifo_reply failed");
	}
out:
	return err;
}

static void
vm_mgnt_handle_lookup_uri(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			  void *buf, size_t len)
{
	rm_error_t ret;

	if (buf == NULL) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (len < 4U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *buf8	 = (uint8_t *)buf;
	uint16_t uri_len = buf8[0] | (uint16_t)((uint16_t)buf8[1] << 8);
	if (uri_len > (uint16_t)(VM_MAX_URI_LEN - 1)) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	size_t uri_align_len = util_balign_up(uri_len, 4U);
	if ((uri_align_len + 4U) != len) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *uri = buf8 + 4;
	uint32_t pad = 0;
	if (memcmp(uri + uri_len, (uint8_t *)&pad, uri_align_len - uri_len) !=
	    0) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	ret = vm_mgnt_lookup_by_id(client_id, msg_id, seq_num, uri, uri_len,
				   cmp_uri);
out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static void
vm_mgnt_handle_lookup_guid(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			   void *buf, size_t len)
{
	rm_error_t ret;

	if (buf == NULL) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (len != (size_t)VM_GUID_LEN) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	ret = vm_mgnt_lookup_by_id(client_id, msg_id, seq_num, (uint8_t *)buf,
				   VM_GUID_LEN, cmp_guid);
out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static void
vm_mgnt_handle_lookup_name(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			   void *buf, size_t len)
{
	rm_error_t ret;

	if (buf == NULL) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (len < 4U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *buf8	  = (uint8_t *)buf;
	uint16_t name_len = buf8[0] | (uint16_t)((uint16_t)buf8[1] << 8);
	if (name_len > (uint16_t)(VM_MAX_NAME_LEN - 1)) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	size_t name_align_len = util_balign_up(name_len, 4U);
	if ((name_align_len + 4U) != len) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *name = buf8 + 4;
	uint32_t pad  = 0;
	if (memcmp(name + name_len, (uint8_t *)&pad,
		   name_align_len - name_len) != 0) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	ret = vm_mgnt_lookup_by_id(client_id, msg_id, seq_num, name, name_len,
				   cmp_name);
out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

static void
vm_mgnt_handle_set_time_base(vmid_t client_id, uint32_t msg_id,
			     uint16_t seq_num, void *buf, size_t len)
{
	vmid_t	   vmid;
	rm_error_t ret	   = RM_ERROR_MSG_INVALID;
	error_t	   hvc_err = ERROR_ARGUMENT_INVALID;

	if (len == 20U) {
		uint16_t *buf16 = (uint16_t *)buf;
		vmid		= buf16[0];
		if (vmid == 0U) {
			vmid = client_id;
		}

		vm_t *vm = vm_lookup(vmid);
		if (vm == NULL) {
			ret = RM_ERROR_NORESOURCE;
			goto out;
		}
		if (!is_vm_query_allowed(vm, client_id)) {
			ret = RM_ERROR_DENIED;
			goto out;
		}

		if ((vm->vm_state != VM_STATE_INIT) &&
		    (vm->vm_state != VM_STATE_READY)) {
			ret = RM_ERROR_VM_STATE;
			goto out;
		}

		uint32_t *buf32	    = (uint32_t *)buf;
		uint64_t  time_base = ((uint64_t)buf32[2] << 32) |
				     (uint64_t)buf32[1];
		uint64_t sys_timer_ref = ((uint64_t)buf32[4] << 32) |
					 (uint64_t)buf32[3];

		hvc_err = vm_config_vrtc_set_time_base(vm, time_base,
						       sys_timer_ref);
		if (hvc_err == OK) {
			ret = RM_OK;
		} else {
			ret = RM_ERROR_ARGUMENT_INVALID;
		}
	}

out:
	if (ret == RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	} else {
		rm_reply_error(client_id, msg_id, seq_num, ret, &hvc_err, 4);
	}
}

static void
vm_mgnt_handle_set_firmware_mem(vmid_t client_id, uint32_t msg_id,
				uint16_t seq_num, void *buf, size_t len)
{
	rm_error_t ret;

	if (len != sizeof(vm_set_firmware_mem_t)) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_set_firmware_mem_t *msg = (vm_set_firmware_mem_t *)buf;
	if (msg->res0 != 0U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_t *vm = vm_lookup(msg->target);
	if (vm == NULL) {
		ret = RM_ERROR_NORESOURCE;
		goto out;
	}

	if (!is_vm_query_allowed(vm, client_id)) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (vm->vm_state != VM_STATE_INIT) {
		ret = RM_ERROR_VM_STATE;
		goto out;
	}

	ret = vm_firmware_vm_set_mem(vm, msg->fw_mp_handle, msg->fw_offset,
				     msg->fw_size);

out:
	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static void
vm_mgnt_handle_set_debug(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			 void *buf, size_t len)
{
	rm_error_t ret;

	if (len != sizeof(vm_set_debug_t)) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_set_debug_t *msg = (vm_set_debug_t *)buf;
	if ((msg->res0 != 0U) || (msg->debug_enabled > 1U)) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_t *vm = vm_lookup(msg->target);
	if (vm == NULL) {
		ret = RM_ERROR_NORESOURCE;
		goto out;
	}

	if ((client_id != vm->vmid) && (client_id != vm->owner)) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (vm->vm_state != VM_STATE_INIT) {
		ret = RM_ERROR_VM_STATE;
		goto out;
	}

	if (platform_get_security_state()) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	vm->debug_enabled = msg->debug_enabled != 0U;
	ret		  = RM_OK;

out:
	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static void
vm_mgnt_handle_set_demand_paging(vmid_t client_id, uint32_t msg_id,
				 uint16_t seq_num, void *buf, size_t len)
{
	rm_error_t ret = RM_ERROR_MSG_INVALID;

	if (len < sizeof(vm_set_demand_paging_t)) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_set_demand_paging_t *msg = (vm_set_demand_paging_t *)buf;
	if (msg->res0_0 != 0U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}
	vm_set_demand_paging_range_t *ranges =
		(vm_set_demand_paging_range_t *)(void *)(msg + 1U);

	if (util_mult_integer_overflows(msg->range_count, sizeof(ranges[0])) ||
	    util_add_overflows((size_t)msg->range_count * sizeof(ranges[0]),
			       sizeof(*msg)) ||
	    (len < ((msg->range_count * sizeof(ranges[0])) + sizeof(*msg)))) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_t *vm = vm_lookup(msg->target);
	if (vm == NULL) {
		ret = RM_ERROR_NORESOURCE;
		goto out;
	}

	if ((client_id != vm->owner) || (vm->vm_state != VM_STATE_INIT) ||
	    (vm->auth_type == VM_AUTH_TYPE_PLATFORM)) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (vm->vm_config->mem_demand_paging) {
		// Can't enable dynamic paging twice
		ret = RM_ERROR_BUSY;
		goto out;
	}

	assert(vm->vm_config->mem_demand_paged_ranges == NULL);
	vm->vm_config->mem_demand_paged_ranges =
		vector_init(struct mem_range, msg->range_count, 1U);
	if (vm->vm_config->mem_demand_paged_ranges == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}
	for (index_t i = 0; i < msg->range_count; i++) {
		struct mem_range r = { .base = ranges[i].paged_base,
				       .size = ranges[i].paged_size };

		if (!util_is_baligned(r.base, PAGE_SIZE) ||
		    !util_is_baligned(r.size, PAGE_SIZE) || (r.size == 0U)) {
			ret = RM_ERROR_ARGUMENT_INVALID;
			goto out_vector_deinit;
		}

		error_t err = vector_push_back(
			vm->vm_config->mem_demand_paged_ranges, r);
		if (err != OK) {
			ret = rm_error_from_hyp(err);
			goto out_vector_deinit;
		}
	}

	vm->vm_config->mem_demand_paging = true;
	ret				 = RM_OK;
	goto out;

out_vector_deinit:
	vector_deinit(vm->vm_config->mem_demand_paged_ranges);
	vm->vm_config->mem_demand_paged_ranges = NULL;
out:
	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static void
vm_mgnt_handle_set_address_layout(vmid_t client_id, uint32_t msg_id,
				  uint16_t seq_num, void *buf, size_t len)
{
	rm_error_t ret = RM_ERROR_MSG_INVALID;

	if (len != sizeof(vm_set_address_layout_t)) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_set_address_layout_t *msg = (vm_set_address_layout_t *)buf;
	if (msg->res0_0 != 0U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_t *vm = vm_lookup(msg->target);
	if ((vm == NULL) || (vm->vm_config == NULL)) {
		ret = RM_ERROR_NORESOURCE;
		goto out;
	}

	if ((client_id != vm->owner) || (vm->vm_state != VM_STATE_INIT)) {
		ret = RM_ERROR_DENIED;
		goto out;
	}

	if (!util_is_baligned(msg->range_base, PAGE_SIZE) ||
	    !util_is_baligned(msg->range_size, PAGE_SIZE) ||
	    (msg->range_size == 0U) ||
	    util_add_overflows(msg->range_base, msg->range_size)) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	switch (msg->range_id) {
	case (uint32_t)ADDRESS_LAYOUT_RANGE_IMAGE:
		vm->vm_config->mem_ipa_base = msg->range_base;
		vm->vm_config->mem_size_max = msg->range_size;
		ret			    = RM_OK;
		break;
	case (uint32_t)ADDRESS_LAYOUT_RANGE_FIRMWARE:
		vm->vm_config->fw_ipa_base = msg->range_base;
		vm->vm_config->fw_size_max = msg->range_size;
		ret			   = RM_OK;
		break;
	default:
		ret = RM_ERROR_ARGUMENT_INVALID;
		break;
	}

out:
	rm_standard_reply(client_id, msg_id, seq_num, ret);
}

static void
vm_mgnt_handle_get_vmid(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len)
{
	rm_error_t ret;

	if (len != 0U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint32_t vmid_ret = client_id;

	rm_reply(client_id, msg_id, seq_num, &vmid_ret, sizeof(vmid_ret));
	ret = RM_OK;

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}

	(void)buf;
}

static void
vm_mgnt_handle_get_owner(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			 void *buf, size_t len)
{
	rm_error_t ret;

	if (len != 0U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_t *client = vm_lookup(client_id);
	assert(client != NULL);

	uint32_t owner_ret = client->owner;
	rm_reply(client_id, msg_id, seq_num, &owner_ret, sizeof(owner_ret));
	ret = RM_OK;

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}

	(void)buf;
}

static void
vm_mgnt_handle_get_peers(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			 void *buf, size_t len)
{
	rm_error_t ret;

	if (len != 0U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	vm_t *client = vm_lookup(client_id);
	assert(client != NULL);

	uint16_t  peers_cnt = (uint16_t)vector_size(client->peers);
	uint32_t *peer_list;
	size_t	  ret_size = sizeof(uint32_t) + (peers_cnt * sizeof(uint32_t));
	uint32_t *buf32	   = calloc(1, ret_size);

	if (buf32 == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out;
	}

	*buf32	  = peers_cnt;
	peer_list = (buf32 + 1);

	for (index_t i = 0; i < peers_cnt; i++) {
		vm_t **vm = vector_at_ptr(vm_t *, client->peers, i);
		assert(*vm != NULL);
		peer_list[i] = (*vm)->vmid;
	}

	rm_reply(client_id, msg_id, seq_num, buf32, ret_size);
	free(buf32);

	ret = RM_OK;

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}

	(void)buf;
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
		vm_mgnt_handle_deallocate(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_START:
		vm_mgnt_handle_start(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_STOP:
		vm_mgnt_handle_stop(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_RESET:
		vm_mgnt_handle_reset(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_EXIT:
		vm_mgnt_handle_exit(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_GET_STATE:
		vm_mgnt_handle_get_state(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_SET_STATUS:
		vm_mgnt_handle_set_state(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_GET_CRASH_MSG:
		vm_mgnt_handle_get_crash_msg(client_id, msg_id, seq_num, buf,
					     len);
		handled = true;
		break;
	case VM_SET_CRASH_MSG:
		vm_mgnt_handle_set_crash_msg(client_id, msg_id, seq_num, buf,
					     len);
		handled = true;
		break;
	case VM_HOST_GET_TYPE:
		vm_mgnt_handle_get_type(client_id, msg_id, seq_num, len);
		handled = true;
		break;
	case VM_GET_ID:
		vm_mgnt_handle_get_id(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_LOOKUP_URI:
		vm_mgnt_handle_lookup_uri(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_LOOKUP_GUID:
		vm_mgnt_handle_lookup_guid(client_id, msg_id, seq_num, buf,
					   len);
		handled = true;
		break;
	case VM_LOOKUP_NAME:
		vm_mgnt_handle_lookup_name(client_id, msg_id, seq_num, buf,
					   len);
		handled = true;
		break;
	case VM_SET_TIME_BASE:
		vm_mgnt_handle_set_time_base(client_id, msg_id, seq_num, buf,
					     len);
		handled = true;
		break;
	case VM_SET_FIRMWARE_MEM:
		vm_mgnt_handle_set_firmware_mem(client_id, msg_id, seq_num, buf,
						len);
		handled = true;
		break;
	case VM_SET_DEMAND_PAGING:
		vm_mgnt_handle_set_demand_paging(client_id, msg_id, seq_num,
						 buf, len);
		handled = true;
		break;
	case VM_SET_ADDRESS_LAYOUT:
		vm_mgnt_handle_set_address_layout(client_id, msg_id, seq_num,
						  buf, len);
		handled = true;
		break;
	case VM_SET_DEBUG:
		vm_mgnt_handle_set_debug(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_GET_VMID:
		vm_mgnt_handle_get_vmid(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_GET_OWNER:
		vm_mgnt_handle_get_owner(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_GET_PEERS:
		vm_mgnt_handle_get_peers(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	default:
		// all msg_id are handled
		break;
	}

out:
	return handled;
}

static error_t
vm_mgnt_parse_peer_id(const char *peer_id, peer_info_t *info)
{
	error_t	    ret;
	const char *id_val = NULL;

	assert((peer_id != NULL) && (info != NULL));

	// Sanity check, ID isn't be longer than 128
#define ID_MAX 128U
	size_t len = strnlen(peer_id, ID_MAX);
	if ((len == 0U) || (len == ID_MAX)) {
		ret = ERROR_FAILURE;
		goto out;
	}

	size_t prefix = 0U;

	// Find the ':' separator for the id_type
	for (index_t i = 0U; i < util_min(len, 8U); i++) {
		if (peer_id[i] == ':') {
			prefix = i;
			break;
		}
	}
	if (prefix == 0U) {
		// no ':' found
		ret = ERROR_FAILURE;
		goto out;
	}

	size_t id_len = len - prefix - 1U;
	if (id_len == 0U) {
		// No id string
		ret = ERROR_FAILURE;
		goto out;
	}

	id_val = &peer_id[prefix + 1U];

	// Check for known prefixes
	if (strncmp(peer_id, "vm-guid:", prefix) == 0) {
		info->id_type = VM_ID_TYPE_GUID;
		ret	      = (id_len >= 32U) ? OK : ERROR_FAILURE;
	} else if (strncmp(peer_id, "vm-name:", prefix) == 0) {
		info->id_type = VM_ID_TYPE_NAME;
		ret	      = (id_len >= 1U) ? OK : ERROR_FAILURE;
	} else if (strncmp(peer_id, "vm-uri:", prefix) == 0) {
		info->id_type = VM_ID_TYPE_URI;

		// Very basic URI validation
		index_t sep = 0U;

		// Find the first '/' separator
		for (index_t i = 0U; i < id_len; i++) {
			if (id_val[i] == '/') {
				sep = i;
				break;
			}
		}
		if ((sep == 0U) || (sep == id_len)) {
			// Not a "domain/path"
			ret = ERROR_FAILURE;
			goto out;
		}
		index_t dot = 0U;
		// Check domain has a dot, e.g.: "xyz.com"
		for (index_t i = 0U; i < sep; i++) {
			if (id_val[i] == '.') {
				dot = i;
				break;
			}
		}
		if ((dot == 0U) || (dot == sep)) {
			// Not a "domain.xyz"
			ret = ERROR_FAILURE;
			goto out;
		}

		ret = OK;
	} else {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	assert(id_val != NULL);
	info->id_buf = id_val;
	info->id_len = (uint16_t)id_len;

	ret = OK;

out:
	return ret;
}

bool
vm_mgnt_is_vm_sensitive(vmid_t vmid)
{
	bool ret;

	// assume RM is sensitive VM
	if (vmid == VMID_RM) {
		ret = true;
		goto out;
	}

	// should find the VM
	vm_t *vm = vm_lookup(vmid);
	assert(vm != NULL);

	ret = vm->sensitive;
out:
	return ret;
}

static void
watchdog_bite_callback(event_t *event, void *data)
{
	(void)event;

	vm_t *vm = (vm_t *)data;
	assert(vm != NULL);

	if (vm->crash_fatal) {
		(void)printf("WDOG bite: VM %d\n", vm->vmid);
		panic("unexpected exit from crash_fatal VM");
	}

	// Ignore if VM has already exited
	if (vm->vm_state >= VM_STATE_EXITED) {
		(void)printf("WDOG bite: VM %d has already exited\n", vm->vmid);
		goto out;
	}

	vm_config_handle_exit(vm);

	vm_mgnt_update_vm_state(vm, VM_STATE_EXITED);
	vm_mgnt_set_exit_type(vm, EXIT_TYPE_WATCHDOG_BITE);

	exit_code_t exit_code = (vm->crash_msg != NULL)
					? EXIT_CODE_SOFTWARE_ERROR
					: EXIT_CODE_NORMAL;

	(void)printf("watchdog bite: VM %u, exit_code %d\n", vm->vmid,
		     exit_code);

	vm_mgnt_set_cleanup_type(vm, NULL);
	if (vm_mgnt_send_exited(vm, 0U, exit_code, 0U, NULL) != RM_OK) {
		(void)printf("WDOG bite: Failed to send exited notification\n");
	}

out:
	return;
}

static void
vcpu_halt_callback(event_t *event, void *data)
{
	rm_error_t err = RM_OK;
	(void)event;

	vcpu_t *vcpu = (vcpu_t *)data;

	vm_t *vm = vm_lookup(vcpu->vmid);
	assert(vm != NULL);

	if (vm->crash_fatal) {
		(void)printf("VCPU halt: VM %d\n", vm->vmid);
		panic("unexpected exit from crash_fatal VM");
	}

	// Ignore if VM has already exited
	if (vm->vm_state >= VM_STATE_EXITED) {
		(void)printf("VCPU halt: VM %d has already exited\n", vm->vmid);
		goto out;
	}

	gunyah_hyp_vcpu_run_check_result_t res;
	res = gunyah_hyp_vcpu_run_check(vcpu->master_cap);
	assert(res.error == OK);

	exit_type_t exit_type;
	uint16_t    exit_flags = 0U;
	exit_code_t exit_code  = (vm->crash_msg != NULL)
					 ? EXIT_CODE_SOFTWARE_ERROR
					 : EXIT_CODE_NORMAL;

	uint32_t extra_size	 = 0U;
	uint32_t extra_reason[4] = { 0U };

	switch (res.vcpu_state) {
	case VCPU_RUN_STATE_POWERED_OFF:
		exit_type = EXIT_TYPE_PLATFORM_OFF;
		break;
	case VCPU_RUN_STATE_PSCI_SYSTEM_RESET:
		// The first state data word contains a PSCI reset type value.
		// Bits 31:0, reset type for PSCI_SYSTEM_RESET2 and 0 for
		// PSCI_SYSTEM_RESET.
		// Bits 63, 1 for PSCI_SYSTEM_RESET call and 0 for
		// PSCI_SYSTEM_RESET2 call. For a PSCI_SYSTEM_RESET2 call, the
		// second state data word contains the cookie value.
		if ((res.state_data_0 & util_bit(63)) != 0U) {
			exit_type = EXIT_TYPE_PLATFORM_RESET;
		} else {
			// Arm PSCI SYSTEM_RESET2
			// exit_reason is the reset type followed by the cookie
			uint32_t reset_type = (uint32_t)res.state_data_0;
			uint64_t cookie	    = res.state_data_1;

			bool is_64bit = (res.state_data_0 & util_bit(62)) != 0U;

			if (is_64bit) {
				exit_flags |= (uint16_t)util_bit(15);
			} else {
				cookie = cookie & 0xffffffffU;
			}

			exit_type	= EXIT_TYPE_PSCI_SYSTEM_RESET2;
			extra_size	= 3U;
			extra_reason[0] = reset_type;
			extra_reason[1] = (uint32_t)cookie;
			extra_reason[2] = (uint32_t)(cookie >> 32);
		}
		break;
	case VCPU_RUN_STATE_FAULT:
		exit_type = EXIT_TYPE_SOFTWARE_ERROR;
		break;
	case VCPU_RUN_STATE_READY:
	case VCPU_RUN_STATE_EXPECTS_WAKEUP:
	case VCPU_RUN_STATE_BLOCKED:
	case VCPU_RUN_STATE_ADDRSPACE_VMMIO_READ:
	case VCPU_RUN_STATE_ADDRSPACE_VMMIO_WRITE:
	case VCPU_RUN_STATE_ADDRSPACE_PAGE_FAULT:
	default:
		(void)printf("unexpected run_stated %d\n", res.vcpu_state);
		exit_type = EXIT_TYPE_SOFTWARE_ERROR;
		exit_code = EXIT_CODE_UNKNOWN_ERROR;
		break;
	}

	vm_config_handle_exit(vm);

	vm_mgnt_update_vm_state(vm, VM_STATE_EXITED);
	vm_mgnt_set_exit_type(vm, exit_type);

	(void)printf(
		"VM exited: VM %d exit_type %d,exit_flags = %x, exit_code %d\n",
		vm->vmid, exit_type, exit_flags, exit_code);

	vm_mgnt_set_cleanup_type(vm, extra_reason);
	err = vm_mgnt_send_exited(vm, exit_flags, exit_code, extra_size,
				  extra_reason);
	if (err != RM_OK) {
		(void)printf("VCPU halt: Failed to send exited notification\n");
	}

out:
	return;
}

rm_error_t
vm_mgnt_register_event(vm_event_src_t event_src, event_t *event, void *data,
		       virq_t virq)
{
	rm_error_t	 err = RM_OK;
	event_callback_t callback;

	switch (event_src) {
	case VM_EVENT_SRC_WDOG_BITE:
		callback = watchdog_bite_callback;
		break;
	case VM_EVENT_SRC_VCPU_HALT:
		callback = vcpu_halt_callback;
		break;
	default:
		err = RM_ERROR_ARGUMENT_INVALID;
		break;
	}

	if (err != RM_OK) {
		goto out;
	}

	error_t ret = event_register(event, callback, data);
	assert(ret == OK);

	err = register_event_isr(virq, event);
	if (err != RM_OK) {
		goto err_register_event_isr;
	}

err_register_event_isr:
	if (err != RM_OK) {
		(void)event_deregister(event);
	}

out:
	return err;
}

void
vm_mgnt_deregister_event(event_t *event, virq_t virq)
{
	(void)deregister_isr(virq);

	(void)event_deregister(event);
}
