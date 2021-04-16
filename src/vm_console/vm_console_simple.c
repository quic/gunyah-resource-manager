// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <asm/arm_smccc.h>
#include <rm-rpc.h>

#include <rm-rpc-fifo.h>
#include <utils/vector.h>
#include <vm_config.h>
#include <vm_console.h>
#include <vm_console_message.h>
#include <vm_mgnt.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

struct vm_console {
	vmid_t self;
	vmid_t owner;
	bool   self_opened;
	bool   owner_opened;
};

#pragma clang diagnostic pop

bool console_allowed = false;

rm_error_t
console_init(void)
{
	// Debug enabled
	console_allowed = true;

	return RM_OK;
}

rm_error_t
vm_console_init(void)
{
	return RM_OK;
}

vm_console_t *
vm_console_create(vm_t *vm)
{
	vm_console_t *console = calloc(1, sizeof(*console));
	if (console == NULL) {
		goto err;
	}

	console->self	      = vm->vmid;
	console->owner	      = vm->owner;
	console->self_opened  = false;
	console->owner_opened = false;

err:
	return console;
}

static vm_console_t *
get_console(vmid_t requester, vmid_t target)
{
	vmid_t self = (target == 0U) ? requester : target;

	return vm_config_get_console(self);
}

static bool
is_console_open(vm_console_t *console, bool owner)
{
	assert(console != NULL);

	return (owner) ? console->owner_opened : console->self_opened;
}

static void
handle_open(vmid_t requester, uint16_t seq_num, vmid_t target)
{
	rm_error_t    err     = RM_OK;
	vm_console_t *console = get_console(requester, target);

	if (console == NULL) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (target == 0U) {
		console->self_opened = true;
	} else if (requester == console->owner) {
		console->owner_opened = true;
	} else {
		err = RM_ERROR_DENIED;
	}

out:
	rm_standard_reply(requester, VM_CONSOLE_OPEN, seq_num, err);
}

static void
handle_close(vmid_t requester, uint16_t seq_num, vmid_t target)
{
	rm_error_t    err     = RM_OK;
	vm_console_t *console = get_console(requester, target);

	if (console == NULL) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (target == 0U) {
		console->self_opened = false;
	} else if (requester == console->owner) {
		console->owner_opened = false;
	} else {
		err = RM_ERROR_DENIED;
	}

out:
	rm_standard_reply(requester, VM_CONSOLE_CLOSE, seq_num, err);
}

static void
handle_write(vmid_t requester, uint16_t seq_num, vmid_t target,
	     uint16_t num_bytes, const uint8_t *content)
{
	rm_error_t    err;
	vm_console_t *console = get_console(requester, target);

	if (console == NULL) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	bool is_owner = requester == console->owner;
	if ((target != 0U) && !is_owner) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	if (!is_console_open(console, is_owner)) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	if (!is_console_open(console, !is_owner)) {
		// FIXME: drop message for now
		err = RM_OK;
		goto out;
	}

	if (!console_allowed) {
		err = RM_OK;
		goto out;
	}

	size_t notif_size = sizeof(vm_console_chars_notify_t) + num_bytes;
	char * notif_buf  = malloc(notif_size);
	if (notif_buf == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	vm_console_chars_notify_t notif = {
		.num_bytes = num_bytes,
		.from	   = (target == 0U) ? console->self : 0U,
	};

	vmid_t to = (target == 0U) ? console->owner : console->self;

	memcpy(notif_buf, &notif, sizeof(notif));
	memcpy(notif_buf + sizeof(notif), content, num_bytes);

	err = rm_rpc_fifo_send_notification(to, NOTIFY_VM_CONSOLE_CHARS,
					    notif_buf, notif_size, notif_size,
					    true);
	if (err != RM_OK) {
		printf("vm_console: Failed to send char notification\n");
		exit(1);
	}

out:
	rm_standard_reply(requester, VM_CONSOLE_WRITE, seq_num, err);
}

static void
handle_flush(vmid_t requester, uint16_t seq_num, vmid_t target)
{
	rm_error_t    err     = RM_OK;
	vm_console_t *console = get_console(requester, target);

	if (console == NULL) {
		err = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}

	bool is_owner = requester == console->owner;
	if ((target != 0U) && !is_owner) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	if (!is_console_open(console, is_owner)) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	if (!console_allowed) {
		err = RM_OK;
	}

	// Chars are sent immediately on write, there is nothing to flush.
	// TODO Wait for pending notifications to be sent.
out:
	rm_standard_reply(requester, VM_CONSOLE_FLUSH, seq_num, err);
}

bool
vm_console_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		       void *buf, size_t len)
{
	bool handled = true;

	switch (msg_id) {
	case VM_CONSOLE_OPEN: {
		vm_console_open_req_t *req = (vm_console_open_req_t *)buf;

		if (len == sizeof(*req)) {
			handle_open(client_id, seq_num, req->target);
		} else {
			rm_standard_reply(client_id, msg_id, seq_num,
					  RM_ERROR_INVALID);
		}

		break;
	}
	case VM_CONSOLE_CLOSE: {
		vm_console_close_req_t *req = (vm_console_close_req_t *)buf;

		if (len == sizeof(*req)) {
			handle_close(client_id, seq_num, req->target);
		} else {
			rm_standard_reply(client_id, msg_id, seq_num,
					  RM_ERROR_INVALID);
		}

		break;
	}
	case VM_CONSOLE_WRITE: {
		vm_console_write_req_t *req = (vm_console_write_req_t *)buf;

		if (len == sizeof(*req) + req->num_bytes) {
			uint8_t *content = (uint8_t *)buf + sizeof(*req);
			handle_write(client_id, seq_num, req->target,
				     req->num_bytes, content);
		} else {
			rm_standard_reply(client_id, msg_id, seq_num,
					  RM_ERROR_INVALID);
		}

		break;
	}
	case VM_CONSOLE_FLUSH: {
		vm_console_flush_req_t *req = (vm_console_flush_req_t *)buf;

		if (len == sizeof(*req)) {
			handle_flush(client_id, seq_num, req->target);
		} else {
			rm_standard_reply(client_id, msg_id, seq_num,
					  RM_ERROR_INVALID);
		}

		break;
	}
	default:
		handled = false;
		break;
	}

	return handled;
}
