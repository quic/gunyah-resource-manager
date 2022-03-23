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

#include <rm-rpc.h>

#include <event.h>
#include <rm-rpc-fifo.h>
#include <utils/list.h>
#include <utils/vector.h>

#define MAX_NOTIFICATION_PENDING (256U)

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

typedef struct pending_notif {
	struct pending_notif *notif_prev;
	struct pending_notif *notif_next;

	uint32_t notif_id;
	void    *buf;
	size_t	 len;
	size_t	 alloc_size;
} pending_notif_t;

typedef struct {
	vmid_t	vm_id;
	event_t send_pending_event;
	// List of pending notifications
	pending_notif_t *pending_notif_list;
	count_t		 pending_notif_count;
	// We only keep one pending reply, as VMs
	// should wait to receive the reply before
	// making another request.
	void    *reply_buf;
	uint32_t reply_msg_id;
	uint16_t reply_seq_num;
	size_t	 reply_len;
	size_t	 reply_alloc_size;
} fifo_status_t;

typedef struct {
	vector_t *fifo_status;
} fifo_manager_t;

typedef struct {
	fifo_status_t *status;
	index_t	       idx;
} find_fifo_status_ret_t;

#pragma clang diagnostic pop

static fifo_manager_t mngr;

static find_fifo_status_ret_t
find_fifo_status(vmid_t peer);

static void
send_pending_cb(event_t *event, void *data);

rm_error_t
rm_rpc_fifo_init(void)
{
	rm_error_t e = RM_OK;

	mngr.fifo_status = vector_init(fifo_status_t *, 4U, 4U);
	if (mngr.fifo_status == NULL) {
		e = RM_ERROR_NOMEM;
	}

	return e;
}

rm_error_t
rm_rpc_fifo_create(vmid_t peer)
{
	rm_error_t e = RM_OK;

	error_t ret_push = ERROR_NOMEM;

	fifo_status_t *fifo = calloc(1, sizeof(*fifo));
	if (fifo == NULL) {
		e = RM_ERROR_NOMEM;
		goto err;
	}

	fifo->vm_id = peer;

	ret_push = vector_push_back(mngr.fifo_status, fifo);
	if (ret_push != OK) {
		e = RM_ERROR_NOMEM;
		goto err;
	}

	find_fifo_status_ret_t ret = find_fifo_status(peer);
	assert(ret.status != NULL);

	error_t ret_event = event_register(&ret.status->send_pending_event,
					   send_pending_cb, ret.status);
	if (ret_event != OK) {
		e = RM_ERROR_DENIED;
	}
err:
	if (e != RM_OK) {
		if (ret_push == OK) {
			e = rm_rpc_fifo_destroy(peer);
		} else {
			free(fifo);
		}
	}

	return e;
}

rm_error_t
rm_rpc_fifo_destroy(vmid_t peer)
{
	find_fifo_status_ret_t ret = find_fifo_status(peer);
	if (ret.status == NULL) {
		goto out;
	}

	vector_delete(mngr.fifo_status, ret.idx);

	free(ret.status);

out:
	return RM_OK;
}

static rm_error_t
send_pending_reply(fifo_status_t *status)
{
	rm_error_t e;

	assert(status->reply_buf != NULL);

	e = rm_rpc_reply(status->vm_id, status->reply_msg_id,
			 status->reply_seq_num, status->reply_buf,
			 status->reply_len, status->reply_alloc_size);
	if (e == RM_OK) {
		status->reply_buf = NULL;
	}

	return e;
}

static void
delete_pending_notif(fifo_status_t *status, pending_notif_t *n, bool sent)
{
	status->pending_notif_count--;
	list_remove(pending_notif_t, &status->pending_notif_list, n, notif_);
	if (!sent) {
		// If the notification was sent, it will be freed in the RPC
		// TX callback, so we only need to free here if dropped.
		free(n->buf);
	}
	free(n);
}

static void
send_pending_notifications(fifo_status_t *status)
{
	while (status->pending_notif_list != NULL) {
		rm_error_t	 e;
		pending_notif_t *n = status->pending_notif_list;

		e = rm_rpc_send_notification(status->vm_id, n->notif_id, n->buf,
					     n->len, n->alloc_size);
		if (e != OK) {
			break;
		}

		delete_pending_notif(status, n, true);
	}
}

rm_error_t
rm_rpc_fifo_reply(vmid_t vm_id, uint32_t msg_id, uint16_t seq_num, void *buf,
		  size_t len, size_t alloc_size)
{
	rm_error_t	       e;
	find_fifo_status_ret_t find_ret = find_fifo_status(vm_id);

	if (find_ret.status == NULL) {
		e = RM_ERROR_VMID_INVALID;
		goto err;
	}

	fifo_status_t *status = find_ret.status;

	// Try to send any pending reply first
	if (status->reply_buf != NULL) {
		e = send_pending_reply(status);
		// If we couldn't send the pending reply, drop it
		if (e != RM_OK) {
			printf("rm-rpc-fifo: Dropped pending reply for VM %d!\n",
			       (int)vm_id);
			free(status->reply_buf);
			status->reply_buf = NULL;
		}
	}

	e = rm_rpc_reply(vm_id, msg_id, seq_num, buf, len, alloc_size);
	if (e == RM_ERROR_BUSY) {
		// Shouldn't have reply pending here
		assert(status->reply_buf == NULL);
		// Buffer this reply
		status->reply_msg_id	 = msg_id;
		status->reply_seq_num	 = seq_num;
		status->reply_buf	 = buf;
		status->reply_len	 = len;
		status->reply_alloc_size = alloc_size;

		e = RM_OK;
	}

err:
	return e;
}

rm_error_t
rm_rpc_fifo_send_notification(vmid_t vm_id, uint32_t notif_id, void *buf,
			      size_t len, size_t alloc_size, bool allow_pending)
{
	rm_error_t	       e;
	find_fifo_status_ret_t find_ret = find_fifo_status(vm_id);

	if (find_ret.status == NULL) {
		e = RM_ERROR_VMID_INVALID;
		goto err;
	}

	fifo_status_t *status = find_ret.status;

	// Try to send any pending notifications first
	send_pending_notifications(status);

	e = rm_rpc_send_notification(vm_id, notif_id, buf, len, alloc_size);
	if ((e == RM_ERROR_BUSY) && allow_pending) {
		// If we are at max notif count, drop the oldest notification
		if (status->pending_notif_count == MAX_NOTIFICATION_PENDING) {
			printf("rm-rpc-fifo: Dropped pending notif for VM %d!\n",
			       (int)vm_id);
			delete_pending_notif(status, status->pending_notif_list,
					     false);
		}

		pending_notif_t *n = calloc(1, sizeof(*n));
		if (n == NULL) {
			e = RM_ERROR_NOMEM;
			goto err;
		}

		n->notif_id   = notif_id;
		n->buf	      = buf;
		n->len	      = len;
		n->alloc_size = alloc_size;

		list_append(pending_notif_t, &status->pending_notif_list, n,
			    notif_);
		status->pending_notif_count++;

		e = RM_OK;
	}

err:
	return e;
}

void
rm_rpc_fifo_tx_callback(vmid_t vm_id)
{
	find_fifo_status_ret_t find_ret = find_fifo_status(vm_id);
	assert(find_ret.status != NULL);

	fifo_status_t *status = find_ret.status;

	if ((status->reply_buf != NULL) ||
	    (status->pending_notif_list != NULL)) {
		event_trigger(&find_ret.status->send_pending_event);
	}
}

void
rm_rpc_fifo_deinit(void)
{
	size_t cnt = vector_size(mngr.fifo_status);
	for (index_t i = 0; i < cnt; ++i) {
		fifo_status_t *s =
			vector_at(fifo_status_t *, mngr.fifo_status, i);
		while (s->pending_notif_list != NULL) {
			delete_pending_notif(s, s->pending_notif_list, false);
		}

		free(s);
	}

	vector_deinit(mngr.fifo_status);
}

find_fifo_status_ret_t
find_fifo_status(vmid_t peer)
{
	find_fifo_status_ret_t ret = { .status = NULL, .idx = 0U };

	size_t cnt = vector_size(mngr.fifo_status);
	for (index_t i = 0; i < cnt; ++i) {
		fifo_status_t *fs =
			vector_at(fifo_status_t *, mngr.fifo_status, i);
		if (fs->vm_id == peer) {
			ret.status = fs;
			ret.idx	   = i;
			break;
		}
	}

	return ret;
}

void
send_pending_cb(event_t *event, void *data)
{
	rm_error_t     e      = RM_OK;
	fifo_status_t *status = (fifo_status_t *)data;

	(void)event;

	if (status->reply_buf != NULL) {
		e = send_pending_reply(status);
	}

	if (e == RM_OK) {
		send_pending_notifications(status);
	}
}

void
rm_reply_error(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
	       rm_error_t err, void *data, size_t len)
{
	if (len > 0U) {
		assert(data != NULL);
	}

	size_t size    = len + sizeof(rm_standard_rep_t);
	char  *out_buf = malloc(size);

	if (out_buf == NULL) {
		printf("OOM: fail to alloc rm_reply\n");
		exit(1);
	}

	rm_standard_rep_t rep;
	rep.err = err;

	memcpy(out_buf, &rep, sizeof(rm_standard_rep_t));
	if (len > 0U) {
		memcpy(out_buf + sizeof(rm_standard_rep_t), data, len);
	}

	rm_error_t rpc_err = rm_rpc_fifo_reply(client_id, msg_id, seq_num,
					       out_buf, size, size);
	// We cannot recover from errors here
	if (rpc_err != RM_OK) {
		printf("rm_reply: err(%d)\n", rpc_err);
		exit(1);
	}
}

void
rm_notify(vmid_t client_id, uint32_t notif_id, void *data, size_t len)
{
	assert(data != NULL);

	char *out_buf = malloc(len);

	if (out_buf == NULL) {
		printf("OOM: fail to alloc rm_notify\n");
		exit(1);
	}

	memcpy(out_buf, data, len);

	rm_error_t rpc_err = rm_rpc_fifo_send_notification(
		client_id, notif_id, out_buf, len, len, true);
	// We cannot recover from errors here
	if (rpc_err != RM_OK) {
		printf("rm_reply: err(%d)\n", rpc_err);
		exit(1);
	}
}
