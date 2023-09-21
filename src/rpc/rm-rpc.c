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

#include <rm_types.h>
#include <util.h>

#include <event.h>
#include <rm-rpc.h>

#include "rm-rpc-internal.h"

static uint8_t transport_buf[RM_RPC_MESSAGE_SIZE];

static bool in_tx_cb;

static rm_rpc_msg_callback_t   msg_cb;
static rm_rpc_notif_callback_t notif_cb;
static rm_rpc_tx_callback_t    tx_cb;

rm_error_t
rm_rpc_init_server(vmid_t my_id)
{
	return rm_rpc_init_server_transport(my_id);
}

static rm_rpc_header_t
create_rpc_header(uint8_t msg_type, size_t num_fragments, uint16_t seq_num,
		  uint32_t msg_id)
{
	rm_rpc_header_t hdr;

	assert(num_fragments < 0x63);

	hdr.api_version	  = RM_RPC_API_VERSION;
	hdr.header_words  = RM_RPC_HEADER_WORDS;
	hdr.msg_type	  = msg_type;
	hdr.num_fragments = (uint8_t)num_fragments;
	hdr.seq_num	  = seq_num;
	hdr.msg_id	  = msg_id;

	return hdr;
}

static void
write_rpc_header(uint8_t *buf, rm_rpc_header_t hdr)
{
	buf[0] = (uint8_t)((hdr.header_words << 4) | hdr.api_version);
	buf[1] = (uint8_t)(hdr.num_fragments << 2) | hdr.msg_type;
	buf[2] = (uint8_t)(hdr.seq_num & 0xffU);
	buf[3] = (uint8_t)((hdr.seq_num >> 8) & 0xffU);
	buf[4] = (uint8_t)(hdr.msg_id & 0xffU);
	buf[5] = (uint8_t)((hdr.msg_id >> 8) & 0xffU);
	buf[6] = (uint8_t)((hdr.msg_id >> 16) & 0xffU);
	buf[7] = (uint8_t)((hdr.msg_id >> 24) & 0xffU);
}

static rm_error_t
read_rpc_header(uint8_t *buf, rm_rpc_header_t *hdr)
{
	rm_error_t err = RM_OK;

	assert(hdr != NULL);

	hdr->api_version   = buf[0] & 0xfU;
	hdr->header_words  = (buf[0] >> 4) & 0xfU;
	hdr->msg_type	   = buf[1] & 0x3U;
	hdr->num_fragments = (buf[1] >> 2) & 0x3fU;
	hdr->seq_num	   = (uint16_t)(((uint16_t)buf[3] << 8) | buf[2]);
	hdr->msg_id = ((uint32_t)buf[7] << 24) | ((uint32_t)buf[6] << 16) |
		      ((uint32_t)buf[5] << 8) | (uint32_t)buf[4];

	if ((hdr->api_version != RM_RPC_API_VERSION) ||
	    (hdr->header_words != RM_RPC_HEADER_WORDS) ||
	    (hdr->num_fragments > RM_RPC_MAX_FRAGMENTS)) {
		err = RM_ERROR_MSG_INVALID;
	}

	return err;
}

static uint16_t
get_next_seq_num(void)
{
	static uint16_t seq_num = 0;

	return seq_num++;
}

void
rm_rpc_init_rx_data(vmid_t vm_id, rm_rpc_rx_data_t *rx_data)
{
	(void)vm_id;
	(void)memset(rx_data, 0, sizeof(*rx_data));
}

void
rm_rpc_init_tx_data(vmid_t vm_id, rm_rpc_tx_data_t *tx_data)
{
	(void)vm_id;
	(void)memset(tx_data, 0, sizeof(*tx_data));
}

static void
do_xmit(vmid_t vm_id, rm_rpc_tx_data_t *tx_data)
{
	rm_error_t err = RM_OK;

	while (tx_data->rem > 0U) {
		size_t	size;
		uint8_t msg_type = (tx_data->rem == tx_data->num_fragments + 1U)
					   ? tx_data->msg_type
					   : RM_RPC_MSG_TYPE_CONTINUED;

		rm_rpc_header_t hdr =
			create_rpc_header(msg_type, tx_data->num_fragments,
					  tx_data->seq_num, tx_data->msg_id);
		write_rpc_header(transport_buf, hdr);

		size_t rem_len = tx_data->len - tx_data->pos;
		if (rem_len > 0U) {
			size = (RM_RPC_MAX_CONTENT > rem_len)
				       ? rem_len
				       : RM_RPC_MAX_CONTENT;
			(void)memcpy(transport_buf + RM_RPC_HEADER_SIZE,
				     tx_data->buf + tx_data->pos, size);
		} else {
			size = 0;
		}

		err = rm_rpc_send_packet(tx_data, transport_buf,
					 size + RM_RPC_HEADER_SIZE);
		if (err == RM_OK) {
			tx_data->rem--;
			tx_data->pos += size;
		} else if (err == RM_ERROR_BUSY) {
			// Try later
			break;
		} else {
			(void)printf("send_packet error\n");
			exit(1);
		}
	}

	if ((tx_data->rem == 0U) && (tx_cb != NULL)) {
		in_tx_cb = true;
		tx_cb(err, vm_id, tx_data->buf, tx_data->len);
		in_tx_cb = false;
	}
}

void
rm_rpc_tx_callback(vmid_t vm_id, rm_rpc_tx_data_t *tx_data)
{
	if (tx_data->rem != 0U) {
		do_xmit(vm_id, tx_data);
	}
}

static rm_error_t
start_xmit(vmid_t vm_id, uint8_t msg_type, uint32_t msg_id, uint16_t seq_num,
	   void *buf, size_t len)
{
	rm_error_t	  err;
	rm_rpc_tx_data_t *tx_data = rm_rpc_get_tx_data(vm_id);
	if (tx_data == NULL) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	if ((tx_data->rem != 0U) || in_tx_cb) {
		err = RM_ERROR_BUSY;
		goto out;
	}

	size_t num_fragments = (len > 0U)
				       ? (((len + (RM_RPC_MAX_CONTENT - 1U)) /
					   RM_RPC_MAX_CONTENT) -
					  1U)
				       : 0U;
	assert(num_fragments <= RM_RPC_MAX_FRAGMENTS);

	tx_data->rem	       = num_fragments + 1U;
	tx_data->msg_id	       = msg_id;
	tx_data->seq_num       = seq_num;
	tx_data->num_fragments = (uint8_t)num_fragments;
	tx_data->msg_type      = msg_type;
	tx_data->buf	       = buf;
	tx_data->len	       = len;
	tx_data->pos	       = 0;

	do_xmit(vm_id, tx_data);
	err = RM_OK;

out:
	return err;
}

static rm_error_t
do_recv(vmid_t vm_id, rm_rpc_rx_data_t *rx_data)
{
	rm_error_t err;
	uint8_t	  *recv_buf    = transport_buf;
	size_t	   len	       = RM_RPC_MESSAGE_SIZE;
	bool	   do_callback = false;

	err = rm_rpc_recv_packet(rx_data, recv_buf, &len);
	if (err != RM_OK) {
		goto do_recv_return;
	}

	if (len < RM_RPC_HEADER_SIZE) {
		// Packet too small, drop it
		err = RM_OK;
		goto do_recv_return;
	}

	rm_rpc_header_t hdr;
	err = read_rpc_header(recv_buf, &hdr);
	if (err != RM_OK) {
		// Invalid header, drop packet
		err = RM_OK;
		goto do_recv_return;
	}

	uint32_t msg_id	       = hdr.msg_id;
	uint16_t seq_num       = hdr.seq_num;
	uint8_t	 num_fragments = hdr.num_fragments;
	uint8_t	 msg_type      = hdr.msg_type;

	recv_buf += RM_RPC_HEADER_SIZE;
	len -= RM_RPC_HEADER_SIZE;

	if (msg_type != RM_RPC_MSG_TYPE_CONTINUED) {
		if (rx_data->partial) {
			// Drop the old buffer.
			free(rx_data->buf);
			rx_data->buf	 = NULL;
			rx_data->partial = false;
		}

		size_t alloc_size = (num_fragments == 0U)
					    ? len
					    : (((size_t)num_fragments + 1U) *
					       RM_RPC_MAX_CONTENT);
		assert(len <= alloc_size);

		uint8_t *data_buf = NULL;

		if (alloc_size > 0U) {
			data_buf = malloc(alloc_size);
			if (data_buf == NULL) {
				(void)printf(
					"rm-rpc: Failed to allocate recv buffer "
					"for VM %d, message ID %lx\n",
					(uint32_t)vm_id, (unsigned long)msg_id);
				err = RM_OK;
				goto do_recv_return;
			}

			if (len != 0U) {
				(void)memcpy(data_buf, recv_buf, len);
			}
		}

		if (num_fragments == 0U) {
			do_callback = true;
		} else {
			rx_data->rem_fragments = num_fragments;
			rx_data->num_fragments = num_fragments;
			rx_data->partial       = true;
		}

		rx_data->buf	    = data_buf;
		rx_data->len	    = len;
		rx_data->alloc_size = alloc_size;

		rx_data->msg_id	  = msg_id;
		rx_data->seq_num  = seq_num;
		rx_data->msg_type = msg_type;
	} else {
		if (!rx_data->partial) {
			// Drop the packet
			err = RM_OK;
			goto do_recv_return;
		}

		// Check consistent
		if ((msg_id != rx_data->msg_id) ||
		    (seq_num != rx_data->seq_num) ||
		    (num_fragments != rx_data->num_fragments)) {
			// Drop the packet
			err = RM_OK;
			goto do_recv_return;
		}

		assert((rx_data->len + len) <= rx_data->alloc_size);

		uint8_t *data_buf = rx_data->buf + rx_data->len;
		(void)memcpy(data_buf, recv_buf, len);
		rx_data->rem_fragments--;
		rx_data->len += len;

		if (rx_data->rem_fragments == 0U) {
			do_callback	 = true;
			rx_data->partial = false;
		}
	}

	if (do_callback) {
		assert(!rx_data->partial);

		if (rx_data->msg_type == RM_RPC_MSG_TYPE_NOTIFICATION) {
			if (notif_cb != NULL) {
				notif_cb(vm_id, rx_data->msg_id, rx_data->buf,
					 rx_data->len);
			} else {
				free(rx_data->buf);
			}
		} else {
			assert(rx_data->msg_type != RM_RPC_MSG_TYPE_CONTINUED);
			if (msg_cb != NULL) {
				msg_cb(vm_id, msg_id, seq_num,
				       rx_data->msg_type, rx_data->buf,
				       rx_data->len);
			} else {
				free(rx_data->buf);
			}
		}

		rx_data->buf = NULL;
	}

do_recv_return:
	return err;
}

void
rm_rpc_rx_callback(vmid_t vm_id, rm_rpc_rx_data_t *rx_data)
{
	rm_error_t err;

	do {
		err = do_recv(vm_id, rx_data);
	} while (err == RM_OK);
}

rm_error_t
rm_rpc_send_notification(vmid_t vm_id, uint32_t notification_id, void *buf,
			 size_t len)
{
	rm_error_t err;

	if (len <= RM_RPC_MAX_MSG_SIZE) {
		err = start_xmit(vm_id, RM_RPC_MSG_TYPE_NOTIFICATION,
				 notification_id, get_next_seq_num(), buf, len);
	} else {
		err = RM_ERROR_MSG_INVALID;
	}

	return err;
}

rm_error_t
rm_rpc_reply(vmid_t vm_id, uint32_t msg_id, uint16_t seq_num, void *buf,
	     size_t len)
{
	rm_error_t err;

	if (len > RM_RPC_MAX_MSG_SIZE) {
		err = RM_ERROR_MSG_INVALID;
		goto rpc_reply_return;
	}

	err = start_xmit(vm_id, RM_RPC_MSG_TYPE_REPLY, msg_id, seq_num, buf,
			 len);

rpc_reply_return:
	return err;
}

void
rm_rpc_free(void *buf)
{
	if (buf != NULL) {
		free(buf);
	}
}

rm_error_t
rm_rpc_register_msg_handler(rm_rpc_msg_callback_t callback)
{
	msg_cb = callback;

	return RM_OK;
}

rm_error_t
rm_rpc_register_notif_handler(rm_rpc_notif_callback_t callback)
{
	notif_cb = callback;

	return RM_OK;
}

rm_error_t
rm_rpc_register_tx_complete_handler(rm_rpc_tx_callback_t callback)
{
	tx_cb = callback;

	return RM_OK;
}

void
rm_rpc_wait(int32_t suspend_timeout)
{
	event_loop_enter_suspend(suspend_timeout);
}

rm_error_t
rm_rpc_read_list(uint8_t *buf, size_t len, uint16_t *entries,
		 const uint32_t max_entries, uintptr_t *list, size_t entry_size,
		 uint8_t **next_buf)
{
	rm_error_t err = RM_OK;

	assert(buf != NULL);
	assert(entries != NULL);
	assert(list != NULL);
	assert(entry_size != 0);
	assert(next_buf != NULL);

	assert(!util_add_overflows((uintptr_t)buf, len));

	uintptr_t curr	     = (uintptr_t)buf;
	uintptr_t start	     = curr;
	size_t	  array_size = 0;
	size_t	  buffer_end = start + len;

	*next_buf = buf;
	*entries  = 0U;

	if (curr == buffer_end) {
		err = RM_OK;
		goto out;
	}

	if (buffer_end < (curr + sizeof(uint32_t))) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	// First 16-bits is the list/array size.
	*entries = *(uint16_t *)curr;
	// Second 16-bit is UNKNOWN, may be used in some RPC messages.
	curr += sizeof(uint32_t);

	if (*entries > max_entries) {
		err = RM_ERROR_NORESOURCE;
		goto out;
	}

	array_size = (*entries) * entry_size;

	if (buffer_end < (curr + array_size)) {
		err = RM_ERROR_MSG_INVALID;
		goto out;
	}

	*list = curr;
	curr += util_balign_up(array_size, sizeof(uint32_t));

	*next_buf = (uint8_t *)curr;

out:
	return err;
}
