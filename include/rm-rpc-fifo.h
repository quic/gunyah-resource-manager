// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

rm_error_t
rm_rpc_fifo_init(void);

rm_error_t
rm_rpc_fifo_create(vmid_t peer);

rm_error_t
rm_rpc_fifo_destroy(vmid_t peer);

rm_error_t
rm_rpc_fifo_reply(vmid_t vm_id, uint32_t msg_id, uint16_t seq_num, void *buf,
		  size_t len);

rm_error_t
rm_rpc_fifo_send_notification(vmid_t vm_id, uint32_t notif_id, void *buf,
			      size_t len, bool allow_pending);

void
rm_rpc_fifo_tx_callback(vmid_t vm_id);

void
rm_rpc_fifo_deinit(void);

typedef struct {
	rm_error_t err;
} rm_standard_rep_t;

// Helper function to perform a reply with a specified error and data
// using rm_rpc_fifo_reply().
//
// data input is copied to a new buffer, and may be safely reused when this
// call returns, pointers to stack data are thus also permitted.
void
rm_reply_error(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
	       rm_error_t err, void *data, size_t len);

// Helper function to perform a reply with error RM_OK and data using
// rm_rpc_fifo_reply().
//
// data input is copied to a new buffer, and may be safely reused when this
// call returns, pointers to stack data are thus also permitted.
static inline void
rm_reply(vmid_t client_id, uint32_t msg_id, uint16_t seq_num, void *data,
	 size_t len)
{
	rm_reply_error(client_id, msg_id, seq_num, RM_OK, data, len);
}

// Helper function to perform a standard reply (i.e. send
// an error code) using rm_rpc_fifo_reply().
static inline void
rm_standard_reply(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		  rm_error_t err)
{
	rm_reply_error(client_id, msg_id, seq_num, err, NULL, 0U);
}

// Helper function that takes a copy of data.
void
rm_notify(vmid_t client_id, uint32_t notif_id, void *data, size_t len);

// Helper function to check if a client can receive RM RPC.
bool
rm_can_rpc(vmid_t client_id);
