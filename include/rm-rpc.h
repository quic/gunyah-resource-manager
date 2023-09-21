// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define RM_RPC_MESSAGE_SIZE 240U

#define RM_RPC_API_VERSION   1U
#define RM_RPC_HEADER_SIZE   8U
#define RM_RPC_HEADER_WORDS  (RM_RPC_HEADER_SIZE / 4U)
#define RM_RPC_MAX_CONTENT   (RM_RPC_MESSAGE_SIZE - RM_RPC_HEADER_SIZE)
#define RM_RPC_MAX_FRAGMENTS 62U
#define RM_RPC_MAX_MSG_SIZE  (RM_RPC_MAX_CONTENT * (RM_RPC_MAX_FRAGMENTS + 1U))

#define RM_RPC_MSG_TYPE_CONTINUED    0U
#define RM_RPC_MSG_TYPE_REQUEST	     1U
#define RM_RPC_MSG_TYPE_REPLY	     2U
#define RM_RPC_MSG_TYPE_NOTIFICATION 3U

rm_error_t
rm_error_from_hyp(error_t err);

rm_error_t
rm_rpc_init_server(vmid_t my_id);

rm_error_t
rm_rpc_server_add_link(vmid_t client_id);

rm_error_t
rm_rpc_server_remove_link(vmid_t client_id);

// Note: this is an unpacked version of the RPC header, and is not to be
// directly copied to message buffers without marshalling.
RM_PADDED(typedef struct {
	uint8_t	 api_version;
	uint8_t	 header_words;
	uint8_t	 msg_type;
	uint8_t	 num_fragments;
	uint16_t seq_num;
	uint32_t msg_id;
} rm_rpc_header_t)

rm_error_t
rm_rpc_send_notification(vmid_t vm_id, uint32_t notification_id, void *buf,
			 size_t len);

rm_error_t
rm_rpc_reply(vmid_t vm_id, uint32_t msg_id, uint16_t seq_num, void *buf,
	     size_t len);

// Free a message buffer allocated by rm-rpc.
void
rm_rpc_free(void *buf);

typedef void (*rm_rpc_msg_callback_t)(vmid_t vm_id, uint32_t msg_id,
				      uint16_t seq_num, uint8_t msg_type,
				      void *buf, size_t len);

rm_error_t
rm_rpc_register_msg_handler(rm_rpc_msg_callback_t callback);

typedef void (*rm_rpc_notif_callback_t)(vmid_t vm_id, uint32_t notification_id,
					void *buf, size_t len);

rm_error_t
rm_rpc_register_notif_handler(rm_rpc_notif_callback_t callback);

typedef void (*rm_rpc_tx_callback_t)(rm_error_t tx_err, vmid_t vm_id, void *buf,
				     size_t len);

// Register a handler which is called when a TX has finished.
// If additional TX needs to be performed, an event must be triggered; the
// rm-rpc library will reject any attempts to TX in the callback.
rm_error_t
rm_rpc_register_tx_complete_handler(rm_rpc_tx_callback_t callback);

void
rm_rpc_wait(int suspend_timeout);

// Utility function to get an RM RPC list (array)'s data start address and
// length.
//
// An RM RPC list has a 16-bit length value, followed by a data array starting
// at the next 32-bit aligned boundary.  This helper function gets list length
// and data from the input [buf, buf + len) memory region.
//
// The list's data array start address is returned in `*list`, and length is
// returned in `*entries`. The element size of this list is `entry_size`. The
// list should only contain no more than `max_entries` elements.
//
// A pointer to the address of the next buffer after the list is returned in
// `next_buf`.
//
// Returns `error != RM_OK` on error.
rm_error_t
rm_rpc_read_list(uint8_t *buf, size_t len, uint16_t *entries,
		 uint32_t max_entries, uintptr_t *list, size_t entry_size,
		 uint8_t **next_buf);
