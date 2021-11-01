// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef uint32_t rm_error_t;

#define RM_OK			  ((rm_error_t)0x0U)
#define RM_ERROR_UNIMPLEMENTED	  ((rm_error_t)0xffffffffU)
#define RM_ERROR_NOMEM		  ((rm_error_t)0x1U)
#define RM_ERROR_NORESOURCE	  ((rm_error_t)0x2U)
#define RM_ERROR_DENIED		  ((rm_error_t)0x3U)
#define RM_ERROR_MSG_INVALID	  ((rm_error_t)0x4U)
#define RM_ERROR_BUSY		  ((rm_error_t)0x5U)
#define RM_ERROR_ARGUMENT_INVALID ((rm_error_t)0x6U)
#define RM_ERROR_HANDLE_INVALID	  ((rm_error_t)0x7U)
#define RM_ERROR_VALIDATE_FAILED  ((rm_error_t)0x8U)
#define RM_ERROR_MAP_FAILED	  ((rm_error_t)0x9U)
#define RM_ERROR_MEM_INVALID	  ((rm_error_t)0xaU)
#define RM_ERROR_MEM_INUSE	  ((rm_error_t)0xbU)
#define RM_ERROR_MEM_RELEASED	  ((rm_error_t)0xcU)
#define RM_ERROR_VMID_INVALID	  ((rm_error_t)0xdU)
#define RM_ERROR_LOOKUP_FAILED	  ((rm_error_t)0xeU)
#define RM_ERROR_IRQ_INVALID	  ((rm_error_t)0xfU)
#define RM_ERROR_IRQ_INUSE	  ((rm_error_t)0x10U)
#define RM_ERROR_IRQ_RELEASED	  ((rm_error_t)0x11U)
#define RM_ERROR_IN_USE		  ((rm_error_t)0x12U)
#define RM_ERROR_IRQ_NOT_MAPPED	  ((rm_error_t)0x13U)

#define RM_RPC_MESSAGE_SIZE 240U

#define RM_RPC_API_VERSION   1U
#define RM_RPC_HEADER_SIZE   8U
#define RM_RPC_HEADER_WORDS  (RM_RPC_HEADER_SIZE / 4U)
#define RM_RPC_MAX_CONTENT   (RM_RPC_MESSAGE_SIZE - RM_RPC_HEADER_SIZE)
#define RM_RPC_MAX_FRAGMENTS 62U
#define RM_RPC_MAX_MSG_SIZE  (RM_RPC_MAX_CONTENT * (RM_RPC_MAX_FRAGMENTS + 1))

#define RM_RPC_MSG_TYPE_CONTINUED    0
#define RM_RPC_MSG_TYPE_REQUEST	     1
#define RM_RPC_MSG_TYPE_REPLY	     2
#define RM_RPC_MSG_TYPE_NOTIFICATION 3

rm_error_t
rm_rpc_init_server(vmid_t my_id);

rm_error_t
rm_rpc_server_add_link(vmid_t client_id);

rm_error_t
rm_rpc_server_remove_link(vmid_t client_id);

// Macros to instruct the compiler not to warn about padding. These should only
// be used on structures that are either internal to the RM or else have been
// unmarshalled from a packed on-the-wire representation.
#define RM_PADDED_BEGIN                                                        \
	_Pragma("clang diagnostic push")                                       \
	_Pragma("clang diagnostic ignored \"-Wpadded\"")
#define RM_PADDED_END _Pragma("clang diagnostic pop")

#define RM_PADDED(struct_body)                                                 \
	RM_PADDED_BEGIN                                                        \
	struct_body;                                                           \
	RM_PADDED_END

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
			 size_t len, size_t alloc_size);

rm_error_t
rm_rpc_reply(vmid_t vm_id, uint32_t msg_id, uint16_t seq_num, void *buf,
	     size_t len, size_t alloc_size);

// Free a message buffer allocated by rm-rpc.
void
rm_rpc_free(void *buf, size_t size);

typedef void (*rm_rpc_msg_callback_t)(vmid_t vm_id, uint32_t msg_id,
				      uint16_t seq_num, uint8_t msg_type,
				      void *buf, size_t len, size_t alloc_size);

rm_error_t
rm_rpc_register_msg_handler(rm_rpc_msg_callback_t callback);

typedef void (*rm_rpc_notif_callback_t)(vmid_t vm_id, uint32_t notification_id,
					void *buf, size_t len,
					size_t alloc_size);

rm_error_t
rm_rpc_register_notif_handler(rm_rpc_notif_callback_t callback);

typedef void (*rm_rpc_tx_callback_t)(rm_error_t tx_err, vmid_t vm_id, void *buf,
				     size_t len, size_t alloc_size);

// Register a handler which is called when a TX has finished.
// If additional TX needs to be performed, an event must be triggered; the
// rm-rpc library will reject any attempts to TX in the callback.
rm_error_t
rm_rpc_register_tx_complete_handler(rm_rpc_tx_callback_t callback);

void
rm_rpc_wait(int suspend_timeout);
