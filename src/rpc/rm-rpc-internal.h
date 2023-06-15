// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

typedef struct {
	uint32_t msg_id;
	uint16_t seq_num;
	uint8_t	 num_fragments;
	uint8_t	 msg_type;
	uint8_t *buf;
	size_t	 len;
	size_t	 pos;
	size_t	 rem;
} rm_rpc_tx_data_t;

typedef struct {
	bool	 partial;
	uint32_t msg_id;
	uint16_t seq_num;
	uint8_t	 msg_type;
	uint8_t	 num_fragments;
	uint8_t	 rem_fragments;
	uint8_t *buf;
	size_t	 len;
	size_t	 alloc_size;
} rm_rpc_rx_data_t;

#pragma clang diagnostic pop

// App Layer
void
rm_rpc_init_rx_data(vmid_t vm_id, rm_rpc_rx_data_t *rx_data);

void
rm_rpc_init_tx_data(vmid_t vm_id, rm_rpc_tx_data_t *tx_data);

void
rm_rpc_tx_callback(vmid_t vm_id, rm_rpc_tx_data_t *tx_data);

void
rm_rpc_rx_callback(vmid_t vm_id, rm_rpc_rx_data_t *rx_data);

// Transport Layer
rm_error_t
rm_rpc_init_server_transport(vmid_t my_id);

rm_rpc_rx_data_t *
rm_rpc_get_rx_data(vmid_t vm_id);

rm_rpc_tx_data_t *
rm_rpc_get_tx_data(vmid_t vm_id);

rm_error_t
rm_rpc_send_packet(rm_rpc_tx_data_t *tx, void *buf, size_t len);

rm_error_t
rm_rpc_recv_packet(rm_rpc_rx_data_t *rx, void *buf, size_t *len);
