// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <rm-rpc.h>

#include <resource-manager.h>

#include <event.h>
#include <fcntl.h>
#include <guest_interface.h>
#include <uapi/interrupt.h>
#include <unistd.h>
#include <utils/list.h>
#include <utils/vector.h>
#include <vm_config.h>

#include "rm-rpc-internal.h"

struct rm_rpc_transport {
	struct rm_rpc_transport *next;
	struct rm_rpc_transport *prev;

	vmid_t	vm_id;
	uint8_t vm_id_padding[6];

	cap_id_t tx_capid;
	cap_id_t rx_capid;

	event_t tx_event;
	event_t rx_event;

	rm_rpc_tx_data_t tx_data;
	rm_rpc_rx_data_t rx_data;
};

typedef struct rm_rpc_transport rm_rpc_transport_t;

static rm_rpc_transport_t *transport_list;

static vmid_t transport_id;

static void
takedown_transport(rm_rpc_transport_t *transport, vmid_t my_id,
		   vmid_t other_id);

static void
msgqueue_tx_callback(event_t *event, void *data)
{
	(void)event;
	rm_rpc_transport_t *transport = (rm_rpc_transport_t *)data;
	rm_rpc_tx_callback(transport->vm_id, &transport->tx_data);
}

static void
msgqueue_rx_callback(event_t *event, void *data)
{
	(void)event;
	rm_rpc_transport_t *transport = (rm_rpc_transport_t *)data;
	rm_rpc_rx_callback(transport->vm_id, &transport->rx_data);
}

static rm_error_t
init_transport(rm_rpc_transport_t *transport, vmid_t my_id, vmid_t other_id)
{
	rm_error_t err = RM_OK;

	transport->vm_id = other_id;

	// find the cap id for send and receive capid
	vm_config_get_rm_rpc_msg_queue_info_ret info_ret =
		vm_config_get_rm_rpc_msg_queue_info(my_id, other_id);

	if (info_ret.err != RM_OK) {
		err = info_ret.err;
		goto err_out;
	}

	transport->tx_capid = info_ret.tx_capid;
	transport->rx_capid = info_ret.rx_capid;

	error_t ret = event_register(&transport->tx_event, msgqueue_tx_callback,
				     transport);
	if (ret != OK) {
		err = RM_ERROR_DENIED;
		goto err_out;
	}

	err = register_event_isr(info_ret.tx_virq, &transport->tx_event);
	if (err != RM_OK) {
		goto err_tx_event;
	}

	ret = event_register(&transport->rx_event, msgqueue_rx_callback,
			     transport);
	if (ret != OK) {
		err = RM_ERROR_DENIED;
		goto err_rx_virq;
	}

	err = register_event_isr(info_ret.rx_virq, &transport->rx_event);
	if (err != RM_OK) {
		goto err_rx_event;
	}

	rm_rpc_init_rx_data(transport->vm_id, &transport->rx_data);
	rm_rpc_init_tx_data(transport->vm_id, &transport->tx_data);

err_rx_event:
	if (err != RM_OK) {
		(void)event_deregister(&transport->rx_event);
	}
err_rx_virq:
	if (err != RM_OK) {
		deregister_isr(info_ret.tx_virq);
	}
err_tx_event:
	if (err != RM_OK) {
		(void)event_deregister(&transport->tx_event);
	}
err_out:
	return err;
}

rm_error_t
rm_rpc_init_server_transport(vmid_t my_id)
{
	rm_error_t err = RM_OK;

	transport_id = my_id;

	error_t ret = event_init();
	if (ret != OK) {
		err = RM_ERROR_DENIED;
	}

	return err;
}

static rm_rpc_transport_t *
rm_rpc_get_transport(vmid_t vm_id)
{
	rm_rpc_transport_t *transport = NULL, *curr;

	loop_list(curr, &transport_list, )
	{
		if (curr->vm_id == vm_id) {
			transport = curr;
			break;
		}
	}

	return transport;
}

rm_rpc_rx_data_t *
rm_rpc_get_rx_data(vmid_t vm_id)
{
	rm_rpc_rx_data_t	 *data      = NULL;
	rm_rpc_transport_t *transport = rm_rpc_get_transport(vm_id);

	if (transport != NULL) {
		data = &transport->rx_data;
	}

	return data;
}

rm_rpc_tx_data_t *
rm_rpc_get_tx_data(vmid_t vm_id)
{
	rm_rpc_tx_data_t	 *data      = NULL;
	rm_rpc_transport_t *transport = rm_rpc_get_transport(vm_id);

	if (transport != NULL) {
		data = &transport->tx_data;
	}

	return data;
}

rm_error_t
rm_rpc_send_packet(rm_rpc_tx_data_t *tx, void *buf, size_t len)
{
	rm_rpc_transport_t *transport;
	error_t		    err;
	rm_error_t	    rm_err;

	transport =
		(rm_rpc_transport_t *)((uintptr_t)tx -
				       offsetof(rm_rpc_transport_t, tx_data));

	if (len > RM_RPC_MESSAGE_SIZE) {
		rm_err = RM_ERROR_MSG_INVALID;
		goto send_packet_return;
	}

	if (transport->vm_id != VMID_HYP) {
		gunyah_hyp_msgqueue_send_result_t send_ret;
		send_ret = gunyah_hyp_msgqueue_send(
			transport->tx_capid, len, (user_ptr_t)buf,
			msgqueue_send_flags_default());
		err = send_ret.error;
	} else {
		err = ERROR_ARGUMENT_INVALID;
	}

	if (err == OK) {
		rm_err = RM_OK;
	} else if (err == ERROR_MSGQUEUE_FULL) {
		rm_err = RM_ERROR_BUSY;
	} else {
		// FIXME: return correct error
		rm_err = RM_ERROR_DENIED;
	}

send_packet_return:
	return rm_err;
}

rm_error_t
rm_rpc_recv_packet(rm_rpc_rx_data_t *rx, void *buf, size_t *len)
{
	rm_rpc_transport_t *transport;
	error_t		    err;
	size_t		    recv_size;
	rm_error_t	    rm_err;

	assert(len != NULL);

	transport =
		(rm_rpc_transport_t *)((uintptr_t)rx -
				       offsetof(rm_rpc_transport_t, rx_data));

	if (*len < RM_RPC_MESSAGE_SIZE) {
		rm_err = RM_ERROR_MSG_INVALID;
		goto recv_packet_return;
	}

	if (transport->vm_id != VMID_HYP) {
		gunyah_hyp_msgqueue_receive_result_t recv_ret;
		recv_ret  = gunyah_hyp_msgqueue_receive(transport->rx_capid,
							(user_ptr_t)buf,
							RM_RPC_MESSAGE_SIZE);
		err	  = recv_ret.error;
		recv_size = recv_ret.size;
	} else {
		err	  = ERROR_ARGUMENT_INVALID;
		recv_size = 0U;
	}

	if (err == OK) {
		rm_err = RM_OK;
		*len   = recv_size;
	} else if (err == ERROR_MSGQUEUE_EMPTY) {
		rm_err = RM_ERROR_BUSY;
	} else {
		// FIXME: return correct error
		rm_err = RM_ERROR_DENIED;
	}

recv_packet_return:
	return rm_err;
}

rm_error_t
rm_rpc_server_add_link(vmid_t client_id)
{
	rm_error_t err;

	if (rm_rpc_get_transport(client_id) != NULL) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	rm_rpc_transport_t *t = malloc(sizeof(rm_rpc_transport_t));
	if (t == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	err = init_transport(t, transport_id, client_id);
	if (err == RM_OK) {
		list_append(rm_rpc_transport_t, &transport_list, t, );
	} else {
		free(t);
	}

out:
	return err;
}

rm_error_t
rm_rpc_server_remove_link(vmid_t client_id)
{
	rm_error_t	    err = RM_OK;
	rm_rpc_transport_t *t	= rm_rpc_get_transport(client_id);
	if (t == NULL) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	list_remove(rm_rpc_transport_t, &transport_list, t, );
	takedown_transport(t, transport_id, client_id);
out:
	return err;
}

void
takedown_transport(rm_rpc_transport_t *transport, vmid_t my_id, vmid_t other_id)
{
	// find the cap id for send and receive capid
	vm_config_get_rm_rpc_msg_queue_info_ret info_ret =
		vm_config_get_rm_rpc_msg_queue_info(my_id, other_id);

	if (info_ret.err != RM_OK) {
		goto out;
	}

	deregister_isr(info_ret.rx_virq);
	(void)event_deregister(&transport->rx_event);

	deregister_isr(info_ret.tx_virq);
	(void)event_deregister(&transport->tx_event);

out:
	return;
}
