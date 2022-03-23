// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <rm-rpc.h>

#include <errno.h>
#include <event.h>
#include <unistd.h>
#include <utils/list.h>

#include "rm-rpc-internal.h"

#define PATH_LEN 30

typedef struct rm_rpc_transport rm_rpc_transport_t;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

struct rm_rpc_transport {
	vmid_t		    vm_id;
	rm_rpc_transport_t *next;
	rm_rpc_transport_t *prev;
	int		    tx_fd;
	int		    rx_fd;
	event_t		    tx_event;
	event_t		    rx_event;
	rm_rpc_tx_data_t    tx_data;
	rm_rpc_rx_data_t    rx_data;
	struct sockaddr_un  tx_addr;
};

#pragma clang diagnostic pop

static rm_rpc_transport_t *transport_list;
static vmid_t		   transport_id;

static int
open_socket(rm_rpc_transport_t *transport, const char *path, bool rx)
{
	int sock_fd, ret = 0;

	if (rx) {
		unlink(path);
	}

	sock_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (sock_fd < 0) {
		perror("Failed to create socket");
		goto open_socket_return;
	}

	if (rx) {
		struct sockaddr_un addr;
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strlcpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

		ret = bind(sock_fd, (const struct sockaddr *)&addr,
			   sizeof(struct sockaddr_un));
		if (ret < 0) {
			perror("Failed to bind socket");
			goto open_socket_return;
		}
	} else {
		memset(&transport->tx_addr, 0, sizeof(transport->tx_addr));
		transport->tx_addr.sun_family = AF_UNIX;
		strlcpy(transport->tx_addr.sun_path, path,
			sizeof(transport->tx_addr.sun_path) - 1);
	}

open_socket_return:
	if (ret < 0) {
		close(sock_fd);
		sock_fd = -1;
	}

	return sock_fd;
}

rm_error_t
rm_rpc_send_packet(rm_rpc_tx_data_t *tx, void *buf, size_t len)
{
	rm_rpc_transport_t *transport;
	rm_error_t	    err;
	ssize_t		    bytes;

	transport =
		(rm_rpc_transport_t *)((uintptr_t)tx -
				       offsetof(rm_rpc_transport_t, tx_data));

	if (len > RM_RPC_MESSAGE_SIZE) {
		err = RM_ERROR_MSG_INVALID;
		goto send_packet_return;
	}

	bytes = sendto(transport->tx_fd, buf, len, 0,
		       (struct sockaddr *)&transport->tx_addr,
		       sizeof(struct sockaddr_un));
	if (bytes == (ssize_t)len) {
		err = RM_OK;
	} else if (bytes >= 0) {
		printf("Only sent %ld/%lu bytes!\n", bytes, len);
		err = RM_ERROR_BUSY;
	} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
		err = RM_ERROR_BUSY;
	} else {
		perror("Failed to send packet");
		err = RM_ERROR_DENIED;
	}

send_packet_return:
	return err;
}

rm_error_t
rm_rpc_recv_packet(rm_rpc_rx_data_t *rx, void *buf, size_t *len)
{
	rm_rpc_transport_t *transport;
	rm_error_t	    err;

	assert(len != NULL);

	transport =
		(rm_rpc_transport_t *)((uintptr_t)rx -
				       offsetof(rm_rpc_transport_t, rx_data));

	if (*len < RM_RPC_MESSAGE_SIZE) {
		err = RM_ERROR_MSG_INVALID;
		goto recv_packet_return;
	}

	ssize_t bytes = recv(transport->rx_fd, buf, RM_RPC_MESSAGE_SIZE, 0);

	if (bytes >= 0) {
		err  = RM_OK;
		*len = (size_t)bytes;
	} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
		err = RM_ERROR_BUSY;
	} else {
		perror("Failed to recv packet");
		err = RM_ERROR_DENIED;
	}

recv_packet_return:
	return err;
}

static void
transport_tx_callback(event_t *event, void *data)
{
	(void)event;
	rm_rpc_transport_t *transport = (rm_rpc_transport_t *)data;
	rm_rpc_tx_callback(transport->vm_id, &transport->tx_data);
}

static void
transport_rx_callback(event_t *event, void *data)
{
	(void)event;
	rm_rpc_transport_t *transport = (rm_rpc_transport_t *)data;
	rm_rpc_rx_callback(transport->vm_id, &transport->rx_data);
}

static void
get_socket_paths(vmid_t my_id, vmid_t other_id, char path[2][PATH_LEN])
{
	snprintf(path[0], PATH_LEN, "/tmp/rm-rpc-%d-%d", my_id, other_id);
	snprintf(path[1], PATH_LEN, "/tmp/rm-rpc-%d-%d", other_id, my_id);
}

static rm_error_t
init_transport(rm_rpc_transport_t *transport, vmid_t my_id, vmid_t other_id)
{
	char	   path[2][PATH_LEN];
	int	   tx_fd = -1, rx_fd = -1;
	error_t	   err;
	rm_error_t rm_err = RM_OK;

	get_socket_paths(my_id, other_id, path);

	transport->vm_id = other_id;

	tx_fd = open_socket(transport, path[0], false);
	if (tx_fd < 0) {
		rm_err = RM_ERROR_DENIED;
		goto init_transport_return;
	}

	rx_fd = open_socket(transport, path[1], true);
	if (rx_fd < 0) {
		rm_err = RM_ERROR_DENIED;
		goto init_transport_return;
	}

	transport->tx_fd = tx_fd;
	transport->rx_fd = rx_fd;

	err = event_register(&transport->tx_event, transport_tx_callback,
			     transport);
	if (err != OK) {
		rm_err = RM_ERROR_DENIED;
		goto init_transport_return;
	}

	err = event_set_fd_trigger(&transport->tx_event, tx_fd, EVENT_FD_WRITE);
	if (err != OK) {
		rm_err = RM_ERROR_DENIED;
		goto init_transport_return;
	}

	err = event_register(&transport->rx_event, transport_rx_callback,
			     transport);
	if (err != OK) {
		rm_err = RM_ERROR_DENIED;
		goto init_transport_return;
	}

	err = event_set_fd_trigger(&transport->rx_event, rx_fd, EVENT_FD_READ);
	if (err != OK) {
		rm_err = RM_ERROR_DENIED;
		goto init_transport_return;
	}

	rm_rpc_init_rx_data(transport->vm_id, &transport->rx_data);
	rm_rpc_init_tx_data(transport->vm_id, &transport->tx_data);

init_transport_return:
	if (rm_err != RM_OK) {
		if (tx_fd >= 0) {
			close(tx_fd);
		}

		if (rx_fd >= 0) {
			close(rx_fd);
		}
	}

	return rm_err;
}

static void
takedown_transport(rm_rpc_transport_t *transport, vmid_t my_id, vmid_t other_id)
{
	char path[2][PATH_LEN];

	get_socket_paths(my_id, other_id, path);

	(void)event_deregister(&transport->rx_event);
	(void)event_deregister(&transport->tx_event);

	(void)close(transport->tx_fd);
	(void)close(transport->rx_fd);

	(void)unlink(path[0]);
	(void)unlink(path[1]);
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

rm_error_t
rm_rpc_server_add_link(vmid_t client_id)
{
	rm_error_t err;

	if (rm_rpc_get_transport(client_id) != NULL) {
		err = RM_ERROR_DENIED;
		goto out;
	}

	rm_rpc_transport_t *t = calloc(1, sizeof(rm_rpc_transport_t));
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
rm_rpc_init_server_transport(vmid_t my_id)
{
	rm_error_t err = RM_OK;

	transport_id = my_id;

	if (event_init() != OK) {
		err = RM_ERROR_NORESOURCE;
	}

	return err;
}
