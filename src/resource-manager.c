// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm-rpc.h>

#include <exit_dev.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <memextent.h>
#include <memparcel.h>
#include <platform.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <uart.h>
#include <util.h>
#include <utils/vector.h>
#include <vm_config.h>
#include <vm_console.h>
#include <vm_creation.h>
#include <vm_mgnt.h>
#include <vm_mgnt_message.h>
#include <vm_resources.h>

#include "rmversion.h"

static boot_env_data_t *priv_env_data;

typedef struct {
	virq_t irq;

	vmid_t	belongs_to;
	uint8_t belongs_to_padding[2];

	cap_id_t irq_cap;
} static_restricted_irq_t;

static hwirq_cap_array_t
rm_get_vic_hwirqs(void);

static void
msg_callback(vmid_t vm_id, uint32_t msg_id, uint16_t seq_num, uint8_t msg_type,
	     void *buf, size_t len, size_t alloc_size)
{
	bool handled;

	if (msg_type != RM_RPC_MSG_TYPE_REQUEST) {
		goto out;
	}

	handled = vm_console_msg_handler(vm_id, msg_id, seq_num, buf, len);
	if (!handled) {
		handled = vm_mgnt_msg_handler(vm_id, msg_id, seq_num, buf, len);
	}
	if (!handled) {
		handled =
			memparcel_msg_handler(vm_id, msg_id, seq_num, buf, len);
	}
	if (!handled) {
		handled = vm_get_resources_handler(vm_id, msg_id, seq_num, buf,
						   len);
	}
	if (!handled) {
		handled = irq_manager_msg_handler(vm_id, msg_id, seq_num, buf,
						  len);
	}
	if (!handled) {
		handled = vm_creation_msg_handler(vm_id, msg_id, seq_num, buf,
						  len);
	}

	if (!handled) {
		printf("Unhandled request from VM %x, ID: %x\n", vm_id, msg_id);
		rm_standard_reply(vm_id, msg_id, seq_num,
				  RM_ERROR_UNIMPLEMENTED);
	}

out:
	rm_rpc_free(buf, alloc_size);
}

static void
notif_callback(vmid_t vm_id, uint32_t notification_id, void *buf, size_t len,
	       size_t alloc_size)
{
	bool handled = false;

	if (vm_id == VMID_HYP) {
		switch (notification_id) {
		default:
			break;
		}
	}

	(void)len;

	if (!handled) {
		printf("Unhandled notification from VM %x, ID: %x\n", vm_id,
		       notification_id);
	}

	rm_rpc_free(buf, alloc_size);
}

static void
rm_tx_callback(rm_error_t tx_err, vmid_t vm_id, void *buf, size_t len,
	       size_t alloc_size)
{
	(void)len;
	(void)alloc_size;

	if (tx_err != RM_OK) {
		printf("TX failed for VM %x, error: %x\n", vm_id, tx_err);
	}

	rm_rpc_fifo_tx_callback(vm_id);

	free(buf);
}

int
main(int argc, char *argv[])
{
	(void)argc;

	error_t		 err;
	rm_error_t	 rm_err;
	uintptr_t	 env_addr = (uintptr_t)argv[1];
	boot_env_data_t *env_data = (boot_env_data_t *)env_addr;

	// should remove it, just temporary for refactor
	priv_env_data = env_data;

	rm_err = register_exit();
	assert(rm_err == RM_OK);

	platform_uart_setup(env_data);

	err = platform_uart_map(env_data->addrspace_capid);
	assert(err == OK);

	rm_err = console_init();
	assert(rm_err == RM_OK);

	// Register UART put function
	rm_err = register_uart();
	assert(rm_err == RM_OK);

	printf("Starting Resource Manager, version: %s (%s)\n", RM_GIT_VERSION,
	       RM_BUILD_DATE);

	vm_mgnt_init();

	rm_err = vm_console_init();
	assert(rm_err == RM_OK);

	rm_err = rm_rpc_fifo_init();
	assert(rm_err == RM_OK);

	rm_err = irq_manager_init();
	assert(rm_err == RM_OK);

	rm_err = rm_rpc_init_server(VMID_RM);
	assert(rm_err == RM_OK);

	// Create HLOS
	err = hlos_vm_create(rm_get_vic_hwirqs());
	if (err != OK) {
		printf("hlos_vm_create ret=%d\n", err);
		goto out;
	}

	vm_t *hlos_vm = vm_lookup(VMID_HLOS);
	if (hlos_vm == NULL) {
		printf("Error: failed to lookup hlos vm\n");
		goto out;
	}

	// FIXME: 1:1 mapping for now
	hlos_vm->mem_base   = env_data->hlos_vm_base;
	hlos_vm->mem_size   = env_data->hlos_vm_size;
	hlos_vm->ipa_base   = env_data->hlos_vm_base;
	hlos_vm->dtb_offset = env_data->hlos_dt_base - env_data->hlos_vm_base;
	hlos_vm->ramfs_offset =
		env_data->hlos_ramfs_base - env_data->hlos_vm_base;

	error_t hlos_vm_ret = hlos_vm_setup();
	if (hlos_vm_ret != OK) {
		printf("Error: failed to setup hlos vm\n");
		goto out;
	}

	// Start the HLOS VM
	err = hlos_vm_start();
	if (err != OK) {
		printf("Failed to start HLOS\n");
		goto out;
	}

	rm_err = rm_rpc_register_msg_handler(msg_callback);
	assert(rm_err == RM_OK);
	rm_err = rm_rpc_register_notif_handler(notif_callback);
	assert(rm_err == RM_OK);
	rm_err = rm_rpc_register_tx_complete_handler(rm_tx_callback);
	assert(rm_err == RM_OK);

	printf("init completed\n");
	printf("UART is disabled\n");
	rm_err = deregister_uart();
	assert(rm_err == RM_OK);
	rm_rpc_wait(-1);

out:
	return 0;
}

cap_id_t
rm_get_rm_addrspace(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->addrspace_capid;
}

cap_id_t
rm_get_rm_cspace(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->cspace_capid;
}

cap_id_t
rm_get_rm_partition(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->partition_capid;
}

cap_id_t
rm_get_device_me(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->device_me_capid;
}

vmaddr_t
rm_get_device_me_base(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->device_me_base;
}

cap_id_t
rm_get_rm_vic(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->vic;
}

static hwirq_cap_array_t
rm_get_vic_hwirqs(void)
{
	assert(priv_env_data != NULL);

	hwirq_cap_array_t ret = { .count = util_array_size(
					  priv_env_data->vic_hwirq),
				  .vic_hwirqs = priv_env_data->vic_hwirq };

	return ret;
}

vmaddr_t
rm_get_hlos_entry(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->entry_hlos;
}

vmaddr_t
rm_get_hlos_dt_base(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->hlos_dt_base;
}

cap_id_t
rm_get_restricted_hwirq(virq_t irq, vmid_t vmid)
{
	(void)irq;
	(void)vmid;

	return CSPACE_CAP_INVALID;
}

cap_id_t
rm_get_uart_me(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->uart_me_capid;
}
