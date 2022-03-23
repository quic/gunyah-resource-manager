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

#include <resource-manager.h>

#include <compiler.h>
#include <dt_overlay.h>
#include <errno.h>
#include <exit_dev.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <log.h>
#include <memextent.h>
#include <memparcel.h>
#include <platform.h>
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

extern gunyah_hyp_hypervisor_identify_result_t hyp_id;

static boot_env_data_t *priv_env_data;

static hwirq_caps_t
rm_get_vic_hwirqs(void);

static void
msg_callback(vmid_t vm_id, uint32_t msg_id, uint16_t seq_num, uint8_t msg_type,
	     void *buf, size_t len, size_t alloc_size)
{
	bool handled;

	if (msg_type != RM_RPC_MSG_TYPE_REQUEST) {
		goto out;
	}

	handled = platform_msg_callback(vm_id, msg_id, seq_num, buf, len);
	if (!handled) {
		handled = vm_console_msg_handler(vm_id, msg_id, seq_num, buf,
						 len);
	}
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
		printf("Unhandled request from VM %d, ID: %x\n", (int)vm_id,
		       msg_id);
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
	bool handled;

	handled = platform_notif_callback(vm_id, notification_id, buf, len);
	if (!handled) {
		printf("Unhandled notification from VM %d, ID: %x\n",
		       (int)vm_id, notification_id);
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
		printf("TX failed for VM %d, error: %x\n", (int)vm_id, tx_err);
	}

	rm_rpc_fifo_tx_callback(vm_id);

	free(buf);
}

gunyah_hyp_hypervisor_identify_result_t hyp_id;

int
main(int argc, char *argv[])
{
	(void)argc;

	int		 ret = 0;
	error_t		 err;
	rm_error_t	 rm_err;
	uintptr_t	 env_addr     = (uintptr_t)argv[1];
	uintptr_t	 log_buf      = (uintptr_t)argv[2];
	size_t		 log_buf_size = (size_t)argv[3];
	boot_env_data_t *env_data     = (boot_env_data_t *)env_addr;

	// should remove it, just temporary for refactor
	priv_env_data = env_data;

	rm_err = register_exit();
	assert(rm_err == RM_OK);

	platform_uart_map(env_data);

	log_buf_size = LOG_AREA_SIZE;
	rm_err	     = log_reconfigure(&log_buf, log_buf_size);
	assert(rm_err == RM_OK);

	// Register UART put function
	rm_err = register_uart();
	assert(rm_err == RM_OK);

	hyp_id = gunyah_hyp_hypervisor_identify();

	printf("Starting Resource Manager, version: %s (%s)\n", RM_GIT_VERSION,
	       RM_BUILD_DATE);
#if defined(CONFIG_DEBUG)
	printf("Gunyah API ver: %i, variant: %x\n",
	       hyp_api_info_get_api_version(&hyp_id.hyp_api_info),
	       hyp_api_info_get_variant(&hyp_id.hyp_api_info));
#endif

	vm_mgnt_init();

	rm_err = vm_console_init();
	assert(rm_err == RM_OK);

	rm_err = rm_rpc_fifo_init();
	assert(rm_err == RM_OK);

	rm_err = irq_manager_init();
	assert(rm_err == RM_OK);

	err = platform_init(env_data);
	assert(err == OK);

	rm_err = rm_rpc_init_server(VMID_RM);
	assert(rm_err == RM_OK);

	// Create HLOS
	err = hlos_vm_create(rm_get_vic_hwirqs(), env_data);
	if (err != OK) {
		printf("hlos_vm_create ret=%d\n", err);
		ret = -ENODEV;
		goto out;
	}

#if defined(CONFIG_TZ_RM_LOG)
	if (!platform_get_security_state()) {
		rm_err = log_expose_to_hlos(log_buf, log_buf_size);
		assert(rm_err == RM_OK);
	}
#else
	(void)log_expose_to_hlos;
#endif

	vm_t *hlos_vm = vm_lookup(VMID_HLOS);
	if (hlos_vm == NULL) {
		printf("Error: failed to lookup hlos vm\n");
		goto out;
	}

	// FIXME: 1:1 mapping for now
	hlos_vm->mem_base = env_data->hlos_vm_base;
	hlos_vm->mem_size = env_data->hlos_vm_size;
	hlos_vm->ipa_base = env_data->hlos_vm_base;
	hlos_vm->dtb_region_offset =
		env_data->hlos_dt_base - env_data->hlos_vm_base;
	// FIXME: get from env_data
	hlos_vm->dtb_region_size = PAGE_SIZE + DTBO_MAX_SIZE;
	hlos_vm->ramfs_offset =
		env_data->hlos_ramfs_base - env_data->hlos_vm_base;

	error_t hlos_vm_ret = hlos_vm_setup(env_data);
	if (hlos_vm_ret != OK) {
		printf("Error: failed to setup hlos vm\n");
		goto out;
	}

	rm_err = rm_rpc_register_msg_handler(msg_callback);
	assert(rm_err == RM_OK);
	rm_err = rm_rpc_register_notif_handler(notif_callback);
	assert(rm_err == RM_OK);
	rm_err = rm_rpc_register_tx_complete_handler(rm_tx_callback);
	assert(rm_err == RM_OK);

#if defined(POST_BOOT_UART_DISABLE) && POST_BOOT_UART_DISABLE
	printf("init completed, disabling UART\n");
	rm_err = deregister_uart();
	if (rm_err != RM_OK) {
		printf("UART disable failed: %d\n", (int)rm_err);
		ret = -EIO;
	}
#else
	printf("init completed.\n");
#endif

	// Start the HLOS VM
	err = hlos_vm_start();
	if (err != OK) {
#if defined(POST_BOOT_UART_DISABLE) && POST_BOOT_UART_DISABLE
		(void)register_uart();
#endif
		printf("Failed to start HLOS: %d\n", (int)err);
		ret = -ENODEV;
		goto out;
	}

	rm_rpc_wait(-1);

out:
	printf("RM exit ret=%d\n", ret);
	return ret;
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

cap_id_t
rm_get_me(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->me_capid;
}

cap_id_t
rm_get_rm_vic(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->vic;
}

static hwirq_caps_t
rm_get_vic_hwirqs(void)
{
	assert(priv_env_data != NULL);

	hwirq_caps_t ret = {
		.vic_hwirq_count = util_array_size(priv_env_data->vic_hwirq),
		.vic_hwirqs	 = priv_env_data->vic_hwirq,
		.vic_msi_source_count =
			util_array_size(priv_env_data->vic_msi_source),
		.vic_msi_sources = priv_env_data->vic_msi_source,
	};

	return ret;
}

vmaddr_t
rm_get_hlos_entry(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->entry_hlos;
}

cap_id_t
rm_get_restricted_hwirq(virq_t irq, vmid_t vmid)
{
	cap_id_t ret = CSPACE_CAP_INVALID;
	(void)vmid;
	(void)irq;

	return ret;
}

count_t
rm_get_platform_max_cores(void)
{
	return sizeof(priv_env_data->usable_cores) * 8U -
	       compiler_clz(priv_env_data->usable_cores);
}

index_t
rm_get_platform_root_vcpu_index(void)
{
	return priv_env_data->boot_core;
}

bool
rm_is_core_usable(cpu_index_t i)
{
	if (i > rm_get_platform_max_cores()) {
		return false;
	} else {
		return ((1UL << i) & priv_env_data->usable_cores) != 0;
	}
}

vmaddr_t
rm_get_me_ipa_base(void)
{
	return priv_env_data->me_ipa_base;
}

paddr_t
rm_ipa_to_pa(uintptr_t ipa)
{
	return (paddr_t)(ipa - priv_env_data->ipa_offset);
}

vmaddr_t
rm_get_hlos_dt_base(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->hlos_dt_base;
}

cap_id_t
rm_get_uart_me(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->uart_me_capid;
}

vmaddr_t
rm_get_device_me_base(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->device_me_base;
}
