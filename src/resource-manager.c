// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>
#include <utils/vector.h>

#include <compiler.h>
#include <errno.h>
#include <event.h>
#include <exit_dev.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <log.h>
#include <memextent.h>
#include <memparcel.h>
#include <platform.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <uart.h>
#include <vm_config.h>
#include <vm_console.h>
#include <vm_creation.h>
#include <vm_dt.h>
#include <vm_firmware.h>
#include <vm_ipa.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_mgnt_message.h>
#include <vm_resources.h>

#include "rmversion.h"

extern gunyah_hyp_hypervisor_identify_result_t hyp_id;

static rm_env_data_t *priv_env_data;

typedef struct {
	cap_id_t irq_cap;
	virq_t	 irq;
	uint8_t	 irq_padding[4];

	// vmid_t	belongs_to;
} static_restricted_irq_t;

// FIXME: refactor these static resources to build configuration?
static count_t		       num_restricted_irqs;
static static_restricted_irq_t restricted_irqs[MAX_RESERVE_NUM_IRQ];

static void
remove_restricted_irqs(void);

static hwirq_caps_t
rm_get_vic_hwirqs(void);

static void
msg_callback(vmid_t vm_id, uint32_t msg_id, uint16_t seq_num, uint8_t msg_type,
	     void *buf, size_t len)
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
		handled = vm_ipa_msg_handler(vm_id, msg_id, seq_num, buf, len);
	}
	if (!handled) {
		handled = vm_firmware_msg_handler(vm_id, msg_id, seq_num, buf,
						  len);
	}

	if (!handled) {
		printf("Unhandled request from VM %d, ID: %x\n", (int)vm_id,
		       msg_id);
		rm_standard_reply(vm_id, msg_id, seq_num,
				  RM_ERROR_UNIMPLEMENTED);
	}

out:
	rm_rpc_free(buf);
}

static void
notif_callback(vmid_t vm_id, uint32_t notification_id, void *buf, size_t len)
{
	bool handled;

	handled = platform_notif_callback(vm_id, notification_id, buf, len);
	if (!handled) {
		printf("Unhandled notification from VM %d, ID: %x\n",
		       (int)vm_id, notification_id);
	}

	rm_rpc_free(buf);
}

static void
rm_tx_callback(rm_error_t tx_err, vmid_t vm_id, void *buf, size_t len)
{
	(void)len;

	if (tx_err != RM_OK) {
		printf("TX failed for VM %d, error: %x\n", (int)vm_id, tx_err);
	}

	rm_rpc_fifo_tx_callback(vm_id);

	free(buf);
}

static void
initialize_restricted_irqs(rm_env_data_t *env_data)
{
	uint32_t num_reserved_dev_irqs = 0U;
	uint32_t num_irq_count	       = 0U;

	num_reserved_dev_irqs = env_data->num_reserved_dev_irqs;
	for (index_t i = 0; i < num_reserved_dev_irqs; i++) {
		if (i < MAX_RESERVE_NUM_IRQ) {
			restricted_irqs[i].irq = env_data->reserved_dev_irq[i];
			// FIXME: need to support other secondary VMs.
			// belongs_to should possibly be replaced with QTI
			// signed access check.
			// restricted_irqs[i].belongs_to = VMID_TUI_VM;
			restricted_irqs[i].irq_cap = CSPACE_CAP_INVALID;
			num_irq_count		   = i;
		} else {
			printf("Warning: number of Reserved IRQ is more than allowed.");
		}
	}
	num_restricted_irqs = num_irq_count;
}

void
process_and_get_env_data(rm_env_data_hdr_t *env_hdr, rm_env_data_t *rm_env);

gunyah_hyp_hypervisor_identify_result_t hyp_id;

int
main(int argc, char *argv[])
{
	(void)argc;

	int		   ret = 0;
	error_t		   err;
	rm_error_t	   rm_err;
	uintptr_t	   env_addr	= (uintptr_t)argv[1];
	uintptr_t	   log_buf	= (uintptr_t)argv[2];
	size_t		   log_buf_size = (size_t)argv[3];
	rm_env_data_hdr_t *env_hdr	= (rm_env_data_hdr_t *)env_addr;

	priv_env_data = (rm_env_data_t *)calloc(1, sizeof(*priv_env_data));
	assert(priv_env_data != NULL);

	err = platform_env_init(&priv_env_data->platform_env);
	assert(err == OK);

	process_and_get_env_data(env_hdr, priv_env_data);

	rm_err = register_exit();
	assert(rm_err == RM_OK);

	initialize_restricted_irqs(priv_env_data);
	remove_restricted_irqs();

	platform_uart_map(priv_env_data);

	log_buf_size = LOG_AREA_SIZE;
	rm_err	     = log_reconfigure(&log_buf, log_buf_size);
	assert(rm_err == RM_OK);

	// Register UART put function
	rm_err = register_uart();
	assert(rm_err == RM_OK);

	hyp_id = gunyah_hyp_hypervisor_identify();

	printf("Resource Manager version: %s (%s)\n", RM_GIT_VERSION,
	       RM_BUILD_DATE);
#if defined(CONFIG_DEBUG)
	printf("Gunyah API ver: %i, variant: %x\n",
	       hyp_api_info_get_api_version(&hyp_id.hyp_api_info),
	       hyp_api_info_get_variant(&hyp_id.hyp_api_info));
	printf("Log buffer: %#lx\n", log_buf);
#endif

	rm_err = vm_mgnt_init();
	assert(rm_err == RM_OK);

	rm_err = vm_console_init();
	assert(rm_err == RM_OK);

	rm_err = rm_rpc_fifo_init();
	assert(rm_err == RM_OK);

	rm_err = irq_manager_init();
	assert(rm_err == RM_OK);

	err = vm_memory_init();
	assert(err == OK);

	rm_err = rm_rpc_init_server(VMID_RM);
	assert(rm_err == RM_OK);

	err = platform_init(priv_env_data, log_buf, log_buf_size);
	assert(err == OK);

	// Create memory management bookkeeping for RM itself
	err = rm_vm_create(priv_env_data);
	if (err != OK) {
		printf("rm_vm_create ret=%d\n", err);
		ret = -ENODEV;
		goto out;
	}

	// Create HLOS
	err = hlos_vm_create(rm_get_vic_hwirqs(), priv_env_data);
	if (err != OK) {
		printf("hlos_vm_create ret=%d\n", err);
		ret = -ENODEV;
		goto out;
	}

	if (platform_expose_log_to_hlos()) {
		rm_err = log_expose_to_hlos(log_buf, log_buf_size);
		assert(rm_err == RM_OK);
	}

	platform_primary_vm_init(priv_env_data, log_buf, log_buf_size);

	rm_err = rm_rpc_register_msg_handler(msg_callback);
	assert(rm_err == RM_OK);
	rm_err = rm_rpc_register_notif_handler(notif_callback);
	assert(rm_err == RM_OK);
	rm_err = rm_rpc_register_tx_complete_handler(rm_tx_callback);
	assert(rm_err == RM_OK);

#if defined(POST_BOOT_UART_DISABLE) && POST_BOOT_UART_DISABLE
	printf("Init completed, disabling UART\n");
	rm_err = deregister_uart();
	if (rm_err != RM_OK) {
		printf("UART disable failed: %d\n", (int)rm_err);
		ret = -EIO;
	}
#else
	printf("Init completed.\n");
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
rm_get_device_me_cap(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->device_me_capid;
}

paddr_t
rm_get_device_me_base(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->device_me_base;
}

size_t
rm_get_device_me_size(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->device_me_size;
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

bool
rm_get_watchdog_supported(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->watchdog_supported;
}

paddr_t
rm_get_watchdog_address(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->wdt_address;
}

static void
remove_restricted_irqs(void)
{
	hwirq_caps_t info = rm_get_vic_hwirqs();

	for (index_t i = 0; i < num_restricted_irqs; ++i) {
		virq_t cur_irq = restricted_irqs[i].irq;

		assert(cur_irq < info.vic_hwirq_count);

		// Save the HW irq cap
		restricted_irqs[i].irq_cap = info.vic_hwirqs[cur_irq];
		info.vic_hwirqs[cur_irq]   = CSPACE_CAP_INVALID;
	}
}

cap_id_t
rm_get_restricted_hwirq(virq_t irq, vmid_t vmid)
{
	cap_id_t ret = CSPACE_CAP_INVALID;
	(void)vmid;

	for (index_t i = 0; i < num_restricted_irqs; ++i) {
		if (restricted_irqs[i].irq == irq) {
			// && (restricted_irqs[i].belongs_to == vmid)) {
			ret = restricted_irqs[i].irq_cap;
			break;
		}
	}

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

rm_error_t
rm_error_from_hyp(error_t err)
{
	rm_error_t ret;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wswitch-enum"
	switch (err) {
	case OK:
		ret = RM_OK;
		break;
	case ERROR_UNIMPLEMENTED:
		ret = RM_ERROR_UNIMPLEMENTED;
		break;
	case ERROR_NOMEM:
		ret = RM_ERROR_NOMEM;
		break;
	case ERROR_NORESOURCES:
		ret = RM_ERROR_NORESOURCE;
		break;
	case ERROR_DENIED:
		ret = RM_ERROR_DENIED;
		break;
	case ERROR_BUSY:
		ret = RM_ERROR_BUSY;
		break;
	case ERROR_ADDR_INVALID:
	case ERROR_ADDR_OVERFLOW:
	case ERROR_ADDR_UNDERFLOW:
		ret = RM_ERROR_MEM_INVALID;
		break;
	case ERROR_ARGUMENT_INVALID:
		ret = RM_ERROR_ARGUMENT_INVALID;
		break;
	default:
		ret = RM_ERROR_DENIED;
		break;
	}
#pragma clang diagnostic pop

	return ret;
}

cap_id_t
rm_get_uart_me(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->uart_me_capid;
}

vmaddr_t
rm_get_hlos_dt_base(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->hlos_dt_base;
}

platform_env_data_t *
rm_get_platform_env_data(void)
{
	assert(priv_env_data != NULL);
	return priv_env_data->platform_env;
}
