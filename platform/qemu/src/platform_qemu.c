// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <rm-rpc.h>

#include <resource-manager.h>

#include <platform.h>
#include <uart.h>
#include <vendor_hyp_call.h>
#include <vm_client.h>

error_t
platform_hlos_get_free_addr_range(vmaddr_t *base, size_t *size)
{
	(void)base;
	(void)size;

	return OK;
}

bool
platform_get_security_state(void)
{
	return false;
}

error_t
platform_hlos_create(cap_id_t hlos_as)
{
	(void)hlos_as;

	return OK;
}
bool
platform_msg_callback(vmid_t vm_id, uint32_t msg_id, uint16_t seq_num,
		      void *buf, size_t len)
{
	(void)vm_id;
	(void)msg_id;
	(void)seq_num;
	(void)buf;
	(void)len;

	return false;
}

bool
platform_notif_callback(vmid_t vm_id, uint32_t notification_id, void *buf,
			size_t len)
{
	(void)vm_id;
	(void)notification_id;
	(void)buf;
	(void)len;

	return false;
}

error_t
platform_init(boot_env_data_t *env_data)
{
	(void)env_data;

	return OK;
}

error_t
platform_vm_create(vm_t *vm, bool hlos)
{
	(void)vm;
	(void)hlos;

	return OK;
}
