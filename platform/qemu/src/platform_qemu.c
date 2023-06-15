// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <rm_types.h>

#include <dt_overlay.h>
#include <event.h>
#include <memextent.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <platform_vm_memory.h>
#include <qcbor/qcbor.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <uart.h>
#include <vgic.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation.h>
#include <vm_dt.h>
#include <vm_memory.h>
#include <vm_mgnt.h>

// Include after qcbor
#include <platform_env.h>

bool
platform_get_security_state(void)
{
	// Emulated/Open platform don't need to be secure
	return false;
}

bool
platform_expose_log_to_hlos(void)
{
	return !platform_get_security_state();
}

error_t
platform_hlos_create(vm_t *vm, const rm_env_data_t *env_data)
{
	vmaddr_t mem_base = env_data->hlos_vm_base;
	size_t	 mem_size = env_data->hlos_vm_size;
	error_t	 err;

	vm->mem_base = mem_base;
	vm->ipa_base = mem_base;
	vm->mem_size = mem_size;

	cap_id_t me_cap = vm_memory_get_owned_extent(vm, MEM_TYPE_NORMAL);

	err = platform_vm_memory_donate_ddr(me_cap, vm->mem_base, vm->mem_size,
					    true);
	if (err != OK) {
		printf("HLOS memory donate failed\n");
		goto out;
	}

	err = vm_memory_map_partial(vm, VM_MEMUSE_NORMAL, me_cap, vm->mem_base,
				    vm->mem_base, vm->mem_size,
				    PGTABLE_ACCESS_RWX,
				    PGTABLE_VM_MEMTYPE_NORMAL_WB);
	if (err != OK) {
		printf("HLOS memory map failed\n");
		goto out;
	}

	mem_base = rm_get_device_me_base();
	mem_size = rm_get_device_me_size();

	err = memextent_map(rm_get_device_me_cap(), vm->vm_config->addrspace,
			    mem_base, PGTABLE_ACCESS_RW,
			    PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
	if (err != OK) {
		printf("Device addr Mapping failed");
		goto out;
	}

	mem_base = env_data->uart_address;
	mem_size = PAGE_SIZE;

	err = memextent_map(rm_get_uart_me(), vm->vm_config->addrspace,
			    mem_base, PGTABLE_ACCESS_RW,
			    PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
	if (err != OK) {
		printf("Device addr Mapping failed");
		goto out;
	}

out:
	return OK;
}

bool
platform_msg_callback(vmid_t vm_id, uint32_t msg_id, uint16_t seq_num,
		      void *buf, size_t len)
{
	bool handled = false;

	if (vm_id != VMID_HYP) {
		goto out;
	}

	switch (msg_id) {
		// TODO: add specific message handlers for platform here
	default:
		break;
	}

out:
	(void)seq_num;
	(void)buf;
	(void)len;

	return handled;
}

bool
platform_notif_callback(vmid_t vm_id, uint32_t notification_id, void *buf,
			size_t len)
{
	bool handled = false;

	if (vm_id != VMID_HYP) {
		goto out;
	}

	switch (notification_id) {
		// TODO: add specific notification handlers for platform here
	default:
		break;
	}

out:
	(void)buf;
	(void)len;

	return handled;
}

error_t
platform_init(rm_env_data_t *env_data, vmaddr_t log_buf, size_t log_buf_size)
{
	error_t err = OK;

	(void)log_buf;
	(void)log_buf_size;
	err = vgic_init(env_data);
	if (err != OK) {
		goto out;
	}

out:
	return err;
}

error_t
platform_vm_create(vm_t *vm, bool hlos)
{
	(void)vm;
	(void)hlos;

	return OK;
}

uint64_t
platform_get_secondary_vmids(void)
{
	return 0xFFFFFFF0U;
}

uint64_t
platform_get_peripheral_vmids(void)
{
	return 0U;
}

error_t
platform_primary_vm_init(rm_env_data_t *env_data, uintptr_t arg1,
			 uintptr_t arg2)
{
	error_t ret = OK;
	(void)arg1;
	(void)arg2;

	vm_t *hlos_vm = vm_lookup(VMID_HLOS);
	if (hlos_vm == NULL) {
		printf("Error: failed to lookup hlos vm\n");
		ret = ERROR_FAILURE;
		goto out;
	}

	hlos_vm->mem_base  = env_data->hlos_vm_base;
	hlos_vm->mem_size  = env_data->hlos_vm_size;
	hlos_vm->ipa_base  = env_data->hlos_vm_base;
	hlos_vm->dt_offset = env_data->hlos_dt_base - env_data->hlos_vm_base;
	hlos_vm->ramfs_offset =
		env_data->hlos_ramfs_base - env_data->hlos_vm_base;

	printf("HLOS Mem Base : %lx\n", hlos_vm->mem_base);
	printf("HLOS Mem Size : %lx\n", hlos_vm->mem_size);
	printf("HLOS IPA base : %lx\n", hlos_vm->ipa_base);
	printf("HLOS DT Ofst  : %lx\n", hlos_vm->dt_offset);
	printf("RAM FS offset : %lx\n", hlos_vm->ramfs_offset);

	// FIXME: for now assuming we can write up to this size into the
	// original DTB region
	hlos_vm->dt_size = DTBO_MAX_SIZE;

	ret = vm_dt_apply_hlos_overlay(hlos_vm, env_data->hlos_dt_base,
				       hlos_vm->dt_size);
out:
	return ret;
}

uint64_t
platform_get_os_boot_arg(vm_t *vm)
{
	(void)vm;

	return rm_get_hlos_dt_base();
}

rm_error_t
platform_vm_auth(vm_t *vm, count_t num_auth_params,
		 vm_auth_param_t *auth_params)
{
	rm_error_t ret;

	(void)vm;
	(void)num_auth_params;
	(void)auth_params;

	ret = RM_OK;
	return ret;
}

rm_error_t
platform_vm_init(vm_t *vm)
{
	rm_error_t err = RM_OK;
	(void)vm;

	return err;
}

rm_error_t
platform_memparcel_accept(memparcel_t *mp, vm_t *vm)
{
	rm_error_t err = RM_OK;

	(void)mp;
	(void)vm;

	return err;
}

rm_error_t
platform_memparcel_release(memparcel_t *mp, vm_t *vm)
{
	rm_error_t err = RM_OK;

	(void)mp;
	(void)vm;

	return err;
}

error_t
platform_vm_takedown(vm_t *vm)
{
	(void)vm;
	return OK;
}

error_t
platform_vm_destroy(vm_t *vm, bool hlos)
{
	(void)vm;
	(void)hlos;
	return OK;
}

error_t
platform_handle_destroy_vdevices(const vm_t *vm)
{
	(void)vm;
	return OK;
}

bool
platform_has_vsmmu_v2_support(void)
{
	bool ret = false;

	return ret;
}

error_t
platform_env_init(platform_env_data_t **platform_env)
{
	*platform_env = NULL;

	return OK;
}

bool
platform_process_qcbor_items(qcbor_item_t     *item,
			     qcbor_dec_ctxt_t *qcbor_decode_ctxt)
{
	(void)item;
	(void)qcbor_decode_ctxt;

	return false;
}

bool
platform_has_watchdog_hlos_virtual_regs(void)
{
	return false;
}
