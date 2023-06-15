// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>

#include <rm_types.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <stdlib.h>
#include <string.h>

#include <util.h>
#include <utils/list.h>
#include <utils/vector.h>

#include <cache.h>
#include <dt_linux.h>
#include <dt_overlay.h>
#include <event.h>
#include <memextent.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_dt.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_dt.h>
#include <vm_memory.h>
#include <vm_mgnt.h>

vm_dt_create_hlos_ret_t
vm_dt_create_hlos(void *base, size_t size, vmaddr_t log_ipa, size_t log_size)
{
	vm_dt_create_hlos_ret_t ret = { .err = OK };
	error_t			e;

	dto_t *dto = dto_init(base, size);
	if (dto == NULL) {
		ret.err = ERROR_NOMEM;
		goto err;
	}

	dto_modify_begin_by_path(dto, "/");

	dto_node_begin(dto, "hypervisor");

	dto_property_add_u32(dto, "#address-cells", 2);
	dto_property_add_u32(dto, "#size-cells", 0);
	const char *hyp_compat[3] = { "qcom,gunyah-hypervisor-1.0",
				      "qcom,gunyah-hypervisor", "simple-bus" };
	dto_property_add_stringlist(dto, "compatible", hyp_compat, 3);
	// FIXME: interrupt-parent we assume is in the root

	dto_node_begin(dto, "qcom,gunyah-vm");
	const char *id_compat[2] = { "qcom,gunyah-vm-id-1.0",
				     "qcom,gunyah-vm-id" };
	dto_property_add_stringlist(dto, "compatible", id_compat, 2);
	dto_property_add_u32(dto, "qcom,vmid", VMID_HLOS);
	dto_property_add_string(dto, "qcom,vendor", "Qualcomm");
	dto_node_end(dto, "qcom,gunyah-vm");

	vm_t *hlos = vm_lookup(VMID_HLOS);
	assert(hlos != NULL);
	assert(hlos->vm_config != NULL);

	vdevice_node_t		*node = NULL;
#if defined(CAP_RIGHTS_WATCHDOG_ALL)
	// Find the watchdog node
	struct vdevice_watchdog *wdt  = NULL;
	loop_list(node, &hlos->vm_config->vdevice_nodes, vdevice_)
	{
		if (node->type == VDEV_WATCHDOG) {
			wdt = (struct vdevice_watchdog *)node->config;
			break;
		}
	}
	if ((wdt != NULL) && !wdt->virtual_regs) {
		// Insert the watchdog node into the device tree
		dto_node_begin(dto, "qcom,gh-watchdog");
		const char *wdt_compat[1] = { "qcom,gh-watchdog" };
		dto_property_add_stringlist(dto, "compatible", wdt_compat, 1);
		dto_property_add_interrupts_array(dto, "interrupts",
						  &wdt->bark_virq, 1);
		dto_node_end(dto, "qcom,gh-watchdog");
	}
#endif

	// Find the RM RPC node
	node					 = NULL;
	struct vdevice_msg_queue_pair *msgq_pair = NULL;

	loop_list(node, &hlos->vm_config->vdevice_nodes, vdevice_)
	{
		if (node->type == VDEV_RM_RPC) {
			msgq_pair =
				(struct vdevice_msg_queue_pair *)node->config;
			if (msgq_pair->peer == VMID_RM) {
				break;
			}
			msgq_pair = NULL;
		}
	}
	assert(msgq_pair != NULL);

	// Start the resource-manager node
	char node_name[128];
	snprintf(node_name, 128, "qcom,resource-manager-rpc@%016lx",
		 msgq_pair->tx_vm_cap);

	dto_node_begin(dto, node_name);
	const char *rpc_compat[8];
	count_t	    i = 0;
	for (index_t j = 0; j < node->push_compatible_num; j++) {
		rpc_compat[i] = node->push_compatible[j];
		i++;
	}
	assert(i < 6);
	rpc_compat[i] = "qcom,gunyah-message-queue";
	i++;
	rpc_compat[i] = "qcom,gunyah-capability";
	i++;

	dto_property_add_stringlist(dto, "compatible", rpc_compat, i);

	uint64_t reg[2] = { msgq_pair->tx_vm_cap, msgq_pair->rx_vm_cap };
	dto_property_add_u64array(dto, "reg", reg, 2);

	interrupt_data_t interrupts[2] = { msgq_pair->tx_vm_virq,
					   msgq_pair->rx_vm_virq };
	dto_property_add_interrupts_array(dto, "interrupts", interrupts,
					  util_array_size(interrupts));

	// dto_property_add_empty(dto, "qcom,console-dev");	// for SVM
	dto_property_add_u32(dto, "qcom,free-irq-start", 960);

	dto_property_add_empty(dto, "qcom,is-full-duplex");
	dto_property_add_u32(dto, "qcom,tx-message-size",
			     (uint32_t)msgq_pair->tx_max_msg_size);
	dto_property_add_u32(dto, "qcom,rx-message-size",
			     (uint32_t)msgq_pair->rx_max_msg_size);
	dto_property_add_u32(dto, "qcom,tx-queue-depth",
			     (uint32_t)msgq_pair->tx_queue_depth);
	dto_property_add_u32(dto, "qcom,rx-queue-depth",
			     (uint32_t)msgq_pair->rx_queue_depth);

	dto_node_end(dto, node_name);

	dto_node_end(dto, "hypervisor");

	dto_modify_end_by_path(dto, "/");

#if defined(PLATFORM_HLOS_SPLIT_DTBO) && PLATFORM_HLOS_SPLIT_DTBO
	e = dto_finalise(dto);
	if (e != OK) {
		ret.err = ERROR_NOMEM;
		goto err;
	}

	ret.dtbos[ret.num_dtbos].base = dto_get_dtbo(dto);
	ret.dtbos[ret.num_dtbos].size = dto_get_size(dto);
	ret.num_dtbos++;

	// The first DTBO should not have taken more than the available size
	assert(ret.dtbos[0].size <= size);

	// Free the first DTBO.
	dto_deinit(dto);
	dto = NULL;

	// DTBs are required to have 8-byte alignment
	size_t offset = util_balign_up(ret.dtbos[0].size, 8U);

	// Start the second DTBO immediately after the first.
	dto = dto_init((char *)base + offset, size - offset);
	if (dto == NULL) {
		ret.err = ERROR_NOMEM;
		goto err;
	}
#endif // PLATFORM_HLOS_SPLIT_DTBO

	// If the RM log is exposed to HLOS, and the TZ log driver has a
	// DT node, patch the node to add the RM log address.
#if defined(CONFIG_TZ_RM_LOG) && !defined(PLATFORM_DISABLE_TZ_DT_PATCH)
	if (!platform_get_security_state() && (log_size != 0U)) {
		dto_modify_begin(dto, "qcom_tzlog");
		dto_property_add_u32(dto, "rmlog-address", (uint32_t)log_ipa);
		dto_property_add_u32(dto, "rmlog-size", (uint32_t)log_size);
		dto_modify_end(dto, "qcom_tzlog");
	}
#else
	(void)log_ipa;
	(void)log_size;
#endif

#if defined(CAP_RIGHTS_WATCHDOG_ALL)
	if (wdt != NULL) {
		// Patch the existing watchdog node
		char	 wdt_node_name[23];
		uint32_t wdt_addr = (uint32_t)rm_get_watchdog_address();
		snprintf(wdt_node_name, 23, "/soc/qcom,wdt@%08x", wdt_addr);
		dto_modify_begin_by_path(dto, wdt_node_name);
		if (!wdt->virtual_regs) {
			// Disable the existing watchdog
			const char *pwdt_status[1] = { "disabled" };
			dto_property_add_stringlist(dto, "status", pwdt_status,
						    1);
		} else {
			// Add the watchdog properties
			uint32_t wdt_reg[2] = { wdt_addr, PAGE_SIZE };
			dto_property_add_u32array(dto, "reg", wdt_reg, 2);
			dto_property_add_string(dto, "reg-names", "wdt-base");
			dto_property_add_interrupts_array(dto, "interrupts",
							  &wdt->bark_virq, 1);
		}
		dto_modify_end_by_path(dto, wdt_node_name);
	}
#endif

	e = platform_dto_finalise(dto, hlos, base);
	if (e != OK) {
		ret.err = ERROR_NOMEM;
		goto err;
	}

	e = dto_finalise(dto);
	if (e != OK) {
		ret.err = ERROR_NOMEM;
		goto err;
	}

	ret.dtbos[ret.num_dtbos].base = dto_get_dtbo(dto);
	ret.dtbos[ret.num_dtbos].size = dto_get_size(dto);
	ret.num_dtbos++;

err:
	if (dto != NULL) {
		dto_deinit(dto);
	}

	return ret;
}

error_t
vm_dt_apply_hlos_overlay(vm_t *hlos_vm, paddr_t hlos_dtb, size_t dtb_size)
{
	error_t err = OK;

	paddr_t		orig_dtb_addr = hlos_dtb;
	size_t		dtb_region_size;
	cap_id_result_t cap_ret;
	cap_id_t	vm_me;
	void	       *dtb_process_buf;
	void	       *overlay_dtbo = NULL;

	vm_me = vm_memory_get_owned_extent(hlos_vm, MEM_TYPE_NORMAL);

	dtb_region_size = dtb_size;

	cap_ret.e = memextent_map_partial(vm_me, rm_get_rm_addrspace(),
					  orig_dtb_addr, orig_dtb_addr,
					  dtb_region_size, PGTABLE_ACCESS_RW,
					  PGTABLE_VM_MEMTYPE_NORMAL_WB);
	if (cap_ret.e != OK) {
		err = ERROR_DENIED;
		goto out;
	}

	// Make sure we don't overflow even after overlay
	if (util_add_overflows((uintptr_t)orig_dtb_addr, dtb_region_size)) {
		err = ERROR_ARGUMENT_SIZE;
		goto out;
	}

	// Allocate for both overlay dtbo and process buff
	size_t overlay_dtb_size = (size_t)PAGE_SIZE + dtb_region_size;
	overlay_dtbo		= calloc(1U, overlay_dtb_size);

	if (overlay_dtbo == NULL) {
		err = ERROR_NOMEM;
		goto out;
	}
	(void)memset(overlay_dtbo, 0, overlay_dtb_size);

	overlay_dtb_size = PAGE_SIZE;

	dtb_process_buf = (void *)((uintptr_t)overlay_dtbo + overlay_dtb_size);

	// Create the HLOS DTBO
	vm_dt_create_hlos_ret_t dtbo_ret =
		vm_dt_create_hlos(overlay_dtbo, overlay_dtb_size, 0, 0);
	if (dtbo_ret.err != OK) {
		err = dtbo_ret.err;
		goto out;
	}

	if (dtbo_ret.num_dtbos < 1U) {
		err = ERROR_NOMEM;
		goto out;
	}

	int open_ret = fdt_open_into((void *)orig_dtb_addr, dtb_process_buf,
				     (int)dtb_region_size);
	if (open_ret != 0) {
		err = ERROR_DENIED;
		goto out;
	}

	count_t cnt = 0;
	while (cnt < dtbo_ret.num_dtbos) {
		int apply_ret = fdt_overlay_apply(dtb_process_buf,
						  dtbo_ret.dtbos[cnt].base);
		if (apply_ret != 0) {
			err = ERROR_DENIED;
			goto out;
		}
		++cnt;
	}

	fdt_pack(dtb_process_buf);

	size_t new_dtb_size = fdt_totalsize(dtb_process_buf);
	assert(new_dtb_size <= dtb_region_size);

	(void)memcpy((void *)orig_dtb_addr, dtb_process_buf, new_dtb_size);
	cache_clean_by_va((void *)orig_dtb_addr, new_dtb_size);

	hlos_vm->dt_size = new_dtb_size;

out:
	if (cap_ret.e == OK) {
		memextent_unmap_partial(rm_get_me(), rm_get_rm_addrspace(),
					orig_dtb_addr, orig_dtb_addr,
					dtb_region_size);
	}

	if (overlay_dtbo != NULL) {
		free(overlay_dtbo);
	}

	return err;
}
