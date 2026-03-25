// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
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
#pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <stdlib.h>
#include <string.h>

#include <util.h>
#include <utils/list.h>

#include <cache.h>
#include <dt_linux.h>
#include <dt_overlay.h>
#include <event.h>
#include <guest_interface.h>
#include <log.h>
#include <mem_region.h>
#include <memextent.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <panic.h>
#include <platform.h>
#include <platform_dt.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vgic.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation_dt.h>
#include <vm_dt.h>
#include <vm_memory.h>
#include <vm_mgnt.h>

#if defined(PLATFORM_SBSA_WDT) && PLATFORM_SBSA_WDT &&                         \
	defined(PLATFORM_QCOM_WDT_REG) && PLATFORM_QCOM_WDT_REG
#error Invalid watchdog configuration
#endif

#if !(defined(PLATFORM_QCOM_WDT_REG) && PLATFORM_QCOM_WDT_REG)
static error_t
vm_dt_disable_vreg_wdt(dto_t *dto, const struct vdevice_watchdog *wdt)
{
	error_t err;
	char	wdt_node_name[23];
	(void)wdt;

	// wdt->base is invalid as current function assumes hlos is not using a
	// qualcomm watchdog
	uint32_t wdt_addr     = (uint32_t)rm_get_watchdog_address();
	int32_t	 snprintf_ret = snprintf(wdt_node_name, sizeof(wdt_node_name),
					 "/soc/qcom,wdt@%08x", wdt_addr);
	if ((snprintf_ret < 0) ||
	    (snprintf_ret >= (int32_t)sizeof(wdt_node_name))) {
		err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	CHECK_DTO(err, dto_modify_begin_by_path(dto, wdt_node_name));
	const char *pwdt_status[1] = { "disabled" };
	CHECK_DTO(err,
		  dto_property_add_stringlist(dto, "status", pwdt_status, 1));
	CHECK_DTO(err, dto_modify_end_by_path(dto, wdt_node_name));

out:
	return err;
}
#endif

static error_t
vm_dt_update_hlos_wdt(const vm_t *hlos, dto_t *dto)
{
	error_t			 err;
	vdevice_node_t		*node = NULL;
	struct vdevice_watchdog *wdt  = NULL;

	loop_list(node, &hlos->vm_config->vdevice_nodes, vdevice_)
	{
		if (node->type == VDEV_WATCHDOG) {
			wdt = node->config.watchdog;
			break;
		}
	}
	if (wdt == NULL) {
		err = OK;
		goto out;
	}

#if defined(PLATFORM_QCOM_WDT_REG) && PLATFORM_QCOM_WDT_REG
	// If PLATFORM_QCOM_WDT_REG is defined we enforce that HLOS uses qcom
	// watchdog. But for SVM, smc watchdog or qcom watchdog can be used
	// either.
	assert(wdt->type == WATCHDOG_EMULATION_QCOM);
#else
	// Not using virtual register emulation on QCOM watchdog. Disable it in
	// case it is present
	err = vm_dt_disable_vreg_wdt(dto, wdt);
	if (err != OK) {
		goto out;
	}
#endif

	assert(wdt->node_path != NULL);

	if (wdt->type == WATCHDOG_SMC_BASED) {
		// For the emulated watchdog, as we don't parse HLOS DT, we
		// assume that the emulated watchdog always have property
		// "interrupts" and "reg". For the SMC based watchdog, we
		// always patch the IRQ in the HLOS devicetree.
		CHECK_DTO(err, dto_modify_begin_by_path(dto, wdt->node_path));
		CHECK_DTO(err, dto_property_add_interrupts_array(
				       dto, "interrupts", &wdt->bark_virq, 1));
		CHECK_DTO(err, dto_modify_end_by_path(dto, wdt->node_path));
	}

	err = OK;
out:
	return err;
}

#if defined(CONFIG_TZ_RM_LOG)
static error_t
vm_dt_map_rm_logs(dto_t *dto, vmaddr_t log_ipa, size_t log_size)
{
	error_t err = OK;

	CHECK_DTO(err, dto_modify_begin(dto, "qcom_tzlog"));
	CHECK_DTO(err, dto_property_add_u32(dto, "rmlog-address",
					    (uint32_t)log_ipa));
	CHECK_DTO(err,
		  dto_property_add_u32(dto, "rmlog-size", (uint32_t)log_size));
	CHECK_DTO(err, dto_modify_end(dto, "qcom_tzlog"));

out:
	return err;
}
#endif

#if defined(PLATFORM_HLOS_SPLIT_DTBO) && PLATFORM_HLOS_SPLIT_DTBO
static size_result_t
vm_dt_split(void *base, size_t size, dto_t **dto, size_t *offset)
{
	error_t ret	 = OK;
	size_t	dto_size = dto_get_size(*dto);

	error_t e = dto_finalise(*dto);
	if (e != OK) {
		ret = ERROR_NOMEM;
		goto out;
	}

	dto_size = dto_get_size(*dto);

	// The first DTBO should not have taken more than the available size
	assert(dto_size <= size);

	// Free the first DTBO.
	dto_deinit(*dto);
	*dto = NULL;

	// DTBs are required to have 8-byte alignment
	*offset += util_balign_up(dto_size, 8U);

	// Start the second DTBO immediately after the first.
	*dto = dto_init((char *)base + (*offset), size - (*offset), NULL);
	if (*dto == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}
out:
	return (size_result_t){
		.r = dto_size,
		.e = ret,
	};
}
#endif

static error_t
vm_dt_add_rm_overlay_support(dto_t				 *dto,
			     const struct vdevice_msg_queue_pair *msgq_pair)
{
	error_t err = OK;

	CHECK_DTO(err, dto_property_add_u32(dto, "qcom,free-irq-start", 960));

	CHECK_DTO(err, dto_property_add_empty(dto, "qcom,is-full-duplex"));
	CHECK_DTO(err,
		  dto_property_add_u32(dto, "qcom,tx-message-size",
				       (uint32_t)msgq_pair->tx_max_msg_size));
	CHECK_DTO(err,
		  dto_property_add_u32(dto, "qcom,rx-message-size",
				       (uint32_t)msgq_pair->rx_max_msg_size));
	CHECK_DTO(err,
		  dto_property_add_u32(dto, "qcom,tx-queue-depth",
				       (uint32_t)msgq_pair->tx_queue_depth));
	CHECK_DTO(err,
		  dto_property_add_u32(dto, "qcom,rx-queue-depth",
				       (uint32_t)msgq_pair->rx_queue_depth));

out:
	return err;
}

static error_t
vm_dt_generate_rm_rpc_node(dto_t *dto, const vdevice_node_t *node,
			   const struct vdevice_msg_queue_pair *msgq_pair)
{
	error_t err = OK;

	char	node_name[128];
	int32_t snprintf_ret = snprintf(node_name, sizeof(node_name),
					"qcom,resource-manager-rpc@%016lx",
					msgq_pair->tx_vm_cap);

	if ((snprintf_ret < 0) ||
	    (snprintf_ret >= (int32_t)sizeof(node_name))) {
		err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	CHECK_DTO(err, dto_node_begin(dto, node_name));

	const char *rpc_compat[VDEVICE_MAX_PUSH_COMPATIBLES];

	assert(node->push_compatible_num <= VDEVICE_MAX_PUSH_COMPATIBLES);
	for (index_t j = 0; j < node->push_compatible_num; j++) {
		rpc_compat[j] = node->push_compatible[j];
	}
	CHECK_DTO(err,
		  dto_property_add_stringlist(dto, "compatible", rpc_compat,
					      node->push_compatible_num));

	uint64_t reg[2] = { msgq_pair->tx_vm_cap, msgq_pair->rx_vm_cap };
	CHECK_DTO(err, dto_property_add_u64array(dto, "reg", reg, 2));

	interrupt_data_t interrupts[2] = { msgq_pair->tx_vm_virq,
					   msgq_pair->rx_vm_virq };
	CHECK_DTO(err, dto_property_add_interrupts_array(
			       dto, "interrupts", interrupts,
			       (count_t)util_array_size(interrupts)));

	// dto_property_add_empty(dto, "qcom,console-dev");	// for SVM
	err = vm_dt_add_rm_overlay_support(dto, msgq_pair);
	if (err != OK) {
		goto out;
	}

	CHECK_DTO(err, dto_node_end(dto, node_name));

out:
	return err;
}

static error_t
vm_dt_rm_rpc_node(const vm_t *hlos, dto_t *dto)
{
	error_t err = OK;

	// Find the RM RPC node
	vdevice_node_t		      *node	 = NULL;
	struct vdevice_msg_queue_pair *msgq_pair = NULL;

	loop_list(node, &hlos->vm_config->vdevice_nodes, vdevice_)
	{
		if (node->type == VDEV_RM_RPC) {
			msgq_pair = node->config.msg_queue_pair;
			if (msgq_pair->peer == VMID_RM) {
				break;
			}
			msgq_pair = NULL;
		}
	}
	assert(msgq_pair != NULL);

	// Start the resource-manager node
	err = vm_dt_generate_rm_rpc_node(dto, node, msgq_pair);

	return err;
}

typedef struct {
	struct vdevice_watchdog *wdt;
	error_t			 err;
	uint8_t			 pad[4];
} vm_dt_wdt_info;

static error_t
vm_dt_generate_root_properties(dto_t *dto)
{
	error_t err = OK;

	CHECK_DTO(err, dto_property_add_u32(dto, "#address-cells", 2));
	CHECK_DTO(err, dto_property_add_u32(dto, "#size-cells", 0));
	const char *hyp_compat[3] = { "qcom,gunyah-hypervisor-1.0",
				      "qcom,gunyah-hypervisor", "simple-bus" };
	CHECK_DTO(err, dto_property_add_stringlist(dto, "compatible",
						   hyp_compat, 3));
	// FIXME: interrupt-parent we assume is in the root

	CHECK_DTO(err, dto_node_begin(dto, "qcom,gunyah-vm"));
	const char *id_compat[2] = { "qcom,gunyah-vm-id-1.0",
				     "qcom,gunyah-vm-id" };
	CHECK_DTO(err,
		  dto_property_add_stringlist(dto, "compatible", id_compat, 2));
	CHECK_DTO(err, dto_property_add_u32(dto, "qcom,vmid", VMID_HLOS));
	CHECK_DTO(err, dto_property_add_string(dto, "qcom,vendor", "Qualcomm"));
	CHECK_DTO(err, dto_node_end(dto, "qcom,gunyah-vm"));

out:
	return err;
}

static error_t
vm_dt_create_hlos_hypervisor_node(vm_t *hlos, dto_t *dto)
{
	error_t err = OK;

	CHECK_DTO(err, dto_modify_begin_by_path(dto, "/"));

	CHECK_DTO(err, dto_node_begin(dto, "hypervisor"));

	err = vm_dt_generate_root_properties(dto);
	if (err != OK) {
		goto out;
	}

	err = vm_dt_rm_rpc_node(hlos, dto);
	if (err != OK) {
		goto out;
	}

	CHECK_DTO(err, dto_node_end(dto, "hypervisor"));

	CHECK_DTO(err, dto_modify_end_by_path(dto, "/"));

out:
	return err;
}

vm_dt_create_hlos_ret_t
vm_dt_create_hlos(void *base, size_t size, vmaddr_t log_ipa, size_t log_size)
{
	vm_dt_create_hlos_ret_t ret = { .err = OK };
	error_t			e;

	dto_t *dto = dto_init(base, size, NULL);
	if (dto == NULL) {
		ret.err = ERROR_NOMEM;
		goto out;
	}

	vm_t *hlos = vm_lookup(VMID_HLOS);
	assert(hlos != NULL);
	assert(hlos->vm_config != NULL);

	// First, generate a minimal overlay to create /hypervisor. Note that
	// the UEFI RM RPC driver requires this overlay to be applicable to an
	// empty tree, so it must not refer to any other nodes.
	e = vm_dt_create_hlos_hypervisor_node(hlos, dto);
	if (e != OK) {
		ret = (vm_dt_create_hlos_ret_t){ .err = e };
		goto out;
	}

#if defined(PLATFORM_HLOS_SPLIT_DTBO) && PLATFORM_HLOS_SPLIT_DTBO
	size_t offset		      = 0U;
	ret.dtbos[ret.num_dtbos].base = dto_get_dtbo(dto);

	size_result_t res = vm_dt_split(base, size, &dto, &offset);
	ret.err		  = res.e;
	if (ret.err != OK) {
		goto out;
	}
	ret.dtbos[ret.num_dtbos].size = res.r;
	ret.num_dtbos++;
#endif // PLATFORM_HLOS_SPLIT_DTBO

	// Register a dummy context for the root node, with impossible cell
	// counts to ensure we never accidentally use them (since we don't know
	// the real counts, and assuming values may break the patched DT).
	e = dto_register_path_ctx(dto, "/", UINT32_MAX, UINT32_MAX, true);
	if (e != OK) {
		LOG_ERR(e);
		ret = (vm_dt_create_hlos_ret_t){ .err = e };
		goto out;
	}

	// If we're generating replacements for any nodes in the base DT, we
	// need to patch those nodes to change their phandles first, so that
	// the patch process doesn't get confused by the duplicate phandles in
	// the replacement nodes.
	e = vm_creation_replace_symbols(hlos, dto);
	if (e != OK) {
		LOG_ERR(e);
		ret = (vm_dt_create_hlos_ret_t){ .err = e };
		goto out;
	}

	// Generate the /vsoc node and its contents.
	e = vm_creation_patch_vsoc_devices(hlos, dto);
	if (e != OK) {
		LOG_ERR(e);
		ret = (vm_dt_create_hlos_ret_t){ .err = e };
		goto out;
	}

	// If the RM log is exposed to HLOS, and the TZ log driver has a
	// DT node, patch the node to add the RM log address.
#if defined(CONFIG_TZ_RM_LOG)
	if (!platform_is_in_secure_state() && (log_size != 0U)) {
		ret.err = vm_dt_map_rm_logs(dto, log_ipa, log_size);
		if (ret.err != OK) {
			goto out;
		}
	}
#else
	(void)log_ipa;
	(void)log_size;
#endif

	e = vm_dt_update_hlos_wdt(hlos, dto);
	if (e != OK) {
		ret = (vm_dt_create_hlos_ret_t){ .err = e };
		goto out;
	}

	e = vgic_dto_finalise(dto, hlos);
	if (e != OK) {
		ret = (vm_dt_create_hlos_ret_t){ .err = e };
		goto out;
	}

	e = platform_dto_finalise(dto, hlos, base);
	if (e != OK) {
		ret = (vm_dt_create_hlos_ret_t){ .err = e };
		goto out;
	}

	e = dto_finalise(dto);
	if (e != OK) {
		ret = (vm_dt_create_hlos_ret_t){ .err = e };
		goto out;
	}

	ret.dtbos[ret.num_dtbos].base = dto_get_dtbo(dto);
	ret.dtbos[ret.num_dtbos].size = dto_get_size(dto);
	ret.num_dtbos++;

out:
	if (dto != NULL) {
		dto_deinit(dto);
	}

	return ret;
}

error_t
vm_dt_apply_hlos_overlay(vm_t *hlos_vm)
{
	error_t err = OK;

	paddr_t orig_dtb_addr = hlos_vm->mem_base + hlos_vm->image_dt_offset;
	size_t	dtb_region_size;
	cap_id_result_t cap_ret;
	cap_id_t	vm_me;
	void	       *dtb_process_buf;
	void	       *overlay_dtbo = NULL;

	vm_me = vm_memory_get_owned_extent(hlos_vm, MEM_TYPE_NORMAL);

	dtb_region_size = hlos_vm->image_dt_size;

	cap_ret.e = memextent_map_partial(vm_me, rm_get_rm_addrspace(),
					  orig_dtb_addr, orig_dtb_addr,
					  dtb_region_size, PGTABLE_ACCESS_RW,
					  PGTABLE_VM_MEMTYPE_NORMAL_WB, false);
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

	(void)fdt_pack(dtb_process_buf);

	size_t new_dtb_size = fdt_totalsize(dtb_process_buf);
	assert(new_dtb_size <= dtb_region_size);

	(void)memscpy((void *)orig_dtb_addr, dtb_region_size, dtb_process_buf,
		      new_dtb_size);
	cache_clean_by_va((void *)orig_dtb_addr, new_dtb_size);

	hlos_vm->image_dt_size = new_dtb_size;

out:
	if (cap_ret.e == OK) {
		error_t e = memextent_unmap_partial(
			vm_me, rm_get_rm_addrspace(), orig_dtb_addr,
			orig_dtb_addr, dtb_region_size);
		if (e != OK) {
			panic("memextent_unmap_partial function failed\n");
		}
	}

	if (overlay_dtbo != NULL) {
		free(overlay_dtbo);
	}

	return err;
}
