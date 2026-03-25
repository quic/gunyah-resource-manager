// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>

#include <rm_types.h>
#include <util.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <utils/list.h>

#include <dt_linux.h>
#include <dt_overlay.h>
#include <dtb_parser.h>
#include <event.h>
#include <guest_interface.h>
#include <log.h>
#include <mem_region.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_creation_dt.h>
#include <vm_mgnt.h>

#include "dto_construct.h"

static char *
vm_creation_append_unit_addr(const char *generate, uint64_t addr);

error_t
dto_create_doorbell(const struct vdevice_node *node, dto_t *dto,
		    uint32_t *phandle)
{
	error_t e = OK;

	struct vdevice_doorbell *cfg = node->config.doorbell;

	char *path = vm_creation_append_unit_addr(node->generate, cfg->vm_cap);
	if (path == NULL) {
		e = ERROR_NOMEM;
		goto err_begin;
	}

	e = dto_construct_begin_path(dto, path);
	if (e != OK) {
		goto err_begin;
	}

	if (cfg->source) {
		// below code should be OK
		const char *c[] = { "qcom,gunyah-doorbell-source",
				    "qcom,gunyah-capability" };

		e = vm_creation_add_compatibles(
			node, c, (count_t)util_array_size(c), dto);
	} else {
		const char *c[] = { "qcom,gunyah-doorbell",
				    "qcom,gunyah-capability" };

		e = vm_creation_add_compatibles(
			node, c, (count_t)util_array_size(c), dto);
	}
	if (e != OK) {
		goto err;
	}

	// FIXME: double check if cap is correct
	e = dto_property_add_u64(dto, "reg", cfg->vm_cap);
	if (e != OK) {
		goto err;
	}

	if (!cfg->source) {
		e = dto_property_add_interrupts_array(dto, "interrupts",
						      &cfg->vm_virq, 1);
		if (e != OK) {
			goto err;
		}
	}

	if (phandle != NULL) {
		e = dto_property_add_phandle(dto, phandle);
		if (e != OK) {
			goto err;
		}
	}

	e = dto_property_add_u32(dto, "qcom,label", cfg->label);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "label", cfg->label);
	if (e != OK) {
		goto err;
	}

err:
	(void)0;

	error_t ret;
	ret = dto_construct_end_path(dto, path);
	if (e == OK) {
		e = ret;
	}

err_begin:
	free(path);

	return e;
}

error_t
dto_create_msg_queue(const struct vdevice_node *node, dto_t *dto)
{
	error_t e = OK;

	struct vdevice_msg_queue *cfg = node->config.msg_queue;

	char *path = vm_creation_append_unit_addr(node->generate, cfg->vm_cap);
	if (path == NULL) {
		e = ERROR_NOMEM;
		goto err_begin;
	}

	e = dto_construct_begin_path(dto, path);
	if (e != OK) {
		goto err_begin;
	}

	const char *c[] = { "qcom,gunyah-message-queue",
			    "qcom,gunyah-capability" };

	e = vm_creation_add_compatibles(node, c, (count_t)util_array_size(c),
					dto);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u64(dto, "reg", cfg->vm_cap);
	if (e != OK) {
		goto err;
	}

	const char *tag = cfg->tx ? "is-sender" : "is-receiver";

	e = dto_property_add_empty(dto, tag);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "tx_message_size", cfg->msg_size);
	if (e != OK) {
		goto err;
	}
	e = dto_property_add_u32(dto, "tx_queue_depth", cfg->queue_depth);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_interrupts_array(dto, "interrupts", &cfg->vm_virq,
					      1);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "qcom,label", cfg->label);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "label", cfg->label);
	if (e != OK) {
		goto err;
	}

err:
	(void)0;

	error_t ret;
	ret = dto_construct_end_path(dto, path);
	if (e == OK) {
		e = ret;
	}

err_begin:
	free(path);

	return e;
}

error_t
dto_guid_to_string(uint8_t *guid, size_t guid_len, char *output,
		   size_t output_len)
{
	error_t ret = OK;

	if (guid_len < 16U) {
		(void)printf("Error: invalid guid len %zu\n", guid_len);
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	int32_t p_ret = snprintf(output, output_len,
				 "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
				 "%02x%02x-%02x%02x%02x%02x%02x%02x",
				 guid[0], guid[1], guid[2], guid[3], guid[4],
				 guid[5], guid[6], guid[7], guid[8], guid[9],
				 guid[10], guid[11], guid[12], guid[13],
				 guid[14], guid[15]);
	if ((p_ret < 0) || ((size_t)p_ret >= output_len)) {
		(void)printf("Error: failed to convert guid to string\n");
		ret = ERROR_DENIED;
		goto out;
	}

out:
	return ret;
}

static error_t
dto_add_msg_queue_properties(const struct vdevice_node *node, dto_t *dto,
			     const struct vdevice_msg_queue_pair *cfg)
{
	error_t e = OK;

	e = dto_property_add_u32(dto, "qcom,free-irq-start", 0);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_empty(dto, "qcom,is-full-duplex");
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "qcom,tx-message-size",
				 (uint32_t)cfg->tx_max_msg_size);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "qcom,rx-message-size",
				 (uint32_t)cfg->rx_max_msg_size);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "qcom,tx-queue-depth",
				 (uint32_t)cfg->tx_queue_depth);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "qcom,rx-queue-depth",
				 (uint32_t)cfg->rx_queue_depth);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "qcom,vdevice-handle", node->handle);
	if (e != OK) {
		goto err;
	}

err:
	return e;
}

error_t
dto_create_msg_queue_pair(const struct vdevice_node *node, dto_t *dto)
{
	error_t e = OK;

	struct vdevice_msg_queue_pair *cfg = node->config.msg_queue_pair;

	char *path =
		vm_creation_append_unit_addr(node->generate, cfg->rx_vm_cap);
	if (path == NULL) {
		e = ERROR_NOMEM;
		goto err_begin;
	}

	e = dto_construct_begin_path(dto, path);
	if (e != OK) {
		goto err_begin;
	}

	const char *c[] = { "qcom,gunyah-message-queue",
			    "qcom,gunyah-capability" };

	e = vm_creation_add_compatibles(node, c, (count_t)util_array_size(c),
					dto);
	if (e != OK) {
		goto err;
	}

	uint64_t reg[2] = { cfg->tx_vm_cap, cfg->rx_vm_cap };

	e = dto_property_add_u64array(dto, "reg", reg, 2);
	if (e != OK) {
		goto err;
	}

	interrupt_data_t interrupts[] = { cfg->tx_vm_virq, cfg->rx_vm_virq };

	e = dto_property_add_interrupts_array(
		dto, "interrupts", interrupts,
		(count_t)util_array_size(interrupts));
	if (e != OK) {
		goto err;
	}

	if (cfg->has_peer_vdevice && cfg->has_valid_peer) {
		e = dto_property_add_u32(dto, "qcom,peer-vmid", cfg->peer);
		if (e != OK) {
			goto err;
		}
	}

	// dto_property_add_empty(dto, "qcom,console-dev");	// for SVM
	e = dto_add_msg_queue_properties(node, dto, cfg);
	if (e != OK) {
		goto err;
	}

	// only generate peer info for message queue pair and skip for rm rpc
	if ((node->type == VDEV_MSG_QUEUE_PAIR) && (cfg->has_peer_vdevice)) {
		e = dto_property_add_string(dto, "peer", cfg->peer_id);
		if (e != OK) {
			goto err;
		}
	}

	if (node->type == VDEV_MSG_QUEUE_PAIR) {
		e = dto_property_add_u32(dto, "qcom,label", cfg->label);
		if (e != OK) {
			goto err;
		}

		e = dto_property_add_u32(dto, "label", cfg->label);
		if (e != OK) {
			goto err;
		}
	}

err:
	(void)0;

	error_t ret;
	ret = dto_construct_end_path(dto, path);
	if (e == OK) {
		e = ret;
	}

err_begin:
	free(path);

	return e;
}

static error_t
dtbo_add_memory_region(dto_t *dto, vmid_t self, label_t label,
		       bool buffer_property)
{
	error_t e = OK;

	bool is_external = false;

	memparcel_t *mp;
	foreach_memparcel_by_target_vmid (mp, self) {
		if (memparcel_get_label(mp) == label) {
			// FIXME: do we need to check multiple buffer with same
			// label?
			break;
		}
	}

	if (mp == NULL) {
		e = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	uint32_t mem_phandle = memparcel_get_phandle(mp, self, &is_external);
	if (mem_phandle == DTO_PHANDLE_UNSET) {
		e = ERROR_FAILURE;
		goto out;
	}

	if (buffer_property) {
		if (is_external) {
			e = dto_property_add_u32(dto, "buffer", mem_phandle);
		} else {
			e = dto_property_ref_internal(dto, "buffer",
						      mem_phandle);
		}
		if (e != OK) {
			goto out;
		}
	}

	if (is_external) {
		e = dto_property_add_u32(dto, "memory-region", mem_phandle);
	} else {
		e = dto_property_ref_internal(dto, "memory-region",
					      mem_phandle);
	}
out:
	return e;
}

error_t
dto_create_shm(const struct vdevice_node *node, dto_t *dto, vmid_t self)
{
	error_t e = OK;

	struct vdevice_shm *cfg = node->config.shm;

	uint32_t db_src_phandle = 0U, db_phandle = 0U;

	// create doorbells if needed
	if (!cfg->is_plain_shm) {
		assert(cfg->db_src != NULL);
		assert(cfg->db != NULL);

		e = dto_create_doorbell(cfg->db_src, dto, &db_src_phandle);
		if (e != OK) {
			goto err_create_doorbell;
		}

		e = dto_create_doorbell(cfg->db, dto, &db_phandle);
		if (e != OK) {
			goto err_create_doorbell;
		}
	}

	e = dto_construct_begin_path(dto, node->generate);
	if (e != OK) {
		goto err_node_begin;
	}

	const count_t compatible_count = 1;

	const char *compatible = NULL;
	if (cfg->is_plain_shm) {
		compatible = "qcom,shared-memory";
	} else {
		compatible = "qcom,gunyah-shm-doorbell";
	}

	e = vm_creation_add_compatibles(node, &compatible, compatible_count,
					dto);
	if (e != OK) {
		goto out;
	}

	e = dtbo_add_memory_region(dto, self, cfg->label, true);
	if (e != OK) {
		if (cfg->is_memory_optional) {
			// reset error if memory is optional and we cannot find
			// the corresponding memory parcel
			e = OK;
		} else {
			goto out;
		}
	}

	e = dto_property_add_u32(dto, "peer", cfg->peer);
	if (e != OK) {
		goto out;
	}

	e = dto_property_add_u32(dto, "qcom,label", cfg->label);
	if (e != OK) {
		goto out;
	}

	e = dto_property_add_u32(dto, "label", cfg->label);
	if (e != OK) {
		goto out;
	}

	if (!cfg->is_plain_shm) {
		e = dto_property_ref_internal(dto, "tx-doorbell",
					      db_src_phandle);
		if (e != OK) {
			goto out;
		}

		e = dto_property_ref_internal(dto, "rx-doorbell", db_phandle);
		if (e != OK) {
			goto out;
		}
	}

	if (cfg->dma_base != (uint64_t)(-1)) {
		e = dto_property_add_u64(dto, "dma_base", cfg->dma_base);
		if (e != OK) {
			goto out;
		}
	}

out:
	(void)0;

	error_t ret;
	ret = dto_construct_end_path(dto, node->generate);
	if (e == OK) {
		e = ret;
	}

err_node_begin:
err_create_doorbell:
	return e;
}

error_t
dto_create_watchdog(const struct vdevice_node *node, dto_t *dto)
{
	error_t ret;

	struct vdevice_watchdog *cfg = node->config.watchdog;

	assert(cfg->node_path != NULL);

	CHECK_DTO(ret, dto_modify_begin_by_path(dto, cfg->node_path));
	if (!cfg->defined_bark_virq) {
		CHECK_DTO(ret, dto_property_add_interrupts_array(
				       dto, "interrupts", &cfg->bark_virq, 1));
	}
#if defined(PLATFORM_SBSA_WDT) && PLATFORM_SBSA_WDT
	if ((cfg->type == WATCHDOG_EMULATION_ARM_SBSA) && !cfg->defined_addr) {
		dto_addrrange_t reg[2] = {
			{ .addr = cfg->base, .size = PAGE_SIZE },
			{ .addr = cfg->base + SBSA_WATCHDOG_FRAME_STRIDE,
			  .size = PAGE_SIZE }
		};
		CHECK_DTO(ret, dto_property_add_addrrange_array(
				       dto, "reg", reg, util_array_size(reg),
				       cfg->addr_cells, cfg->size_cells));
	}
#elif defined(PLATFORM_QCOM_WDT_REG) && PLATFORM_QCOM_WDT_REG
	if ((cfg->type == WATCHDOG_EMULATION_QCOM) && !cfg->defined_addr) {
		dto_addrrange_t reg[1] = { { .addr = cfg->base,
					     .size = cfg->size } };
		CHECK_DTO(ret, dto_property_add_addrrange_array(
				       dto, "reg", reg, util_array_size(reg),
				       cfg->addr_cells, cfg->size_cells));
	}
#endif
	CHECK_DTO(ret, dto_modify_end_by_path(dto, cfg->node_path));

out:
	return ret;
}

static error_t
dto_add_virtio_mmio_props(const struct vdevice_node *node, dto_t *dto,
			  vmid_t self, const struct vdevice_virtio *cfg,
			  const ctx_t *parent_ctx)
{
	error_t e;

	if (node->bus != VDEVICE_BUS_MMIO) {
		e = ERROR_OBJECT_CONFIG;
		goto err;
	}

	const char *c[] = { "virtio,mmio" };
	e = vm_creation_add_compatibles(node, c, (count_t)util_array_size(c),
					dto);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_addrrange(dto, "reg", parent_ctx->child_addr_cells,
				       cfg->mmio.ipa,
				       parent_ctx->child_size_cells,
				       cfg->mmio.size);
	if (e != OK) {
		goto err;
	}

	if (cfg->mmio.have_shm) {
		e = dtbo_add_memory_region(dto, self, cfg->mmio.label, false);
		if (e != OK) {
			goto err;
		}
	}

	e = dto_property_add_interrupts_array(dto, "interrupts",
					      &cfg->mmio.virq, 1);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "qcom,label", cfg->mmio.label);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "label", cfg->mmio.label);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u64(dto, "dma_base", cfg->mmio.dma_base);
	if (e != OK) {
		goto err;
	}

	if (cfg->backend.valid) {
		e = dto_property_add_u32(dto, "peer", cfg->backend.vm);
		if (e != OK) {
			goto err;
		}
	}

	if (cfg->mmio.dma_coherent) {
		e = dto_property_add_empty(dto, "dma-coherent");
		if (e != OK) {
			goto err;
		}
	}

err:
	return e;
}

static char *
dto_begin_vsoc_device(dto_t *dto, const void *base_dtb, const char *generate,
		      char *patch, uintptr_t address)
{
	error_t e;

	char *path = NULL;

	if (base_dtb == NULL) {
		const char   vsoc_path_prefix[] = "/vsoc/";
		const size_t prefix_len		= sizeof(vsoc_path_prefix) - 1U;

		// Patching the HLOS device tree. Assume that we're in the /vsoc
		// node and that the generate string is fixed accordingly.
		assert((generate != NULL) && (patch == NULL));
		assert(strncmp(generate, vsoc_path_prefix, prefix_len) == 0);

		path = vm_creation_append_unit_addr(generate, address);
		if (path == NULL) {
			e = ERROR_NOMEM;
			goto out;
		}

		const char *node = strrchr(path, (int)'/');
		assert(node != NULL);
		node++; // Drop leading '/'
		CHECK_DTO(e, dto_node_begin(dto, node));
	} else if (patch != NULL) {
		path = patch;
		if (fdt_path_offset(base_dtb, path) < 0) {
			e = ERROR_ARGUMENT_INVALID;
			LOG_ERR(e);
			goto out;
		}

		CHECK_DTO(e, dto_modify_begin_by_path(dto, path));
	} else if (generate != NULL) {
		path = vm_creation_append_unit_addr(generate, address);
		if (path == NULL) {
			e = ERROR_NOMEM;
			goto out;
		}

		CHECK_DTO(e, dto_construct_begin_path(dto, path));
	} else {
		// Patching or generation not requested, nothing to do
		e = OK;
	}

out:
	if (e != OK) {
		free(path);
		path = NULL;
	}
	return path;
}

static error_t
dto_end_vsoc_device(dto_t *dto, const void *base_dtb, const char *generate,
		    char *patch, char *path)
{
	error_t e;

	if (base_dtb == NULL) {
		const char *node = strrchr(path, (int)'/');
		assert(node != NULL);
		node++; // Drop leading '/'
		CHECK_DTO(e, dto_node_end(dto, node));
		free(path);
	} else if (patch != NULL) {
		CHECK_DTO(e, dto_modify_end_by_path(dto, path));
	} else if (generate != NULL) {
		CHECK_DTO(e, dto_construct_end_path(dto, path));
		free(path);
	} else {
		// Patching or generation not requested, nothing to do
		e = OK;
	}

out:
	return e;
}

error_t
dto_create_virtio_mmio(const void *base_dtb, const struct vdevice_node *node,
		       dto_t *dto, vmid_t self)
{
	error_t		       e;
	struct vdevice_virtio *cfg = node->config.virtio;

	assert(node->bus == VDEVICE_BUS_MMIO);

	char *path = dto_begin_vsoc_device(dto, base_dtb, node->generate,
					   cfg->patch, cfg->mmio.ipa);
	if (path == NULL) {
		// No path to patch; nothing more to do.
		e = OK;
		goto out;
	}

	ctx_t parent_ctx;
	e = dto_get_path_ctx(dto, path, &parent_ctx, true);
	if (e != OK) {
		goto out;
	}

	if (!parent_ctx.child_addr_is_phys) {
		(void)printf(
			"Warning: patched addr %#zx in %s is not physical!\n",
			cfg->mmio.ipa, path);
	}

	e = dto_add_virtio_mmio_props(node, dto, self, cfg, &parent_ctx);

	CHECK_DTO(e, dto_end_vsoc_device(dto, base_dtb, node->generate,
					 cfg->patch, path));

out:
	if (e != OK) {
		free(path);
	}

	return e;
}

static error_t
dto_add_pci_common(const struct vdevice_pci *cfg, dto_t *dto,
		   const ctx_t *parent_ctx)
{
	error_t e;

	e = dto_property_add_string(dto, "device_type", "pci");
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "#address-cells", 3);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "#size-cells", 2);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_u32(dto, "#interrupt-cells", 1);
	if (e != OK) {
		goto err;
	}

	e = dto_property_add_addrrange(dto, "reg",
				       (count_t)parent_ctx->child_addr_cells,
				       cfg->config_ipa,
				       (count_t)parent_ctx->child_size_cells,
				       cfg->config_size);
	if (e != OK) {
		goto err;
	}

	uint32_t bus_range[2] = { 0U,
				  (uint32_t)(cfg->config_size >> 20U) - 1U };
	e = dto_property_add_u32array(dto, "bus-range", bus_range, 2U);
	if (e != OK) {
		goto err;
	}

	if (cfg->linux_pci_domain != ~(uint32_t)0U) {
		e = dto_property_add_u32(dto, "linux,pci-domain",
					 cfg->linux_pci_domain);
		if (e != OK) {
			goto err;
		}
	}

	if (cfg->dma_coherent) {
		e = dto_property_add_empty(dto, "dma-coherent");
		if (e != OK) {
			goto err;
		}
	}
err:
	return e;
}

static error_t
dto_add_pci_ranges(const struct vdevice_pci *cfg, dto_t *dto,
		   const ctx_t *parent_ctx)
{
	error_t e;

	uint32_t ranges[7] = { 0 };
	if (((cfg->npmem_size + cfg->npmem_size) <= util_bit(32U)) ||
	    (parent_ctx->child_addr_cells == 1U)) {
		// Either the NP aperture is within the 4GiB boundary, or we
		// have 32-bit host addresses and must rely on the alias.
		// 32-bit Memory, non-prefetchable, non-relocatable
		ranges[0U] = 0x02000000U;
		// 32-bit bus address
		ranges[1U] = 0U;
		ranges[2U] = (uint32_t)(cfg->npmem_ipa & util_mask(32U));
		// Host address
		if (parent_ctx->child_addr_cells > 1U) {
			// Host address is 64-bit
			ranges[3U] = (uint32_t)(cfg->npmem_ipa >> 32U);
			ranges[4U] =
				(uint32_t)(cfg->npmem_ipa & util_mask(32U));
		} else {
			ranges[3U] =
				(uint32_t)(cfg->npmem_ipa & util_mask(32U));
		}
		// 32-bit size
		ranges[3U + parent_ctx->child_addr_cells] = 0U;
		ranges[4U + parent_ctx->child_addr_cells] =
			(uint32_t)(cfg->npmem_size & util_mask(32U));
	} else {
		assert(parent_ctx->child_addr_cells == 2U);
		// 64-bit Memory, non-prefetchable, non-relocatable
		ranges[0U] = 0x03000000U;
		// 64-bit bus address
		ranges[1U] = (uint32_t)(cfg->npmem_ipa >> 32U);
		ranges[2U] = (uint32_t)(cfg->npmem_ipa & util_mask(32U));
		// 64-bit host address
		ranges[3U] = (uint32_t)(cfg->npmem_ipa >> 32U);
		ranges[4U] = (uint32_t)(cfg->npmem_ipa & util_mask(32U));
		// 64-bit size
		ranges[5U] = (uint32_t)(cfg->npmem_size >> 32U);
		ranges[6U] = (uint32_t)(cfg->npmem_size & util_mask(32U));
	}

	e = dto_property_add_u32array(
		dto, "ranges", ranges,
		5U + (count_t)parent_ctx->child_addr_cells);
	if (e != OK) {
		goto err;
	}
err:
	return e;
}

static error_t
dto_add_pci_irqs(const vm_config_t *vm_cfg, const struct vdevice_pci *cfg,
		 dto_t *dto)
{
	error_t e;

	// FIXME: this code is platform-specific; it assumes a GIC.
	const count_t  addr_cells = vm_cfg->map_addr_cells;
	const uint32_t parent_phandle =
		((cfg->irq_parent_phandle == DTO_PHANDLE_UNSET) &&
		 (vm_cfg->vgic_phandle != ~0U))
			? vm_cfg->vgic_phandle
			: cfg->irq_parent_phandle;

	// Each entry in the interrupt-map property needs (#address-cells +
	// #interrupt-cells + 1 + parent #address-cells + parent
	// #interrupt-cells) cells for each entry. For PCI with a GIC, that is
	// between 8 and 10 cells, and in principle we could have up to 32
	// legacy IRQ lines to map (or 128 if we support multi-function). So,
	// allocate the array temporarily on the heap to avoid overflowing the
	// stack.
	const count_t interrupt_map_cells = 8U + addr_cells;
	uint32_t     *interrupt_map =
		calloc(util_array_size(cfg->legacy_virqs),
		       interrupt_map_cells * sizeof(uint32_t));
	if (interrupt_map == NULL) {
		e = ERROR_NOMEM;
		goto err;
	}

	count_t interrupt_map_entries = 0U;
	for (index_t i = 0U; i < util_array_size(cfg->legacy_virqs); i++) {
		if (cfg->legacy_virqs[i].irq == VIRQ_INVALID) {
			// Slot has no IRQ bound
			continue;
		}

		const index_t base =
			interrupt_map_entries * interrupt_map_cells;
		// Slot index is in bits 16:11 of the first address cell
		interrupt_map[base] = i << 11U;
		// Cell 4 contains the interrupt controller phandle
		interrupt_map[base + 4U] = parent_phandle;

		// If the interrupt parent node has an #address-cells property
		// (which it will if it is a GIC with an ITS), then due to a
		// quirk of the interrupt-map binding, we have to add that many
		// extra cells at this point. Their values do not matter; they
		// would hypothetically be used if the interrupt parent had an
		// interrupt-map property, as was the case on some old PowerPC
		// hardware. We just set them to 0.
		//
		// This would not be a big problem, except that we now need to
		// assume the #address-cells value used by the base DTB's GIC
		// node in the case of the primary VM.
		for (index_t j = 0U; j < addr_cells; j++) {
			interrupt_map[base + 5U + j] = 0U;
		}

		// The last 3 cells are the GIC-format interrupt property.
		const interrupt_data_t *d = &cfg->legacy_virqs[i];
		uint32_t		type, irq, flags;
		assert(!d->is_cpu_local);

		if ((d->irq >= 32U) && (d->irq < 1020U)) {
			type = DT_GIC_SPI;
			irq  = d->irq - 32U;
		} else if ((d->irq >= 4096U) && (d->irq < 5120U)) {
			type = DT_GIC_ESPI;
			irq  = d->irq - 4096U;
		} else {
			e = ERROR_ARGUMENT_INVALID;
			goto err_free_map;
		}
		flags = d->is_edge_triggering ? DT_GIC_IRQ_TYPE_EDGE_RISING
					      : DT_GIC_IRQ_TYPE_LEVEL_HIGH;
		interrupt_map[base + addr_cells + 5U] = type;
		interrupt_map[base + addr_cells + 6U] = irq;
		interrupt_map[base + addr_cells + 7U] = flags;

		if (parent_phandle == DTO_PHANDLE_UNSET) {
			// The parent phandle is unknown; generate an external
			// ref to fix it up, assuming that the GIC's symbol is
			// &intc. Note that this is only used for HLOS; we
			// require a phandle in the vdevice node for SVMs.
			e = dto_fixup_ref_external(
				dto, "interrupt-map", "intc",
				(base + 4U) * (uint32_t)sizeof(uint32_t));
			if (e != OK) {
				goto err_free_map;
			}
		}

		interrupt_map_entries++;
	}

	if (interrupt_map_entries != 0U) {
		// Interrupt map selects based on device ID only; all four lines
		// are tied together
		uint32_t interrupt_map_mask[4] = { 0xf800, 0x0, 0x0, 0x0 };
		e			       = dto_property_add_u32array(
			     dto, "interrupt-map-mask", interrupt_map_mask,
			     (count_t)util_array_size(interrupt_map_mask));
		if (e != OK) {
			goto err_free_map;
		}

		e = dto_property_add_u32array(
			dto, "interrupt-map", interrupt_map,
			interrupt_map_entries * interrupt_map_cells);
		if (e != OK) {
			goto err_free_map;
		}
	}

	e = OK;

err_free_map:
	free(interrupt_map);
err:
	return e;
}

static error_t
dto_add_pci_msis(const struct vdevice_pci *cfg, dto_t *dto)
{
	error_t e;

	if (cfg->msi_passthrough) {
		// We can't enable both passthrough and vdevice MSIs on the same
		// virtual RC (assuming we don't know all the slot allocations
		// yet).
		assert(!cfg->msi_vdevices);

		// We assume here that RM can allocate linear mapped virtual
		// device IDs based on the virtual RID, even if the physical
		// device IDs are not linear. Note that this currently only
		// works if the physical RID bits are all significant, which
		// is the case on our targets.
		e = dto_property_add_u32(dto, "msi-map-mask", 0xffffU);
		if (e != OK) {
			goto out;
		}

		// The msi-map has a single entry covering all RIDs and mapping
		// them linearly to device IDs starting at the specified base.
		// We assume the parent is a virtual ITS, which has #msi-cells
		// set to 1 for the ITS device ID.
		uint32_t msi_map[4] = {
			0x0,
			cfg->msi_parent_phandle,
			cfg->msi_passthrough_base,
			cfg->msi_passthrough_length,
		};
		e = dto_property_add_u32array(
			dto, "msi-map", msi_map,
			(count_t)util_array_size(msi_map));
		if (e != OK) {
			goto out;
		}
	} else if (cfg->msi_vdevices) {
		// Virtual MSIs can only be routed to virtual GIC SPIs at
		// present. SPI routing always ignores the RID, so we can use
		// msi-parent rather than msi-map. The GICD will need
		// msi-controller and mbi-ranges properties, and should have
		// #msi-cells 0 (or unset).
		e = dto_property_add_u32(dto, "msi-parent",
					 cfg->msi_parent_phandle);
		if (e != OK) {
			goto out;
		}

		if (cfg->msi_parent_phandle == DTO_PHANDLE_UNSET) {
			// The parent phandle is unknown; generate an external
			// ref to fix it up, assuming that the GIC's symbol is
			// &intc. Note that this is only used for HLOS; we
			// require a phandle in the vdevice node for SVMs.
			e = dto_fixup_ref_external(dto, "msi-parent", "intc",
						   0U);
			if (e != OK) {
				goto out;
			}
		}
	} else {
		// MSIs not enabled; don't add anything.
		e = OK;
	}

out:
	return e;
}

static char *
dto_get_pci_compatible(const struct vdevice_node *node)
{
	char	*ret;
	uint16_t vendor_id, device_id;

	if (node->type == VDEV_VIRTIO) {
		struct vdevice_virtio *cfg = node->config.virtio;
		vendor_id		   = 0x1af4U;
		device_id = (uint16_t)(0x1040U + (uint16_t)cfg->device_type);
	} else {
		// IDs unknown
		ret = NULL;
		goto out;
	}

	// Section 2.5 of the PCI Bus Binding (rev 2.1, 29/8/1998) gives a list
	// of seven compatible values to be set for every PCI child node, but we
	// only have enough information for (5) "pciVVVV,DDDD" with the vendor
	// and device IDs substituted. This string is usually sufficient, and
	// the virtio-iommu binding requires it specifically.
	const size_t len = strlen("pciVVVV,DDDD") + 1U;
	ret		 = malloc(len);
	if (ret == NULL) {
		goto out;
	}

	int32_t snp_ret = snprintf(ret, len, "pci%04x,%04x",
				   (unsigned)vendor_id, (unsigned)device_id);
	assert((snp_ret >= 0) && ((size_t)snp_ret < DTB_NODE_NAME_MAX));

out:
	return ret;
}

static char *
dto_get_pci_name(const struct vdevice_node *node, const char *base_compat)
{
	char *ret = (char *)malloc(DTB_NODE_NAME_MAX);
	if (ret == NULL) {
		goto out;
	}

	// We assume that all PCI vdevices are single-function devices, so
	// the unit address is always d,0 where d is the slot number.
	//
	// The PCI binding documents various generic names depending on the
	// class ID, but bus child node names are not practically meaningful and
	// we don't know the class ID anyway so we always fall back to the base
	// compatible string "pciVVVV,DDDD".
	int32_t snp_name_ret = snprintf(ret, DTB_NODE_NAME_MAX, "%s@%x,0",
					base_compat, node->pci.slot_index);
	assert((snp_name_ret >= 0) &&
	       ((size_t)snp_name_ret < DTB_NODE_NAME_MAX));

out:
	return ret;
}

static error_t
dto_create_pci_child(const struct vdevice_node *node, dto_t *dto)
{
	error_t e;
	char   *name = NULL;

	// Determine the device / vendor IDs and construct pciVVVV,DDDD.
	char *base_compat = dto_get_pci_compatible(node);
	if (base_compat == NULL) {
		e = ERROR_NOMEM;
		goto out;
	}

	// Construct the node name, with unit address appended. By default this
	// is derived from the base compatible name but can have special cases.
	name = dto_get_pci_name(node, base_compat);
	if (name == NULL) {
		e = ERROR_NOMEM;
		goto out;
	}

	CHECK_DTO(e, dto_node_begin(dto, name));

	const char *c[] = { base_compat };
	CHECK_DTO(e, vm_creation_add_compatibles(node, c, 1U, dto));
	CHECK_DTO(e, vm_creation_add_symbol(node, dto));
	CHECK_DTO(e, vm_creation_virtio_device_properties(node, dto));

	// PCI "reg" property encoding: 3 words of address, 2 of size. The first
	// word of the address contains BDF << 8; the rest MBZ. See
	// sections 4.1.1 and 2.5 of the PCI Bus Binding (rev 2.1, 29/8/1998)
	// for details.
	//
	// Note that this encoding is the same as the base address of the PCI
	// CAM region for the function, but the binding states that this
	// encoding is used even if the config mechanism is not CAM, so it
	// applies for PCIe ECAM too.
	//
	// We assume here that all PCI vdevices are single-function devices, so
	// BDF << 8 is just slot_index << 11.
	uint32_t reg[] = { node->pci.slot_index << 11U, 0U, 0U, 0U, 0U };
	CHECK_DTO(e, dto_property_add_u32array(dto, "reg", reg,
					       (count_t)util_array_size(reg)));

	if (node->pci.has_legacy_irq) {
		// If legacy IRQs are enabled, we must have an "interrupts"
		// property containing the value 1 (indicating IRQA).
		CHECK_DTO(e, dto_property_add_u32(dto, "interrupts", 1U));
	}

	CHECK_DTO(e, dto_node_end(dto, name));

out:
	free(name);
	free(base_compat);
	return e;
}

error_t
dto_create_pci(const void *base_dtb, const struct vdevice_node *node,
	       dto_t *dto, vmid_t vmid)
{
	error_t e;

	vm_t *vm = vm_lookup(vmid);
	assert(vm != NULL);

	const struct vdevice_pci *cfg = node->config.pci;

	char *path = dto_begin_vsoc_device(dto, base_dtb, node->generate,
					   cfg->patch, cfg->config_ipa);
	if (path == NULL) {
		// No path to patch; nothing more to do.
		e = OK;
		goto out;
	}

	const char *c[] = { "qcom,gunyah-virtual-pcie",
			    "pci-host-ecam-generic" };
	e = vm_creation_add_compatibles(node, c, (count_t)util_array_size(c),
					dto);
	if (e != OK) {
		LOG_ERR(e);
		goto out;
	}

	ctx_t parent_ctx;
	e = dto_get_path_ctx(dto, path, &parent_ctx, true);
	if (e != OK) {
		LOG_ERR(e);
		goto out;
	}

	e = dto_add_pci_common(cfg, dto, &parent_ctx);
	if (e != OK) {
		LOG_ERR(e);
		goto out;
	}

	e = dto_add_pci_ranges(cfg, dto, &parent_ctx);
	if (e != OK) {
		LOG_ERR(e);
		goto out;
	}

	e = dto_add_pci_irqs(vm->vm_config, cfg, dto);
	if (e != OK) {
		LOG_ERR(e);
		goto out;
	}

	e = dto_add_pci_msis(cfg, dto);
	if (e != OK) {
		LOG_ERR(e);
		goto out;
	}

	if (cfg->have_memory_region) {
		e = dtbo_add_memory_region(dto, vmid, cfg->label, false);
		if (e != OK) {
			LOG_ERR(e);
			goto out;
		}
	}

	// Generate child nodes if necessary
	vdevice_node_t *child_node = NULL;
	loop_list(child_node, &vm->vm_config->vdevice_nodes, vdevice_)
	{
		if (!child_node->export_to_dt ||
		    (child_node->bus != VDEVICE_BUS_PCI) ||
		    (child_node->pci.bus_config_ipa != cfg->config_ipa)) {
			continue;
		}

		CHECK_DTO(e, dto_create_pci_child(child_node, dto));
	}

	CHECK_DTO(e, dto_end_vsoc_device(dto, base_dtb, node->generate,
					 cfg->patch, path));

out:
	if (e != OK) {
		free(path);
	}

	return e;
}

error_t
vm_creation_add_compatibles(const struct vdevice_node *node,
			    const char *const	       compatibles[],
			    count_t compatible_cnt, dto_t *dto)
{
	error_t ret = OK;

	assert(node->push_compatible_num <= VDEVICE_MAX_PUSH_COMPATIBLES);

	if (util_add_overflows(compatible_cnt, node->push_compatible_num)) {
		ret = ERROR_ARGUMENT_SIZE;
		goto err_alloc_compatibles;
	}
	// handle compatibles /push_compatibles
	count_t total_cnt = compatible_cnt + node->push_compatible_num;

	const char **final_compatibles =
		calloc(total_cnt, sizeof(*final_compatibles));
	if (final_compatibles == NULL) {
		ret = ERROR_NOMEM;
		goto err_alloc_compatibles;
	}

	index_t i = 0;
	// copy the input DT compatibles first (if any)
	for (i = 0; i < node->push_compatible_num; ++i) {
		final_compatibles[i] = node->push_compatible[i];
	}
	// then add the generic compatibles
	for (index_t j = 0; j < compatible_cnt; ++j) {
		final_compatibles[i + j] = compatibles[j];
	}

	ret = dto_property_add_stringlist(dto, "compatible", final_compatibles,
					  total_cnt);
	if (ret != OK) {
		goto err_add_compatibles;
	}

err_add_compatibles:
	free(final_compatibles);
err_alloc_compatibles:
	return ret;
}

error_t
vm_creation_add_symbol(const struct vdevice_node *node, dto_t *dto)
{
	error_t ret;

	if (node->replace_symbol) {
		assert(node->symbol != NULL);
		// Create a new phandle property (replacing any existing one)
		// and then fix it up with named symbol, so the symbol points to
		// this node. This relies on vm_creation_replace_symbols()
		// having already been called to replace the phandle property of
		// the symbol's original target node.
		//
		// Note that we need to create a real unique phandle here even
		// though it will be discarded. That is because any property
		// named "phandle" will undergo an internal fixup before the
		// external fixup is applied, so overlay application might fail
		// if it isn't unique.
		uint32_t unused_phandle;
		CHECK_DTO(ret, dto_property_add_phandle(dto, &unused_phandle));
		CHECK_DTO(ret, dto_fixup_ref_external(dto, "phandle",
						      node->symbol, 0U));
	} else if (node->symbol != NULL) {
		// No support for defining new symbols yet
		ret = ERROR_UNIMPLEMENTED;
	} else {
		// Nothing to do
		ret = OK;
	}

out:
	return ret;
}

error_t
vm_creation_virtio_device_properties(const struct vdevice_node *node,
				     dto_t		       *dto)
{
	error_t ret;

	if (node->type == VDEV_VIRTIO) {
		if (node->config.virtio->device_type ==
		    VIRTIO_DEVICE_TYPE_IOMMU) {
			CHECK_DTO(ret, dto_property_add_u32(dto, "#iommu-cells",
							    0x1));
		} else {
			// No support for other devices yet
			ret = ERROR_UNIMPLEMENTED;
		}
	} else {
		// Nothing to do
		ret = OK;
	}

out:
	return ret;
}

error_t
vm_creation_replace_symbols(const vm_t *vm, dto_t *dto)
{
	error_t ret;

	vdevice_node_t *node = NULL;
	loop_list(node, &vm->vm_config->vdevice_nodes, vdevice_)
	{
		if (!node->export_to_dt || !node->replace_symbol) {
			continue;
		}

		assert(node->symbol != NULL);
		CHECK_DTO(ret, dto_modify_begin(dto, node->symbol));

		// Give the replaced node a new phandle so that references in
		// the existing tree will no longer find it.
		uint32_t dummy_phandle;
		CHECK_DTO(ret, dto_property_add_phandle(dto, &dummy_phandle));

		// Ensure that the replaced node doesn't have a driver loaded.
		CHECK_DTO(ret,
			  dto_property_add_string(dto, "status", "disabled"));

		CHECK_DTO(ret, dto_modify_end(dto, node->symbol));
	}
	ret = OK;

out:
	return ret;
}

static char *
vm_creation_append_unit_addr(const char *generate, uint64_t addr)
{
	error_t err = OK;

	assert(generate != NULL);
	size_t sz = strlen(generate) + DTB_NODE_NAME_MAX;

	char *ret = (char *)malloc(sz);
	if (ret == NULL) {
		(void)printf("Error: failed to allocate path for %s\n",
			     generate);
		err = ERROR_NOMEM;
		goto out;
	}

	int32_t snp_name_ret = snprintf(ret, sz, "%s@%lx", generate, addr);
	assert((snp_name_ret >= 0) && ((size_t)snp_name_ret <= sz));
out:
	if (err != OK) {
		free(ret);
		ret = NULL;
	}

	return ret;
}
