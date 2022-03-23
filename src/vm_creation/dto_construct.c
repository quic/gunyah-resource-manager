// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>

#include <rm-rpc.h>

#include <resource-manager.h>

#include <event.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform_vm_config.h>
#include <util.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_mgnt.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <dt_linux.h>
#include <dt_overlay.h>

#include "dto_construct.h"

static char *
dto_construct_append_capid(const char *generate, cap_id_t cap_id);

static error_t
add_compatibles(struct vdevice_node *node, char *compatibles[],
		count_t compatible_cnt, dto_t *dto);

error_t
dto_create_doorbell(struct vdevice_node *node, dto_t *dto, uint32_t *phandle)
{
	error_t e = OK;

	struct vdevice_doorbell *cfg = (struct vdevice_doorbell *)node->config;

	char *path = dto_construct_append_capid(node->generate, cfg->vm_cap);
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
		char *c[] = { "qcom,gunyah-doorbell-source",
			      "qcom,gunyah-capability" };

		e = add_compatibles(node, c, util_array_size(c), dto);
	} else {
		char *c[] = { "qcom,gunyah-doorbell",
			      "qcom,gunyah-capability" };

		e = add_compatibles(node, c, util_array_size(c), dto);
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
		uint32_t interrupts[3] = { 0, cfg->vm_virq - 32, 1 };
		e = dto_property_add_u32array(dto, "interrupts", interrupts, 3);
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
dto_create_msg_queue(struct vdevice_node *node, dto_t *dto)
{
	error_t e = OK;

	struct vdevice_msg_queue *cfg =
		(struct vdevice_msg_queue *)node->config;

	char *path = dto_construct_append_capid(node->generate, cfg->vm_cap);
	if (path == NULL) {
		e = ERROR_NOMEM;
		goto err_begin;
	}

	e = dto_construct_begin_path(dto, path);
	if (e != OK) {
		goto err_begin;
	}

	char *c[] = { "qcom,gunyah-message-queue", "qcom,gunyah-capability" };

	e = add_compatibles(node, c, util_array_size(c), dto);
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

	uint32_t interrupts[3] = { 0, cfg->vm_virq - 32, 1 };
	e = dto_property_add_u32array(dto, "interrupts", interrupts, 3);
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

	if (guid_len < 16) {
		printf("Error: invalid guid len %zu\n", guid_len);
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	int p_ret = snprintf(output, output_len,
			     "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
			     "%02x%02x-%02x%02x%02x%02x%02x%02x",
			     guid[0], guid[1], guid[2], guid[3], guid[4],
			     guid[5], guid[6], guid[7], guid[8], guid[9],
			     guid[10], guid[11], guid[12], guid[13], guid[14],
			     guid[15]);
	if ((p_ret < 0) || ((size_t)p_ret >= output_len)) {
		printf("Error: failed to convert guid to string\n");
		ret = ERROR_DENIED;
		goto out;
	}

out:
	return ret;
}

error_t
dto_create_msg_queue_pair(struct vdevice_node *node, dto_t *dto)
{
	error_t e = OK;

	struct vdevice_msg_queue_pair *cfg =
		(struct vdevice_msg_queue_pair *)node->config;

	char *path = dto_construct_append_capid(node->generate, cfg->rx_vm_cap);
	if (path == NULL) {
		e = ERROR_NOMEM;
		goto err_begin;
	}

	e = dto_construct_begin_path(dto, path);
	if (e != OK) {
		goto err_begin;
	}

	char *c[] = { "qcom,gunyah-message-queue", "qcom,gunyah-capability" };

	e = add_compatibles(node, c, util_array_size(c), dto);
	if (e != OK) {
		goto err;
	}

	uint64_t reg[2] = { cfg->tx_vm_cap, cfg->rx_vm_cap };

	e = dto_property_add_u64array(dto, "reg", reg, 2);
	if (e != OK) {
		goto err;
	}

	uint32_t interrupts[6] = { 0, cfg->tx_vm_virq - 32, 1,
				   0, cfg->rx_vm_virq - 32, 1 };
	e = dto_property_add_u32array(dto, "interrupts", interrupts, 6);
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
dtbo_add_memory_region(dto_t *dto, vmid_t self, label_t label)
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

	uint32_t mem_phandle = 0U;
	if (mp == NULL) {
		e = ERROR_ARGUMENT_INVALID;
		goto out;
	} else {
		mem_phandle = memparcel_get_phandle(mp, self, &is_external);
	}

	// FIXME: if the handle is not set correctly, should we refacter it,
	// and return error?

	if (is_external) {
		e = dto_property_add_u32(dto, "buffer", mem_phandle);
	} else {
		e = dto_property_ref_internal(dto, "buffer", mem_phandle);
	}
	if (e != OK) {
		goto out;
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
dto_create_shm(struct vdevice_node *node, dto_t *dto, vmid_t self)
{
	error_t e = OK;

	struct vdevice_shm *cfg = (struct vdevice_shm *)node->config;

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

	char *compatible = NULL;
	if (cfg->is_plain_shm) {
		compatible = "qcom,shared-memory";
	} else {
		compatible = "qcom,gunyah-shm-doorbell";
	}

	e = add_compatibles(node, &compatible, compatible_count, dto);
	if (e != OK) {
		goto out;
	}

	e = dtbo_add_memory_region(dto, self, cfg->label);
	if (e != OK) {
		goto out;
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
		e = dto_property_add_u32(dto, "tx-doorbell", db_src_phandle);
		if (e != OK) {
			goto out;
		}

		e = dto_property_add_u32(dto, "rx-doorbell", db_phandle);
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
add_compatibles(struct vdevice_node *node, char *compatibles[],
		count_t compatible_cnt, dto_t *dto)
{
	error_t ret = OK;

	if ((compatible_cnt > VDEVICE_MAX_PUSH_COMPATIBLES) ||
	    (node->push_compatible_num > VDEVICE_MAX_PUSH_COMPATIBLES)) {
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
	for (i = 0; i < compatible_cnt; ++i) {
		final_compatibles[i] = compatibles[i];
	}
	for (index_t j = 0; j < node->push_compatible_num; ++j) {
		final_compatibles[i + j] = node->push_compatible[j];
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

char *
dto_construct_append_capid(const char *generate, cap_id_t cap_id)
{
	error_t err = OK;

	size_t sz = strlen(generate) + DTB_NODE_NAME_MAX;

	char *ret = (char *)malloc(sz);
	if (ret == NULL) {
		printf("Error: failed to allocate path for %s\n", generate);
		err = ERROR_NOMEM;
		goto out;
	}

	int snp_name_ret = snprintf(ret, sz, "%s@%lx", generate, cap_id);
	assert((size_t)snp_name_ret <= sz);
out:
	if (err != OK) {
		free(ret);
		ret = NULL;
	}

	return ret;
}

error_t
dto_construct_begin_path(dto_t *dto, const char *path)
{
	error_t ret = OK;

	char *target = strdup(path);
	if (target == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	const char separator = '/';

	assert(target[0] == separator);

	char *name_start = target + 1;

	assert(*name_start != '\0');

	dto_modify_begin_by_path(dto, "/");

	char *name_end = NULL;
	do {
		name_end = strchr(name_start, separator);
		if (name_end == NULL) {
			break;
		}

		*name_end = '\0';

		ret = dto_node_begin(dto, name_start);
		if (ret != OK) {
			goto out;
		}

		name_start = name_end + 1;
	} while (name_end != NULL);

	// the generate should specify a node name
	// we can change it to return error latter
	assert(*name_start != '\0');

	// create the last node
	ret = dto_node_begin(dto, name_start);

out:
	free(target);
	return ret;
}

error_t
dto_construct_end_path(dto_t *dto, const char *path)
{
	error_t ret = OK;

	size_t sz = strlen(path);

	char *target = strdup(path);
	if (target == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	const char separator = '/';

	assert(target[0] == separator);

	// should have a node name
	assert(target[sz - 1] != '/');

	// remove the node name
	char *name_start = NULL;

	do {
		name_start = strrchr(target, separator);
		if (name_start == NULL) {
			break;
		}

		*name_start = '\0';

		ret = dto_node_end(dto, &name_start[1]);
		if (ret != OK) {
			goto out;
		}
	} while (name_start != NULL);

	dto_modify_end_by_path(dto, "/");
out:
	free(target);
	return ret;
}
