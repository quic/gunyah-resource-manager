// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>

#include <rm-rpc.h>

#include <memparcel.h>
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
#include <libfdt.h>
#pragma clang diagnostic pop

#include <dt_linux.h>
#include <dt_overlay.h>

#include "dto_construct.h"

static char *
get_name_from_generate(const char *generate);

static error_t
add_compatibles(struct vdevice_node *node, char *compatibles[],
		count_t compatible_cnt, dto_t *dto);

error_t
dto_create_doorbell(struct vdevice_node *node, dto_t *dto, uint32_t *phandle)
{
	error_t e = OK;

	struct vdevice_doorbell *cfg = (struct vdevice_doorbell *)node->config;

	char *base_name = get_name_from_generate(node->generate);
	if (base_name == NULL) {
		e = ERROR_ARGUMENT_INVALID;
		goto err_base_name;
	}

	char name[DTB_NODE_NAME_MAX];
	int  snp_name_ret = snprintf(name, DTB_NODE_NAME_MAX, "%s@%lx",
				     base_name, cfg->vm_cap);
	(void)snp_name_ret;
	assert(snp_name_ret <= DTB_NODE_NAME_MAX);

	e = dto_node_begin(dto, name);
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

err:
	(void)0;

	error_t ret;
	ret = dto_node_end(dto, name);
	if (e == OK) {
		e = ret;
	}
err_begin:
err_base_name:
	return e;
}

error_t
dto_create_msg_queue(struct vdevice_node *node, dto_t *dto)
{
	error_t e = OK;

	struct vdevice_msg_queue *cfg =
		(struct vdevice_msg_queue *)node->config;

	char *base_name = get_name_from_generate(node->generate);
	if (base_name == NULL) {
		e = ERROR_ARGUMENT_INVALID;
		goto err_base_name;
	}

	char name[DTB_NODE_NAME_MAX];
	int  snp_name_ret = snprintf(name, DTB_NODE_NAME_MAX, "%s@%lx",
				     base_name, cfg->vm_cap);
	(void)snp_name_ret;
	assert(snp_name_ret <= DTB_NODE_NAME_MAX);

	e = dto_node_begin(dto, name);
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

err:
	(void)0;

	error_t ret;

	ret = dto_node_end(dto, name);
	if (e == OK) {
		e = ret;
	}
err_begin:
err_base_name:
	return e;
}

error_t
dto_create_msg_queue_pair(struct vdevice_node *node, dto_t *dto)
{
	error_t e = OK;

	struct vdevice_msg_queue_pair *cfg =
		(struct vdevice_msg_queue_pair *)node->config;

	char *base_name = get_name_from_generate(node->generate);
	if (base_name == NULL) {
		e = ERROR_ARGUMENT_INVALID;
		goto err_base_name;
	}

	char name[DTB_NODE_NAME_MAX];
	int  snp_name_ret = snprintf(name, DTB_NODE_NAME_MAX, "%s@%lx",
				     base_name, cfg->rx_vm_cap);
	(void)snp_name_ret;
	assert(snp_name_ret <= DTB_NODE_NAME_MAX);

	e = dto_node_begin(dto, name);
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

	// FIXME: double check rm-rpc doesn't have label

err:
	(void)0;

	error_t ret;
	ret = dto_node_end(dto, name);
	if (e == OK) {
		e = ret;
	}
err_begin:
err_base_name:
	return e;
}

error_t
dto_create_shm(struct vdevice_node *node, dto_t *dto, vmid_t self)
{
	error_t e = OK;

	struct vdevice_shm *cfg = (struct vdevice_shm *)node->config;

	// FIXME: only support memparcel way
	assert(!cfg->need_allocate);

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

	char *base_name = get_name_from_generate(node->generate);
	if (base_name == NULL) {
		e = ERROR_ARGUMENT_INVALID;
		goto err_base_name;
	}

	// create shm
	e = dto_node_begin(dto, base_name);
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

	bool is_external = false;

	memparcel_t *mp;
	foreach_memparcel_by_target_vmid (mp, self) {
		if (memparcel_get_label(mp) == cfg->label) {
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

out:
	(void)0;

	error_t ret;
	ret = dto_node_end(dto, base_name);
	if (e == OK) {
		e = ret;
	}

err_node_begin:
err_base_name:
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
get_name_from_generate(const char *generate)
{
	size_t sz  = strlen(generate);
	char * ret = NULL;

	// not allowed generate tailing with '/'
	if (generate[sz - 1] == '/') {
		goto out;
	}

	// find the last '/'
	ret = strrchr(generate, '/');
	if (ret == NULL) {
		goto out;
	}
	ret++;

out:
	return ret;
}
