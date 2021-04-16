// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>

#include <rm-rpc.h>

#include <guest_interface.h>
#include <resource-manager.h>
#include <utils/vector.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_mgnt.h>

#include "libfdt_env.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <dtb_parser.h>

#include "vm_config_parser.h"

#define LABEL_ID "qcom,label"

//#define DEFAULT_INTERRUPT_CELLS (2)
#define DEFAULT_MSG_QUEUE_DEPTH (8U)
#define DEFAULT_MSG_QUEUE_SIZE	RM_RPC_MESSAGE_SIZE

static void *
alloc_parser_data(void);

static void
free_parser_data(void *data);

static listener_return_t
parse_vm_config(void *data, void *fdt, int node_ofs, ctx_t *ctx);

static listener_return_t
parse_memory(void *data, void *fdt, int node_ofs, ctx_t *ctx);

static listener_return_t
parse_interrupts(void *data, void *fdt, int node_ofs, ctx_t *ctx);

static listener_return_t
parse_rm_rpc(void *data, void *fdt, int node_ofs, ctx_t *ctx);

static error_t
parse_general_vdevice_props(general_data_t *cfg, void *fdt, int node_ofs,
			    ctx_t *ctx);
static void
destroy_general_vdevice_props(general_data_t *cfg);

static listener_return_t
parse_doorbell_source(void *data, void *fdt, int node_ofs, ctx_t *ctx);

static listener_return_t
parse_doorbell(void *data, void *fdt, int node_ofs, ctx_t *ctx);

static listener_return_t
parse_message_queue(void *data, void *fdt, int node_ofs, ctx_t *ctx);

static listener_return_t
parse_message_queue_pair(void *data, void *fdt, int node_ofs, ctx_t *ctx);

static listener_return_t
parse_shm_doorbell(void *data, void *fdt, int node_ofs, ctx_t *ctx);

static listener_return_t
parse_vcpus(void *data, void *fdt, int node_ofs, ctx_t *ctx);

static bool
read_interrupts_config(void *fdt, int node_ofs, interrupt_data_t *irqs,
		       count_t count);

typedef struct {
	uint16_t size;
	uint16_t depth;
} msg_queue_param_t;
static msg_queue_param_t
get_msg_queue_param(void *fdt, int node_ofs);

static error_t
parse_iomem_ranges(vm_config_parser_data_t *vd, void *fdt, int node_ofs,
		   ctx_t *ctx);

static error_t
parse_irq_ranges(vm_config_parser_data_t *vd, void *fdt, int node_ofs);

static error_t
parse_segments(vm_config_parser_data_t *vd, void *fdt, int node_ofs);

static dtb_listener_t vm_config_listener[] = {
	{
		.type	       = BY_PATH,
		.expected_path = "^/qcom,vm-config$",
		.action	       = parse_vm_config,
	},
	{
		.type	       = BY_PATH,
		.expected_path = "^/qcom,vm-config/memory$",
		.action	       = parse_memory,
	},
	{
		.type	       = BY_PATH,
		.expected_path = "^/qcom,vm-config/interrupts$",
		.action	       = parse_interrupts,
	},
	{
		.type	       = BY_PATH,
		.expected_path = "^/qcom,vm-config/vcpus$",
		.action	       = parse_vcpus,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "rm-rpc",
		.action		  = parse_rm_rpc,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "shm-doorbell",
		.action		  = parse_shm_doorbell,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "shm",
		.action		  = parse_shm_doorbell,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "doorbell-source",
		.action		  = parse_doorbell_source,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "doorbell",
		.action		  = parse_doorbell,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "message-queue",
		.action		  = parse_message_queue,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "message-queue-pair",
		.action		  = parse_message_queue_pair,
	},

};

static dtb_parser_ops_t vm_config_parser_ops = {
	.alloc = alloc_parser_data,
	.free  = free_parser_data,

	.listeners = vm_config_listener,
	.listener_cnt =
		sizeof(vm_config_listener) / sizeof(vm_config_listener[0]),
};

listener_return_t
parse_vm_config(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	int lenp = 0;

	// get vm type
	const char *vm_type =
		(const char *)fdt_getprop(fdt, node_ofs, "vm-type", &lenp);
	if (vm_type != NULL) {
		// should be OK to use strcmp instead of strncmp
		// also default is aarch64, refactor it when have more types
		if (strcmp(vm_type, "aarch64-guest") == 0) {
			vd->vm_type = VM_CONFIG_VM_TYPE_AARCH64_GUEST;
		}
	}

	const char *boot_config =
		(const char *)fdt_getprop(fdt, node_ofs, "boot-config", &lenp);
	if (boot_config != NULL) {
		if (strcmp(boot_config, "fdt,unified") == 0) {
			vd->boot_config = VM_CONFIG_BOOT_CONFIG_FDT_UNIFIED;
		}
	}

	const char *os_type =
		(const char *)fdt_getprop(fdt, node_ofs, "os-type", &lenp);
	if (os_type != NULL) {
		if (strcmp(os_type, "linux") == 0) {
			vd->os_type = VM_CONFIG_OS_TYPE_LINUX;
		}
	}

	const char *kernel_entry_segment = (const char *)fdt_getprop(
		fdt, node_ofs, "kernel-entry-segment", &lenp);
	if (kernel_entry_segment != NULL) {
		vd->kernel_entry_segment = strdup(kernel_entry_segment);
		if (vd->kernel_entry_segment == NULL) {
			ret = RET_ERROR;
			goto out;
		}
	}

	const fdt32_t *kernel_entry_offset = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "kernel_entry_offset", &lenp);
	if (kernel_entry_offset != NULL) {
		vd->kernel_entry_offset =
			fdt_read_num(kernel_entry_offset, ctx->addr_cells);
	}

	// get vendor name
	const char *vendor_name =
		(const char *)fdt_getprop(fdt, node_ofs, "vendor", &lenp);
	if (vendor_name != NULL) {
		vd->vendor_name = strdup(vendor_name);
		if (vd->vendor_name == NULL) {
			ret = RET_ERROR;
			free(vd->kernel_entry_segment);
			goto out;
		}
	}

	const char *image_name =
		(const char *)fdt_getprop(fdt, node_ofs, "image-name", &lenp);
	if (image_name != NULL) {
		vd->image_name = strdup(image_name);
		if (vd->image_name == NULL) {
			ret = RET_ERROR;
			free(vd->vendor_name);
			free(vd->kernel_entry_segment);
			goto out;
		}
	}

	const fdt64_t *swid =
		(const fdt64_t *)fdt_getprop(fdt, node_ofs, "qcom,swid", &lenp);
	if (swid != NULL) {
		vd->swid = fdt64_to_cpu(*swid);
	}

	// parse io memory range
	error_t iomem_ranges_ret = parse_iomem_ranges(vd, fdt, node_ofs, ctx);
	if (iomem_ranges_ret != OK) {
		ret = RET_ERROR;
		free(vd->image_name);
		free(vd->vendor_name);
		free(vd->kernel_entry_segment);
		goto out;
	}

	error_t irq_ranges_ret = parse_irq_ranges(vd, fdt, node_ofs);
	if (irq_ranges_ret != OK) {
		ret = RET_ERROR;
		free(vd->image_name);
		free(vd->vendor_name);
		free(vd->kernel_entry_segment);
		goto out;
	}

	error_t segments_ret = parse_segments(vd, fdt, node_ofs);
	if (segments_ret != OK) {
		ret = RET_ERROR;
		free(vd->image_name);
		free(vd->vendor_name);
		free(vd->kernel_entry_segment);
		goto out;
	}

out:
	return ret;
}

error_t
parse_iomem_ranges(vm_config_parser_data_t *vd, void *fdt, int node_ofs,
		   ctx_t *ctx)
{
	error_t ret = OK;

	int lenp = 0;

	const fdt32_t *iomems = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "iomemory-ranges", &lenp);
	if (iomems == NULL) {
		goto out;
	}

	size_t total_size = (size_t)lenp / sizeof(iomems[0]);

	index_t i = 0;
	while (i < total_size) {
		iomem_range_data_t r;

		r.phys_base = fdt_read_num(&iomems[i], ctx->addr_cells);
		i += ctx->addr_cells;

		r.ipa_base = fdt_read_num(&iomems[i], ctx->addr_cells);
		i += ctx->addr_cells;

		r.size = fdt_read_num(&iomems[i], ctx->addr_cells);
		i += ctx->size_cells;

		uint16_t access_code = (uint16_t)fdt_read_num(&iomems[i], 1);
		if (access_code >= IOMEM_RANGE_ACCESS_MAX) {
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}
		i++;

		r.access = (enum iomem_range_access)access_code;

		ret = vector_push_back(vd->iomem_ranges, r);
		if (ret != OK) {
			goto out;
		}
	}
out:
	return ret;
}

listener_return_t
parse_memory(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	const fdt32_t *base_ipa = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "base-address", &lenp);
	if (base_ipa != NULL) {
		vd->mem_base_ipa = fdt_read_num(base_ipa, ctx->addr_cells);
	}

	const fdt32_t *size_min =
		(const fdt32_t *)fdt_getprop(fdt, node_ofs, "size-min", &lenp);
	if (size_min != NULL) {
		vd->mem_size_min = fdt_read_num(size_min, ctx->addr_cells);
	}

	return ret;
}

listener_return_t
parse_interrupts(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	const fdt32_t *config =
		(const fdt32_t *)fdt_getprop(fdt, node_ofs, "config", &lenp);
	assert(config != NULL);

	uint32_t phandle  = fdt32_to_cpu(*config);
	int	 vgic_ofs = fdt_node_offset_by_phandle(fdt, phandle);

	// check vgic compatible
	const char *compatible =
		(const char *)fdt_getprop(fdt, node_ofs, "compatible", &lenp);
	if ((compatible == NULL) || (strcmp(compatible, "arm,gic-v3") != 0)) {
		ret = RET_ERROR;
		goto err_compatible;
	}

	const struct fdt_property *p =
		fdt_get_property(fdt, node_ofs, "interrupt-controller", &lenp);
	if (p == NULL) {
		ret = RET_ERROR;
		goto err_interrupt_controller;
	}

	ctx_t vgic_ctx;
	dtb_parser_update_ctx(fdt, vgic_ofs, ctx, &vgic_ctx);

	const fdt32_t *reg_data =
		(const fdt32_t *)fdt_getprop(fdt, node_ofs, "reg", &lenp);
	if (reg_data != NULL) {
		index_t i = 0;
		while (i < (size_t)lenp / sizeof(reg_data[0])) {
			// no pa provided in reg field
			// pa = 0UL;

			// FIXME: keep ipa if needed
			vd->vgic_base_ipa =
				fdt_read_num(&reg_data[i], vgic_ctx.addr_cells);
			i += vgic_ctx.addr_cells;

			// FIXME: keep size if needed
			vd->vgic_ipa_size =
				fdt_read_num(&reg_data[i], vgic_ctx.size_cells);
			i += vgic_ctx.size_cells;
		}
	}

err_interrupt_controller:
err_compatible:
	return ret;
}

listener_return_t
parse_rm_rpc(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	rm_rpc_data_t cfg;

	memset(&cfg, 0, sizeof(cfg));

	const struct fdt_property *is_console_ptr =
		fdt_get_property(fdt, node_ofs, "console-dev", &lenp);
	if (is_console_ptr != NULL) {
		cfg.is_console_dev = true;
	} else {
		cfg.is_console_dev = false;
	}

	// handle irq
	cfg.defined_irq =
		read_interrupts_config(fdt, node_ofs, cfg.irqs,
				       sizeof(cfg.irqs) / sizeof(cfg.irqs[0]));

	error_t general_parse_ret =
		parse_general_vdevice_props(&cfg.general, fdt, node_ofs, ctx);
	if (general_parse_ret != OK) {
		ret = RET_ERROR;
		goto out;
	}

	// add two more additional push_compatibles
	index_t i = cfg.general.push_compatible_num;
	if (i + 2 > VDEVICE_MAX_PUSH_COMPATIBLES) {
		ret = RET_ERROR;
		goto out;
	}

	char *extra_compatible = strdup("qcom,resource-manager");
	if (extra_compatible == NULL) {
		ret = RET_ERROR;
		goto out;
	}

	char *extra_compatible_with_version =
		calloc(VDEVICE_MAX_COMPATIBLE_LEN, sizeof(char));
	if (extra_compatible_with_version == NULL) {
		free(extra_compatible);
		ret = RET_ERROR;
		goto out;
	}

	int snprintf_ret = snprintf(extra_compatible_with_version,
				    VDEVICE_MAX_COMPATIBLE_LEN,
				    "qcom,resource-manager-%s",
				    gunyah_api_version);
	if (snprintf_ret < 0) {
		free(extra_compatible);
		free(extra_compatible_with_version);
		ret = RET_ERROR;
		goto out;
	}

	cfg.general.push_compatible[i]	    = extra_compatible;
	cfg.general.push_compatible[i + 1U] = extra_compatible_with_version;

	cfg.general.push_compatible_num += 2U;

	msg_queue_param_t p = get_msg_queue_param(fdt, node_ofs);

	// FIXME: find correct way to get IRQ allocated if needed

	cfg.msg_size	= p.size;
	cfg.queue_depth = p.depth;

	error_t push_err;
	vector_push_back_imm(rm_rpc_data_t, vd->rm_rpcs, cfg, push_err);

	if (push_err != OK) {
		destroy_general_vdevice_props(&cfg.general);
		ret = RET_ERROR;
	}

out:
	return ret;
}

void
destroy_general_vdevice_props(general_data_t *cfg)
{
	for (index_t i = 0; i < VDEVICE_MAX_PUSH_COMPATIBLES; i++) {
		free(cfg->push_compatible[i]);
		cfg->push_compatible[i] = NULL;
	}

	cfg->push_compatible_num = 0UL;

	free(cfg->generate);
	cfg->generate = NULL;
}

error_t
parse_general_vdevice_props(general_data_t *cfg, void *fdt, int node_ofs,
			    ctx_t *ctx)
{
	(void)ctx;

	error_t ret = OK;

	int lenp = 0;

	const fdt32_t *label_ptr =
		(const fdt32_t *)fdt_getprop(fdt, node_ofs, LABEL_ID, &lenp);

	if (label_ptr != NULL) {
		// only set if there's a label, or else untouch it since it will
		// be updated by others (like shm doorbell)
		cfg->label = fdt32_to_cpu(*label_ptr);
	}

	const char *generate =
		(const char *)fdt_getprop(fdt, node_ofs, "generate", &lenp);
	if (generate != NULL) {
		cfg->generate = strdup(generate);
		if (cfg->generate == NULL) {
			ret = ERROR_NOMEM;
			destroy_general_vdevice_props(cfg);
			goto out;
		}
	}

	const char *push_compatibles_string = (const char *)fdt_getprop(
		fdt, node_ofs, "push-compatible", &lenp);

	int	cur_len = 0;
	index_t i	= 0;

	const char *next = push_compatibles_string;
	while (cur_len < lenp) {
		if (i >= VDEVICE_MAX_PUSH_COMPATIBLES) {
			ret = ERROR_DENIED;
			destroy_general_vdevice_props(cfg);
			goto out;
		}

		cfg->push_compatible[i] = strdup(next);
		if (cfg->push_compatible[i] == NULL) {
			ret = ERROR_NOMEM;
			destroy_general_vdevice_props(cfg);
			goto out;
		}

		cur_len += strlen(next) + 1;
		next = push_compatibles_string + cur_len;
		i++;
	}

	cfg->push_compatible_num = i;

out:
	return ret;
}

listener_return_t
parse_doorbell_source(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	doorbell_data_t cfg;
	memset(&cfg, 0, sizeof(cfg));

	cfg.is_source = true;

	// should not define irq for source doorbell
	cfg.defined_irq = false;

	const struct fdt_property *p =
		fdt_get_property(fdt, node_ofs, "peer-default", &lenp);
	if (p == NULL) {
		ret = RET_ERROR;
		goto err_not_peer_default;
	}

	cfg.peer = VMID_HLOS;

	error_t parse_general_ret =
		parse_general_vdevice_props(&cfg.general, fdt, node_ofs, ctx);
	if (parse_general_ret != OK) {
		ret = RET_ERROR;
		goto err_parse_general;
	}

	error_t push_err;
	vector_push_back_imm(doorbell_data_t, vd->doorbells, cfg, push_err);

	if (push_err != OK) {
		destroy_general_vdevice_props(&cfg.general);
		ret = RET_ERROR;
	}

err_parse_general:
err_not_peer_default:
	return ret;
}

listener_return_t
parse_doorbell(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	doorbell_data_t cfg;
	memset(&cfg, 0, sizeof(cfg));

	cfg.is_source = false;

	cfg.defined_irq = read_interrupts_config(fdt, node_ofs, &cfg.irq, 1);

	const struct fdt_property *p =
		fdt_get_property(fdt, node_ofs, "peer-default", &lenp);
	if (p == NULL) {
		ret = RET_ERROR;
		goto err_not_peer_default;
	}

	cfg.peer = VMID_HLOS;

	error_t parse_general_ret =
		parse_general_vdevice_props(&cfg.general, fdt, node_ofs, ctx);
	if (parse_general_ret != OK) {
		ret = RET_ERROR;
		goto err_parse_general;
	}

	error_t push_err;
	vector_push_back_imm(doorbell_data_t, vd->doorbells, cfg, push_err);

	if (push_err != OK) {
		destroy_general_vdevice_props(&cfg.general);
		ret = RET_ERROR;
	}

err_parse_general:
err_not_peer_default:
	return ret;
}

listener_return_t
parse_message_queue(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	msg_queue_data_t cfg;
	memset(&cfg, 0, sizeof(cfg));

	cfg.is_pair = false;

	// only need 1 irq
	cfg.defined_irq = read_interrupts_config(fdt, node_ofs, cfg.irqs, 1);

	bool is_sender;

	const struct fdt_property *sender_flag =
		fdt_get_property(fdt, node_ofs, "is-sender", &lenp);
	if (sender_flag != NULL) {
		is_sender = true;
	} else {
		is_sender = false;
	}

	bool is_receiver;

	const struct fdt_property *receiver_flag =
		fdt_get_property(fdt, node_ofs, "is-receiver", &lenp);
	if (receiver_flag != NULL) {
		is_receiver = true;
	} else {
		is_receiver = false;
	}

	assert(is_sender ^ is_receiver);

	cfg.is_sender = is_sender;

	const struct fdt_property *peer_default =
		fdt_get_property(fdt, node_ofs, "peer-default", &lenp);
	if (peer_default == NULL) {
		ret = RET_ERROR;
		goto err_not_peer_default;
	}

	cfg.peer = VMID_HLOS;

	error_t parse_general_ret =
		parse_general_vdevice_props(&cfg.general, fdt, node_ofs, ctx);
	if (parse_general_ret != OK) {
		ret = RET_ERROR;
		goto err_parse_general;
	}

	msg_queue_param_t p = get_msg_queue_param(fdt, node_ofs);

	cfg.msg_size	= p.size;
	cfg.queue_depth = p.depth;

	error_t push_err;
	vector_push_back_imm(msg_queue_data_t, vd->msg_queues, cfg, push_err);

	if (push_err != OK) {
		destroy_general_vdevice_props(&cfg.general);
		ret = RET_ERROR;
	}

err_parse_general:
err_not_peer_default:
	return ret;
}

listener_return_t
parse_message_queue_pair(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	msg_queue_data_t cfg;
	memset(&cfg, 0, sizeof(cfg));

	cfg.is_pair = true;

	const struct fdt_property *peer_default =
		fdt_get_property(fdt, node_ofs, "peer-default", &lenp);
	if (peer_default == NULL) {
		ret = RET_ERROR;
		goto err_not_peer_default;
	}

	cfg.peer = VMID_HLOS;

	cfg.defined_irq =
		read_interrupts_config(fdt, node_ofs, cfg.irqs,
				       sizeof(cfg.irqs) / sizeof(cfg.irqs[0]));

	error_t parse_general_ret =
		parse_general_vdevice_props(&cfg.general, fdt, node_ofs, ctx);
	if (parse_general_ret != OK) {
		ret = RET_ERROR;
		goto err_parse_general;
	}

	msg_queue_param_t p = get_msg_queue_param(fdt, node_ofs);

	cfg.msg_size	= p.size;
	cfg.queue_depth = p.depth;

	error_t push_err;
	vector_push_back_imm(msg_queue_data_t, vd->msg_queues, cfg, push_err);

	if (push_err != OK) {
		destroy_general_vdevice_props(&cfg.general);
		ret = RET_ERROR;
	}

err_parse_general:
err_not_peer_default:
	return ret;
}

static listener_return_t
parse_shm_doorbell(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	shm_data_t cfg;
	memset(&cfg, 0, sizeof(cfg));

	const char *vdevice_type =
		(const char *)fdt_getprop(fdt, node_ofs, "vdevice-type", &lenp);

	assert(vdevice_type != NULL);
	if (strcmp(vdevice_type, "shm") == 0) {
		cfg.is_plain_shm = true;
	} else {
		cfg.is_plain_shm = false;
	}

	// handle sub memory node
	bool found_mem	  = false;
	int  sub_node_ofs = 0;

	// parse memory node
	fdt_for_each_subnode (sub_node_ofs, fdt, node_ofs) {
		const char *node_name = fdt_get_name(fdt, sub_node_ofs, &lenp);
		(void)node_name;
		// the node must be memory
		assert(strcmp(node_name, "memory") == 0);

		ctx_t mem_ctx;
		dtb_parser_update_ctx(fdt, sub_node_ofs, ctx, &mem_ctx);

		// Only allows one shm memory right now
		assert(!found_mem);
		found_mem = true;

		// mem_label
		const fdt32_t *label_ptr = (const fdt32_t *)fdt_getprop(
			fdt, sub_node_ofs, LABEL_ID, &lenp);
		if (label_ptr != NULL) {
			cfg.general.label = fdt32_to_cpu(*label_ptr);
		} else {
			ret = RET_ERROR;
			goto err_no_label;
		}

		const fdt64_t *base = (const fdt64_t *)fdt_getprop(
			fdt, sub_node_ofs, "base", &lenp);
		if (base != NULL) {
			cfg.mem_base_ipa = fdt_read_num((const fdt32_t *)base,
							mem_ctx.addr_cells);
		} else {
			cfg.mem_base_ipa = 0UL;
		}

		// check if need allocate
		cfg.need_allocate = false;

		const struct fdt_property *p = fdt_get_property(
			fdt, sub_node_ofs, "allocate_base", &lenp);
		if (p != NULL) {
			cfg.need_allocate = true;
			cfg.mem_base_ipa  = 0UL;
		}
	}

	const struct fdt_property *peer_default =
		fdt_get_property(fdt, node_ofs, "peer-default", &lenp);
	if (peer_default == NULL) {
		ret = RET_ERROR;
		goto err_not_peer_default;
	}

	cfg.peer = VMID_HLOS;

	// create shm vdevice (to gather all these information)
	error_t parse_general_ret =
		parse_general_vdevice_props(&cfg.general, fdt, node_ofs, ctx);
	if (parse_general_ret != OK) {
		ret = RET_ERROR;
		goto err_parse_general;
	}

	error_t push_err;
	vector_push_back_imm(shm_data_t, vd->shms, cfg, push_err);

	if (push_err != OK) {
		destroy_general_vdevice_props(&cfg.general);
		ret = RET_ERROR;
	}

err_no_label:
err_parse_general:
err_not_peer_default:
	return ret;
}

listener_return_t
parse_vcpus(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	(void)ctx;

	listener_return_t ret = RET_CONTINUE;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	// read sched time slice
	const fdt32_t *sched_time_slice_ptr = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "sched-timeslice", &lenp);
	vd->sched_time_slice = sched_time_slice_ptr == NULL
				       ? 0UL
				       : fdt32_to_cpu(*sched_time_slice_ptr);

	// read sched priority
	const fdt32_t *sched_priority_ptr = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "sched-priority", &lenp);
	vd->sched_priority = sched_priority_ptr == NULL
				     ? 0UL
				     : fdt32_to_cpu(*sched_priority_ptr);

	// read affinity type
	const char *affinity =
		(const char *)fdt_getprop(fdt, node_ofs, "affinity", &lenp);
	if (affinity != NULL) {
		if (strcmp(affinity, "sticky") == 0) {
			vd->affinity = VM_CONFIG_AFFINITY_STICKY;
		} else {
			// default is static
			vd->affinity = VM_CONFIG_AFFINITY_STATIC;
		}
	}

	// read affinity map
	const fdt32_t *affinity_map = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "affinity-map", &lenp);
	if (affinity_map != NULL) {
		size_t sz = (size_t)lenp / sizeof(affinity_map[0]);

		vd->affinity_map_cnt = sz;

		vd->affinity_map =
			(cpu_index_t *)calloc(sizeof(affinity_map[0]), sz);

		if (vd->affinity_map == NULL) {
			goto out;
		}

		index_t i = 0;
		while (i < sz) {
			vd->affinity_map[i] =
				(cpu_index_t)fdt32_to_cpu(affinity_map[i]);
			i++;
		}
	}

	// read cpus number in device tree
	const char *config =
		(const char *)fdt_getprop(fdt, node_ofs, "config", &lenp);
	if (config == NULL) {
		goto out;
	}

	int config_ofs = fdt_path_offset(fdt, config);
	if (config_ofs < 0) {
		ret = RET_ERROR;
		goto out;
	}

	// create secondary vcpus only
	int sub_node_ofs = 0;

	size_t cpu_count = 0;
	fdt_for_each_subnode (sub_node_ofs, fdt, config_ofs) {
		const char *device_type = (const char *)fdt_getprop(
			fdt, sub_node_ofs, "device_type", &lenp);

		if ((device_type != NULL) &&
		    (strcmp(device_type, "cpu") == 0)) {
			cpu_count++;
		}
	}

	vd->vcpu_cnt = cpu_count;

	// FIXME: should check vcpu count and affinity count?

out:
	return ret;
}

msg_queue_param_t
get_msg_queue_param(void *fdt, int node_ofs)
{
	msg_queue_param_t ret = { 0 };

	int lenp = 0;

	const fdt32_t *msg_size_ptr = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "message-size", &lenp);
	const fdt32_t *queue_depth_ptr = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "queue-depth", &lenp);

	ret.size = msg_size_ptr == NULL ? DEFAULT_MSG_QUEUE_SIZE
					: (uint16_t)fdt32_to_cpu(*msg_size_ptr);

	ret.depth = queue_depth_ptr == NULL
			    ? DEFAULT_MSG_QUEUE_DEPTH
			    : (uint16_t)fdt32_to_cpu(*queue_depth_ptr);

	return ret;
}

dtb_parser_ops_t *
vm_config_parser_get_ops()
{
	return &vm_config_parser_ops;
}

void *
alloc_parser_data(void)
{
	vm_config_parser_data_t *ret =
		calloc(1, sizeof(vm_config_parser_data_t));
	if (ret == NULL) {
		goto err_out;
	}

	ret->rm_rpcs = vector_init(rm_rpc_data_t, 1U, 1U);
	if (ret->rm_rpcs == NULL) {
		goto err_out;
	}

	ret->doorbells = vector_init(doorbell_data_t, 2U, 2U);
	if (ret->doorbells == NULL) {
		goto err_out;
	}

	ret->msg_queues = vector_init(msg_queue_data_t, 2U, 2U);
	if (ret->msg_queues == NULL) {
		goto err_out;
	}

	ret->shms = vector_init(shm_data_t, 1U, 1U);
	if (ret->shms == NULL) {
		goto err_out;
	}

	ret->iomem_ranges = vector_init(iomem_range_data_t, 1U, 1U);
	if (ret->iomem_ranges == NULL) {
		goto err_out;
	}

	ret->irq_ranges = vector_init(irq_range_data_t, 1U, 1U);
	if (ret->irq_ranges == NULL) {
		goto err_out;
	}

	goto out;

err_out:
	if (ret) {
		if (ret->iomem_ranges != NULL) {
			vector_deinit(ret->iomem_ranges);
		}
		if (ret->shms != NULL) {
			vector_deinit(ret->shms);
		}
		if (ret->msg_queues != NULL) {
			vector_deinit(ret->msg_queues);
		}
		if (ret->doorbells != NULL) {
			vector_deinit(ret->doorbells);
		}
		if (ret->rm_rpcs != NULL) {
			vector_deinit(ret->rm_rpcs);
		}
		free(ret);
		ret = NULL;
	}
out:
	return ret;
}

void
free_parser_data(void *data)
{
	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	if (vd == NULL) {
		goto out;
	}

#define FREE_GENERAL(element_type, vector)                                     \
	do {                                                                   \
		size_t cnt = vector_size(vector);                              \
		for (index_t i = 0; i < cnt; ++i) {                            \
			element_type *d =                                      \
				vector_at_ptr(element_type, vector, i);        \
			destroy_general_vdevice_props(&d->general);            \
		}                                                              \
	} while (0)

	if (vd->rm_rpcs != NULL) {
		FREE_GENERAL(rm_rpc_data_t, vd->rm_rpcs);
		vector_deinit(vd->rm_rpcs);
	}

	if (vd->doorbells != NULL) {
		FREE_GENERAL(doorbell_data_t, vd->doorbells);
		vector_deinit(vd->doorbells);
	}

	if (vd->msg_queues != NULL) {
		FREE_GENERAL(msg_queue_data_t, vd->msg_queues);
		vector_deinit(vd->msg_queues);
	}

	if (vd->shms != NULL) {
		FREE_GENERAL(shm_data_t, vd->shms);
		vector_deinit(vd->shms);
	}

#undef FREE_GENERAL

	if (vd->iomem_ranges) {
		vector_deinit(vd->iomem_ranges);
	}

	if (vd->irq_ranges) {
		vector_deinit(vd->irq_ranges);
	}

	free(vd->kernel_entry_segment);
	free(vd->vendor_name);
	free(vd->image_name);
	free(vd->affinity_map);

	free(vd);

out:
	return;
}

bool
read_interrupts_config(void *fdt, int node_ofs, interrupt_data_t *irqs,
		       count_t count)
{
	bool	       ret	= false;
	int	       lenp	= 0;
	const fdt32_t *irq_data = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "interrupts", &lenp);
	if (irq_data == NULL) {
		ret = false;
		goto out;
	}

	if ((uint32_t)lenp != 3 * sizeof(irq_data[0]) * count) {
		ret = false;
		goto out;
	}

	index_t i   = 0;
	count_t cnt = count;

	interrupt_data_t *cur_irq = irqs;
	while (cnt > 0) {
		ret = true;

		if (fdt32_to_cpu(irq_data[i]) == 0) {
			cur_irq->is_cpu_local = false;
		} else {
			cur_irq->is_cpu_local = true;
		}
		++i;

		cur_irq->virq = (virq_t)fdt32_to_cpu(irq_data[i]);
		++i;

		if (fdt32_to_cpu(irq_data[i]) == 0x1) {
			cur_irq->is_edge_triggerring = true;
		} else {
			cur_irq->is_edge_triggerring = false;
		}
		++i;

		++cur_irq;
		--cnt;
	}
out:
	return ret;
}

error_t
parse_irq_ranges(vm_config_parser_data_t *vd, void *fdt, int node_ofs)
{
	error_t ret = OK;

	int lenp = 0;

	const fdt32_t *irqs = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "gic-irq-ranges", &lenp);
	if (irqs == NULL) {
		ret = ERROR_FAILURE;
		goto out;
	}

	size_t total_size = (size_t)lenp / sizeof(irqs[0]);

	index_t i = 0;
	while (i < total_size) {
		irq_range_data_t r;

		r.hw_irq = (virq_t)fdt_read_num(&irqs[i], 1);
		i++;

		r.virq = (virq_t)fdt_read_num(&irqs[i], 1);
		i++;

		ret = vector_push_back(vd->irq_ranges, r);
		if (ret != OK) {
			goto err_push;
		}
	}
err_push:
out:
	return ret;
}

error_t
parse_segments(vm_config_parser_data_t *vd, void *fdt, int node_ofs)
{
	error_t ret = OK;

	int lenp = 0;

	int segments_ofs = fdt_subnode_offset(fdt, node_ofs, "segments");
	if (segments_ofs < 0) {
		ret = ERROR_FAILURE;
		goto out;
	}

	const fdt32_t *ramfs_idx_ptr = (const fdt32_t *)fdt_getprop(
		fdt, segments_ofs, "ramdisk", &lenp);
	if (ramfs_idx_ptr == NULL) {
		printf("Warning: failed to find segment ramdisk segment index\n");

		vd->ramfs_idx = -1;
		goto out;
	}

	vd->ramfs_idx = (int)(int32_t)fdt32_to_cpu(*ramfs_idx_ptr);
out:
	return ret;
}
