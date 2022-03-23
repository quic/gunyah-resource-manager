// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <endian.h>
#include <stdio.h>

#include <rm-rpc.h>

#include <resource-manager.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <dtb_parser.h>
#include <guest_interface.h>
#include <memparcel_msg.h>
#include <platform_dt_parser.h>
#include <platform_vm_config.h>
#include <util.h>
#include <utils/vector.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_mgnt.h>

#include "libfdt_env.h"

// Must be last
#include <platform_vm_config_parser.h>
#include <vm_config_parser.h>

#define LABEL_ID "qcom,label"

// FIXME: double check it
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
parse_iomem(void *data, void *fdt, int node_ofs, ctx_t *ctx);

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

listener_return_t
platform_parse_vm_config(void *data, void *fdt, int node_ofs, ctx_t *ctx);

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
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "iomem",
		.action		  = parse_iomem,
	},
	PLATFORM_LISTENERS
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
	listener_return_t ret = RET_CLAIMED;

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

	const char *vm_attrs =
		(const char *)fdt_getprop(fdt, node_ofs, "vm-attrs", &lenp);
	if (vm_attrs != NULL) {
		if (fdt_stringlist_contains(vm_attrs, lenp,
					    "ras-error-handler") != 0) {
			// FIXME restrict to QTI signed images
			vd->ras_error_handler = true;
		}
		if (fdt_stringlist_contains(vm_attrs, lenp,
					    "amu-counting-disabled") != 0) {
			vd->amu_counting_disabled = true;
		}
		if (fdt_stringlist_contains(vm_attrs, lenp, "crash-fatal") !=
		    0) {
			vd->crash_fatal = true;
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
			goto out;
		}
	}

	// Get VM/image name
	const char *image_name =
		(const char *)fdt_getprop(fdt, node_ofs, "image-name", &lenp);
	if (image_name != NULL) {
		strlcpy(vd->vm_name, image_name, VM_MAX_NAME_LEN);
	} else {
		printf("Error: missing image name\n");
		ret = RET_ERROR;
		goto out;
	}

	// Get VM URI
	const char *vm_uri =
		(const char *)fdt_getprop(fdt, node_ofs, "vm-uri", &lenp);
	if (vm_uri != NULL) {
		strlcpy(vd->vm_uri, vm_uri, VM_MAX_URI_LEN);
	}

	// Get VM-GUID and convert from string to byte array
	const char *vm_guid =
		(const char *)fdt_getprop(fdt, node_ofs, "vm-guid", &lenp);
	if (vm_guid != NULL) {
		unsigned int tmp[8];

		int num_in = sscanf(vm_guid,
				    "%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
				    &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4],
				    &tmp[5], &tmp[6], &tmp[7]);
		if (num_in != 8) {
			printf("invalid vm-guid\n");
			ret = RET_ERROR;
			goto out;
		}

		for (int i = 0; i < 8; i++) {
			uint16_t be16 = htobe16((uint16_t)tmp[i]);
			memcpy(vd->vm_guid + (i * 2), &be16, 2);
		}

		vd->has_guid = true;
	} else {
		memset(vd->vm_guid, 0, sizeof(vd->vm_guid));
		vd->has_guid = false;
	}

	const fdt64_t *pasid = (const fdt64_t *)fdt_getprop(
		fdt, node_ofs, "qcom,pasid", &lenp);
	if (pasid != NULL) {
		if (lenp != sizeof(uint64_t)) {
			printf("qcom,pasid invalid\n");
			ret = RET_ERROR;
			goto out;
		}
		vd->pasid = fdt64_to_cpu(*pasid);
	}

	// parse io memory range
	error_t iomem_ranges_ret = parse_iomem_ranges(vd, fdt, node_ofs, ctx);
	if (iomem_ranges_ret != OK) {
		ret = RET_ERROR;
		goto out;
	}

	error_t irq_ranges_ret = parse_irq_ranges(vd, fdt, node_ofs);
	if (irq_ranges_ret != OK) {
		ret = RET_ERROR;
		goto out;
	}

	error_t segments_ret = parse_segments(vd, fdt, node_ofs);
	if (segments_ret != OK) {
		ret = RET_ERROR;
		goto out;
	}

	const struct fdt_property *p =
		fdt_get_property(fdt, node_ofs, "qcom,sensitive", &lenp);
	if (p != NULL) {
		vd->sensitive = true;
		// Sensitive VM implies hiding AMU data from HLOS
		vd->amu_counting_disabled = true;
	} else {
		vd->sensitive = false;
	}

	ret = platform_parse_vm_config(data, fdt, node_ofs, ctx);

out:
	if (ret == RET_ERROR) {
		if (vd->kernel_entry_segment != NULL) {
			free(vd->kernel_entry_segment);
		}
		if (vd->vendor_name != NULL) {
			free(vd->vendor_name);
		}
	}

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

	count_t num_words   = (count_t)lenp / sizeof(iomems[0]);
	count_t range_words = (ctx->addr_cells * 3) + 1;

	if ((num_words == 0U) || ((num_words % range_words) != 0U)) {
		printf("iomemory-ranges invalid length\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	index_t i = 0;
	while (i < num_words) {
		iomem_range_data_t r;

		r.phys_base = fdt_read_num(&iomems[i], ctx->addr_cells);
		i += ctx->addr_cells;

		r.ipa_base = fdt_read_num(&iomems[i], ctx->addr_cells);
		i += ctx->addr_cells;

		r.size = fdt_read_num(&iomems[i], ctx->addr_cells);
		i += ctx->size_cells;

		if (!util_is_baligned(r.phys_base, PAGE_SIZE) ||
		    !util_is_baligned(r.ipa_base, PAGE_SIZE) ||
		    !util_is_baligned(r.size, PAGE_SIZE)) {
			printf("iomemory-ranges invalid alignment\n");
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}

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
	listener_return_t ret = RET_CLAIMED;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	const fdt32_t *base_ipa = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "base-address", &lenp);
	if (base_ipa != NULL) {
		vd->mem_base_ipa = fdt_read_num(base_ipa, ctx->addr_cells);
		if (!util_is_baligned(vd->mem_base_ipa, PAGE_SIZE)) {
			printf("base-address invalid alignment\n");
			ret = RET_ERROR;
			goto out;
		}
	}

	const fdt32_t *size_min =
		(const fdt32_t *)fdt_getprop(fdt, node_ofs, "size-min", &lenp);
	if (size_min != NULL) {
		vd->mem_size_min = fdt_read_num(size_min, ctx->addr_cells);
		if (!util_is_baligned(vd->mem_size_min, PAGE_SIZE)) {
			printf("size-min invalid alignment\n");
			ret = RET_ERROR;
			goto out;
		}
	}

out:
	return ret;
}

listener_return_t
parse_interrupts(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	int lenp = 0;

	(void)data;

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

	// FIXME future: parse 'reg' property and setup GIC IPA dynamically

err_interrupt_controller:
err_compatible:
	return ret;
}

listener_return_t
parse_rm_rpc(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

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
		goto out_free;
	}

	char *extra_compatible = strdup("qcom,resource-manager");
	if (extra_compatible == NULL) {
		ret = RET_ERROR;
		goto out_free;
	}

	char *extra_compatible_with_version =
		calloc(VDEVICE_MAX_COMPATIBLE_LEN, sizeof(char));
	if (extra_compatible_with_version == NULL) {
		free(extra_compatible);
		ret = RET_ERROR;
		goto out_free;
	}

	int snprintf_ret = snprintf(extra_compatible_with_version,
				    VDEVICE_MAX_COMPATIBLE_LEN,
				    "qcom,resource-manager-%s",
				    gunyah_api_version);
	if (snprintf_ret < 0) {
		free(extra_compatible);
		free(extra_compatible_with_version);
		ret = RET_ERROR;
		goto out_free;
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
		ret = RET_ERROR;
	}

out:
	return ret;

out_free:
	destroy_general_vdevice_props(&cfg.general);

	goto out;
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
	} else {
		cfg->generate = NULL;
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
	listener_return_t ret = RET_CLAIMED;

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

	cfg.peer = VMID_PEER_DEFAULT;

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
	listener_return_t ret = RET_CLAIMED;

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

	cfg.peer = VMID_PEER_DEFAULT;

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
	listener_return_t ret = RET_CLAIMED;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	msg_queue_data_t cfg;
	memset(&cfg, 0, sizeof(cfg));

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

	cfg.peer = VMID_PEER_DEFAULT;

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
	listener_return_t ret = RET_CLAIMED;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	msg_queue_pair_data_t cfg;
	memset(&cfg, 0, sizeof(cfg));

	const struct fdt_property *peer_default =
		fdt_get_property(fdt, node_ofs, "peer-default", &lenp);
	if (peer_default != NULL) {
		cfg.peer    = VMID_PEER_DEFAULT;
		cfg.peer_id = NULL;
	} else {
		const char *peer =
			(const char *)fdt_getprop(fdt, node_ofs, "peer", &lenp);
		if (peer != NULL) {
			assert(strlen(peer) + 1 == (size_t)lenp);

			// should be safe to dup str
			cfg.peer_id = strdup(peer);
			if (cfg.peer_id == NULL) {
				printf("Error: failed to save peer id\n");
				ret = RET_ERROR;
				goto err_not_peer;
			}
		} else {
			ret = RET_ERROR;
			goto err_not_peer;
		}
	}

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
	vector_push_back_imm(msg_queue_pair_data_t, vd->msg_queue_pairs, cfg,
			     push_err);

	if (push_err != OK) {
		destroy_general_vdevice_props(&cfg.general);
		ret = RET_ERROR;
	}

err_parse_general:
err_not_peer:
	if (ret != RET_CLAIMED) {
		free(cfg.peer_id);
	}

	return ret;
}

static listener_return_t
parse_memory_node(void *fdt, int node_ofs, ctx_t *ctx, uint32_t *label,
		  paddr_t *mem_base_ipa, bool *need_allocate)
{
	listener_return_t ret = RET_CLAIMED;

	// handle sub memory node
	bool found_mem	  = false;
	int  sub_node_ofs = 0;
	int  lenp	  = 0;

	// parse memory node
	fdt_for_each_subnode (sub_node_ofs, fdt, node_ofs) {
		const char *node_name = fdt_get_name(fdt, sub_node_ofs, &lenp);
		(void)node_name;
		// the node must be memory
		if (strcmp(node_name, "memory") != 0U) {
			printf("parse vdevice node: expected \"memory\" node\n");
			ret = RET_ERROR;
			goto err_unexpected;
		}

		ctx_t mem_ctx;
		dtb_parser_update_ctx(fdt, sub_node_ofs, ctx, &mem_ctx);

		// Only allows one shm memory right now
		if (found_mem) {
			printf("parse vdevice node: multiple \"memory\" nodes\n");
			ret = RET_ERROR;
			goto err_unexpected;
		}
		found_mem = true;

		// mem_label
		const fdt32_t *label_ptr = (const fdt32_t *)fdt_getprop(
			fdt, sub_node_ofs, LABEL_ID, &lenp);
		if (label_ptr != NULL) {
			*label = fdt32_to_cpu(*label_ptr);
		} else {
			ret = RET_ERROR;
			goto err_no_label;
		}

		const fdt64_t *base = (const fdt64_t *)fdt_getprop(
			fdt, sub_node_ofs, "base", &lenp);
		if (base != NULL) {
			*mem_base_ipa = fdt_read_num((const fdt32_t *)base,
						     mem_ctx.addr_cells);
		} else {
			*mem_base_ipa = 0UL;
		}
		if (!util_is_baligned(*mem_base_ipa, PAGE_SIZE)) {
			printf("parse vdevice node: base not aligned\n");
			ret = RET_ERROR;
			goto err_unexpected;
		}

		// check if need allocate
		*need_allocate = false;

		const struct fdt_property *p = fdt_get_property(
			fdt, sub_node_ofs, "allocate-base", &lenp);
		if (p != NULL) {
			if (base != NULL) {
				printf("parse vdevice node: base and allocate-base both present\n");
				ret = RET_ERROR;
				goto err_unexpected;
			}
			*need_allocate = true;
			*mem_base_ipa  = 0UL;
		} else if (base == NULL) {
			printf("parse vdevice node: neither base or allocate-base present\n");
			ret = RET_ERROR;
			goto err_unexpected;
		}
	}
err_unexpected:
err_no_label:
	return ret;
}

static listener_return_t
parse_shm_doorbell(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

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

	ret = parse_memory_node(fdt, node_ofs, ctx, &cfg.general.label,
				&cfg.mem_base_ipa, &cfg.need_allocate);
	if (ret != RET_CLAIMED) {
		goto err_parse_memory_node;
	}

	const struct fdt_property *peer_default =
		fdt_get_property(fdt, node_ofs, "peer-default", &lenp);
	if (peer_default == NULL) {
		ret = RET_ERROR;
		goto err_not_peer_default;
	}

	cfg.peer = VMID_PEER_DEFAULT;

	const fdt64_t *dma_base_ptr =
		(const fdt64_t *)fdt_getprop(fdt, node_ofs, "dma_base", &lenp);
	cfg.dma_base = dma_base_ptr == NULL
			       ? (uint64_t)(-1)
			       : fdt_read_num((const fdt32_t *)dma_base_ptr, 2);

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

err_parse_memory_node:
err_parse_general:
err_not_peer_default:
	return ret;
}

listener_return_t
parse_vcpus(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	(void)ctx;

	listener_return_t ret = RET_CLAIMED;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	// read sched time slice
	const fdt32_t *sched_time_slice_ptr = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "sched-timeslice", &lenp);
	if (sched_time_slice_ptr != NULL) {
		vd->sched_time_slice = fdt32_to_cpu(*sched_time_slice_ptr);
	}

	// read sched priority
	const fdt32_t *sched_priority_ptr = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "sched-priority", &lenp);
	if (sched_priority_ptr != NULL) {
		vd->sched_priority = (int32_t)fdt32_to_cpu(*sched_priority_ptr);
	}

	// default is static
	vd->affinity = VM_CONFIG_AFFINITY_STATIC;
	// read affinity type
	const char *affinity =
		(const char *)fdt_getprop(fdt, node_ofs, "affinity", &lenp);
	if (affinity != NULL) {
		if (strcmp(affinity, "sticky") == 0) {
			vd->affinity = VM_CONFIG_AFFINITY_STICKY;
		} else if (strcmp(affinity, "pinned") == 0) {
			vd->affinity = VM_CONFIG_AFFINITY_PINNED;
		} else if (strcmp(affinity, "static") == 0) {
			vd->affinity = VM_CONFIG_AFFINITY_STATIC;
		} else {
			printf("parse_vcpus: unsupported \"affinity\"\n");
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
			ret = RET_ERROR;
			goto out;
		}

		index_t i = 0;
		while (i < sz) {
			vd->affinity_map[i] =
				(cpu_index_t)fdt32_to_cpu(affinity_map[i]);
			i++;
		}
	} else {
		printf("parse_vcpus: \"affinity_map\" missing\n");
		ret = RET_ERROR;
		goto out;
	}

	// read cpus number in device tree
	const char *config =
		(const char *)fdt_getprop(fdt, node_ofs, "config", &lenp);
	if (config == NULL) {
		printf("parse_vcpus: \"config\" missing\n");
		ret = RET_ERROR;
		goto out;
	}

	int config_ofs = fdt_path_offset(fdt, config);
	if (config_ofs < 0) {
		printf("parse_vcpus: \"config\" path invalid\n");
		ret = RET_ERROR;
		goto out;
	}

	// Optional default method
	const char *default_enable_method = (const char *)fdt_getprop(
		fdt, config_ofs, "enable-method", &lenp);

	// create secondary vcpus only
	int sub_node_ofs = 0;

	count_t idle_state_count	= 0;
	count_t gunyah_hvc_method_count = 0;

	fdt_for_each_subnode (sub_node_ofs, fdt, config_ofs) {
		const char *device_type = (const char *)fdt_getprop(
			fdt, sub_node_ofs, "device_type", &lenp);

		if ((device_type != NULL) &&
		    (strcmp(device_type, "cpu") == 0)) {
			// Check if default method is overriden
			const char *cpu_enable_method =
				(const char *)fdt_getprop(fdt, sub_node_ofs,
							  "enable-method",
							  &lenp);

			const char *enable_method =
				(cpu_enable_method != NULL)
					? cpu_enable_method
					: default_enable_method;

			if (enable_method == NULL) {
				printf("parse_vcpus: no enable-method defined\n");
				ret = RET_ERROR;
				goto out;
			}

			// Check if the cpu has idle states
			const fdt32_t *idle_states =
				(const fdt32_t *)fdt_getprop(fdt, sub_node_ofs,
							     "cpu-idle-states",
							     &lenp);

			if ((idle_states == NULL) &&
			    (strcmp(enable_method, "qcom,gunyah-hvc") == 0)) {
				gunyah_hvc_method_count++;
			} else if ((idle_states != NULL) &&
				   (strcmp(enable_method, "psci") == 0)) {
				idle_state_count++;
			} else {
				printf("parse_vcpus: idle states must be defined only for psci\n");
				ret = RET_ERROR;
				goto out;
			}

			char path[128];
			int  path_ret =
				fdt_get_path(fdt, sub_node_ofs, path, 128);
			if (path_ret != 0) {
				ret = RET_ERROR;
				goto out;
			}

			vcpu_data_t cfg;
			memset(&cfg, 0, sizeof(cfg));

			cfg.patch = strdup(path);

			error_t push_err;
			vector_push_back_imm(vcpu_data_t, vd->vcpus, cfg,
					     push_err);
			if (push_err != OK) {
				ret = RET_ERROR;
				goto out;
			}
		}
	}

	size_t cpu_count = vector_size(vd->vcpus);

	if (cpu_count != vd->affinity_map_cnt) {
		printf("parse_vcpus: cpu and affinity count don't match\n");
		ret = RET_ERROR;
		goto out;
	}

	if (cpu_count == gunyah_hvc_method_count) {
		vd->enable_vpm_psci = false;
	} else if (cpu_count == idle_state_count) {
		vd->enable_vpm_psci = true;
	} else {
		printf("parse_vcpus: invalid idle states or method count\n");
		ret = RET_ERROR;
		goto out;
	}

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

	ret->msg_queue_pairs = vector_init(msg_queue_pair_data_t, 2U, 2U);
	if (ret->msg_queue_pairs == NULL) {
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

	ret->iomems = vector_init(iomem_data_t, 1U, 1U);
	if (ret->iomems == NULL) {
		goto err_out;
	}

	ret->vcpus = vector_init(vcpu_data_t, 1U, 1U);
	if (ret->vcpus == NULL) {
		goto err_out;
	}

	ret->platform_data = vector_init(platform_data_t, 1U, 1U);
	if (ret->platform_data == NULL) {
		goto err_out;
	}

	goto out;

err_out:
	if (ret) {
		if (ret->vcpus != NULL) {
			vector_deinit(ret->vcpus);
		}
		if (ret->iomems != NULL) {
			vector_deinit(ret->iomems);
		}
		if (ret->irq_ranges != NULL) {
			vector_deinit(ret->irq_ranges);
		}
		if (ret->iomem_ranges != NULL) {
			vector_deinit(ret->iomem_ranges);
		}
		if (ret->shms != NULL) {
			vector_deinit(ret->shms);
		}
		if (ret->msg_queues != NULL) {
			vector_deinit(ret->msg_queues);
		}
		if (ret->msg_queue_pairs != NULL) {
			vector_deinit(ret->msg_queue_pairs);
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

	if (vd->msg_queue_pairs != NULL) {
		FREE_GENERAL(msg_queue_data_t, vd->msg_queue_pairs);
		vector_deinit(vd->msg_queue_pairs);
	}

	if (vd->shms != NULL) {
		FREE_GENERAL(shm_data_t, vd->shms);
		vector_deinit(vd->shms);
	}

	if (vd->iomems != NULL) {
		FREE_GENERAL(iomem_data_t, vd->iomems);
		vector_deinit(vd->iomems);
	}

#undef FREE_GENERAL

	if (vd->iomem_ranges) {
		vector_deinit(vd->iomem_ranges);
	}

	if (vd->irq_ranges) {
		vector_deinit(vd->irq_ranges);
	}

	if (vd->vcpus != NULL) {
		vector_deinit(vd->vcpus);
	}

	if (vd->platform_data != NULL) {
		size_t cnt = vector_size(vd->platform_data);
		for (index_t idx = 0; idx < cnt; ++idx) {
			platform_data_t *d = vector_at_ptr(
				platform_data_t, vd->platform_data, idx);
			if (d->data) {
				free(d->data);
			}
		}

		vector_deinit(vd->platform_data);
	}

	free(vd->kernel_entry_segment);
	free(vd->vendor_name);
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
		// skip irq range setup if there's no such property
		ret = OK;
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

listener_return_t
parse_iomem(void *data, void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	int lenp = 0;

	vm_config_parser_data_t *vd = (vm_config_parser_data_t *)data;

	iomem_data_t cfg;
	memset(&cfg, 0, sizeof(cfg));

	error_t parse_general_ret =
		parse_general_vdevice_props(&cfg.general, fdt, node_ofs, ctx);
	if (parse_general_ret != OK) {
		ret = RET_ERROR;
		goto out;
	}

	const char *patch_node_path =
		(const char *)fdt_getprop(fdt, node_ofs, "patch", &lenp);
	if (patch_node_path != NULL) {
		cfg.patch_node_path = strdup(patch_node_path);
		if (cfg.patch_node_path == NULL) {
			ret = RET_ERROR;
			goto out;
		}
	}

	const struct fdt_property *p =
		fdt_get_property(fdt, node_ofs, "peer-default", &lenp);
	if (p == NULL) {
		ret = RET_ERROR;
		goto out;
	}

	struct vdevice_iomem *d = &cfg.data;

	d->peer = VMID_HLOS;

	int sub_node_ofs = 0;

	// parse memory node
	fdt_for_each_subnode (sub_node_ofs, fdt, node_ofs) {
		const char *node_name = fdt_get_name(fdt, sub_node_ofs, &lenp);
		(void)node_name;
		// the node must be memory
		assert(strcmp(node_name, "memory") == 0);

		ctx_t mem_ctx;
		dtb_parser_update_ctx(fdt, sub_node_ofs, ctx, &mem_ctx);

		// mem_label
		const fdt32_t *label_ptr = (const fdt32_t *)fdt_getprop(
			fdt, sub_node_ofs, LABEL_ID, &lenp);
		if (label_ptr != NULL) {
			cfg.general.label = fdt32_to_cpu(*label_ptr);

			d->label = cfg.general.label;
		} else {
			ret = RET_ERROR;
			goto out;
		}

		// mem_label
		const fdt32_t *tag_ptr = (const fdt32_t *)fdt_getprop(
			fdt, sub_node_ofs, "qcom,mem-info-tag", &lenp);
		if (tag_ptr != NULL) {
			d->mem_info_tag = fdt32_to_cpu(*tag_ptr);

			d->mem_info_tag_set = true;
		} else {
			d->mem_info_tag = 0;

			d->mem_info_tag_set = false;
		}

		// optional parse acl
		const fdt32_t *acl = (const fdt32_t *)fdt_getprop(
			fdt, node_ofs, "qcom,rm_acl", &lenp);
		if (acl != NULL) {
			error_t read_err =
				fdt_read_u32_array(acl, lenp, d->rm_acl,
						   IOMEM_VALIDATION_NUM_IDXS);
			if (read_err != OK) {
				printf("Error: failed to parse qcom,rm_acl for "
				       "iomem %d\n",
				       cfg.general.label);
				ret = RET_ERROR;
				goto out;
			}

			d->validate_acl = true;
		} else {
			d->validate_acl = false;
		}

		// optional parse attributes
		const fdt32_t *attrs = (const fdt32_t *)fdt_getprop(
			fdt, node_ofs, "qcom,rm_attributes", &lenp);
		if (attrs != NULL) {
			error_t read_err =
				fdt_read_u32_array(attrs, lenp, d->rm_attrs,
						   IOMEM_VALIDATION_NUM_IDXS);
			if (read_err != OK) {
				printf("Error: failed to parse "
				       " qcom,rm_attributes for iomem %d\n",
				       cfg.general.label);
				ret = RET_ERROR;
				goto out;
			}

			d->validate_attrs = true;
		} else {
			d->validate_attrs = false;
		}

		// optional sglist for validation
		const fdt32_t *sgl_entry = (const fdt32_t *)fdt_getprop(
			fdt, node_ofs, "qcom,rm_sglist", &lenp);
		if (sgl_entry != NULL) {
			if ((size_t)lenp % sizeof(d->rm_sglist[0]) != 0) {
				printf("Error: invalid qcom,rm_sglist value\n");
				ret = RET_ERROR;
				goto out;
			}

			count_t entries =
				(count_t)lenp / sizeof(d->rm_sglist[0]);

			d->rm_sglist = calloc(entries, sizeof(d->rm_sglist[0]));
			if (d->rm_sglist == NULL) {
				ret = RET_ERROR;
				goto out;
			}

			for (index_t i = 0; i < entries; i++) {
				d->rm_sglist[i].ipa =
					fdt_read_num(sgl_entry, 2U);

				d->rm_sglist[i].size =
					fdt_read_num(sgl_entry + 2, 2U);

				// next sgl entry
				sgl_entry += 4;
			}
		}

		// check if need allocate
		// FIXME: how to handle if need_allocate is false
		d->need_allocate = false;

		const struct fdt_property *allocate_base = fdt_get_property(
			fdt, sub_node_ofs, "allocate_base", &lenp);
		if (allocate_base != NULL) {
			d->need_allocate = true;
		}
	}

	error_t push_err;
	vector_push_back_imm(iomem_data_t, vd->iomems, cfg, push_err);

	if (push_err != OK) {
		destroy_general_vdevice_props(&cfg.general);
		ret = RET_ERROR;
	}
out:
	if (ret == RET_ERROR) {
		free(cfg.data.rm_sglist);
		free(cfg.patch_node_path);
		destroy_general_vdevice_props(&cfg.general);
	}

	return ret;
}
