// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <endian.h>
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

#include <util.h>
#include <utils/vector.h>

#include <dt_linux.h>
#include <dtb_parser.h>
#include <event.h>
#include <guest_interface.h>
#include <memparcel_msg.h>
#include <platform_dt_parser.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_mgnt.h>

#include <platform_vm_config_parser.h>
#include <vm_config_parser.h>

#include "libfdt_env.h"
#include "vm_parser_rtc.h"

#define LABEL_ID "qcom,label"

// FIXME: double check it
// #define DEFAULT_INTERRUPT_CELLS (2)
#define DEFAULT_MSG_QUEUE_DEPTH (8U)
#define DEFAULT_MSG_QUEUE_SIZE	RM_RPC_MESSAGE_SIZE
#define DEFAULT_VIRTIO_VQS_NUM	(1U)

static vm_config_parser_data_t *
alloc_parser_data(const vm_config_parser_params_t *params);

static void
free_parser_data(vm_config_parser_data_t *vd);

static listener_return_t
parse_memory(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	     const ctx_t *ctx);

static listener_return_t
parse_vm_config(vm_config_parser_data_t *vd, const void *fdt, int32_t node_ofs,
		const ctx_t *ctx);

static listener_return_t
parse_vm_memory(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		const ctx_t *ctx);

static listener_return_t
parse_rm_rpc(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	     const ctx_t *ctx);

static error_t
parse_general_vdevice_props(general_data_t *cfg, const void *fdt, int node_ofs,
			    const ctx_t *ctx);
static void
destroy_general_vdevice_props(general_data_t *cfg);

static listener_return_t
parse_doorbell_source(vm_config_parser_data_t *vd, const void *fdt,
		      int node_ofs, const ctx_t *ctx);

static listener_return_t
parse_doorbell(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	       const ctx_t *ctx);

static listener_return_t
parse_message_queue(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		    const ctx_t *ctx);

static listener_return_t
parse_message_queue_pair(vm_config_parser_data_t *vd, const void *fdt,
			 int node_ofs, const ctx_t *ctx);

static listener_return_t
parse_virtio_mmio(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		  const ctx_t *ctx);

static listener_return_t
parse_shm_doorbell(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		   const ctx_t *ctx);

static listener_return_t
parse_iomem(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	    const ctx_t *ctx);

static listener_return_t
parse_vcpus(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	    const ctx_t *ctx);

static listener_return_t
parse_vsmmuv2(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	      const ctx_t *ctx);

static listener_return_t
parse_psci(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	   const ctx_t *ctx);

static bool
read_interrupts_config(const void *fdt, int node_ofs, interrupt_data_t *irqs,
		       count_t count);

typedef struct {
	uint32_t size;
	uint32_t depth;
} msg_queue_param_t;

static msg_queue_param_t
get_msg_queue_param(const void *fdt, int node_ofs);

static error_t
parse_iomem_ranges(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		   const ctx_t *ctx);

static error_t
parse_irq_ranges(vm_config_parser_data_t *vd, const void *fdt, int node_ofs);

listener_return_t
platform_parse_vm_config(vm_config_parser_data_t *vd, const void *fdt,
			 int node_ofs, const ctx_t *ctx);

static dtb_listener_t vm_config_listener[] = {
	// This _must_ be the first listener, to prevent an untrusted VMM
	// sneaking a memory node past us by disguising it as another node.
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "device_type",
		.expected_string  = "memory",
		.action		  = parse_memory,
	},
	{
		.type	       = BY_PATH,
		.expected_path = "^/(qcom,|gunyah-)vm-config$",
		.action	       = parse_vm_config,
	},
	{
		.type	       = BY_PATH,
		.expected_path = "^/(qcom,|gunyah-)vm-config/memory$",
		.action	       = parse_vm_memory,
	},
	{
		.type	       = BY_PATH,
		.expected_path = "^/(qcom,|gunyah-)vm-config/vcpus$",
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
		.expected_string  = "virtio-mmio",
		.action		  = parse_virtio_mmio,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "iomem",
		.action		  = parse_iomem,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "vsmmu-v2",
		.action		  = parse_vsmmuv2,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "vrtc-pl031",
		.action		  = parse_vrtc,
	},
	{
		.type		   = BY_COMPATIBLE,
		.compatible_string = "arm,psci-0.2",
		.action		   = parse_psci,
	},
	{
		// Some existing VM DTs only declare support for 1.0, despite it
		// being backwards compatible with 0.2
		.type		   = BY_COMPATIBLE,
		.compatible_string = "arm,psci-1.0",
		.action		   = parse_psci,
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

static error_t
parse_device_label(const void *fdt, int node_ofs, uint32_t *label)
{
	if (!fdt_getprop_u32(fdt, node_ofs, LABEL_ID, label)) {
		return OK;
	}

	return fdt_getprop_u32(fdt, node_ofs, "label", label);
}

static void
warn_if_not_phys(const void *fdt, int node_ofs, const ctx_t *ctx)
{
	if (!ctx->addr_is_phys) {
		char path[128];
		if (fdt_get_path(fdt, node_ofs, path, (int32_t)sizeof(path)) !=
		    0) {
			strlcpy(path, "<unknown path>", sizeof(path));
		}
		(void)printf("Warning: addresses in %s are not 1:1 physical!\n",
			     path);
	}
}

static listener_return_t
parse_vm_info(vm_config_parser_data_t *vd, const void *fdt, int32_t node_ofs)
{
	listener_return_t ret = RET_CLAIMED;

	int32_t len = 0;

	// Get VM URI
	const char *vm_uri =
		fdt_stringlist_get(fdt, node_ofs, "vm-uri", 0, &len);
	if ((vm_uri != NULL) && (len < VM_MAX_URI_LEN)) {
		strlcpy(vd->vm_uri, vm_uri, VM_MAX_URI_LEN);
	}

	// Get VM-GUID and convert from string to byte array
	const char *vm_guid =
		fdt_stringlist_get(fdt, node_ofs, "vm-guid", 0, NULL);
	if (vm_guid != NULL) {
		unsigned int tmp[8];

		int num_in = sscanf(vm_guid,
				    "%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
				    &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4],
				    &tmp[5], &tmp[6], &tmp[7]);
		if (num_in != 8) {
			(void)printf("invalid vm-guid\n");
			ret = RET_ERROR;
			goto out;
		}

		for (int i = 0; i < 8; i++) {
			uint16_t be16 = htobe16((uint16_t)tmp[i]);
			memcpy(vd->vm_guid + (i * 2), &be16, 2);
		}

		vd->has_guid = true;
	} else {
		(void)memset(vd->vm_guid, 0, sizeof(vd->vm_guid));
		vd->has_guid = false;
	}

out:
	return ret;
}

static listener_return_t
get_vendor_and_vm_name(vm_config_parser_data_t *vd, const void *fdt,
		       int32_t node_ofs)
{
	listener_return_t ret = RET_CLAIMED;

	int32_t len = 0;

	// get vendor name
	const char *vendor_name =
		fdt_stringlist_get(fdt, node_ofs, "vendor", 0, NULL);
	if (vendor_name != NULL) {
		vd->vendor_name = strdup(vendor_name);
		if (vd->vendor_name == NULL) {
			(void)printf(
				"Error: out of memory copying vendor name\n");
			ret = RET_ERROR;
			goto out;
		}
	}

	// Get VM/image name
	const char *image_name =
		fdt_stringlist_get(fdt, node_ofs, "image-name", 0, &len);
	if ((image_name != NULL) && (len < VM_MAX_NAME_LEN)) {
		strlcpy(vd->vm_name, image_name, VM_MAX_NAME_LEN);
	} else {
		(void)printf("Error: image name missing or too long\n");
		ret = RET_ERROR;
		goto out;
	}

out:
	return ret;
}

static listener_return_t
parse_kernel_image_info(vm_config_parser_data_t *vd, const void *fdt,
			int32_t node_ofs, const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	const char *kernel_entry_segment = fdt_stringlist_get(
		fdt, node_ofs, "kernel-entry-segment", 0, NULL);
	if (kernel_entry_segment != NULL) {
		vd->kernel_entry_segment = strdup(kernel_entry_segment);
		if (vd->kernel_entry_segment == NULL) {
			(void)printf(
				"Error: out of memory copying entry segment\n");
			ret = RET_ERROR;
			goto out;
		}
	}

	if (fdt_getprop_num(fdt, node_ofs, "kernel-entry-offset",
			    ctx->addr_cells, &vd->kernel_entry_offset) != OK) {
		// kernel-entry-offset is unset, use the default
	}

out:
	return ret;
}

static listener_return_t
parse_vm_attrs(vm_config_parser_data_t *vd, const void *fdt, int32_t node_ofs)
{
	listener_return_t ret = RET_CLAIMED;

	int vm_attrs_count = fdt_stringlist_count(fdt, node_ofs, "vm-attrs");
	if (vm_attrs_count == -FDT_ERR_BADVALUE) {
		(void)printf("Error: malformed stringlist in vm-attrs\n");
		ret = RET_ERROR;
		goto out;
	}
	for (int i = 0; i < vm_attrs_count; i++) {
		const char *vm_attr =
			fdt_stringlist_get(fdt, node_ofs, "vm-attrs", i, NULL);
		if (strcmp(vm_attr, "ras-error-handler") == 0) {
			vd->ras_error_handler = true;
		} else if (strcmp(vm_attr, "amu-counting-disabled") == 0) {
			vd->amu_counting_disabled = true;
		} else if (strcmp(vm_attr, "crash-fatal") == 0) {
			vd->crash_fatal = true;
			// Crash-fatal implies no-shutdown.
			vd->no_shutdown = true;
			// Crash-fatal implies reset is not allowed.
			vd->no_reset = true;
		} else if (strcmp(vm_attr, "context-dump") == 0) {
			vd->context_dump = true;
		} else if (strcmp(vm_attr, "no-shutdown") == 0) {
			vd->no_shutdown = true;
		} else if (strcmp(vm_attr, "no-reset") == 0) {
			vd->no_reset = true;
		}
#if defined(GUEST_RAM_DUMP_ENABLE) && GUEST_RAM_DUMP_ENABLE
		else if (strcmp(vm_attr, "guest-ram-dump") == 0) {
			// get guest ram dump status
			vd->guest_ram_dump = true;
		}
#endif // GUEST_RAM_DUMP_ENABLE
#if defined(PLATFORM_ALLOW_INSECURE_CONSOLE) && PLATFORM_ALLOW_INSECURE_CONSOLE
		else if (strcmp(vm_attr, "insecure-console") == 0) {
			vd->insecure_console = true;
			(void)printf("VM has insecure console\n");
		}
#endif // PLATFORM_ALLOW_INSECURE_CONSOLE
		else {
			(void)printf("Warning: Unknown VM attribute \"%s\"\n",
				     vm_attr);
		}
	}

out:
	return ret;
}

static listener_return_t
parse_vm_config(vm_config_parser_data_t *vd, const void *fdt, int32_t node_ofs,
		const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	warn_if_not_phys(fdt, node_ofs, ctx);

	// get vm type
	const char *vm_type =
		fdt_stringlist_get(fdt, node_ofs, "vm-type", 0, NULL);
	if (vm_type != NULL) {
		// default is aarch64, refactor it when have more types
		if (strcmp(vm_type, "aarch64-guest") == 0) {
			vd->vm_type = VM_CONFIG_VM_TYPE_AARCH64_GUEST;
		}
	}

	const char *os_type =
		fdt_stringlist_get(fdt, node_ofs, "os-type", 0, NULL);
	if (os_type != NULL) {
		if (strcmp(os_type, "linux") == 0) {
			vd->os_type = VM_CONFIG_OS_TYPE_LINUX;
		}
	}

	ret = parse_vm_attrs(vd, fdt, node_ofs);
	if (ret != RET_CLAIMED) {
		goto out;
	}

	ret = parse_kernel_image_info(vd, fdt, node_ofs, ctx);
	if (ret != RET_CLAIMED) {
		goto out;
	}

	ret = get_vendor_and_vm_name(vd, fdt, node_ofs);
	if (ret != RET_CLAIMED) {
		goto out;
	}

	ret = parse_vm_info(vd, fdt, node_ofs);
	if (ret != RET_CLAIMED) {
		goto out;
	}

	// parse io memory range
	error_t iomem_ranges_ret = parse_iomem_ranges(vd, fdt, node_ofs, ctx);
	if (iomem_ranges_ret != OK) {
		(void)printf("Error: parse_iomem_ranges failed: %d\n",
			     iomem_ranges_ret);
		ret = RET_ERROR;
		goto out;
	}

	error_t irq_ranges_ret = parse_irq_ranges(vd, fdt, node_ofs);
	if (irq_ranges_ret != OK) {
		(void)printf("Error: parse_irq_ranges failed: %d\n",
			     irq_ranges_ret);
		ret = RET_ERROR;
		goto out;
	}

	if (fdt_getprop_bool(fdt, node_ofs, "qcom,sensitive")) {
		vd->sensitive = true;
		// Sensitive VM implies hiding AMU data from HLOS
		vd->amu_counting_disabled = true;
	}

	ret = platform_parse_vm_config(vd, fdt, node_ofs, ctx);

out:
	if (ret == RET_ERROR) {
		if (vd->kernel_entry_segment != NULL) {
			free(vd->kernel_entry_segment);
			vd->kernel_entry_segment = NULL;
		}
		if (vd->vendor_name != NULL) {
			free(vd->vendor_name);
			vd->vendor_name = NULL;
		}
	}

	return ret;
}

static error_t
parse_iomem_ranges(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		   const ctx_t *ctx)
{
	error_t ret = OK;

	int len = 0;

	const fdt32_t *iomems = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "iomemory-ranges", &len);
	if (iomems == NULL) {
		goto out;
	}

	count_t num_words   = (count_t)len / sizeof(iomems[0]);
	count_t range_words = (ctx->addr_cells * 2U) + ctx->size_cells + 1U;

	if ((num_words == 0U) || ((num_words % range_words) != 0U)) {
		(void)printf(
			"iomemory-ranges invalid length (%d words, should be multiple of %d)\n",
			num_words, range_words);
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

		r.size = fdt_read_num(&iomems[i], ctx->size_cells);
		i += ctx->size_cells;

		if (!util_is_baligned(r.phys_base, PAGE_SIZE) ||
		    !util_is_baligned(r.ipa_base, PAGE_SIZE) ||
		    !util_is_baligned(r.size, PAGE_SIZE)) {
			(void)printf("iomemory-ranges invalid alignment\n");
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}

		uint16_t access_code = (uint16_t)fdt_read_num(&iomems[i], 1);
		if (access_code >= (uint16_t)IOMEM_RANGE_ACCESS_MAX) {
			(void)printf("iomemory-ranges invalid access\n");
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

static listener_return_t
parse_vm_memory(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	warn_if_not_phys(fdt, node_ofs, ctx);

	if (fdt_getprop_bool(fdt, node_ofs, "is-direct")) {
		vd->mem_map_direct = true;
		// Default value of the maximum size is the whole address space.
		vd->mem_size_max = ~(size_t)0U;
	}

	if (fdt_getprop_num(fdt, node_ofs, "base-address", ctx->addr_cells,
			    &vd->mem_base_ipa) == OK) {
		if (!util_is_baligned(vd->mem_base_ipa, PAGE_SIZE)) {
			(void)printf("base-address invalid alignment\n");
			ret = RET_ERROR;
			goto out;
		}
		if (!util_is_baligned(vd->mem_base_ipa, ((size_t)2U << 20))) {
			(void)printf(
				"Warning: base-address not 2MB aligned, aligning up\n");
			vd->mem_base_ipa =
				util_p2align_up(vd->mem_base_ipa, 21);
		}
		// Default value of the maximum size is the whole address space
		// above the configured base address
		vd->mem_size_max = 0U - (size_t)vd->mem_base_ipa;
	}

	if (fdt_getprop_num(fdt, node_ofs, "size-min", ctx->size_cells,
			    &vd->mem_size_min) == OK) {
		if (!util_is_baligned(vd->mem_size_min, PAGE_SIZE)) {
			(void)printf("size-min invalid alignment");
			ret = RET_ERROR;
			goto out;
		}
	}

	if (fdt_getprop_num(fdt, node_ofs, "size-max", ctx->size_cells,
			    &vd->mem_size_max) == OK) {
		if (!util_is_baligned(vd->mem_size_max, PAGE_SIZE)) {
			(void)printf("size-max invalid alignment");
			ret = RET_ERROR;
			goto out;
		}
		if (util_add_overflows(vd->mem_base_ipa, vd->mem_size_max)) {
			(void)printf("size-max too large for base-address");
			ret = RET_ERROR;
			goto out;
		}
	}

	if (fdt_getprop_num(fdt, node_ofs, "firmware-address", ctx->addr_cells,
			    &vd->fw_base_ipa) == OK) {
		if (!util_is_baligned(vd->fw_base_ipa, PAGE_SIZE)) {
			(void)printf("base-address invalid alignment\n");
			ret = RET_ERROR;
			goto out;
		}
	}

	if (fdt_getprop_num(fdt, node_ofs, "firmware-size-max", ctx->size_cells,
			    &vd->fw_size_max) == OK) {
		if (!util_is_baligned(vd->fw_size_max, PAGE_SIZE)) {
			(void)printf("firmware-size-max invalid alignment");
			ret = RET_ERROR;
			goto out;
		}
		if (util_add_overflows(vd->fw_base_ipa, vd->fw_size_max)) {
			(void)printf(
				"firmware-size-max too large for base-address");
			ret = RET_ERROR;
			goto out;
		}
	}

	// optional base-mem-constraints
	// < generic-constraints platform-constraints >;
	error_t err = fdt_getprop_u32_array(
		fdt, node_ofs, "base-mem-constraints", vd->mem_base_constraints,
		sizeof(vd->mem_base_constraints), NULL);
	if (err == OK) {
		vd->mem_base_constraints_set = true;
	} else if (err == ERROR_ARGUMENT_INVALID) {
		vd->mem_base_constraints_set = false;
	} else {
		(void)printf("Failed to parse base-mem-constraints %d\n", err);
		ret = RET_ERROR;
		goto out;
	}

out:
	return ret;
}

static listener_return_t
parse_rm_rpc(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	     const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;
	char		 *cp;

	rm_rpc_data_t cfg;

	(void)memset(&cfg, 0, sizeof(cfg));

	cfg.is_console_dev = fdt_getprop_bool(fdt, node_ofs, "console-dev");

	// handle irq
	cfg.defined_irq = read_interrupts_config(fdt, node_ofs, cfg.irqs,
						 util_array_size(cfg.irqs));

	error_t general_parse_ret =
		parse_general_vdevice_props(&cfg.general, fdt, node_ofs, ctx);
	if (general_parse_ret != OK) {
		ret = RET_ERROR;
		goto out;
	}

	// add three more additional push_compatibles
	index_t cnt = cfg.general.push_compatible_num;
	if (cnt + 3U > VDEVICE_MAX_PUSH_COMPATIBLES) {
		ret = RET_ERROR;
		goto out_free;
	}

	cp = strdup("gunyah-resource-manager");
	if (cp == NULL) {
		ret = RET_ERROR;
		goto out_free;
	}
	cfg.general.push_compatible[cnt + 0U] = cp;

	cp = strdup("qcom,resource-manager");
	if (cp == NULL) {
		ret = RET_ERROR;
		goto out_free;
	}
	cfg.general.push_compatible[cnt + 1U] = cp;

	cp = calloc(VDEVICE_MAX_COMPATIBLE_LEN, sizeof(char));
	if (cp == NULL) {
		ret = RET_ERROR;
		goto out_free;
	}
	cfg.general.push_compatible[cnt + 2U] = cp;

	int snprintf_ret = snprintf(cp, VDEVICE_MAX_COMPATIBLE_LEN,
				    "qcom,resource-manager-%s",
				    gunyah_api_version);
	if (snprintf_ret < 0) {
		ret = RET_ERROR;
		goto out_free;
	}

	cfg.general.push_compatible_num += 3U;

	msg_queue_param_t p = get_msg_queue_param(fdt, node_ofs);

	// FIXME: find correct way to get IRQ allocated if needed

	cfg.msg_size	= (uint16_t)p.size;
	cfg.queue_depth = (uint16_t)p.depth;

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

static void
destroy_general_vdevice_props(general_data_t *cfg)
{
	char *cp;

	for (index_t i = 0; i < VDEVICE_MAX_PUSH_COMPATIBLES; i++) {
		cp = cfg->push_compatible[i];
		if (cp) {
			free(cp);
			cfg->push_compatible[i] = NULL;
		}
	}

	cfg->push_compatible_num = 0UL;

	free(cfg->generate);
	cfg->generate = NULL;
}

static error_t
parse_general_vdevice_props(general_data_t *cfg, const void *fdt, int node_ofs,
			    const ctx_t *ctx)
{
	(void)ctx;

	error_t ret = OK;

	(void)parse_device_label(fdt, node_ofs, &cfg->label);

	const char *generate =
		fdt_stringlist_get(fdt, node_ofs, "generate", 0, NULL);
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

	int num_push_compatibles =
		fdt_stringlist_count(fdt, node_ofs, "push-compatible");
	if (num_push_compatibles > (int32_t)VDEVICE_MAX_PUSH_COMPATIBLES) {
		ret = ERROR_DENIED;
		destroy_general_vdevice_props(cfg);
		goto out;
	}

	if (num_push_compatibles >= 0) {
		for (int i = 0; i < num_push_compatibles; i++) {
			cfg->push_compatible[i] = strdup(fdt_stringlist_get(
				fdt, node_ofs, "push-compatible", i, NULL));
		}
		cfg->push_compatible_num = (count_t)num_push_compatibles;
	}

out:
	return ret;
}

static listener_return_t
parse_doorbell_source(vm_config_parser_data_t *vd, const void *fdt,
		      int node_ofs, const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	doorbell_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	cfg.is_source = true;

	// should not define irq for source doorbell
	cfg.defined_irq = false;

	if (fdt_getprop_bool(fdt, node_ofs, "peer-default")) {
		cfg.peer    = VMID_PEER_DEFAULT;
		cfg.peer_id = NULL;
	} else {
		const char *peer =
			fdt_stringlist_get(fdt, node_ofs, "peer", 0, NULL);
		if (peer != NULL) {
			cfg.peer_id = strdup(peer);
			if (cfg.peer_id == NULL) {
				(void)printf("Error: failed to save peer id\n");
				ret = RET_ERROR;
				goto err_not_peer;
			}
		} else {
			ret = RET_ERROR;
			goto err_not_peer;
		}
	}

	cfg.source_can_clear =
		fdt_getprop_bool(fdt, node_ofs, "source-can-clear");

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
err_not_peer:
	if (ret != RET_CLAIMED) {
		free(cfg.peer_id);
	}

	return ret;
}

static listener_return_t
parse_doorbell(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	       const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	doorbell_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	cfg.is_source = false;

	cfg.defined_irq = read_interrupts_config(fdt, node_ofs, &cfg.irq, 1);

	if (fdt_getprop_bool(fdt, node_ofs, "peer-default")) {
		cfg.peer    = VMID_PEER_DEFAULT;
		cfg.peer_id = NULL;
	} else {
		const char *peer =
			fdt_stringlist_get(fdt, node_ofs, "peer", 0, NULL);
		if (peer != NULL) {
			cfg.peer_id = strdup(peer);
			if (cfg.peer_id == NULL) {
				(void)printf("Error: failed to save peer id\n");
				ret = RET_ERROR;
				goto err_not_peer;
			}
		} else {
			ret = RET_ERROR;
			goto err_not_peer;
		}
	}

	cfg.source_can_clear =
		fdt_getprop_bool(fdt, node_ofs, "source-can-clear");

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
err_not_peer:
	if (ret != RET_CLAIMED) {
		free(cfg.peer_id);
	}

	return ret;
}

static listener_return_t
parse_message_queue(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		    const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	msg_queue_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	// only need 1 irq
	cfg.defined_irq = read_interrupts_config(fdt, node_ofs, cfg.irqs, 1);

	bool is_sender	 = fdt_getprop_bool(fdt, node_ofs, "is-sender");
	bool is_receiver = fdt_getprop_bool(fdt, node_ofs, "is-receiver");

	if (is_sender == is_receiver) {
		ret = RET_ERROR;
		goto err_not_sender_xor_receiver;
	}

	cfg.is_sender = is_sender;

	if (!fdt_getprop_bool(fdt, node_ofs, "peer-default")) {
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

	cfg.msg_size	= (uint16_t)p.size;
	cfg.queue_depth = (uint16_t)p.depth;

	error_t push_err;
	vector_push_back_imm(msg_queue_data_t, vd->msg_queues, cfg, push_err);

	if (push_err != OK) {
		destroy_general_vdevice_props(&cfg.general);
		ret = RET_ERROR;
	}

err_parse_general:
err_not_peer_default:
err_not_sender_xor_receiver:
	return ret;
}

static listener_return_t
parse_message_queue_pair(vm_config_parser_data_t *vd, const void *fdt,
			 int node_ofs, const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	msg_queue_pair_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	if (fdt_getprop_bool(fdt, node_ofs, "peer-default")) {
		cfg.peer    = VMID_PEER_DEFAULT;
		cfg.peer_id = NULL;
	} else {
		const char *peer =
			fdt_stringlist_get(fdt, node_ofs, "peer", 0, NULL);
		if (peer != NULL) {
			cfg.peer_id = strdup(peer);
			if (cfg.peer_id == NULL) {
				(void)printf("Error: failed to save peer id\n");
				ret = RET_ERROR;
				goto err_not_peer;
			}
		} else {
			ret = RET_ERROR;
			goto err_not_peer;
		}
	}

	cfg.defined_irq = read_interrupts_config(fdt, node_ofs, cfg.irqs,
						 util_array_size(cfg.irqs));

	error_t parse_general_ret =
		parse_general_vdevice_props(&cfg.general, fdt, node_ofs, ctx);
	if (parse_general_ret != OK) {
		ret = RET_ERROR;
		goto err_parse_general;
	}

	msg_queue_param_t p = get_msg_queue_param(fdt, node_ofs);

	cfg.msg_size	= (uint16_t)p.size;
	cfg.queue_depth = (uint16_t)p.depth;

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
parse_memory_node(const void *fdt, int node_ofs, const ctx_t *ctx,
		  uint32_t *label, paddr_t *mem_base_ipa, bool *need_allocate,
		  bool *is_optional)
{
	listener_return_t ret = RET_CLAIMED;

	// Get memory sub node
	bool found_mem	  = false;
	int  sub_node_ofs = 0;
	int  cur_node_ofs = 0;
	int  len	  = 0;

	fdt_for_each_subnode (cur_node_ofs, fdt, node_ofs) {
		const char *node_name = fdt_get_name(fdt, cur_node_ofs, &len);
		if (strcmp(node_name, "memory") != 0) {
			(void)printf(
				"parse vdevice node: expected \"memory\" node\n");
			ret = RET_ERROR;
			goto err_unexpected;
		}

		if (found_mem) {
			(void)printf(
				"parse vdevice node: multiple \"memory\" nodes\n");
			ret = RET_ERROR;
			goto err_unexpected;
		}

		sub_node_ofs = cur_node_ofs;
		found_mem    = true;
	}

	if (!found_mem) {
		(void)printf("parse vdevice node: missing \"memory\" node\n");
		ret = RET_ERROR;
		goto err_unexpected;
	}

	ctx_t mem_ctx;
	dtb_parser_update_ctx(fdt, sub_node_ofs, ctx, &mem_ctx);

	warn_if_not_phys(fdt, sub_node_ofs, &mem_ctx);

	// mem_label
	if (parse_device_label(fdt, sub_node_ofs, label) != OK) {
		ret = RET_ERROR;
		goto err_no_label;
	}

	bool have_base = true;
	if (fdt_getprop_num(fdt, sub_node_ofs, "base", mem_ctx.addr_cells,
			    mem_base_ipa) != OK) {
		have_base     = false;
		*mem_base_ipa = 0U;
	}
	if (!util_is_baligned(*mem_base_ipa, PAGE_SIZE)) {
		(void)printf("parse vdevice node: base not aligned\n");
		ret = RET_ERROR;
		goto err_unexpected;
	}

	if (is_optional != NULL) {
		*is_optional = fdt_getprop_bool(fdt, sub_node_ofs, "optional");
	}

	// check if need allocate
	*need_allocate = false;

	if (fdt_getprop_bool(fdt, sub_node_ofs, "allocate-base")) {
		if (have_base) {
			(void)printf(
				"parse vdevice node: base and allocate-base both present\n");
			ret = RET_ERROR;
			goto err_unexpected;
		}
		*need_allocate = true;
		*mem_base_ipa  = 0UL;
	} else if (!have_base) {
		(void)printf(
			"parse vdevice node: neither base or allocate-base present\n");
		ret = RET_ERROR;
		goto err_unexpected;
	} else {
		// no allocation needed
	}

err_unexpected:
err_no_label:
	return ret;
}

static listener_return_t
parse_virtio_mmio(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		  const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	virtio_mmio_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	cfg.dma_coherent = fdt_getprop_bool(fdt, node_ofs, "dma-coherent");

	if (!fdt_getprop_bool(fdt, node_ofs, "peer-default")) {
		ret = RET_ERROR;
		goto err_not_peer_default;
	}

	cfg.peer = VMID_HLOS;

	if (fdt_getprop_u32(fdt, node_ofs, "vqs-num", &cfg.vqs_num) != OK) {
		cfg.vqs_num = DEFAULT_VIRTIO_VQS_NUM;
	}

	if (fdt_getprop_u64(fdt, node_ofs, "dma_base", &cfg.dma_base) != OK) {
		cfg.dma_base = 0U;
	}

	if (fdt_getprop_u32(fdt, node_ofs, "virtio,device-type",
			    &cfg.device_type) != OK) {
		cfg.device_type	      = VIRTIO_DEVICE_TYPE_INVALID;
		cfg.valid_device_type = false;
	} else {
		cfg.valid_device_type = true;
	}

	ret = parse_memory_node(fdt, node_ofs, ctx, &cfg.general.label,
				&cfg.mem_base_ipa, &cfg.need_allocate, NULL);
	if (ret != RET_CLAIMED) {
		destroy_general_vdevice_props(&cfg.general);
		goto err_parse_memory_node;
	}

	error_t parse_general_ret =
		parse_general_vdevice_props(&cfg.general, fdt, node_ofs, ctx);
	if (parse_general_ret != OK) {
		ret = RET_ERROR;
		goto err_parse_general;
	}

	error_t push_err;
	vector_push_back_imm(virtio_mmio_data_t, vd->virtio_mmios, cfg,
			     push_err);

	if (push_err != OK) {
		destroy_general_vdevice_props(&cfg.general);
		ret = RET_ERROR;
	}

err_not_peer_default:
err_parse_general:
err_parse_memory_node:
	return ret;
}

static listener_return_t
parse_shm_doorbell(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		   const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	shm_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	const char *vdevice_type =
		fdt_stringlist_get(fdt, node_ofs, "vdevice-type", 0, NULL);
	if (vdevice_type == NULL) {
		ret = RET_ERROR;
		goto err_no_vdevice_type;
	}

	cfg.is_plain_shm = (strcmp(vdevice_type, "shm") == 0);

	ret = parse_memory_node(fdt, node_ofs, ctx, &cfg.general.label,
				&cfg.mem_base_ipa, &cfg.need_allocate,
				&cfg.is_memory_optional);
	if (ret != RET_CLAIMED) {
		goto err_parse_memory_node;
	}

	if (!fdt_getprop_bool(fdt, node_ofs, "peer-default")) {
		ret = RET_ERROR;
		goto err_not_peer_default;
	}

	cfg.peer = VMID_PEER_DEFAULT;

	if (fdt_getprop_u64(fdt, node_ofs, "dma_base", &cfg.dma_base) != OK) {
		cfg.dma_base = (uint64_t)-1;
	}

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
err_no_vdevice_type:
	return ret;
}

static listener_return_t
parse_vcpus(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	    const ctx_t *ctx)
{
	(void)ctx;

	listener_return_t ret = RET_CLAIMED;

	int len = 0;

	// default is static
	vd->affinity = VM_CONFIG_AFFINITY_STATIC;
	// read affinity type
	const char *affinity =
		fdt_stringlist_get(fdt, node_ofs, "affinity", 0, NULL);
	if (affinity != NULL) {
		if (strcmp(affinity, "sticky") == 0) {
			vd->affinity = VM_CONFIG_AFFINITY_STICKY;
		} else if (strcmp(affinity, "pinned") == 0) {
			vd->affinity = VM_CONFIG_AFFINITY_PINNED;
		} else if (strcmp(affinity, "static") == 0) {
			vd->affinity = VM_CONFIG_AFFINITY_STATIC;
		} else if (strcmp(affinity, "proxy") == 0) {
			vd->affinity = VM_CONFIG_AFFINITY_PROXY;
		} else {
			(void)printf("parse_vcpus: unsupported \"affinity\"\n");
		}
	}

	if (vd->affinity != VM_CONFIG_AFFINITY_PROXY) {
		// read sched time slice
		if (fdt_getprop_u32(fdt, node_ofs, "sched-timeslice",
				    &vd->sched_time_slice) != OK) {
			// Use default scheduler timeslice; nothing to do here
		}

		// read sched priority
		if (fdt_getprop_s32(fdt, node_ofs, "sched-priority",
				    &vd->sched_priority) != OK) {
			// Use default scheduler priority; nothing to do here
		}

		// read affinity map
		const fdt32_t *affinity_map = (const fdt32_t *)fdt_getprop(
			fdt, node_ofs, "affinity-map", &len);
		if (affinity_map != NULL) {
			size_t sz = (size_t)len / sizeof(affinity_map[0]);

			vd->affinity_map_cnt = sz;

			vd->affinity_map = (cpu_index_t *)calloc(
				sizeof(affinity_map[0]), sz);

			if (vd->affinity_map == NULL) {
				ret = RET_ERROR;
				goto out;
			}

			index_t i = 0;
			while (i < sz) {
				vd->affinity_map[i] = (cpu_index_t)fdt32_to_cpu(
					affinity_map[i]);
				i++;
			}
		} else {
			(void)printf("parse_vcpus: \"affinity_map\" missing\n");
			ret = RET_ERROR;
			goto out;
		}
	}

	// read cpus number in device tree
	const char *config =
		fdt_stringlist_get(fdt, node_ofs, "config", 0, NULL);
	if (config == NULL) {
		config = "/cpus";
	}

	int config_ofs = fdt_path_offset(fdt, config);
	if (config_ofs < 0) {
		(void)printf("parse_vcpus: \"config\" path invalid\n");
		ret = RET_ERROR;
		goto out;
	}

	// Optional default method
	const char *default_enable_method =
		fdt_stringlist_get(fdt, config_ofs, "enable-method", 0, NULL);

	// create secondary vcpus only
	int sub_node_ofs = 0;

	count_t idle_state_count  = 0;
	count_t psci_enable_count = 0;
	count_t enabled_cpu_count = 0;

	fdt_for_each_subnode (sub_node_ofs, fdt, config_ofs) {
		const char *device_type = fdt_stringlist_get(
			fdt, sub_node_ofs, "device_type", 0, NULL);

		if ((device_type == NULL) ||
		    (strcmp(device_type, "cpu") != 0)) {
			continue;
		}

		// Check whether this CPU is enabled at boot time
		const char *status = fdt_stringlist_get(fdt, sub_node_ofs,
							"status", 0, NULL);
		bool	    is_boot_cpu;

		if (status == NULL) {
			// We assume that the first CPU we see with no status
			// property is enabled, and all others are disabled.
			//
			// This is to support single-core VMs, and also our
			// existing hand-coded and VMM-generated DTs for
			// multi-core-VMs, which have no status properties at
			// all (which violates the DT spec, but is accepted by
			// the Linux kernel).
			is_boot_cpu = (enabled_cpu_count == 0U);
		} else if (strcmp(status, "okay") == 0) {
			is_boot_cpu = true;
		} else if (strcmp(status, "disabled") == 0) {
			is_boot_cpu = false;
		} else if ((strcmp(status, "fail") == 0) ||
			   (strncmp(status, "fail-", 5) == 0)) {
			// Ignore failed VCPUs.
			continue;
		} else {
			(void)printf("parse_vcpus: unexpected status \"%s\"\n",
				     status);
			ret = RET_ERROR;
			goto out;
		}

		// Check if default enable-method is overriden
		const char *cpu_enable_method = fdt_stringlist_get(
			fdt, sub_node_ofs, "enable-method", 0, NULL);

		const char *enable_method = (cpu_enable_method != NULL)
						    ? cpu_enable_method
						    : default_enable_method;

		// Check if the cpu has idle states
		bool has_idle_states =
			fdt_getprop_bool(fdt, sub_node_ofs, "cpu-idle-states");
		if (has_idle_states) {
			idle_state_count++;
		}

		if (is_boot_cpu) {
			enabled_cpu_count++;
		} else if (enable_method == NULL) {
			(void)printf(
				"parse_vcpus: secondary VCPUs must set enable-method\n");
			ret = RET_ERROR;
			goto out;
		} else if (strcmp(enable_method, "psci") == 0) {
			psci_enable_count++;
		} else if (strcmp(enable_method, "qcom,gunyah-hvc") == 0) {
			// VCPU will be enabled by a standard Gunyah hypercall
			// using its cap ID; nothing more to do here
		} else {
			(void)printf(
				"parse_vcpus: unknown enable-method: \"%s\"\n",
				enable_method);
			ret = RET_ERROR;
			goto out;
		}

		char path[128];
		if (fdt_get_path(fdt, sub_node_ofs, path, (int)sizeof(path)) !=
		    0) {
			ret = RET_ERROR;
			goto out;
		}

		vcpu_data_t cfg = {
			.patch	   = strdup(path),
			.boot_vcpu = is_boot_cpu,
		};

		if (cfg.patch == NULL) {
			ret = RET_ERROR;
			goto out;
		}

		error_t push_err;
		vector_push_back_imm(vcpu_data_t, vd->vcpus, cfg, push_err);
		if (push_err != OK) {
			free(cfg.patch);
			ret = RET_ERROR;
			goto out;
		}
	}

	size_t cpu_count = vector_size(vd->vcpus);

	if (enabled_cpu_count == 0U) {
		(void)printf(
			"parse_vcpus: at least one vCPU must be enabled at VM boot\n");
		ret = RET_ERROR;
		goto out;
	}

	if ((vd->affinity != VM_CONFIG_AFFINITY_PROXY) &&
	    (cpu_count != vd->affinity_map_cnt)) {
		(void)printf(
			"parse_vcpus: cpu and affinity count don't match\n");
		ret = RET_ERROR;
		goto out;
	}

	if ((psci_enable_count != 0U) || (idle_state_count != 0U)) {
		vd->enable_vpm_psci = true;
	}

	if (vd->enable_vpm_psci && (vd->affinity != VM_CONFIG_AFFINITY_PROXY) &&
	    (idle_state_count != cpu_count)) {
		(void)printf(
			"parse_vcpus: PSCI enabled for non-proxy VM but not all CPUs have idle states\n");
		ret = RET_ERROR;
		goto out;
	}

out:
	return ret;
}

static listener_return_t
parse_vsmmuv2(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	      const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	(void)ctx;

	smmu_v2_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	if (fdt_getprop_u32(fdt, node_ofs, "smmu-handle", &cfg.smmu_handle) !=
	    OK) {
		(void)printf("Missing smmu-handle in vsmmu config\n");
		ret = RET_ERROR;
		goto out;
	}

	const char *patch = fdt_stringlist_get(fdt, node_ofs, "patch", 0, NULL);
	if (patch == NULL) {
		(void)printf("Missing patch in vsmmu config\n");
		ret = RET_ERROR;
		goto out;
	}

	cfg.patch = strdup(patch);
	if (cfg.patch == NULL) {
		(void)printf("Failed strdup patch in vsmmu config\n");
		ret = RET_ERROR;
		goto out;
	}

	if (fdt_getprop_u32(fdt, node_ofs, "num-cbs", &cfg.num_cbs) != OK) {
		(void)printf("Missing num-cbs in vsmmu config\n");
		ret = RET_ERROR;
		goto out;
	}
	if (cfg.num_cbs > 255U) {
		(void)printf("Invalid context banks count\n");
		ret = RET_ERROR;
		goto out;
	}

	if (fdt_getprop_u32(fdt, node_ofs, "num-smrs", &cfg.num_smrs) != OK) {
		(void)printf("Missing num-smrs in vsmmu config\n");
		ret = RET_ERROR;
		goto out;
	}
	if (cfg.num_smrs > 255U) {
		(void)printf("Invalid SMR count\n");
		ret = RET_ERROR;
		goto out;
	}

	error_t push_err;
	vector_push_back_imm(smmu_v2_data_t, vd->smmus, cfg, push_err);

	if (push_err != OK) {
		ret = RET_ERROR;
	}

out:
	if ((ret != RET_CLAIMED) && (cfg.patch != NULL)) {
		free(cfg.patch);
	}

	return ret;
}

static listener_return_t
parse_psci(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	   const ctx_t *ctx)
{
	(void)fdt;
	(void)node_ofs;
	(void)ctx;

	vd->enable_vpm_psci = true;

	return RET_CLAIMED;
}

static listener_return_t
parse_memory(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	     const ctx_t *ctx)
{
	(void)vd;
	(void)ctx;

	bool permitted = false;

	// This listener is called for nodes with device_type = "memory".
	//
	// The DT must not specify any such node other than /memory, which
	// will be replaced by the overlay. If any other memory node exists,
	// then at best the VM will crash, and at worst it might be vulnerable
	// to a VMM interfering with it by trapping and emulating memory.
	int	    len;
	const char *name = fdt_get_name(fdt, node_ofs, &len);
	if ((name != NULL) && (strcmp(name, "memory") == 0)) {
		// Calling fdt_parent_offset() is slow; do this last.
		if (fdt_parent_offset(fdt, node_ofs) == 0) {
			// This node is named /memory and will be replaced
			// by create_memory_node(). It's ok for it to exist.
			permitted = true;
		}
	}

	return permitted ? RET_CLAIMED : RET_ERROR;
}

static msg_queue_param_t
get_msg_queue_param(const void *fdt, int node_ofs)
{
	msg_queue_param_t ret = { 0 };

	if (fdt_getprop_u32(fdt, node_ofs, "message-size", &ret.size) != OK) {
		ret.size = DEFAULT_MSG_QUEUE_SIZE;
	}

	if (fdt_getprop_u32(fdt, node_ofs, "queue-depth", &ret.depth) != OK) {
		ret.depth = DEFAULT_MSG_QUEUE_DEPTH;
	}

	return ret;
}

dtb_parser_ops_t *
vm_config_parser_get_ops(void)
{
	return &vm_config_parser_ops;
}

vm_config_parser_params_t
vm_config_parser_get_params(const vm_t *vm)
{
	return (vm_config_parser_params_t){
		.auth_type = vm->auth_type,
	};
}

static void
alloc_parser_data_rollback(vm_config_parser_data_t *vd)
{
	if (vd->rtc != NULL) {
		vector_deinit(vd->rtc);
	}
	if (vd->vcpus != NULL) {
		vector_deinit(vd->vcpus);
	}
	if (vd->smmus != NULL) {
		vector_deinit(vd->smmus);
	}
	if (vd->iomems != NULL) {
		vector_deinit(vd->iomems);
	}
	if (vd->irq_ranges != NULL) {
		vector_deinit(vd->irq_ranges);
	}
	if (vd->iomem_ranges != NULL) {
		vector_deinit(vd->iomem_ranges);
	}
	if (vd->virtio_mmios != NULL) {
		vector_deinit(vd->virtio_mmios);
	}
	if (vd->shms != NULL) {
		vector_deinit(vd->shms);
	}
	if (vd->msg_queues != NULL) {
		vector_deinit(vd->msg_queues);
	}
	if (vd->msg_queue_pairs != NULL) {
		vector_deinit(vd->msg_queue_pairs);
	}
	if (vd->doorbells != NULL) {
		vector_deinit(vd->doorbells);
	}
	if (vd->rm_rpcs != NULL) {
		vector_deinit(vd->rm_rpcs);
	}
	if (vd->minidump != NULL) {
		vector_deinit(vd->minidump);
	}
	free(vd);
}

static vm_config_parser_data_t *
alloc_parser_data(const vm_config_parser_params_t *params)
{
	vm_config_parser_data_t *ret = calloc(1, sizeof(*ret));
	if (ret == NULL) {
		goto out;
	}

	ret->auth_type = params->auth_type;

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

	ret->virtio_mmios = vector_init(virtio_mmio_data_t, 1U, 1U);
	if (ret->virtio_mmios == NULL) {
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

	ret->smmus = vector_init(smmu_v2_data_t, 1U, 1U);
	if (ret->smmus == NULL) {
		goto err_out;
	}

	ret->vcpus = vector_init(vcpu_data_t, 1U, 1U);
	if (ret->vcpus == NULL) {
		goto err_out;
	}

	ret->rtc = vector_init(rtc_data_t, 1U, 1U);
	if (ret->rtc == NULL) {
		goto err_out;
	}

	ret->minidump = vector_init(minidump_data_t, 1U, 1U);
	if (ret->minidump == NULL) {
		goto err_out;
	}

	ret->platform_data = vector_init(platform_data_t, 1U, 1U);
	if (ret->platform_data == NULL) {
		goto err_out;
	}

	rm_error_t rm_err = platform_alloc_parser_data(ret);
	if (rm_err != RM_OK) {
		goto err_out;
	}

	ret->mem_base_ipa = PLATFORM_SVM_IPA_BASE;
	ret->mem_size_min = 0U;
	ret->mem_size_max = PLATFORM_SVM_IPA_SIZE;
	ret->fw_base_ipa  = INVALID_ADDRESS;
	ret->fw_size_max  = 0x400000U;

	goto out;

err_out:
	alloc_parser_data_rollback(ret);
	ret = NULL;
out:
	return ret;
}

static void
free_parser_data(vm_config_parser_data_t *vd)
{
	if (vd == NULL) {
		goto out;
	}

#define FREE_ALL(element_type, vector, cleanup)                                \
	do {                                                                   \
		size_t cnt = vector_size(vector);                              \
		for (index_t i = 0; i < cnt; ++i) {                            \
			element_type *d =                                      \
				vector_at_ptr(element_type, vector, i);        \
			destroy_general_vdevice_props(&d->general);            \
			cleanup                                                \
		}                                                              \
	} while (0)

#define FREE_GENERAL(element_type, vector) FREE_ALL(element_type, vector, )

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
		FREE_ALL(msg_queue_pair_data_t, vd->msg_queue_pairs,
			 { free(d->peer_id); });
		vector_deinit(vd->msg_queue_pairs);
	}

	if (vd->shms != NULL) {
		FREE_GENERAL(shm_data_t, vd->shms);
		vector_deinit(vd->shms);
	}

	if (vd->virtio_mmios != NULL) {
		FREE_GENERAL(virtio_mmio_data_t, vd->virtio_mmios);
		vector_deinit(vd->virtio_mmios);
	}

	if (vd->iomems != NULL) {
		FREE_ALL(iomem_data_t, vd->iomems, {
			free(d->patch_node_path);
			free(d->rm_sglist);
		});
		vector_deinit(vd->iomems);
	}

	if (vd->minidump != NULL) {
		FREE_GENERAL(minidump_data_t, vd->minidump);
		vector_deinit(vd->minidump);
	}

#undef FREE_GENERAL

	if (vd->iomem_ranges) {
		vector_deinit(vd->iomem_ranges);
	}

	if (vd->irq_ranges) {
		vector_deinit(vd->irq_ranges);
	}

	if (vd->smmus != NULL) {
		size_t cnt = vector_size(vd->smmus);
		for (index_t i = 0U; i < cnt; i++) {
			smmu_v2_data_t *d =
				vector_at_ptr(smmu_v2_data_t, vd->smmus, i);
			free(d->patch);
		}

		vector_deinit(vd->smmus);
	}

	if (vd->vcpus != NULL) {
		size_t cnt = vector_size(vd->vcpus);
		for (index_t i = 0U; i < cnt; i++) {
			vcpu_data_t *d =
				vector_at_ptr(vcpu_data_t, vd->vcpus, i);
			free(d->patch);
		}

		vector_deinit(vd->vcpus);
	}

	if (vd->rtc != NULL) {
		vector_deinit(vd->rtc);
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

	if (vd->kernel_entry_segment != NULL) {
		free(vd->kernel_entry_segment);
	}

	if (vd->vendor_name != NULL) {
		free(vd->vendor_name);
	}

	if (vd->affinity_map != NULL) {
		free(vd->affinity_map);
	}

	platform_free_parser_data(vd);

	free(vd);

out:
	return;
}

static bool
read_interrupts_config(const void *fdt, int node_ofs, interrupt_data_t *irqs,
		       count_t count)
{
	bool ret = false;
	int  len = 0;

	const fdt32_t *irq_data =
		(const fdt32_t *)fdt_getprop(fdt, node_ofs, "interrupts", &len);
	if (irq_data == NULL) {
		ret = false;
		goto out;
	}

	if ((uint32_t)len != (3U * sizeof(irq_data[0]) * count)) {
		ret = false;
		goto out;
	}

	index_t i   = 0;
	count_t cnt = count;

	interrupt_data_t *cur_irq = irqs;
	while (cnt > 0U) {
		virq_t offset = 0, limit = 0;

		ret = true;

		switch (fdt32_to_cpu(irq_data[i])) {
		case DT_GIC_SPI:
			cur_irq->is_cpu_local = false;
			offset		      = 32;
			limit		      = 1020;
			break;
		case DT_GIC_PPI:
			cur_irq->is_cpu_local = true;
			offset		      = 16;
			limit		      = 32;
			break;
		case DT_GIC_ESPI:
			cur_irq->is_cpu_local = false;
			offset		      = 4096;
			limit		      = 5120;
			break;
		case DT_GIC_EPPI:
			cur_irq->is_cpu_local = true;
			offset		      = 1056;
			limit		      = 1120;
			break;
		default:
			(void)printf("Ignoring invalid GIC IRQ class %d\n",
				     fdt32_to_cpu(irq_data[i]));
			ret = false;
			break;
		}
		if (!ret) {
			break;
		}
		++i;

		cur_irq->irq = (virq_t)fdt32_to_cpu(irq_data[i]) + offset;
		if (cur_irq->irq >= limit) {
			(void)printf("Ignoring invalid GIC IRQ number %d\n",
				     cur_irq->irq);
			ret = false;
			break;
		}
		++i;

		switch (fdt32_to_cpu(irq_data[i]) & 0xfU) {
		case DT_GIC_IRQ_TYPE_EDGE_RISING:
			cur_irq->is_edge_triggering = true;
			break;
		case DT_GIC_IRQ_TYPE_LEVEL_HIGH:
			cur_irq->is_edge_triggering = false;
			break;
		default:
			(void)printf(
				"Ignoring invalid GIC IRQ trigger mode %#x\n",
				fdt32_to_cpu(irq_data[i]) & 0xfU);
			ret = false;
			break;
		}
		if (!ret) {
			break;
		}
		++i;

		++cur_irq;
		--cnt;
	}
out:
	return ret;
}

static error_t
parse_irq_ranges(vm_config_parser_data_t *vd, const void *fdt, int node_ofs)
{
	error_t ret = OK;

	int len = 0;

	const fdt32_t *irqs = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "gic-irq-ranges", &len);
	if (irqs == NULL) {
		// skip irq range setup if there's no such property
		ret = OK;
		goto out;
	}

	size_t total_size = (size_t)len / sizeof(irqs[0]);

	index_t i = 0;
	while (((size_t)i + 2U) <= total_size) {
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

static listener_return_t
parse_iomem_opt(const void *fdt, int node_ofs, iomem_data_t *cfg)
{
	listener_return_t ret = RET_CLAIMED;

	int len = 0;

	// optional parse acl
	error_t err = fdt_getprop_u32_array(fdt, node_ofs, "qcom,rm_acl",
					    cfg->rm_acl, sizeof(cfg->rm_acl),
					    NULL);
	if (err == OK) {
		cfg->validate_acl = true;
	} else if (err == ERROR_ARGUMENT_INVALID) {
		cfg->validate_acl = false;
	} else {
		(void)printf("Error: failed to parse qcom,rm_acl for "
			     "iomem %d\n",
			     cfg->general.label);
		ret = RET_ERROR;
		goto out;
	}

	// optional parse attributes
	err = fdt_getprop_u32_array(fdt, node_ofs, "qcom,rm_attributes",
				    cfg->rm_attrs, sizeof(cfg->rm_attrs), NULL);
	if (err == OK) {
		cfg->validate_attrs = true;
	} else if (err == ERROR_ARGUMENT_INVALID) {
		cfg->validate_attrs = false;
	} else {
		(void)printf("Error: failed to parse qcom,rm_attributes for "
			     "iomem %d\n",
			     cfg->general.label);
		ret = RET_ERROR;
		goto out;
	}

	// optional sglist for validation
	const fdt32_t *sgl_entry = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "qcom,rm_sglist", &len);
	if (sgl_entry != NULL) {
		const count_t addr_cells  = 2U;
		const count_t size_cells  = 2U;
		const count_t entry_cells = addr_cells + size_cells;
		size_t	      entry_size  = entry_cells * sizeof(fdt32_t);

		if (((size_t)len % entry_size) != 0U) {
			(void)printf("Error: invalid qcom,rm_sglist value\n");
			ret = RET_ERROR;
			goto out;
		}

		size_t entries = (size_t)len / entry_size;

		cfg->rm_sglist = calloc(entries, sizeof(cfg->rm_sglist[0]));
		if (cfg->rm_sglist == NULL) {
			ret = RET_ERROR;
			goto out;
		}
		cfg->rm_sglist_len = entries;

		for (index_t i = 0; i < entries; i++) {
			cfg->rm_sglist[i].ipa = fdt_read_num(
				&sgl_entry[i * entry_cells], addr_cells);
			cfg->rm_sglist[i].size = fdt_read_num(
				&sgl_entry[(i * entry_cells) + addr_cells],
				size_cells);
		}
	}

out:
	return ret;
}

static listener_return_t
parse_iomem(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	    const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	int len = 0;

	iomem_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	error_t parse_general_ret =
		parse_general_vdevice_props(&cfg.general, fdt, node_ofs, ctx);
	if (parse_general_ret != OK) {
		ret = RET_ERROR;
		goto out;
	}

	const char *patch_node_path =
		fdt_stringlist_get(fdt, node_ofs, "patch", 0, NULL);
	if (patch_node_path != NULL) {
		cfg.patch_node_path = strdup(patch_node_path);
		if (cfg.patch_node_path == NULL) {
			ret = RET_ERROR;
			goto out;
		}
	}

	if (!fdt_getprop_bool(fdt, node_ofs, "peer-default")) {
		ret = RET_ERROR;
		goto out;
	}

	cfg.peer = VMID_HLOS;

	int  sub_node_ofs = 0;
	int  cur_node_ofs = 0;
	bool found_mem	  = false;

	// Get memory sub node
	fdt_for_each_subnode (cur_node_ofs, fdt, node_ofs) {
		const char *node_name = fdt_get_name(fdt, cur_node_ofs, &len);
		if (strncmp(node_name, "memory", (size_t)len) != 0) {
			continue;
		}

		if (found_mem) {
			(void)printf(
				"parse vdevice node: multiple \"memory\" nodes\n");
			ret = RET_ERROR;
			goto out;
		}

		sub_node_ofs = cur_node_ofs;
		found_mem    = true;
	}

	if (!found_mem) {
		(void)printf("parse vdevice node: Missing \"memory\" node\n");
		ret = RET_ERROR;
		goto out;
	}

	ctx_t mem_ctx;
	dtb_parser_update_ctx(fdt, sub_node_ofs, ctx, &mem_ctx);

	// mem_label
	if (parse_device_label(fdt, sub_node_ofs, &cfg.general.label) == OK) {
		cfg.label = cfg.general.label;
	} else {
		ret = RET_ERROR;
		goto out;
	}

	// mem-info-tag
	if (fdt_getprop_u32(fdt, sub_node_ofs, "qcom,mem-info-tag",
			    &cfg.mem_info_tag) == OK) {
		cfg.mem_info_tag_set = true;
	} else {
		cfg.mem_info_tag     = 0;
		cfg.mem_info_tag_set = false;
	}

	ret = parse_iomem_opt(fdt, node_ofs, &cfg);
	if (ret != RET_CLAIMED) {
		goto out;
	}

	// check if need allocate
	// FIXME: how to handle if need_allocate is false
	cfg.need_allocate =
		fdt_getprop_bool(fdt, sub_node_ofs, "allocate-base");

	error_t push_err;
	vector_push_back_imm(iomem_data_t, vd->iomems, cfg, push_err);

	if (push_err != OK) {
		destroy_general_vdevice_props(&cfg.general);
		ret = RET_ERROR;
	}
out:
	if (ret == RET_ERROR) {
		free(cfg.rm_sglist);
		free(cfg.patch_node_path);
		destroy_general_vdevice_props(&cfg.general);
	}

	return ret;
}
