// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <endian.h>
#include <inttypes.h>
#include <regex.h>
#include <stdio.h>

#include <rm_types.h>

#include "libfdt_env.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <util.h>
#include <utils/guid_parser.h>
#include <utils/vector.h>

#include <compiler.h>
#include <dt_linux.h>
#include <dt_overlay.h>
#include <dtb_parser.h>
#include <dtb_parser_listener.h>
#include <event.h>
#include <guest_interface.h>
#include <mem_region.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_dt_parser.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <uapi/mem.h>
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

#define PHANDLE_MISSING ~(uint32_t)0U

#define FREE_ALL(element_type, vector, general, cleanup)                       \
	do {                                                                   \
		size_t cnt = vector_size(vector);                              \
		for (index_t i = 0; i < cnt; ++i) {                            \
			element_type *d =                                      \
				vector_at_ptr(element_type, (vector), i);      \
			destroy_general_vdevice_props(&d->general);            \
			cleanup                                                \
		}                                                              \
	} while (0)

#define FREE_GENERAL(element_type, vector)                                     \
	FREE_ALL(element_type, (vector), general, )

static listener_return_t
parse_memory(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	     const ctx_t *ctx);

static listener_return_t
eval_skip_all_children(vm_config_parser_data_t *vd, const void *fdt,
		       int node_ofs, const ctx_t *ctx);

static listener_return_t
eval_skip_non_rm(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
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
parse_virtio_pci(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		 const ctx_t *ctx);

static listener_return_t
parse_virtio_iommu(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
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
parse_cpus(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	   const ctx_t *ctx);

static listener_return_t
parse_vsmmuv2(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	      const ctx_t *ctx);

static listener_return_t
parse_psci(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	   const ctx_t *ctx);

static listener_return_t
parse_pci(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	  const ctx_t *ctx);

static listener_return_t
parse_arm_timer(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		const ctx_t *ctx);

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
parse_vmmio_ranges(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		   const ctx_t *ctx);

static listener_return_t
parse_resmem(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	     const ctx_t *ctx);

static error_t
parse_irq_ranges(vm_config_parser_data_t *vd, const void *fdt, int node_ofs);

static listener_return_t
parse_interrupts(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		 const ctx_t *ctx);

static listener_return_t
parse_root(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	   const ctx_t *ctx);

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
		.action		  = &parse_memory,
		.safe		  = true,
	},
	// Skip all overlay fragments. These are not strictly part of the DT.
	// They may be present in QTVM image DTs when firmware is in use; in
	// this case, they will be applied to the VMM DT if relevant, and we
	// should parse their contents in that DT.
	{
		.type	       = BY_PATH,
		.expected_path = "/__overlay__$",
		.action	       = &eval_skip_all_children,
	},
	{
		.type	       = BY_PATH,
		.expected_path = "^/(qcom,|gunyah-)vm-config$",
		.action	       = &parse_vm_config,
	},
	{
		.type	       = BY_PATH,
		.expected_path = "^/(qcom,|gunyah-)vm-config/memory$",
		.action	       = &parse_vm_memory,
		.safe	       = true,
	},
	{
		.type	       = BY_PATH,
		.expected_path = "^/(qcom,|gunyah-)vm-config/vcpus$",
		.action	       = &parse_vcpus,
	},
	{
		.type	       = BY_PATH,
		.expected_path = "/cpus$",
		.action	       = &parse_cpus,
		.safe	       = true,
	},
	{
		.type	       = BY_PATH,
		.expected_path = "^/reserved-memory$",
		.action	       = &parse_resmem,
		.safe	       = true,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "rm-rpc",
		.action		  = &parse_rm_rpc,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "shm-doorbell",
		.action		  = &parse_shm_doorbell,
		.safe		  = true,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "shm",
		.action		  = &parse_shm_doorbell,
		.safe		  = true,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "doorbell-source",
		.action		  = &parse_doorbell_source,
		.safe		  = true,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "doorbell",
		.action		  = &parse_doorbell,
		.safe		  = true,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "message-queue",
		.action		  = &parse_message_queue,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "message-queue-pair",
		.action		  = &parse_message_queue_pair,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "virtio-mmio",
		.action		  = &parse_virtio_mmio,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "virtio-pci",
		.action		  = &parse_virtio_pci,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "iomem",
		.action		  = &parse_iomem,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "vsmmu-v2",
		.action		  = &parse_vsmmuv2,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "vrtc-pl031",
		.action		  = &parse_vrtc,
	},
	{
		.type		   = BY_COMPATIBLE,
		.compatible_string = "arm,psci-0.2",
		.action		   = &parse_psci,
		.safe		   = true,
	},
	{
		// Some existing VM DTs only declare support for 1.0, despite it
		// being backwards compatible with 0.2
		.type		   = BY_COMPATIBLE,
		.compatible_string = "arm,psci-1.0",
		.action		   = &parse_psci,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "pci",
		.action		  = &parse_pci,
	},
	{
		.type		  = BY_STRING_PROP,
		.string_prop_name = "vdevice-type",
		.expected_string  = "virtio-iommu",
		.action		  = &parse_virtio_iommu,
	},
	{
		.type		   = BY_COMPATIBLE,
		.compatible_string = "arm,armv8-timer",
		.action		   = &parse_arm_timer,
		.safe		   = true,
	},
	{
		.type	       = BY_PATH,
		.expected_path = "^/(qcom,|gunyah-)vm-config/interrupts$",
		.action	       = &parse_interrupts,
	},
	{
		.type	       = BY_PATH,
		.expected_path = "^/$",
		.action	       = &parse_root,
		.safe	       = true,
	},
	PLATFORM_LISTENERS
	// Skip the children of any other node that is not understood by RM.
	{
		.type	       = BY_PATH,
		.expected_path = "^/.",
		.action	       = &eval_skip_non_rm,
	},
};

static dtb_parser_ops_t vm_config_parser_ops = {
	.listeners = vm_config_listener,
	.listener_cnt =
		sizeof(vm_config_listener) / sizeof(vm_config_listener[0]),
};

static error_t
parse_device_label(const void *fdt, int node_ofs, uint32_t *label)
{
	if (fdt_getprop_u32(fdt, node_ofs, LABEL_ID, label) == OK) {
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
			(void)strlcpy(path, "<unknown path>", sizeof(path));
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
		(void)strlcpy(vd->vm_uri, vm_uri, VM_MAX_URI_LEN);
	}

	// Get VM-GUID and convert from string to byte array
	const char *vm_guid =
		fdt_stringlist_get(fdt, node_ofs, "vm-guid", 0, NULL);

	vd->has_guid = false;

	if (vm_guid != NULL) {
		error_t err = parse_guid_string(vm_guid, &vd->vm_guid);
		if (err != OK) {
			(void)printf("vm_info invalid guid\n");
			ret = RET_ERROR;
			goto out;
		}

		vd->has_guid = true;
	}

out:
	if (!vd->has_guid) {
		(void)memset(vd->vm_guid, 0, sizeof(vd->vm_guid));
	}
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
		(void)strlcpy(vd->vm_name, image_name, VM_MAX_NAME_LEN);
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
		} else if (strcmp(vm_attr, "bite-fatal") == 0) {
			vd->bite_fatal = true;
			// Bite-fatal implies the same things as crash-fatal.
			vd->no_shutdown = true;
			vd->no_reset	= true;
		} else if (strcmp(vm_attr, "context-dump") == 0) {
			vd->context_dump = true;
		} else if (strcmp(vm_attr, "no-shutdown") == 0) {
			vd->no_shutdown = true;
		} else if (strcmp(vm_attr, "no-reset") == 0) {
			vd->no_reset = true;
		} else if (strcmp(vm_attr, "allow-unprotected") == 0) {
			vd->allow_unprotected = true;
		} else if (strcmp(vm_attr, "crash-restart") == 0) {
			vd->crash_restart = true;
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
		else if (strcmp(vm_attr, "vpm-virq") == 0) {
			// get vpm virq status
			vd->enable_vpm_psci_virq = true;
		} else if (strcmp(vm_attr, "nosve") == 0) {
			vd->sve_not_allowed = true;
		} else if (strcmp(vm_attr, "sme") == 0) {
			vd->sme_allowed = true;
		} else if (strcmp(vm_attr, "no-vpm-aggregation") == 0) {
			vd->disable_vpm_aggregation = true;
		} else if (strcmp(vm_attr, "no-dtb-patch") == 0) {
			vd->no_dtb_patch = true;
		} else if (strcmp(vm_attr, "sdei") == 0) {
			vd->sdei_allowed = true;
		} else {
			(void)printf("Warning: Unknown VM attribute \"%s\"\n",
				     vm_attr);
		}
	}

out:
	return ret;
}

static listener_return_t
parse_peripheral_vms(vm_config_parser_data_t *vd, const void *fdt,
		     int32_t node_ofs)
{
	listener_return_t ret;
	int32_t		  len = 0;

	const fdt32_t *periph_vmids = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "qcom,peripheral-vmids", &len);
	if (periph_vmids == NULL) {
		ret = RET_CLAIMED;
		goto out;
	}

	count_t num_vmids = (count_t)len / (count_t)sizeof(periph_vmids[0]);
	if (num_vmids == 0U) {
		(void)printf("Error: empty peripheral vmids\n");
		ret = RET_ERROR;
		goto out;
	}

	for (index_t i = 0; i < num_vmids; i++) {
		uint64_t val = fdt_read_num(&periph_vmids[i], 1U);
		if (val >= 64U) {
			(void)printf("Error: invalid peripheral vmid %lu\n",
				     val);
			ret = RET_ERROR;
			goto out;
		}

		vmid_t vmid = (vmid_t)val;
		if (!vm_is_peripheral_vm(vmid)) {
			(void)printf("Error: VM %u is not a peripheral\n",
				     vmid);
			ret = RET_ERROR;
			goto out;
		}

		vd->allowed_periph_vmids |= util_bit(vmid);
	}

	ret = RET_CLAIMED;

out:
	return ret;
}

static error_t
parse_segments(vm_config_parser_data_t *vd, const void *fdt, int node_ofs)
{
	error_t ret = OK;

	int segments_ofs = fdt_subnode_offset(fdt, node_ofs, "segments");
	if (segments_ofs > 0) {
		(void)fdt_getprop_s32(fdt, segments_ofs, "ramdisk",
				      &vd->ramfs_idx);

		(void)fdt_getprop_s32(fdt, segments_ofs, "config_cpio",
				      &vd->cfgcpio_idx);

		(void)fdt_getprop_s32(fdt, segments_ofs, "fallback-dtb",
				      &vd->fallback_dt_idx);
	}

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

	error_t vmmio_ranges_ret = parse_vmmio_ranges(vd, fdt, node_ofs, ctx);
	if (vmmio_ranges_ret != OK) {
		(void)printf("Error: parse_vmmio_ranges failed: %d\n",
			     vmmio_ranges_ret);
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

	ret = parse_peripheral_vms(vd, fdt, node_ofs);
	if (ret != RET_CLAIMED) {
		goto out;
	}

	error_t segments_ret = parse_segments(vd, fdt, node_ofs);
	if (segments_ret != OK) {
		(void)printf("Error: parse_segments failed: %d\n", ret);
		ret = RET_ERROR;
		goto out;
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

	count_t num_words   = (count_t)len / (count_t)sizeof(iomems[0]);
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

static error_t
parse_vmmio_ranges(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		   const ctx_t *ctx)
{
	error_t ret = OK;

	int len = 0;

	const fdt32_t *vmmios = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "vmmio-ranges", &len);
	if (vmmios == NULL) {
		goto out;
	}
	vd->vmmio_ranges_set = true;

	count_t num_words   = (count_t)len / (count_t)sizeof(vmmios[0]);
	count_t range_words = ctx->addr_cells + ctx->size_cells;

	if ((range_words == 0U) || ((num_words % range_words) != 0U)) {
		(void)printf(
			"vmmio-ranges invalid length (%d words, should be multiple of %d)\n",
			num_words, range_words);
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	index_t i = 0;
	while (i < num_words) {
		mem_range_t r;

		r.base = fdt_read_num(&vmmios[i], ctx->addr_cells);
		i += ctx->addr_cells;

		r.size = fdt_read_num(&vmmios[i], ctx->size_cells);
		i += ctx->size_cells;

		ret = vector_push_back(vd->vmmio_ranges, r);
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
		if (!util_is_baligned(vd->mem_base_ipa, LARGE_PAGE_SIZE)) {
			(void)printf(
				"Warning: base-address not 2MB aligned, aligning up\n");
			vd->mem_base_ipa = util_balign_up(vd->mem_base_ipa,
							  LARGE_PAGE_SIZE);
		}
		// Default value of the maximum size is the whole address space
		// above the configured base address
		vd->mem_size_max = 0U - (size_t)vd->mem_base_ipa;
		vd->mem_base_set = true;
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
		vd->fw_base_set = true;
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
	cfg.defined_irq = read_interrupts_config(
				  fdt, node_ofs, "interrupts", cfg.irqs,
				  (count_t)util_array_size(cfg.irqs)) == OK;

	error_t general_parse_ret =
		parse_general_vdevice_props(&cfg.general, fdt, node_ofs, ctx);
	if (general_parse_ret != OK) {
		ret = RET_ERROR;
		goto out;
	}

	// add three more additional push_compatibles
	index_t cnt = cfg.general.push_compatible_num;
	if ((cnt + 3U) > VDEVICE_MAX_PUSH_COMPATIBLES) {
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

	int32_t snprintf_ret = snprintf(cp, VDEVICE_MAX_COMPATIBLE_LEN,
					"qcom,resource-manager-%s",
					gunyah_api_version);
	if ((snprintf_ret < 0) ||
	    (snprintf_ret >= (int32_t)VDEVICE_MAX_COMPATIBLE_LEN)) {
		ret = RET_ERROR;
		goto out_free;
	}

	cfg.general.push_compatible_num += 3U;

	msg_queue_param_t p = get_msg_queue_param(fdt, node_ofs);

	// FIXME: find correct way to get IRQ allocated if needed

	cfg.msg_size	= (uint16_t)p.size;
	cfg.queue_depth = (uint16_t)p.depth;

	const char *console_owner =
		fdt_stringlist_get(fdt, node_ofs, "console-owner", 0, NULL);
	if (console_owner != NULL) {
		cfg.console_owner = strdup(console_owner);
		if (cfg.console_owner == NULL) {
			ret = RET_ERROR;
			goto out_free;
		}
	}

	error_t push_err;
	vector_push_back_imm(rm_rpc_data_t, vd->rm_rpcs, cfg, push_err);

	if (push_err != OK) {
		ret = RET_ERROR;
		goto out_free;
	}

out_free:
	if (ret == RET_ERROR) {
		destroy_general_vdevice_props(&cfg.general);
		free(cfg.console_owner);
	}

out:
	return ret;
}

static void
destroy_general_vdevice_props(general_data_t *cfg)
{
	char *cp;

	for (index_t i = 0; i < VDEVICE_MAX_PUSH_COMPATIBLES; i++) {
		cp = cfg->push_compatible[i];
		if (cp != NULL) {
			free(cp);
			cfg->push_compatible[i] = NULL;
		}
	}

	cfg->push_compatible_num = 0U;

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

	if (fdt_getprop_bool(fdt, node_ofs, "peer-default")) {
		cfg.peer    = VMID_PEER_DEFAULT;
		cfg.peer_id = NULL;

		cfg.defined_irq = read_interrupts_config(fdt, node_ofs,
							 "peer-interrupts",
							 &cfg.irq, 1) == OK;
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
			cfg.defined_irq =
				read_interrupts_config(fdt, node_ofs,
						       "peer-interrupts",
						       &cfg.irq, 1) == OK;
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

	cfg.defined_irq = read_interrupts_config(fdt, node_ofs, "interrupts",
						 &cfg.irq, 1) == OK;
	if (!cfg.defined_irq) {
		cfg.defined_irq = read_sdei_event_interrupt_config(
			fdt, node_ofs, &cfg.irq);
	}

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
	cfg.defined_irq = read_interrupts_config(fdt, node_ofs, "interrupts",
						 cfg.irqs, 1) == OK;

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

	cfg.defined_irq = read_interrupts_config(
				  fdt, node_ofs, "interrupts", cfg.irqs,
				  (count_t)util_array_size(cfg.irqs)) == OK;

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
parse_memory_node(const void *fdt, int sub_node_ofs, const ctx_t *ctx,
		  uint32_t *label, paddr_t *mem_base_ipa, bool *need_allocate,
		  bool *is_optional)
{
	listener_return_t ret = RET_CLAIMED;

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

static error_t
parse_virtio_common(virtio_common_data_t *cfg, const void *fdt, int node_ofs,
		    const ctx_t *ctx)
{
	error_t ret;

	(void)ctx;

	if (!fdt_getprop_bool(fdt, node_ofs, "peer-default")) {
		ret = ERROR_ARGUMENT_INVALID;
		goto err_not_peer_default;
	}
	cfg->peer = VMID_PEER_DEFAULT;

	cfg->sync_reset = fdt_getprop_bool(fdt, node_ofs, "sync-reset");

	if (fdt_getprop_u32(fdt, node_ofs, "vqs-num", &cfg->vqs_num) != OK) {
		cfg->vqs_num = DEFAULT_VIRTIO_VQS_NUM;
	}

	if (fdt_getprop_u32(fdt, node_ofs, "virtio,device-type",
			    &cfg->device_type) != OK) {
		cfg->device_type = VIRTIO_DEVICE_TYPE_INVALID;
	}

	error_t err =
		parse_general_vdevice_props(&cfg->general, fdt, node_ofs, ctx);
	if (err != OK) {
		ret = err;
		goto err_parse_general;
	}

	const char *patch = fdt_stringlist_get(fdt, node_ofs, "patch", 0, NULL);
	if (patch != NULL) {
		if (cfg->general.generate != NULL) {
			ret = ERROR_NOMEM;
			goto err_parse_patch;
		}

		cfg->patch = strdup(patch);
		if (cfg->patch == NULL) {
			ret = ERROR_NOMEM;
			goto err_parse_patch;
		}
	}

	ret = OK;

err_parse_patch:
err_parse_general:
	if (ret != OK) {
		destroy_general_vdevice_props(&cfg->general);
	}
err_not_peer_default:
	return ret;
}

static void
destroy_virtio_common_props(virtio_common_data_t *cfg)
{
	if (cfg->patch != NULL) {
		free(cfg->patch);
	}
	destroy_general_vdevice_props(&cfg->general);
}

static listener_return_t
parse_virtio_mmio(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		  const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	virtio_mmio_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	error_t parse_common_ret =
		parse_virtio_common(&cfg.common, fdt, node_ofs, ctx);
	if (parse_common_ret != OK) {
		ret = RET_ERROR;
		goto err_parse_common;
	}

	cfg.dma_coherent = fdt_getprop_bool(fdt, node_ofs, "dma-coherent");

	if (fdt_getprop_u64(fdt, node_ofs, "dma_base", &cfg.dma_base) != OK) {
		cfg.dma_base = 0U;
	}

	if (fdt_getprop_u32(fdt, node_ofs, "virtio,device-type",
			    &cfg.common.device_type) != OK) {
		cfg.common.device_type = VIRTIO_DEVICE_TYPE_INVALID;
	}

	int sub_node_ofs = 0;
	fdt_for_each_subnode (sub_node_ofs, fdt, node_ofs) {
		int	    len	      = 0;
		const char *node_name = fdt_get_name(fdt, sub_node_ofs, &len);
		if (strcmp(node_name, "memory") == 0) {
			ret = parse_memory_node(fdt, sub_node_ofs, ctx,
						&cfg.common.general.label,
						&cfg.dma_base_ipa,
						&cfg.need_allocate, NULL);
			if (ret != RET_CLAIMED) {
				goto err_parse_memory_node;
			}
			cfg.have_shm = true;
			break;
		}
	}

	error_t push_err;
	vector_push_back_imm(virtio_mmio_data_t, vd->virtio_mmios, cfg,
			     push_err);
	if (push_err != OK) {
		ret = RET_ERROR;
	}

err_parse_memory_node:
err_parse_common:
	if (ret != RET_CLAIMED) {
		destroy_virtio_common_props(&cfg.common);
	}
	return ret;
}

static listener_return_t
parse_virtio_pci(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		 const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;

	virtio_pci_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	error_t parse_common_ret =
		parse_virtio_common(&cfg.common, fdt, node_ofs, ctx);
	if (parse_common_ret != OK) {
		ret = RET_ERROR;
		goto err_parse_common;
	}

	if (fdt_getprop_u32(fdt, node_ofs, "pci-bus", &cfg.pci_bus_phandle) !=
	    OK) {
		cfg.pci_bus_phandle = PHANDLE_MISSING;
	}

	if (fdt_getprop_u32(fdt, node_ofs, "pci-slot-index",
			    &cfg.pci_slot_index) != OK) {
		cfg.pci_slot_index = ~(index_t)0U;
	}

	// Per-queue backend IRQs are enabled by default for PCIE, but old
	// backends might not support the updated notify hypercall; provide a
	// flag to disable it.
	cfg.per_queue_irqs =
		!fdt_getprop_bool(fdt, node_ofs, "disable-per-queue-irqs");

	error_t push_err;
	vector_push_back_imm(virtio_pci_data_t, vd->virtio_pcis, cfg, push_err);
	if (push_err != OK) {
		ret = RET_ERROR;
	}

err_parse_common:
	if (ret != RET_CLAIMED) {
		destroy_virtio_common_props(&cfg.common);
	}
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

	int  sub_node_ofs      = 0;
	bool found_memory_node = false;
	fdt_for_each_subnode (sub_node_ofs, fdt, node_ofs) {
		int	    len	      = 0;
		const char *node_name = fdt_get_name(fdt, sub_node_ofs, &len);
		if (strcmp(node_name, "memory") == 0) {
			ret = parse_memory_node(fdt, sub_node_ofs, ctx,
						&cfg.general.label,
						&cfg.mem_base_ipa,
						&cfg.need_allocate,
						&cfg.is_memory_optional);
			if (ret != RET_CLAIMED) {
				goto err_parse_memory_node;
			}
			found_memory_node = true;
			break;
		}
	}
	if (!found_memory_node) {
		(void)printf("parse shm vdevice: missing \"memory\" node\n");
		ret = RET_ERROR;
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
parse_cpus(vm_config_parser_data_t *vd, const void *fdt, int32_t node_ofs,
	   const ctx_t *ctx)
{
	(void)ctx;
	listener_return_t ret = RET_CLAIMED;

	const char *default_enable_method =
		fdt_stringlist_get(fdt, node_ofs, "enable-method", 0, NULL);

	if ((ctx->child_size_cells != 0U) || (ctx->child_addr_cells == 0U) ||
	    ctx->child_addr_is_phys) {
		ret = RET_ERROR;
		goto out;
	}

	// create secondary vcpus only
	int sub_node_ofs = 0;

	count_t vcpu_count	  = 0;
	count_t idle_state_count  = 0;
	count_t psci_enable_count = 0;
	count_t enabled_cpu_count = 0;

	// Determine the sufficient set of bits to represent all addresses
	vd->vcpu_addr_mask = 0U;

	fdt_for_each_subnode (sub_node_ofs, fdt, node_ofs) {
		const char *device_type = fdt_stringlist_get(
			fdt, sub_node_ofs, "device_type", 0, NULL);

		if ((device_type == NULL) ||
		    (strcmp(device_type, "cpu") != 0)) {
			continue;
		}

		// Read the physical CPU address
		uint64_t address;
		if (fdt_getprop_num(fdt, sub_node_ofs, "reg",
				    ctx->child_addr_cells, &address) != OK) {
			(void)printf("cpu reg property invalid\n");
			ret = RET_ERROR;
			goto out;
		}
		vd->vcpu_addr_mask |= address;

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

		// Check if default enable-method is overridden
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
			.address   = address,
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
		vcpu_count++;
	}

	if ((psci_enable_count != 0U) || (idle_state_count != 0U)) {
		vd->enable_vpm_psci = true;
	}

	vd->enabled_cpu_count = enabled_cpu_count;
	vd->idle_state_count  = idle_state_count;
	vd->psci_enable_count = psci_enable_count;

	// 8-bit affinity level field offsets matching MPIDR_EL1, as specified
	// by the Linux kernel's arm64 cpus DT binding.
	const count_t aff_shifts[4U] = { 0U, 8U, 16U, 32U };

	(void)printf("parse_cpus: address mask %#zx\n", vd->vcpu_addr_mask);
	count_t next_addr_bit = 0U;
	for (index_t i = 0U; i < util_array_size(vd->vcpu_addr_shifts); i++) {
		count_t	 aff_shift = aff_shifts[i];
		uint64_t aff_mask  = (vd->vcpu_addr_mask >> aff_shift) &
				    util_mask(8U);
		if (aff_mask == 0U) {
			// No significant bits in this affinity field
			vd->vcpu_addr_shifts[i] = next_addr_bit;
			continue;
		}

		// Try to strip off low bits that are always zero.
		count_t field_shift = compiler_ctz(aff_mask);

		// We can't have a negative shift, so if stripping low bits
		// would leave us with one, we must artificially add bits to
		// the mask to make it 0.
		if (field_shift > next_addr_bit) {
			vd->vcpu_addr_mask |= (util_mask(field_shift) -
					       util_mask(next_addr_bit))
					      << aff_shift;
			field_shift = next_addr_bit;
		}

		// Calculate the final shift.
		vd->vcpu_addr_shifts[i] = next_addr_bit - field_shift;
		next_addr_bit += compiler_msb(aff_mask) + 1U - field_shift;
	}
	(void)printf(
		"parse_cpus: shifts %d/%d/%d/%d, used %d bits, mask now %#zx\n",
		vd->vcpu_addr_shifts[0], vd->vcpu_addr_shifts[1],
		vd->vcpu_addr_shifts[2], vd->vcpu_addr_shifts[3], next_addr_bit,
		vd->vcpu_addr_mask);

	// Ensure that we can fit a bitmap of used CPUs in a uint64_t
	if (util_bit(next_addr_bit) >
	    (sizeof(vd->vcpu_used_indices) * (size_t)CHAR_BIT)) {
		(void)printf(
			"error: cpus have too many significant address bits\n");
		ret = RET_ERROR;
		goto out;
	}

	vd->vcpu_used_indices = 0U;
	for (index_t i = 0U; i < vcpu_count; i++) {
		vcpu_data_t *vcpu   = vector_at_ptr(vcpu_data_t, vd->vcpus, i);
		vcpu->address_index = 0U;
		for (index_t j = 0U; j < util_array_size(vd->vcpu_addr_shifts);
		     j++) {
			count_t	 aff_shift = aff_shifts[j];
			uint64_t aff_field = (vcpu->address >> aff_shift) &
					     util_mask(8U);
			vcpu->address_index |=
				((index_t)aff_field << vd->vcpu_addr_shifts[j]);
		}

		assert(vcpu->address_index < 64U);
		if ((vd->vcpu_used_indices & util_bit(vcpu->address_index)) !=
		    0U) {
			(void)printf("error: /cpus: duplicate index %d "
				     "for address %#zx\n",
				     vcpu->address_index, vcpu->address);
			ret = RET_ERROR;
			goto out;
		}
		vd->vcpu_used_indices |= util_bit(vcpu->address_index);

		(void)printf("parse_cpus: vcpu %d: address %#zx index %d\n", i,
			     vcpu->address, vcpu->address_index);
	}
	(void)printf("parse_cpus: used index mask %#zx\n",
		     vd->vcpu_used_indices);

out:
	return ret;
}

static listener_return_t
parse_vcpus(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	    const ctx_t *ctx)
{
	(void)ctx;

	listener_return_t ret;

	int len = 0;

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
	ret = RET_CLAIMED;

	const char *config =
		fdt_stringlist_get(fdt, node_ofs, "config", 0, NULL);
	if ((config != NULL) && (strcmp(config, "/cpus") != 0)) {
		(void)printf(
			"warning: parse_vcpus: ignoring \"config\" property");
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
parse_virtio_iommu(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		   const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;
	(void)ctx;

	virtio_iommu_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	// The base address of the target HW SMMU
	if (fdt_getprop_u64(fdt, node_ofs, "smmu-handle", &cfg.smmu_handle) !=
	    OK) {
		(void)printf("Missing smmu-handle in virtio-iommu config\n");
		ret = RET_ERROR;
		goto out;
	}

	if (fdt_getprop_u32(fdt, node_ofs, "max-streams", &cfg.max_streams) !=
	    OK) {
		(void)printf("Missing max-steams in virtio-iommu config\n");
		ret = RET_ERROR;
		goto out;
	}

	if (fdt_getprop_u32(fdt, node_ofs, "pci-slot-index",
			    &cfg.pci_slot_index) != OK) {
		(void)printf("Missing pci-slot-index in virtio-iommu config\n");
		ret = RET_ERROR;
		goto out;
	}

	error_t push_err;
	vector_push_back_imm(virtio_iommu_data_t, vd->virtio_iommus, cfg,
			     push_err);

	if (push_err != OK) {
		ret = RET_ERROR;
	}

out:
	return ret;
}

static error_t
parse_pci_addrs(const void *fdt, int node_ofs, const ctx_t *ctx,
		pci_data_t *cfg)
{
	error_t ret;

	if (fdt_getprop_num(fdt, node_ofs, "config-base-address",
			    ctx->addr_cells, &cfg->config_base_ipa) == OK) {
		if (!util_is_baligned(cfg->config_base_ipa, PAGE_SIZE)) {
			(void)printf("base-address invalid alignment\n");
			ret = ERROR_ARGUMENT_ALIGNMENT;
			goto out;
		}
	} else {
		cfg->config_base_ipa = ~(vmaddr_t)0U;
	}

	// The size of the ECAM region is required to be 1MiB per bus for
	// between 2 and 256 buses; virtual PCI does not need or implement
	// bridges, so the minimum size of 2MiB is always sufficient.
	cfg->config_bits = 21U;
	size_t config_size_val;
	if (fdt_getprop_num(fdt, node_ofs, "config-size", ctx->addr_cells,
			    &config_size_val) == OK) {
		if (util_bit(cfg->config_bits) > config_size_val) {
			(void)printf(
				"specified config-size is less than 2MiB\n");
			ret = ERROR_ARGUMENT_SIZE;
			goto out;
		}
	}

	if (fdt_getprop_num(fdt, node_ofs, "npmem-base-address",
			    ctx->addr_cells, &cfg->npmem_base_ipa) == OK) {
		if (!util_is_baligned(cfg->npmem_base_ipa, PAGE_SIZE)) {
			(void)printf("base-address invalid alignment\n");
			ret = ERROR_ARGUMENT_ALIGNMENT;
			goto out;
		}
	} else {
		cfg->npmem_base_ipa = ~(vmaddr_t)0U;
	}

	size_t npmem_size_val;
	if (fdt_getprop_num(fdt, node_ofs, "npmem-size", ctx->addr_cells,
			    &npmem_size_val) == OK) {
		if (!util_is_p2(npmem_size_val)) {
			(void)printf("npmem-size must be a power of two\n");
			ret = ERROR_ARGUMENT_SIZE;
			goto out;
		}
		cfg->npmem_bits = (count_t)compiler_msb(npmem_size_val);
	} else {
		// npmem-size is mandatory
		(void)printf("npmem-size must be specified for pci vdevices\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	ret = OK;
out:
	return ret;
}

static listener_return_t
parse_pci(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	  const ctx_t *ctx)
{
	listener_return_t ret;

	pci_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	error_t err = parse_pci_addrs(fdt, node_ofs, ctx, &cfg);
	if (err != OK) {
		ret = RET_ERROR;
		goto out;
	}

	uint64_t msi_parent_phandle;
	if (fdt_getprop_num(fdt, node_ofs, "msi-parent", 1U,
			    &msi_parent_phandle) == OK) {
		cfg.msi_parent_phandle = (uint32_t)msi_parent_phandle;
		uint64_t msi_passthrough_base;
		if (fdt_getprop_num(fdt, node_ofs, "msi-passthrough-base", 1U,
				    &msi_passthrough_base) == OK) {
			uint64_t msi_passthrough_length;
			if (fdt_getprop_num(fdt, node_ofs,
					    "msi-passthrough-length", 1U,
					    &msi_passthrough_length) != OK) {
				// By default, reserve virtual device IDs for
				// all valid RIDs
				msi_passthrough_length = 0x10000U;
			}
			cfg.msi_passthrough = true;
			cfg.msi_passthrough_base =
				(uint32_t)msi_passthrough_base;
			cfg.msi_passthrough_length =
				(uint32_t)msi_passthrough_length;
		} else {
			cfg.msi_vdevices = true;
		}
	} else {
		cfg.msi_parent_phandle = DTO_PHANDLE_UNSET;
	}

	uint64_t irq_parent_phandle;
	if (fdt_getprop_num(fdt, node_ofs, "interrupt-parent", 1U,
			    &irq_parent_phandle) == OK) {
		cfg.irq_parent_phandle = (uint32_t)irq_parent_phandle;
		cfg.irq_vdevices       = true;
	} else {
		cfg.irq_parent_phandle = DTO_PHANDLE_UNSET;
		cfg.irq_vdevices = !cfg.msi_vdevices && !cfg.msi_passthrough;
	}

	cfg.dma_coherent = fdt_getprop_bool(fdt, node_ofs, "dma-coherent");

	int sub_node_ofs = 0;
	fdt_for_each_subnode (sub_node_ofs, fdt, node_ofs) {
		int	    len	      = 0;
		const char *node_name = fdt_get_name(fdt, sub_node_ofs, &len);
		if (strcmp(node_name, "memory") == 0) {
			ret = parse_memory_node(fdt, sub_node_ofs, ctx,
						&cfg.general.label,
						&cfg.dma_base_ipa,
						&cfg.need_allocate, NULL);
			if (ret != RET_CLAIMED) {
				goto err_parse_memory_node;
			}
			cfg.have_memory_region = true;
			break;
		}
	}

	if (fdt_getprop_u32(fdt, node_ofs, "config", &cfg.bus_phandle) != OK) {
		if (vd->have_default_pci_bus) {
			(void)printf(
				"error: Multiple vpci buses without phandles\n");
			ret = RET_ERROR;
			goto out;
		}
		vd->have_default_pci_bus = true;
		cfg.bus_phandle		 = PHANDLE_MISSING;
	}

	if (fdt_getprop_u32(fdt, node_ofs, "linux,pci-domain",
			    &cfg.linux_pci_domain) != OK) {
		cfg.linux_pci_domain = ~(uint32_t)0U;
	}

	error_t parse_general_ret =
		parse_general_vdevice_props(&cfg.general, fdt, node_ofs, ctx);
	if (parse_general_ret != OK) {
		ret = RET_ERROR;
		goto err_parse_general;
	}

	const char *patch = fdt_stringlist_get(fdt, node_ofs, "patch", 0, NULL);
	if (patch != NULL) {
		if (cfg.general.generate != NULL) {
			(void)printf(
				"error: patch and generate are mutually exclusive\n");
			ret = RET_ERROR;
			goto err_parse_patch;
		}

		cfg.patch = strdup(patch);
		if (cfg.patch == NULL) {
			ret = RET_ERROR;
			goto err_parse_patch;
		}
	}

	error_t push_err;
	vector_push_back_imm(pci_data_t, vd->pci_buses, cfg, push_err);

	if (push_err != OK) {
		ret = RET_ERROR;
	} else {
		ret = RET_CLAIMED;
	}

err_parse_patch:
err_parse_general:
	if (ret == RET_ERROR) {
		destroy_general_vdevice_props(&cfg.general);
	}
err_parse_memory_node:
out:
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
parse_arm_timer(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		const ctx_t *ctx)
{
	(void)ctx;

	// ARM generic timer has 4 interrupts:
	// Index 0: secure phys timer
	// Index 1: el1 phys timer
	// Index 2: el1 virtual timer
	// Index 3: el2 phys timer
	interrupt_data_t irqs[4];
	(void)memset(irqs, 0, sizeof(irqs));

	error_t ret = read_interrupts_config(fdt, node_ofs, "interrupts", irqs,
					     (count_t)util_array_size(irqs));
	if (ret == OK) {
		vd->el1_phys_timer_irq = irqs[1].irq;
		vd->el1_virt_timer_irq = irqs[2].irq;
		(void)printf(
			"ARM Timer: el1_phys_timer IRQ = %u el1_virt_timer IRQ = %u\n",
			vd->el1_phys_timer_irq, vd->el1_virt_timer_irq);
	} else {
		(void)printf("ARM Timer: Failed to read interrupts\n");
	}

	return RET_CLAIMED;
}

static listener_return_t
eval_skip_all_children(vm_config_parser_data_t *vd, const void *fdt,
		       int node_ofs, const ctx_t *ctx)
{
	(void)vd;
	(void)fdt;
	(void)node_ofs;
	(void)ctx;
	return RET_SKIP_CHILD_NODES;
}

static listener_return_t
eval_skip_non_rm(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		 const ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;
	(void)vd;

	if (strcmp(ctx->node_path, "/firmware") == 0) {
		goto out;
	}

	if (fdt_getprop(fdt, node_ofs, "ranges", NULL) != NULL) {
		goto out;
	}

	if (strstr(ctx->node_path, "vm-config") != NULL) {
		goto out;
	}

	ret = RET_SKIP_CHILD_NODES;
out:
	return ret;
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

static listener_return_t
parse_resmem(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	     const ctx_t *ctx)
{
	listener_return_t ret;

	int32_t region_node_ofs;

	if (!ctx->child_addr_is_phys) {
		(void)printf(
			"Error: addresses in /reserved-memory are not 1:1 physical!");
		ret = RET_ERROR;
		goto out;
	}

	fdt_for_each_subnode (region_node_ofs, fdt, node_ofs) {
		const char *name = fdt_get_name(fdt, region_node_ofs, NULL);
		assert(name != NULL);

		resmem_range_data_t data = { 0 };

		int	       reg_len;
		const fdt32_t *reg =
			fdt_getprop(fdt, region_node_ofs, "reg", &reg_len);

		uint32_t target_vmid;
		if (fdt_getprop_u32(fdt, region_node_ofs, "qcom,target-vmid",
				    &target_vmid) == OK) {
			if (!fdt_getprop_bool(fdt, region_node_ofs, "no-map")) {
				(void)printf(
					"error: /reserved-memory/%s: "
					"external memory must be marked no-map\n",
					name);
				ret = RET_ERROR;
				goto out;
			}
			if (target_vmid >=
			    (sizeof(vd->used_periph_vmids) * 8U)) {
				(void)printf(
					"error: /reserved-memory/%s: "
					"qcom,target-vmid out of range: %d\n",
					name, target_vmid);
				ret = RET_ERROR;
				goto out;
			}
			vd->used_periph_vmids |=
				(uint64_t)util_bit(target_vmid);
			continue;
		}

		if (reg == NULL) {
			// This isn't a fixed address allocation, so it won't
			// influence the VM creation and we can leave it alone
			// until DTBO generation.
			continue;
		}

		data.label_valid =
			(fdt_getprop_u32(fdt, region_node_ofs, "qcom,label",
					 &data.label) == OK);
		data.is_reusable =
			fdt_getprop_bool(fdt, region_node_ofs, "reusable");

		assert(reg_len >= 0);

		count_t cells = ctx->child_addr_cells + ctx->child_size_cells;
		size_t	expected_len = sizeof(fdt32_t) * cells;
		if ((size_t)reg_len != expected_len) {
			// TODO: Support multiple-range reserved memory nodes
			(void)printf(
				"Bad \"reg\" in /reserved-memory/%s; len %zd != %zd\n",
				name, (size_t)reg_len, expected_len);
			ret = RET_ERROR;
			goto out;
		}

		// Reg property is valid. Parse the address and size.
		data.ipa_base =
			(vmaddr_t)fdt_read_num(&reg[0], ctx->child_addr_cells);
		data.size = (size_t)fdt_read_num(&reg[ctx->child_addr_cells],
						 ctx->child_size_cells);
		if ((data.size == 0U) ||
		    util_add_overflows(data.ipa_base, data.size - 1U)) {
			(void)printf(
				"Bad \"reg\" in /reserved-memory/%s; size %#zx\n",
				name, data.size);
			ret = RET_ERROR;
			goto out;
		}

		(void)printf(
			"/reserved-memory/%s: addr %#zx, size %#zx, label %#x\n",
			fdt_get_name(fdt, region_node_ofs, NULL), data.ipa_base,
			data.size, data.label);

		error_t push_err =
			vector_push_back(vd->resmem_fixed_ranges, data);
		if (push_err != OK) {
			ret = RET_ERROR;
			goto out;
		}
	}

	ret = RET_CLAIMED;
out:
	return ret;
}

dtb_parser_ops_t *
vm_config_parser_get_ops(void)
{
	return &vm_config_parser_ops;
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
	if (vd->pci_buses != NULL) {
		vector_deinit(vd->pci_buses);
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
	if (vd->vmmio_ranges != NULL) {
		vector_deinit(vd->vmmio_ranges);
	}
	if (vd->virtio_mmios != NULL) {
		vector_deinit(vd->virtio_mmios);
	}
	if (vd->virtio_pcis != NULL) {
		vector_deinit(vd->virtio_pcis);
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
	if (vd->resmem_fixed_ranges != NULL) {
		vector_deinit(vd->resmem_fixed_ranges);
	}
	if (vd->minidump != NULL) {
		vector_deinit(vd->minidump);
	}
	if (vd->watchdog != NULL) {
		vector_deinit(vd->watchdog);
	}
	free(vd);
}

vm_config_parser_data_t *
vm_config_parser_alloc_data(const vm_t *vm)
{
	vm_config_parser_data_t *ret = calloc(1, sizeof(*ret));
	if (ret == NULL) {
		goto out;
	}

	ret->auth_type = vm->auth_type;

	RM_PADDED_BEGIN

	struct {
		vector_t **v;
		size_t	   size;
		count_t	   step;
	} vectors[] = {
		{ &ret->resmem_fixed_ranges, sizeof(resmem_range_data_t), 1U },
		{ &ret->rm_rpcs, sizeof(rm_rpc_data_t), 1U },
		{ &ret->doorbells, sizeof(doorbell_data_t), 2U },
		{ &ret->msg_queues, sizeof(msg_queue_data_t), 2U },
		{ &ret->msg_queue_pairs, sizeof(msg_queue_pair_data_t), 2U },
		{ &ret->shms, sizeof(shm_data_t), 2U },
		{ &ret->virtio_mmios, sizeof(virtio_mmio_data_t), 1U },
		{ &ret->virtio_pcis, sizeof(virtio_pci_data_t), 1U },
		{ &ret->virtio_iommus, sizeof(virtio_iommu_data_t), 1U },
		{ &ret->iomem_ranges, sizeof(iomem_range_data_t), 2U },
		{ &ret->vmmio_ranges, sizeof(mem_range_t), 2U },
		{ &ret->irq_ranges, sizeof(irq_range_data_t), 2U },
		{ &ret->iomems, sizeof(iomem_data_t), 1U },
		{ &ret->smmus, sizeof(smmu_v2_data_t), 1U },
		{ &ret->pci_buses, sizeof(pci_data_t), 1U },
		{ &ret->vcpus, sizeof(vcpu_data_t), 2U },
		{ &ret->rtc, sizeof(rtc_data_t), 1U },
		{ &ret->minidump, sizeof(minidump_data_t), 1U },
		{ &ret->watchdog, sizeof(watchdog_data_t), 1U },
	};

	RM_PADDED_END

	for (index_t i = 0U; i < util_array_size(vectors); i++) {
		*vectors[i].v = vector_init_size(
			vectors[i].step, vectors[i].step, vectors[i].size);
		if (*vectors[i].v == NULL) {
			goto err_out;
		}
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

	ret->ramfs_idx	     = -1;
	ret->cfgcpio_idx     = -1;
	ret->fallback_dt_idx = -1;

	goto out;

err_out:
	alloc_parser_data_rollback(ret);
	ret = NULL;
out:
	return ret;
}

static void
free_vcpus_parser_data(vm_config_parser_data_t *vd)
{
	if (vd->vcpus != NULL) {
		size_t cnt = vector_size(vd->vcpus);
		for (index_t i = 0U; i < cnt; i++) {
			vcpu_data_t *d =
				vector_at_ptr(vcpu_data_t, vd->vcpus, i);
			free(d->patch);
		}

		vector_deinit(vd->vcpus);
	}
}

static void
free_pci_parser_data(vm_config_parser_data_t *vd)
{
	if (vd->pci_buses != NULL) {
		FREE_ALL(pci_data_t, vd->pci_buses, general,
			 { free(d->patch); });

		vector_deinit(vd->pci_buses);
	}
}

static void
free_smmus_parser_data(vm_config_parser_data_t *vd)
{
	if (vd->smmus != NULL) {
		size_t cnt = vector_size(vd->smmus);
		for (index_t i = 0U; i < cnt; i++) {
			smmu_v2_data_t *d =
				vector_at_ptr(smmu_v2_data_t, vd->smmus, i);
			free(d->patch);
		}

		vector_deinit(vd->smmus);
	}
}

static void
free_virtio_iommus_parser_data(vm_config_parser_data_t *vd)
{
	if (vd->virtio_iommus != NULL) {
		vector_deinit(vd->virtio_iommus);
	}
}

static void
free_io_parser_data(vm_config_parser_data_t *vd)
{
	if (vd->virtio_mmios != NULL) {
		FREE_ALL(virtio_mmio_data_t, vd->virtio_mmios, common.general,
			 { free(d->common.patch); });
		vector_deinit(vd->virtio_mmios);
	}

	if (vd->virtio_pcis != NULL) {
		FREE_ALL(virtio_pci_data_t, vd->virtio_pcis, common.general,
			 { free(d->common.patch); });
		vector_deinit(vd->virtio_pcis);
	}

	if (vd->iomems != NULL) {
		FREE_ALL(iomem_data_t, vd->iomems, general, {
			free(d->patch_node_path);
			free(d->rm_sglist);
		});
		vector_deinit(vd->iomems);
	}
}

static void
free_msg_parser_data(vm_config_parser_data_t *vd)
{
	if (vd->msg_queues != NULL) {
		FREE_GENERAL(msg_queue_data_t, vd->msg_queues);
		vector_deinit(vd->msg_queues);
	}

	if (vd->msg_queue_pairs != NULL) {
		FREE_ALL(msg_queue_pair_data_t, vd->msg_queue_pairs, general,
			 { free(d->peer_id); });
		vector_deinit(vd->msg_queue_pairs);
	}

	if (vd->shms != NULL) {
		FREE_GENERAL(shm_data_t, vd->shms);
		vector_deinit(vd->shms);
	}
}

static void
free_watchdog(vm_config_parser_data_t *vd)
{
	if (vd->watchdog != NULL) {
		size_t cnt = vector_size(vd->watchdog);
		for (index_t i = 0U; i < cnt; i++) {
			watchdog_data_t *d =
				vector_at_ptr(watchdog_data_t, vd->watchdog, i);
			free(d->node_path);
		}

		vector_deinit(vd->watchdog);
	}
}

void
vm_config_parser_free_data(vm_config_parser_data_t *vd)
{
	if (vd == NULL) {
		goto out;
	}

	if (vd->resmem_fixed_ranges != NULL) {
		vector_deinit(vd->resmem_fixed_ranges);
	}

	if (vd->rm_rpcs != NULL) {
		FREE_ALL(rm_rpc_data_t, vd->rm_rpcs, general,
			 { free(d->console_owner); });
		vector_deinit(vd->rm_rpcs);
	}

	if (vd->doorbells != NULL) {
		FREE_GENERAL(doorbell_data_t, vd->doorbells);
		vector_deinit(vd->doorbells);
	}

	free_msg_parser_data(vd);

	free_io_parser_data(vd);

	if (vd->minidump != NULL) {
		FREE_GENERAL(minidump_data_t, vd->minidump);
		vector_deinit(vd->minidump);
	}

	free_watchdog(vd);

	if (vd->iomem_ranges != NULL) {
		vector_deinit(vd->iomem_ranges);
	}

	if (vd->vmmio_ranges != NULL) {
		vector_deinit(vd->vmmio_ranges);
	}

	if (vd->irq_ranges != NULL) {
		vector_deinit(vd->irq_ranges);
	}

	free_smmus_parser_data(vd);

	free_pci_parser_data(vd);

	free_virtio_iommus_parser_data(vd);

	free_vcpus_parser_data(vd);

	if (vd->rtc != NULL) {
		vector_deinit(vd->rtc);
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

#undef FREE_GENERAL

error_t
read_interrupts_config(const void *fdt, int node_ofs, const char *property,
		       interrupt_data_t *irqs, count_t count)
{
	error_t ret;
	int	len;

	const fdt32_t *irq_data =
		(const fdt32_t *)fdt_getprop(fdt, node_ofs, property, &len);
	if (irq_data == NULL) {
		if (len == -FDT_ERR_NOTFOUND) {
			ret = ERROR_DENIED;
		} else {
			ret = ERROR_FAILURE;
		}
		goto out;
	}

	// We assume #interrupt-cells = 3 by default.
	if (((len % 3) != 0) ||
	    ((uint32_t)len < (3U * sizeof(irq_data[0]) * count))) {
		ret = ERROR_ARGUMENT_SIZE;
		goto out;
	}

	index_t i   = 0;
	count_t cnt = count;

	interrupt_data_t *cur_irq = irqs;
	while (cnt > 0U) {
		virq_t offset = 0, limit = 0;

		ret = OK;

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
			ret = ERROR_ARGUMENT_INVALID;
			break;
		}
		if (ret != OK) {
			goto out;
		}
		++i;

		cur_irq->irq = (virq_t)fdt32_to_cpu(irq_data[i]) + offset;
		if (cur_irq->irq >= limit) {
			(void)printf("Ignoring invalid GIC IRQ number %d\n",
				     cur_irq->irq);
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}
		++i;

		switch (fdt32_to_cpu(irq_data[i]) & 0xfU) {
		case DT_GIC_IRQ_TYPE_EDGE_RISING:
			cur_irq->is_edge_triggering = true;
			break;
		case DT_GIC_IRQ_TYPE_LEVEL_HIGH:
		case DT_GIC_IRQ_TYPE_LEVEL_LOW:
			cur_irq->is_edge_triggering = false;
			break;
		default:
			(void)printf(
				"Ignoring invalid GIC IRQ trigger mode %#x\n",
				fdt32_to_cpu(irq_data[i]) & 0xfU);
			ret = ERROR_ARGUMENT_INVALID;
			break;
		}
		if (ret != OK) {
			goto out;
		}
		++i;

		++cur_irq;
		--cnt;
	}

	ret = OK;
out:
	return ret;
}

bool
read_sdei_event_interrupt_config(const void *fdt, int node_ofs,
				 interrupt_data_t *irq)
{
	bool	 ret;
	uint32_t event_number;

	if (fdt_getprop_u32(fdt, node_ofs, "sdei-event-number",
			    &event_number) != OK) {
		ret = false;
		goto out;
	}

	irq->irq		= event_number | VIRQ_SDEI_BIT;
	irq->is_cpu_local	= false;
	irq->is_edge_triggering = true;
	irq->is_sdei		= true;
	ret			= true;
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

		if ((entry_size == 0U) || (((size_t)len % entry_size) != 0U)) {
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

static error_t
platform_parse_gic(vm_config_parser_data_t *vd, const void *fdt,
		   uint32_t phandle)
{
	error_t ret;
	int	vgic_ofs = fdt_node_offset_by_phandle(fdt, phandle);

	if (vgic_ofs < 0) {
		(void)printf("Interrupt controller phandle is invalid\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	ctx_t ctx = dtb_parser_get_ctx(fdt, vgic_ofs);

	if (!ctx.addr_is_phys) {
		char path[256];
		if (fdt_get_path(fdt, vgic_ofs, path, (int)sizeof(path)) != 0) {
			(void)strlcpy(path, "<unknown path>", sizeof(path));
		}
		(void)printf("Warning: addresses in %s are not 1:1 physical!\n",
			     path);
	}

	// check vgic compatible
	if (fdt_node_check_compatible(fdt, vgic_ofs, "arm,gic-v3") != 0) {
		(void)printf("Interrupt controller is not a GIC\n");
		ret = ERROR_UNIMPLEMENTED;
		goto out;
	}

	if (!fdt_getprop_bool(fdt, vgic_ofs, "interrupt-controller")) {
		(void)printf("Missing \"interrupt-controller\" property\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	vd->vgic_addr_cells	  = ctx.addr_cells;
	vd->vgic_size_cells	  = ctx.size_cells;
	vd->vgic_child_addr_cells = ctx.child_addr_cells;

	// if there is no 'address_cells' defined for this node, then the
	// child 'interrupt-map' assumes 0.
	vd->map_addr_cells =
		ctx.child_addr_cells_default ? 0U : ctx.child_addr_cells;

	uint32_t gicr_regions;
	if ((fdt_getprop_u32(fdt, vgic_ofs, "#redistributor-regions",
			     &gicr_regions) == OK) &&
	    (gicr_regions != 1U)) {
		(void)printf("Can't support multiple GICR regions\n");
		ret = ERROR_ADDR_INVALID;
		goto out;
	}

	uint32_t int_cells;
	if ((fdt_getprop_u32(fdt, vgic_ofs, "#interrupt-cells", &int_cells) !=
	     OK) ||
	    (int_cells != 3U)) {
		(void)printf(
			"GIC node does not specify #interrupt-cells = 3\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	int	       len;
	const fdt32_t *reg =
		(const fdt32_t *)fdt_getprop(fdt, vgic_ofs, "reg", &len);
	uint32_t reg_cells = ctx.addr_cells + ctx.size_cells;
	if (reg == NULL) {
		// No reg property; patch DT and allocate addresses
		vd->vgic_gicd_base = INVALID_ADDRESS;
		vd->vgic_gicr_base = INVALID_ADDRESS;
		vd->vgic_patch_dt  = true;
	} else if ((size_t)len >= (sizeof(fdt32_t) * 2U * reg_cells)) {
		// Reg property is valid. Parse GICD and GICR addresses, and
		// don't patch the DT.
		index_t i	   = 0;
		vd->vgic_gicd_base = fdt_read_num(&reg[i], ctx.addr_cells);
		i += reg_cells;
		vd->vgic_gicr_base = fdt_read_num(&reg[i], ctx.addr_cells);
		vd->vgic_patch_dt  = false;
	} else {
		(void)printf("Truncated \"reg\" property in GIC node\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	// Virtual GICR is always GICv3, with no VLPIS, so size is 128K
	const size_t gicr_size = (size_t)2U << 16;

	if (fdt_getprop_u64(fdt, vgic_ofs, "redistributor-stride",
			    &vd->vgic_gicr_stride) == OK) {
		if ((vd->vgic_gicr_stride < gicr_size) ||
		    !util_is_p2aligned(vd->vgic_gicr_stride, 16)) {
			(void)printf(
				"GIC node's \"redistributor-stride\" value (%#zx) is too small or misaligned\n",
				vd->vgic_gicr_stride);
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}
	} else {
		// No stride property; default to the size of the GICR.
		vd->vgic_gicr_stride = gicr_size;
	}

	ret = OK;

out:
	if (ret != OK) {
		vd->vgic_gicr_stride = 0U;
		vd->vgic_phandle     = ~0U;
	} else {
		vd->vgic_phandle = phandle;
	}
	return ret;
}

static listener_return_t
parse_interrupts(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
		 const ctx_t *ctx)
{
	listener_return_t ret = RET_CLAIMED;
	(void)ctx;

	// Try to find the GIC from the explicit config path.
	uint32_t    phandle = ~0U;
	int	    len;
	const char *path = fdt_stringlist_get(fdt, node_ofs, "config", 0, &len);
	if ((path != NULL) && (len > 1) && (path[0] == '/')) {
		int gic_ofs = fdt_path_offset(fdt, path);
		if (gic_ofs < 0) {
			(void)printf(
				"Error: couldn't find GIC node \"%s\": %d\n",
				path, gic_ofs);
			ret = RET_ERROR;
			goto out;
		}
		phandle = fdt_get_phandle(fdt, gic_ofs);
	} else if ((len == -FDT_ERR_NOTFOUND) && (vd->vgic_phandle != ~0U)) {
		// Property was missing (not invalid) and we already found the
		// GIC from the root node; no error.
		ret = RET_CONTINUE;
		goto out;
	} else if (fdt_getprop_u32(fdt, node_ofs, "config", &phandle) == OK) {
		(void)printf(
			"Warning: interrupts \"config\" property looks like a phandle (%#x), but should be a path\n",
			phandle);
	} else {
		// Property is present, but doesn't look like either a path or
		// a phandle
		(void)printf("Error: couldn't read \"config\" property\n");
		ret = RET_ERROR;
		goto out;
	}

	if (phandle != vd->vgic_phandle) {
		// Config specified a GIC, and it's not the same as the root
		// interrupt-parent (or the latter was missing or invalid).
		error_t err = platform_parse_gic(vd, fdt, phandle);
		if (err != OK) {
			(void)printf("Parsing GIC node failed: %" PRId32 "\n",
				     (int32_t)err);
			ret = RET_ERROR;
			goto out;
		}
	}

out:
	return ret;
}

static listener_return_t
parse_root(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	   const ctx_t *ctx)
{
	(void)ctx;
	listener_return_t ret;

	// Since the root node is the first node visited, we should not have
	// already parsed the vm-config interrupts node. However, in cases where
	// there are two DTs, the image DT may have tried to specify a GIC;
	// doing this will fail because there is no way for interrupt-map
	// and interrupt-parent properties in the VMM DT to name the GIC node,
	// so we don't need to try to handle it.
	if ((vd->vgic_phandle != 0U) && (vd->vgic_phandle != ~0U)) {
		(void)printf("Image DT specified a GIC node (phandle %#x)\n",
			     vd->vgic_phandle);
		ret = RET_ERROR;
		goto out;
	}
	vd->vgic_phandle = ~0U;

	// Try to find the GIC from the root interrupt-parent.
	uint32_t phandle;
	if (fdt_getprop_u32(fdt, node_ofs, "interrupt-parent", &phandle) ==
	    OK) {
		// Try to parse the GIC node. Ignore an ERROR_UNIMPLEMENTED,
		// which means the root interrupt controller is not a GIC; in
		// that case we will obtain a link to the GIC from the VM
		// configuration's interrupts phandle.
		error_t err = platform_parse_gic(vd, fdt, phandle);
		if ((err != OK) && (err != ERROR_UNIMPLEMENTED)) {
			(void)printf("Unable to parse interrupt-parent: %u\n",
				     err);
			ret = RET_ERROR;
			goto out;
		}
	}

	ret = RET_CONTINUE;
out:
	return ret;
}
