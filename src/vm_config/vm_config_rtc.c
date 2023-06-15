// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
#include <utils/address_range_allocator.h>
#include <utils/list.h>
#include <utils/vector.h>

#include <dtb_parser.h>
#include <event.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <memextent.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_memory.h>
#include <vm_mgnt.h>

// Must be last
#include <platform_vm_config_parser.h>
#include <vm_config_parser.h>

#include "vm_config_rtc.h"
#include "vm_parser_rtc.h"

#define ALIGN_4KB (4UL * 1024)

error_t
vm_config_vrtc_set_time_base(vm_t *vm, uint64_t time_base,
			     uint64_t sys_timer_ref)
{
	error_t	 err	 = ERROR_DENIED;
	cap_id_t rtc_cap = vm->vm_config->rtc;

	if (rtc_cap == CSPACE_CAP_INVALID) {
		// No vRTC in this VM
		goto out;
	}

	err = platform_rtc_set_time_base(rtc_cap, time_base, sys_timer_ref);
out:
	return err;
}

static error_t
add_rtc_dev_node(vm_config_t *vmcfg, vmaddr_t ipa)
{
	error_t err;

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		printf("Failed to allocate vRTC configuration node\n");
		err = ERROR_NOMEM;
		goto out;
	}

	node->type	   = VDEV_RTC;
	node->export_to_dt = true;
	node->visible	   = true;
	node->generate	   = strdup("/vsoc");
	if (node->generate == NULL) {
		printf("Failed to allocate vRTC generate string\n");
		err = ERROR_NOMEM;
		goto out;
	}

	struct vdevice_rtc *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		printf("Failed to allocate vRTC configuration buffer\n");
		err = ERROR_NOMEM;
		goto out;
	}

	cfg->ipa      = ipa;
	cfg->ipa_size = RTC_IPA_SIZE;

	node->config = cfg;

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);

	err = OK;

out:
	if (err != OK) {
		if (node && node->generate) {
			free(node->generate);
		}
		if (node) {
			free(node);
		}
	}

	return err;
}

static error_t
add_rtc(vm_config_t *vmcfg, rtc_data_t *d)
{
	error_t err;

	if (d->allocate_base) {
		d->ipa_base = INVALID_ADDRESS;
	}

	// Reserve a region for the virtual RTC device. Leave it unmapped.
	vm_address_range_result_t alloc_ret = vm_address_range_alloc(
		vmcfg->vm, VM_MEMUSE_RTC, d->ipa_base, INVALID_ADDRESS,
		RTC_IPA_SIZE, ALIGN_4KB);
	if (alloc_ret.err != OK) {
		err = alloc_ret.err;
		printf("Failed to allocate IPA for vRTC at %lu, error %d\n",
		       d->ipa_base, err);
		goto out;
	}
	vmaddr_t ipa = alloc_ret.base;

	cap_id_result_t ret;
	ret = platform_vrtc_create_and_configure(rm_get_rm_partition(),
						 rm_get_rm_cspace(), ipa);
	if (ret.e != OK) {
		printf("Create_Config virtual RTC failed, error %d\n", ret.e);
		err = ret.e;
		goto out_free;
	}

	cap_id_t cap = ret.r;
	err	     = gunyah_hyp_object_activate(cap);
	if (err != OK) {
		printf("Activating virtual RTC failed, error %d\n", err);
		goto out_free;
	}

	vmcfg->rtc = cap;
	err	   = add_rtc_dev_node(vmcfg, ipa);

out_free:
	if (err != OK) {
		vm_address_range_free(vmcfg->vm, VM_MEMUSE_RTC, ipa,
				      RTC_IPA_SIZE);
		if (vmcfg->rtc != CSPACE_CAP_INVALID) {
			error_t err_del = gunyah_hyp_cspace_delete_cap_from(
				rm_get_rm_cspace(), vmcfg->rtc);
			assert(err_del == OK);
			vmcfg->rtc = CSPACE_CAP_INVALID;
		}
	}
out:
	return err;
}

error_t
handle_rtc(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;

	if (vector_is_empty(data->rtc)) {
		// No vRTC in this VM
		goto out;
	}

	// Make sure RTC virtualisation is supported
	if (!platform_has_vrtc_support()) {
		printf("Virtual RTC requested but not supported\n");
		ret = ERROR_UNIMPLEMENTED;
		goto out;
	}

	rtc_data_t *d = vector_at_ptr(rtc_data_t, data->rtc, 0);

	ret = add_rtc(vmcfg, d);
	if (ret != OK) {
		goto out;
	}

	ret = platform_vrtc_attach_addrspace(vmcfg->rtc, vmcfg->addrspace);
	if (ret != OK) {
		printf("Failed attach RTC\n");
		goto out;
	}

out:
	return ret;
}

error_t
handle_rtc_teardown(vm_config_t *vmcfg, vdevice_node_t **node)
{
	error_t err = OK;
	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), vmcfg->rtc);
	if (err != OK) {
		goto out;
	}

	struct vdevice_rtc *vrtc = (struct vdevice_rtc *)(*node)->config;

	vm_address_range_free(vmcfg->vm, VM_MEMUSE_RTC, vrtc->ipa,
			      RTC_IPA_SIZE);

	vm_config_delete_vdevice_node(vmcfg, node);

out:
	return err;
}

listener_return_t
parse_vrtc(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	   const ctx_t *ctx)
{
	(void)ctx;

	listener_return_t ret = RET_CLAIMED;

	if (vector_size(vd->rtc) != 0) {
		// Only one vRTC allowed per VM
		ret = RET_ERROR;
		goto out;
	}

	rtc_data_t cfg;
	memset(&cfg, 0, sizeof(cfg));

	bool	have_base = true;
	error_t err = fdt_getprop_u64(fdt, node_ofs, "base", &cfg.ipa_base);
	if (err != OK) {
		if (err == ERROR_FAILURE) {
			// Wrong size for base
			printf("vRTC: Base invalid\n");
			ret = RET_ERROR;
			goto out;
		} else {
			have_base = false;
		}
	}

	cfg.allocate_base = fdt_getprop_bool(fdt, node_ofs, "allocate-base");

	if (have_base) {
		if (cfg.allocate_base) {
			printf("vRTC error: Base and allocate-base both present\n");
			ret = RET_ERROR;
			goto out;
		}
		if (!util_is_baligned(cfg.ipa_base, PAGE_SIZE)) {
			printf("vRTC: Base not aligned\n");
			ret = RET_ERROR;
			goto out;
		}
	} else {
		if (!cfg.allocate_base) {
			printf("vRTC error: Neither base nor allocate-base present\n");
			ret = RET_ERROR;
			goto out;
		}
	}

	error_t push_err;
	vector_push_back_imm(rtc_data_t, vd->rtc, cfg, push_err);

	if (push_err != OK) {
		ret = RET_ERROR;
	}

out:
	return ret;
}
