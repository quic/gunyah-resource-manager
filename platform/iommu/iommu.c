// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>
#include <utils/list.h>
#include <utils/vector.h>

#include <dt_overlay.h>
#include <event.h>
#include <guest_interface.h>
#include <irq_manager.h>
#include <panic.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_mgnt.h>

#include "platform_iommu.h"

#if defined(PLATFORM_HLOS_NEEDS_VPCI) && PLATFORM_HLOS_NEEDS_VPCI
static vector_t *hlos_virtio_iommus = NULL;

static void
platform_virtio_iommu_attach_stream_id_ranges(
	platform_virtio_iommu_t *virtio_iommu, index_t virtio_iommu_idx,
	cap_id_t iommu_cap)
{
	count_t num_ranges = 0U;

	const stream_id_range_t *ranges =
		platform_iommu_get_hlos_stream_id_ranges(virtio_iommu_idx,
							 &num_ranges);

	for (count_t i = 0U; i < num_ranges; i++) {
		const stream_id_range_t *r = ranges + i;

		gunyah_hyp_viommu_bind_streams_result_t attach_r =
			gunyah_hyp_viommu_bind_streams(virtio_iommu->iommu_cap,
						       iommu_cap, r->id_start,
						       r->count);
		if (attach_r.error != OK) {
			(void)printf("virtio_iommu: failed to attach range: "
				     "id_start %u, count %u, err %d\n",
				     r->id_start, r->count, attach_r.error);
			panic("Failed to attach stream id range");
		}
	}
}

// Create some IOMMU instances for our VM
error_t
platform_iommu_init(vm_config_t *vmcfg)
{
	error_t ret = OK;

	// Assume there is only one physical SMMUv3 for now.
	cap_id_t iommu_cap = rm_get_smmuv3_cap(0);
	if (iommu_cap == CSPACE_CAP_INVALID) {
		panic("No smmuv3 cap provided");
	}

	virtio_iommu_options_t options = virtio_iommu_options_default();
	virtio_iommu_options_set_max_streams(
		&options, PLATFORM_HLOS_VIRTIO_IOMMU_MAX_STREAMS);

	hlos_virtio_iommus = vector_init(platform_virtio_iommu_t, 0, 0);
	assert(hlos_virtio_iommus != NULL);

	gunyah_hyp_partition_create_virtio_iommu_result_t iommu_ret;
	for (index_t i = 0U; i < PLATFORM_HLOS_VIRTIO_IOMMU_NUM_INSTANCES;
	     i++) {
		// Create the iommu
		iommu_ret = gunyah_hyp_partition_create_virtio_iommu(
			rm_get_rm_partition(), rm_get_rm_cspace());
		if (iommu_ret.error != OK) {
			ret = iommu_ret.error;
			goto out;
		}

		ret = gunyah_hyp_virtio_iommu_configure(iommu_ret.new_cap,
							iommu_cap, options,
							vmcfg->addrspace);
		if (ret != OK) {
			goto err_config;
		}

		ret = gunyah_hyp_object_activate(iommu_ret.new_cap);
		if (ret != OK) {
			goto err_activate;
		}

		platform_virtio_iommu_t iommu = {
			.iommu_cap = iommu_ret.new_cap,
		};

		if (iommu.iommu_cap != CSPACE_CAP_INVALID) {
			error_t err =
				vector_push_back(hlos_virtio_iommus, iommu);
			assert(err == OK);
		}

		platform_virtio_iommu_attach_stream_id_ranges(&iommu, i,
							      iommu_cap);
	}

err_activate:
err_config:
	if ((ret != OK) && (iommu_ret.new_cap != CSPACE_CAP_INVALID)) {
		error_t err = gunyah_hyp_cspace_delete_cap_from(
			rm_get_rm_cspace(), iommu_ret.new_cap);
		assert(err == OK);
	}

out:
	return ret;
}

// Attach the IOMMUs to the VM vPCI bus
// We need to do this before the VPCI bus is activated
error_t
platform_iommu_vpci_add(vm_config_t *vmcfg)
{
	error_t err;

	// Allocate and attach the vdevice address ranges
	assert(vmcfg != NULL);
	vm_t *vm = vmcfg->vm;
	assert(vm != NULL);

	// This is the primary VM.
	vmcfg->platform.virtio_iommus = hlos_virtio_iommus;
	hlos_virtio_iommus	      = NULL;
	vdevice_node_t *node	      = NULL;

	index_t			 i;
	platform_virtio_iommu_t *virtio_iommu;
	foreach_vector_ptr (platform_virtio_iommu_t,
			    vm->vm_config->platform.virtio_iommus, i,
			    virtio_iommu) {
		node = calloc(1, sizeof(*node));
		if (node == NULL) {
			(void)printf(
				"Failed to allocate Virtio-IOMMU configuration node\n");
			err = ERROR_NOMEM;
			goto out;
		}

		node->type		 = VDEV_VIRTIO;
		node->bus		 = VDEVICE_BUS_PCI;
		node->pci.bus_config_ipa = INVALID_ADDRESS;
		node->pci.bus_phandle	 = DTO_PHANDLE_UNSET;
		node->pci.has_legacy_irq = true;

		// Let Hyp choose a vPCI slot
		node->pci.slot_index   = ~(index_t)0U;
		node->pci.function_cap = virtio_iommu->iommu_cap;

		// Replace the existing SMMUv3 node, retaining the device
		// mappings
		node->visible	     = true;
		node->export_to_dt   = true;
		node->replace_symbol = true;
		node->symbol	     = strdup("pcie_smmu");

		struct vdevice_virtio *cfg = calloc(1, sizeof(*cfg));
		if (cfg == NULL) {
			(void)printf(
				"Failed to allocate Virtio-IOMMU configuration buffer\n");
			err = ERROR_NOMEM;
			goto out_free_node;
		}

		cfg->device_type    = VIRTIO_DEVICE_TYPE_IOMMU;
		node->config.virtio = cfg;

		list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node,
			    vdevice_);
	}

	err = OK;

out_free_node:
	if (err != OK) {
		free(node->symbol);
		free(node);
	}

out:
	return err;
}
#endif // PLATFORM_HLOS_NEEDS_VPCI
