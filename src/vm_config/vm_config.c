// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/list.h>
#include <utils/vector.h>

#include <event.h>
#include <guest_interface.h>
#include <guest_rights.h>
#include <irq_manager.h>
#include <log.h>
#include <memextent.h>
#include <memparcel.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <time.h>
#include <virq.h>
#include <vm_client.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_console.h>
#include <vm_creation.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_passthrough_config.h>
#include <vm_resource_msg.h>
#include <vm_vcpu.h>

#include <platform_vm_config_parser.h>
#include <vm_config_parser.h>

#include "vm_config_rtc.h"

vmid_t ras_handler_vm = VMID_HYP;

static resource_handle_t vdevice_handle = 0;

static pgtable_access_t
	iomem_range_access_to_pgtable_access[IOMEM_RANGE_ACCESS_MAX] = {
		[IOMEM_RANGE_RW]   = PGTABLE_ACCESS_RW,
		[IOMEM_RANGE_R]	   = PGTABLE_ACCESS_R,
		[IOMEM_RANGE_RWX]  = PGTABLE_ACCESS_RWX,
		[IOMEM_RANGE_W]	   = PGTABLE_ACCESS_W,
		[IOMEM_RANGE_X]	   = PGTABLE_ACCESS_X,
		[IOMEM_RANGE_RX]   = PGTABLE_ACCESS_RX,
		[IOMEM_RANGE_NONE] = PGTABLE_ACCESS_NONE,
	};

extern cap_id_t rm_cspace;

static cap_id_result_t
create_msgqueue(uint16_t queue_depth, uint16_t msg_size);

static cap_id_result_t
create_doorbell(void);

#if defined(CAP_RIGHTS_VIRTIO_MMIO_ALL)
static cap_id_result_t
create_virtio_mmio(vm_config_t *frontend_cfg, vm_config_t *backend_cfg,
		   count_t vqs_num, vmaddr_t *frontend_ipa,
		   virtio_device_type_t device_type, bool valid_device_type,
		   vmaddr_t *backend_ipa, cap_id_t *me_cap, size_t *me_size,
		   void **rm_addr);
#endif

static error_t
handle_rm_rpc(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_doorbell(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_msgqueue(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_msgqueue_pair(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_shm(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_vcpu(vm_config_t *vmcfg, vm_config_parser_data_t *data);
#if defined(CAP_RIGHTS_VIRTIO_MMIO_ALL)
static error_t
handle_virtio_mmio(vm_config_t *vmcfg, vm_config_parser_data_t *data);
#endif
static error_t
handle_iomems(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_iomem_ranges(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_irqs(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_interrupt_controller(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_ids(vm_config_t *vmcfg, vm_config_parser_data_t *data);
#if defined(CAP_RIGHTS_WATCHDOG_ALL)
static error_t
handle_watchdog(vm_config_t *vmcfg, vm_config_parser_data_t *data);
#endif

static void
free_compatibles(vdevice_node_t *vdevice);

static error_t
vm_config_add_shm(vm_config_t *vmcfg, shm_data_t *data, vdevice_node_t *db,
		  vdevice_node_t *db_src);

static error_t
vm_config_add_vpm_group(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
			interrupt_data_t peer_virq, uint32_t label,
			const char *generate);

#if defined(CAP_RIGHTS_VIRTIO_MMIO_ALL)
static error_t
vm_config_add_virtio_mmio(vm_config_t *frontend_cfg, vm_config_t *backend_cfg,
			  cap_id_t rm_cap, interrupt_data_t frontend_virq,
			  interrupt_data_t backend_virq, virtio_mmio_data_t *d,
			  bool export_to_dt, vmaddr_t frontend_ipa,
			  vmaddr_t backend_ipa, cap_id_t me_cap, size_t me_size,
			  void *rm_addr);
#endif

static vdevice_node_t *
vm_config_add_doorbell(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
		       bool source, interrupt_data_t virq, uint32_t label,
		       const char *generate, bool export_to_dt,
		       bool source_can_clear);
static error_t
vm_config_add_msgqueue(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
		       bool tx, interrupt_data_t vm_virq,
		       interrupt_data_t peer_virq, const msg_queue_data_t *data,
		       bool export_to_dt);
static error_t
vm_config_add_msgqueue_pair(vm_config_t *vmcfg, msg_queue_pair_data_t *data,
			    cap_id_t rm_tx_cap, cap_id_t rm_rx_cap,
			    struct vdevice_msg_queue_pair *peer_cfg,
			    vm_t *peer_vm, resource_handle_t handle);

static error_t
vm_config_add_rm_rpc(vm_config_t *vmcfg, rm_rpc_data_t *data, cap_id_t rx,
		     cap_id_t tx);

#if defined(CAP_RIGHTS_WATCHDOG_ALL)
static error_t
vm_config_add_watchdog(vm_config_t *vmcfg, cap_id_t rm_cap,
		       interrupt_data_t bark_virq, bool allow_management);
#endif

static void
handle_msgqueue_pair_destruction(vm_config_t *vmcfg, vdevice_node_t **node);
static error_t
vm_config_check_peer(char *peer_id, vm_t *peer_vm);

typedef struct {
	error_t err;
	uint8_t err_padding[4];

	vdevice_node_t *node;
} add_doorbell_ret_t;

static add_doorbell_ret_t
add_doorbell(vm_config_t *vmcfg, vmid_t self, vmid_t peer, bool is_src,
	     label_t label, const char *generate, interrupt_data_t virq,
	     bool need_alloc_virq, bool export_to_dt, bool source_can_clear);

static error_t
add_msgqueue(vm_config_t *vmcfg, msg_queue_data_t *data, bool is_sender,
	     interrupt_data_t self_virq, bool alloc_self_virq,
	     interrupt_data_t peer_virq, bool alloc_peer_virq);

static void
vm_config_destroy_vdevice(vm_config_t *vmcfg, vdevice_node_t **node);

static void
handle_rm_rpc_destruction(vm_config_t *vmcfg, vdevice_node_t **node);
static void
handle_doorbell_destruction(vm_config_t *vmcfg, vdevice_node_t **node);
static void
handle_msgqueue_destruction(vm_config_t *vmcfg, vdevice_node_t **node);
static void
handle_shm_destruction(vm_config_t *vmcfg, vdevice_node_t **node);
#if defined(CAP_RIGHTS_WATCHDOG_ALL)
static void
handle_watchdog_destruction(vm_config_t *vmcfg, vdevice_node_t **node);
#endif
#if defined(CAP_RIGHTS_VIRTIO_MMIO_ALL)
static void
handle_virtio_mmio_destruction(vm_config_t *vmcfg, vdevice_node_t **node);
#endif
static void
handle_iomem_destruction(vm_config_t *vmcfg, vdevice_node_t **node);
static void
handle_vpm_group_destruction(vm_config_t *vmcfg, vdevice_node_t **node);

static vmid_t
get_peer(vm_config_t *vmcfg, vmid_t cfg_peer)
{
	return (cfg_peer == VMID_PEER_DEFAULT) ? vmcfg->vm->owner : cfg_peer;
}

static bool
check_default_peer(vm_config_t *self, vm_t *peer)
{
	// peer can be NULL
	assert(self != NULL);
	assert(self->vm != NULL);

	return (peer != NULL) && (self->vm->owner == peer->vmid);
}

// FIXME: define a dedicate API to generate handle
static resource_handle_t
get_vdevice_resource_handle(void)
{
	// crash if it's overflow, it might take quite long to crash
	assert(!util_add_overflows(vdevice_handle, 1U));

	return vdevice_handle++;
}

static error_t
map_virq(vmid_t vmid, uint32_t irq)
{
	vm_t *vm = vm_lookup(vmid);
	assert(vm != NULL);

	return irq_manager_vm_virq_map(vm, irq, true);
}

static uint32_result_t
alloc_map_virq(vmid_t vmid)
{
	vm_t *vm = vm_lookup(vmid);
	assert(vm != NULL);

	uint32_result_t irq_ret = irq_manager_vm_alloc_global(vm);
	if (irq_ret.e != OK) {
		goto out;
	}

	error_t err = irq_manager_vm_virq_map(vm, irq_ret.r, false);
	if (err != OK) {
		irq_ret.e = err;
		err	  = irq_manager_vm_free_global(vm, irq_ret.r);
		assert(err == OK);
	}

out:
	return irq_ret;
}

static void
revert_map_virq(vmid_t vmid, uint32_t irq)
{
	vm_t *vm = vm_lookup(vmid);
	assert(vm != NULL);

	error_t err = irq_manager_vm_virq_unmap(vm, irq, true);
	assert(err == OK);
}
#if defined(CAP_RIGHTS_VIRTIO_MMIO_ALL)
static error_t
add_virtio_mmio(vm_config_t *frontend_cfg, virtio_mmio_data_t *d);
#endif

#if defined(CAP_RIGHTS_WATCHDOG_ALL)
static void
get_vdev_watchdog_desc(vmid_t self, vmid_t vmid, vdevice_node_t *node,
		       vector_t *descs)
{
	rm_hyp_resource_resp_t item = {
		.partner_vmid = vmid,
	};

	struct vdevice_watchdog *vwdt = (struct vdevice_watchdog *)node->config;
	assert(vwdt != NULL);

	if (vwdt->manager == self) {
		item.resource_type = RSC_WATCHDOG;
		item.resource_capid_low =
			(uint32_t)(vwdt->manager_cap & 0xffffffffU);
		item.resource_capid_high = (uint32_t)(vwdt->manager_cap >> 32);
		vector_push_back(descs, item);
	}
}
#endif

static void
get_vdev_virtio_mmio_desc(vmid_t self, vmid_t vmid, vdevice_node_t *node,
			  vector_t *descs)
{
	rm_hyp_resource_resp_t item = {
		.partner_vmid = vmid,
	};

#if defined(CAP_RIGHTS_VIRTIO_MMIO_ALL)
	struct vdevice_virtio_mmio *vio =
		(struct vdevice_virtio_mmio *)node->config;
	assert(vio != NULL);

	if (vio->backend == self) {
		item.resource_type  = RSC_VIRTIO_MMIO;
		item.resource_label = vio->label;
		item.resource_capid_low =
			(uint32_t)(vio->backend_cap & 0xffffffffU);
		item.resource_capid_high  = (uint32_t)(vio->backend_cap >> 32);
		item.resource_virq_number = virq_get_number(vio->backend_virq);
		item.resource_base_address_low =
			(uint32_t)(vio->backend_ipa & 0xffffffffU);
		item.resource_base_address_high =
			(uint32_t)(vio->backend_ipa >> 32);
		item.resource_size_low = (uint32_t)(vio->me_size & 0xffffffffU);
		item.resource_size_high = (uint32_t)(vio->me_size >> 32);
		vector_push_back(descs, item);
	} else {
		// Ignore
	}
#endif
}

static void
get_vdev_virtual_pm_desc(vmid_t self, vmid_t vmid, vdevice_node_t *node,
			 vector_t *descs)
{
	rm_hyp_resource_resp_t item = {
		.partner_vmid = vmid,
	};

	struct vdevice_virtual_pm *vpm =
		(struct vdevice_virtual_pm *)node->config;
	assert(vpm != NULL);

	if (vpm->peer == self) {
		item.resource_type  = RSC_VIRTUAL_PM;
		item.resource_label = vpm->label;
		item.resource_capid_low =
			(uint32_t)(vpm->peer_cap & 0xffffffffU);
		item.resource_capid_high  = (uint32_t)(vpm->peer_cap >> 32);
		item.resource_virq_number = virq_get_number(vpm->peer_virq);
		vector_push_back(descs, item);
	} else {
		// Ignore
	}
}

static void
get_vdev_msg_queue_pair_desc(vmid_t self, vmid_t vmid, vdevice_node_t *node,
			     vector_t *descs)
{
	rm_hyp_resource_resp_t item = {
		.partner_vmid = vmid,
	};

	struct vdevice_msg_queue_pair *mq =
		(struct vdevice_msg_queue_pair *)node->config;
	if (mq->peer == vmid) {
		// Tx msgqueue from self vdevice list
		item.resource_type  = RSC_MSG_QUEUE_SEND;
		item.resource_label = mq->label;
		item.resource_capid_low =
			(uint32_t)(mq->tx_vm_cap & 0xffffffffU);
		item.resource_capid_high  = (uint32_t)(mq->tx_vm_cap >> 32);
		item.resource_virq_number = virq_get_number(mq->tx_vm_virq);
		vector_push_back(descs, item);

		// Rx msgqueue from self vdevice list
		item.resource_type  = RSC_MSG_QUEUE_RECV;
		item.resource_label = mq->label;
		item.resource_capid_low =
			(uint32_t)(mq->rx_vm_cap & 0xffffffffU);
		item.resource_capid_high  = (uint32_t)(mq->rx_vm_cap >> 32);
		item.resource_virq_number = virq_get_number(mq->rx_vm_virq);
		vector_push_back(descs, item);
	} else if ((mq->peer == self) && (!mq->has_peer_vdevice)) {
		// returns resource info if there is no peer vdevice
		// Currently, only use peer-default (PVM), the vdevice
		// is only defined in SVM side.
		// Tx msgqueue from peer vdevice list
		item.resource_type  = RSC_MSG_QUEUE_SEND;
		item.resource_label = mq->label;
		item.resource_capid_low =
			(uint32_t)(mq->tx_peer_cap & 0xffffffffU);
		item.resource_capid_high  = (uint32_t)(mq->tx_peer_cap >> 32);
		item.resource_virq_number = virq_get_number(mq->tx_peer_virq);
		vector_push_back(descs, item);

		// Rx msgqueue from peer vdevice list
		item.resource_type  = RSC_MSG_QUEUE_RECV;
		item.resource_label = mq->label;
		item.resource_capid_low =
			(uint32_t)(mq->rx_peer_cap & 0xffffffffU);
		item.resource_capid_high  = (uint32_t)(mq->rx_peer_cap >> 32);
		item.resource_virq_number = virq_get_number(mq->rx_peer_virq);
		vector_push_back(descs, item);
	} else {
		// Ignore
	}
}

static void
get_vdev_msg_queue_desc(vmid_t self, vmid_t vmid, vdevice_node_t *node,
			vector_t *descs)
{
	rm_hyp_resource_resp_t item = {
		.partner_vmid = vmid,
	};

	struct vdevice_msg_queue *mq = (struct vdevice_msg_queue *)node->config;
	if (mq->peer == vmid) {
		// Msgqueue from self vdevice list
		item.resource_type	 = (mq->tx) ? RSC_MSG_QUEUE_SEND
						    : RSC_MSG_QUEUE_RECV;
		item.resource_label	 = mq->label;
		item.resource_capid_low	 = (uint32_t)(mq->vm_cap & 0xffffffffU);
		item.resource_capid_high = (uint32_t)(mq->vm_cap >> 32);
		item.resource_virq_number = virq_get_number(mq->vm_virq);
		vector_push_back(descs, item);
	} else if (mq->peer == self) {
		// Msgqueue from peer vdevice list
		item.resource_type  = (mq->tx) ? RSC_MSG_QUEUE_RECV
					       : RSC_MSG_QUEUE_SEND;
		item.resource_label = mq->label;
		item.resource_capid_low =
			(uint32_t)(mq->peer_cap & 0xffffffffU);
		item.resource_capid_high  = (uint32_t)(mq->peer_cap >> 32);
		item.resource_virq_number = virq_get_number(mq->peer_virq);
		vector_push_back(descs, item);
	} else {
		// Ignore
	}
}

static void
get_vdev_doorbell_desc(vmid_t self, vmid_t vmid, vdevice_node_t *node,
		       vector_t *descs)
{
	rm_hyp_resource_resp_t item = {
		.partner_vmid = vmid,
	};

	struct vdevice_doorbell *db = (struct vdevice_doorbell *)node->config;
	if (db->peer == vmid) {
		// Doorbell from self vdevice list
		item.resource_type	 = (db->source) ? RSC_DOORBELL_SRC
							: RSC_DOORBELL;
		item.resource_label	 = db->label;
		item.resource_capid_low	 = (uint32_t)(db->vm_cap & 0xffffffffU);
		item.resource_capid_high = (uint32_t)(db->vm_cap >> 32);
		// The 0 here should be changed to VIRQ_NUM_INVALID.
		// FIXME:
		item.resource_virq_number =
			db->source ? 0U : virq_get_number(db->vm_virq);
		vector_push_back(descs, item);
	} else if ((db->peer == self) && (!db->has_peer_vdevice)) {
		// returns resource info if there is no peer vdevice

		// Doorbell from peer vdevice list
		item.resource_type  = (db->source) ? RSC_DOORBELL
						   : RSC_DOORBELL_SRC;
		item.resource_label = db->label;
		item.resource_capid_low =
			(uint32_t)(db->peer_cap & 0xffffffffU);
		item.resource_capid_high = (uint32_t)(db->peer_cap >> 32);
		// The 0 here should be changed to VIRQ_NUM_INVALID.
		// FIXME:
		item.resource_virq_number =
			db->source ? virq_get_number(db->peer_virq) : 0U;
		vector_push_back(descs, item);
	} else {
		// Ignore
	}
}

static rm_error_t
get_vdev_desc(vmid_t self, vmid_t vmid, vdevice_node_t *node, vector_t *descs)
{
	if (!node->visible) {
		goto out;
	}

	if (node->type == VDEV_DOORBELL) {
		get_vdev_doorbell_desc(self, vmid, node, descs);
	} else if (node->type == VDEV_MSG_QUEUE) {
		get_vdev_msg_queue_desc(self, vmid, node, descs);
	} else if (node->type == VDEV_MSG_QUEUE_PAIR) {
		get_vdev_msg_queue_pair_desc(self, vmid, node, descs);
	} else if (node->type == VDEV_VIRTUAL_PM) {
		get_vdev_virtual_pm_desc(self, vmid, node, descs);
	} else if (node->type == VDEV_VIRTIO_MMIO) {
		get_vdev_virtio_mmio_desc(self, vmid, node, descs);
#if defined(CAP_RIGHTS_WATCHDOG_ALL)
	} else if (node->type == VDEV_WATCHDOG) {
		get_vdev_watchdog_desc(self, vmid, node, descs);
#endif
	} else {
		// Other vdevice types not supplied in get resources
	}
out:
	return RM_OK;
}

rm_error_t
vm_config_get_resource_descs(vmid_t self, vmid_t vmid, vector_t *descs)
{
	rm_error_t ret = RM_OK;
	vm_t	  *vm  = vm_lookup(vmid);

	if (vm == NULL) {
		ret = RM_ERROR_ARGUMENT_INVALID;
		goto out;
	}
	bool owner	      = self == vm->owner;
	bool rm_caps_for_hlos = (vmid == VMID_RM) && (self == VMID_HLOS);

	vm_config_t *vmcfg = vm->vm_config;
	if (vmcfg == NULL) {
		ret = RM_ERROR_NORESOURCE;
		goto out;
	}

	if (owner || rm_caps_for_hlos) {
		// Add vcpu info
		size_t cnt = vector_size(vmcfg->vcpus);
		for (index_t i = 0; i < cnt; i++) {
			vcpu_t *vcpu = vector_at(vcpu_t *, vmcfg->vcpus, i);
			assert(vcpu != NULL);

			rm_hyp_resource_resp_t item = { 0 };
			item.resource_type	    = RSC_VIRTUAL_CPU;
			item.resource_label	    = vcpu->affinity_index;
			item.resource_capid_low =
				(uint32_t)(vcpu->owner_cap & 0xffffffffU);
			item.resource_capid_high =
				(uint32_t)(vcpu->owner_cap >> 32);
			item.resource_virq_number =
				virq_get_number(vcpu->proxy_virq);

			vector_push_back(descs, item);
		}
	}

	// Add vdevice resource info from self
	vm_t *self_vm = vm_lookup(self);
	assert(self_vm != NULL);

	vm_config_t *self_vmcfg = self_vm->vm_config;
	assert(self_vmcfg != NULL);

	vdevice_node_t *node;

	loop_list(node, &self_vmcfg->vdevice_nodes, vdevice_)
	{
		ret = get_vdev_desc(self, vmid, node, descs);
		if (ret != RM_OK) {
			break;
		}
	}

	// Add vdevice resource info from peer
	loop_list(node, &vmcfg->vdevice_nodes, vdevice_)
	{
		ret = get_vdev_desc(self, vmid, node, descs);
		if (ret != RM_OK) {
			break;
		}
	}

out:
	return ret;
}

error_t
vm_config_add_vcpu(vm_config_t *vmcfg, cap_id_t rm_cap, uint32_t affinity_index,
		   bool boot_vcpu, const char *patch)
{
	error_t ret;
	vcpu_t *vcpu = calloc(1, sizeof(*vcpu));

	if (vcpu == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	vcpu->master_cap     = rm_cap;
	vcpu->vm_cap	     = CSPACE_CAP_INVALID;
	vcpu->owner_cap	     = CSPACE_CAP_INVALID;
	vcpu->affinity_index = affinity_index;
	vcpu->boot_vcpu	     = boot_vcpu;
	vcpu->vmid	     = vmcfg->vm->vmid;

	if (patch != NULL) {
		vcpu->patch = strdup(patch);
		if (vcpu->patch == NULL) {
			ret = ERROR_NOMEM;
			goto deallocate_vcpu;
		}
	} else {
		vcpu->patch = NULL;
	}

	// Allocate halt virq
	uint32_result_t irq_ret = alloc_map_virq(VMID_RM);
	if (irq_ret.e != OK) {
		ret = irq_ret.e;
		goto deallocate_patch;
	}
	interrupt_data_t halt_virq = virq_edge(irq_ret.r);

	vcpu->halt_virq = halt_virq;

	error_t err;

	// Bind the halt virq to RM's vic
	ret = gunyah_hyp_vcpu_bind_virq(rm_cap, rm_get_rm_vic(),
					virq_get_number(halt_virq),
					VCPU_VIRQ_TYPE_HALT);
	if (ret != OK) {
		goto err_bind_virq;
	}

	vmid_t	     owner     = vmcfg->vm->owner;
	vm_config_t *owner_cfg = NULL;
	if (owner != VMID_RM) {
		vm_t *owner_vm = vm_lookup(owner);
		if ((owner_vm == NULL) || (owner_vm->vm_config == NULL)) {
			(void)printf("Failed: invalid owner VM\n");
			ret = ERROR_ARGUMENT_INVALID;
			goto err_create_owner_cap;
		}

		owner_cfg = owner_vm->vm_config;

		// Copy SVM vcpu caps to owner VM cspace
		gunyah_hyp_cspace_copy_cap_from_result_t copy_ret;

		cap_rights_t rights = CAP_RIGHTS_THREAD_AFFINITY |
				      CAP_RIGHTS_THREAD_YIELD_TO;

		copy_ret = gunyah_hyp_cspace_copy_cap_from(
			rm_get_rm_cspace(), rm_cap, owner_cfg->cspace, rights);
		if (copy_ret.error != OK) {
			(void)printf("Failed: copy vcpu cap from rm cspace\n");
			ret = copy_ret.error;
			goto err_create_owner_cap;
		}

		vcpu->owner_cap = copy_ret.new_cap;
	}

	// Non-PSCI VMs need to use the vcpu_poweron/off hypercalls and for that
	// they need the POWER right
	if (vmcfg->vpm_group == CSPACE_CAP_INVALID) {
		gunyah_hyp_cspace_copy_cap_from_result_t copy_ret;

		copy_ret = gunyah_hyp_cspace_copy_cap_from(
			rm_get_rm_cspace(), rm_cap, vmcfg->cspace,
			CAP_RIGHTS_THREAD_POWER);
		if (copy_ret.error != OK) {
			(void)printf("Failed: copy vcpu cap from rm cspace\n");
			ret = copy_ret.error;
			goto err_create_power_cap;
		}

		vcpu->vm_cap = copy_ret.new_cap;
	}

	// Add to vm_config
	ret = vector_push_back(vmcfg->vcpus, vcpu);
	if (ret != OK) {
		goto err_vector_push_back;
	}

	// Register VCPU halt event
	rm_error_t rm_err = vm_mgnt_register_event(VM_EVENT_SRC_VCPU_HALT,
						   &vcpu->halt_event, vcpu,
						   virq_get_number(halt_virq));
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
		goto err_register_event;
	}

	if (ret == OK) {
		goto out;
	}

err_register_event:
	(void)vector_pop_back(vcpu_t *, vmcfg->vcpus);
err_vector_push_back:
	if (vmcfg->vpm_group == CSPACE_CAP_INVALID) {
		err = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace,
							vcpu->vm_cap);
		assert(err == OK);
	}
err_create_power_cap:
	if (vcpu->owner_cap != CSPACE_CAP_INVALID) {
		assert(owner_cfg != NULL);
		err = gunyah_hyp_cspace_delete_cap_from(owner_cfg->cspace,
							vcpu->owner_cap);
		assert(err == OK);
	}
err_create_owner_cap:
	err = gunyah_hyp_vcpu_unbind_virq(rm_cap, VCPU_VIRQ_TYPE_HALT);
	assert(err == OK);
err_bind_virq:
	revert_map_virq(VMID_RM, virq_get_number(halt_virq));
	vcpu->halt_virq = VIRQ_INVALID;
deallocate_patch:
	free(vcpu->patch);
deallocate_vcpu:
	free(vcpu);
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

static void
vm_config_remove_vcpus(vm_config_t *vmcfg, bool delete_master_caps)
{
	error_t err;
	vm_t   *owner_vm = vm_lookup(vmcfg->vm->owner);

	while (!vector_is_empty(vmcfg->vcpus)) {
		vcpu_t **vcpu_ptr = vector_pop_back(vcpu_t *, vmcfg->vcpus);
		assert(vcpu_ptr != NULL);
		vcpu_t *vcpu = *vcpu_ptr;

		assert(vcpu != NULL);

		// unbind proxy virq
		if (virq_is_valid(vcpu->proxy_virq)) {
			err = gunyah_hyp_vcpu_unbind_virq(
				vcpu->master_cap,
				VCPU_VIRQ_TYPE_VCPU_RUN_WAKEUP);
			assert(err == OK);

			revert_map_virq(vmcfg->vm->owner,
					virq_get_number(vcpu->proxy_virq));
		}

		if (vcpu->vm_cap != CSPACE_CAP_INVALID) {
			err = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace,
								vcpu->vm_cap);
			assert(err == OK);
		}

		if ((owner_vm != NULL) && (owner_vm->vm_config != NULL)) {
			err = gunyah_hyp_cspace_delete_cap_from(
				owner_vm->vm_config->cspace, vcpu->owner_cap);
			assert(err == OK);
		}

		vm_mgnt_deregister_event(&vcpu->halt_event,
					 virq_get_number(vcpu->halt_virq));
		err = gunyah_hyp_vcpu_unbind_virq(vcpu->master_cap,
						  VCPU_VIRQ_TYPE_HALT);
		assert(err == OK);

		revert_map_virq(VMID_RM, virq_get_number(vcpu->halt_virq));

		if (delete_master_caps) {
			err = gunyah_hyp_cspace_delete_cap_from(
				rm_get_rm_cspace(), vcpu->master_cap);
			assert(err == OK);
		}

		free(vcpu->patch);
		free(vcpu);
	}
}

vector_t *
vm_config_get_vcpus(const vm_config_t *vmcfg)
{
	assert(vmcfg != NULL);

	return vmcfg->vcpus;
}

static error_t
vm_config_add_vpm_group(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
			interrupt_data_t peer_virq, uint32_t label,
			const char *generate)
{
	error_t	     ret      = OK;
	cap_id_t     peer_cap = CSPACE_CAP_INVALID;
	vm_config_t *peer_cfg = NULL;

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		(void)printf("Failed: to alloc vdevice node\n");
		ret = ERROR_NOMEM;
		goto out;
	}

	node->type	   = VDEV_VIRTUAL_PM;
	node->export_to_dt = false;
	node->visible	   = true;
	node->handle	   = get_vdevice_resource_handle();

	if (generate != NULL) {
		node->generate = strdup(generate);
	} else {
		node->generate = strdup("/hypervisor/qcom,vpm");
	}

	if (node->generate == NULL) {
		(void)printf("Failed: to alloc virtual pm generate string\n");
		ret = ERROR_NOMEM;
		goto out;
	}

	struct vdevice_virtual_pm *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		(void)printf("Failed: to alloc vpm config\n");
		ret = ERROR_NOMEM;
		goto out;
	}
	node->config = cfg;

	vm_t *peer_vm = vm_lookup(peer);
	if ((peer_vm == NULL) || (peer_vm->vm_config == NULL)) {
		(void)printf("Failed: invalid peer\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	peer_cfg = peer_vm->vm_config;

	// Copy vpm cap to the peer VM's cspace with query rights
	gunyah_hyp_cspace_copy_cap_from_result_t copy_ret;

	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(), rm_cap,
						   peer_cfg->cspace,
						   CAP_RIGHTS_VPM_GROUP_QUERY);
	if (copy_ret.error != OK) {
		(void)printf("Failed: to copy vpm cap\n");
		ret = copy_ret.error;
		goto out;
	}
	peer_cap = copy_ret.new_cap;

	// Bind VIRQs to peer's vic
	ret = gunyah_hyp_vpm_group_bind_virq(rm_cap, peer_cfg->vic,
					     virq_get_number(peer_virq));
	if (ret != OK) {
		(void)printf("Failed: to bind vpm virq\n");
		goto out;
	}

	cfg->peer	= peer;
	cfg->master_cap = rm_cap;
	cfg->label	= label;
	cfg->peer_cap	= peer_cap;
	cfg->peer_virq	= peer_virq;

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);

out:
	if ((ret != OK) && (node != NULL)) {
		if (peer_cap != CSPACE_CAP_INVALID) {
			assert(peer_cfg != NULL);
			error_t err = gunyah_hyp_cspace_delete_cap_from(
				peer_cfg->cspace, peer_cap);
			assert(err == OK);
		}
		free(node->config);
		free(node->generate);
		free(node);
	}

	return ret;
}

static vdevice_node_t *
vm_config_add_doorbell(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
		       bool source, interrupt_data_t virq, uint32_t label,
		       const char *generate, bool export_to_dt,
		       bool source_can_clear)
{
	vm_config_t *send_cfg = NULL, *recv_cfg = NULL;
	cap_id_t send_cap = CSPACE_CAP_INVALID, recv_cap = CSPACE_CAP_INVALID;
	error_t	 err;

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		(void)printf("Failed: to alloc vdevice node\n");
		err = ERROR_NOMEM;
		goto out;
	}

	node->type	   = VDEV_DOORBELL;
	node->export_to_dt = export_to_dt;
	node->visible	   = true;
	node->handle	   = get_vdevice_resource_handle();

	if (generate != NULL) {
		node->generate = strdup(generate);
	} else {
		node->generate = strdup("/hypervisor/qcom,doorbell");
	}

	if (node->generate == NULL) {
		(void)printf("Failed: to alloc doorbell generate string\n");
		err = ERROR_NOMEM;
		goto out;
	}

	struct vdevice_doorbell *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		(void)printf("Failed: to alloc doorbell config\n");
		err = ERROR_NOMEM;
		goto out;
	}

	node->config = cfg;

	vm_t *peer_vm = vm_lookup(peer);
	if ((peer_vm == NULL) || (peer_vm->vm_config == NULL)) {
		(void)printf("Failed: invalid peer\n");
		err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if (source) {
		send_cfg = vmcfg;
		recv_cfg = peer_vm->vm_config;
	} else {
		send_cfg = peer_vm->vm_config;
		recv_cfg = vmcfg;
	}

	// Copy doorbell cap to source VM cspace with send rights
	gunyah_hyp_cspace_copy_cap_from_result_t copy_ret;

	copy_ret = gunyah_hyp_cspace_copy_cap_from(
		rm_get_rm_cspace(), rm_cap, send_cfg->cspace,
		CAP_RIGHTS_DOORBELL_SEND |
			(source_can_clear ? CAP_RIGHTS_DOORBELL_RECEIVE : 0U));
	if (copy_ret.error != OK) {
		(void)printf("Failed: to copy send cap\n");
		err = copy_ret.error;
		goto out;
	}
	send_cap = copy_ret.new_cap;

	// Copy doorbell cap to recv VM cspace with receive rights
	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(), rm_cap,
						   recv_cfg->cspace,
						   CAP_RIGHTS_DOORBELL_RECEIVE);
	if (copy_ret.error != OK) {
		(void)printf("Failed: to copy recv cap\n");
		err = copy_ret.error;
		goto out;
	}
	recv_cap = copy_ret.new_cap;

	// Bind VIRQ to recv VM's VIC
	err = gunyah_hyp_doorbell_bind_virq(rm_cap, recv_cfg->vic,
					    virq_get_number(virq));
	if (err != OK) {
		(void)printf("Failed: to bind db virq(%d) err(0x%x)\n",
			     virq_get_number(virq), err);
		goto out;
	}

	cfg->peer	= peer;
	cfg->source	= source;
	cfg->master_cap = rm_cap;
	cfg->label	= label;
	if (source) {
		cfg->vm_cap   = send_cap;
		cfg->vm_virq  = VIRQ_INVALID;
		cfg->peer_cap = recv_cap;

		cfg->peer_virq = virq;
	} else {
		cfg->vm_cap    = recv_cap;
		cfg->vm_virq   = virq;
		cfg->peer_cap  = send_cap;
		cfg->peer_virq = VIRQ_INVALID;
	}

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);
out:
	if ((err != OK) && (node != NULL)) {
		if (recv_cap != CSPACE_CAP_INVALID) {
			assert(recv_cfg != NULL);
			err = gunyah_hyp_cspace_delete_cap_from(
				recv_cfg->cspace, recv_cap);
			assert(err == OK);
		}
		if (send_cap != CSPACE_CAP_INVALID) {
			assert(send_cfg != NULL);
			err = gunyah_hyp_cspace_delete_cap_from(
				send_cfg->cspace, send_cap);
			assert(err == OK);
		}

		free(node->config);
		free(node->generate);
		free(node);

		node = NULL;
	}

	return node;
}

#if defined(CAP_RIGHTS_VIRTIO_MMIO_ALL)
static error_t
vm_config_add_virtio_mmio(vm_config_t *frontend_cfg, vm_config_t *backend_cfg,
			  cap_id_t rm_cap, interrupt_data_t frontend_virq,
			  interrupt_data_t backend_virq, virtio_mmio_data_t *d,
			  bool export_to_dt, vmaddr_t frontend_ipa,
			  vmaddr_t backend_ipa, cap_id_t me_cap, size_t me_size,
			  void *rm_addr)
{
	error_t ret = OK;

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		(void)printf("Failed: to alloc vdevice node\n");
		goto out;
	}
	(void)memset(node, 0, sizeof(*node));

	node->type	   = VDEV_VIRTIO_MMIO;
	node->export_to_dt = export_to_dt;
	node->visible	   = true;
	node->handle	   = get_vdevice_resource_handle();

	if (d->general.generate != NULL) {
		node->generate = strdup(d->general.generate);
	} else {
		node->generate = strdup("/hypervisor/qcom,virtio_mmio");
	}
	if (node->generate == NULL) {
		(void)printf("Failed: to virtio_mmio alloc generate string\n");
		ret = ERROR_NOMEM;
		goto error_generate;
	}

	ret = handle_compatibles(node, &d->general);
	if (ret != OK) {
		(void)printf("Failed: save compatible in virtio node\n");
		goto error_push_comp;
	}

	struct vdevice_virtio_mmio *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		(void)printf("Failed: to alloc virtio_mmio config\n");
		ret = ERROR_NOMEM;
		goto error_cfg_alloc;
	}
	node->config = cfg;

	// Copy virtio_mmio cap to the backend vm with config and assert rights
	gunyah_hyp_cspace_copy_cap_from_result_t copy_ret;

	copy_ret = gunyah_hyp_cspace_copy_cap_from(
		rm_get_rm_cspace(), rm_cap, backend_cfg->cspace,
		CAP_RIGHTS_VIRTIO_MMIO_CONFIG |
			CAP_RIGHTS_VIRTIO_MMIO_ASSERT_VIRQ);
	if (copy_ret.error != OK) {
		(void)printf("Failed: to copy backend cap\n");
		goto error_backend_cap;
	}
	cap_id_t backend_cap = copy_ret.new_cap;

	error_t err;

	// Bind frontend's VIRQ and vic to backend's source, so that the
	// frontend gets an interrupt every time the backend asserts
	ret = gunyah_hyp_virtio_mmio_backend_bind_virq(
		rm_cap, frontend_cfg->vic, virq_get_number(frontend_virq));
	if (ret != OK) {
		(void)printf("Failed: to bind FE virq\n");
		goto error_bind_fe;
	}

	// Bind backend's VIRQ and vic to frontend's source, so that the backend
	// gets an interrupt every time the frontend writes to the kick register
	ret = gunyah_hyp_virtio_mmio_frontend_bind_virq(
		rm_cap, backend_cfg->vic, virq_get_number(backend_virq));
	if (ret != OK) {
		(void)printf("Failed: to bind BE virq\n");
		goto error_bind_be;
	}

	cfg->backend	   = backend_cfg->vm->vmid;
	cfg->master_cap	   = rm_cap;
	cfg->label	   = d->general.label;
	cfg->frontend_virq = frontend_virq;
	cfg->backend_cap   = backend_cap;
	cfg->backend_virq  = backend_virq;
	cfg->frontend_ipa  = frontend_ipa;
	cfg->backend_ipa   = backend_ipa;
	cfg->dma_base	   = d->dma_base;
	cfg->dma_coherent  = d->dma_coherent;
	cfg->need_allocate = d->need_allocate;
	cfg->base_ipa	   = d->mem_base_ipa;
	cfg->me_cap	   = me_cap;
	cfg->me_size	   = me_size;
	cfg->rm_addr	   = rm_addr;

	list_append(vdevice_node_t, &frontend_cfg->vdevice_nodes, node,
		    vdevice_);

	if (ret == OK) {
		goto out;
	}

error_bind_be:
	err = gunyah_hyp_virtio_mmio_backend_unbind_virq(rm_cap);
	assert(err == OK);
error_bind_fe:
	err = gunyah_hyp_cspace_delete_cap_from(backend_cfg->cspace,
						backend_cap);
	assert(err == OK);
error_backend_cap:
	free(cfg);
error_cfg_alloc:
	free_compatibles(node);
error_push_comp:
	free(node->generate);
error_generate:
	free(node);
out:
	return ret;
}
#endif

static error_t
vm_config_add_msgqueue(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
		       bool tx, interrupt_data_t vm_virq,
		       interrupt_data_t peer_virq, const msg_queue_data_t *data,
		       bool export_to_dt)
{
	vm_config_t *tx_cfg = NULL, *rx_cfg = NULL;

	cap_id_t tx_cap = CSPACE_CAP_INVALID, rx_cap = CSPACE_CAP_INVALID;

	error_t ret;
	error_t err;

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		(void)printf("Failed: to alloc vdevice node\n");
		ret = ERROR_NOMEM;
		goto out;
	}

	node->type	   = VDEV_MSG_QUEUE;
	node->export_to_dt = export_to_dt;
	node->visible	   = true;
	node->handle	   = get_vdevice_resource_handle();

	const char *generate = data->general.generate;
	if (generate != NULL) {
		node->generate = strdup(generate);
	} else {
		node->generate = strdup("/hypervisor/qcom,message-queue");
	}

	if (node->generate == NULL) {
		(void)printf("Failed: to msgqueue alloc generate string\n");
		ret = ERROR_NOMEM;
		goto out;
	}

	err = handle_compatibles(node, &data->general);
	if (err != OK) {
		ret = err;
		(void)printf("Failed: save compatible in msgqueue node\n");
		goto out;
	}

	struct vdevice_msg_queue *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		(void)printf("Failed: to alloc doorbell config\n");
		ret = ERROR_NOMEM;
		goto out;
	}
	node->config = cfg;

	vm_t *peer_vm = vm_lookup(peer);
	if ((peer_vm == NULL) || (peer_vm->vm_config == NULL)) {
		(void)printf("Failed: invalid peer\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	interrupt_data_t tx_virq, rx_virq;
	if (tx) {
		tx_cfg	= vmcfg;
		rx_cfg	= peer_vm->vm_config;
		tx_virq = vm_virq;
		rx_virq = peer_virq;
	} else {
		tx_cfg	= peer_vm->vm_config;
		rx_cfg	= vmcfg;
		tx_virq = peer_virq;
		rx_virq = vm_virq;
	}

	// Copy msgqueue cap to tx VM cspace with send rights
	gunyah_hyp_cspace_copy_cap_from_result_t copy_ret;

	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(), rm_cap,
						   tx_cfg->cspace,
						   CAP_RIGHTS_MSGQUEUE_SEND);
	if (copy_ret.error != OK) {
		(void)printf("Failed: to copy tx cap\n");
		ret = copy_ret.error;
		goto out;
	}
	tx_cap = copy_ret.new_cap;

	// Copy msgqueue cap to rx VM cspace with recv rights
	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(), rm_cap,
						   rx_cfg->cspace,
						   CAP_RIGHTS_MSGQUEUE_RECEIVE);
	if (copy_ret.error != OK) {
		(void)printf("Failed: to copy rx cap\n");
		ret = copy_ret.error;
		goto out;
	}
	rx_cap = copy_ret.new_cap;

	// Bind VIRQs
	ret = gunyah_hyp_msgqueue_bind_send_virq(rm_cap, tx_cfg->vic,
						 virq_get_number(tx_virq));
	if (ret != OK) {
		(void)printf("Failed: to bind tx virq\n");
		goto out;
	}
	ret = gunyah_hyp_msgqueue_bind_receive_virq(rm_cap, rx_cfg->vic,
						    virq_get_number(rx_virq));
	if (ret != OK) {
		(void)printf("Failed: to bind rx virq\n");
		(void)gunyah_hyp_msgqueue_unbind_send_virq(rm_cap);
		goto out;
	}

	cfg->peer	 = peer;
	cfg->tx		 = tx;
	cfg->master_cap	 = rm_cap;
	cfg->queue_depth = data->queue_depth;
	cfg->msg_size	 = data->msg_size;
	cfg->label	 = data->general.label;
	if (tx) {
		cfg->vm_cap    = tx_cap;
		cfg->vm_virq   = tx_virq;
		cfg->peer_cap  = rx_cap;
		cfg->peer_virq = rx_virq;
	} else {
		cfg->vm_cap    = rx_cap;
		cfg->vm_virq   = rx_virq;
		cfg->peer_cap  = tx_cap;
		cfg->peer_virq = tx_virq;
	}

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);

out:
	if ((ret != OK) && (node != NULL)) {
		if (tx_cap != CSPACE_CAP_INVALID) {
			assert(tx_cfg != NULL);
			err = gunyah_hyp_cspace_delete_cap_from(tx_cfg->cspace,
								tx_cap);
			assert(err == OK);
		}

		if (rx_cap != CSPACE_CAP_INVALID) {
			assert(rx_cfg != NULL);
			err = gunyah_hyp_cspace_delete_cap_from(rx_cfg->cspace,
								rx_cap);
			assert(err == OK);
		}

		free(node->config);
		free_compatibles(node);
		free(node->generate);
		free(node);
	}

	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

static error_t
configure_msgqueue_pair(vm_config_t *vmcfg, struct vdevice_msg_queue_pair **cfg,
			cap_id_t rm_tx_cap, cap_id_t rm_rx_cap, bool alloc_irq,
			interrupt_data_t defined_tx_virq,
			interrupt_data_t defined_rx_virq)
{
	error_t ret;

	// Reserve and bind virqs and copy caps

	if (*cfg == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	assert(vmcfg != NULL);
	vmid_t vmid = vmcfg->vm->vmid;

	interrupt_data_t vm_tx_virq = defined_tx_virq;

	if (alloc_irq) {
		uint32_result_t irq_ret = alloc_map_virq(vmid);
		if (irq_ret.e != OK) {
			ret = irq_ret.e;
			goto out;
		}
		vm_tx_virq = virq_edge(irq_ret.r);
	} else {
		ret = map_virq(vmid, virq_get_number(vm_tx_virq));
		if (ret != OK) {
			goto out;
		}
	}

	error_t err;

	interrupt_data_t vm_rx_virq = defined_rx_virq;
	if (alloc_irq) {
		uint32_result_t irq_ret = alloc_map_virq(vmid);
		if (irq_ret.e != OK) {
			ret = irq_ret.e;
			goto out_return_tx_virq;
		}
		vm_rx_virq = virq_edge(irq_ret.r);
	} else {
		ret = map_virq(vmid, virq_get_number(vm_rx_virq));
		if (ret != OK) {
			goto out_return_tx_virq;
		}
	}

	// Copy msgqueue caps to VM cspace
	gunyah_hyp_cspace_copy_cap_from_result_t tx_cap_ret;
	tx_cap_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(),
						     rm_tx_cap, vmcfg->cspace,
						     CAP_RIGHTS_MSGQUEUE_SEND);
	if (tx_cap_ret.error != OK) {
		(void)printf("Failed: to copy cap\n");
		ret = tx_cap_ret.error;
		goto out_return_rx_virq;
	}
	cap_id_t vm_tx_cap = tx_cap_ret.new_cap;

	gunyah_hyp_cspace_copy_cap_from_result_t rx_cap_ret;
	rx_cap_ret = gunyah_hyp_cspace_copy_cap_from(
		rm_get_rm_cspace(), rm_rx_cap, vmcfg->cspace,
		CAP_RIGHTS_MSGQUEUE_RECEIVE);
	if (rx_cap_ret.error != OK) {
		(void)printf("Failed: to copy cap\n");
		ret = rx_cap_ret.error;
		goto out_delete_tx_cap;
	}
	cap_id_t vm_rx_cap = rx_cap_ret.new_cap;

	// Bind virqs to VM's vic
	ret = gunyah_hyp_msgqueue_bind_send_virq(rm_tx_cap, vmcfg->vic,
						 virq_get_number(vm_tx_virq));
	if (ret != OK) {
		(void)printf("Failed: to bind virq\n");
		goto out_delete_rx_cap;
	}

	ret = gunyah_hyp_msgqueue_bind_receive_virq(
		rm_rx_cap, vmcfg->vic, virq_get_number(vm_rx_virq));
	if (ret != OK) {
		(void)printf("Failed: to bind virq\n");
		goto out_unbind_tx_virq;
	}

	(*cfg)->tx_vm_cap  = vm_tx_cap;
	(*cfg)->rx_vm_cap  = vm_rx_cap;
	(*cfg)->tx_vm_virq = vm_tx_virq;
	(*cfg)->rx_vm_virq = vm_rx_virq;

	goto out;

out_unbind_tx_virq:
	err = gunyah_hyp_msgqueue_unbind_send_virq(rm_tx_cap);
	assert(err == OK);
out_delete_rx_cap:
	err = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace, vm_rx_cap);
	assert(err == OK);
out_delete_tx_cap:
	err = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace, vm_tx_cap);
	assert(err == OK);
out_return_rx_virq:
	revert_map_virq(vmid, virq_get_number(vm_rx_virq));
out_return_tx_virq:
	revert_map_virq(vmid, virq_get_number(vm_tx_virq));
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

static error_t
vm_config_check_peer(char *peer_id, vm_t *peer_vm)
{
	error_t ret = OK;

	if (peer_id == NULL) {
		(void)printf("error: invalid peer argument\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}
	// when we have peer, we can double check if peer is expected
	vm_t *expected_vm = vm_lookup_by_id(peer_id);
	if ((expected_vm == NULL) || (expected_vm != peer_vm)) {
		(void)printf("error: invalid peer\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

out:
	return ret;
}

static error_t
vm_config_add_msgqueue_pair(vm_config_t *vmcfg, msg_queue_pair_data_t *data,
			    cap_id_t rm_tx_cap, cap_id_t rm_rx_cap,
			    struct vdevice_msg_queue_pair *peer_cfg,
			    vm_t *peer_vm, resource_handle_t handle)
{
	error_t ret;

	assert((peer_vm != NULL) || (peer_cfg == NULL));

	interrupt_data_t vm_tx_virq = VIRQ_INVALID, vm_rx_virq = VIRQ_INVALID;
	cap_id_t tx_vm_cap = CSPACE_CAP_INVALID, rx_vm_cap = CSPACE_CAP_INVALID;
	vmid_t	 self = vmcfg->vm->vmid;

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		(void)printf("Failed: to alloc vdevice node\n");
		ret = ERROR_NOMEM;
		goto out;
	}

	node->type	   = VDEV_MSG_QUEUE_PAIR;
	node->export_to_dt = true;
	node->visible	   = true;
	node->handle	   = handle;

	ret = handle_compatibles(node, &data->general);
	if (ret != OK) {
		(void)printf("Failed: to alloc push compatibles\n");
		goto out_free_node;
	}

	if (data->general.generate != NULL) {
		node->generate = strdup(data->general.generate);
	} else {
		node->generate = strdup("/hypervisor/qcom,message-queue-pair");
	}
	if (node->generate == NULL) {
		(void)printf(
			"Failed: to msgqueue_pair alloc generate string\n");
		ret = ERROR_NOMEM;
		goto out_free_compatible;
	}

	struct vdevice_msg_queue_pair *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		(void)printf("Failed: to alloc msgqueue_pair config\n");
		ret = ERROR_NOMEM;
		goto out_free_generate;
	}
	node->config = cfg;

	if (data->defined_irq) {
		vm_tx_virq = data->irqs[TX_IRQ_IDX];
		vm_rx_virq = data->irqs[RX_IRQ_IDX];
	}

	ret = configure_msgqueue_pair(vmcfg, &cfg, rm_tx_cap, rm_rx_cap,
				      !data->defined_irq, vm_tx_virq,
				      vm_rx_virq);
	if (ret != OK) {
		goto out_free_cfg;
	}

	cfg->tx_master_cap = rm_tx_cap;
	cfg->rx_master_cap = rm_rx_cap;

	cfg->tx_queue_depth  = data->queue_depth;
	cfg->rx_queue_depth  = data->queue_depth;
	cfg->tx_max_msg_size = data->msg_size;
	cfg->rx_max_msg_size = data->msg_size;

	cfg->label = data->general.label;

	if (data->peer_id != NULL) {
		cfg->peer_id = strdup(data->peer_id);
		if (cfg->peer_id == NULL) {
			ret = ERROR_NOMEM;
			goto out_free_cfg;
		}
	} else {
		cfg->peer_id = NULL;
	}

	if ((peer_cfg != NULL) && !check_default_peer(vmcfg, peer_vm)) {
		ret = vm_config_check_peer(peer_cfg->peer_id, vmcfg->vm);
		if (ret != OK) {
			goto out_free_peer_id;
		}
	}

	if (check_default_peer(vmcfg, peer_vm)) {
		// Since "peer-default" is used in the DT node, its peer does
		// not have a correspoding vdevice for the msgqueue_pair. We
		// need to create a temporal vdevice to later update the values
		// of self.

		assert(peer_vm != NULL);
		assert(peer_cfg == NULL);

		peer_cfg = calloc(1, sizeof(*peer_cfg));
		if (peer_cfg == NULL) {
			(void)printf("Failed: to alloc peer_cfg\n");
			goto out_teardown_vm_msgqueue_pair;
		}

		peer_cfg->tx_queue_depth  = data->queue_depth;
		peer_cfg->rx_queue_depth  = data->queue_depth;
		peer_cfg->tx_max_msg_size = data->msg_size;
		peer_cfg->rx_max_msg_size = data->msg_size;

		// What is tx for self is rx for peer and viceversa
		ret = configure_msgqueue_pair(peer_vm->vm_config, &peer_cfg,
					      rm_rx_cap, rm_tx_cap, true,
					      VIRQ_INVALID, VIRQ_INVALID);
		if (ret != OK) {
			goto out_free_default_peer_cfg;
		}

		// No peer vdevice exists when using peer-default
		cfg->has_peer_vdevice = false;
	} else {
		// Peer VM also has a vdevice node for this msgqueue pair
		cfg->has_peer_vdevice = true;
	}

	cfg->has_valid_peer = false;

	if (peer_cfg != NULL) {
		if ((peer_cfg->tx_queue_depth != cfg->rx_queue_depth) &&
		    (peer_cfg->rx_queue_depth != cfg->tx_queue_depth) &&
		    (peer_cfg->tx_max_msg_size != cfg->rx_max_msg_size) &&
		    (peer_cfg->rx_max_msg_size != cfg->tx_max_msg_size)) {
			(void)printf(
				"msg_queue_pair: msg_size/queue_depth is not "
				"identical between two VMs\n");
			goto out_invalid_msg_queue_pair_argument;
		}

		// Update self with peer info
		cfg->peer	    = peer_vm->vmid;
		cfg->tx_peer_cap    = peer_cfg->tx_vm_cap;
		cfg->rx_peer_cap    = peer_cfg->rx_vm_cap;
		cfg->tx_peer_virq   = peer_cfg->tx_vm_virq;
		cfg->rx_peer_virq   = peer_cfg->rx_vm_virq;
		cfg->has_valid_peer = true;

		// Update peer with self info
		peer_cfg->peer		 = self;
		peer_cfg->tx_peer_cap	 = tx_vm_cap;
		peer_cfg->rx_peer_cap	 = rx_vm_cap;
		peer_cfg->tx_peer_virq	 = vm_tx_virq;
		peer_cfg->rx_peer_virq	 = vm_rx_virq;
		peer_cfg->has_valid_peer = true;
	}

	// Allow trusted VMs to peer with HLOS. This is allowed as the HLOS vmid
	// does not change. Use this for discovering peer vdevices to set up.
	if (vmcfg->trusted_config && (peer_vm != NULL) &&
	    (peer_vm->vmid == VMID_HLOS)) {
		cfg->peer = peer_vm->vmid;
	}

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);

out_invalid_msg_queue_pair_argument:
out_free_default_peer_cfg:
	if (check_default_peer(vmcfg, peer_vm) && (peer_cfg != NULL)) {
		free(peer_cfg);
	}
	if (ret == OK) {
		goto out;
	}
out_teardown_vm_msgqueue_pair:
	handle_msgqueue_pair_destruction(vmcfg, &node);
out_free_peer_id:
	if (cfg->peer_id != NULL) {
		free(cfg->peer_id);
	}
out_free_cfg:
	free(cfg);
out_free_generate:
	if ((node != NULL) && (node->generate != NULL)) {
		free(node->generate);
	}
out_free_compatible:
	if (node != NULL) {
		free_compatibles(node);
	}
out_free_node:
	free(node);
out:
	return ret;
}

static error_t
vm_config_add_rm_rpc(vm_config_t *vmcfg, rm_rpc_data_t *data, cap_id_t rx,
		     cap_id_t tx)
{
	vdevice_node_t *rpc_node;

	vmid_t peer = VMID_RM;

	interrupt_data_t rm_tx_virq = VIRQ_INVALID, rm_rx_virq = VIRQ_INVALID;
	interrupt_data_t vm_tx_virq = VIRQ_INVALID, vm_rx_virq = VIRQ_INVALID;
	error_t		 ret = OK;

	assert(vmcfg != NULL);
	assert(vmcfg->vm != NULL);

	vmid_t			       self = vmcfg->vm->vmid;
	struct vdevice_msg_queue_pair *cfg  = NULL;

	rpc_node = calloc(1, sizeof(*rpc_node));
	if (rpc_node == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	rpc_node->type	       = VDEV_RM_RPC;
	rpc_node->export_to_dt = true;
	rpc_node->visible      = false;

	// no need to have handle since it's never returned by GET_HYP_RESOURCE
	rpc_node->handle = 0;

	ret = handle_compatibles(rpc_node, &data->general);
	if (ret != OK) {
		(void)printf("Failed: to alloc push compatibles\n");
		goto out_free_node;
	}

	rpc_node->generate = strdup(data->general.generate);
	if (rpc_node->generate == NULL) {
		ret = ERROR_NOMEM;
		goto out_free_compatible;
	}

	rpc_node->config = calloc(1, sizeof(*cfg));
	if (rpc_node->config == NULL) {
		ret = ERROR_NOMEM;
		goto out_free_generate;
	}

	cfg = (struct vdevice_msg_queue_pair *)rpc_node->config;

	uint32_result_t irq_ret = alloc_map_virq(peer);
	if (irq_ret.e != OK) {
		ret = irq_ret.e;
		goto out_free_config;
	}
	rm_tx_virq = virq_edge(irq_ret.r);

	irq_ret = alloc_map_virq(peer);
	if (irq_ret.e != OK) {
		ret = irq_ret.e;
		goto out_return_rm_tx_virq;
	}
	rm_rx_virq = virq_edge(irq_ret.r);

	error_t err;

	if (data->defined_irq) {
		vm_tx_virq = data->irqs[TX_IRQ_IDX];
		ret	   = map_virq(self, virq_get_number(vm_tx_virq));
		if (ret != OK) {
			goto out_return_rm_rx_virq;
		}
	} else {
		irq_ret = alloc_map_virq(self);
		if (irq_ret.e != OK) {
			ret = irq_ret.e;
			goto out_return_rm_rx_virq;
		}
		vm_tx_virq = virq_edge(irq_ret.r);
	}

	if (data->defined_irq) {
		vm_rx_virq = data->irqs[RX_IRQ_IDX];
		ret	   = map_virq(self, virq_get_number(vm_rx_virq));
		if (ret != OK) {
			goto out_return_vm_tx_virq;
		}
	} else {
		irq_ret = alloc_map_virq(self);
		if (irq_ret.e != OK) {
			ret = irq_ret.e;
			goto out_return_rm_rx_virq;
		}
		vm_rx_virq = virq_edge(irq_ret.r);
	}

	cfg->peer = VMID_RM;

	// Create msgqueue pair for transport
	cfg->rx_master_cap = rx;
	cfg->tx_peer_cap   = cfg->rx_master_cap;

	cfg->tx_master_cap = tx;
	cfg->rx_peer_cap   = cfg->tx_master_cap;

	cfg->tx_queue_depth  = data->queue_depth;
	cfg->rx_queue_depth  = data->queue_depth;
	cfg->tx_max_msg_size = data->msg_size;
	cfg->rx_max_msg_size = data->msg_size;

	cfg->rx_vm_cap = CSPACE_CAP_INVALID;
	cfg->tx_vm_cap = CSPACE_CAP_INVALID;

	// since it's communicated with RM, no peer vdevice as well
	cfg->has_peer_vdevice = false;

	// Copy msgqueue caps to VM cspace
	gunyah_hyp_cspace_copy_cap_from_result_t copy_ret;

	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(),
						   cfg->tx_master_cap,
						   vmcfg->cspace,
						   CAP_RIGHTS_MSGQUEUE_SEND);
	if (copy_ret.error != OK) {
		ret = copy_ret.error;
		goto out_return_vm_rx_virq;
	}
	cfg->tx_vm_cap = copy_ret.new_cap;

	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(),
						   cfg->rx_master_cap,
						   vmcfg->cspace,
						   CAP_RIGHTS_MSGQUEUE_RECEIVE);
	if (copy_ret.error != OK) {
		ret = copy_ret.error;
		goto out_delete_cap_tx_vm;
	}

	cfg->rx_vm_cap = copy_ret.new_cap;

	// Bind virqs to RM's vic
	ret = gunyah_hyp_msgqueue_bind_receive_virq(
		cfg->tx_master_cap, rm_get_rm_vic(),
		virq_get_number(rm_rx_virq));
	if (ret != OK) {
		goto out_delete_cap_rx_vm;
	}
	cfg->rx_peer_virq = rm_rx_virq;

	ret = gunyah_hyp_msgqueue_bind_send_virq(cfg->rx_master_cap,
						 rm_get_rm_vic(),
						 virq_get_number(rm_tx_virq));
	if (ret != OK) {
		goto out_unbind_rm_rx_virq;
	}
	cfg->tx_peer_virq = rm_tx_virq;

	// Bind virqs to VM's vic
	ret = gunyah_hyp_msgqueue_bind_send_virq(cfg->tx_master_cap, vmcfg->vic,
						 virq_get_number(vm_tx_virq));
	if (ret != OK) {
		goto out_unbind_rm_tx_virq;
	}
	cfg->tx_vm_virq = vm_tx_virq;

	ret = gunyah_hyp_msgqueue_bind_receive_virq(
		cfg->rx_master_cap, vmcfg->vic, virq_get_number(vm_rx_virq));
	if (ret != OK) {
		goto out_unbind_vm_tx_virq;
	}
	cfg->rx_vm_virq = vm_rx_virq;

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, rpc_node, vdevice_);

	if (ret == OK) {
		goto out;
	}

out_unbind_vm_tx_virq:
	err = gunyah_hyp_msgqueue_unbind_send_virq(cfg->tx_master_cap);
	assert(err == OK);
out_unbind_rm_tx_virq:
	err = gunyah_hyp_msgqueue_unbind_send_virq(cfg->rx_master_cap);
	assert(err == OK);
out_unbind_rm_rx_virq:
	err = gunyah_hyp_msgqueue_unbind_receive_virq(cfg->tx_master_cap);
	assert(err == OK);
out_delete_cap_rx_vm:
	err = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace, cfg->rx_vm_cap);
	assert(err == OK);
out_delete_cap_tx_vm:
	err = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace, cfg->tx_vm_cap);
	assert(err == OK);
out_return_vm_rx_virq:
	revert_map_virq(self, virq_get_number(vm_rx_virq));
out_return_vm_tx_virq:
	revert_map_virq(self, virq_get_number(vm_tx_virq));
out_return_rm_rx_virq:
	revert_map_virq(peer, virq_get_number(rm_rx_virq));
out_return_rm_tx_virq:
	revert_map_virq(peer, virq_get_number(rm_tx_virq));
out_free_config:
	free(rpc_node->config);
out_free_generate:
	free(rpc_node->generate);
out_free_compatible:
	for (index_t i = 0; i < rpc_node->push_compatible_num; ++i) {
		free(rpc_node->push_compatible[i]);
	}
out_free_node:
	free(rpc_node);
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

static error_t
vm_config_add_shm(vm_config_t *vmcfg, shm_data_t *data, vdevice_node_t *db,
		  vdevice_node_t *db_src)
{
	error_t ret  = OK;
	vmid_t	peer = get_peer(vmcfg, data->peer);

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		(void)printf("Failed: to alloc vdevice node\n");
		ret = ERROR_NOMEM;
		goto out;
	}

	node->type	   = VDEV_SHM;
	node->export_to_dt = true;
	node->visible	   = false;

	if (data->general.generate != NULL) {
		node->generate = strdup(data->general.generate);
	} else {
		node->generate = strdup("/hypervisor/qcom,shm");
	}

	if (node->generate == NULL) {
		(void)printf("Failed: to shm alloc generate string\n");
		ret = ERROR_NOMEM;
		goto out;
	}

	ret = handle_compatibles(node, &data->general);
	if (ret != OK) {
		(void)printf("Failed: save compatible in shm node\n");
		goto out;
	}

	struct vdevice_shm *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		(void)printf("Failed: to alloc doorbell config\n");
		ret = ERROR_NOMEM;
		goto out;
	}
	node->config = cfg;

	vm_t *peer_vm = vm_lookup(peer);
	if (peer_vm == NULL) {
		(void)printf("Failed: invalid peer\n");
		ret = ERROR_DENIED;
		goto out;
	}

	cfg->peer  = peer;
	cfg->label = data->general.label;

	cfg->is_memory_optional = data->is_memory_optional;

	cfg->need_allocate = data->need_allocate;

	cfg->base_ipa = data->mem_base_ipa;

	cfg->is_plain_shm = data->is_plain_shm;
	cfg->dma_base	  = data->dma_base;

	if (!cfg->is_plain_shm) {
		assert(db != NULL);
		assert(db_src != NULL);

		cfg->db	    = db;
		cfg->db_src = db_src;
	}

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);

out:
	if ((ret != OK) && (node != NULL)) {
		free_compatibles(node);
		free(node->generate);
		free(node->config);
		free(node);
	}
	return ret;
}

#if defined(CAP_RIGHTS_WATCHDOG_ALL)
static error_t
vm_config_add_watchdog(vm_config_t *vmcfg, cap_id_t rm_cap,
		       interrupt_data_t bark_virq, bool allow_management)
{
	error_t ret;

	if (vmcfg->watchdog == CSPACE_CAP_INVALID) {
		ret = ERROR_DENIED;
		goto out;
	}

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	ret = vm_config_check_watchdog_vdevice(vmcfg);
	if (ret != OK) {
		goto err_attach_vdevice;
	}

	// If no bind options are set, it will assume that its a bark virq
	watchdog_bind_option_flags_t bind_bark_options =
		watchdog_bind_option_flags_default();

	// Bind the watchdog bark vIRQ to VM's VIC
	ret = gunyah_hyp_watchdog_bind_virq(vmcfg->watchdog, vmcfg->vic,
					    virq_get_number(bark_virq),
					    bind_bark_options);
	if (ret != OK) {
		goto err_bind_bark_virq;
	}

	error_t err;

	uint32_result_t irq_ret = alloc_map_virq(VMID_RM);
	if (irq_ret.e != OK) {
		ret = irq_ret.e;
		goto err_reserve_virq;
	}
	interrupt_data_t bite_virq = virq_edge(irq_ret.r);

	watchdog_bind_option_flags_t bind_bite_options =
		watchdog_bind_option_flags_default();
	watchdog_bind_option_flags_set_bite_virq(&bind_bite_options, true);

	// Bind the watchdog bite virq to RM's vic
	ret = gunyah_hyp_watchdog_bind_virq(vmcfg->watchdog, rm_get_rm_vic(),
					    virq_get_number(bite_virq),
					    bind_bite_options);
	if (ret != OK) {
		goto err_bind_bite_virq;
	}

	// Register event to handle watchdog bite virq
	rm_error_t rm_err = vm_mgnt_register_event(VM_EVENT_SRC_WDOG_BITE,
						   &vmcfg->vm->wdog_bite_event,
						   vmcfg->vm,
						   virq_get_number(bite_virq));
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
		goto err_register_event;
	}

	node->type	   = VDEV_WATCHDOG;
	node->export_to_dt = true;
	node->visible	   = true;
	node->generate = strdup("/hypervisor/qcom,gh-watchdog");

	if (node->generate == NULL) {
		ret = ERROR_NOMEM;
		goto err_generate_strdup;
	}

	cap_id_t     manager_cap = CSPACE_CAP_INVALID;
	vmid_t	     manager = allow_management ? (vmcfg->vm->owner) : VMID_HYP;
	vm_config_t *manager_cfg = NULL;
	if (manager != VMID_HYP) {
		vm_t *manager_vm = vm_lookup(manager);
		if ((manager_vm == NULL) || (manager_vm->vm_config == NULL)) {
			(void)printf("Failed: invalid owner VM\n");
			ret = ERROR_ARGUMENT_INVALID;
			goto err_copy_mgnt_cap;
		}

		manager_cfg = manager_vm->vm_config;
		gunyah_hyp_cspace_copy_cap_from_result_t copy_ret;

		cap_rights_t rights = CAP_RIGHTS_WATCHDOG_MANAGE;

		copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(),
							   rm_cap,
							   manager_cfg->cspace,
							   rights);
		if (copy_ret.error != OK) {
			(void)printf("Failed: copy vcpu cap from rm cspace\n");
			ret = copy_ret.error;
			goto err_copy_mgnt_cap;
		}

		manager_cap = copy_ret.new_cap;
	}

	struct vdevice_watchdog *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		ret = ERROR_NOMEM;
		goto err_allocate_cfg;
	}

	assert(cfg != NULL);
	cfg->bark_virq	 = bark_virq;
	cfg->bite_virq	 = bite_virq;
	cfg->manager	 = manager;
	cfg->manager_cap = manager_cap;
	node->config	 = cfg;

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);
	ret = OK;
	goto out;

err_allocate_cfg:
	if (manager != VMID_HYP) {
		assert(manager_cfg != NULL);
		err = gunyah_hyp_cspace_delete_cap_from(manager_cfg->cspace,
							manager_cap);
		assert(err == OK);
	}
err_copy_mgnt_cap:
	free(node->generate);
err_generate_strdup:
	vm_mgnt_deregister_event(&vmcfg->vm->wdog_bite_event,
				 virq_get_number(bite_virq));
err_register_event:
	err = gunyah_hyp_watchdog_unbind_virq(vmcfg->watchdog,
					      bind_bite_options);
	assert(err == OK);
err_bind_bite_virq:
	revert_map_virq(VMID_RM, virq_get_number(bite_virq));
err_reserve_virq:
	err = gunyah_hyp_watchdog_unbind_virq(vmcfg->watchdog,
					      bind_bark_options);
	assert(err == OK);
err_bind_bark_virq:
err_attach_vdevice:
	free(node);
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}
#endif

static cap_id_result_t
create_doorbell(void)
{
	cap_id_result_t ret;

	gunyah_hyp_partition_create_doorbell_result_t create_ret;

	create_ret = gunyah_hyp_partition_create_doorbell(rm_get_rm_partition(),
							  rm_get_rm_cspace());
	if (create_ret.error != OK) {
		ret = cap_id_result_error(create_ret.error);
		goto out;
	}

	error_t err = gunyah_hyp_object_activate(create_ret.new_cap);
	if (err != OK) {
		ret = cap_id_result_error(err);
		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							create_ret.new_cap);
		assert(err == OK);
		goto out;
	}

	ret = cap_id_result_ok(create_ret.new_cap);
out:
	return ret;
}

static cap_id_result_t
create_msgqueue(uint16_t queue_depth, uint16_t msg_size)
{
	cap_id_result_t ret;

	gunyah_hyp_partition_create_msgqueue_result_t create_ret;

	create_ret = gunyah_hyp_partition_create_msgqueue(rm_get_rm_partition(),
							  rm_get_rm_cspace());
	if (create_ret.error != OK) {
		ret = cap_id_result_error(create_ret.error);
		goto out;
	}

	msgqueue_create_info_t msgqueue_info = msgqueue_create_info_default();
	msgqueue_create_info_set_queue_depth(&msgqueue_info, queue_depth);
	msgqueue_create_info_set_max_msg_size(&msgqueue_info, msg_size);

	error_t err = gunyah_hyp_msgqueue_configure(create_ret.new_cap,
						    msgqueue_info);
	if (err != OK) {
		ret = cap_id_result_error(err);
		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							create_ret.new_cap);
		assert(err == OK);
		goto out;
	}

	err = gunyah_hyp_object_activate(create_ret.new_cap);
	if (err != OK) {
		ret = cap_id_result_error(err);
		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							create_ret.new_cap);
		assert(err == OK);
		goto out;
	}

	ret = cap_id_result_ok(create_ret.new_cap);

out:
	return ret;
}

static error_t
add_msgqueue(vm_config_t *vmcfg, msg_queue_data_t *data, bool is_sender,
	     interrupt_data_t self_virq, bool alloc_self_virq,
	     interrupt_data_t peer_virq, bool alloc_peer_virq)
{
	error_t ret = OK;

	cap_id_result_t mq = create_msgqueue(data->queue_depth, data->msg_size);
	if (mq.e != OK) {
		ret = mq.e;
		goto out;
	}

	vmid_t peer = get_peer(vmcfg, data->peer);
	vmid_t self = vmcfg->vm->vmid;

	error_t err;

	interrupt_data_t svirq = self_virq;
	if (alloc_self_virq) {
		uint32_result_t irq_ret = alloc_map_virq(self);
		if (irq_ret.e != OK) {
			ret = irq_ret.e;
			goto out_destroy_msq;
		}
		svirq = virq_edge(irq_ret.r);
	} else {
		ret = map_virq(self, virq_get_number(svirq));
		if (ret != OK) {
			goto out_destroy_msq;
		}
	}

	interrupt_data_t pvirq = peer_virq;
	if (alloc_peer_virq) {
		// or else it will get the same virq number
		assert(peer != self);

		uint32_result_t irq_ret = alloc_map_virq(peer);
		if (irq_ret.e != OK) {
			ret = irq_ret.e;
			goto out_return_virq;
		}
		pvirq = virq_edge(irq_ret.r);
	} else {
		ret = map_virq(peer, virq_get_number(pvirq));
		if (ret != OK) {
			goto out_return_virq;
		}
	}

	ret = vm_config_add_msgqueue(vmcfg, peer, mq.r, is_sender, svirq, pvirq,
				     data, true);

	if (ret == OK) {
		goto out;
	}

	revert_map_virq(peer, virq_get_number(pvirq));
out_return_virq:
	revert_map_virq(self, virq_get_number(svirq));
out_destroy_msq:
	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), mq.r);
	assert(err == OK);
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

static error_t
handle_msgqueue(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;
	size_t	cnt = vector_size(data->msg_queues);

	for (index_t i = 0; i < cnt; ++i) {
		msg_queue_data_t *d =
			vector_at_ptr(msg_queue_data_t, data->msg_queues, i);

		interrupt_data_t virq = d->defined_irq ? d->irqs[0]
						       : VIRQ_INVALID;
		ret = add_msgqueue(vmcfg, d, d->is_sender, virq,
				   !d->defined_irq, VIRQ_INVALID, true);
		if (ret != OK) {
			goto out;
		}
	}

out:
	return ret;
}

static error_t
create_msgqueue_pair(msg_queue_pair_data_t *d, cap_id_t *tx, cap_id_t *rx,
		     vm_t *peer_vm, struct vdevice_msg_queue_pair **peer_cfg,
		     resource_handle_t *handle, bool is_default_peer)
{
	error_t ret;

	if ((peer_vm == NULL) || (peer_vm->vm_config == NULL) ||
	    is_default_peer) {
		// Create msgqueues on the first VM that contains the
		// message-queue-pair vdevice DT node
		cap_id_result_t res =
			create_msgqueue(d->queue_depth, d->msg_size);
		if (res.e != OK) {
			ret = res.e;
			goto out;
		}
		*tx = res.r;

		res = create_msgqueue(d->queue_depth, d->msg_size);
		if (res.e != OK) {
			ret = res.e;
			goto out_destroy_tx_msgq;
		}
		*rx = res.r;

		*handle = get_vdevice_resource_handle();
	} else {
		// Find peer's msgqueue_pair vdevice
		vdevice_node_t		      *node	    = NULL;
		struct vdevice_msg_queue_pair *msg_pair_cfg = NULL;

		loop_list(node, &peer_vm->vm_config->vdevice_nodes, vdevice_)
		{
			if (node->type == VDEV_MSG_QUEUE_PAIR) {
				msg_pair_cfg = (struct vdevice_msg_queue_pair *)
						       node->config;
				if ((msg_pair_cfg->label == d->general.label) &&
				    (msg_pair_cfg->tx_max_msg_size ==
				     d->msg_size) &&
				    (msg_pair_cfg->tx_queue_depth ==
				     d->queue_depth)) {
					break;
				}
				msg_pair_cfg = NULL;
			}
		}

		if (msg_pair_cfg == NULL) {
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}

		// What is tx for self is rx for peer and viceversa
		*tx = msg_pair_cfg->rx_master_cap;
		*rx = msg_pair_cfg->tx_master_cap;

		*peer_cfg = msg_pair_cfg;

		*handle = node->handle;
	}

	ret = OK;

	goto out;

out_destroy_tx_msgq:
	if (peer_vm == NULL) {
		error_t err = gunyah_hyp_cspace_delete_cap_from(
			rm_get_rm_cspace(), *tx);
		assert(err == OK);
	}
out:
	return ret;
}

static error_t
handle_msgqueue_pair(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;
	size_t	cnt = vector_size(data->msg_queue_pairs);

	for (index_t i = 0; i < cnt; ++i) {
		msg_queue_pair_data_t *d = vector_at_ptr(
			msg_queue_pair_data_t, data->msg_queue_pairs, i);

		assert(d != NULL);

		cap_id_t rm_tx_cap			= CSPACE_CAP_INVALID,
			 rm_rx_cap			= CSPACE_CAP_INVALID;
		struct vdevice_msg_queue_pair *peer_cfg = NULL;
		vm_t			      *peer_vm	= NULL;

		// handles arguments here if possible
		if (d->peer_id != NULL) {
			// Non-default peer
			// Check if peer exists, if so, register them as peers
			peer_vm = vm_lookup_by_id(d->peer_id);
			if (peer_vm != NULL) {
				ret = vm_register_peers(vmcfg->vm, peer_vm);
				if (ret != OK) {
					goto out;
				}
			}

			// else leave peer_VM as NULL, and just partially
			// configure the message queue pair
		} else {
			// currently we only allowed peer to be default
			assert(d->peer == VMID_PEER_DEFAULT);

			vmid_t peer = get_peer(vmcfg, d->peer);
			peer_vm	    = vm_lookup(peer);
			if ((peer_vm == NULL) || (peer_vm->vm_config == NULL)) {
				(void)printf("Failed: to find peer VM(%d)\n",
					     peer);
				ret = ERROR_ARGUMENT_INVALID;
				goto out;
			}
		}

		if (peer_vm == vmcfg->vm) {
			assert(vmcfg->vm != NULL);
			(void)printf(
				"msgqueue_pair: cannot setup peer as itself\n");
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}

		resource_handle_t handle = 0;

		ret = create_msgqueue_pair(d, &rm_tx_cap, &rm_rx_cap, peer_vm,
					   &peer_cfg, &handle,
					   check_default_peer(vmcfg, peer_vm));
		if (ret != OK) {
			goto out;
		}

		ret = vm_config_add_msgqueue_pair(vmcfg, d, rm_tx_cap,
						  rm_rx_cap, peer_cfg, peer_vm,
						  handle);
		if (ret != OK) {
			goto out;
		}
	}

out:
	return ret;
}

static error_t
configure_doorbell_with_peer(const vm_config_t	     *vmcfg,
			     struct vdevice_doorbell *cfg, cap_id_t rm_cap,
			     bool alloc_irq, interrupt_data_t defined_virq)
{
	error_t ret;

	// Reserve and bind virqs and copy caps

	assert(cfg != NULL);
	assert(vmcfg != NULL);
	vmid_t vmid = vmcfg->vm->vmid;

	interrupt_data_t vm_virq = defined_virq;

	cap_rights_t rights_mask;
	if (cfg->source) {
		// Copy doorbell cap to source VM cspace with send rights
		rights_mask = CAP_RIGHTS_DOORBELL_SEND |
			      (cfg->source_can_clear
				       ? CAP_RIGHTS_DOORBELL_RECEIVE
				       : 0U);

		cfg->vm_virq = (interrupt_data_t){ 0 };
	} else {
		if (alloc_irq) {
			uint32_result_t irq_ret = alloc_map_virq(vmid);
			if (irq_ret.e != OK) {
				ret = irq_ret.e;
				goto out;
			}
			vm_virq = virq_edge(irq_ret.r);
		} else {
			ret = map_virq(vmid, virq_get_number(vm_virq));
			if (ret != OK) {
				goto out;
			}
		}

		// Copy doorbell cap to recv VM cspace with receive rights
		rights_mask = CAP_RIGHTS_DOORBELL_RECEIVE;
	}

	gunyah_hyp_cspace_copy_cap_from_result_t copy_ret =
		gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(), rm_cap,
						vmcfg->cspace, rights_mask);
	if (copy_ret.error != OK) {
		(void)printf("Failed: to copy dbl cap\n");
		ret = copy_ret.error;
		goto out_return_virq;
	}
	cap_id_t vm_cap = copy_ret.new_cap;

	if (!cfg->source) {
		// Bind VIRQ to recv VM's VIC
		ret = gunyah_hyp_doorbell_bind_virq(rm_cap, vmcfg->vic,
						    virq_get_number(vm_virq));
		if (ret != OK) {
			(void)printf("Failed: to bind dbl virq\n");
			goto out_delete_cap;
		}
		cfg->vm_virq = vm_virq;
	}

	cfg->vm_cap = vm_cap;
	ret	    = OK;

out_delete_cap:
	if (ret != OK) {
		error_t err = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace,
								vm_cap);
		assert(err == OK);
	}
out_return_virq:
	if ((ret != OK) && (!cfg->source)) {
		revert_map_virq(vmid, virq_get_number(vm_virq));
	}
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

static error_t
vm_config_add_doorbell_with_peer_config_vdevice(
	vm_config_t *vmcfg, const doorbell_data_t *data, cap_id_t rm_cap,
	struct vdevice_doorbell *peer_cfg, vm_t *peer_vm, vdevice_node_t *node)
{
	error_t ret;

	interrupt_data_t vm_virq = VIRQ_INVALID;
	cap_id_t	 vm_cap	 = CSPACE_CAP_INVALID;
	vmid_t		 self	 = vmcfg->vm->vmid;

	struct vdevice_doorbell *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		(void)printf("Failed: to alloc doorbell config\n");
		ret = ERROR_NOMEM;
		goto out;
	}
	node->config = cfg;

	if (data->defined_irq) {
		vm_virq = data->irq;
	}

	cfg->source	      = data->is_source;
	cfg->source_can_clear = data->source_can_clear;
	ret		      = configure_doorbell_with_peer(vmcfg, cfg, rm_cap,
							     !data->defined_irq, vm_virq);
	if (ret != OK) {
		goto out_free_cfg;
	}

	cfg->master_cap = rm_cap;
	cfg->label	= data->general.label;
	cfg->peer_id	= NULL;

	if (data->peer_id != NULL) {
		cfg->peer_id = strdup(data->peer_id);
		if (cfg->peer_id == NULL) {
			ret = ERROR_NOMEM;
			goto out_free_cfg;
		}
	}

	if ((peer_cfg != NULL) && !check_default_peer(vmcfg, peer_vm)) {
		ret = vm_config_check_peer(peer_cfg->peer_id, vmcfg->vm);
		if (ret != OK) {
			goto out_free_peer_id;
		}
	}

	bool peer_cfg_alloc = false;
	if (check_default_peer(vmcfg, peer_vm)) {
		// Since "peer-default" is used in the DT node, its peer does
		// not have a correspoding vdevice for the doorbell. We
		// need to create a temporal vdevice to later update the values
		// of self.

		assert(peer_vm != NULL);
		assert(peer_cfg == NULL);

		peer_cfg = calloc(1, sizeof(*peer_cfg));
		if (peer_cfg == NULL) {
			(void)printf("Failed: to alloc peer_cfg\n");
			goto out_teardown_vm_dbl;
		}

		peer_cfg_alloc = true;

		// if we are 'source' peer is 'destination'
		peer_cfg->source	   = !data->is_source;
		peer_cfg->source_can_clear = data->source_can_clear;
		ret = configure_doorbell_with_peer(peer_vm->vm_config, peer_cfg,
						   rm_cap, true, VIRQ_INVALID);
		if (ret != OK) {
			goto out_free_default_peer_cfg;
		}

		// No peer vdevice exists when using peer-default
		cfg->has_peer_vdevice = false;
	} else {
		// Peer VM also has a vdevice node for this doorbell
		cfg->has_peer_vdevice = true;
	}

	cfg->has_valid_peer = false;

	if (peer_cfg != NULL) {
		if ((peer_cfg->label != cfg->label) &&
		    (peer_cfg->source == cfg->source) &&
		    (peer_cfg->source_can_clear != cfg->source_can_clear)) {
			(void)printf(
				"doorbell: config not identical between two VMs\n");
			goto out_invalid_dbl_argument;
		}

		// Update self with peer info
		cfg->peer	    = peer_vm->vmid;
		cfg->peer_cap	    = peer_cfg->vm_cap;
		cfg->peer_virq	    = peer_cfg->vm_virq;
		cfg->has_valid_peer = true;

		// Update peer with self info
		peer_cfg->peer		 = self;
		peer_cfg->peer_cap	 = vm_cap;
		peer_cfg->peer_virq	 = vm_virq;
		peer_cfg->has_valid_peer = true;
	}

	// Allow trusted VMs to peer with HLOS. This is allowed as the HLOS vmid
	// does not change. Use this for discovering peer vdevices to set up.
	if (vmcfg->trusted_config && (peer_vm != NULL) &&
	    (peer_vm->vmid == VMID_HLOS)) {
		cfg->peer = peer_vm->vmid;
	}

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);

out_invalid_dbl_argument:
out_free_default_peer_cfg:
	if (peer_cfg_alloc) {
		free(peer_cfg);
	}
	if (ret == OK) {
		goto out;
	}
out_teardown_vm_dbl:
	handle_doorbell_destruction(vmcfg, &node);
out_free_peer_id:
	free(cfg->peer_id);
out_free_cfg:
	free(cfg);
out:
	return ret;
}

static error_t
vm_config_add_doorbell_with_peer(vm_config_t	       *vmcfg,
				 const doorbell_data_t *data, cap_id_t rm_cap,
				 struct vdevice_doorbell *peer_cfg,
				 vm_t *peer_vm, resource_handle_t handle)
{
	error_t ret;

	assert((peer_vm != NULL) || (peer_cfg == NULL));

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		(void)printf("Failed: to alloc vdevice node\n");
		ret = ERROR_NOMEM;
		goto out;
	}

	node->type	   = VDEV_DOORBELL;
	node->export_to_dt = true;
	node->visible	   = true;
	node->handle	   = handle;

	ret = handle_compatibles(node, &data->general);
	if (ret != OK) {
		(void)printf("Failed: to alloc push compatibles\n");
		goto out_free_node;
	}

	if (data->general.generate != NULL) {
		node->generate = strdup(data->general.generate);
	} else {
		node->generate =
			data->is_source
				? strdup("/hypervisor/qcom,doorbell-source")
				: strdup("/hypervisor/qcom,doorbell");
	}
	if (node->generate == NULL) {
		(void)printf("Failed: to alloc doorbell generate string\n");
		ret = ERROR_NOMEM;
		goto out_free_compatible;
	}

	ret = vm_config_add_doorbell_with_peer_config_vdevice(
		vmcfg, data, rm_cap, peer_cfg, peer_vm, node);

	if (ret == OK) {
		goto out;
	}

	// If we get here there was a problem
	if ((node != NULL) && (node->generate != NULL)) {
		free(node->generate);
	}
out_free_compatible:
	if (node != NULL) {
		free_compatibles(node);
	}
out_free_node:
	free(node);
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

static error_t
create_doorbell_with_peer(const doorbell_data_t *d, cap_id_t *cap,
			  vm_t *peer_vm, struct vdevice_doorbell **peer_cfg,
			  resource_handle_t *handle, bool is_default_peer)
{
	error_t ret;

	if ((peer_vm == NULL) || (peer_vm->vm_config == NULL) ||
	    is_default_peer) {
		// Create doorbell on the first VM that contains the
		// doorbell vdevice DT node
		cap_id_result_t res = create_doorbell();
		if (res.e != OK) {
			ret = res.e;
			goto out;
		}
		*cap = res.r;

		*handle = get_vdevice_resource_handle();
	} else {
		// Find peer's doorbell vdevice with matching label
		// If we are a src the peer must be dst device
		vdevice_node_t		*node	 = NULL;
		struct vdevice_doorbell *dbl_cfg = NULL;

		loop_list(node, &peer_vm->vm_config->vdevice_nodes, vdevice_)
		{
			if (node->type == VDEV_DOORBELL) {
				dbl_cfg =
					(struct vdevice_doorbell *)node->config;
				if ((dbl_cfg->label == d->general.label) &&
				    (dbl_cfg->source != d->is_source)) {
					break;
				}
				dbl_cfg = NULL;
			}
		}

		if (dbl_cfg == NULL) {
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}

		// What is destination for self is source for peer and viceversa
		*cap	  = dbl_cfg->master_cap;
		*peer_cfg = dbl_cfg;
		*handle	  = node->handle;
	}

	ret = OK;

out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

static error_t
handle_doorbell(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;
	size_t	cnt = vector_size(data->doorbells);

	for (index_t i = 0; i < cnt; ++i) {
		doorbell_data_t *d =
			vector_at_ptr(doorbell_data_t, data->doorbells, i);

		assert(d != NULL);

		vm_t *peer_vm = NULL;

		// handle arguments here if possible
		if (d->peer_id != NULL) {
			// Non-default peer
			// Check if peer exists, if so, register them as peers
			peer_vm = vm_lookup_by_id(d->peer_id);
			if (peer_vm != NULL) {
				ret = vm_register_peers(vmcfg->vm, peer_vm);
				if (ret != OK) {
					goto out;
				}
			}

			// else leave peer_vm as NULL, and just partially
			// configure the doorbell
		} else {
			// currently we only allow peer to be default
			assert(d->peer == VMID_PEER_DEFAULT);

			vmid_t peer = get_peer(vmcfg, d->peer);
			peer_vm	    = vm_lookup(peer);
			if ((peer_vm == NULL) || (peer_vm->vm_config == NULL)) {
				(void)printf("Failed: to find peer VM(%d)\n",
					     peer);
				ret = ERROR_ARGUMENT_INVALID;
				goto out;
			}
		}

		if (peer_vm == vmcfg->vm) {
			assert(vmcfg->vm != NULL);
			(void)printf("doorbell: cannot setup peer as itself\n");
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}

		resource_handle_t	 handle	  = 0;
		cap_id_t		 rm_cap	  = CSPACE_CAP_INVALID;
		struct vdevice_doorbell *peer_cfg = NULL;

		ret = create_doorbell_with_peer(
			d, &rm_cap, peer_vm, &peer_cfg, &handle,
			check_default_peer(vmcfg, peer_vm));
		if (ret != OK) {
			goto out;
		}

		ret = vm_config_add_doorbell_with_peer(
			vmcfg, d, rm_cap, peer_cfg, peer_vm, handle);
		if (ret != OK) {
			goto out;
		}
	}

out:
	return ret;
}

static error_t
handle_rm_rpc(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;

	size_t cnt = vector_size(data->rm_rpcs);

	vmid_t vmid = vmcfg->vm->vmid;

	bool console_created = false;
	for (index_t i = 0; i < cnt; ++i) {
		rm_rpc_data_t *d =
			vector_at_ptr(rm_rpc_data_t, data->rm_rpcs, i);

		cap_id_result_t tx =
			create_msgqueue(d->queue_depth, d->msg_size);
		if (tx.e != OK) {
			ret = tx.e;
			goto out;
		}

		cap_id_result_t rx =
			create_msgqueue(d->queue_depth, d->msg_size);
		if (rx.e != OK) {
			ret = rx.e;
			goto out;
		}

		ret = vm_config_add_rm_rpc(vmcfg, d, rx.r, tx.r);
		if (ret != OK) {
			goto out;
		}

		if (d->is_console_dev) {
			assert(!console_created);

			vm_console_t *console = vm_console_create(vmcfg->vm);
			if (console == NULL) {
				ret = ERROR_DENIED;
				goto out;
			}

			vm_config_set_console(vmcfg, console);

			console_created = true;
		}
	}

	if (cnt > 0U) {
		// Add RM RPC link
		rm_error_t rm_err = rm_rpc_server_add_link(vmid);
		if (rm_err != RM_OK) {
			ret = ERROR_DENIED;
			goto out;
		}

		// Create RM RPC FIFO
		rm_err = rm_rpc_fifo_create(vmid);
		if (rm_err != RM_OK) {
			ret = ERROR_DENIED;
			goto out;
		}
	}

out:
	return ret;
}

static error_t
handle_vcpu(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t		 ret	  = OK;
	cap_id_t	*caps	  = NULL;
	vmid_t		 peer	  = VMID_PEER_DEFAULT;
	interrupt_data_t vpm_virq = VIRQ_INVALID;

	assert(vmcfg->vm != NULL);

	vm_t   *owner_vm  = vm_lookup(vmcfg->vm->owner);
	count_t max_cores = rm_get_platform_max_cores();
	assert(owner_vm != NULL);

	priority_t    priority;
	nanoseconds_t timeslice;

	if (data->affinity == VM_CONFIG_AFFINITY_PROXY) {
		// Ignore any supplied priority or timeslice.
		priority  = SCHEDULER_MIN_PRIORITY;
		timeslice = SCHEDULER_MIN_TIMESLICE;
	} else {
		// The supplied priority is offset from the owner's priority.
		int32_t offset_priority =
			(int32_t)owner_vm->priority + data->sched_priority;
		if ((offset_priority < (int32_t)SCHEDULER_MIN_PRIORITY) ||
		    (offset_priority > (int32_t)SCHEDULER_MAX_PRIORITY)) {
			(void)printf("handle_vcpu: invalid priority\n");
			ret = ERROR_ARGUMENT_INVALID;
			goto err_sched_prop;
		}
		priority = (priority_t)offset_priority;

		// The supplied timeslice needs to be converted from US to NS.
		timeslice = (nanoseconds_t)data->sched_time_slice * 1000U;
		if ((timeslice < SCHEDULER_MIN_TIMESLICE) ||
		    (timeslice > SCHEDULER_MAX_TIMESLICE)) {
			(void)printf("handle_vcpu: invalid timeslice\n");
			ret = ERROR_ARGUMENT_INVALID;
			goto err_sched_prop;
		}

		assert(data->affinity_map != NULL);
	}
	vmcfg->vm->priority = priority;

	if ((priority >= owner_vm->priority) && !vmcfg->trusted_config) {
		(void)printf(
			"Error: Untrusted VM config must have equal or lower priority (%d >= %d)\n",
			priority, owner_vm->priority);
		ret = ERROR_DENIED;
		goto err_sched_prop;
	}

	size_t vcpu_cnt = vector_size(data->vcpus);
	if ((vcpu_cnt == 0U) || (vcpu_cnt > max_cores)) {
		(void)printf("Error: invalid vcpu cnt(%zu) vs max cores(%u)\n",
			     vcpu_cnt, rm_get_platform_max_cores());
		ret = ERROR_DENIED;
		goto err_vcpu_cnt;
	}

	error_t err;

	if (data->enable_vpm_psci) {
		// Create the PSCI group
		gunyah_hyp_partition_create_vpm_group_result_t vg;
		vg = gunyah_hyp_partition_create_vpm_group(
			rm_get_rm_partition(), rm_get_rm_cspace());
		if (vg.error != OK) {
			(void)printf("handle_vcpu: failed create vpm group\n");
			ret = vg.error;
			goto err_create_vpm;
		}

		vmcfg->vpm_group = vg.new_cap;

		if ((data->affinity == VM_CONFIG_AFFINITY_PROXY) &&
		    !vmcfg->watchdog_enabled) {
			vpm_group_option_flags_t flags =
				vpm_group_option_flags_default();
			vpm_group_option_flags_set_no_aggregation(&flags, true);
			ret = gunyah_hyp_vpm_group_configure(vmcfg->vpm_group,
							     flags);
			if (ret == ERROR_UNIMPLEMENTED) {
				(void)printf(
					"Warning: handle_vcpu: vpm group config unsupported\n");
			} else if (ret != OK) {
				(void)printf(
					"handle_vcpu: failed config vpm group\n");
				goto err_config_vpm;
			} else {
				// Configure succeeded
			}
		}

		ret = gunyah_hyp_object_activate(vmcfg->vpm_group);
		if (ret != OK) {
			(void)printf("handle_vcpu: failed create vpm group\n");
			goto err_active_vpm;
		}

		// For some VMs vpm groups, we must reserve and bind a VIRQ to
		// the owner for signalling VM suspend
		if (data->enable_vpm_psci_virq) {
			peer = vmcfg->vm->owner;

			uint32_result_t irq_ret = alloc_map_virq(peer);
			if (irq_ret.e != OK) {
				ret = irq_ret.e;
				goto err_alloc_virq;
			}
			vpm_virq = virq_edge(irq_ret.r);

			ret = vm_config_add_vpm_group(vmcfg, peer,
						      vmcfg->vpm_group,
						      vpm_virq, 0U, NULL);
			if (ret != OK) {
				(void)printf(
					"handle_vcpu: failed add_vpm_group\n");
				goto err_add_vpm;
			}
		}
	} else {
		vmcfg->vpm_group = CSPACE_CAP_INVALID;
	}

	caps = calloc(vcpu_cnt, sizeof(caps[0]));
	if (caps == NULL) {
		(void)printf("handle_vcpu: nomem\n");
		ret = ERROR_NOMEM;
		goto err_alloc_caps;
	}

	for (cpu_index_t i = 0U; i < vcpu_cnt; i++) {
		caps[i] = CSPACE_CAP_INVALID;
	}

	vcpu_option_flags_t vcpu_options = vcpu_option_flags_default();
	if (data->ras_error_handler) {
		// FIXME restrict to QTI signed images
		if (vcpu_cnt < max_cores) {
			(void)printf(
				"invalid vcpu count for ras error handler\n");
			ret = ERROR_DENIED;
			goto err_vcpu_options;
		}
		if (ras_handler_vm != VMID_HYP) {
			(void)printf("ras handler VM already exists\n");
			ret = ERROR_DENIED;
			goto err_vcpu_options;
		}
		vcpu_option_flags_set_ras_error_handler(&vcpu_options, true);
	}

	vcpu_option_flags_set_critical(&vcpu_options, data->crash_fatal);

	if (data->affinity == VM_CONFIG_AFFINITY_PINNED) {
		vcpu_option_flags_set_pinned(&vcpu_options, true);
	}
	vcpu_option_flags_set_amu_counting_disabled(
		&vcpu_options, data->amu_counting_disabled);
	if (data->affinity == VM_CONFIG_AFFINITY_PROXY) {
		if (hyp_api_flags0_get_vcpu_run(&hyp_id.api_flags_0)) {
			vcpu_option_flags_set_vcpu_run_scheduled(&vcpu_options,
								 true);
		}
	}

	cpu_index_t idx;
	for (idx = 0; idx < vcpu_cnt; idx++) {
		gunyah_hyp_partition_create_thread_result_t vcpu;
		vcpu = gunyah_hyp_partition_create_thread(vmcfg->partition,
							  rm_get_rm_cspace());
		if (vcpu.error != OK) {
			(void)printf("handle_vcpu: failed create thread\n");
			ret = vcpu.error;
			goto err_create_thread;
		}

		caps[idx] = vcpu.new_cap;

		cpu_index_t affinity;

		if (data->affinity != VM_CONFIG_AFFINITY_PROXY) {
			assert(idx < data->affinity_map_cnt);

			affinity = data->affinity_map[idx];
		} else {
			affinity = CPU_INDEX_INVALID;
		}

		ret = gunyah_hyp_vcpu_set_affinity(vcpu.new_cap, affinity);
		if (ret != OK) {
			(void)printf("handle_vcpu: failed set affinity\n");
			goto err_create_thread;
		}

		ret = gunyah_hyp_vcpu_set_priority(vcpu.new_cap, priority);
		if (ret != OK) {
			(void)printf("handle_vcpu: failed set priority\n");
			goto err_create_thread;
		}

		ret = gunyah_hyp_vcpu_set_timeslice(vcpu.new_cap, timeslice);
		if (ret != OK) {
			(void)printf("handle_vcpu: failed set timeslice\n");
			goto err_create_thread;
		}

		ret = gunyah_hyp_cspace_attach_thread(vmcfg->cspace,
						      vcpu.new_cap);
		if (ret != OK) {
			(void)printf("handle_vcpu: failed attach cspace\n");
			goto err_create_thread;
		}

		ret = gunyah_hyp_addrspace_attach_thread(vmcfg->addrspace,
							 vcpu.new_cap);
		if (ret != OK) {
			(void)printf("handle_vcpu: failed attach addrspace\n");
			goto err_create_thread;
		}

#if defined(CAP_RIGHTS_WATCHDOG_ALL)
		if (vmcfg->watchdog != CSPACE_CAP_INVALID) {
			ret = gunyah_hyp_watchdog_attach_vcpu(vmcfg->watchdog,
							      vcpu.new_cap);
			if (ret != OK) {
				(void)printf(
					"handle_vcpu: failed attach watchdog\n");
				goto err_create_thread;
			}
		}
#endif

		if (vmcfg->vpm_group != CSPACE_CAP_INVALID) {
			ret = gunyah_hyp_vpm_group_attach_vcpu(
				vmcfg->vpm_group, vcpu.new_cap, idx);
			if (ret != OK) {
				(void)printf(
					"handle_vcpu: failed attach vpm\n");
				goto err_create_thread;
			}
		}

		ret = gunyah_hyp_vic_attach_vcpu(vmcfg->vic, vcpu.new_cap, idx);
		if (ret != OK) {
			(void)printf("handle_vcpu: failed attach vic\n");
			goto err_create_thread;
		}

		ret = gunyah_hyp_vcpu_configure(vcpu.new_cap, vcpu_options);
		if (ret != OK) {
			(void)printf("handle_vcpu: failed vcpu configure\n");
			goto err_create_thread;
		}
	}

	// Activate VCPUs, and bind proxy scheduling doorbells if needed
	for (index_t i = 0; i < vcpu_cnt; i++) {
		ret = gunyah_hyp_object_activate(caps[i]);
		if (ret != OK) {
			(void)printf("handle_vcpu: failed vcpu activate\n");
			goto err_activate_thread;
		}

		vcpu_data_t *vcpu_data =
			vector_at_ptr(vcpu_data_t, data->vcpus, i);
		assert(vcpu_data != NULL);

		ret = vm_config_add_vcpu(
			vmcfg, caps[i],
			(data->affinity == VM_CONFIG_AFFINITY_PROXY)
				? i
				: data->affinity_map[i],
			vcpu_data->boot_vcpu, vcpu_data->patch);

		if (ret != OK) {
			goto err_activate_thread;
		}

		vcpu_t *vcpu = vector_at(vcpu_t *, vmcfg->vcpus, i);
		assert(vcpu != NULL);
		interrupt_data_t proxy_virq = VIRQ_INVALID;
		if (data->affinity == VM_CONFIG_AFFINITY_PROXY) {
			vm_config_t *owner_cfg = owner_vm->vm_config;
			vmid_t	     owner     = vmcfg->vm->owner;

			uint32_result_t irq_ret = alloc_map_virq(owner);
			if (irq_ret.e != OK) {
				ret = irq_ret.e;
				goto err_activate_thread;
			}
			proxy_virq = virq_edge(irq_ret.r);

			// Bind VIRQ to peer's vic
			ret = gunyah_hyp_vcpu_bind_virq(
				caps[i], owner_cfg->vic,
				virq_get_number(proxy_virq),
				VCPU_VIRQ_TYPE_VCPU_RUN_WAKEUP);
			if (ret != OK) {
				(void)printf(
					"handle_vcpu: failed to bind proxy_virq %d\n",
					ret);

				revert_map_virq(owner,
						virq_get_number(proxy_virq));
				goto err_activate_thread;
			}

			vcpu->proxy_virq = proxy_virq;
		} else {
			vcpu->proxy_virq = VIRQ_INVALID;
		}
	}

	if (data->ras_error_handler) {
		ras_handler_vm = vmcfg->vm->vmid;
	}

err_activate_thread:
	if (ret != OK) {
		vm_config_remove_vcpus(vmcfg, false);
	}
err_create_thread:
	if (ret != OK) {
		for (index_t i = 0U; i < idx; i++) {
			err = gunyah_hyp_cspace_delete_cap_from(
				rm_get_rm_cspace(), caps[i]);
			assert(err == OK);
		}
	}
err_vcpu_options:
err_alloc_caps:
err_add_vpm:
	if ((ret != OK) && virq_is_valid(vpm_virq)) {
		revert_map_virq(peer, virq_get_number(vpm_virq));
	}
err_alloc_virq:
err_active_vpm:
err_config_vpm:
	if ((ret != OK) && (vmcfg->vpm_group != CSPACE_CAP_INVALID)) {
		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							vmcfg->vpm_group);
		assert(err == OK);
		vmcfg->vpm_group = CSPACE_CAP_INVALID;
	}
err_create_vpm:
	free(caps);
err_vcpu_cnt:
err_sched_prop:

	return ret;
}

#if defined(CAP_RIGHTS_WATCHDOG_ALL)
static error_t
handle_watchdog(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;

	if (!rm_get_watchdog_supported() || !vmcfg->watchdog_enabled) {
		vmcfg->watchdog = CSPACE_CAP_INVALID;
		goto out;
	}

	vmid_t vmid = vmcfg->vm->vmid;

	// Create the watchdog
	gunyah_hyp_partition_create_watchdog_result_t wdt;
	wdt = gunyah_hyp_partition_create_watchdog(rm_get_rm_partition(),
						   rm_get_rm_cspace());
	if (wdt.error != OK) {
		ret = wdt.error;
		goto out;
	}

	error_t err;

	watchdog_option_flags_t watchdog_options =
		watchdog_option_flags_default();

	watchdog_option_flags_set_critical_bite(
		&watchdog_options, data->crash_fatal && vmcfg->trusted_config);

	ret = gunyah_hyp_watchdog_configure(wdt.new_cap, watchdog_options);
	if (ret != OK) {
		goto err_config;
	}

	ret = gunyah_hyp_object_activate(wdt.new_cap);
	if (ret != OK) {
		goto err_activate;
	}
	vmcfg->watchdog = wdt.new_cap;

	uint32_result_t irq_ret = alloc_map_virq(vmid);
	if (irq_ret.e != OK) {
		ret = irq_ret.e;
		goto err_alloc_virq;
	}
	interrupt_data_t bark_virq = virq_edge(irq_ret.r);

	// Add the watchdog, and allow the owner to manage the watchdog if the
	// VM is proxy-scheduled (and therefore might be starved of CPU time by
	// the owner)
	ret = vm_config_add_watchdog(vmcfg, wdt.new_cap, bark_virq,
				     data->affinity ==
					     VM_CONFIG_AFFINITY_PROXY);

	if (ret != OK) {
		revert_map_virq(vmid, virq_get_number(bark_virq));
	}
err_alloc_virq:
err_activate:
err_config:
	if ((ret != OK) && (vmcfg->watchdog != CSPACE_CAP_INVALID)) {
		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							vmcfg->watchdog);
		assert(err == OK);
		vmcfg->watchdog = CSPACE_CAP_INVALID;
	}
out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}
#endif

// Leave add_doorbell() for use with SHM
static add_doorbell_ret_t
add_doorbell(vm_config_t *vmcfg, vmid_t self, vmid_t peer, bool is_src,
	     label_t label, const char *generate, interrupt_data_t virq,
	     bool need_alloc_virq, bool export_to_dt, bool source_can_clear)
{
	add_doorbell_ret_t ret = { .err = OK };

	cap_id_result_t cap_ret = create_doorbell();
	if (cap_ret.e != OK) {
		ret.err = cap_ret.e;
		goto out;
	}

	vmid_t db_vmid = self;
	if (is_src) {
		db_vmid = peer;
	}

	error_t err;

	interrupt_data_t db_virq = virq;
	if (need_alloc_virq) {
		uint32_result_t irq_ret = alloc_map_virq(db_vmid);
		if (irq_ret.e != OK) {
			ret.err = irq_ret.e;
			goto out_destroy_db;
		}
		db_virq = virq_edge(irq_ret.r);
	} else {
		ret.err = map_virq(db_vmid, virq_get_number(db_virq));
		if (ret.err != OK) {
			goto out_destroy_db;
		}
	}

	ret.node = vm_config_add_doorbell(vmcfg, peer, cap_ret.r, is_src,
					  db_virq, label, generate,
					  export_to_dt, source_can_clear);
	if (ret.node == NULL) {
		ret.err = ERROR_DENIED;
		goto out_return_virq;
	}

	goto out;

out_return_virq:
	revert_map_virq(db_vmid, virq_get_number(db_virq));
out_destroy_db:
	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), cap_ret.r);
	assert(err == OK);
out:
	return ret;
}

static error_t
handle_shm(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;

	size_t cnt = vector_size(data->shms);
	for (index_t i = 0; i < cnt; ++i) {
		shm_data_t *d = vector_at_ptr(shm_data_t, data->shms, i);

		vdevice_node_t *db     = NULL;
		vdevice_node_t *db_src = NULL;
		if (!d->is_plain_shm) {
			vmid_t self = vmcfg->vm->vmid;
			vmid_t peer = get_peer(vmcfg, d->peer);

			// FIXME:
			// Refactor these doorbells to use new handler code.
			// SHM does not support adding non existing peers yet,
			// so leave this for now.
			add_doorbell_ret_t add_ret;
			add_ret = add_doorbell(vmcfg, self, peer, false,
					       d->general.label, NULL,
					       VIRQ_INVALID, true, false,
					       false);
			if (add_ret.err != OK) {
				ret = add_ret.err;
				goto out;
			}
			db = add_ret.node;

			add_ret = add_doorbell(vmcfg, self, peer, true,
					       d->general.label, NULL,
					       VIRQ_INVALID, true, false,
					       false);
			if (add_ret.err != OK) {
				ret = add_ret.err;
				goto out;
			}
			db_src = add_ret.node;
		}

		ret = vm_config_add_shm(vmcfg, d, db, db_src);
		if (ret != OK) {
			goto out;
		}
	}
out:
	return ret;
}

#if defined(CAP_RIGHTS_VIRTIO_MMIO_ALL)
static cap_id_result_t
create_virtio_mmio(vm_config_t *frontend_cfg, vm_config_t *backend_cfg,
		   count_t vqs_num, vmaddr_t *frontend_ipa,
		   virtio_device_type_t device_type, bool valid_device_type,
		   vmaddr_t *backend_ipa, cap_id_t *me_cap, size_t *me_size,
		   void **rm_addr)
{
	cap_id_result_t ret;

	// We need to dynamically allocate one page for the virtio memory and
	// attach it to a memextent. For this, we have to derive a memextent
	// from the RM's memextent and map this allocated range as read-only for
	// the frontend and read-write for the backend.

	size_t virtio_size = PAGE_SIZE;

	void *rm_ipa = aligned_alloc(PAGE_SIZE, virtio_size);
	if (rm_ipa == NULL) {
		ret = cap_id_result_error(ERROR_NOMEM);
		goto out;
	}
	(void)memset(rm_ipa, 0, virtio_size);

	size_t offset = (size_t)((vmaddr_t)rm_ipa - rm_get_me_ipa_base());

	cap_id_result_t me_ret = memextent_create(
		offset, virtio_size, MEMEXTENT_TYPE_BASIC, PGTABLE_ACCESS_RW,
		MEMEXTENT_MEMTYPE_DEVICE, rm_get_me());
	if (me_ret.e != OK) {
		ret = cap_id_result_error(me_ret.e);
		goto error_create_me;
	}

	error_t err;

	gunyah_hyp_partition_create_virtio_mmio_result_t vio_ret;

	vio_ret = gunyah_hyp_partition_create_virtio_mmio(rm_get_rm_partition(),
							  rm_get_rm_cspace());
	if (vio_ret.error != OK) {
		ret = cap_id_result_error(vio_ret.error);
		goto error_create_virtio;
	}
	virtio_option_flags_t flags = virtio_option_flags_default();
	virtio_option_flags_set_valid_device_type(&flags, valid_device_type);
	err = gunyah_hyp_virtio_mmio_configure(vio_ret.new_cap, me_ret.r,
					       vqs_num, flags, device_type);
	if (err != OK) {
		ret = cap_id_result_error(err);
		goto error_configure_virtio;
	}

	err = gunyah_hyp_object_activate(vio_ret.new_cap);
	if (err != OK) {
		ret = cap_id_result_error(err);
		goto error_activate_virtio;
	}

	// Allocate IPA for frontend
	vm_address_range_result_t alloc_ret = vm_address_range_alloc(
		frontend_cfg->vm, VM_MEMUSE_VDEVICE, INVALID_ADDRESS,
		INVALID_ADDRESS, virtio_size, PAGE_SIZE);
	if (alloc_ret.err != OK) {
		ret = cap_id_result_error(alloc_ret.err);
		goto error_frontend_ipa_allocation;
	}
	vmaddr_t frontend_alloc_ipa = alloc_ret.base;

	// Allocate IPA for backend
	alloc_ret = vm_address_range_alloc(backend_cfg->vm, VM_MEMUSE_VDEVICE,
					   INVALID_ADDRESS, INVALID_ADDRESS,
					   virtio_size, PAGE_SIZE);
	if (alloc_ret.err != OK) {
		ret = cap_id_result_error(alloc_ret.err);
		goto error_backend_ipa_allocation;
	}
	vmaddr_t backend_alloc_ipa = alloc_ret.base;

	// Map it read-only for the frontend
	err = vm_memory_map(frontend_cfg->vm, VM_MEMUSE_VDEVICE, me_ret.r,
			    frontend_alloc_ipa, PGTABLE_ACCESS_R,
			    PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
	if (err != OK) {
		ret = cap_id_result_error(err);
		goto error_frontend_me_map;
	}

	// Map it read-write for the backend, so that it can modify the
	// configuration space
	err = vm_memory_map(backend_cfg->vm, VM_MEMUSE_VDEVICE, me_ret.r,
			    backend_alloc_ipa, PGTABLE_ACCESS_RW,
			    PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
	if (err != OK) {
		ret = cap_id_result_error(err);
		goto error_backend_me_map;
	}

	ret = cap_id_result_ok(vio_ret.new_cap);

	*frontend_ipa = frontend_alloc_ipa;
	*backend_ipa  = backend_alloc_ipa;
	*me_cap	      = me_ret.r;
	*me_size      = virtio_size;
	*rm_addr      = rm_ipa;

	if (ret.e == OK) {
		goto out;
	}

error_backend_me_map:
	err = vm_memory_unmap(frontend_cfg->vm, VM_MEMUSE_VDEVICE, me_ret.r,
			      frontend_alloc_ipa);
	assert(err == OK);
error_frontend_me_map:
	err = vm_address_range_free(backend_cfg->vm, VM_MEMUSE_VDEVICE,
				    backend_alloc_ipa, virtio_size);
	assert(err == OK);
error_backend_ipa_allocation:
	err = vm_address_range_free(frontend_cfg->vm, VM_MEMUSE_VDEVICE,
				    frontend_alloc_ipa, virtio_size);
	assert(err == OK);
error_frontend_ipa_allocation:
error_activate_virtio:
error_configure_virtio:
	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
						vio_ret.new_cap);
	assert(err == OK);
error_create_virtio:
	memextent_delete(me_ret.r);
error_create_me:
	free(rm_ipa);

out:
	return ret;
}

static error_t
add_virtio_mmio(vm_config_t *frontend_cfg, virtio_mmio_data_t *d)
{
	error_t ret = OK;

	vmid_t backend = d->peer;

	vm_t *backend_vm = vm_lookup(backend);
	if ((backend_vm == NULL) || (backend_vm->vm_config == NULL)) {
		(void)printf("Failed: invalid backend\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	vm_config_t *backend_cfg = backend_vm->vm_config;

	vmaddr_t frontend_ipa = 0x0;
	vmaddr_t backend_ipa  = 0x0;
	cap_id_t me_cap	      = CSPACE_CAP_INVALID;
	size_t	 me_size      = 0U;
	void	*rm_addr      = NULL;

	cap_id_result_t vio = create_virtio_mmio(
		frontend_cfg, backend_cfg, d->vqs_num, &frontend_ipa,
		d->device_type, d->valid_device_type, &backend_ipa, &me_cap,
		&me_size, &rm_addr);
	if (vio.e != OK) {
		ret = vio.e;
		goto out;
	}

	vmid_t frontend = frontend_cfg->vm->vmid;

	error_t err;

	// Reserve VIRQs for front- and backend

	uint32_result_t irq_ret = alloc_map_virq(frontend);
	if (irq_ret.e != OK) {
		ret = irq_ret.e;
		goto error_get_frontend_virq;
	}
	interrupt_data_t frontend_virq = virq_edge(irq_ret.r);

	// or else it will get the same virq number
	assert(backend != frontend);

	irq_ret = alloc_map_virq(backend);
	if (irq_ret.e != OK) {
		ret = irq_ret.e;
		goto error_get_backend_virq;
	}
	interrupt_data_t backend_virq = virq_edge(irq_ret.r);

	ret = vm_config_add_virtio_mmio(frontend_cfg, backend_cfg, vio.r,
					frontend_virq, backend_virq, d, true,
					frontend_ipa, backend_ipa, me_cap,
					me_size, rm_addr);
	if (ret == OK) {
		goto out;
	}

	revert_map_virq(backend, virq_get_number(backend_virq));
error_get_backend_virq:
	revert_map_virq(frontend, virq_get_number(frontend_virq));
error_get_frontend_virq:
	err = vm_memory_unmap(backend_cfg->vm, VM_MEMUSE_VDEVICE, me_cap,
			      backend_ipa);
	assert(err == OK);
	err = vm_memory_unmap(frontend_cfg->vm, VM_MEMUSE_VDEVICE, me_cap,
			      frontend_ipa);
	assert(err == OK);
	err = vm_address_range_free(backend_cfg->vm, VM_MEMUSE_VDEVICE,
				    backend_ipa, me_size);
	assert(err == OK);
	err = vm_address_range_free(frontend_cfg->vm, VM_MEMUSE_VDEVICE,
				    frontend_ipa, me_size);
	assert(err == OK);
	// XXX need to do much more than delete cap here ?
	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), vio.r);
	assert(err == OK);
	memextent_delete(me_cap);
	free(rm_addr);
out:
	return ret;
}

static error_t
handle_virtio_mmio(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;

	if (data->virtio_mmios == NULL) {
		goto out;
	}

	size_t cnt = vector_size(data->virtio_mmios);

	for (index_t i = 0; i < cnt; ++i) {
		virtio_mmio_data_t *d = vector_at_ptr(virtio_mmio_data_t,
						      data->virtio_mmios, i);

		ret = add_virtio_mmio(vmcfg, d);
		if (ret != OK) {
			goto out;
		}
	}
out:
	return ret;
}
#endif

// This API validates the IO memory range provided via the VM's DT config
// is valid. Checks if the passed address range i.e., the IPA and the size
// is either mapped to HLOS or configured via passthrough device assignments.
// In case the IO memory range is part of passthrough device assignments the
// pagetable access parsed from the DT config is validated against the
// passthrough configuration.
// parmeters
// vmid - VM ID for which the IO memory range mapping is requested.
// ipa - Start address requested for mapping.
// size - Size of the IO memory range to be mapped.
// access - Pagetable access requested for mapping.
// return - 'true' if the address range is either mapped to HLOS or part of
// passthrough configuration
//			and the pagetable access requested matches with
// passthrough configuration.			'false' otherwise.
static bool
is_iomem_range_valid(vmid_t vmid, vmaddr_t ipa, size_t size,
		     pgtable_access_t access)
{
	bool result = false;
	result =
		vm_passthrough_config_is_addr_in_range(vmid, ipa, size, access);

#if defined(PLATFORM_ALLOW_IOMEM_STATIC_SHARE)
	// Deprecated: Allow static sharing from HLOS.
	if (!result) {
		vm_t *hlos_vm = vm_lookup(VMID_HLOS);
		assert(hlos_vm != NULL);

		vm_memory_result_t ret =
			vm_memory_lookup(hlos_vm, VM_MEMUSE_IO, ipa, size);
		if (ret.err != OK) {
			LOG("Warning: Static share of iomem not mapped in HLOS: %lx %lx\n",
			    ipa, size);
		}
		result = true;
	}
#endif
	return result;
}

static error_t
handle_iomem_ranges(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;
	index_t idx = 0;
	size_t	cnt = vector_size(data->iomem_ranges);

	if (cnt == 0U) {
		goto out;
	}

	if (!vmcfg->trusted_config) {
		// The code below directly derives from the device extent and
		// therefore will unmap devices from the primary VM. It is not
		// safe to allow it for ranges coming from untrusted configs.
		ret = ERROR_DENIED;
		goto out;
	}

	for (idx = 0; idx < cnt; idx++) {
		iomem_range_data_t *d = vector_at_ptr(iomem_range_data_t,
						      data->iomem_ranges, idx);

		paddr_t	 phys = d->phys_base;
		vmaddr_t ipa  = d->ipa_base;
		size_t	 size = d->size;

		if ((ipa != phys) || (util_add_overflows(ipa, size - 1))) {
			ret = ERROR_DENIED;
			goto iomem_err;
		}

		if (util_array_size(iomem_range_access_to_pgtable_access) <=
		    (size_t)d->access) {
			ret = ERROR_DENIED;
			goto iomem_err;
		}
		pgtable_access_t access =
			iomem_range_access_to_pgtable_access[d->access];

		vm_address_range_result_t as_ret = vm_address_range_alloc(
			vmcfg->vm, VM_MEMUSE_IO, ipa, phys, size,
			ADDRESS_RANGE_NO_ALIGNMENT);
		if (as_ret.err != OK) {
			ret = as_ret.err;
			goto iomem_err;
		}

		if (!is_iomem_range_valid(vmcfg->vm->vmid, ipa, size, access)) {
			ret = ERROR_ADDR_INVALID;
			goto iomem_err;
		}

		vm_t *hlos = vm_lookup(VMID_HLOS);
		assert(hlos != NULL);

		cap_id_t device_me =
			vm_memory_get_owned_extent(hlos, MEM_TYPE_IO);
		size_t offset = phys - vm_memory_get_extent_base(MEM_TYPE_IO);

		cap_id_result_t me_ret = vm_memory_create_and_map(
			vmcfg->vm, VM_MEMUSE_IO, device_me, offset, size, ipa,
			MEMEXTENT_MEMTYPE_DEVICE, access,
			PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
		if (me_ret.e == ERROR_MEMDB_NOT_OWNER) {
			// This is a WA to handle the case in which some IO
			// memory should be present in hlos aperture memory map
			// but actually not. Then we have to run the
			// create-and-map again using device_me.
			device_me = rm_get_device_me_cap();
			offset	  = phys - rm_get_device_me_base();

			me_ret = vm_memory_create_and_map(
				vmcfg->vm, VM_MEMUSE_IO, device_me, offset,
				size, ipa, MEMEXTENT_MEMTYPE_DEVICE, access,
				PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
		}
		if (me_ret.e != OK) {
			ret = me_ret.e;
			goto iomem_err;
		} else {
			ret = vector_push_back(vmcfg->iomem_ranges, me_ret.r);
			if (ret != OK) {
				memextent_delete(me_ret.r);
				goto iomem_err;
			}
		}
	}
iomem_err:
	if (ret != OK) {
		while (idx > 0U) {
			idx--;
			cap_id_t *me =
				vector_pop_back(cap_id_t, vmcfg->iomem_ranges);
			// empty vector returns null
			if (me != NULL) {
				memextent_delete(*me);
			}
		}
	}
out:
	return ret;
}

static error_t
handle_iomems(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;

	vdevice_node_t	     *node = NULL;
	struct vdevice_iomem *cfg  = NULL;

	// only copy parameters from iomem data
	size_t cnt = vector_size(data->iomems);
	for (index_t idx = 0; idx < cnt; ++idx) {
		iomem_data_t *d =
			vector_at_ptr(iomem_data_t, data->iomems, idx);

		node = calloc(1, sizeof(*node));
		if (node == NULL) {
			ret = ERROR_NOMEM;
			goto out;
		}

		node->type	   = VDEV_IOMEM;
		node->export_to_dt = true;
		node->visible	   = true;

		if (d->general.generate != NULL) {
			node->generate = strdup(d->general.generate);
			if (node->generate == NULL) {
				ret = ERROR_NOMEM;
				goto out;
			}
		} else if (d->patch_node_path != NULL) {
			node->generate = strdup(d->patch_node_path);
			if (node->generate == NULL) {
				ret = ERROR_NOMEM;
				goto out;
			}
		} else {
			ret = ERROR_DENIED;
			goto out;
		}

		ret = handle_compatibles(node, &d->general);
		if (ret != OK) {
			(void)printf(
				"Failed: save compatible in iomems node\n");
			goto out;
		}

		cfg = calloc(1, sizeof(*cfg));
		if (cfg == NULL) {
			ret = ERROR_NOMEM;
			goto out;
		}

		node->config = cfg;

		// Copy iomem_data to vdevice cfg
		for (index_t i = 0; i < IOMEM_VALIDATION_NUM_IDXS; i++) {
			cfg->rm_acl[i]	 = d->rm_acl[i];
			cfg->rm_attrs[i] = d->rm_attrs[i];
		}

		cfg->peer	      = d->peer;
		cfg->label	      = d->label;
		cfg->mem_info_tag     = d->mem_info_tag;
		cfg->mem_info_tag_set = d->mem_info_tag_set;
		cfg->need_allocate    = d->need_allocate;
		cfg->validate_acl     = d->validate_acl;
		cfg->validate_attrs   = d->validate_attrs;

		cfg->rm_sglist_len = d->rm_sglist_len;
		// deep copy
		if (cfg->rm_sglist_len > 0U) {
			sgl_entry_t *rm_sglist =
				calloc(d->rm_sglist_len, sizeof(rm_sglist[0]));
			if (rm_sglist == NULL) {
				ret = ERROR_NOMEM;
				goto out;
			}

			memcpy(rm_sglist, d->rm_sglist,
			       d->rm_sglist_len * sizeof(rm_sglist[0]));
			cfg->rm_sglist = rm_sglist;
		}

		list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node,
			    vdevice_);
	}
out:
	if (ret != OK) {
		// only free the current node (which cause error)
		if (cfg != NULL) {
			free(cfg->rm_sglist);
			free(cfg);
		}

		if (node != NULL) {
			free_compatibles(node);
			free(node->generate);
			free(node);
		}
	}

	return ret;
}

static error_t
vm_config_init_addrspace(vm_config_t *vmcfg)
{
	error_t err;

	assert(vmcfg != NULL);

	vm_t *vm = vmcfg->vm;
	assert(vm != NULL);

	cap_id_t rm_partition_cap = rm_get_rm_partition();
	cap_id_t rm_cspace_cap	  = rm_get_rm_cspace();

	// Init address range allocator
	size_result_t ar_ret = vm_address_range_init(vm);
	if (ar_ret.e != OK) {
		err = ar_ret.e;
		LOG_ERR(err);
		goto out;
	}
	vm->as_size = ar_ret.r;

	// Create, configure, activate, and attach address space
	gunyah_hyp_partition_create_addrspace_result_t as;
	as = gunyah_hyp_partition_create_addrspace(rm_partition_cap,
						   rm_cspace_cap);
	if (as.error != OK) {
		err = as.error;
		LOG_ERR(err);
		goto out;
	}

	err = gunyah_hyp_addrspace_configure(as.new_cap, vm->vmid);
	if (err != OK) {
		LOG_ERR(err);
		goto out_destroy_addrspace;
	}

	err = vm_creation_config_vm_info_area(vmcfg);
	if (err != OK) {
		LOG_ERR(err);
		goto out_destroy_addrspace;
	}

	err = gunyah_hyp_addrspace_configure_info_area(
		as.new_cap, vmcfg->vm_info_area_me_cap,
		vmcfg->vm->vm_info_area_ipa);
	if (err != OK) {
		LOG_ERR(err);
		goto out_destroy_addrspace;
	}

	// Register a default VMMIO region for unauthenticated VMs
	if (vm->auth_type != VM_AUTH_TYPE_PLATFORM) {
		// The address range is from Google's protected virtual platform
		// spec, which is not platform-specific.
		err = gunyah_hyp_addrspace_configure_vmmio(
			as.new_cap, 0UL, 0x40000000UL,
			ADDRSPACE_VMMIO_CONFIGURE_OP_ADD);
		if (err != OK) {
			LOG_ERR(err);
			goto out_destroy_addrspace;
		}
	}

	err = gunyah_hyp_object_activate(as.new_cap);
	if (err != OK) {
		LOG_ERR(err);
		goto out_destroy_addrspace;
	}
	vmcfg->addrspace = as.new_cap;

	err = vm_creation_map_vm_info_area(vmcfg);
	if (err != OK) {
		LOG_ERR(err);
		goto out;
	}

	goto out;

out_destroy_addrspace:
	err = gunyah_hyp_cspace_delete_cap_from(rm_cspace_cap, as.new_cap);
	assert(err == OK);
out:
	return err;
}

static error_t
vm_config_validate_base_constraints(const vm_config_t		  *vmcfg,
				    const vm_config_parser_data_t *data)
{
	error_t ret;

	uint32_t generic_constraints  = data->mem_base_constraints[0];
	uint32_t platform_constraints = data->mem_base_constraints[1];

	address_range_tag_t tag = vm_memory_constraints_to_tag(
		vmcfg->vm, generic_constraints, platform_constraints);
	if (tag == ADDRESS_RANGE_NO_TAG) {
		(void)printf("Error: invalid base-mem-constraints %x %x\n",
			     generic_constraints, platform_constraints);
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	if ((tag & vmcfg->vm->mem_base_tag) != tag) {
		(void)printf("Error: insufficient base memory tag %x, %x\n",
			     vmcfg->vm->mem_base_tag, tag);
		ret = ERROR_DENIED;
		goto out;
	}

	ret = OK;

out:
	return ret;
}

static error_t
vm_config_update_and_validate_fw_ipa(vm_config_t		   *vmcfg,
				     const vm_config_parser_data_t *data)
{
	error_t ret;

	vmcfg->fw_ipa_base = data->fw_base_ipa;
	vmcfg->fw_size_max = data->fw_size_max;

	if (vmcfg->vm->fw_mp_handle == vmcfg->vm->mem_mp_handle) {
		// Firmware is inside the image memparcel.

		if ((vmcfg->fw_ipa_base == INVALID_ADDRESS) ||
		    vmcfg->mem_map_direct) {
			// DT did not configure the FW base address, or
			// the VM is configured as direct mapped.
			vmcfg->fw_ipa_base = vmcfg->mem_ipa_base;
		} else if (vmcfg->fw_ipa_base == vmcfg->mem_ipa_base) {
			// DT configured both addresses the same,
			// nothing more to do
		} else {
			// DT configured both addresses differently
			(void)printf(
				"Error: firmware-address %#zx != base-address %#zx with only one memparcel %d\n",
				vmcfg->fw_ipa_base, vmcfg->mem_ipa_base,
				vmcfg->vm->fw_mp_handle);
			ret = ERROR_ADDR_INVALID;
			goto out;
		}
	} else {
		// Firmware has a separate memparcel.

		if (vmcfg->mem_map_direct) {
			// Override the base IPA with the phys base of
			// the firmware memparcel.
			memparcel_t *fw_mp = memparcel_lookup_by_target_vmid(
				vmcfg->vm->vmid, vmcfg->vm->fw_mp_handle);
			if (fw_mp == NULL) {
				ret = ERROR_NORESOURCES;
				goto out;
			}

			paddr_result_t pret = memparcel_get_phys(fw_mp, 0U);
			assert(pret.e == OK);

			vmcfg->fw_ipa_base = pret.r;
		} else if (vmcfg->fw_ipa_base != INVALID_ADDRESS) {
			// DT configured the FW base address; nothing to
			// do.
		} else {
			// DT did not configure the FW base address;
			// this is mandatory for a separate memparcel
			(void)printf(
				"Error: firmware-address unspecified for memparcel %d\n",
				vmcfg->vm->fw_mp_handle);
			ret = ERROR_ADDR_INVALID;
			goto out;
		}
	}

	if (vmcfg->fw_ipa_base >= vmcfg->vm->as_size) {
		(void)printf("Error: firmware region limits out of range");
		ret = ERROR_ADDR_INVALID;
		goto out;
	}

	// Truncate the max FW size to the size of the address space.
	vmcfg->fw_size_max = util_min(vmcfg->fw_size_max,
				      vmcfg->vm->as_size - vmcfg->fw_ipa_base);

	if ((vmcfg->vm->fw_mp_handle != vmcfg->vm->mem_mp_handle) &&
	    !vmcfg->mem_map_direct) {
		vmaddr_t fw_ipa_end =
			vmcfg->fw_ipa_base + vmcfg->fw_size_max - 1U;
		vmaddr_t mem_ipa_end =
			vmcfg->mem_ipa_base + vmcfg->mem_size_max - 1U;
		if ((vmcfg->mem_ipa_base <= fw_ipa_end) &&
		    (vmcfg->fw_ipa_base <= mem_ipa_end)) {
			// FW range overlaps with image range
			(void)printf(
				"Error: overlapping FW range %#zx-%#zx and image range %#zx-%#zx\n",
				vmcfg->fw_ipa_base, fw_ipa_end,
				vmcfg->mem_ipa_base, mem_ipa_end);
			ret = ERROR_ADDR_INVALID;
			goto out;
		}
	}

	ret = OK;
out:
	return ret;
}

error_t
vm_config_update_parsed(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret;

#if defined(GUEST_RAM_DUMP_ENABLE) && GUEST_RAM_DUMP_ENABLE
	// update guest ram dump status
	vmcfg->guestdump_allowed = data->guest_ram_dump;
#endif // GUEST_RAM_DUMP_ENABLE
       // update SVM console status
#if defined(PLATFORM_ALLOW_INSECURE_CONSOLE) && PLATFORM_ALLOW_INSECURE_CONSOLE
	vmcfg->insecure_console = data->insecure_console;
#endif // PLATFORM_ALLOW_INSECURE_CONSOLE

	// Update and validate the normal memory range
	vmcfg->mem_ipa_base   = data->mem_base_ipa;
	vmcfg->mem_size_min   = data->mem_size_min;
	vmcfg->mem_size_max   = data->mem_size_max;
	vmcfg->mem_map_direct = data->mem_map_direct;

	if (vmcfg->mem_map_direct) {
		// Override the base IPA with the phys base of the image
		// memparcel.
		memparcel_t *image_mp = memparcel_lookup_by_target_vmid(
			vmcfg->vm->vmid, vmcfg->vm->mem_mp_handle);
		if (image_mp == NULL) {
			ret = ERROR_NORESOURCES;
			goto out;
		}

		paddr_result_t pret = memparcel_get_phys(image_mp, 0U);
		assert(pret.e == OK);

		vmcfg->mem_ipa_base = pret.r;
	}

	ret = vm_config_init_addrspace(vmcfg);
	if (ret != OK) {
		goto out;
	}

	if ((vmcfg->mem_ipa_base >= vmcfg->vm->as_size) ||
	    (vmcfg->mem_size_min > vmcfg->mem_size_max)) {
		(void)printf("Error: address space limits out of range");
		ret = ERROR_ADDR_INVALID;
		goto out;
	}

	// Truncate the private memory range to the size of the address space.
	size_t mem_size_avail = vmcfg->mem_map_direct ? vmcfg->vm->as_size
						      : (vmcfg->vm->as_size -
							 vmcfg->mem_ipa_base);
	vmcfg->mem_size_max   = util_min(vmcfg->mem_size_max, mem_size_avail);

	if (data->mem_base_constraints_set) {
		// Check that the base memory meets the required constraints.
		ret = vm_config_validate_base_constraints(vmcfg, data);
		if (ret != OK) {
			goto out;
		}
	}

	if (vmcfg->vm->fw_size != 0U) {
		// Firmware memparcel range has been set. Update and validate
		// the firmware IPA range.
		ret = vm_config_update_and_validate_fw_ipa(vmcfg, data);
		if (ret != OK) {
			(void)printf(
				"Error: failed to update firmware IPA range\n");
			goto out;
		}
	}

	ret = handle_ids(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle VM IDs\n");
		goto out;
	}

	ret = platform_config_update_parsed(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to update platform vm_config %d\n",
			     ret);
		goto out;
	}

	// Config has been parsed and updated, perform final checks

	if (data->crash_fatal && !vmcfg->trusted_config) {
		ret = ERROR_DENIED;
		LOG_ERR(ret);
		goto out;
	}

	if (vmcfg->mem_map_direct && !vmcfg->trusted_config) {
		ret = ERROR_DENIED;
		LOG_ERR(ret);
		goto out;
	}

out:
	return ret;
}

static error_t
vm_config_update_peer_doorbell(vm_config_t	       *vmcfg,
			       struct vdevice_doorbell *dbl_cfg, vm_t *peer_vm,
			       resource_handle_t handle)
{
	error_t err;

	assert(dbl_cfg != NULL);
	assert(peer_vm != NULL);

	doorbell_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	// If our peer is dst we are src and viceversa
	cfg.is_source	     = !dbl_cfg->source;
	cfg.source_can_clear = dbl_cfg->source_can_clear;
	cfg.defined_irq	     = false;
	cfg.general.label    = dbl_cfg->label;

	err = vm_config_add_doorbell_with_peer(vmcfg, &cfg, dbl_cfg->master_cap,
					       dbl_cfg, peer_vm, handle);
	if (err != OK) {
		goto out;
	}

	err = OK;

out:
	if (err != OK) {
		LOG_ERR(err);
	}
	return err;
}

static error_t
vm_config_update_peer_msg_queue_pair(vm_config_t *vmcfg,
				     struct vdevice_msg_queue_pair *msg_pair_cfg,
				     vm_t *peer_vm, resource_handle_t handle)
{
	error_t err;

	assert(msg_pair_cfg != NULL);
	assert(peer_vm != NULL);

	msg_queue_pair_data_t cfg;
	(void)memset(&cfg, 0, sizeof(cfg));

	cfg.msg_size	  = (uint16_t)msg_pair_cfg->tx_max_msg_size;
	cfg.queue_depth	  = (uint16_t)msg_pair_cfg->tx_queue_depth;
	cfg.defined_irq	  = false;
	cfg.general.label = msg_pair_cfg->label;

	// What is tx for self is rx for peer and viceversa
	err = vm_config_add_msgqueue_pair(vmcfg, &cfg,
					  msg_pair_cfg->rx_master_cap,
					  msg_pair_cfg->tx_master_cap,
					  msg_pair_cfg, peer_vm, handle);
	if (err != OK) {
		goto out;
	}

	err = OK;

out:
	if (err != OK) {
		LOG_ERR(err);
	}
	return err;
}

static error_t
vm_config_add_hlos_peer_vdevices(vm_t *vm)
{
	error_t ret = ERROR_FAILURE;

	// This function assumes that HLOS is allocated prior to GearVM's
	// vdevices being set up, otherwise HLOS won't be added as a peer

	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	// Check if any peers were created before this VM, go through their
	// vdevice list and set up any peered vdevices. We only support
	// doorbells and msgQ pairs for now

	assert(vm->vmid == VMID_HLOS);

	size_t cnt = vector_size(vm->peers);
	for (index_t i = 0; i < cnt; i++) {
		vm_t *peer_vm = vector_at(vm_t *, vm->peers, i);
		assert(peer_vm != NULL);

		// Only add trusted VM devices
		if (!peer_vm->vm_config->trusted_config) {
			continue;
		}

		// Find peer's msgqueue_pair and doorbell vdevices
		vdevice_node_t *node = NULL;
		loop_list(node, &peer_vm->vm_config->vdevice_nodes, vdevice_)
		{
			if (node->type == VDEV_MSG_QUEUE_PAIR) {
				struct vdevice_msg_queue_pair *msg_pair_cfg =
					(struct vdevice_msg_queue_pair *)
						node->config;

				if ((msg_pair_cfg->peer == vm->vmid) &&
				    (msg_pair_cfg->tx_max_msg_size > 0U) &&
				    (msg_pair_cfg->tx_queue_depth > 0U)) {
					ret = vm_config_update_peer_msg_queue_pair(
						vm->vm_config, msg_pair_cfg,
						peer_vm, node->handle);
					if (ret != OK) {
						(void)printf(
							"peer vdev: failed to add msgq_pair\n");
						goto out;
					}
				}
				continue;
			}

			if (node->type == VDEV_DOORBELL) {
				struct vdevice_doorbell *doorbell_cfg =
					(struct vdevice_doorbell *)node->config;

				if (doorbell_cfg->peer == vm->vmid) {
					ret = vm_config_update_peer_doorbell(
						vm->vm_config, doorbell_cfg,
						peer_vm, node->handle);
					if (ret != OK) {
						(void)printf(
							"peer vdev: failed to add doorbell\n");
						goto out;
					}
				}
				continue;
			}
		}
	}

	ret = OK;

out:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

error_t
vm_config_create_vdevices(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret;

	ret = handle_interrupt_controller(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle interrupt controller\n");
		goto out;
	}

	ret = handle_irqs(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle irqs\n");
		goto out;
	}

	ret = handle_iomems(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle iomems\n");
		goto out;
	}

	ret = handle_iomem_ranges(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle iomem ranges\n");
		goto out;
	}

#if defined(CAP_RIGHTS_WATCHDOG_ALL)
	ret = handle_watchdog(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle watchdog\n");
		goto out;
	}
#endif

	ret = handle_rtc(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle vRTC\n");
		goto out;
	}

	ret = handle_vcpu(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle vcpus, ret=%" PRId32 "\n",
			     (int32_t)ret);
		goto out;
	}

	ret = handle_rm_rpc(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle rm rpcs\n");
		goto out;
	}

	ret = handle_doorbell(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle doorbells\n");
		goto out;
	}

	ret = handle_msgqueue(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle msgqueues\n");
		goto out;
	}

	ret = handle_msgqueue_pair(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle msgqueue pairs\n");
		goto out;
	}

	ret = handle_shm(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle shms\n");
		goto out;
	}

#if defined(CAP_RIGHTS_VIRTIO_MMIO_ALL)
	ret = handle_virtio_mmio(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle virtio_mmio\n");
		goto out;
	}
#endif

	ret = platform_vm_config_create_vdevices(vmcfg, data);
	if (ret != OK) {
		(void)printf("Error: failed to handle platform vm_config\n");
		goto out;
	}

out:
	return ret;
}

vm_config_get_rm_rpc_msg_queue_info_ret_t
vm_config_get_rm_rpc_msg_queue_info(vmid_t self, vmid_t peer_id)
{
	vm_config_t *vmcfg;

	assert(self == VMID_RM);

	vm_t *vm = vm_lookup(peer_id);
	if (vm == NULL) {
		vmcfg = NULL;
	} else {
		vmcfg = vm->vm_config;
	}

	vm_config_get_rm_rpc_msg_queue_info_ret_t ret;

	if (vmcfg != NULL) {
		// Find the RM RPC node
		vdevice_node_t		      *node	 = NULL;
		struct vdevice_msg_queue_pair *msgq_pair = NULL;

		loop_list(node, &vmcfg->vdevice_nodes, vdevice_)
		{
			if (node->type == VDEV_RM_RPC) {
				msgq_pair = (struct vdevice_msg_queue_pair *)
						    node->config;
				if (msgq_pair->peer == VMID_RM) {
					break;
				}
				msgq_pair = NULL;
			}
		}
		assert(msgq_pair != NULL);

		ret = (vm_config_get_rm_rpc_msg_queue_info_ret_t){
			.err	  = RM_OK,
			.tx_capid = msgq_pair->tx_peer_cap,
			.rx_capid = msgq_pair->rx_peer_cap,
			.tx_virq  = virq_get_number(msgq_pair->tx_peer_virq),
			.rx_virq  = virq_get_number(msgq_pair->rx_peer_virq),
		};
	} else if ((peer_id == VMID_HYP) &&
		   (platform_get_hyp_rpc_msg_queue_info != NULL)) {
		ret = platform_get_hyp_rpc_msg_queue_info();
	} else {
		ret = (vm_config_get_rm_rpc_msg_queue_info_ret_t){
			.err = RM_ERROR_NORESOURCE,
		};
	}

	return ret;
}

void
vm_config_set_console(vm_config_t *vmcfg, vm_console_t *console)
{
	assert(vmcfg != NULL);
	assert(console != NULL);
	assert(vmcfg->console == NULL);

	vmcfg->console = console;
}

static void
vm_config_remove_console(vm_config_t *vmcfg)
{
	assert(vmcfg != NULL);
	assert(vmcfg->vm != NULL);

	if (vmcfg->console != NULL) {
		vm_console_destroy(vmcfg->console);
		vmcfg->console = NULL;
	}
}

struct vm_console *
vm_config_get_console(vmid_t self)
{
	vm_t	     *vm      = vm_lookup(self);
	vm_console_t *console = NULL;

	if ((vm != NULL) && (vm->vm_config != NULL)) {
		console = vm->vm_config->console;
	}

	return console;
}

// This function evaluates and returns whether console for SVM is allowed or not
// parmeters
// self - VM ID for which the console status is requested.
// return - 'true' If the PLATFORM_ALLOW_INSECURE_CONSOLE is enabled and
// insecure_console value parsed from DT is true or if it is a non secured
// device. 'false' otherwise.
bool
vm_config_check_console_allowed(vmid_t self)
{
	bool console_enabled = !platform_get_security_state();
#if defined(PLATFORM_ALLOW_INSECURE_CONSOLE) && PLATFORM_ALLOW_INSECURE_CONSOLE
	vm_t *vm = vm_lookup(self);
	if ((vm != NULL) && (vm->vm_config != NULL) &&
	    (vm->vm_config->insecure_console)) {
		console_enabled = true;
	}
#else
	(void)self;

#endif
	return console_enabled;
}

vm_config_t *
vm_config_alloc(vm_t *vm, cap_id_t cspace, cap_id_t partition)
{
	vm_config_t *vmcfg = NULL;

	vmcfg = calloc(1, sizeof(*vmcfg));
	if (vmcfg == NULL) {
		goto err_out;
	}

	vmcfg->vcpus = vector_init(vcpu_t *, 8U, 8U);
	if (vmcfg->vcpus == NULL) {
		goto err_out;
	}
	vmcfg->iomem_ranges = vector_init(cap_id_t, 1U, 1U);
	if (vmcfg->iomem_ranges == NULL) {
		goto err_out;
	}

	vmcfg->partition	= partition;
	vmcfg->cspace		= cspace;
	vmcfg->addrspace	= CSPACE_CAP_INVALID;
	vmcfg->vic		= CSPACE_CAP_INVALID;
	vmcfg->vpm_group	= CSPACE_CAP_INVALID;
	vmcfg->watchdog		= CSPACE_CAP_INVALID;
	vmcfg->rtc		= CSPACE_CAP_INVALID;
	vmcfg->minidump_allowed = false;

	vmcfg->accepted_memparcels = vector_init(memparcel_t *, 1U, 1U);
	if (vmcfg->accepted_memparcels == NULL) {
		goto err_out;
	}

	assert(vm != NULL);
	vmcfg->vm     = vm;
	vm->vm_config = vmcfg;

	goto out;
err_out:
	if (vmcfg != NULL) {
		if (vmcfg->vcpus != NULL) {
			vector_deinit(vmcfg->vcpus);
		}
		if (vmcfg->iomem_ranges != NULL) {
			vector_deinit(vmcfg->iomem_ranges);
		}
		if (vmcfg->accepted_memparcels != NULL) {
			vector_deinit(vmcfg->accepted_memparcels);
		}
		free(vmcfg);
		vmcfg = NULL;
	}
out:
	return vmcfg;
}

void
vm_config_dealloc(vm_t *vm)
{
	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	vector_deinit(vm->vm_config->accepted_memparcels);
	vector_deinit(vm->vm_config->iomem_ranges);
	vector_deinit(vm->vm_config->vcpus);

	free(vm->vm_config);
	vm->vm_config = NULL;
}

void
vm_config_hlos_vdevices_setup(vm_config_t *vmcfg, cap_id_t vic)
{
	const uint16_t depth = 8U;
	const uint16_t size  = RM_RPC_MESSAGE_SIZE;
	error_t	       ret   = OK;

	cap_id_result_t tx = cap_id_result_error(ERROR_DENIED);
	cap_id_result_t rx = cap_id_result_error(ERROR_DENIED);

	vmcfg->vic = vic;

	tx = create_msgqueue(depth, size);
	if (tx.e != OK) {
		(void)printf(
			"Error: failed to create hlos tx msg queue, err(%x)\n",
			tx.e);
		ret = tx.e;
		goto out;
	}

	rx = create_msgqueue(depth, size);
	if (rx.e != OK) {
		(void)printf(
			"Error: failed to create hlos rx msg queue, err(%x)\n",
			rx.e);
		ret = rx.e;
		goto out;
	}

	rm_rpc_data_t d = {
		.general = {
			.push_compatible = { "gunyah-resource-manager",
					     "qcom,resource-manager-1-0",
					     "qcom,resource-manager" },
			.push_compatible_num = 3,
			.label		   = 0U,
			.generate = "/hypervisor/gunyah-resource-mgr",
		},
		.msg_size = size,
		.queue_depth = depth,
		.defined_irq = false,
		.is_console_dev = true,
	};

	ret = vm_config_add_rm_rpc(vmcfg, &d, rx.r, tx.r);
	if (ret != OK) {
		(void)printf(
			"Error: failed to add hlos rm rpc vdevice, err(%x)\n",
			ret);
		goto out;
	}

#if defined(CAP_RIGHTS_WATCHDOG_ALL)
	if (rm_get_watchdog_supported()) {
#if defined(CONFIG_WATCHDOG_VIRQ)
		const interrupt_data_t watchdog_bark_virq =
			virq_level(CONFIG_WATCHDOG_VIRQ);
#else
		const interrupt_data_t watchdog_bark_virq = VIRQ_INVALID;
#endif
		ret = vm_config_add_watchdog(vmcfg, CSPACE_CAP_INVALID,
					     watchdog_bark_virq, false);
		if (ret != OK) {
			(void)printf(
				"Error: failed to add hlos watchdog, err(%x)\n",
				ret);
			goto out;
		}
	}
#endif
	// Process any vdevices that may have been added by peers before HLOS
	// was created
	ret = vm_config_add_hlos_peer_vdevices(vmcfg->vm);
	if (ret != OK) {
		(void)printf(
			"Error: failed to handle vm_config add peer vdevices\n");
		goto out;
	}

	ret = platform_vm_config_hlos_vdevices_setup(vmcfg);
	if (ret != OK) {
		(void)printf("Error: failed to handle platform vm_config\n");
		goto out;
	}

out:

	if (ret != OK) {
		if (tx.e == OK) {
			ret = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace,
								tx.r);
			assert(ret == OK);
		}

		if (rx.e == OK) {
			ret = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace,
								rx.r);
			assert(ret == OK);
		}
	}

	return;
}

static error_t
handle_interrupt_controller(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t err;

	// Unused for now; interrupt controller base address will be read from
	// here eventually
	(void)data;

	gunyah_hyp_partition_create_vic_result_t v;
	v = gunyah_hyp_partition_create_vic(vmcfg->partition,
					    rm_get_rm_cspace());
	if (v.error != OK) {
		err = v.error;
		goto out;
	}

	vic_option_flags_t vic_options = vic_option_flags_default();
	vic_option_flags_set_disable_default_addr(&vic_options,
						  !PLATFORM_VIC_DEFAULT_ADDR);
	err = gunyah_hyp_vic_configure(v.new_cap, rm_get_platform_max_cores(),
				       GIC_SPI_NUM, vic_options, 0U);
	if (err != OK) {
		goto out_destroy_vic;
	}

	if ((vmcfg->vm != NULL) &&
	    (vmcfg->vm->auth_type != VM_AUTH_TYPE_PLATFORM)) {
		// Set up the MPIDR mapping to be linear, as is expected by
		// most target-independent VMs.
		//
		// This should actually be derived from the parsed /cpu nodes,
		// not just hard-coded. Also it should be in arch code.
		// FIXME:
		err = gunyah_hyp_vgic_set_mpidr_mapping(v.new_cap, 0x7fff, 0, 8,
							16, 24, false);
		if (err != OK) {
			goto out;
		}
	}

	err = gunyah_hyp_object_activate(v.new_cap);
	if (err != OK) {
		goto out_destroy_vic;
	}

	vmcfg->vic = v.new_cap;

	err = irq_manager_vm_init(vmcfg->vm, vmcfg->vic, PLATFORM_IRQ_MAX);
	if (err != OK) {
		goto out_destroy_vic;
	}

out_destroy_vic:
	if (err != OK) {
		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							v.new_cap);
		assert(err == OK);
		vmcfg->vic = CSPACE_CAP_INVALID;
	}
out:
	return err;
}

static error_t
handle_irqs(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret;

	assert(vmcfg != NULL);

	size_t cnt = vector_size(data->irq_ranges);
	if (!vmcfg->trusted_config && (cnt > 0U)) {
		// The code below will map IRQs that are either restricted or
		// owned by the owner VM. It is not safe to allow it for ranges
		// coming from untrusted configs.
		ret = ERROR_DENIED;
		goto err_denied;
	}

	vm_t *hlos = vm_lookup(VMID_HLOS);
	assert(hlos != NULL);

	vmid_t self = vmcfg->vm->vmid;
	ret	    = OK;

	// check all requested irqs, if it's a restricted hw_irq directly map
	// it.
	for (index_t i = 0; i < cnt; i++) {
		irq_range_data_t *d =
			vector_at_ptr(irq_range_data_t, data->irq_ranges, i);

		virq_t hw_irq = d->hw_irq;
		virq_t virq   = d->virq;

		vmid_result_t owner_ret = irq_manager_hwirq_get_owner(hw_irq);

		if ((owner_ret.e == OK) && (owner_ret.r == VMID_ANY)) {
			ret = irq_manager_vm_restricted_lend(vmcfg->vm, virq,
							     hw_irq);
			if (ret != OK) {
				break;
			}
		} else if ((owner_ret.e == OK) && (owner_ret.r == self)) {
			ret = irq_manager_vm_hwirq_map(vmcfg->vm, virq, hw_irq,
						       true);
			if (ret != OK) {
				break;
			}
		} else if ((owner_ret.e == OK) && (owner_ret.r == VMID_HLOS)) {
#if defined(PLATFORM_STATIC_IRQ_SHARE_ALLOWED) &&                              \
	PLATFORM_STATIC_IRQ_SHARE_ALLOWED
			ret = irq_manager_vm_static_lend(vmcfg->vm, virq,
							 hw_irq);
			if (ret != OK) {
				break;
			}
			(void)self;
#else
			LOG("static lend IRQ denied! (%d) %d -> (%d) %d\n",
			    VMID_HLOS, hw_irq, self, virq);
			ret = ERROR_DENIED;
			break;
#endif
		} else {
			LOG("invalid irq %d/%d\n", virq, hw_irq);
			continue;
		}
	}

err_denied:
	if (ret != OK) {
		LOG_ERR(ret);
	}
	return ret;
}

static error_t
handle_ids(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;
	assert(data != NULL);

	vm_t *vm = vmcfg->vm;
	assert(vm != NULL);

	vm->has_guid = data->has_guid;
	memcpy(vm->guid, data->vm_guid, VM_GUID_LEN);

	if (data->sensitive) {
		vm->sensitive = true;
	}
	vm->crash_fatal = data->crash_fatal;
	vm->no_shutdown = data->no_shutdown;
	vm->no_reset	= data->no_reset;

	strlcpy(vm->uri, data->vm_uri, VM_MAX_URI_LEN);
	vm->uri_len = (uint16_t)strlen(vm->uri);

	strlcpy(vm->name, data->vm_name, VM_MAX_NAME_LEN);
	vm->name_len = (uint16_t)strlen(vm->name);

	return ret;
}

static void
free_compatibles(vdevice_node_t *vdevice)
{
	for (index_t i = 0; i < vdevice->push_compatible_num; ++i) {
		free(vdevice->push_compatible[i]);
	}
	vdevice->push_compatible_num = 0;
}

error_t
handle_compatibles(vdevice_node_t *vdevice, const general_data_t *data)
{
	error_t ret = OK;
	index_t i;

	assert(data->push_compatible_num <= VDEVICE_MAX_PUSH_COMPATIBLES);
	for (i = 0; i < data->push_compatible_num; ++i) {
		assert(data->push_compatible[i] != NULL);
		vdevice->push_compatible[i] = strdup(data->push_compatible[i]);
		if (vdevice->push_compatible[i] == NULL) {
			ret = ERROR_NOMEM;
			break;
		}
	}
	vdevice->push_compatible_num = i;

	if (ret != OK) {
		free_compatibles(vdevice);
	}

	return ret;
}

void
vm_config_destroy_vm_objects(vm_t *vm)
{
	error_t err;

	assert(vm != NULL);

	vm_config_t *vmcfg = vm->vm_config;
	assert(vmcfg != NULL);

	if (vmcfg->addrspace != CSPACE_CAP_INVALID) {
		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							vmcfg->addrspace);
		assert(err == OK);
	}

	vm_creation_vm_info_area_teardown(vmcfg);
	vm_address_range_destroy(vm);
	vm_memory_teardown(vm);

	if (vmcfg->vic != CSPACE_CAP_INVALID) {
		irq_manager_vm_reset(vm);

		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							vmcfg->vic);
		assert(err == OK);
	}

	if (vmcfg->vpm_group != CSPACE_CAP_INVALID) {
		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							vmcfg->vpm_group);
		assert(err == OK);
	}

	// Opposite of handle_iomem_ranges
	assert(vmcfg->iomem_ranges != NULL);
	while (!vector_is_empty(vmcfg->iomem_ranges)) {
		cap_id_t *me = vector_pop_back(cap_id_t, vmcfg->iomem_ranges);

		if (me != NULL) {
			err = gunyah_hyp_cspace_delete_cap_from(
				rm_get_rm_cspace(), *me);
			assert(err == OK);
		}
	}

	// Opposite of handle_vcpus
	vm_config_remove_vcpus(vmcfg, true);

	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
						vmcfg->cspace);
	assert(err == OK);
}

void
vm_config_delete_vdevice_node(vm_config_t *vmcfg, vdevice_node_t **node)
{
	assert(vmcfg != NULL);
	assert((node != NULL) && (*node != NULL));

	list_remove(vdevice_node_t, &vmcfg->vdevice_nodes, *node, vdevice_);

	free((*node)->config);
	free((*node)->generate);

	free_compatibles(*node);

	free(*node);
	*node = NULL;
}

static void
handle_msgqueue_pair_destruction(vm_config_t *vmcfg, vdevice_node_t **node)
{
	assert(vmcfg != NULL);
	assert((node != NULL) && (*node != NULL));

	struct vdevice_msg_queue_pair *cfg =
		(struct vdevice_msg_queue_pair *)(*node)->config;

	free(cfg->peer_id);

	cap_id_t rx = cfg->rx_master_cap;
	cap_id_t tx = cfg->tx_master_cap;

	// Delete caps copied to VM cspace
	error_t err;
	err = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace, cfg->tx_vm_cap);
	assert(err == OK);
	err = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace, cfg->rx_vm_cap);
	assert(err == OK);

	revert_map_virq(vmcfg->vm->vmid, virq_get_number(cfg->tx_vm_virq));
	revert_map_virq(vmcfg->vm->vmid, virq_get_number(cfg->rx_vm_virq));

	bool  has_matching_vdevice = false;
	vm_t *peer_vm		   = vm_lookup(cfg->peer);

	if (!cfg->has_peer_vdevice) {
		// peer-default has no matching msgqueue_pair vdevice, therefore
		// we need to return the virqs here. For non-default peer with
		// matching vdevice, this will happen when its VM is reset.

		revert_map_virq(cfg->peer, virq_get_number(cfg->rx_peer_virq));
		revert_map_virq(cfg->peer, virq_get_number(cfg->tx_peer_virq));
	} else if ((peer_vm != NULL) && (peer_vm->vm_config != NULL)) {
		// Check if peer's vdevice still exists
		vdevice_node_t		      *peer_node = NULL;
		struct vdevice_msg_queue_pair *peer_cfg	 = NULL;

		loop_list(peer_node, &peer_vm->vm_config->vdevice_nodes,
			  vdevice_)
		{
			if (peer_node->type == VDEV_MSG_QUEUE_PAIR) {
				peer_cfg = (struct vdevice_msg_queue_pair *)
						   peer_node->config;
				if ((peer_cfg->label == cfg->label) &&
				    (peer_cfg->tx_max_msg_size ==
				     cfg->tx_max_msg_size) &&
				    (peer_cfg->tx_queue_depth ==
				     cfg->tx_queue_depth)) {
					has_matching_vdevice = true;
					break;
				}
				peer_cfg = NULL;
			}
		}
	} else {
		// no peer vm exists
	}

	// Only destroy if there is no matching vdevice
	if (!has_matching_vdevice) {
		if ((peer_vm != NULL) && (peer_vm->vm_config != NULL)) {
			err = gunyah_hyp_cspace_delete_cap_from(
				peer_vm->vm_config->cspace, cfg->rx_peer_cap);
			assert(err == OK);
			err = gunyah_hyp_cspace_delete_cap_from(
				peer_vm->vm_config->cspace, cfg->tx_peer_cap);
			assert(err == OK);
		}

		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), rx);
		assert(err == OK);
		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), tx);
		assert(err == OK);
	}

	vm_config_delete_vdevice_node(vmcfg, node);
}

static void
handle_rm_rpc_destruction(vm_config_t *vmcfg, vdevice_node_t **node)
{
	assert(vmcfg != NULL);
	assert((node != NULL) && (*node != NULL));

	vmid_t vmid = vmcfg->vm->vmid;

	// Destroy RM RPC FIFO
	rm_error_t rm_err = rm_rpc_fifo_destroy(vmid);
	assert(rm_err == RM_OK);

	// Remove RM RPC link if any
	rm_err = rm_rpc_server_remove_link(vmid);
	assert(rm_err == RM_OK);

	struct vdevice_msg_queue_pair *cfg =
		(struct vdevice_msg_queue_pair *)(*node)->config;

	cap_id_t rx = cfg->rx_master_cap;
	cap_id_t tx = cfg->tx_master_cap;

	error_t err;

	revert_map_virq(vmcfg->vm->vmid, virq_get_number(cfg->rx_vm_virq));
	revert_map_virq(vmcfg->vm->vmid, virq_get_number(cfg->tx_vm_virq));
	revert_map_virq(cfg->peer, virq_get_number(cfg->rx_peer_virq));
	revert_map_virq(cfg->peer, virq_get_number(cfg->tx_peer_virq));

	// The deletes for peer caps are not required,
	// because they are the same as the master caps.
	err = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace, cfg->rx_vm_cap);
	assert(err == OK);
	err = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace, cfg->tx_vm_cap);
	assert(err == OK);

	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), rx);
	assert(err == OK);
	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), tx);
	assert(err == OK);

	vm_config_delete_vdevice_node(vmcfg, node);
	vm_config_remove_console(vmcfg);
}

static void
handle_doorbell_destruction(vm_config_t *vmcfg, vdevice_node_t **node)
{
	assert(vmcfg != NULL);
	assert((node != NULL) && (*node != NULL));

	struct vdevice_doorbell *cfg =
		(struct vdevice_doorbell *)(*node)->config;

	free(cfg->peer_id);

	cap_id_t db_cap = cfg->master_cap;

	// Delete caps copied to VM cspace
	error_t err;
	err = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace, cfg->vm_cap);
	assert(err == OK);

	if (!cfg->source) {
		revert_map_virq(vmcfg->vm->vmid, virq_get_number(cfg->vm_virq));
	}

	bool  has_matching_vdevice = false;
	vm_t *peer_vm		   = vm_lookup(cfg->peer);

	if (!cfg->has_peer_vdevice) {
		// peer-default has no matching doorbell vdevice, therefore
		// we need to return the virqs here. For non-default peer with
		// matching vdevice, this will happen when its VM is reset.

		// If we were the src we need to free the dest virq
		if (cfg->source) {
			revert_map_virq(cfg->peer,
					virq_get_number(cfg->peer_virq));
		}
	} else if ((peer_vm != NULL) && (peer_vm->vm_config != NULL)) {
		// Check if peer's vdevice still exists
		vdevice_node_t		*peer_node = NULL;
		struct vdevice_doorbell *peer_cfg  = NULL;

		loop_list(peer_node, &peer_vm->vm_config->vdevice_nodes,
			  vdevice_)
		{
			if (peer_node->type == VDEV_DOORBELL) {
				peer_cfg = (struct vdevice_doorbell *)
						   peer_node->config;
				if ((peer_cfg->label == cfg->label) &&
				    (peer_cfg->source != cfg->source)) {
					has_matching_vdevice = true;
					break;
				}
				peer_cfg = NULL;
			}
		}
	} else {
		// no peer vm exists
	}

	// Only destroy if there is no matching vdevice
	if (!has_matching_vdevice) {
		if ((peer_vm != NULL) && (peer_vm->vm_config != NULL)) {
			err = gunyah_hyp_cspace_delete_cap_from(
				peer_vm->vm_config->cspace, cfg->peer_cap);
			assert(err == OK);
		}
		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							db_cap);
		assert(err == OK);
	}

	vm_config_delete_vdevice_node(vmcfg, node);
}

static void
handle_msgqueue_destruction(vm_config_t *vmcfg, vdevice_node_t **node)
{
	assert(vmcfg != NULL);
	assert((node != NULL) && (*node != NULL));

	struct vdevice_msg_queue *cfg =
		(struct vdevice_msg_queue *)(*node)->config;

	vm_t *peer_vm = vm_lookup(cfg->peer);
	assert((peer_vm != NULL) && (peer_vm->vm_config != NULL));

	error_t err;

	revert_map_virq(vmcfg->vm->vmid, virq_get_number(cfg->vm_virq));
	revert_map_virq(cfg->peer, virq_get_number(cfg->peer_virq));

	err = gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace, cfg->vm_cap);
	assert(err == OK);
	err = gunyah_hyp_cspace_delete_cap_from(peer_vm->vm_config->cspace,
						cfg->peer_cap);
	assert(err == OK);
	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
						cfg->master_cap);
	assert(err == OK);

	vm_config_delete_vdevice_node(vmcfg, node);
}

static void
handle_shm_destruction(vm_config_t *vmcfg, vdevice_node_t **node)
{
	vm_config_delete_vdevice_node(vmcfg, node);
}

#if defined(CAP_RIGHTS_WATCHDOG_ALL)
static void
handle_watchdog_destruction(vm_config_t *vmcfg, vdevice_node_t **node)
{
	assert(rm_get_watchdog_supported());

	assert(vmcfg != NULL);
	assert((node != NULL) && (*node != NULL));

	error_t err;

	struct vdevice_watchdog *cfg =
		(struct vdevice_watchdog *)(*node)->config;

	watchdog_bind_option_flags_t bind_bite_options =
		watchdog_bind_option_flags_default();
	watchdog_bind_option_flags_set_bite_virq(&bind_bite_options, true);
	err = gunyah_hyp_watchdog_unbind_virq(vmcfg->watchdog,
					      bind_bite_options);
	assert(err == OK);
	revert_map_virq(VMID_RM, virq_get_number(cfg->bite_virq));

	watchdog_bind_option_flags_t bind_bark_options =
		watchdog_bind_option_flags_default();
	err = gunyah_hyp_watchdog_unbind_virq(vmcfg->watchdog,
					      bind_bark_options);
	assert(err == OK);
	revert_map_virq(vmcfg->vm->vmid, virq_get_number(cfg->bark_virq));

	if (cfg->manager_cap != CSPACE_CAP_INVALID) {
		vm_t *manager_vm = vm_lookup(cfg->manager);
		if ((manager_vm != NULL) && (manager_vm->vm_config != NULL)) {
			err = gunyah_hyp_cspace_delete_cap_from(
				manager_vm->vm_config->cspace,
				cfg->manager_cap);
			assert(err == OK);
		}
	}

	vm_mgnt_deregister_event(&vmcfg->vm->wdog_bite_event,
				 virq_get_number(cfg->bite_virq));

	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
						vmcfg->watchdog);
	assert(err == OK);

	vmcfg->watchdog = CSPACE_CAP_INVALID;

	vm_config_delete_vdevice_node(vmcfg, node);
}
#endif

static void
handle_vpm_group_destruction(vm_config_t *vmcfg, vdevice_node_t **node)
{
	assert(vmcfg != NULL);
	assert((node != NULL) && (*node != NULL));

	struct vdevice_virtual_pm *cfg =
		(struct vdevice_virtual_pm *)(*node)->config;

	vm_t *peer_vm = vm_lookup(cfg->peer);
	assert((peer_vm != NULL) && (peer_vm->vm_config != NULL));

	error_t err;

	err = gunyah_hyp_vpm_group_unbind_virq(cfg->master_cap);
	assert(err == OK);

	// Revoke all children caps
	err = gunyah_hyp_cspace_revoke_caps_from(rm_get_rm_cspace(),
						 cfg->master_cap);
	assert(err == OK);

	revert_map_virq(cfg->peer, virq_get_number(cfg->peer_virq));

	err = gunyah_hyp_cspace_delete_cap_from(peer_vm->vm_config->cspace,
						cfg->peer_cap);
	assert(err == OK);

	// The VPM group does not always have an associated vdevice, so the
	// master cap is deleted in vm_config_destroy_vm_objects() instead.

	vm_config_delete_vdevice_node(vmcfg, node);
}

#if defined(CAP_RIGHTS_VIRTIO_MMIO_ALL)
static void
handle_virtio_mmio_destruction(vm_config_t *vmcfg, vdevice_node_t **node)
{
	assert(vmcfg != NULL);
	assert((node != NULL) && (*node != NULL));

	struct vdevice_virtio_mmio *cfg =
		(struct vdevice_virtio_mmio *)(*node)->config;

	cap_id_t virtio_cap = cfg->master_cap;

	vm_t *backend_vm = vm_lookup(cfg->backend);
	assert((backend_vm != NULL) && (backend_vm->vm_config != NULL));

	error_t err;

	revert_map_virq(cfg->backend, virq_get_number(cfg->backend_virq));
	revert_map_virq(vmcfg->vm->vmid, virq_get_number(cfg->frontend_virq));

	err = vm_memory_unmap(vmcfg->vm, VM_MEMUSE_VDEVICE, cfg->me_cap,
			      cfg->frontend_ipa);
	assert(err == OK);

	err = vm_memory_unmap(backend_vm, VM_MEMUSE_VDEVICE, cfg->me_cap,
			      cfg->backend_ipa);
	assert(err == OK);

	err = vm_address_range_free(backend_vm, VM_MEMUSE_VDEVICE,
				    cfg->backend_ipa, cfg->me_size);
	assert(err == OK);

	err = vm_address_range_free(vmcfg->vm, VM_MEMUSE_VDEVICE,
				    cfg->frontend_ipa, cfg->me_size);
	assert(err == OK);

	err = gunyah_hyp_cspace_delete_cap_from(backend_vm->vm_config->cspace,
						cfg->backend_cap);
	assert(err == OK);
	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), virtio_cap);
	assert(err == OK);

	memextent_delete(cfg->me_cap);
	free(cfg->rm_addr);

	vm_config_delete_vdevice_node(vmcfg, node);
}
#endif

static void
handle_iomem_destruction(vm_config_t *vmcfg, vdevice_node_t **node)
{
	assert(vmcfg != NULL);
	assert((node != NULL) && (*node != NULL));

	struct vdevice_iomem *cfg = (struct vdevice_iomem *)(*node)->config;

	if (cfg->rm_sglist_len > 0U) {
		free(cfg->rm_sglist);
	}

	vm_config_delete_vdevice_node(vmcfg, node);
}

static void
vm_config_destroy_vdevice(vm_config_t *vmcfg, vdevice_node_t **node)
{
	switch ((*node)->type) {
	case VDEV_RM_RPC:
		handle_rm_rpc_destruction(vmcfg, node);
		break;
	case VDEV_DOORBELL:
		handle_doorbell_destruction(vmcfg, node);
		break;
	case VDEV_MSG_QUEUE:
		handle_msgqueue_destruction(vmcfg, node);
		break;
	case VDEV_MSG_QUEUE_PAIR:
		handle_msgqueue_pair_destruction(vmcfg, node);
		break;
	case VDEV_SHM:
		handle_shm_destruction(vmcfg, node);
		break;
#if defined(CAP_RIGHTS_WATCHDOG_ALL)
	case VDEV_WATCHDOG:
		handle_watchdog_destruction(vmcfg, node);
		break;
#endif
	case VDEV_VIRTUAL_PM:
		handle_vpm_group_destruction(vmcfg, node);
		break;
#if defined(CAP_RIGHTS_VIRTIO_MMIO_ALL)
	case VDEV_VIRTIO_MMIO:
		handle_virtio_mmio_destruction(vmcfg, node);
		break;
#endif
	case VDEV_IOMEM:
		handle_iomem_destruction(vmcfg, node);
		break;
	case VDEV_RTC:
		(void)handle_rtc_teardown(vmcfg, node);
		break;
	case VDEV_MINIDUMP:
	default:
		(void)printf("Error: invalid vdevice\n");
		break;
	}
}

static bool
try_run_vcpu(vm_config_t *vmcfg, vcpu_t *vcpu)
{
	bool scheduled = false;

	assert(vmcfg != NULL);
	assert(vmcfg->vm != NULL);
	assert(vcpu != NULL);

	if (vcpu->exited) {
		goto out;
	}

	vcpu_run_state_t vcpu_state;
	register_t	 state_data;

	bool is_proxy_scheduled = virq_is_valid(vcpu->proxy_virq);

	if (is_proxy_scheduled) {
		gunyah_hyp_vcpu_run_result_t res =
			gunyah_hyp_vcpu_run(vcpu->master_cap, 0U, 0U, 0U);
		scheduled  = (res.error == OK);
		vcpu_state = res.vcpu_state;
		state_data = res.state_data_0;
	} else {
		gunyah_hyp_vcpu_run_check_result_t res =
			gunyah_hyp_vcpu_run_check(vcpu->master_cap);
		assert((res.error == OK) || (res.error == ERROR_BUSY));
		vcpu_state = res.vcpu_state;
		state_data = res.state_data_0;
	}

	if (vcpu_state == VCPU_RUN_STATE_POWERED_OFF) {
		// Confirm that the VCPU exited.
		vcpu_run_poweroff_flags_t flags =
			vcpu_run_poweroff_flags_cast((uint32_t)state_data);
		assert(vcpu_run_poweroff_flags_get_exited(&flags));
		vcpu->exited = true;
		goto out;
	}

	assert((vcpu_state == VCPU_RUN_STATE_READY) ||
	       (vcpu_state == VCPU_RUN_STATE_BLOCKED));

	if (!is_proxy_scheduled) {
		// We can only indirectly assist in scheduling the VCPU; boost
		// its priority to the default if the VM had low priority.
		if (vmcfg->vm->priority < SCHEDULER_DEFAULT_PRIORITY) {
			error_t err = gunyah_hyp_vcpu_set_priority(
				vcpu->master_cap, SCHEDULER_DEFAULT_PRIORITY);
			assert(err == OK);
		}
	}

out:
	return scheduled;
}

static bool
wait_for_vcpu_exit(const vm_t *vm)
{
	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	vm_config_t *vmcfg = vm->vm_config;

	size_t	vcpu_count	   = vector_size(vmcfg->vcpus);
	bool	vcpu_still_running = false;
	index_t i;

	for (i = 0U; i < vcpu_count; i++) {
		vcpu_t *vcpu = vector_at(vcpu_t *, vmcfg->vcpus, i);
		assert(vcpu != NULL);

		bool scheduled = try_run_vcpu(vmcfg, vcpu);
		if (!vcpu->exited) {
			vcpu_still_running = true;
		}

		if (scheduled && event_is_pending()) {
			// An event became pending while the VCPU was
			// running; handle it immediately.
			break;
		}
	}

	bool all_exited = (i == vcpu_count) && !vcpu_still_running;

	if (!all_exited && !event_is_pending()) {
		// Sleep for a short time and wait for the VCPUs to exit.
		struct timespec ts = { .tv_nsec = 2000000U }; // 2ms
		(void)clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, NULL);
	}

	return all_exited;
}

static void
kill_all_vcpus(const vm_t *vm)
{
	vector_t *vcpus = vm_config_get_vcpus(vm->vm_config);

	size_t num_vcpus = vector_size(vcpus);
	for (index_t i = 0; i < num_vcpus; i++) {
		vcpu_t *vcpu = vector_at(vcpu_t *, vcpus, i);
		assert(vcpu != NULL);
		error_t err = gunyah_hyp_vcpu_kill(vcpu->master_cap);
		assert(err == OK);
	}
}

void
vm_config_handle_exit(const vm_t *vm)
{
	kill_all_vcpus(vm);

	while (!wait_for_vcpu_exit(vm)) {
	}

	error_t ret = platform_vm_exit(vm);
	assert(ret == OK);
}

bool
vm_reset_handle_init(const vm_t *vm)
{
	(void)vm;
	return true;
}

// Destroy one vdevice per event handler
bool
vm_reset_handle_destroy_vdevices(const vm_t *vm)
{
	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	vm_config_t *vmcfg = vm->vm_config;

	vdevice_node_t *node = vmcfg->vdevice_nodes;
	if (node != NULL) {
		vm_config_destroy_vdevice(vmcfg, &node);
	}

	// Returns whether there are any other vdevices to destroy
	bool generic_vdevice_destruction_done = is_empty(vmcfg->vdevice_nodes);

	if (generic_vdevice_destruction_done) {
		error_t err = platform_handle_destroy_vdevices(vm);
		assert(err == OK);
	}

	return generic_vdevice_destruction_done;
}

void
vm_config_destroy_vdevices(vm_t *vm)
{
	assert(vm != NULL);
	assert(vm->vm_config != NULL);

	vm_config_t *vmcfg = vm->vm_config;

	vdevice_node_t *current_node = NULL;
	vdevice_node_t *next_node    = NULL;

	loop_list_safe(current_node, next_node, &vmcfg->vdevice_nodes, vdevice_)
	{
		vm_config_destroy_vdevice(vmcfg, &current_node);
	}
}
