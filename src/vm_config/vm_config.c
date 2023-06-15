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
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_console.h>
#include <vm_creation.h>
#include <vm_memory.h>
#include <vm_mgnt.h>
#include <vm_resource_msg.h>
#include <vm_vcpu.h>

// Must be last
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
		   size_t *frontend_size, vmaddr_t *backend_ipa,
		   size_t *backend_size, cap_id_t *me_cap);
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
			  size_t frontend_size, vmaddr_t backend_ipa,
			  size_t backend_size, cap_id_t me_cap);
#endif

static vdevice_node_t *
vm_config_add_doorbell(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
		       bool source, interrupt_data_t virq, uint32_t label,
		       const char *generate, bool export_to_dt,
		       bool source_can_clear);
static void
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
		       interrupt_data_t bark_virq, bool allow_management,
		       bool virtual_regs);
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

#if defined(CAP_RIGHTS_VIRTIO_MMIO_ALL)
static error_t
add_virtio_mmio(vm_config_t *frontend_cfg, virtio_mmio_data_t *d);
#endif

static rm_error_t
get_vdev_desc(vmid_t self, vmid_t vmid, vdevice_node_t *node, vector_t *descs)
{
	if (!node->visible) {
		goto out;
	}

	rm_hyp_resource_resp_t item = {
		.partner_vmid = vmid,
	};

	if (node->type == VDEV_DOORBELL) {
		struct vdevice_doorbell *db =
			(struct vdevice_doorbell *)node->config;
		if (db->peer == vmid) {
			// Doorbell from self vdevice list
			item.resource_type  = (db->source) ? RSC_DOORBELL_SRC
							   : RSC_DOORBELL;
			item.resource_label = db->label;
			item.resource_capid_low =
				(uint32_t)(db->vm_cap & 0xffffffffU);
			item.resource_capid_high = (uint32_t)(db->vm_cap >> 32);
			item.resource_virq_number =
				irq_manager_virq_for_hypercall(db->vm_virq);
			vector_push_back(descs, item);
		} else if (db->peer == self) {
			// Doorbell from peer vdevice list
			item.resource_type  = (db->source) ? RSC_DOORBELL
							   : RSC_DOORBELL_SRC;
			item.resource_label = db->label;
			item.resource_capid_low =
				(uint32_t)(db->peer_cap & 0xffffffffU);
			item.resource_capid_high =
				(uint32_t)(db->peer_cap >> 32);
			item.resource_virq_number =
				irq_manager_virq_for_hypercall(db->peer_virq);
			vector_push_back(descs, item);
		} else {
			// Ignore
		}
	} else if (node->type == VDEV_MSG_QUEUE) {
		struct vdevice_msg_queue *mq =
			(struct vdevice_msg_queue *)node->config;
		if (mq->peer == vmid) {
			// Msgqueue from self vdevice list
			item.resource_type  = (mq->tx) ? RSC_MSG_QUEUE_SEND
						       : RSC_MSG_QUEUE_RECV;
			item.resource_label = mq->label;
			item.resource_capid_low =
				(uint32_t)(mq->vm_cap & 0xffffffffU);
			item.resource_capid_high = (uint32_t)(mq->vm_cap >> 32);
			item.resource_virq_number =
				irq_manager_virq_for_hypercall(mq->vm_virq);
			vector_push_back(descs, item);
		} else if (mq->peer == self) {
			// Msgqueue from peer vdevice list
			item.resource_type  = (mq->tx) ? RSC_MSG_QUEUE_RECV
						       : RSC_MSG_QUEUE_SEND;
			item.resource_label = mq->label;
			item.resource_capid_low =
				(uint32_t)(mq->peer_cap & 0xffffffffU);
			item.resource_capid_high =
				(uint32_t)(mq->peer_cap >> 32);
			item.resource_virq_number =
				irq_manager_virq_for_hypercall(mq->peer_virq);
			vector_push_back(descs, item);
		} else {
			// Ignore
		}
	} else if (node->type == VDEV_MSG_QUEUE_PAIR) {
		struct vdevice_msg_queue_pair *mq =
			(struct vdevice_msg_queue_pair *)node->config;
		if (mq->peer == vmid) {
			// Tx msgqueue from self vdevice list
			item.resource_type  = RSC_MSG_QUEUE_SEND;
			item.resource_label = mq->label;
			item.resource_capid_low =
				(uint32_t)(mq->tx_vm_cap & 0xffffffffU);
			item.resource_capid_high =
				(uint32_t)(mq->tx_vm_cap >> 32);
			item.resource_virq_number =
				irq_manager_virq_for_hypercall(mq->tx_vm_virq);
			vector_push_back(descs, item);

			// Rx msgqueue from self vdevice list
			item.resource_type  = RSC_MSG_QUEUE_RECV;
			item.resource_label = mq->label;
			item.resource_capid_low =
				(uint32_t)(mq->rx_vm_cap & 0xffffffffU);
			item.resource_capid_high =
				(uint32_t)(mq->rx_vm_cap >> 32);
			item.resource_virq_number =
				irq_manager_virq_for_hypercall(mq->rx_vm_virq);
			vector_push_back(descs, item);
		} else if ((mq->peer == self) && (!mq->has_peer_vdevice)) {
			// returns resource info if the there's no peer vdevice
			// Currently, only use peer-default (PVM), the vdevice
			// is only defined in SVM side.
			// Tx msgqueue from peer vdevice list
			item.resource_type  = RSC_MSG_QUEUE_SEND;
			item.resource_label = mq->label;
			item.resource_capid_low =
				(uint32_t)(mq->tx_peer_cap & 0xffffffffU);
			item.resource_capid_high =
				(uint32_t)(mq->tx_peer_cap >> 32);
			item.resource_virq_number =
				irq_manager_virq_for_hypercall(
					mq->tx_peer_virq);
			vector_push_back(descs, item);

			// Rx msgqueue from peer vdevice list
			item.resource_type  = RSC_MSG_QUEUE_RECV;
			item.resource_label = mq->label;
			item.resource_capid_low =
				(uint32_t)(mq->rx_peer_cap & 0xffffffffU);
			item.resource_capid_high =
				(uint32_t)(mq->rx_peer_cap >> 32);
			item.resource_virq_number =
				irq_manager_virq_for_hypercall(
					mq->rx_peer_virq);
			vector_push_back(descs, item);
		} else {
			// Ignore
		}
	} else if (node->type == VDEV_VIRTUAL_PM) {
		struct vdevice_virtual_pm *vpm =
			(struct vdevice_virtual_pm *)node->config;
		assert(vpm != NULL);

		if (vpm->peer == self) {
			item.resource_type  = RSC_VIRTUAL_PM;
			item.resource_label = vpm->label;
			item.resource_capid_low =
				(uint32_t)(vpm->peer_cap & 0xffffffffU);
			item.resource_capid_high =
				(uint32_t)(vpm->peer_cap >> 32);
			item.resource_virq_number =
				irq_manager_virq_for_hypercall(vpm->peer_virq);
			vector_push_back(descs, item);
		} else {
			// Ignore
		}
#if defined(CAP_RIGHTS_VIRTIO_MMIO_ALL)
	} else if (node->type == VDEV_VIRTIO_MMIO) {
		struct vdevice_virtio_mmio *vio =
			(struct vdevice_virtio_mmio *)node->config;
		assert(vio != NULL);

		if (vio->backend == self) {
			item.resource_type  = RSC_VIRTIO_MMIO;
			item.resource_label = vio->label;
			item.resource_capid_low =
				(uint32_t)(vio->backend_cap & 0xffffffffU);
			item.resource_capid_high =
				(uint32_t)(vio->backend_cap >> 32);
			item.resource_virq_number =
				irq_manager_virq_for_hypercall(
					vio->backend_virq);
			item.resource_base_address_low =
				(uint32_t)(vio->backend_ipa & 0xffffffffU);
			item.resource_base_address_high =
				(uint32_t)(vio->backend_ipa >> 32);
			item.resource_size_low =
				(uint32_t)(vio->backend_size & 0xffffffffU);
			item.resource_size_high =
				(uint32_t)(vio->backend_size >> 32);
			vector_push_back(descs, item);
		} else {
			// Ignore
		}
#endif
#if defined(CAP_RIGHTS_WATCHDOG_ALL)
	} else if (node->type == VDEV_WATCHDOG) {
		struct vdevice_watchdog *vwdt =
			(struct vdevice_watchdog *)node->config;
		assert(vwdt != NULL);

		if (vwdt->manager == self) {
			item.resource_type = RSC_WATCHDOG;
			item.resource_capid_low =
				(uint32_t)(vwdt->manager_cap & 0xffffffffU);
			item.resource_capid_high =
				(uint32_t)(vwdt->manager_cap >> 32);
			vector_push_back(descs, item);
		}
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
				irq_manager_virq_for_hypercall(
					vcpu->proxy_virq);

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
		   bool boot_vcpu, char *patch)
{
	error_t ret  = OK;
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
	vcpu->patch	     = patch;
	vcpu->vmid	     = vmcfg->vm->vmid;

	// Allocate halt virq
	irq_manager_get_free_virt_virq_ret_t free_irq_ret;
	free_irq_ret = irq_manager_get_free_virt_virq(VMID_RM, false);
	if (free_irq_ret.err != RM_OK) {
		ret = ERROR_DENIED;
		goto deallocate;
	}

	interrupt_data_t halt_virq = free_irq_ret.virq;

	rm_error_t rm_err = irq_manager_reserve_virq(VMID_RM, halt_virq, true);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
		goto deallocate;
	}

	vcpu->halt_virq = halt_virq;

	error_t err;

	// Bind the halt virq to RM's vic
	ret = gunyah_hyp_vcpu_bind_virq(rm_cap, rm_get_rm_vic(), halt_virq.irq,
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
	rm_err = vm_mgnt_register_event(VM_EVENT_SRC_VCPU_HALT,
					&vcpu->halt_event, vcpu, halt_virq.irq);
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
	err = irq_manager_return_virq(VMID_RM, halt_virq);
	assert(err == OK);
deallocate:
	free(vcpu);
out:
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
		if (vcpu->proxy_virq.irq != VIRQ_INVALID.irq) {
			err = gunyah_hyp_vcpu_unbind_virq(
				vcpu->master_cap,
				VCPU_VIRQ_TYPE_VCPU_RUN_WAKEUP);
			assert(err == OK);

			err = irq_manager_return_virq(vmcfg->vm->owner,
						      vcpu->proxy_virq);
			assert(err == OK);
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
					 vcpu->halt_virq.irq);
		err = gunyah_hyp_vcpu_unbind_virq(vcpu->master_cap,
						  VCPU_VIRQ_TYPE_HALT);
		assert(err == OK);

		err = irq_manager_return_virq(VMID_RM, vcpu->halt_virq);
		assert(err == OK);

		if (delete_master_caps) {
			err = gunyah_hyp_cspace_delete_cap_from(
				rm_get_rm_cspace(), vcpu->master_cap);
			assert(err == OK);
		}
		free(vcpu);
	}

	// FIXME:
	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
						vmcfg->cspace);
	assert(err == OK);
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
	ret = gunyah_hyp_vpm_group_bind_virq(
		rm_cap, peer_cfg->vic,
		irq_manager_virq_for_hypercall(peer_virq));
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
	error_t	 ret = OK;
	error_t	 err = OK;

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		(void)printf("Failed: to alloc vdevice node\n");
		ret = ERROR_NOMEM;
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
		ret = copy_ret.error;
		goto out;
	}
	send_cap = copy_ret.new_cap;

	// Copy doorbell cap to recv VM cspace with receive rights
	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(), rm_cap,
						   recv_cfg->cspace,
						   CAP_RIGHTS_DOORBELL_RECEIVE);
	if (copy_ret.error != OK) {
		(void)printf("Failed: to copy recv cap\n");
		ret = copy_ret.error;
		goto out;
	}
	recv_cap = copy_ret.new_cap;

	// Bind VIRQ to recv VM's VIC
	ret = gunyah_hyp_doorbell_bind_virq(
		rm_cap, recv_cfg->vic, irq_manager_virq_for_hypercall(virq));
	if (ret != OK) {
		(void)printf("Failed: to bind db virq(%d) err(0x%x)\n",
			     irq_manager_virq_for_hypercall(virq), err);
		goto out;
	}

	cfg->peer	= peer;
	cfg->source	= source;
	cfg->master_cap = rm_cap;
	cfg->label	= label;
	if (source) {
		cfg->vm_cap   = send_cap;
		cfg->vm_virq  = (interrupt_data_t){ 0 };
		cfg->peer_cap = recv_cap;

		cfg->peer_virq = virq;
	} else {
		cfg->vm_cap    = recv_cap;
		cfg->vm_virq   = virq;
		cfg->peer_cap  = send_cap;
		cfg->peer_virq = (interrupt_data_t){ 0 };
	}

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);
out:
	if ((ret != OK) && (node != NULL)) {
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
			  size_t frontend_size, vmaddr_t backend_ipa,
			  size_t backend_size, cap_id_t me_cap)
{
	error_t ret = OK;

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		(void)printf("Failed: to alloc vdevice node\n");
		goto out;
	}
	memset(node, 0, sizeof(*node));

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
		rm_cap, frontend_cfg->vic,
		irq_manager_virq_for_hypercall(frontend_virq));
	if (ret != OK) {
		(void)printf("Failed: to bind fe virq\n");
		goto error_bind_fe;
	}

	// Bind backend's VIRQ and vic to frontend's source, so that the backend
	// gets an interrupt every time the frontend writes to the kick register
	ret = gunyah_hyp_virtio_mmio_frontend_bind_virq(
		rm_cap, backend_cfg->vic,
		irq_manager_virq_for_hypercall(backend_virq));
	if (ret != OK) {
		(void)printf("failed: to bind be virq\n");
		goto error_bind_be;
	}

	cfg->backend	   = backend_cfg->vm->vmid;
	cfg->master_cap	   = rm_cap;
	cfg->label	   = d->general.label;
	cfg->frontend_virq = frontend_virq;
	cfg->backend_cap   = backend_cap;
	cfg->backend_virq  = backend_virq;
	cfg->frontend_ipa  = frontend_ipa;
	cfg->frontend_size = frontend_size;
	cfg->backend_ipa   = backend_ipa;
	cfg->backend_size  = backend_size;
	cfg->dma_base	   = d->dma_base;
	cfg->dma_coherent  = d->dma_coherent;
	cfg->need_allocate = d->need_allocate;
	cfg->base_ipa	   = d->mem_base_ipa;
	cfg->memextent_cap = me_cap;

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

static void
vm_config_add_msgqueue(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
		       bool tx, interrupt_data_t vm_virq,
		       interrupt_data_t peer_virq, const msg_queue_data_t *data,
		       bool export_to_dt)
{
	vm_config_t *tx_cfg = NULL, *rx_cfg = NULL;

	cap_id_t tx_cap = CSPACE_CAP_INVALID, rx_cap = CSPACE_CAP_INVALID;

	error_t ret = OK;
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
		err = ERROR_NOMEM;
		goto out;
	}

	err = handle_compatibles(node, &data->general);
	if (err != OK) {
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
	ret = gunyah_hyp_msgqueue_bind_send_virq(
		rm_cap, tx_cfg->vic, irq_manager_virq_for_hypercall(tx_virq));
	if (ret != OK) {
		(void)printf("Failed: to bind tx virq\n");
		goto out;
	}
	ret = gunyah_hyp_msgqueue_bind_receive_virq(
		rm_cap, rx_cfg->vic, irq_manager_virq_for_hypercall(rx_virq));
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

	return;
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

	vmid_t vmid = vmcfg->vm->vmid;

	irq_manager_get_free_virt_virq_ret_t free_irq_ret;
	rm_error_t			     rm_err;

	interrupt_data_t vm_tx_virq = defined_tx_virq;
	if (alloc_irq) {
		free_irq_ret = irq_manager_get_free_virt_virq(vmid, false);
		if (free_irq_ret.err != RM_OK) {
			(void)printf("Failed: to get free virq\n");
			ret = ERROR_DENIED;
			goto out;
		}
		vm_tx_virq = free_irq_ret.virq;
	}

	rm_err = irq_manager_reserve_virq(vmid, vm_tx_virq, true);
	if (rm_err != RM_OK) {
		(void)printf("Failed: to reserve virq\n");
		ret = ERROR_DENIED;
		goto out;
	}

	error_t err;

	interrupt_data_t vm_rx_virq = defined_rx_virq;
	if (alloc_irq) {
		free_irq_ret = irq_manager_get_free_virt_virq(vmid, false);
		if (free_irq_ret.err != RM_OK) {
			(void)printf("Failed: to get free virq\n");
			ret = ERROR_DENIED;
			goto out_return_tx_virq;
		}
		vm_rx_virq = free_irq_ret.virq;
	}

	rm_err = irq_manager_reserve_virq(vmid, vm_rx_virq, true);
	if (rm_err != RM_OK) {
		(void)printf("Failed: to reserve virq\n");
		ret = ERROR_DENIED;
		goto out_return_tx_virq;
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
	ret = gunyah_hyp_msgqueue_bind_send_virq(
		rm_tx_cap, vmcfg->vic,
		irq_manager_virq_for_hypercall(vm_tx_virq));
	if (ret != OK) {
		(void)printf("Failed: to bind virq\n");
		goto out_delete_rx_cap;
	}

	ret = gunyah_hyp_msgqueue_bind_receive_virq(
		rm_rx_cap, vmcfg->vic,
		irq_manager_virq_for_hypercall(vm_rx_virq));
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
	err = irq_manager_return_virq(vmid, vm_rx_virq);
	assert(err == OK);
out_return_tx_virq:
	err = irq_manager_return_virq(vmid, vm_tx_virq);
	assert(err == OK);
out:
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
			goto out_free_cfg;
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

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);

out_invalid_msg_queue_pair_argument:
out_free_default_peer_cfg:
	if ((data->peer_id == NULL) && (peer_cfg != NULL)) {
		free(peer_cfg);
	}
	if (ret == OK) {
		goto out;
	}
out_teardown_vm_msgqueue_pair:
	handle_msgqueue_pair_destruction(vmcfg, &node);
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

	rm_error_t rm_err = RM_OK;

	irq_manager_get_free_virt_virq_ret_t free_irq_ret;

	free_irq_ret = irq_manager_get_free_virt_virq(peer, false);
	if (free_irq_ret.err != RM_OK) {
		ret = ERROR_DENIED;
		goto out_free_config;
	}
	rm_tx_virq = free_irq_ret.virq;

	rm_err = irq_manager_reserve_virq(peer, rm_tx_virq, true);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
		goto out_free_config;
	}

	error_t err;

	free_irq_ret = irq_manager_get_free_virt_virq(peer, false);
	if (free_irq_ret.err != RM_OK) {
		ret = ERROR_DENIED;
		goto out_return_rm_tx_virq;
	}
	rm_rx_virq = free_irq_ret.virq;

	rm_err = irq_manager_reserve_virq(peer, rm_rx_virq, true);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
		goto out_return_rm_tx_virq;
	}

	if (data->defined_irq) {
		vm_tx_virq = data->irqs[TX_IRQ_IDX];
	} else {
		free_irq_ret = irq_manager_get_free_virt_virq(self, false);
		if (free_irq_ret.err != RM_OK) {
			ret = ERROR_DENIED;
			goto out_return_rm_rx_virq;
		}

		vm_tx_virq = free_irq_ret.virq;
	}

	rm_err = irq_manager_reserve_virq(self, vm_tx_virq, true);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
		goto out_return_rm_rx_virq;
	}

	if (data->defined_irq) {
		vm_rx_virq = data->irqs[RX_IRQ_IDX];
	} else {
		free_irq_ret = irq_manager_get_free_virt_virq(self, false);
		if (free_irq_ret.err != RM_OK) {
			ret = ERROR_DENIED;
			goto out_return_vm_tx_virq;
		}
		vm_rx_virq = free_irq_ret.virq;
	}

	rm_err = irq_manager_reserve_virq(self, vm_rx_virq, true);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
		goto out_return_vm_tx_virq;
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
		irq_manager_virq_for_hypercall(rm_rx_virq));
	if (ret != OK) {
		goto out_delete_cap_rx_vm;
	}
	cfg->rx_peer_virq = rm_rx_virq;

	ret = gunyah_hyp_msgqueue_bind_send_virq(
		cfg->rx_master_cap, rm_get_rm_vic(),
		irq_manager_virq_for_hypercall(rm_tx_virq));
	if (ret != OK) {
		goto out_unbind_rm_rx_virq;
	}
	cfg->tx_peer_virq = rm_tx_virq;

	// Bind virqs to VM's vic
	ret = gunyah_hyp_msgqueue_bind_send_virq(
		cfg->tx_master_cap, vmcfg->vic,
		irq_manager_virq_for_hypercall(vm_tx_virq));
	if (ret != OK) {
		goto out_unbind_rm_tx_virq;
	}
	cfg->tx_vm_virq = vm_tx_virq;

	ret = gunyah_hyp_msgqueue_bind_receive_virq(
		cfg->rx_master_cap, vmcfg->vic,
		irq_manager_virq_for_hypercall(vm_rx_virq));
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
	err = irq_manager_return_virq(self, vm_rx_virq);
	assert(err == OK);
out_return_vm_tx_virq:
	err = irq_manager_return_virq(self, vm_tx_virq);
	assert(err == OK);
out_return_rm_rx_virq:
	err = irq_manager_return_virq(peer, rm_rx_virq);
	assert(err == OK);
out_return_rm_tx_virq:
	err = irq_manager_return_virq(peer, rm_tx_virq);
	assert(err == OK);
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
		       interrupt_data_t bark_virq, bool allow_management,
		       bool virtual_regs)
{
	error_t ret = OK;

	if (vmcfg->watchdog == CSPACE_CAP_INVALID) {
		ret = ERROR_DENIED;
		goto out;
	}

	vdevice_node_t *node = calloc(1, sizeof(*node));
	assert(node != NULL);

	if (virtual_regs) {
		ret = gunyah_hyp_addrspace_attach_vdevice(
			vmcfg->addrspace, vmcfg->watchdog, 0U,
			rm_get_watchdog_address(), PAGE_SIZE);
		if (ret != OK) {
			(void)printf(
				"Failed to attach watchdog virtual device: %d\n",
				ret);
			goto out;
		}
	}

	// If no bind options are set, it will assume that its a bark virq
	watchdog_bind_option_flags_t bind_bark_options =
		watchdog_bind_option_flags_default();

	// Bind the watchdog bark vIRQ to VM's VIC
	ret = gunyah_hyp_watchdog_bind_virq(
		vmcfg->watchdog, vmcfg->vic,
		irq_manager_virq_for_hypercall(bark_virq), bind_bark_options);
	if (ret != OK) {
		goto err_bind_bark_virq;
	}

	error_t err;

	irq_manager_get_free_virt_virq_ret_t free_irq_ret;
	free_irq_ret = irq_manager_get_free_virt_virq(VMID_RM, false);
	if (free_irq_ret.err != RM_OK) {
		ret = ERROR_DENIED;
		goto err_reserve_virq;
	}

	interrupt_data_t bite_virq = free_irq_ret.virq;

	rm_error_t rm_err = irq_manager_reserve_virq(VMID_RM, bite_virq, true);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
		goto err_reserve_virq;
	}

	watchdog_bind_option_flags_t bind_bite_options =
		watchdog_bind_option_flags_default();
	watchdog_bind_option_flags_set_bite_virq(&bind_bite_options, true);

	// Bind the watchdog bite virq to RM's vic
	ret = gunyah_hyp_watchdog_bind_virq(
		vmcfg->watchdog, rm_get_rm_vic(),
		irq_manager_virq_for_hypercall(bite_virq), bind_bite_options);
	if (ret != OK) {
		goto err_bind_bite_virq;
	}

	// Register event to handle watchdog bite virq
	rm_err = vm_mgnt_register_event(VM_EVENT_SRC_WDOG_BITE,
					&vmcfg->vm->wdog_bite_event, vmcfg->vm,
					bite_virq.irq);
	if (rm_err != RM_OK) {
		ret = ERROR_DENIED;
		goto err_register_event;
	}

	node->type	   = VDEV_WATCHDOG;
	node->export_to_dt = true;
	node->visible	   = true;
	node->generate	   = "/hypervisor/qcom,gh-watchdog";

	cap_id_t manager_cap = CSPACE_CAP_INVALID;
	vmid_t	 manager     = allow_management ? (vmcfg->vm->owner) : VMID_HYP;
	if (manager != VMID_HYP) {
		vm_t *manager_vm = vm_lookup(manager);
		if ((manager_vm == NULL) || (manager_vm->vm_config == NULL)) {
			(void)printf("Failed: invalid owner VM\n");
			ret = ERROR_ARGUMENT_INVALID;
			goto err_copy_mgnt_cap;
		}

		vm_config_t *manager_cfg = manager_vm->vm_config;
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
	assert(cfg != NULL);
	cfg->bark_virq	  = bark_virq;
	cfg->bite_virq	  = bite_virq;
	cfg->virtual_regs = virtual_regs;
	cfg->manager	  = manager;
	cfg->manager_cap  = manager_cap;
	node->config	  = cfg;

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);

	if (ret == OK) {
		goto out;
	}

err_copy_mgnt_cap:
	(void)gunyah_hyp_watchdog_unbind_virq(vmcfg->watchdog,
					      bind_bite_options);
err_register_event:
	err = gunyah_hyp_watchdog_unbind_virq(vmcfg->watchdog,
					      bind_bite_options);
	assert(err == OK);
err_bind_bite_virq:
	err = irq_manager_return_virq(VMID_RM, bite_virq);
	assert(err == OK);
err_reserve_virq:
	err = gunyah_hyp_watchdog_unbind_virq(vmcfg->watchdog,
					      bind_bark_options);
	assert(err == OK);
err_bind_bark_virq:
	free(node);
out:
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

	// Reserve VIRQs
	rm_error_t rm_err = RM_OK;
	error_t	   err;

	interrupt_data_t svirq = self_virq;
	if (alloc_self_virq) {
		irq_manager_get_free_virt_virq_ret_t free_irq_ret;
		free_irq_ret = irq_manager_get_free_virt_virq(self, false);
		if (free_irq_ret.err != RM_OK) {
			ret = ERROR_DENIED;
			goto out_destroy_msq;
		}
		svirq = free_irq_ret.virq;
	}

	rm_err = irq_manager_reserve_virq(self, svirq, true);
	if (rm_err != OK) {
		ret = ERROR_DENIED;
		goto out_destroy_msq;
	}

	interrupt_data_t pvirq = peer_virq;
	if (alloc_peer_virq) {
		// or else it will get the same virq number
		assert(peer != self);

		irq_manager_get_free_virt_virq_ret_t free_irq_ret;
		free_irq_ret = irq_manager_get_free_virt_virq(peer, false);
		if (free_irq_ret.err != RM_OK) {
			ret = ERROR_DENIED;
			goto out_return_virq;
		}
		pvirq = free_irq_ret.virq;
	}

	rm_err = irq_manager_reserve_virq(peer, pvirq, true);
	if (rm_err != OK) {
		ret = ERROR_DENIED;
		goto out_return_virq;
	}

	vm_config_add_msgqueue(vmcfg, peer, mq.r, is_sender, svirq, pvirq, data,
			       true);

	goto out;

out_return_virq:
	err = irq_manager_return_virq(self, svirq);
	assert(err == OK);
out_destroy_msq:
	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), mq.r);
	assert(err == OK);
out:
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

	if ((peer_vm == NULL) || is_default_peer) {
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
handle_doorbell(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;

	size_t cnt = vector_size(data->doorbells);
	for (index_t i = 0; i < cnt; ++i) {
		doorbell_data_t *d =
			vector_at_ptr(doorbell_data_t, data->doorbells, i);

		vmid_t peer = get_peer(vmcfg, d->peer);

		add_doorbell_ret_t add_ret = add_doorbell(
			vmcfg, vmcfg->vm->vmid, peer, d->is_source,
			d->general.label, d->general.generate, d->irq,
			!d->defined_irq, true, d->source_can_clear);
		if (add_ret.err != OK) {
			ret = add_ret.err;
			goto out;
		}

		ret = handle_compatibles(add_ret.node, &d->general);
		if (ret != OK) {
			(void)printf(
				"Failed: save compatible in doorbell node\n");
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

	if (cnt > 0) {
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
	if ((vcpu_cnt == 0) || (vcpu_cnt > max_cores)) {
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

			irq_manager_get_free_virt_virq_ret_t free_irq_ret;
			free_irq_ret =
				irq_manager_get_free_virt_virq(peer, false);
			if (free_irq_ret.err != RM_OK) {
				(void)printf(
					"handle_vcpu: failed get free virq\n");
				ret = ERROR_DENIED;
				goto err_alloc_virq;
			}

			vpm_virq = free_irq_ret.virq;

			rm_error_t rm_err =
				irq_manager_reserve_virq(peer, vpm_virq, true);
			if (rm_err != RM_OK) {
				(void)printf(
					"handle_vcpu: failed reserve vpm_virq\n");
				ret = ERROR_DENIED;
				goto err_alloc_virq;
			}

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

			irq_manager_get_free_virt_virq_ret_t free_irq_ret;
			free_irq_ret =
				irq_manager_get_free_virt_virq(owner, false);
			if (free_irq_ret.err != RM_OK) {
				(void)printf(
					"handle_vcpu: failed get free virq for proxy sched\n");
				ret = ERROR_DENIED;
				goto err_activate_thread;
			}

			proxy_virq = free_irq_ret.virq;

			rm_error_t rm_err = irq_manager_reserve_virq(
				owner, proxy_virq, true);
			if (rm_err != RM_OK) {
				(void)printf(
					"handle_vcpu: failed reserve proxy_virq\n");
				ret = ERROR_DENIED;
				goto err_activate_thread;
			}

			// Bind VIRQ to peer's vic
			ret = gunyah_hyp_vcpu_bind_virq(
				caps[i], owner_cfg->vic,
				irq_manager_virq_for_hypercall(proxy_virq),
				VCPU_VIRQ_TYPE_VCPU_RUN_WAKEUP);
			if (ret != OK) {
				(void)printf(
					"handle_vcpu: failed to bind proxy_virq %d\n",
					ret);
				err = irq_manager_return_virq(owner,
							      proxy_virq);
				assert(err == OK);
				goto err_activate_thread;
			}

			vcpu->proxy_virq = proxy_virq;
		} else {
			vcpu->proxy_virq = VIRQ_INVALID;
		}

		(void)printf("handle_vcpu: activated VCPU %d with VIRQ %d\n", i,
			     irq_manager_virq_for_hypercall(vcpu->proxy_virq));
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
	if ((ret != OK) && (vpm_virq.irq != VIRQ_INVALID.irq)) {
		err = irq_manager_return_virq(peer, vpm_virq);
		assert(err == OK);
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

	irq_manager_get_free_virt_virq_ret_t free_irq_ret;
	free_irq_ret = irq_manager_get_free_virt_virq(vmid, false);
	if (free_irq_ret.err != RM_OK) {
		(void)printf("handle_watchdog: failed get free virq\n");
		ret = ERROR_DENIED;
		goto err_alloc_virq;
	}

	interrupt_data_t bark_virq = free_irq_ret.virq;

	rm_error_t rm_err = irq_manager_reserve_virq(vmid, bark_virq, true);
	if (rm_err != RM_OK) {
		(void)printf("handle_watchdog: failed reserve bark virq\n");
		ret = ERROR_DENIED;
		goto err_alloc_virq;
	}

	// Add the watchdog, and allow the owner to manage the watchdog if the
	// VM is proxy-scheduled (and therefore might be starved of CPU time by
	// the owner)
	ret = vm_config_add_watchdog(vmcfg, wdt.new_cap, bark_virq,
				     data->affinity == VM_CONFIG_AFFINITY_PROXY,
				     false);

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
	return ret;
}
#endif

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
		irq_manager_get_free_virt_virq_ret_t free_irq_ret;
		free_irq_ret = irq_manager_get_free_virt_virq(db_vmid, false);
		if (free_irq_ret.err != RM_OK) {
			ret.err = ERROR_DENIED;
			goto out_destroy_db;
		}

		db_virq = free_irq_ret.virq;
	}

	// Reserve VIRQ for recv VM
	rm_error_t rm_err = irq_manager_reserve_virq(db_vmid, db_virq, true);
	if (rm_err != RM_OK) {
		ret.err = ERROR_DENIED;
		goto out_destroy_db;
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
	err = irq_manager_return_virq(db_vmid, db_virq);
	assert(err == OK);
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
		   size_t *frontend_size, vmaddr_t *backend_ipa,
		   size_t *backend_size, cap_id_t *me_cap)
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
	memset(rm_ipa, 0, virtio_size);

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

	err = gunyah_hyp_virtio_mmio_configure(vio_ret.new_cap, me_ret.r,
					       vqs_num);
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
		frontend_cfg->vm, VM_MEMUSE_VIRTIO, INVALID_ADDRESS,
		INVALID_ADDRESS, virtio_size, PAGE_SIZE);
	if (alloc_ret.err != OK) {
		ret = cap_id_result_error(alloc_ret.err);
		goto error_frontend_ipa_allocation;
	}
	vmaddr_t frontend_alloc_ipa = alloc_ret.base;

	// Allocate IPA for backend
	alloc_ret = vm_address_range_alloc(backend_cfg->vm, VM_MEMUSE_VIRTIO,
					   INVALID_ADDRESS, INVALID_ADDRESS,
					   virtio_size, PAGE_SIZE);
	if (alloc_ret.err != OK) {
		ret = cap_id_result_error(alloc_ret.err);
		goto error_backend_ipa_allocation;
	}
	vmaddr_t backend_alloc_ipa = alloc_ret.base;

	// Map it read-only for the frontend
	err = vm_memory_map(frontend_cfg->vm, VM_MEMUSE_VIRTIO, me_ret.r,
			    frontend_alloc_ipa, PGTABLE_ACCESS_R,
			    PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
	if (err != OK) {
		ret = cap_id_result_error(err);
		goto error_frontend_me_map;
	}

	// Map it read-write for the backend, so that it can modify the
	// configuration space
	err = vm_memory_map(backend_cfg->vm, VM_MEMUSE_VIRTIO, me_ret.r,
			    backend_alloc_ipa, PGTABLE_ACCESS_RW,
			    PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
	if (err != OK) {
		ret = cap_id_result_error(err);
		goto error_backend_me_map;
	}

	ret = cap_id_result_ok(vio_ret.new_cap);

	*frontend_ipa  = frontend_alloc_ipa;
	*frontend_size = virtio_size;
	*backend_ipa   = backend_alloc_ipa;
	*backend_size  = virtio_size;
	*me_cap	       = me_ret.r;

	if (ret.e == OK) {
		goto out;
	}

error_backend_me_map:
	err = vm_memory_unmap(frontend_cfg->vm, VM_MEMUSE_VIRTIO, me_ret.r,
			      frontend_alloc_ipa);
	assert(err == OK);
error_frontend_me_map:
	vm_address_range_free(backend_cfg->vm, VM_MEMUSE_VIRTIO,
			      backend_alloc_ipa, virtio_size);
error_backend_ipa_allocation:
	vm_address_range_free(frontend_cfg->vm, VM_MEMUSE_VIRTIO,
			      frontend_alloc_ipa, virtio_size);
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

	vmaddr_t frontend_ipa  = 0x0;
	size_t	 frontend_size = 0U;
	vmaddr_t backend_ipa   = 0x0;
	size_t	 backend_size  = 0U;
	cap_id_t me_cap	       = CSPACE_CAP_INVALID;

	cap_id_result_t vio = create_virtio_mmio(frontend_cfg, backend_cfg,
						 d->vqs_num, &frontend_ipa,
						 &frontend_size, &backend_ipa,
						 &backend_size, &me_cap);
	if (vio.e != OK) {
		ret = vio.e;
		goto out;
	}

	vmid_t frontend = frontend_cfg->vm->vmid;

	error_t err;

	// Reserve VIRQs for front- and backend

	irq_manager_get_free_virt_virq_ret_t free_irq_ret;
	free_irq_ret = irq_manager_get_free_virt_virq(frontend, false);
	if (free_irq_ret.err != RM_OK) {
		ret = ERROR_DENIED;
		goto error_get_frontend_virq;
	}
	interrupt_data_t frontend_virq = free_irq_ret.virq;

	rm_error_t rm_err =
		irq_manager_reserve_virq(frontend, frontend_virq, true);
	if (rm_err != OK) {
		ret = ERROR_DENIED;
		goto error_get_frontend_virq;
	}

	// or else it will get the same virq number
	assert(backend != frontend);

	free_irq_ret = irq_manager_get_free_virt_virq(backend, false);
	if (free_irq_ret.err != RM_OK) {
		ret = ERROR_DENIED;
		goto error_get_backend_virq;
	}
	interrupt_data_t backend_virq = free_irq_ret.virq;

	rm_err = irq_manager_reserve_virq(backend, backend_virq, true);
	if (rm_err != OK) {
		ret = ERROR_DENIED;
		goto error_get_backend_virq;
	}

	ret = vm_config_add_virtio_mmio(frontend_cfg, backend_cfg, vio.r,
					frontend_virq, backend_virq, d, true,
					frontend_ipa, frontend_size,
					backend_ipa, backend_size, me_cap);
	if (ret == OK) {
		goto out;
	}

	err = irq_manager_return_virq(backend, backend_virq);
	assert(err == OK);
error_get_backend_virq:
	err = irq_manager_return_virq(frontend, frontend_virq);
	assert(err == OK);
error_get_frontend_virq:
	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), vio.r);
	assert(err == OK);
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

		pgtable_access_t access =
			iomem_range_access_to_pgtable_access[d->access];
		if (access >=
		    util_array_size(iomem_range_access_to_pgtable_access)) {
			ret = ERROR_DENIED;
			goto iomem_err;
		}

		vm_address_range_result_t as_ret = vm_address_range_alloc(
			vmcfg->vm, VM_MEMUSE_DEVICE, ipa, phys, size,
			ADDRESS_RANGE_NO_ALIGNMENT);
		if (as_ret.err != OK) {
			ret = as_ret.err;
			goto iomem_err;
		}

		cap_id_t device_me = rm_get_device_me_cap();
		size_t	 offset	   = phys - rm_get_device_me_base();

		cap_id_result_t me_ret = vm_memory_create_and_map(
			vmcfg->vm, VM_MEMUSE_DEVICE, device_me, offset, size,
			ipa, MEMEXTENT_MEMTYPE_DEVICE, access,
			PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
		if (me_ret.e != OK) {
			ret = me_ret.e;
			goto iomem_err;
		} else {
			ret = vector_push_back(vmcfg->iomem_ranges, me_ret.r);
			if (ret != OK) {
				goto out;
			}
		}
	}
iomem_err:
	if (ret != OK) {
		while (idx > 0) {
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

error_t
vm_config_update_parsed(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret;

	// Update and validate the normal memory range
	vmcfg->mem_ipa_base = data->mem_base_ipa;
	vmcfg->mem_size_min = data->mem_size_min;
	vmcfg->mem_size_max = data->mem_size_max;

	if ((vmcfg->mem_ipa_base >= vmcfg->vm->as_size) ||
	    (vmcfg->mem_size_min > vmcfg->mem_size_max)) {
		(void)printf("Error: address space limits out of range");
		ret = ERROR_ADDR_INVALID;
		goto out;
	}

	// Truncate the private memory range to the size of the address space
	if (util_add_overflows(vmcfg->mem_size_max, vmcfg->mem_ipa_base) ||
	    ((vmcfg->mem_size_max + vmcfg->mem_ipa_base) >
	     vmcfg->vm->as_size)) {
		vmcfg->mem_size_max = vmcfg->vm->as_size - vmcfg->mem_ipa_base;
	}

	if (data->mem_base_constraints_set) {
		// Check that the base memory meets the required constraints
		uint32_t generic_constraints  = data->mem_base_constraints[0];
		uint32_t platform_constraints = data->mem_base_constraints[1];

		address_range_tag_t tag = vm_memory_constraints_to_tag(
			vmcfg->vm, generic_constraints, platform_constraints);
		if (tag == ADDRESS_RANGE_NO_TAG) {
			(void)printf(
				"Error: invalid base-mem-constraints %x %x\n",
				generic_constraints, platform_constraints);
			ret = ERROR_ARGUMENT_INVALID;
			goto out;
		}

		if ((tag & vmcfg->vm->mem_base_tag) != tag) {
			(void)printf(
				"Error: insufficient base memory tag %x, %x\n",
				vmcfg->vm->mem_base_tag, tag);
			ret = ERROR_DENIED;
			goto out;
		}
	}

	if (vmcfg->vm->fw_size != 0U) {
		// Firmware memparcel range has been set. Update and validate
		// the firmware IPA range.
		vmcfg->fw_ipa_base = data->fw_base_ipa;
		vmcfg->fw_size_max = data->fw_size_max;

		if (vmcfg->vm->fw_mp_handle == vmcfg->vm->mem_mp_handle) {
			// Firmware is inside the image memparcel.

			if (vmcfg->fw_ipa_base == INVALID_ADDRESS) {
				// DT did not configure the FW base address
				vmcfg->fw_ipa_base = vmcfg->mem_ipa_base;

				if (util_add_overflows(vmcfg->fw_size_max,
						       vmcfg->fw_ipa_base) ||
				    ((vmcfg->fw_size_max + vmcfg->fw_ipa_base) >
				     vmcfg->vm->as_size)) {
					vmcfg->fw_size_max =
						vmcfg->vm->as_size -
						vmcfg->fw_ipa_base;
				}
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

			if (vmcfg->fw_ipa_base == INVALID_ADDRESS) {
				// DT did not configure the FW base address;
				// this is mandatory for a separate memparcel
				(void)printf(
					"Error: firmware-address unspecified for memparcel %d\n",
					vmcfg->vm->fw_mp_handle);
				ret = ERROR_ADDR_INVALID;
				goto out;
			}

			if (util_add_overflows(vmcfg->fw_size_max,
					       vmcfg->fw_ipa_base) ||
			    ((vmcfg->fw_size_max + vmcfg->fw_ipa_base) >
			     vmcfg->vm->as_size)) {
				vmcfg->fw_size_max =
					vmcfg->vm->as_size - vmcfg->fw_ipa_base;
			}

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

		if ((vmcfg->fw_ipa_base >= vmcfg->vm->as_size) ||
		    ((vmcfg->fw_ipa_base + vmcfg->fw_size_max) >
		     vmcfg->vm->as_size)) {
			(void)printf(
				"Error: firmware region limits out of range");
			ret = ERROR_ADDR_INVALID;
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

out:
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
			.tx_virq  = irq_manager_virq_for_hypercall(
				 msgq_pair->tx_peer_virq),
			.rx_virq = irq_manager_virq_for_hypercall(
				msgq_pair->rx_peer_virq),
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
vm_config_set_irq_manager(vm_config_t *vmcfg, vm_irq_manager_t *irq_manager)
{
	assert(vmcfg != NULL);
	assert(irq_manager != NULL);
	assert(vmcfg->irq_manager == NULL);

	vmcfg->irq_manager = irq_manager;
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
		const interrupt_data_t watchdog_bark_virq = {
#if defined(CONFIG_WATCHDOG_VIRQ)
			.irq = CONFIG_WATCHDOG_VIRQ,
#else
			.irq = VIRQ_NUM_INVALID,
#endif
			.is_cpu_local	    = false,
			.is_edge_triggering = false,
		};
		ret = vm_config_add_watchdog(
			vmcfg, CSPACE_CAP_INVALID, watchdog_bark_virq, false,
			platform_has_watchdog_hlos_virtual_regs());
		if (ret != OK) {
			(void)printf(
				"Error: failed to add hlos watchdog, err(%x)\n",
				ret);
			goto out;
		}
	}
#endif

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

out_destroy_vic:
	if (err != OK) {
		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							v.new_cap);
		assert(err == OK);
	}
out:
	return err;
}

static error_t
handle_irqs(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t	     ret      = OK;
	const virq_t max_virq = irq_manager_get_max_virq();

	if (util_add_overflows(max_virq, 1U)) {
		ret = ERROR_NOMEM;
		goto err_alloc;
	}

	cap_id_t *irqs = malloc(((size_t)max_virq + 1U) * sizeof(*irqs));
	if (irqs == NULL) {
		ret = ERROR_NOMEM;
		goto err_alloc;
	}

	for (index_t i = 0; i <= max_virq; ++i) {
		irqs[i] = CSPACE_CAP_INVALID;
	}

	vmid_t self = vmcfg->vm->vmid;

	size_t cnt = vector_size(data->irq_ranges);
	if (!vmcfg->trusted_config && (cnt > 0U)) {
		// The code below will map IRQs that are either restricted or
		// owned by the owner VM. It is not safe to allow it for ranges
		// coming from untrusted configs.
		ret = ERROR_DENIED;
		goto err_denied;
	}

	// check all requested irqs, if it's a restricted hw_irq directly map
	// it.
	for (index_t i = 0; i < cnt; i++) {
		irq_range_data_t *d =
			vector_at_ptr(irq_range_data_t, data->irq_ranges, i);

		virq_t hw_irq = d->hw_irq;
		virq_t virq   = d->virq;

		cap_id_t irq_cap = rm_get_restricted_hwirq(hw_irq, self);

		if (irq_cap != CSPACE_CAP_INVALID) {
			irqs[virq] = irq_cap;
		}
	}

	// create irq manager
	vm_irq_manager_t *irq_manager =
		irq_manager_create(vmcfg->vic, max_virq + 1U, irqs);
	assert(irq_manager != NULL);
	vm_config_set_irq_manager(vmcfg, irq_manager);

	// check if the owner VM has the required irq, if so, do static share
	for (index_t i = 0; i < cnt; i++) {
		irq_range_data_t *d =
			vector_at_ptr(irq_range_data_t, data->irq_ranges, i);

		virq_t hw_irq = d->hw_irq;
		virq_t virq   = d->virq;

		(void)irq_manager_static_share(vmcfg->vm->owner, hw_irq, self,
					       virq);
	}

err_denied:
	free(irqs);
err_alloc:
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
	assert(vm != NULL);

	vm_config_t *vmcfg = vm->vm_config;
	assert(vmcfg != NULL);

	error_t err;
	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
						vmcfg->addrspace);
	assert(err == OK);

	vm_address_range_destroy(vm);
	vm->as_allocator = NULL;
	vm_memory_teardown(vm);

	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), vmcfg->vic);
	assert(err == OK);

	// Opposite of handle_iomem_ranges
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
}

void
vm_config_delete_vdevice_node(vm_config_t *vmcfg, vdevice_node_t **node)
{
	assert(vmcfg != NULL);
	assert((node != NULL) && (*node != NULL));

	list_remove(vdevice_node_t, &vmcfg->vdevice_nodes, *node, vdevice_);

	free((*node)->config);

	if ((*node)->generate_alloc) {
		free((*node)->generate);
	}

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

	err = irq_manager_return_virq(vmcfg->vm->vmid, cfg->tx_vm_virq);
	assert(err == OK);
	err = irq_manager_return_virq(vmcfg->vm->vmid, cfg->rx_vm_virq);
	assert(err == OK);

	bool  has_matching_vdevice = false;
	vm_t *peer_vm		   = vm_lookup(cfg->peer);

	if (!cfg->has_peer_vdevice) {
		// peer-default has no matching msgqueue_pair vdevice, therefore
		// we need to return the virqs here. For non-default peer with
		// matching vdevice, this will happen when its VM is reset.

		err = irq_manager_return_virq(cfg->peer, cfg->rx_peer_virq);
		assert(err == OK);
		err = irq_manager_return_virq(cfg->peer, cfg->tx_peer_virq);
		assert(err == OK);
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

	vm_config_delete_vdevice_node(vmcfg, node);

	// Only destroy if there is no matching vdevice
	if (!has_matching_vdevice) {
		// FIXME: Revoke all children caps by revoke_caps_from
		err = gunyah_hyp_cspace_revoke_caps_from(rm_get_rm_cspace(),
							 rx);
		assert(err == OK);
		err = gunyah_hyp_cspace_revoke_caps_from(rm_get_rm_cspace(),
							 tx);
		assert(err == OK);

		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), rx);
		assert(err == OK);
		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), tx);
		assert(err == OK);
	}

	return;
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

	// Revoke all children caps
	error_t err;
	err = gunyah_hyp_cspace_revoke_caps_from(rm_get_rm_cspace(),
						 cfg->rx_master_cap);
	assert(err == OK);
	err = gunyah_hyp_cspace_revoke_caps_from(rm_get_rm_cspace(),
						 cfg->tx_master_cap);
	assert(err == OK);

	err = irq_manager_return_virq(vmcfg->vm->vmid, cfg->rx_vm_virq);
	assert(err == OK);
	err = irq_manager_return_virq(vmcfg->vm->vmid, cfg->tx_vm_virq);
	assert(err == OK);
	err = irq_manager_return_virq(cfg->peer, cfg->rx_peer_virq);
	assert(err == OK);
	err = irq_manager_return_virq(cfg->peer, cfg->tx_peer_virq);
	assert(err == OK);

	vm_config_delete_vdevice_node(vmcfg, node);

	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), rx);
	assert(err == OK);
	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), tx);
	assert(err == OK);

	vm_config_remove_console(vmcfg);

	return;
}

static void
handle_doorbell_destruction(vm_config_t *vmcfg, vdevice_node_t **node)
{
	assert(vmcfg != NULL);
	assert((node != NULL) && (*node != NULL));

	struct vdevice_doorbell *cfg =
		(struct vdevice_doorbell *)(*node)->config;

	cap_id_t db_cap = cfg->master_cap;

	vm_t *peer_vm = vm_lookup(cfg->peer);
	assert((peer_vm != NULL) && (peer_vm->vm_config != NULL));

	// Revoke all children caps
	error_t err;
	err = gunyah_hyp_cspace_revoke_caps_from(rm_get_rm_cspace(),
						 cfg->master_cap);
	assert(err == OK);

	if (cfg->source) {
		err = irq_manager_return_virq(cfg->peer, cfg->peer_virq);
		assert(err == OK);
	} else {
		err = irq_manager_return_virq(vmcfg->vm->vmid, cfg->vm_virq);
		assert(err == OK);
	}

	vm_config_delete_vdevice_node(vmcfg, node);

	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), db_cap);
	assert(err == OK);
}

static void
handle_msgqueue_destruction(vm_config_t *vmcfg, vdevice_node_t **node)
{
	assert(vmcfg != NULL);
	assert((node != NULL) && (*node != NULL));

	struct vdevice_msg_queue *cfg =
		(struct vdevice_msg_queue *)(*node)->config;

	cap_id_t mq_cap = cfg->master_cap;

	vm_t *peer_vm = vm_lookup(cfg->peer);
	assert((peer_vm != NULL) && (peer_vm->vm_config != NULL));

	// Revoke all children caps
	error_t err;
	err = gunyah_hyp_cspace_revoke_caps_from(rm_get_rm_cspace(),
						 cfg->master_cap);
	assert(err == OK);

	err = irq_manager_return_virq(vmcfg->vm->vmid, cfg->vm_virq);
	assert(err == OK);
	err = irq_manager_return_virq(cfg->peer, cfg->peer_virq);
	assert(err == OK);

	vm_config_delete_vdevice_node(vmcfg, node);

	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), mq_cap);
	assert(err == OK);
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

	watchdog_bind_option_flags_t bind_bite_options =
		watchdog_bind_option_flags_default();
	watchdog_bind_option_flags_set_bite_virq(&bind_bite_options, true);
	err = gunyah_hyp_watchdog_unbind_virq(vmcfg->watchdog,
					      bind_bite_options);
	assert(err == OK);
	(void)printf("unbind bite for watchdog\n");

	watchdog_bind_option_flags_t bind_bark_options =
		watchdog_bind_option_flags_default();
	err = gunyah_hyp_watchdog_unbind_virq(vmcfg->watchdog,
					      bind_bark_options);
	assert(err == OK);

	struct vdevice_watchdog *cfg =
		(struct vdevice_watchdog *)(*node)->config;

	vm_mgnt_deregister_event(&vmcfg->vm->wdog_bite_event,
				 cfg->bite_virq.irq);

	err = irq_manager_return_virq(VMID_RM, cfg->bite_virq);
	assert(err == OK);

	vm_config_delete_vdevice_node(vmcfg, node);

	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
						vmcfg->watchdog);
	assert(err == OK);

	vmcfg->watchdog = CSPACE_CAP_INVALID;
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

	err = irq_manager_return_virq(cfg->peer, cfg->peer_virq);
	assert(err == OK);

	vm_config_delete_vdevice_node(vmcfg, node);

	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
						vmcfg->vpm_group);
	assert(err == OK);

	vmcfg->vpm_group = CSPACE_CAP_INVALID;
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

	// Revoke all children caps
	error_t err;
	err = gunyah_hyp_cspace_revoke_caps_from(rm_get_rm_cspace(),
						 cfg->master_cap);
	assert(err == OK);

	err = irq_manager_return_virq(cfg->backend, cfg->backend_virq);
	assert(err == OK);
	err = irq_manager_return_virq(vmcfg->vm->vmid, cfg->frontend_virq);
	assert(err == OK);

	err = memextent_unmap(cfg->memextent_cap, vmcfg->addrspace,
			      cfg->frontend_ipa);
	assert(err == OK);

	err = memextent_unmap(cfg->memextent_cap,
			      backend_vm->vm_config->addrspace,
			      cfg->backend_ipa);
	assert(err == OK);

	err = address_range_allocator_free(backend_vm->as_allocator,
					   cfg->backend_ipa, cfg->backend_size);
	assert(err == OK);
	err = address_range_allocator_free(
		vmcfg->vm->as_allocator, cfg->frontend_ipa, cfg->frontend_size);
	assert(err == OK);

	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
						cfg->memextent_cap);
	assert(err == OK);

	vm_config_delete_vdevice_node(vmcfg, node);

	err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), virtio_cap);
	assert(err == OK);
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

	error_t err = platform_handle_destroy_vdevices(vm);
	assert(err == OK);

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
