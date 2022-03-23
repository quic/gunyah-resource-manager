// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm-rpc.h>

#include <resource-manager.h>

#include <guest_interface.h>
#include <guest_rights.h>
#include <irq_manager.h>
#include <memextent.h>
#include <memparcel_msg.h>
#include <platform.h>
#include <platform_vm_config.h>
#include <rm-rpc-fifo.h>
#include <util.h>
#include <utils/address_range_allocator.h>
#include <utils/list.h>
#include <utils/vector.h>
#include <vm_config.h>
#include <vm_config_struct.h>
#include <vm_console.h>
#include <vm_creation.h>
#include <vm_mgnt.h>
#include <vm_resource_msg.h>
#include <vm_vcpu.h>

// Must be last
#include <platform_vm_config_parser.h>
#include <vm_config_parser.h>

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
static error_t
handle_iomems(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_iomem_ranges(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_irqs(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_segments(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_ids(vm_config_t *vmcfg, vm_config_parser_data_t *data);

static error_t
handle_compatibles(vdevice_node_t *vdevice, const general_data_t *data);
static void
free_compatibles(vdevice_node_t *vdevice);

static error_t
vm_config_add_shm(vm_config_t *vmcfg, shm_data_t *data, vdevice_node_t *db,
		  vdevice_node_t *db_src);

static vdevice_node_t *
vm_config_add_doorbell(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
		       bool source, virq_t virq, uint32_t label,
		       const char *generate, bool export_to_dt);
static void
vm_config_add_msgqueue(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
		       bool tx, virq_t vm_virq, virq_t peer_virq,
		       const msg_queue_data_t *data, bool export_to_dt);
static error_t
vm_config_add_msgqueue_pair(vm_config_t *vmcfg, msg_queue_pair_data_t *data,
			    cap_id_t rm_tx_cap, cap_id_t rm_rx_cap,
			    struct vdevice_msg_queue_pair *peer_cfg,
			    vm_t *peer_vm, resource_handle_t handle);

static error_t
vm_config_add_rm_rpc(vm_config_t *vmcfg, rm_rpc_data_t *data, cap_id_t rx,
		     cap_id_t tx);

static void
vm_config_delete_vdevice_node(vm_config_t *vmcfg, vdevice_node_t **node);
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
	     label_t label, const char *generate, virq_t virq,
	     bool need_alloc_virq, bool export_to_dt);

static error_t
add_msgqueue(vm_config_t *vmcfg, msg_queue_data_t *data, bool is_sender,
	     virq_t self_virq, bool alloc_self_virq, virq_t peer_virq,
	     bool alloc_peer_virq);

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
			item.resource_virq_number = db->vm_virq;
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
			item.resource_virq_number = db->peer_virq;
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
			item.resource_virq_number = mq->vm_virq;
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
			item.resource_virq_number = mq->peer_virq;
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
			item.resource_virq_number = mq->tx_vm_virq;
			vector_push_back(descs, item);

			// Rx msgqueue from self vdevice list
			item.resource_type  = RSC_MSG_QUEUE_RECV;
			item.resource_label = mq->label;
			item.resource_capid_low =
				(uint32_t)(mq->rx_vm_cap & 0xffffffffU);
			item.resource_capid_high =
				(uint32_t)(mq->rx_vm_cap >> 32);
			item.resource_virq_number = mq->rx_vm_virq;
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
			item.resource_virq_number = mq->tx_peer_virq;
			vector_push_back(descs, item);

			// Rx msgqueue from peer vdevice list
			item.resource_type  = RSC_MSG_QUEUE_RECV;
			item.resource_label = mq->label;
			item.resource_capid_low =
				(uint32_t)(mq->rx_peer_cap & 0xffffffffU);
			item.resource_capid_high =
				(uint32_t)(mq->rx_peer_cap >> 32);
			item.resource_virq_number = mq->rx_peer_virq;
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
			item.resource_virq_number = vpm->peer_virq;
			vector_push_back(descs, item);
		} else {
			// Ignore
		}
	} else {
		// Other vdevice types not supplied in get resources
	}
out:
	return OK;
}

error_t
vm_config_get_resource_descs(vmid_t self, vmid_t vmid, vector_t *descs)
{
	error_t err = OK;
	vm_t   *vm  = vm_lookup(vmid);

	if (vm == NULL) {
		err = ERROR_ARGUMENT_INVALID;
		goto out;
	}
	bool owner = self == vm->owner;

	vm_config_t *vmcfg = vm->vm_config;
	assert(vmcfg != NULL);

	if (owner) {
		// Add vcpu info
		size_t cnt = vector_size(vmcfg->vcpus);
		for (index_t i = 0; i < cnt; i++) {
			vcpu_t *vcpu = vector_at_ptr(vcpu_t, vmcfg->vcpus, i);

			rm_hyp_resource_resp_t item = { 0 };
			item.resource_type	    = RSC_VIRTUAL_CPU;
			item.resource_label	    = vcpu->affinity_index;
			item.resource_capid_low =
				(uint32_t)(vcpu->owner_cap & 0xffffffffU);
			item.resource_capid_high =
				(uint32_t)(vcpu->owner_cap >> 32);

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
		err = get_vdev_desc(self, vmid, node, descs);
		if (err != OK) {
			break;
		}
	}

	// Add vdevice resource info from peer
	loop_list(node, &vmcfg->vdevice_nodes, vdevice_)
	{
		err = get_vdev_desc(self, vmid, node, descs);
		if (err != OK) {
			break;
		}
	}

out:
	return err;
}

error_t
vm_config_add_vcpu(vm_config_t *vmcfg, cap_id_t rm_cap, uint32_t affinity_index,
		   bool boot_vcpu, char *patch)
{
	error_t ret  = OK;
	vcpu_t	vcpu = { 0 };

	vcpu.master_cap	    = rm_cap;
	vcpu.vm_cap	    = CSPACE_CAP_INVALID;
	vcpu.affinity_index = affinity_index;
	vcpu.boot_vcpu	    = boot_vcpu;
	vcpu.patch	    = patch;

	vmid_t owner = vmcfg->vm->owner;
	if (owner == VMID_RM) {
		goto out;
	}

	vm_t *owner_vm = vm_lookup(owner);
	if ((owner_vm == NULL) || (owner_vm->vm_config == NULL)) {
		printf("Failed: invalid owner VM\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto err;
	}

	vm_config_t *owner_cfg = owner_vm->vm_config;

	// Copy SVM vcpu caps to owner VM cspace
	gunyah_hyp_cspace_copy_cap_from_result_t copy_ret;

	cap_rights_t rights = CAP_RIGHTS_THREAD_AFFINITY |
			      CAP_RIGHTS_THREAD_YIELD_TO;

	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(), rm_cap,
						   owner_cfg->cspace, rights);
	if (copy_ret.error != OK) {
		printf("Failed: copy vcpu cap from rm cspace\n");
		ret = copy_ret.error;
		goto err;
	}

	vcpu.owner_cap = copy_ret.new_cap;

	// Non-PSCI VMs need to use the vcpu_poweron/off hypercalls and for that
	// they need the POWER right
	if (vmcfg->vpm_group == CSPACE_CAP_INVALID) {
		copy_ret = gunyah_hyp_cspace_copy_cap_from(
			rm_get_rm_cspace(), rm_cap, vmcfg->cspace,
			CAP_RIGHTS_THREAD_POWER);
		if (copy_ret.error != OK) {
			printf("Failed: copy vcpu cap from rm cspace\n");
			ret = copy_ret.error;
			goto err;
		}

		vcpu.vm_cap = copy_ret.new_cap;
	}

out:
	// Add to vm_config
	vector_push_back(vmcfg->vcpus, vcpu);

err:
	return ret;
}

vdevice_node_t *
vm_config_add_doorbell(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
		       bool source, virq_t virq, uint32_t label,
		       const char *generate, bool export_to_dt)
{
	vm_config_t *send_cfg = NULL, *recv_cfg = NULL;
	cap_id_t send_cap = CSPACE_CAP_INVALID, recv_cap = CSPACE_CAP_INVALID;
	error_t	 err = OK;

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		printf("Failed: to alloc vdevice node\n");
		err = ERROR_NOMEM;
		goto out;
	}

	node->type	   = VDEV_DOORBELL;
	node->export_to_dt = export_to_dt;
	node->visible	   = true;
	node->handle	   = get_vdevice_resource_handle();

	if (generate != NULL) {
		node->generate = strdup(generate);
		if (node->generate == NULL) {
			printf("Failed: to alloc doorbell generate string\n");
			err = ERROR_NOMEM;
			goto out;
		}
	} else {
		node->generate = "/hypervisor/qcom,doorbell";
	}

	struct vdevice_doorbell *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		printf("Failed: to alloc doorbell config\n");
		err = ERROR_NOMEM;
		goto out;
	}

	node->config = cfg;

	vm_t *peer_vm = vm_lookup(peer);
	if ((peer_vm == NULL) || (peer_vm->vm_config == NULL)) {
		printf("Failed: invalid peer\n");
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

	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(), rm_cap,
						   send_cfg->cspace,
						   CAP_RIGHTS_DOORBELL_SEND);
	if (copy_ret.error != OK) {
		printf("Failed: to copy send cap\n");
		err = copy_ret.error;
		goto out;
	}
	send_cap = copy_ret.new_cap;

	// Copy doorbell cap to recv VM cspace with receive rights
	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(), rm_cap,
						   recv_cfg->cspace,
						   CAP_RIGHTS_DOORBELL_RECEIVE);
	if (copy_ret.error != OK) {
		printf("Failed: to copy recv cap\n");
		err = copy_ret.error;
		goto out;
	}
	recv_cap = copy_ret.new_cap;

	// Bind VIRQ to recv VM's VIC
	err = gunyah_hyp_doorbell_bind_virq(rm_cap, recv_cfg->vic, virq);
	if (err != OK) {
		printf("Failed: to bind db virq(%d) err(0x%x)\n", virq, err);
		goto out;
	}

	cfg->peer	= peer;
	cfg->source	= source;
	cfg->master_cap = rm_cap;
	cfg->label	= label;
	if (source) {
		cfg->vm_cap   = send_cap;
		cfg->vm_virq  = 0U;
		cfg->peer_cap = recv_cap;

		cfg->peer_virq = virq;
	} else {
		cfg->vm_cap    = recv_cap;
		cfg->vm_virq   = virq;
		cfg->peer_cap  = send_cap;
		cfg->peer_virq = 0U;
	}

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);
out:
	if ((err != OK) && (node != NULL)) {
		if (recv_cap != CSPACE_CAP_INVALID) {
			assert(recv_cfg != NULL);
			(void)gunyah_hyp_cspace_delete_cap_from(
				recv_cfg->cspace, recv_cap);
		}
		if (send_cap != CSPACE_CAP_INVALID) {
			assert(send_cfg != NULL);
			(void)gunyah_hyp_cspace_delete_cap_from(
				send_cfg->cspace, send_cap);
		}

		free(node->config);
		free(node->generate);
		free(node);

		node = NULL;
	}

	return node;
}

void
vm_config_add_msgqueue(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
		       bool tx, virq_t vm_virq, virq_t peer_virq,
		       const msg_queue_data_t *data, bool export_to_dt)
{
	vm_config_t *tx_cfg = NULL, *rx_cfg = NULL;

	cap_id_t tx_cap = CSPACE_CAP_INVALID, rx_cap = CSPACE_CAP_INVALID;

	error_t err = OK;

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		printf("Failed: to alloc vdevice node\n");
		err = ERROR_NOMEM;
		goto out;
	}

	node->type	   = VDEV_MSG_QUEUE;
	node->export_to_dt = export_to_dt;
	node->visible	   = true;
	node->handle	   = get_vdevice_resource_handle();

	const char *generate = data->general.generate;
	if (generate != NULL) {
		node->generate = strdup(generate);
		if (node->generate == NULL) {
			printf("Failed: to msgqueue alloc generate string\n");
			err = ERROR_NOMEM;
			goto out;
		}
	} else {
		node->generate = "/hypervisor/qcom,message-queue";
	}

	err = handle_compatibles(node, &data->general);
	if (err != OK) {
		printf("Failed: save compatible in msgqueue node\n");
		goto out;
	}

	struct vdevice_msg_queue *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		printf("Failed: to alloc doorbell config\n");
		err = ERROR_NOMEM;
		goto out;
	}
	node->config = cfg;

	vm_t *peer_vm = vm_lookup(peer);
	if ((peer_vm == NULL) || (peer_vm->vm_config == NULL)) {
		printf("Failed: invalid peer\n");
		err = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	virq_t tx_virq, rx_virq;
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
		printf("Failed: to copy tx cap\n");
		err = copy_ret.error;
		goto out;
	}
	tx_cap = copy_ret.new_cap;

	// Copy msgqueue cap to rx VM cspace with recv rights
	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(), rm_cap,
						   rx_cfg->cspace,
						   CAP_RIGHTS_MSGQUEUE_RECEIVE);
	if (copy_ret.error != OK) {
		printf("Failed: to copy rx cap\n");
		err = copy_ret.error;
		goto out;
	}
	rx_cap = copy_ret.new_cap;

	// Bind VIRQs
	err = gunyah_hyp_msgqueue_bind_send_virq(rm_cap, tx_cfg->vic, tx_virq);
	if (err != OK) {
		printf("Failed: to bind tx virq\n");
		goto out;
	}
	err = gunyah_hyp_msgqueue_bind_receive_virq(rm_cap, rx_cfg->vic,
						    rx_virq);
	if (err != OK) {
		printf("Failed: to bind rx virq\n");
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
	if ((err != OK) && (node != NULL)) {
		if (tx_cap != CSPACE_CAP_INVALID) {
			assert(tx_cfg != NULL);
			(void)gunyah_hyp_cspace_delete_cap_from(tx_cfg->cspace,
								tx_cap);
		}

		if (rx_cap != CSPACE_CAP_INVALID) {
			assert(rx_cfg != NULL);
			(void)gunyah_hyp_cspace_delete_cap_from(rx_cfg->cspace,
								rx_cap);
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
			virq_t defined_tx_virq, virq_t defined_rx_virq)
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

	virq_t vm_tx_virq = defined_tx_virq;
	if (alloc_irq) {
		free_irq_ret = irq_manager_get_free_virt_virq(vmid);
		if (free_irq_ret.err != RM_OK) {
			printf("Failed: to get free virq\n");
			ret = ERROR_DENIED;
			goto out;
		}
		vm_tx_virq = free_irq_ret.virq;
	}

	rm_err = irq_manager_reserve_virq(vmid, vm_tx_virq, true);
	if (rm_err != RM_OK) {
		printf("Failed: to reserve virq\n");
		ret = ERROR_DENIED;
		goto out;
	}

	error_t err;

	virq_t vm_rx_virq = defined_rx_virq;
	if (alloc_irq) {
		free_irq_ret = irq_manager_get_free_virt_virq(vmid);
		if (free_irq_ret.err != RM_OK) {
			printf("Failed: to get free virq\n");
			ret = ERROR_DENIED;
			goto out_return_tx_virq;
		}
		vm_rx_virq = free_irq_ret.virq;
	}

	rm_err = irq_manager_reserve_virq(vmid, vm_rx_virq, true);
	if (rm_err != RM_OK) {
		printf("Failed: to reserve virq\n");
		ret = ERROR_DENIED;
		goto out_return_tx_virq;
	}

	// Copy msgqueue caps to VM cspace
	gunyah_hyp_cspace_copy_cap_from_result_t tx_cap_ret;
	tx_cap_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(),
						     rm_tx_cap, vmcfg->cspace,
						     CAP_RIGHTS_MSGQUEUE_SEND);
	if (tx_cap_ret.error != OK) {
		printf("Failed: to copy cap\n");
		ret = tx_cap_ret.error;
		goto out_return_rx_virq;
	}
	cap_id_t vm_tx_cap = tx_cap_ret.new_cap;

	gunyah_hyp_cspace_copy_cap_from_result_t rx_cap_ret;
	rx_cap_ret = gunyah_hyp_cspace_copy_cap_from(
		rm_get_rm_cspace(), rm_rx_cap, vmcfg->cspace,
		CAP_RIGHTS_MSGQUEUE_RECEIVE);
	if (rx_cap_ret.error != OK) {
		printf("Failed: to copy cap\n");
		ret = rx_cap_ret.error;
		goto out_delete_tx_cap;
	}
	cap_id_t vm_rx_cap = rx_cap_ret.new_cap;

	// Bind virqs to VM's vic
	ret = gunyah_hyp_msgqueue_bind_send_virq(rm_tx_cap, vmcfg->vic,
						 vm_tx_virq);
	if (ret != OK) {
		printf("Failed: to bind virq\n");
		goto out_delete_rx_cap;
	}

	ret = gunyah_hyp_msgqueue_bind_receive_virq(rm_rx_cap, vmcfg->vic,
						    vm_rx_virq);
	if (ret != OK) {
		printf("Failed: to bind virq\n");
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

error_t
vm_config_check_peer(char *peer_id, vm_t *peer_vm)
{
	error_t ret = OK;

	if (peer_id == NULL) {
		printf("error: invalid peer argument\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}
	// when we have peer, we can double check if peer is expected
	vm_t *expected_vm = vm_lookup_by_id(peer_id);
	if ((expected_vm == NULL) || (expected_vm != peer_vm)) {
		printf("error: invalid peer\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

out:
	return ret;
}

error_t
vm_config_add_msgqueue_pair(vm_config_t *vmcfg, msg_queue_pair_data_t *data,
			    cap_id_t rm_tx_cap, cap_id_t rm_rx_cap,
			    struct vdevice_msg_queue_pair *peer_cfg,
			    vm_t *peer_vm, resource_handle_t handle)
{
	error_t ret;

	assert((peer_vm != NULL) || (peer_cfg == NULL));

	virq_t	 vm_tx_virq = VIRQ_INVALID, vm_rx_virq = VIRQ_INVALID;
	cap_id_t tx_vm_cap = CSPACE_CAP_INVALID, rx_vm_cap = CSPACE_CAP_INVALID;
	vmid_t	 self = vmcfg->vm->vmid;

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		printf("Failed: to alloc vdevice node\n");
		ret = ERROR_NOMEM;
		goto out;
	}

	node->type	   = VDEV_MSG_QUEUE_PAIR;
	node->export_to_dt = true;
	node->visible	   = true;
	node->handle	   = handle;

	ret = handle_compatibles(node, &data->general);
	if (ret != OK) {
		printf("Failed: to alloc push compatibles\n");
		goto out_free_node;
	}

	if (data->general.generate != NULL) {
		node->generate = strdup(data->general.generate);
		if (node->generate == NULL) {
			printf("Failed: to msgqueue_pair alloc generate string\n");
			ret = ERROR_NOMEM;
			goto out_free_compatible;
		}
	} else {
		node->generate = NULL;
	}

	struct vdevice_msg_queue_pair *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		printf("Failed: to alloc msgqueue_pair config\n");
		ret = ERROR_NOMEM;
		goto out_free_generate;
	}
	node->config = cfg;

	if (data->defined_irq) {
		vm_tx_virq = data->irqs[TX_IRQ_IDX].virq;
		vm_rx_virq = data->irqs[RX_IRQ_IDX].virq;
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
			printf("Failed: to alloc peer_cfg\n");
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
			printf("msg_queue_pair: msg_size/queue_depth is not "
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
	if (node != NULL) {
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

error_t
vm_config_add_rm_rpc(vm_config_t *vmcfg, rm_rpc_data_t *data, cap_id_t rx,
		     cap_id_t tx)
{
	vdevice_node_t *rpc_node;

	vmid_t peer = VMID_RM;

	virq_t	rm_tx_virq = VIRQ_INVALID, rm_rx_virq = VIRQ_INVALID;
	virq_t	vm_tx_virq = VIRQ_INVALID, vm_rx_virq = VIRQ_INVALID;
	error_t err = OK;

	assert(vmcfg != NULL);
	assert(vmcfg->vm != NULL);

	vmid_t			       self = vmcfg->vm->vmid;
	struct vdevice_msg_queue_pair *cfg  = NULL;

	rpc_node = calloc(1, sizeof(*rpc_node));
	if (rpc_node == NULL) {
		err = ERROR_NOMEM;
		goto out;
	}

	rpc_node->type	       = VDEV_RM_RPC;
	rpc_node->export_to_dt = true;
	rpc_node->visible      = false;

	// no need to have handle since it's never returned by GET_HYP_RESOURCE
	rpc_node->handle = 0;

	err = handle_compatibles(rpc_node, &data->general);
	if (err != OK) {
		printf("Failed: to alloc push compatibles\n");
		goto out;
	}

	rpc_node->generate = strdup(data->general.generate);
	if (rpc_node->generate == NULL) {
		err = ERROR_NOMEM;
		goto out;
	}

	rpc_node->config = calloc(1, sizeof(struct vdevice_msg_queue_pair));
	if (rpc_node->config == NULL) {
		err = ERROR_NOMEM;
		goto out;
	}

	cfg = (struct vdevice_msg_queue_pair *)rpc_node->config;

	rm_error_t rm_err = RM_OK;

	irq_manager_get_free_virt_virq_ret_t free_irq_ret;

	free_irq_ret = irq_manager_get_free_virt_virq(peer);
	if (free_irq_ret.err != RM_OK) {
		err = ERROR_DENIED;
		goto out;
	}
	rm_tx_virq = free_irq_ret.virq;

	rm_err = irq_manager_reserve_virq(peer, rm_tx_virq, true);
	if (rm_err != RM_OK) {
		err = ERROR_DENIED;
		goto out;
	}

	free_irq_ret = irq_manager_get_free_virt_virq(peer);
	if (free_irq_ret.err != RM_OK) {
		err = ERROR_DENIED;
		goto out;
	}
	rm_rx_virq = free_irq_ret.virq;

	rm_err = irq_manager_reserve_virq(peer, rm_rx_virq, true);
	if (rm_err != RM_OK) {
		err = ERROR_DENIED;
		goto out;
	}

	if (data->defined_irq) {
		vm_tx_virq = data->irqs[TX_IRQ_IDX].virq;
	} else {
		free_irq_ret = irq_manager_get_free_virt_virq(self);
		if (free_irq_ret.err != RM_OK) {
			err = ERROR_DENIED;
			goto out;
		}

		vm_tx_virq = free_irq_ret.virq;
	}

	rm_err = irq_manager_reserve_virq(self, vm_tx_virq, true);
	if (rm_err != RM_OK) {
		err = ERROR_DENIED;
		goto out;
	}

	if (data->defined_irq) {
		vm_rx_virq = data->irqs[RX_IRQ_IDX].virq;
	} else {
		free_irq_ret = irq_manager_get_free_virt_virq(self);
		if (free_irq_ret.err != RM_OK) {
			err = ERROR_DENIED;
			goto out;
		}
		vm_rx_virq = free_irq_ret.virq;
	}

	rm_err = irq_manager_reserve_virq(self, vm_rx_virq, true);
	if (rm_err != RM_OK) {
		err = ERROR_DENIED;
		goto out;
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
		err = copy_ret.error;
		goto out;
	}
	cfg->tx_vm_cap = copy_ret.new_cap;

	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(),
						   cfg->rx_master_cap,
						   vmcfg->cspace,
						   CAP_RIGHTS_MSGQUEUE_RECEIVE);
	if (copy_ret.error != OK) {
		err = copy_ret.error;
		goto out;
	}

	cfg->rx_vm_cap = copy_ret.new_cap;

	// Bind virqs to RM's vic
	err = gunyah_hyp_msgqueue_bind_receive_virq(
		cfg->tx_master_cap, rm_get_rm_vic(), rm_rx_virq);
	if (err != OK) {
		goto out;
	}
	cfg->rx_peer_virq = rm_rx_virq;

	err = gunyah_hyp_msgqueue_bind_send_virq(cfg->rx_master_cap,
						 rm_get_rm_vic(), rm_tx_virq);
	if (err != OK) {
		(void)gunyah_hyp_msgqueue_unbind_receive_virq(
			cfg->tx_master_cap);
		goto out;
	}
	cfg->tx_peer_virq = rm_tx_virq;

	// Bind virqs to VM's vic
	err = gunyah_hyp_msgqueue_bind_send_virq(cfg->tx_master_cap, vmcfg->vic,
						 vm_tx_virq);
	if (err != OK) {
		(void)gunyah_hyp_msgqueue_unbind_send_virq(cfg->rx_master_cap);
		(void)gunyah_hyp_msgqueue_unbind_receive_virq(
			cfg->tx_master_cap);
		goto out;
	}
	cfg->tx_vm_virq = vm_tx_virq;

	err = gunyah_hyp_msgqueue_bind_receive_virq(cfg->rx_master_cap,
						    vmcfg->vic, vm_rx_virq);
	if (err != OK) {
		(void)gunyah_hyp_msgqueue_unbind_send_virq(cfg->tx_master_cap);
		(void)gunyah_hyp_msgqueue_unbind_send_virq(cfg->rx_master_cap);
		(void)gunyah_hyp_msgqueue_unbind_receive_virq(
			cfg->tx_master_cap);
		goto out;
	}
	cfg->rx_vm_virq = vm_rx_virq;

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, rpc_node, vdevice_);

out:
	if ((err != OK) && (rpc_node != NULL)) {
		if ((cfg != NULL) && (cfg->rx_vm_cap != CSPACE_CAP_INVALID)) {
			(void)gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace,
								cfg->rx_vm_cap);
		}

		if ((cfg != NULL) && (cfg->tx_vm_cap != CSPACE_CAP_INVALID)) {
			(void)gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace,
								cfg->tx_vm_cap);
		}

		if ((vm_rx_virq != VIRQ_INVALID) && (!data->defined_irq)) {
			irq_manager_return_virq(self, vm_rx_virq);
		}

		if ((vm_tx_virq != VIRQ_INVALID) && (!data->defined_irq)) {
			irq_manager_return_virq(self, vm_tx_virq);
		}

		if (rm_rx_virq != VIRQ_INVALID) {
			irq_manager_return_virq(peer, rm_rx_virq);
		}

		if (rm_tx_virq != VIRQ_INVALID) {
			irq_manager_return_virq(peer, rm_tx_virq);
		}

		free_compatibles(rpc_node);
		free(rpc_node->generate);
		free(rpc_node->config);
		free(rpc_node);
	}
	return err;
}

error_t
vm_config_add_shm(vm_config_t *vmcfg, shm_data_t *data, vdevice_node_t *db,
		  vdevice_node_t *db_src)
{
	error_t ret  = OK;
	vmid_t	peer = get_peer(vmcfg, data->peer);

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		printf("Failed: to alloc vdevice node\n");
		ret = ERROR_NOMEM;
		goto out;
	}

	node->type	   = VDEV_SHM;
	node->export_to_dt = true;
	node->visible	   = false;

	if (data->general.generate != NULL) {
		node->generate = strdup(data->general.generate);
		if (node->generate == NULL) {
			printf("Failed: to shm alloc generate string\n");
			ret = ERROR_NOMEM;
			goto out;
		}
	} else {
		node->generate = "/hypervisor/qcom,shm";
	}

	ret = handle_compatibles(node, &data->general);
	if (ret != OK) {
		printf("Failed: save compatible in shm node\n");
		goto out;
	}

	struct vdevice_shm *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		printf("Failed: to alloc doorbell config\n");
		ret = ERROR_NOMEM;
		goto out;
	}
	node->config = cfg;

	vm_t *peer_vm = vm_lookup(peer);
	if (peer_vm == NULL) {
		printf("Failed: invalid peer\n");
		ret = ERROR_DENIED;
		goto out;
	}

	cfg->peer  = peer;
	cfg->label = data->general.label;

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

cap_id_result_t
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
		(void)gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							create_ret.new_cap);
		goto out;
	}

	ret = cap_id_result_ok(create_ret.new_cap);
out:
	return ret;
}

cap_id_result_t
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
		(void)gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							create_ret.new_cap);
		goto out;
	}

	err = gunyah_hyp_object_activate(create_ret.new_cap);
	if (err != OK) {
		ret = cap_id_result_error(err);
		(void)gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							create_ret.new_cap);
		goto out;
	}

	ret = cap_id_result_ok(create_ret.new_cap);

out:
	return ret;
}

error_t
add_msgqueue(vm_config_t *vmcfg, msg_queue_data_t *data, bool is_sender,
	     virq_t self_virq, bool alloc_self_virq, virq_t peer_virq,
	     bool alloc_peer_virq)
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

	virq_t svirq = self_virq;
	if (alloc_self_virq) {
		irq_manager_get_free_virt_virq_ret_t free_irq_ret;
		free_irq_ret = irq_manager_get_free_virt_virq(self);
		if (free_irq_ret.err != RM_OK) {
			ret = ERROR_DENIED;
			(void)gunyah_hyp_cspace_delete_cap_from(
				rm_get_rm_cspace(), mq.r);
			goto out;
		}
		svirq = free_irq_ret.virq;
	}

	rm_err = irq_manager_reserve_virq(self, svirq, true);
	if (rm_err != OK) {
		ret = ERROR_DENIED;
		(void)gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							mq.r);
		goto out;
	}

	virq_t pvirq = peer_virq;
	if (alloc_peer_virq) {
		// or else it will get the same virq number
		assert(peer != self);

		irq_manager_get_free_virt_virq_ret_t free_irq_ret;
		free_irq_ret = irq_manager_get_free_virt_virq(peer);
		if (free_irq_ret.err != RM_OK) {
			ret = ERROR_DENIED;
			irq_manager_return_virq(self, svirq);
			(void)gunyah_hyp_cspace_delete_cap_from(
				rm_get_rm_cspace(), mq.r);
			goto out;
		}
		pvirq = free_irq_ret.virq;
	}

	rm_err = irq_manager_reserve_virq(peer, pvirq, true);
	if (rm_err != OK) {
		ret = ERROR_DENIED;
		irq_manager_return_virq(self, svirq);
		(void)gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							mq.r);
		goto out;
	}

	vm_config_add_msgqueue(vmcfg, peer, mq.r, is_sender, svirq, pvirq, data,
			       true);

out:
	return ret;
}

error_t
handle_msgqueue(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;
	size_t	cnt = vector_size(data->msg_queues);

	for (index_t i = 0; i < cnt; ++i) {
		msg_queue_data_t *d =
			vector_at_ptr(msg_queue_data_t, data->msg_queues, i);

		virq_t virq = 0U;

		if (d->defined_irq) {
			virq = d->irqs[0].virq;
		}

		ret = add_msgqueue(vmcfg, d, d->is_sender, virq,
				   !d->defined_irq, 0U, true);
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
		vdevice_node_t		       *node	    = NULL;
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

error_t
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
		vm_t			     *peer_vm	= NULL;

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
				printf("Failed: to find peer VM(%d)\n", peer);
				ret = ERROR_ARGUMENT_INVALID;
				goto out;
			}
		}

		if (peer_vm == vmcfg->vm) {
			assert(vmcfg->vm != NULL);
			printf("msgqueue_pair: cannot setup peer as itself\n");
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

error_t
handle_doorbell(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;

	size_t cnt = vector_size(data->doorbells);
	for (index_t i = 0; i < cnt; ++i) {
		doorbell_data_t *d =
			vector_at_ptr(doorbell_data_t, data->doorbells, i);

		vmid_t peer = get_peer(vmcfg, d->peer);

		add_doorbell_ret_t add_ret =
			add_doorbell(vmcfg, vmcfg->vm->vmid, peer, d->is_source,
				     d->general.label, d->general.generate,
				     d->irq.virq, !d->defined_irq, true);
		if (add_ret.err != OK) {
			ret = add_ret.err;
			goto out;
		}

		ret = handle_compatibles(add_ret.node, &d->general);
		if (ret != OK) {
			printf("Failed: save compatible in doorbell node\n");
			goto out;
		}
	}

out:
	return ret;
}

error_t
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

error_t
handle_vcpu(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t	  ret  = OK;
	cap_id_t *caps = NULL;

	assert(vmcfg->vm != NULL);

	vm_t   *owner_vm  = vm_lookup(vmcfg->vm->owner);
	count_t max_cores = rm_get_platform_max_cores();
	assert(owner_vm != NULL);

	// The supplied priority is offset from the owner's priority.
	priority_t priority = (priority_t)((int32_t)owner_vm->priority +
					   data->sched_priority);
	if ((priority < SCHEDULER_MIN_PRIORITY) ||
	    (priority > SCHEDULER_MAX_PRIORITY)) {
		printf("handle_vcpu: invalid priority\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto err_sched_prop;
	}

	vmcfg->vm->priority = priority;

	// The supplied timeslice needs to be converted from US to NS.
	nanoseconds_t timeslice = data->sched_time_slice * 1000U;
	if ((timeslice < SCHEDULER_MIN_TIMESLICE) ||
	    (timeslice > SCHEDULER_MAX_TIMESLICE)) {
		printf("handle_vcpu: invalid timeslice\n");
		ret = ERROR_ARGUMENT_INVALID;
		goto err_sched_prop;
	}

	size_t vcpu_cnt = vector_size(data->vcpus);

	if ((vcpu_cnt == 0) || (vcpu_cnt > max_cores)) {
		printf("Error: invalid vcpu cnt(%zu) vs max cores(%u)\n",
		       vcpu_cnt, rm_get_platform_max_cores());
		ret = ERROR_DENIED;
		goto err_vcpu_cnt;
	}

	if (data->enable_vpm_psci) {
		// Create the PSCI group
		gunyah_hyp_partition_create_vpm_group_result_t vg;
		vg = gunyah_hyp_partition_create_vpm_group(
			rm_get_rm_partition(), rm_get_rm_cspace());
		if (vg.error != OK) {
			printf("handle_vcpu: failed create vpm group\n");
			ret = vg.error;
			goto err_create_vpm;
		}

		vmcfg->vpm_group = vg.new_cap;

		ret = gunyah_hyp_object_activate(vmcfg->vpm_group);
		if (ret != OK) {
			printf("handle_vcpu: failed create vpm group\n");
			goto err_active_vpm;
		}
	} else {
		vmcfg->vpm_group = CSPACE_CAP_INVALID;
	}

	caps = calloc(vcpu_cnt, sizeof(caps[0]));
	if (caps == NULL) {
		printf("handle_vcpu: nomem\n");
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
			printf("invalid vcpu count for ras error handler\n");
			ret = ERROR_DENIED;
			goto err_vcpu_options;
		}
		if (ras_handler_vm != VMID_HYP) {
			printf("ras handler VM already exists\n");
			ret = ERROR_DENIED;
			goto err_vcpu_options;
		}
		vcpu_option_flags_set_ras_error_handler(&vcpu_options, true);
	}
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
			printf("handle_vcpu: failed create thread\n");
			ret = vcpu.error;
			goto err_create_thread;
		}

		caps[idx] = vcpu.new_cap;

		assert(idx < data->affinity_map_cnt);

		cpu_index_t affinity = data->affinity_map[idx];

		ret = gunyah_hyp_vcpu_set_affinity(vcpu.new_cap, affinity);
		if (ret != OK) {
			printf("handle_vcpu: failed set affinity\n");
			goto err_create_thread;
		}

		ret = gunyah_hyp_vcpu_set_priority(vcpu.new_cap, priority);
		if (ret != OK) {
			printf("handle_vcpu: failed set priority\n");
			goto err_create_thread;
		}

		ret = gunyah_hyp_vcpu_set_timeslice(vcpu.new_cap, timeslice);
		if (ret != OK) {
			printf("handle_vcpu: failed set timeslice\n");
			goto err_create_thread;
		}

		vcpu_data_t *vcpu_data =
			vector_at_ptr(vcpu_data_t, data->vcpus, idx);
		assert(vcpu_data != NULL);

		bool boot_vcpu = idx == rm_get_platform_root_vcpu_index();
		ret = vm_config_add_vcpu(vmcfg, vcpu.new_cap, affinity,
					 boot_vcpu, vcpu_data->patch);
		if (ret != OK) {
			printf("handle_vcpu: failed to add vcpu\n");
			goto err_create_thread;
		}

		ret = gunyah_hyp_cspace_attach_thread(vmcfg->cspace,
						      vcpu.new_cap);
		if (ret != OK) {
			printf("handle_vcpu: failed attach cspace\n");
			goto err_create_thread;
		}

		ret = gunyah_hyp_addrspace_attach_thread(vmcfg->addrspace,
							 vcpu.new_cap);
		if (ret != OK) {
			printf("handle_vcpu: failed attach addrspace\n");
			goto err_create_thread;
		}

		if (vmcfg->vpm_group != CSPACE_CAP_INVALID) {
			ret = gunyah_hyp_vpm_group_attach_vcpu(
				vmcfg->vpm_group, vcpu.new_cap, idx);
			if (ret != OK) {
				printf("handle_vcpu: failed attach vpm\n");
				goto err_create_thread;
			}
		}

		ret = gunyah_hyp_vic_attach_vcpu(vmcfg->vic, vcpu.new_cap, idx);
		if (ret != OK) {
			printf("handle_vcpu: failed attach vic\n");
			goto err_create_thread;
		}

		ret = gunyah_hyp_vcpu_configure(vcpu.new_cap, vcpu_options);
		if (ret != OK) {
			printf("handle_vcpu: failed vcpu configure\n");
			goto err_create_thread;
		}
	}

	vmcfg->vm->primary_vcpu_cap = caps[rm_get_platform_root_vcpu_index()];

	// we should activate secondary vcpus in dtb parser
	// Activate secondary vcpus
	for (index_t i = 0; i < vcpu_cnt; i++) {
		ret = gunyah_hyp_object_activate(caps[i]);
		if (ret != OK) {
			printf("handle_vcpu: failed vcpu activate\n");
			goto err_create_thread;
		}
	}

	if (data->ras_error_handler) {
		ras_handler_vm = vmcfg->vm->vmid;
	}
err_create_thread:
	if (ret != OK) {
		do {
			(void)gunyah_hyp_cspace_delete_cap_from(
				rm_get_rm_cspace(), caps[idx]);
			idx--;
		} while (idx != 0);
	}

err_vcpu_options:
err_alloc_caps:
err_active_vpm:
	if ((ret != OK) && (vmcfg->vpm_group != CSPACE_CAP_INVALID)) {
		(void)gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							vmcfg->vpm_group);
		vmcfg->vpm_group = CSPACE_CAP_INVALID;
	}
err_create_vpm:
	free(caps);
err_vcpu_cnt:
err_sched_prop:

	return ret;
}

add_doorbell_ret_t
add_doorbell(vm_config_t *vmcfg, vmid_t self, vmid_t peer, bool is_src,
	     label_t label, const char *generate, virq_t virq,
	     bool need_alloc_virq, bool export_to_dt)
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

	virq_t db_virq = virq;
	if (need_alloc_virq) {
		irq_manager_get_free_virt_virq_ret_t free_irq_ret;
		free_irq_ret = irq_manager_get_free_virt_virq(db_vmid);
		if (free_irq_ret.err != RM_OK) {
			ret.err = ERROR_DENIED;
			(void)gunyah_hyp_cspace_delete_cap_from(
				rm_get_rm_cspace(), cap_ret.r);
			goto out;
		}

		db_virq = free_irq_ret.virq;
	}

	// Reserve VIRQ for recv VM
	rm_error_t rm_err = irq_manager_reserve_virq(db_vmid, db_virq, true);
	if (rm_err != RM_OK) {
		ret.err = ERROR_DENIED;
		(void)gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							cap_ret.r);
		goto out;
	}

	ret.node = vm_config_add_doorbell(vmcfg, peer, cap_ret.r, is_src,
					  db_virq, label, generate,
					  export_to_dt);
	if (ret.node == NULL) {
		ret.err = ERROR_DENIED;
		irq_manager_return_virq(db_vmid, db_virq);
		(void)gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(),
							cap_ret.r);
		goto out;
	}
out:
	return ret;
}

error_t
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
					       d->general.label, NULL, 0U, true,
					       false);
			if (add_ret.err != OK) {
				ret = add_ret.err;
				goto out;
			}
			db = add_ret.node;

			add_ret = add_doorbell(vmcfg, self, peer, true,
					       d->general.label, NULL, 0U, true,
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

error_t
handle_iomem_ranges(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;

	// NOTE: make sure ipa provided is equal/larger than iomem_addr if
	// iomem_addr is not 0UL
	const vmaddr_t iomem_addr = 0UL;
	const size_t   iomem_size = 0x20000000UL;

	index_t idx = 0;

	size_t cnt = vector_size(data->iomem_ranges);

	cap_id_t *created_me = calloc(cnt, sizeof(cap_id_t));
	if (created_me == NULL) {
		ret = ERROR_NOMEM;
		goto err_alloc_cap_id;
	}

	// Reserve from zero page to end of IO memory
	address_range_allocator_alloc_ret_t as_ret;
	as_ret = address_range_allocator_alloc(vmcfg->vm->as_allocator,
					       iomem_addr, iomem_size,
					       ALIGNMENT_IGNORED);
	if (as_ret.err != OK) {
		ret = as_ret.err;
		goto err_alloc_ipa;
	}

	for (idx = 0; idx < cnt; idx++) {
		iomem_range_data_t *d = vector_at_ptr(iomem_range_data_t,
						      data->iomem_ranges, idx);

		paddr_t phys = d->phys_base;

		vmaddr_t ipa = d->ipa_base;

		size_t size = d->size;

		// NOTE: make sure ipa provided is equal/larger than iomem_addr
		// if iomem_addr is not 0UL
		if (util_add_overflows(ipa, size - 1) ||
		    ((ipa - 1 + size) > (iomem_addr - 1 + iomem_size))) {
			ret = ERROR_DENIED;
			goto out;
		}

		pgtable_access_t access =
			iomem_range_access_to_pgtable_access[d->access];
		if (access >=
		    util_array_size(iomem_range_access_to_pgtable_access)) {
			ret = ERROR_DENIED;
			goto out;
		}

		cap_id_result_t me_ret = memextent_create_and_map(
			vmcfg->addrspace, phys, ipa, size, access,
			MEMEXTENT_MEMTYPE_DEVICE,
			PGTABLE_VM_MEMTYPE_DEVICE_NGNRE, rm_get_device_me());

		if (me_ret.e != OK) {
			ret = me_ret.e;
			goto out;
		} else {
			created_me[idx] = me_ret.r;
		}
	}
out:
	if (ret != OK) {
		while (idx > 0) {
			idx--;
			(void)gunyah_hyp_cspace_delete_cap_from(
				rm_get_device_me(), created_me[idx]);
		}
	}

	if (ret != OK) {
		(void)address_range_allocator_free(vmcfg->vm->as_allocator,
						   iomem_addr, iomem_size);
	}
err_alloc_ipa:
	free(created_me);
err_alloc_cap_id:
	return ret;
}

error_t
handle_iomems(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;

	vdevice_node_t       *node = NULL;
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
			printf("Failed: save compatible in iomems node\n");
			goto out;
		}

		cfg = calloc(1, sizeof(*cfg));
		if (cfg == NULL) {
			ret = ERROR_NOMEM;
			goto out;
		}

		node->config = cfg;

		*cfg = d->data;

		// deep copy
		if (cfg->rm_sglist_len > 0U) {
			sgl_entry_t *rm_sglist = calloc(d->data.rm_sglist_len,
							sizeof(rm_sglist[0]));
			if (rm_sglist == NULL) {
				ret = ERROR_NOMEM;
				goto out;
			}

			memcpy(rm_sglist, d->data.rm_sglist,
			       d->data.rm_sglist_len * sizeof(rm_sglist[0]));
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

	ret = handle_segments(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle segments\n");
		goto out;
	}

	ret = handle_ids(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle VM IDs\n");
		goto out;
	}

out:
	return ret;
}

error_t
vm_config_create_vdevices(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret;

	ret = handle_irqs(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle irqs\n");
		goto out;
	}

	ret = handle_iomems(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle iomems\n");
		goto out;
	}

	ret = handle_iomem_ranges(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle iomem ranges\n");
		goto out;
	}

	ret = handle_vcpu(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle vcpus, ret=%d\n", (int)ret);
		goto out;
	}

	ret = handle_rm_rpc(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle rm rpcs\n");
		goto out;
	}

	ret = handle_doorbell(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle doorbells\n");
		goto out;
	}

	ret = handle_msgqueue(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle msgqueues\n");
		goto out;
	}

	ret = handle_msgqueue_pair(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle msgqueue pairs\n");
		goto out;
	}

	ret = handle_shm(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle shms\n");
		goto out;
	}

	ret = platform_vm_config_create_vdevices(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle platform vm_config\n");
		goto out;
	}

out:
	return ret;
}

vm_config_get_rm_rpc_msg_queue_info_ret
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

	vm_config_get_rm_rpc_msg_queue_info_ret ret;

	if (vmcfg != NULL) {
		// Find the RM RPC node
		vdevice_node_t		       *node	 = NULL;
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

		ret = (vm_config_get_rm_rpc_msg_queue_info_ret){
			.err	  = RM_OK,
			.tx_capid = msgq_pair->tx_peer_cap,
			.rx_capid = msgq_pair->rx_peer_cap,
			.tx_virq  = msgq_pair->tx_peer_virq,
			.rx_virq  = msgq_pair->rx_peer_virq,
		};
	} else {
		ret = (vm_config_get_rm_rpc_msg_queue_info_ret){
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
	assert(vmcfg != NULL);

	vmcfg->vcpus = vector_init(vcpu_t, 2, 1);

	vmcfg->partition = partition;
	vmcfg->cspace	 = cspace;
	vmcfg->addrspace = CSPACE_CAP_INVALID;
	vmcfg->vic	 = CSPACE_CAP_INVALID;
	vmcfg->vpm_group = CSPACE_CAP_INVALID;
	vmcfg->watchdog	 = CSPACE_CAP_INVALID;

	assert(vm != NULL);
	vmcfg->vm     = vm;
	vm->vm_config = vmcfg;

	return vmcfg;
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
		printf("Error: failed to create hlos tx msg queue, err(%x)\n",
		       tx.e);
		ret = tx.e;
		goto out;
	}

	rx = create_msgqueue(depth, size);
	if (rx.e != OK) {
		printf("Error: failed to create hlos rx msg queue, err(%x)\n",
		       rx.e);
		ret = rx.e;
		goto out;
	}

	rm_rpc_data_t d = {
		.general = {
			.push_compatible = { "qcom,resource-manager-1-0",
						"qcom,resource-manager" },
			.push_compatible_num = 2,
			.label		   = 0U,
			.generate = "/hypervisor/qcom,resource-mgr",
		},
		.msg_size = size,
		.queue_depth = depth,
		.defined_irq = false,
		.is_console_dev = true,
	};

	ret = vm_config_add_rm_rpc(vmcfg, &d, rx.r, tx.r);
	if (ret != OK) {
		printf("Error: failed to add hlos rm rpc vdevice, err(%x)\n",
		       ret);
		goto out;
	}

	vm_console_t *console = vm_console_create(vmcfg->vm);
	if (console == NULL) {
		printf("Error: failed to allocate a console\n");
	} else {
		printf("HLOS: allocate console ...\n");
		vm_config_set_console(vmcfg, console);
	}

	ret = platform_vm_config_hlos_vdevices_setup(vmcfg);
	if (ret != OK) {
		printf("Error: failed to handle platform vm_config\n");
		goto out;
	}

out:

	if (ret != OK) {
		if (tx.e == OK) {
			(void)gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace,
								tx.r);
		}

		if (rx.e == OK) {
			(void)gunyah_hyp_cspace_delete_cap_from(vmcfg->cspace,
								rx.r);
		}
	}

	return;
}

error_t
handle_irqs(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;

	cap_id_t *irqs = malloc(VIRQ_LAST_VALID * sizeof(cap_id_t));

	if (irqs == NULL) {
		return ERROR_NOMEM;
	}

	for (index_t i = 0; i < VIRQ_LAST_VALID; ++i) {
		irqs[i] = CSPACE_CAP_INVALID;
	}

	vmid_t self = vmcfg->vm->vmid;

	size_t cnt = vector_size(data->irq_ranges);
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
		irq_manager_create(vmcfg->vic, VIRQ_LAST_VALID, irqs);
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

	free(irqs);

	return ret;
}

error_t
handle_segments(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;

	vm_t *vm = vmcfg->vm;
	assert(vm != NULL);

	vm->ramfs_idx = data->ramfs_idx;

	return ret;
}

error_t
handle_ids(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;
	assert(data != NULL);

	vm_t *vm = vmcfg->vm;
	assert(vm != NULL);

	vm->has_guid = data->has_guid;
	memcpy(vm->guid, data->vm_guid, VM_GUID_LEN);

	vm->sensitive = data->sensitive;

	strlcpy(vm->uri, data->vm_uri, VM_MAX_URI_LEN);
	vm->uri_len = (uint16_t)strlen(vm->uri);

	strlcpy(vm->name, data->vm_name, VM_MAX_NAME_LEN);
	vm->name_len = (uint16_t)strlen(vm->name);

	ret = platform_config_handle_ids(vmcfg, data);

	return ret;
}

void
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

	for (i = 0; i < data->push_compatible_num; ++i) {
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

void
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
		vdevice_node_t		       *peer_node = NULL;
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
	}

	vm_config_delete_vdevice_node(vmcfg, node);

	// Only destroy if there is no matching vdevice
	if (!has_matching_vdevice) {
		// FIXME: Revoke all children caps by revoke_caps_from
		err = gunyah_hyp_cspace_revoke_cap_from(rm_get_rm_cspace(), rx);
		assert(err == OK);
		err = gunyah_hyp_cspace_revoke_cap_from(rm_get_rm_cspace(), tx);
		assert(err == OK);

		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), rx);
		assert(err == OK);
		err = gunyah_hyp_cspace_delete_cap_from(rm_get_rm_cspace(), tx);
		assert(err == OK);
	}

	return;
}
