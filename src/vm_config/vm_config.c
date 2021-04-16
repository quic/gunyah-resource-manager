// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm-rpc.h>

#include <guest_interface.h>
#include <guest_rights.h>
#include <irq_manager.h>
#include <memextent.h>
#include <resource-manager.h>
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

#include "vm_config_parser.h"

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
handle_shm(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_vcpu(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_iomems(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_irqs(vm_config_t *vmcfg, vm_config_parser_data_t *data);
static error_t
handle_segments(vm_config_t *vmcfg, vm_config_parser_data_t *data);

static error_t
vm_config_add_shm(vm_config_t *vmcfg, shm_data_t *data, vdevice_node_t *db,
		  vdevice_node_t *db_src);

static error_t
vm_config_add_vpm_group(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
			virq_t vm_virq, uint32_t label, const char *generate);

static vdevice_node_t *
vm_config_add_doorbell(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
		       bool source, virq_t virq, uint32_t label,
		       const char *generate, bool export_to_dt);
static void
vm_config_add_msgqueue(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
		       bool tx, uint16_t queue_depth, uint16_t msg_size,
		       virq_t vm_virq, virq_t peer_virq, uint32_t label,
		       const char *generate, bool export_to_dt);
static error_t
vm_config_add_rm_rpc(vm_config_t *vmcfg, rm_rpc_data_t *data, cap_id_t rx,
		     cap_id_t tx);

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
			item.resource_type = (db->source) ? RSC_DOORBELL_SRC
							  : RSC_DOORBELL;
			item.resource_label = db->label;
			item.resource_capid_low =
				(uint32_t)(db->vm_cap & 0xffffffffU);
			item.resource_capid_high = (uint32_t)(db->vm_cap >> 32);
			item.resource_virq_number = db->vm_virq;
			vector_push_back(descs, item);
		} else if (db->peer == self) {
			// Doorbell from peer vdevice list
			item.resource_type = (db->source) ? RSC_DOORBELL
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
			item.resource_type = (mq->tx) ? RSC_MSG_QUEUE_SEND
						      : RSC_MSG_QUEUE_RECV;
			item.resource_label = mq->label;
			item.resource_capid_low =
				(uint32_t)(mq->vm_cap & 0xffffffffU);
			item.resource_capid_high = (uint32_t)(mq->vm_cap >> 32);
			item.resource_virq_number = mq->vm_virq;
			vector_push_back(descs, item);
		} else if (mq->peer == self) {
			// Msgqueue from peer vdevice list
			item.resource_type = (mq->tx) ? RSC_MSG_QUEUE_RECV
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
	vm_t *	vm  = vm_lookup(vmid);

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

void
vm_config_add_vcpu(vm_config_t *vmcfg, cap_id_t rm_cap, uint32_t affinity_index,
		   bool boot_vcpu)
{
	vcpu_t	     vcpu = { 0 };
	vm_config_t *owner_cfg;

	vcpu.master_cap	    = rm_cap;
	vcpu.vm_cap	    = CSPACE_CAP_INVALID;
	vcpu.affinity_index = affinity_index;
	vcpu.boot_vcpu	    = boot_vcpu;

	vm_t *hlos = vm_lookup(VMID_HLOS);
	if ((hlos == NULL) || (hlos->vm_config == NULL)) {
		printf("Failed: invalid hlos vm\n");
		goto err;
	}

	owner_cfg = hlos->vm_config;

	if (vmcfg->vm->vmid == VMID_HLOS) {
		goto out;
	}

	// Copy SVM vcpu caps to HLOS cspace
	gunyah_hyp_cspace_copy_cap_from_result_t copy_ret;

	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(), rm_cap,
						   owner_cfg->cspace,
						   CAP_RIGHTS_THREAD_AFFINITY);
	if (copy_ret.error != OK) {
		printf("Failed: copy vcpu cap from rm cspace\n");
		goto err;
	}

	vcpu.owner_cap = copy_ret.new_cap;

out:
	// Add to vm_config
	vector_push_back(vmcfg->vcpus, vcpu);

err:
	return;
}

error_t
vm_config_add_vpm_group(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
			virq_t peer_virq, uint32_t label, const char *generate)
{
	error_t	     err      = OK;
	cap_id_t     peer_cap = CSPACE_CAP_INVALID;
	vm_config_t *peer_cfg = NULL;

	vdevice_node_t *node = calloc(1, sizeof(*node));
	if (node == NULL) {
		printf("Failed: to alloc vdevice node\n");
		err = ERROR_NOMEM;
		goto out;
	}

	node->type	   = VDEV_VIRTUAL_PM;
	node->export_to_dt = false;
	node->visible	   = true;

	if (generate != NULL) {
		node->generate = strdup(generate);
		if (node->generate == NULL) {
			printf("Failed: to alloc virtual pm generate string\n");
			err = ERROR_NOMEM;
			goto out;
		}
	} else {
		node->generate = "/hypervisor/qcom,vpm";
	}

	struct vdevice_virtual_pm *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		printf("Failed: to alloc vpm config\n");
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

	peer_cfg = peer_vm->vm_config;

	// Copy vpm cap to the peer VM's cspace with query rights
	gunyah_hyp_cspace_copy_cap_from_result_t copy_ret;

	copy_ret = gunyah_hyp_cspace_copy_cap_from(rm_get_rm_cspace(), rm_cap,
						   peer_cfg->cspace,
						   CAP_RIGHTS_VPM_GROUP_QUERY);
	if (copy_ret.error != OK) {
		printf("Failed: to copy vpm cap\n");
		err = copy_ret.error;
		goto out;
	}
	peer_cap = copy_ret.new_cap;

	// Bind VIRQs to peer's vic
	err = gunyah_hyp_vpm_group_bind_virq(rm_cap, peer_cfg->vic, peer_virq);
	if (err != OK) {
		printf("Failed: to bind vpm virq\n");
		goto out;
	}

	cfg->peer	= peer;
	cfg->master_cap = rm_cap;
	cfg->label	= label;
	cfg->peer_cap	= peer_cap;
	cfg->peer_virq	= peer_virq;

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);

out:
	if ((err != OK) && (node != NULL)) {
		if (peer_cap != CSPACE_CAP_INVALID) {
			assert(peer_cfg != NULL);
			(void)gunyah_hyp_cspace_delete_cap_from(
				peer_cfg->cspace, peer_cap);
		}
		free(node->config);
		free(node->generate);
		free(node);
	}

	return err;
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
	}

	return node;
}

void
vm_config_add_msgqueue(vm_config_t *vmcfg, vmid_t peer, cap_id_t rm_cap,
		       bool tx, uint16_t queue_depth, uint16_t msg_size,
		       virq_t vm_virq, virq_t peer_virq, uint32_t label,
		       const char *generate, bool export_to_dt)
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
	cfg->queue_depth = queue_depth;
	cfg->msg_size	 = msg_size;
	cfg->label	 = label;
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
		free(node->generate);
		free(node);
	}

	return;
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

	rpc_node->push_compatible_num = data->general.push_compatible_num;
	for (index_t i = 0; i < data->general.push_compatible_num; ++i) {
		rpc_node->push_compatible[i] =
			strdup(data->general.push_compatible[i]);
		if (rpc_node->push_compatible[i] == NULL) {
			err = ERROR_NOMEM;
			goto out;
		}
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

		for (index_t i = 0; i < rpc_node->push_compatible_num; ++i) {
			free(rpc_node->push_compatible[i]);
		}
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
	error_t ret = OK;

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

	node->push_compatible_num = data->general.push_compatible_num;
	for (index_t i = 0; i < data->general.push_compatible_num; ++i) {
		node->push_compatible[i] =
			strdup(data->general.push_compatible[i]);
		if (node->push_compatible[i] == NULL) {
			ret = ERROR_NOMEM;
			goto out;
		}
	}

	struct vdevice_shm *cfg = calloc(1, sizeof(*cfg));
	if (cfg == NULL) {
		printf("Failed: to alloc doorbell config\n");
		ret = ERROR_NOMEM;
		goto out;
	}
	node->config = cfg;

	vm_t *peer_vm = vm_lookup(data->peer);
	if (peer_vm == NULL) {
		printf("Failed: invalid peer\n");
		ret = ERROR_DENIED;
		goto out;
	}

	cfg->peer  = data->peer;
	cfg->label = data->general.label;

	cfg->need_allocate = data->need_allocate;

	cfg->base_ipa = data->mem_base_ipa;

	cfg->is_plain_shm = data->is_plain_shm;

	if (!cfg->is_plain_shm) {
		assert(db != NULL);
		assert(db_src != NULL);

		cfg->db	    = db;
		cfg->db_src = db_src;
	}

	// need to match & set latter
	cfg->mp = NULL;

	list_append(vdevice_node_t, &vmcfg->vdevice_nodes, node, vdevice_);

out:
	if ((ret != OK) && (node != NULL)) {
		for (index_t i = 0; i < node->push_compatible_num; ++i) {
			free(node->push_compatible[i]);
		}
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

	vmid_t peer = data->peer, self = vmcfg->vm->vmid;

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

	vm_config_add_msgqueue(vmcfg, VMID_HLOS, mq.r, is_sender,
			       data->queue_depth, data->msg_size, svirq, pvirq,
			       data->general.label, data->general.generate,
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

		if (d->is_pair) {
			virq_t self_tx = 0U;
			virq_t self_rx = 0U;

			if (d->defined_irq) {
				self_tx = d->irqs[TX_IRQ_IDX].virq;
				self_rx = d->irqs[RX_IRQ_IDX].virq;
			}

			// create send mq
			ret = add_msgqueue(vmcfg, d, true, self_tx,
					   !d->defined_irq, 0U, true);
			if (ret != OK) {
				goto out;
			}

			ret = add_msgqueue(vmcfg, d, false, self_rx,
					   !d->defined_irq, 0U, true);
			if (ret != OK) {
				goto out;
			}
		} else {
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

		add_doorbell_ret_t add_ret = add_doorbell(
			vmcfg, vmcfg->vm->vmid, VMID_HLOS, d->is_source,
			d->general.label, d->general.generate, d->irq.virq,
			!d->defined_irq, true);
		if (add_ret.err != OK) {
			ret = add_ret.err;
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
	error_t ret = OK;

	// Create the PSCI group

	gunyah_hyp_partition_create_vpm_group_result_t vg;
	vg = gunyah_hyp_partition_create_vpm_group(rm_get_rm_partition(),
						   rm_get_rm_cspace());
	if (vg.error != OK) {
		ret = vg.error;
		goto out;
	}

	ret = gunyah_hyp_object_activate(vg.new_cap);
	if (ret != OK) {
		goto out;
	}
	vmcfg->vpm_group = vg.new_cap;

	assert(vmcfg->vm != NULL);

	// For SVM's vpm group we must reserve and bind a VIRQ to HLOS' vic
	if (vmcfg->vm->vmid == VMID_SVM) {
		vmid_t peer = VMID_HLOS;

		irq_manager_get_free_virt_virq_ret_t free_irq_ret;
		free_irq_ret = irq_manager_get_free_virt_virq(peer);
		if (free_irq_ret.err != RM_OK) {
			ret = ERROR_DENIED;
			goto out;
		}

		virq_t vpm_virq = free_irq_ret.virq;

		rm_error_t rm_err =
			irq_manager_reserve_virq(peer, vpm_virq, true);
		if (rm_err != RM_OK) {
			ret = ERROR_DENIED;
			goto out;
		}

		ret = vm_config_add_vpm_group(vmcfg, peer, vmcfg->vpm_group,
					      vpm_virq, 0U, NULL);
		if (ret != OK) {
			irq_manager_return_virq(peer, vpm_virq);
			goto out;
		}
	}

	cap_id_t caps[PLATFORM_MAX_CORES];

	for (cpu_index_t i = 0U; i < PLATFORM_MAX_CORES; i++) {
		caps[i] = CSPACE_CAP_INVALID;
	}

	for (cpu_index_t i = 0; i < data->vcpu_cnt; i++) {
		gunyah_hyp_partition_create_thread_result_t vcpu;
		vcpu = gunyah_hyp_partition_create_thread(vmcfg->partition,
							  rm_get_rm_cspace());
		if (vcpu.error != OK) {
			goto out;
		}

		caps[i] = vcpu.new_cap;

		cpu_index_t affinity;
		if (i < data->affinity_map_cnt) {
			affinity = data->affinity_map[i];
		} else {
			affinity = i;
		}

		ret = gunyah_hyp_vcpu_set_affinity(vcpu.new_cap, affinity);
		if (ret != OK) {
			goto out;
		}

		// FIXME: should we check root cpu index is in the range
		// of defined cpus?
		bool boot_vcpu = (i == ROOT_VCPU_INDEX ? true : false);
		vm_config_add_vcpu(vmcfg, vcpu.new_cap, affinity, boot_vcpu);

		ret = gunyah_hyp_cspace_attach_thread(vmcfg->cspace,
						      vcpu.new_cap);
		if (ret != OK) {
			goto out;
		}

		ret = gunyah_hyp_addrspace_attach_thread(vmcfg->addrspace,
							 vcpu.new_cap);
		if (ret != OK) {
			goto out;
		}

		ret = gunyah_hyp_vpm_group_attach_vcpu(vmcfg->vpm_group,
						       vcpu.new_cap, i);
		if (ret != OK) {
			goto out;
		}

		ret = gunyah_hyp_vic_attach_vcpu(vmcfg->vic, vcpu.new_cap, i);
		if (ret != OK) {
			goto out;
		}
	}

	vmcfg->vm->primary_vcpu_cap = caps[ROOT_VCPU_INDEX];

	// we should activate secondary vcpus in dtb parser
	// Activate secondary vcpus
	for (index_t i = 0; i < data->vcpu_cnt; i++) {
		ret = gunyah_hyp_object_activate(caps[i]);
		if (ret != OK) {
			goto out;
		}
	}

out:
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
			vmid_t peer = d->peer;

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
handle_iomems(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret = OK;

	// NOTE: make sure ipa provided is euqal/larger than iomem_addr if
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

		// NOTE: make sure ipa provided is euqal/larger than iomem_addr
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
			MEMEXTENT_MEMTYPE_DEVICE, rm_get_device_me());

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
vm_config_update_parsed(vm_config_t *vmcfg, vm_config_parser_data_t *data)
{
	error_t ret;

	ret = handle_segments(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle segments\n");
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

	ret = handle_vcpu(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle vcpus\n");
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

	ret = handle_shm(vmcfg, data);
	if (ret != OK) {
		printf("Error: failed to handle shms\n");
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
		vdevice_node_t *	       node	 = NULL;
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
			.err = RM_ERROR_INVALID,
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
	vm_t *	      vm      = vm_lookup(self);
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

error_t
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

	return ret;
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

	// check if the required irq is in HLOS irq, if so, do static share
	for (index_t i = 0; i < cnt; i++) {
		irq_range_data_t *d =
			vector_at_ptr(irq_range_data_t, data->irq_ranges, i);

		virq_t hw_irq = d->hw_irq;
		virq_t virq   = d->virq;

		(void)irq_manager_static_share(VMID_HLOS, hw_irq, self, virq);
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
