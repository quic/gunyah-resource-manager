// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef struct memparcel memparcel_t;

typedef enum {
	// two message queues to communicate with resource manager
	VDEV_RM_RPC = 0,
	// indicates the one to receive the doorbell
	VDEV_DOORBELL,
	// contains one direction message queue
	VDEV_MSG_QUEUE,
	// contains two direction message queue
	VDEV_MSG_QUEUE_PAIR,
	VDEV_SHM,
	VDEV_VIRTUAL_PM,
} vdevice_type_t;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

struct vdevice_msg_queue_pair {
	// TX msgq is from VM's perspective
	vmid_t peer;

	// Caps in RM's cspace
	cap_id_t tx_master_cap;
	cap_id_t rx_master_cap;

	cap_id_t tx_vm_cap;
	virq_t	 tx_vm_virq;
	cap_id_t rx_vm_cap;
	virq_t	 rx_vm_virq;

	// Note, peer tx == vm rx
	cap_id_t tx_peer_cap;
	virq_t	 tx_peer_virq;
	cap_id_t rx_peer_cap;
	virq_t	 rx_peer_virq;

	count_t tx_queue_depth;
	count_t rx_queue_depth;

	size_t tx_max_msg_size;
	size_t rx_max_msg_size;
};

struct vdevice_doorbell {
	vmid_t peer;
	bool   source;

	cap_id_t master_cap;

	cap_id_t vm_cap;
	virq_t	 vm_virq;
	cap_id_t peer_cap;
	virq_t	 peer_virq;

	uint32_t label;

	// only valid if it's associtated with a shm
	memparcel_t *related_mp;
};

struct vdevice_virtual_pm {
	vmid_t peer;

	cap_id_t master_cap;

	cap_id_t peer_cap;
	virq_t	 peer_virq;

	uint32_t label;
};

struct vdevice_msg_queue {
	vmid_t peer;
	bool   tx;

	cap_id_t master_cap;

	cap_id_t vm_cap;
	virq_t	 vm_virq;
	cap_id_t peer_cap;
	virq_t	 peer_virq;

	uint16_t queue_depth;
	uint16_t msg_size;

	uint32_t label;
};

struct vdevice_shm {
	vdevice_node_t *db;
	vdevice_node_t *db_src;

	vmid_t peer;

	label_t label;

	bool is_plain_shm;

	bool need_allocate;

	vmaddr_t base_ipa;

	size_t sz;

	// FIXME: might be better to use handle for external module
	memparcel_t *mp;
};

#define VDEVICE_MAX_COMPATIBLE_LEN   256U
#define VDEVICE_MAX_PUSH_COMPATIBLES 4

struct vdevice_node {
	vdevice_type_t type;

	struct vdevice_node *vdevice_next;
	struct vdevice_node *vdevice_prev;

	// Indicates vdevice should be added to the VM's device tree overlay.
	bool export_to_dt;

	bool visible; // visible to queries

	count_t push_compatible_num;
	char *	push_compatible[VDEVICE_MAX_PUSH_COMPATIBLES];

	char *generate;

	// type specific configuration
	void *config;
};

struct vm_config {
	vm_t *vm;

	// for vm identification
	char *vendor;

	char *image_name;

	uint64_t swid;

	vector_t *vcpus;

	vdevice_node_t *vdevice_nodes;

	// FIXME: legacy - move
	cap_id_t partition;
	cap_id_t cspace;
	cap_id_t addrspace;
	cap_id_t vic;
	cap_id_t vpm_group;

	vm_console_t *console;

	vm_irq_manager_t *irq_manager;
};

#pragma clang diagnostic pop
