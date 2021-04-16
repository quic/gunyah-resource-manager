// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define VMID_HYP  0x0U
#define VMID_HLOS 0x3U
#define VMID_SVM  0x2DU
#define VMID_RM	  0xFFU

extern const char *gunyah_api_version;

typedef uint32_t label_t;

struct vdevice_node;
typedef struct vdevice_node vdevice_node_t;

struct vm_config;
typedef struct vm_config vm_config_t;

struct vm_console;
typedef struct vm_console vm_console_t;

struct vm_irq_manager;
typedef struct vm_irq_manager vm_irq_manager_t;

struct vm;
typedef struct vm vm_t;

struct rm_rpc_data;
typedef struct rm_rpc_data rm_rpc_data_t;

struct dtb_parser_ops;
typedef struct dtb_parser_ops dtb_parser_ops_t;

struct vm_config_parser_data;
typedef struct vm_config_parser_data vm_config_parser_data_t;

rm_error_t
vm_config_init(boot_env_data_t *env_data);

vm_config_t *
vm_config_alloc(vm_t *vm, cap_id_t cspace, cap_id_t partition);

error_t
vm_config_hlos_vdevices_setup(vm_config_t *vmcfg, cap_id_t vic);

void
vm_config_add_vdevices(vm_config_t *vmcfg);

rm_error_t
vm_config_parse_dt(vm_config_t *vmcfg, void *fdt);

void
vm_config_add_vcpu(vm_config_t *vmcfg, cap_id_t rm_cap, uint32_t affinity_index,
		   bool boot_vcpu);

void
vm_config_destroy(vm_config_t *vmcfg);

void
vm_config_deinit(void);

// APIs to help vm query
error_t
vm_config_get_resource_descs(vmid_t self, vmid_t vmid, vector_t *descs);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

typedef struct {
	rm_error_t err;

	cap_id_t tx_capid;
	cap_id_t rx_capid;

	virq_t tx_virq;
	virq_t rx_virq;
} vm_config_get_rm_rpc_msg_queue_info_ret;

#pragma clang diagnostic pop

vm_config_get_rm_rpc_msg_queue_info_ret
vm_config_get_rm_rpc_msg_queue_info(vmid_t self, vmid_t peer_id);

void
vm_config_set_console(vm_config_t *vmcfg, vm_console_t *console);

struct vm_console *
vm_config_get_console(vmid_t self);

void
vm_config_set_irq_manager(vm_config_t *vmcfg, vm_irq_manager_t *irq_manager);

struct vm_irq_manager *
vm_config_get_irq_manager(vmid_t self);

void
vm_config_flush_rm_rpc(vmid_t self);

dtb_parser_ops_t *
vm_config_parser_get_ops(void);

error_t
vm_config_update_parsed(vm_config_t *vmcfg, vm_config_parser_data_t *data);

error_t
vm_config_create_vdevices(vm_config_t *vmcfg, vm_config_parser_data_t *data);
