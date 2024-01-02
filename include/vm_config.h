// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

extern const char *gunyah_api_version;

typedef uint32_t label_t;

struct vdevice_node;
typedef struct vdevice_node vdevice_node_t;

struct vm_console;
typedef struct vm_console vm_console_t;

struct rm_rpc_data;
typedef struct rm_rpc_data rm_rpc_data_t;

struct dtb_parser_ops;
typedef struct dtb_parser_ops dtb_parser_ops_t;

struct dtb_parser_data_s;
typedef struct dtb_parser_data_s vm_config_parser_data_t;

struct dtb_parser_alloc_params_s;
typedef struct dtb_parser_alloc_params_s vm_config_parser_params_t;

struct general_data;
typedef struct general_data general_data_t;

typedef uint32_t resource_handle_t;

typedef struct vector_s vector_t;

#define VDEVICE_MAX_COMPATIBLE_LEN   256U
#define VDEVICE_MAX_PUSH_COMPATIBLES 6U

rm_error_t
vm_config_init(rm_env_data_t *env_data);

vm_config_t *
vm_config_alloc(vm_t *vm, cap_id_t cspace, cap_id_t partition);

void
vm_config_dealloc(vm_t *vm);

void
vm_config_hlos_vdevices_setup(vm_config_t *vmcfg, cap_id_t vic);

void
vm_config_add_vdevices(vm_config_t *vmcfg);

rm_error_t
vm_config_parse_dt(vm_config_t *vmcfg, void *fdt);

error_t
vm_config_add_vcpu(vm_config_t *vmcfg, cap_id_t rm_cap, uint32_t affinity_index,
		   bool boot_vcpu, const char *patch);

vector_t *
vm_config_get_vcpus(const vm_config_t *vmcfg);

void
vm_config_destroy(vm_config_t *vmcfg);

void
vm_config_deinit(void);

error_t
handle_compatibles(vdevice_node_t *vdevice, const general_data_t *data);

// APIs to help vm query
rm_error_t
vm_config_get_resource_descs(vmid_t self, vmid_t vmid, vector_t *descs);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

typedef struct {
	rm_error_t err;

	cap_id_t tx_capid;
	cap_id_t rx_capid;

	virq_t tx_virq;
	virq_t rx_virq;
} vm_config_get_rm_rpc_msg_queue_info_ret_t;

#pragma clang diagnostic pop

vm_config_get_rm_rpc_msg_queue_info_ret_t
vm_config_get_rm_rpc_msg_queue_info(vmid_t self, vmid_t peer_id);

__attribute__((weak)) vm_config_get_rm_rpc_msg_queue_info_ret_t
platform_get_hyp_rpc_msg_queue_info(void);

void
vm_config_set_console(vm_config_t *vmcfg, vm_console_t *console);

struct vm_console *
vm_config_get_console(vmid_t self);

bool
vm_config_check_console_allowed(vmid_t self);

void
vm_config_flush_rm_rpc(vmid_t self);

dtb_parser_ops_t *
vm_config_parser_get_ops(void);

vm_config_parser_params_t
vm_config_parser_get_params(const vm_t *vm);

error_t
vm_config_update_parsed(vm_config_t *vmcfg, vm_config_parser_data_t *data);

error_t
vm_config_create_vdevices(vm_config_t *vmcfg, vm_config_parser_data_t *data);

void
vm_config_destroy_vm_objects(vm_t *vm);

void
vm_config_handle_exit(const vm_t *vm);

bool
vm_reset_handle_init(const vm_t *vm);

bool
vm_reset_handle_destroy_vdevices(const vm_t *vm);

void
vm_config_delete_vdevice_node(vm_config_t *vmcfg, vdevice_node_t **node);

void
vm_config_destroy_vdevices(vm_t *vm);

extern vmid_t ras_handler_vm;

error_t
vm_config_vrtc_set_time_base(vm_t *vm, uint64_t time_base,
			     uint64_t sys_timer_ref);
