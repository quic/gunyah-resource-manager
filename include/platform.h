// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

struct dtb_parser_data_s;
typedef struct dtb_parser_data_s vm_config_parser_data_t;

error_t
platform_env_init(platform_env_data_t **platform_env);

error_t
platform_hlos_create(vm_t *vm, const rm_env_data_t *env_data);

bool
platform_msg_callback(vmid_t vm_id, uint32_t msg_id, uint16_t seq_num,
		      void *buf, size_t len);

bool
platform_notif_callback(vmid_t vm_id, uint32_t notification_id, void *buf,
			size_t len);

__attribute__((weak)) error_t
platform_hyp_rpc_send_packet(cap_id_t tx_cap, void *buf, size_t len);

__attribute__((weak)) error_t
platform_hyp_rpc_recv_packet(cap_id_t rx_cap, void *buf, size_t buf_len,
			     size_t *recv_size);

error_t
platform_config_update_parsed(vm_config_t	      *vmcfg,
			      vm_config_parser_data_t *data);

// return true if running on a security enabled device
bool
platform_get_security_state(void);

bool
platform_expose_log_to_hlos(void);

const char *
platform_get_sign_authority_string(uint32_t signer_info);

error_t
platform_init(rm_env_data_t *env_data, vmaddr_t log_buf, size_t log_buf_size);

error_t
platform_init_complete(void);

error_t
platform_vm_create(vm_t *vm, bool hlos);

error_t
platform_vm_dt_create_hlos(vm_t *vm);

typedef struct vm_auth_param vm_auth_param_t;

rm_error_t
platform_vm_auth(vm_t *vm, count_t num_auth_params,
		 vm_auth_param_t *auth_params);

rm_error_t
platform_vm_init(vm_t *vm);

error_t
platform_vm_takedown(vm_t *vm);

error_t
platform_vm_destroy(vm_t *vm, bool hlos);

error_t
platform_handle_destroy_vdevices(const vm_t *vm);

void
platform_exit_handler(int exit_code);

// TODO: Cleanly define a platform API that allows a platform to mark a range
// of VMIDs as platform reserved, and remove secondary and peripheral VMIDs
// here.

// Bitmap of platform VMIDs which are managed by RM.
uint64_t
platform_get_secondary_vmids(void);

// Bitmap of platform peripheral VMIDs which are not managed by RM.
uint64_t
platform_get_peripheral_vmids(void);

error_t
platform_primary_vm_init(rm_env_data_t *env_data, uintptr_t log_buf,
			 size_t log_buf_size);

uint64_t
platform_get_os_boot_arg(vm_t *vm);

error_t
platform_rtc_set_time_base(cap_id_t rtc_cap, uint64_t time_base,
			   uint64_t sys_timer_ref);

error_t
platform_vrtc_attach_addrspace(cap_id_t rtc_cap, cap_id_t addrspace_cap);

bool
platform_has_vrtc_support(void);

bool
platform_has_vsmmu_v2_support(void);

cap_id_result_t
platform_vrtc_create_and_configure(cap_id_t p_cap, cap_id_t cs_cap,
				   vmaddr_t ipa);

bool
platform_has_watchdog_hlos_virtual_regs(void);

error_t
platform_pre_hlos_vm_init(const rm_env_data_t *env_data);
