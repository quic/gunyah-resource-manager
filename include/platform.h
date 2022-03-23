// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

struct vm;
typedef struct vm vm_t;

struct vm_config;
typedef struct vm_config vm_config_t;

struct vm_config_parser_data;
typedef struct vm_config_parser_data vm_config_parser_data_t;

void
uart_putc(const char c);

void
uart_write(const char *out, size_t size);

void
platform_uart_map(boot_env_data_t *env_data);

error_t
platform_hlos_create(cap_id_t hlos_as);

bool
platform_msg_callback(vmid_t vm_id, uint32_t msg_id, uint16_t seq_num,
		      void *buf, size_t len);

bool
platform_notif_callback(vmid_t vm_id, uint32_t notification_id, void *buf,
			size_t len);

error_t
platform_hlos_get_free_addr_range(vmaddr_t *base, size_t *size);

error_t
platform_config_handle_ids(vm_config_t *vmcfg, vm_config_parser_data_t *data);

bool
platform_get_security_state(void);

const char *
platform_get_sign_authority_string(uint32_t signer_info);

error_t
platform_init(boot_env_data_t *env_data);

error_t
platform_vm_create(vm_t *vm, bool hlos);

error_t
platform_vm_config_add(vm_config_t *vmcfg, vm_config_parser_data_t *data,
		       bool hlos);

void
platform_exit_handler(int exit_code);
