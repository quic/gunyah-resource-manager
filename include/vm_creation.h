// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define MAX_CAPS    1024
#define GIC_SPI_NUM 988
#define GIC_LPI_NUM 8192

error_t
rm_vm_create(const rm_env_data_t *env_data);

error_t
hlos_vm_create(const rm_env_data_t *env_data);

error_t
hlos_vm_start(void);

rm_error_t
vm_creation_config_image(vm_t *vm, vm_auth_type_t auth,
			 resource_handle_t image_mp_handle,
			 uint64_t image_offset, uint64_t image_size,
			 uint64_t dt_offset, uint64_t dt_size);

typedef struct vm_auth_param {
	uint32_t auth_param_type;
	uint32_t auth_param;
} vm_auth_param_t;

rm_error_t
vm_creation_auth(vm_t *vm, count_t num_auth_params,
		 vm_auth_param_t *auth_params);

rm_error_t
vm_creation_init(vm_t *vm);

void
svm_takedown(vmid_t vmid);

void
svm_destroy(vmid_t vmid);

error_t
svm_create(vm_t *svm);

bool
vm_creation_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			void *buf, size_t len);

error_t
vm_creation_process_resource(vm_t *vm);

typedef struct memparcel memparcel_t;

error_t
vm_creation_process_memparcel(vm_t *vm, memparcel_t *mp);

uintptr_result_t
map_dtb(size_t dtb_offset, size_t dtb_size, uint32_t mp_handle,
	size_t ipa_size);

error_t
unmap_dtb(uint32_t mp_handle);

error_t
vm_creation_config_vm_info_area(vm_config_t *vmcfg);

error_t
vm_creation_map_vm_info_area(vm_config_t *vmcfg);

void
vm_creation_vm_info_area_teardown(vm_config_t *vmcfg);

bool
vm_reset_handle_cleanup(vm_t *vm);

bool
vm_reset_handle_destroy(vm_t *vm);
