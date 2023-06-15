// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define VM_CONFIG_IMAGE 0x56000009
#define VM_AUTH_IMAGE	0x5600000a
#define VM_INIT		0x5600000b

typedef struct {
	vmid_t	 target;
	uint16_t auth_type;

	resource_handle_t image_mp_handle;

	uint64_t image_offset;
	uint64_t image_size;
	uint64_t dt_offset;
	uint64_t dt_size;
} vm_config_image_req_t;

typedef struct {
	vmid_t		target;
	uint16_t	num_auth_params;
	vm_auth_param_t auth_params[];
} vm_auth_req_t;

typedef struct {
	vmid_t	 target;
	uint16_t res0;
} vm_init_req_t;
