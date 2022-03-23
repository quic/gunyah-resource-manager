
// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wgnu-empty-struct"

struct platform_vm_config {
};

#pragma clang diagnostic pop

typedef struct platform_vm_config platform_vm_config_t;

struct vm_config;
typedef struct vm_config vm_config_t;

struct vm_config_parser_data;
typedef struct vm_config_parser_data vm_config_parser_data_t;

error_t
platform_vm_config_create_vdevices(vm_config_t	       *vmcfg,
				   vm_config_parser_data_t *data);

error_t
platform_vm_config_hlos_vdevices_setup(vm_config_t *vmcfg);
