// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

RM_PADDED(struct platform_vm_config_parser_data { void *dummy; })

typedef struct platform_vm_config_parser_data platform_vm_config_parser_data_t;

rm_error_t
platform_alloc_parser_data(vm_config_parser_data_t *vd);

void
platform_free_parser_data(vm_config_parser_data_t *vd);
