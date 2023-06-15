// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define RTC_IPA_SIZE 0x1000

error_t
handle_rtc(vm_config_t *vmcfg, vm_config_parser_data_t *data);

error_t
handle_rtc_teardown(vm_config_t *vmcfg, vdevice_node_t **node);
