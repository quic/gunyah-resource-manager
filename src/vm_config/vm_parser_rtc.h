// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef SRC_VM_PARSER_RTC_H_
#define SRC_VM_PARSER_RTC_H_

listener_return_t
parse_vrtc(vm_config_parser_data_t *vd, const void *fdt, int node_ofs,
	   const ctx_t *ctx);

#else

#error src/vm_config/vm_parser_rtc.h multiple include

#endif
