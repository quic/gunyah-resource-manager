// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

struct dtb_parser_data_s;
typedef struct dtb_parser_data_s vm_config_parser_data_t;

listener_return_t
platform_parse_interrupts(vm_config_parser_data_t *data, const void *fdt,
			  int node_ofs, const ctx_t *ctx);

listener_return_t
platform_parse_root(vm_config_parser_data_t *data, const void *fdt,
		    int node_ofs, const ctx_t *ctx);

// clang-format off
#define PLATFORM_LISTENERS                                                     \
	{                                                                      \
		.type	       = BY_PATH,                                      \
		.expected_path = "^/(qcom,|gunyah-)vm-config/interrupts$",     \
		.action	       = platform_parse_interrupts,                    \
	},                                                                     \
	{                                                                      \
		.type	       = BY_PATH,                                      \
		.expected_path = "^/$",                                        \
		.action	       = platform_parse_root,                          \
	},

// clang-format on

typedef struct platform_data {
	uintptr_t type;
	void	 *data;
} platform_data_t;
