// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Parse vm config device tree node, and trigger visitors based on provided
// condition.

typedef struct {
	size_t addr_cells;
	size_t size_cells;
	size_t interrupt_cells;
} ctx_t;

typedef enum {
	BY_PATH,
	BY_STRING_PROP,
} listener_trigger_type_t;

typedef enum {
	RET_CONTINUE,
	RET_ERROR,
	RET_STOP,
} listener_return_t;

typedef listener_return_t (*action_t)(void *data, void *fdt, int node_ofs,
				      ctx_t *ctx);

typedef void *(*dtb_parser_data_alloc_t)(void);

typedef void (*dtb_parser_data_free_t)(void *data);

typedef struct {
	listener_trigger_type_t type;
	uint8_t			type_padding[4];

	char *expected_path;

	char *string_prop_name;
	char *expected_string;

	action_t action;
} dtb_listener_t;

struct dtb_parser_ops {
	dtb_parser_data_alloc_t alloc;

	dtb_listener_t *listeners;

	size_t listener_cnt;

	dtb_parser_data_free_t free;
};
typedef struct dtb_parser_ops dtb_parser_ops_t;

typedef struct {
	error_t err;
	uint8_t err_padding[4];

	void *r;
} dtb_parser_parse_dtb_ret_t;

dtb_parser_parse_dtb_ret_t
dtb_parser_parse_dtb(void *fdt, const dtb_parser_ops_t *ops);

// utilities

void
dtb_parser_update_ctx(void *fdt, int node_ofs, ctx_t *parent, ctx_t *child);

bool
fdt_match_strings(const char *strings, int lenp, const char *expect);

uint64_t
fdt_read_num(const fdt32_t *data, size_t cell_cnt);
