// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Parse vm config device tree node, and trigger visitors based on provided
// condition.

RM_PADDED(typedef struct {
	count_t addr_cells;
	count_t size_cells;
	bool	addr_is_phys;

	count_t child_addr_cells;
	count_t child_size_cells;
	bool	child_addr_is_phys;
	bool	child_cells_default;
} ctx_t)

typedef enum {
	BY_PATH,
	BY_STRING_PROP,
	BY_COMPATIBLE,
} listener_trigger_type_t;

typedef enum {
	RET_CONTINUE,
	RET_ERROR,
	RET_STOP,
	RET_CLAIMED,
} listener_return_t;

struct dtb_parser_data_s;
typedef struct dtb_parser_data_s dtb_parser_data_t;
typedef listener_return_t (*action_t)(dtb_parser_data_t *data, const void *fdt,
				      int node_ofs, const ctx_t *ctx);

struct dtb_parser_alloc_params_s;
typedef struct dtb_parser_alloc_params_s dtb_parser_alloc_params_t;
typedef dtb_parser_data_t *(*dtb_parser_data_alloc_t)(
	const dtb_parser_alloc_params_t *params);

typedef void (*dtb_parser_data_free_t)(dtb_parser_data_t *data);

typedef struct {
	listener_trigger_type_t type;
	uint8_t			type_padding[4];

	union {
		char *expected_path;

		struct {
			char *string_prop_name;
			char *expected_string;
		};

		char *compatible_string;
	};

	action_t action;
} dtb_listener_t;

struct dtb_parser_ops {
	dtb_parser_data_alloc_t alloc;

	dtb_listener_t *listeners;

	size_t listener_cnt;

	dtb_parser_data_free_t free;
};
typedef struct dtb_parser_ops dtb_parser_ops_t;

RM_PADDED(typedef struct {
	error_t		   err;
	dtb_parser_data_t *r;
} dtb_parser_parse_dtb_ret_t)

dtb_parser_parse_dtb_ret_t
dtb_parser_parse_dtb(const void *fdt, const dtb_parser_ops_t *ops,
		     const dtb_parser_alloc_params_t *params);

error_t
dtb_parser_free(const dtb_parser_ops_t *ops, dtb_parser_data_t *data);

// utilities

void
dtb_parser_update_ctx(const void *fdt, int node_ofs, const ctx_t *parent,
		      ctx_t *child);

ctx_t
dtb_parser_get_ctx(const void *fdt, int node_ofs);

uint64_t
fdt_read_num(const fdt32_t *data, size_t cell_cnt);

error_t
fdt_getprop_u32(const void *fdt, int node_ofs, const char *propname,
		uint32_t *val);

error_t
fdt_getprop_s32(const void *fdt, int node_ofs, const char *propname,
		int32_t *val);

error_t
fdt_getprop_u64(const void *fdt, int node_ofs, const char *propname,
		uint64_t *val);

error_t
fdt_getprop_u32_array(const void *fdt, int node_ofs, const char *propname,
		      uint32_t *array, size_t array_size, count_t *count);

error_t
fdt_getprop_num(const void *fdt, int node_ofs, const char *propname,
		count_t cells, uint64_t *val);

bool
fdt_getprop_bool(const void *fdt, int node_ofs, const char *propname);
