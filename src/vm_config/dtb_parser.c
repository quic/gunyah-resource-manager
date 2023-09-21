// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <rm_types.h>
#include <util.h>
#include <utils/vector.h>

#include <regex.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <dtb_parser.h>

#define MAX_DEPTH    (16)
#define MAX_PATH_LEN (256)

#define DEFAULT_ADDR_CELLS (2)
#define DEFAULT_SIZE_CELLS (1)

static void
push_ctx(ctx_t ctxs[], int next_depth, const void *fdt, int node_ofs);

static void
pop_ctx(ctx_t ctxs[], int prev_depth, int cur_depth);

static listener_return_t
check_listeners(dtb_parser_data_t *data, const dtb_listener_t *listeners,
		size_t listener_cnt, const void *fdt, int node_ofs,
		const ctx_t *ctx);

static listener_return_t
check_path_listener(dtb_parser_data_t *data, const dtb_listener_t *listener,
		    const void *fdt, int node_ofs, const ctx_t *ctx);

static listener_return_t
check_strings_prop_listener(dtb_parser_data_t	 *data,
			    const dtb_listener_t *listener, const void *fdt,
			    int node_ofs, const ctx_t *ctx);

static listener_return_t
check_compatible_listener(dtb_parser_data_t    *data,
			  const dtb_listener_t *listener, const void *fdt,
			  int node_ofs, const ctx_t *ctx);

// FIXME: might define it in configuration
const char *gunyah_api_version = "1-0";

dtb_parser_parse_dtb_ret_t
dtb_parser_parse_dtb(const void *fdt, const dtb_parser_ops_t *ops,
		     const dtb_parser_alloc_params_t *params)
{
	dtb_parser_parse_dtb_ret_t ret = { .err = OK };

	assert(fdt != NULL);
	assert(fdt_check_header(fdt) == 0);

	// alloc data for return
	assert(ops->alloc != NULL);
	dtb_parser_data_t *data = ops->alloc(params);
	if (data == NULL) {
		ret.err = ERROR_NOMEM;
		goto out;
	}

	ret.r = data;

	ctx_t ctxs[MAX_DEPTH];
	(void)memset(ctxs, 0, sizeof(ctxs));

	// start from vm_config, loop all subnodes
	int cur_depth = 0;

	int cur_ofs = 0;

	// init ctx for root node
	push_ctx(ctxs, cur_depth, fdt, cur_ofs);

	// NOTE: the parsing order is the same as device node defined, so if a
	// device node is used before definition, we will get undefined issue.
	bool done = false;
	while (!done) {
		listener_return_t listener_ret =
			check_listeners(data, ops->listeners, ops->listener_cnt,
					fdt, cur_ofs, &ctxs[cur_depth]);
		if (listener_ret == RET_ERROR) {
			char path[MAX_PATH_LEN];
			int  path_ret =
				fdt_get_path(fdt, cur_ofs, path, sizeof(path));
			if (path_ret != 0) {
				strlcpy(path, "<unknown>", sizeof(path));
			}
			(void)printf("Fatal error in DTB parsing at node %s\n",
				     path);
			ret.err = ERROR_FAILURE;
			done	= true;
		} else if (listener_ret == RET_STOP) {
			done = true;
		} else {
			int next_depth = cur_depth;

			cur_ofs = fdt_next_node(fdt, cur_ofs, &next_depth);
			if (cur_ofs < 0) {
				ret.err = ERROR_DENIED;
				done	= true;
			} else if (next_depth < 0) {
				done = true;
			} else {
				if (next_depth == cur_depth + 1) {
					push_ctx(ctxs, next_depth, fdt,
						 cur_ofs);
				} else if (next_depth < cur_depth) {
					pop_ctx(ctxs, cur_depth, next_depth);
				} else {
					assert(next_depth == cur_depth);
				}

				cur_depth = next_depth;
			}
		}
	}
out:
	return ret;
}

error_t
dtb_parser_free(const dtb_parser_ops_t *ops, dtb_parser_data_t *data)
{
	assert(ops != NULL);
	assert(data != NULL);

	ops->free(data);

	return OK;
}

static bool
ranges_are_direct(const void *fdt, int node_ofs, const ctx_t *ctx)
{
	bool	       is_direct;
	int	       ranges_len;
	const fdt32_t *ranges = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "ranges", &ranges_len);
	if (ranges == NULL) {
		is_direct = false;
	} else {
		is_direct	    = true;
		count_t range_cells = ctx->child_addr_cells + ctx->addr_cells +
				      ctx->child_size_cells;
		count_t ranges_count =
			(count_t)((size_t)ranges_len / sizeof(uint32_t)) /
			range_cells;

		if ((size_t)ranges_len !=
		    (ranges_count * range_cells * sizeof(uint32_t))) {
			char path[MAX_PATH_LEN];
			if (fdt_get_path(fdt, node_ofs, path, sizeof(path)) !=
			    0) {
				strlcpy(path, "<unknown path>", sizeof(path));
			}
			(void)printf(
				"Warning: ignoring extra data in ranges property of node %s\n",
				path);
		}

		for (index_t i = 0U; i < ranges_count; i++) {
			const fdt32_t *range = &ranges[i * range_cells];

			uint64_t range_parent_addr =
				fdt_read_num(range, ctx->child_addr_cells);
			uint64_t range_child_addr = fdt_read_num(
				&range[ctx->child_addr_cells], ctx->addr_cells);

			if (range_parent_addr != range_child_addr) {
				is_direct = false;
				break;
			}
		}
	}

	return is_direct;
}

void
dtb_parser_update_ctx(const void *fdt, int node_ofs, const ctx_t *parent,
		      ctx_t *child)
{
	// Determine the address property parameters for this node
	if (parent == NULL) {
		// Root node shouldn't need these and has no standard way to
		// define them; set them to defaults
		child->addr_cells   = DEFAULT_ADDR_CELLS;
		child->size_cells   = DEFAULT_SIZE_CELLS;
		child->addr_is_phys = true;
	} else {
#if 0
		if (parent->child_cells_default) {
			// The parent failed to define address-cells and/or
			// size-cells, contrary to the DT spec
			char path[MAX_PATH_LEN];
			if (fdt_get_path(fdt, node_ofs, path, sizeof(path)) !=
			    OK) {
				strlcpy(path, "<unknown path>", sizeof(path));
			}
			(void)printf("Warning: node %s using default #*-cells!\n",
			       path);
		}
#endif

		child->addr_cells   = parent->child_addr_cells;
		child->size_cells   = parent->child_size_cells;
		child->addr_is_phys = parent->child_addr_is_phys;
	}

	// Determine the address and size cells for children of this node
	child->child_cells_default = false;

	if (fdt_getprop_u32(fdt, node_ofs, "#address-cells",
			    &child->child_addr_cells) != OK) {
		child->child_addr_cells	   = DEFAULT_ADDR_CELLS;
		child->child_cells_default = true;
	}

	if (fdt_getprop_u32(fdt, node_ofs, "#size-cells",
			    &child->child_size_cells) != OK) {
		child->child_size_cells	   = DEFAULT_SIZE_CELLS;
		child->child_cells_default = true;
	}

	// Determine whether this node's children are physically addressed
	if (parent == NULL) {
		// Root node's children are always physically addressed
		child->child_addr_is_phys = true;
	} else if (!child->addr_is_phys) {
		// This node's addresses aren't physical, so its children's
		// can't be physical either
		child->child_addr_is_phys = false;
	} else {
		// Read the ranges property to determine whether addresses are
		// 1:1 mapped
		child->child_addr_is_phys =
			ranges_are_direct(fdt, node_ofs, child);
	}
}

ctx_t
dtb_parser_get_ctx(const void *fdt, int node_ofs)
{
	struct {
		int   ofs;
		ctx_t ctx;
	} stack[8] = { 0 };

	stack[0].ofs = node_ofs;
	index_t i    = 0U;
	for (i = 0U; i < util_array_size(stack) - 1U; i++) {
		if (stack[i].ofs == 0) {
			break;
		}
		stack[i + 1U].ofs = fdt_parent_offset(fdt, stack[i].ofs);
		if (stack[i + 1U].ofs < 0) {
			(void)printf(
				"Warning: can't find parent of node @ %d (%d)\n",
				stack[i].ofs, stack[i + 1U].ofs);
			goto out;
		}
	}

	if (stack[i].ofs != 0) {
		(void)printf("Warning: node @ %d has depth > %zd\n", node_ofs,
			     util_array_size(stack));
	}

	ctx_t *parent = NULL;
	for (; i < util_array_size(stack); i--) {
		dtb_parser_update_ctx(fdt, stack[i].ofs, parent, &stack[i].ctx);
		parent = &stack[i].ctx;
	}

out:
	return stack[0].ctx;
}

static void
push_ctx(ctx_t ctxs[], int next_depth, const void *fdt, int node_ofs)
{
	assert(next_depth < MAX_DEPTH);
	assert(next_depth >= 0);

	ctx_t *child = &ctxs[next_depth];

	ctx_t *parent = NULL;
	if (next_depth > 0) {
		parent = &ctxs[next_depth - 1];
	}

	// parse/update context if there's any
	dtb_parser_update_ctx(fdt, node_ofs, parent, child);
}

static void
pop_ctx(ctx_t ctxs[], int prev_depth, int cur_depth)
{
	assert(prev_depth >= 0);
	assert(cur_depth >= 0);

	int d = prev_depth;
	while (d > cur_depth) {
		(void)memset(&ctxs[d], 0, sizeof(ctxs[d]));
		d--;
	}
}

static listener_return_t
check_listeners(dtb_parser_data_t *data, const dtb_listener_t *listeners,
		size_t listener_cnt, const void *fdt, int node_ofs,
		const ctx_t *ctx)
{
	listener_return_t act = RET_CONTINUE;

	for (index_t i = 0; i < listener_cnt; ++i) {
		const dtb_listener_t *cur_listener = listeners + i;

		if (cur_listener->type == BY_PATH) {
			act = check_path_listener(data, cur_listener, fdt,
						  node_ofs, ctx);
		} else if (cur_listener->type == BY_STRING_PROP) {
			act = check_strings_prop_listener(data, cur_listener,
							  fdt, node_ofs, ctx);
		} else if (cur_listener->type == BY_COMPATIBLE) {
			act = check_compatible_listener(data, cur_listener, fdt,
							node_ofs, ctx);
		} else {
			act = RET_CONTINUE;
		}
		if (act != RET_CONTINUE) {
			break;
		}
	}

	return act;
}

static listener_return_t
check_path_listener(dtb_parser_data_t *data, const dtb_listener_t *listener,
		    const void *fdt, int node_ofs, const ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	char path[MAX_PATH_LEN];
	int  path_ret = fdt_get_path(fdt, node_ofs, path, MAX_PATH_LEN);
	if (path_ret != 0) {
		ret = RET_ERROR;
		goto out_get_path_failure;
	}

	regex_t regex;
	int	reg_ret = regcomp(&regex, listener->expected_path,
				  REG_NOSUB | REG_EXTENDED);
	if (reg_ret != 0) {
		ret = RET_ERROR;
		goto out_regcomp_failure;
	}

	reg_ret = regexec(&regex, path, 0, NULL, 0);
	if (reg_ret == 0) {
		// match
		ret = listener->action(data, fdt, node_ofs, ctx);
	} else if (reg_ret == REG_NOMATCH) {
		ret = RET_CONTINUE;
	} else {
		ret = RET_ERROR;
	}

	regfree(&regex);

out_regcomp_failure:
out_get_path_failure:
	return ret;
}

static listener_return_t
check_strings_prop_listener(dtb_parser_data_t	 *data,
			    const dtb_listener_t *listener, const void *fdt,
			    int node_ofs, const ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	if (fdt_stringlist_search(fdt, node_ofs, listener->string_prop_name,
				  listener->expected_string) >= 0) {
		ret = listener->action(data, fdt, node_ofs, ctx);
	}

	return ret;
}

static listener_return_t
check_compatible_listener(dtb_parser_data_t    *data,
			  const dtb_listener_t *listener, const void *fdt,
			  int node_ofs, const ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	int fdt_ret = fdt_node_check_compatible(fdt, node_ofs,
						listener->compatible_string);

	if (fdt_ret == 0) {
		// match
		ret = listener->action(data, fdt, node_ofs, ctx);
	} else {
		ret = RET_CONTINUE;
	}

	return ret;
}

uint64_t
fdt_read_num(const fdt32_t *data, size_t cell_cnt)
{
	// only support 32 or 64 bits num
	assert(cell_cnt <= 2);

	uint64_t ret = 0;
	for (index_t i = 0; i < cell_cnt; ++i) {
		ret = (ret << 32) | fdt32_to_cpu(*data);
		++data;
	}

	return ret;
}

error_t
fdt_getprop_u32(const void *fdt, int node_ofs, const char *propname,
		uint32_t *val)
{
	error_t	       ret;
	int	       len;
	const fdt32_t *prop = fdt_getprop(fdt, node_ofs, propname, &len);
	if (prop == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
	} else if ((size_t)len != sizeof(fdt32_t)) {
		ret = ERROR_FAILURE;
	} else {
		ret = OK;
		if (val != NULL) {
			*val = fdt32_to_cpu(*prop);
		}
	}

	return ret;
}

error_t
fdt_getprop_s32(const void *fdt, int node_ofs, const char *propname,
		int32_t *val)
{
	error_t	       ret;
	int	       len;
	const fdt32_t *prop = fdt_getprop(fdt, node_ofs, propname, &len);
	if (prop == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
	} else if ((size_t)len != sizeof(fdt32_t)) {
		ret = ERROR_FAILURE;
	} else {
		ret = OK;
		if (val != NULL) {
			*val = (int32_t)fdt32_to_cpu(*prop);
		}
	}

	return ret;
}

error_t
fdt_getprop_u64(const void *fdt, int node_ofs, const char *propname,
		uint64_t *val)
{
	error_t	       ret;
	int	       len;
	const fdt64_t *prop = fdt_getprop(fdt, node_ofs, propname, &len);
	if (prop == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
	} else if ((size_t)len != sizeof(fdt64_t)) {
		ret = ERROR_FAILURE;
	} else {
		ret = OK;
		if (val != NULL) {
			*val = fdt64_to_cpu(*prop);
		}
	}

	return ret;
}

error_t
fdt_getprop_u32_array(const void *fdt, int node_ofs, const char *propname,
		      uint32_t *array, size_t array_size, count_t *count)
{
	error_t ret;

	int	       len;
	const fdt32_t *data = fdt_getprop(fdt, node_ofs, propname, &len);

	if (data == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
	} else if ((size_t)len > array_size) {
		(void)printf(
			"Error: array property \"%s\" length %zd exceeds expected size %zd\n",
			propname, (size_t)len, array_size);
		ret = ERROR_ARGUMENT_SIZE;
	} else if ((size_t)len % sizeof(fdt32_t) != 0U) {
		(void)printf(
			"Error: array property \"%s\" has misaligned size %zd\n",
			propname, (size_t)len);
		ret = ERROR_FAILURE;
	} else {
		index_t i;
		for (i = 0; i < ((size_t)len / sizeof(fdt32_t)); ++i) {
			array[i] = fdt32_to_cpu(*(data + i));
		}
		if (count != NULL) {
			*count = i;
		}
		ret = OK;
	}

	return ret;
}

error_t
fdt_getprop_num(const void *fdt, int node_ofs, const char *propname,
		count_t cells, uint64_t *val)
{
	error_t ret;

	int	       len;
	const fdt32_t *data = fdt_getprop(fdt, node_ofs, propname, &len);

	if (data == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
	} else if ((cells != 1U) && (cells != 2U)) {
		ret = ERROR_ARGUMENT_SIZE;
	} else if ((size_t)len != (cells * sizeof(fdt32_t))) {
		ret = ERROR_FAILURE;
	} else {
		ret = OK;
		if (val != NULL) {
			*val = fdt_read_num(data, cells);
		}
	}

	return ret;
}

bool
fdt_getprop_bool(const void *fdt, int node_ofs, const char *propname)
{
	return fdt_getprop(fdt, node_ofs, propname, NULL) != NULL;
}
