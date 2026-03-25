// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <rm_types.h>
#include <util.h>
#include <utils/vector.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#include <libfdt.h>
#pragma clang diagnostic pop

#include <dtb_parser.h>
#include <dtb_parser_listener.h>
#include <guest_interface.h>
#include <platform.h>
#include <resource-manager.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>

#define MAX_DEPTH    (16)
#define MAX_PATH_LEN (256)

#define DEFAULT_ADDR_CELLS (2)
#define DEFAULT_SIZE_CELLS (1)

static void
dtb_parser_update_ctx_child(const void *fdt, int node_ofs, ctx_t *ctx,
			    bool is_root_node);

static error_t
push_ctx(ctx_t ctxs[], int next_depth, const void *fdt, int node_ofs,
	 const char *parent_name);

static void
pop_ctx(ctx_t ctxs[], int prev_depth, int cur_depth);

static listener_return_t
check_listeners(dtb_parser_data_t *data, dtb_listener_t *listeners,
		size_t listener_cnt, const void *fdt, int node_ofs,
		const ctx_t *ctx, const char *path, bool tainted_source);

static listener_return_t
check_path_listener(dtb_parser_data_t *data, dtb_listener_t *listener,
		    const void *fdt, int node_ofs, const ctx_t *ctx,
		    const char *path);

static listener_return_t
check_strings_prop_listener(dtb_parser_data_t	 *data,
			    const dtb_listener_t *listener, const void *fdt,
			    int node_ofs, const ctx_t *ctx);

static listener_return_t
check_compatible_listener(dtb_parser_data_t *data, dtb_listener_t *listener,
			  const void *fdt, int node_ofs, const ctx_t *ctx);

static char *
make_new_path(const char *path, const char *node, bool append_path_sep);

static char *
make_new_path(const char *path, const char *node, bool append_path_sep)
{
	char  *out_path;
	size_t name_size, str_size;

	out_path = NULL;
	str_size = strnlen(path, MAX_PATH_LEN);
	if (str_size == (size_t)MAX_PATH_LEN) {
		goto out;
	}
	name_size = str_size;

	str_size = strnlen(node, MAX_PATH_LEN);
	if (str_size == (size_t)MAX_PATH_LEN) {
		goto out;
	}
	name_size += str_size;

	if (append_path_sep) {
		name_size += (size_t)2;
	} else {
		name_size += (size_t)1;
	}

	out_path = calloc(1, name_size);
	if (out_path == NULL) {
		goto out;
	}

	(void)strlcpy(out_path, path, name_size);
	(void)strlcat(out_path, node, name_size);
	if (append_path_sep) {
		(void)strlcat(out_path, "/", name_size);
	}
out:
	return out_path;
}

RM_PADDED(typedef struct {
	error_t err;
	bool	done;
} skip_to_next_node_ret_t)

static skip_to_next_node_ret_t
move_to_next_node(const void *fdt, int *cur_ofs_ptr, ctx_t ctxs[],
		  int *cur_depth_ptr, const char *node_name,
		  bool skip_child_nodes, int skip_to_depth)
{
	skip_to_next_node_ret_t ret	    = { .err = OK };
	bool			done	    = false;
	const char	       *parent_name = node_name;
	int			cur_ofs;
	int			cur_depth;
	int			next_depth;

	assert(cur_ofs_ptr != NULL);
	assert(cur_depth_ptr != NULL);

	cur_ofs	   = *cur_ofs_ptr;
	cur_depth  = *cur_depth_ptr;
	next_depth = cur_depth;

	do {
		cur_ofs = fdt_next_node(fdt, cur_ofs, &next_depth);
		if (cur_ofs < 0) {
			ret.err = ERROR_DENIED;
			done	= true;
		} else if (next_depth < 0) {
			pop_ctx(ctxs, cur_depth, 0);
			done = true;
		} else if (!skip_child_nodes) {
			error_t perr = OK;
			if (next_depth == (cur_depth + 1)) {
				perr = push_ctx(ctxs, next_depth, fdt, cur_ofs,
						parent_name);
			} else {
				if (next_depth < cur_depth) {
					pop_ctx(ctxs, cur_depth, next_depth);
				} else {
					assert(next_depth == cur_depth);
				}

				dtb_parser_update_ctx_child(fdt, cur_ofs,
							    &ctxs[next_depth],
							    next_depth == 0);
			}

			if (perr != OK) {
				pop_ctx(ctxs, cur_depth, 0);
				ret.err = ERROR_FAILURE;
				goto out;
			}
		} else if (next_depth < cur_depth) {
			pop_ctx(ctxs, cur_depth, next_depth);
		} else {
			// Skipping this node, nothing to do
		}
		cur_depth = next_depth;

		if (skip_child_nodes && (next_depth <= skip_to_depth)) {
			dtb_parser_update_ctx_child(fdt, cur_ofs,
						    &ctxs[next_depth],
						    next_depth == 0);
			break;
		}

	} while (!done && skip_child_nodes);
out:
	*cur_ofs_ptr   = cur_ofs;
	*cur_depth_ptr = cur_depth;
	ret.done       = done;
	return ret;
}

// FIXME: might define it in configuration
const char *gunyah_api_version = "1-0";

error_t
dtb_parser_parse_dtb(const void *fdt, const dtb_parser_ops_t *ops,
		     dtb_parser_data_t *data, bool tainted_source)
{
	error_t ret;

	assert(fdt != NULL);
	assert(fdt_check_header(fdt) == 0);

	ctx_t ctxs[MAX_DEPTH], *cur_ctxt;
	(void)memset(ctxs, 0, sizeof(ctxs));

	// start from vm_config, loop all subnodes
	int cur_depth = 0;

	int  cur_ofs	      = 0;
	bool skip_child_nodes = false;
	int  skip_to_depth    = 0;

	// init ctx for root node
	error_t perr = push_ctx(ctxs, cur_depth, fdt, cur_ofs, "");
	if (perr != OK) {
		ret = ERROR_FAILURE;
		goto out;
	}

	// NOTE: the parsing order is the same as device node defined, so if a
	// device node is used before definition, we will get undefined issue.
	bool done = false;
	do {
		const char *node_name;
		char	   *node_path;

		cur_ctxt  = &ctxs[cur_depth];
		node_name = fdt_get_name(fdt, cur_ofs, NULL);

		node_path = make_new_path(cur_ctxt->parent_path, node_name,
					  cur_depth == 0);
		if (node_path == NULL) {
			ret  = ERROR_FAILURE;
			done = true;
			break;
		}

		skip_child_nodes	       = false;
		cur_ctxt->node_path	       = node_path;
		listener_return_t listener_ret = check_listeners(
			data, ops->listeners, ops->listener_cnt, fdt, cur_ofs,
			cur_ctxt, node_path, tainted_source);

		if (listener_ret == RET_SKIP_CHILD_NODES) {
			skip_child_nodes = true;
			skip_to_depth	 = cur_depth;
		}
		free(node_path);

		if (listener_ret == RET_ERROR) {
			char path[MAX_PATH_LEN];
			int  path_ret = fdt_get_path(fdt, cur_ofs, path,
						     (int32_t)sizeof(path));
			if (path_ret != 0) {
				(void)strlcpy(path, "<unknown>", sizeof(path));
			}
			(void)printf("Fatal error in DTB parsing at node %s\n",
				     path);
			ret  = ERROR_FAILURE;
			done = true;
		} else if (listener_ret == RET_STOP) {
			ret  = OK;
			done = true;
		} else {
			skip_to_next_node_ret_t skip_ret;
			skip_ret = move_to_next_node(fdt, &cur_ofs, ctxs,
						     &cur_depth, node_name,
						     skip_child_nodes,
						     skip_to_depth);
			ret	 = skip_ret.err;
			done	 = skip_ret.done;
		}
	} while (!done);

	if (cur_depth > 0) {
		pop_ctx(ctxs, cur_depth, 0);
	}

	free(ctxs[0].parent_path);
out:
	return ret;
}

static bool
ranges_are_direct(const void *fdt, int node_ofs, const ctx_t *ctx)
{
	bool is_direct;

	// If there are too many address cells or size cells to parse into a
	// uint64_t, we just assume that the ranges are not direct. In practice
	// this only happens for PCI buses, which have 3 address cells and are
	// not direct-mapped.
	if ((ctx->child_addr_cells > 2U) || (ctx->child_size_cells > 2U)) {
		is_direct = false;
		goto out;
	}

	int	       ranges_len;
	const fdt32_t *ranges = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "ranges", &ranges_len);
	if (ranges == NULL) {
		is_direct = false;
		goto out;
	}

	count_t range_cells =
		ctx->child_addr_cells + ctx->addr_cells + ctx->child_size_cells;
	count_t ranges_count =
		(count_t)((size_t)ranges_len / sizeof(uint32_t)) / range_cells;

	if ((size_t)ranges_len !=
	    ((size_t)ranges_count * (size_t)range_cells * sizeof(uint32_t))) {
		char path[MAX_PATH_LEN];
		if (fdt_get_path(fdt, node_ofs, path, (int32_t)sizeof(path)) !=
		    0) {
			(void)strlcpy(path, "<unknown path>", sizeof(path));
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
			goto out;
		}
	}
	is_direct = true;

out:
	return is_direct;
}

static void
dtb_parser_update_ctx_child(const void *fdt, int node_ofs, ctx_t *ctx,
			    bool is_root_node)
{
	// Determine the address and size cells for children of this node
	ctx->child_addr_cells_default = false;
	ctx->child_size_cells_default = false;

	if (fdt_getprop_u32(fdt, node_ofs, "#address-cells",
			    &ctx->child_addr_cells) != OK) {
		ctx->child_addr_cells	      = DEFAULT_ADDR_CELLS;
		ctx->child_addr_cells_default = true;
	}

	if (fdt_getprop_u32(fdt, node_ofs, "#size-cells",
			    &ctx->child_size_cells) != OK) {
		ctx->child_size_cells	      = DEFAULT_SIZE_CELLS;
		ctx->child_size_cells_default = true;
	}

	// Determine whether this node's children are physically addressed
	if (is_root_node) {
		// Root node's children are always physically addressed
		ctx->child_addr_is_phys = true;
	} else if (!ctx->addr_is_phys) {
		// This node's addresses aren't physical, so its children's
		// can't be physical either
		ctx->child_addr_is_phys = false;
	} else {
		// Read the ranges property to determine whether addresses are
		// 1:1 mapped
		ctx->child_addr_is_phys = ranges_are_direct(fdt, node_ofs, ctx);
	}
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
		if (parent->child_addr_cells_default || parent->child_size_cells_default) {
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

	dtb_parser_update_ctx_child(fdt, node_ofs, child, parent == NULL);
}

ctx_t
dtb_parser_get_ctx(const void *fdt, int node_ofs)
{
	struct {
		int	ofs;
		uint8_t padding[4];
		ctx_t	ctx;
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

static error_t
push_ctx(ctx_t ctxs[], int next_depth, const void *fdt, int node_ofs,
	 const char *parent_name)
{
	error_t ret = OK;

	assert(next_depth < MAX_DEPTH);
	assert(next_depth >= 0);

	ctx_t *child = &ctxs[next_depth];
	assert(child->parent_path == NULL);

	ctx_t *parent = NULL;
	if (next_depth > 0) {
		parent = &ctxs[next_depth - 1];
	}

	char *parent_path = "";

	if (parent == NULL) {
		child->parent_path = calloc(1, 1);
		if (child->parent_path == NULL) {
			ret = ERROR_ARGUMENT_SIZE;
			goto out;
		}
	} else {
		char *node_path;

		parent_path = parent->parent_path;

		node_path = make_new_path(parent_path, parent_name, true);
		if (node_path == NULL) {
			(void)printf("Path construction failed\n");
			child->parent_path = NULL;
			ret		   = ERROR_ARGUMENT_SIZE;
			goto out;
		} else {
			child->parent_path = node_path;
		}
	}

	// parse/update context if there's any
	dtb_parser_update_ctx(fdt, node_ofs, parent, child);
out:
	return ret;
}

static void
pop_ctx(ctx_t ctxs[], int prev_depth, int cur_depth)
{
	assert(prev_depth >= 0);
	assert(cur_depth >= 0);

	int d = prev_depth;
	while (d > cur_depth) {
		if (ctxs[d].parent_path != NULL) {
			free(ctxs[d].parent_path);
		}
		(void)memset(&ctxs[d], 0, sizeof(ctxs[d]));
		d--;
	}
}

static listener_return_t
check_listeners(dtb_parser_data_t *data, dtb_listener_t *listeners,
		size_t listener_cnt, const void *fdt, int node_ofs,
		const ctx_t *ctx, const char *path, bool tainted_source)
{
	listener_return_t act = RET_CONTINUE;

	const char *status =
		fdt_stringlist_get(fdt, node_ofs, "status", 0, NULL);
	if ((status != NULL) &&
	    ((strcmp(status, "okay") != 0) || (strcmp(status, "ok") != 0))) {
		goto out;
	}

	for (index_t i = 0; i < listener_cnt; ++i) {
		dtb_listener_t *cur_listener = listeners + i;

		if (tainted_source && !cur_listener->safe) {
			// Listener isn't safe for tainted sources, skip it
			act = RET_CONTINUE;
		} else if (cur_listener->type == BY_PATH) {
			act = check_path_listener(data, cur_listener, fdt,
						  node_ofs, ctx, path);
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

out:
	return act;
}

static listener_return_t
check_path_listener(dtb_parser_data_t *data, dtb_listener_t *listener,
		    const void *fdt, int node_ofs, const ctx_t *ctx,
		    const char *path)
{
	listener_return_t ret = RET_CONTINUE;
	int		  reg_ret;

	if (listener->ctxt == NULL) {
		listener->ctxt = calloc(1, sizeof(*listener->ctxt));
		if (listener->ctxt == NULL) {
			ret = RET_ERROR;
			goto out_regcomp_failure;
		}

		reg_ret = regcomp(listener->ctxt, listener->expected_path,
				  (int)((uint32_t)REG_NOSUB |
					(uint32_t)REG_EXTENDED));
		if (reg_ret != 0) {
			ret = RET_ERROR;
			goto out_regcomp_failure;
		}
	}

	reg_ret = regexec(listener->ctxt, path, 0, NULL, 0);
	if (reg_ret == 0) {
		// match
		ret = listener->action(data, fdt, node_ofs, ctx);
	} else if (reg_ret == REG_NOMATCH) {
		ret = RET_CONTINUE;
	} else {
		ret = RET_ERROR;
	}

out_regcomp_failure:
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
check_compatible_listener(dtb_parser_data_t *data, dtb_listener_t *listener,
			  const void *fdt, int node_ofs, const ctx_t *ctx)
{
	listener_return_t ret;
	int		  reg_ret;

	const char *compatible =
		fdt_stringlist_get(fdt, node_ofs, "compatible", 0, NULL);
	if (compatible == NULL) {
		ret = RET_CONTINUE;
		goto out;
	}

	if (listener->ctxt == NULL) {
		listener->ctxt = calloc(1, sizeof(*listener->ctxt));
		if (listener->ctxt == NULL) {
			ret = RET_ERROR;
			goto out_regcomp_failure;
		}

		reg_ret = regcomp(listener->ctxt, listener->compatible_string,
				  (int)((uint32_t)REG_NOSUB |
					(uint32_t)REG_EXTENDED));
		if (reg_ret != 0) {
			ret = RET_ERROR;
			goto out_regcomp_failure;
		}
	}

	reg_ret = regexec(listener->ctxt, compatible, 0, NULL, 0);
	if (reg_ret == 0) {
		// match
		ret = listener->action(data, fdt, node_ofs, ctx);
	} else if (reg_ret == REG_NOMATCH) {
		ret = RET_CONTINUE;
	} else {
		ret = RET_ERROR;
	}

out_regcomp_failure:
out:
	return ret;
}

uint64_t
fdt_read_num(const fdt32_t *data, size_t cell_cnt)
{
	// only support 32 or 64 bits num
	assert(cell_cnt <= 2U);

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
	} else if (((size_t)len % sizeof(fdt32_t)) != 0U) {
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
