// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <rm-rpc.h>

#include <regex.h>
#include <utils/vector.h>
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

#define DEFAULT_ADDR_CELLS	(2)
#define DEFAULT_SIZE_CELLS	(1)
#define DEFAULT_INTERRUPT_CELLS (2)

void
dtb_parser_update_ctx(void *fdt, int node_ofs, ctx_t *parent, ctx_t *child);

static void
push_ctx(ctx_t ctxs[], int next_depth, void *fdt, int node_ofs);

static void
pop_ctx(ctx_t ctxs[], int prev_depth, int cur_depth);

static listener_return_t
check_listeners(void *data, dtb_listener_t *listeners, size_t listener_cnt,
		void *fdt, int node_ofs, ctx_t *ctx);

static listener_return_t
check_path_listener(void *data, dtb_listener_t *listener, void *fdt,
		    int node_ofs, char path[], ctx_t *ctx);

static listener_return_t
check_strings_prop_listener(void *data, dtb_listener_t *listener, void *fdt,
			    int node_ofs, ctx_t *ctx);

// FIXME: might define it in configuration
const char *gunyah_api_version = "1-0";

dtb_parser_parse_dtb_ret_t
dtb_parser_parse_dtb(void *fdt, const dtb_parser_ops_t *ops)
{
	dtb_parser_parse_dtb_ret_t ret = { .err = OK };

	assert(fdt != NULL);
	assert(fdt_check_header(fdt) == 0);

	// alloc data for return
	assert(ops->alloc != NULL);
	void *data = ops->alloc();
	if (data == NULL) {
		ret.err = ERROR_NOMEM;
		goto out;
	}

	ret.r = data;

	ctx_t ctxs[MAX_DEPTH];
	memset(ctxs, 0, sizeof(ctxs));

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
					fdt, cur_ofs, ctxs);
		if (listener_ret == RET_ERROR) {
			ret.err = ERROR_DENIED;
			done	= true;
			break;
		} else if (listener_ret == RET_STOP) {
			done = true;
			break;
		}

		int next_depth = cur_depth;

		cur_ofs = fdt_next_node(fdt, cur_ofs, &next_depth);
		if (cur_ofs < 0) {
			ret.err = ERROR_DENIED;
			done	= true;
		} else if (next_depth < 0) {
			done = true;
		} else {
			if (next_depth == cur_depth + 1) {
				push_ctx(ctxs, next_depth, fdt, cur_ofs);
			} else if (next_depth < cur_depth) {
				pop_ctx(ctxs, cur_depth, next_depth);
			} else {
				assert(next_depth == cur_depth);
			}

			cur_depth = next_depth;
		}
	}
out:
	return ret;
}

void
dtb_parser_update_ctx(void *fdt, int node_ofs, ctx_t *parent, ctx_t *child)
{
	if (parent != NULL) {
		*child = *parent;
	} else {
		child->addr_cells      = DEFAULT_ADDR_CELLS;
		child->size_cells      = DEFAULT_SIZE_CELLS;
		child->interrupt_cells = DEFAULT_INTERRUPT_CELLS;
	}

	// check if there's override value
	int	       len	  = 0;
	const fdt32_t *addr_cells = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "#address-cells", &len);
	if (addr_cells != NULL) {
		child->addr_cells = fdt32_to_cpu(*addr_cells);
	}
	const fdt32_t *size_cells = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "#size-cells", &len);
	if (size_cells != NULL) {
		child->size_cells = fdt32_to_cpu(*size_cells);
	}
	const fdt32_t *irq_cells = (const fdt32_t *)fdt_getprop(
		fdt, node_ofs, "#interrupt-cells", &len);
	if (irq_cells != NULL) {
		child->interrupt_cells = fdt32_to_cpu(*irq_cells);
	}
}

void
push_ctx(ctx_t ctxs[], int next_depth, void *fdt, int node_ofs)
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

void
pop_ctx(ctx_t ctxs[], int prev_depth, int cur_depth)
{
	assert(prev_depth >= 0);
	assert(cur_depth >= 0);

	int d = prev_depth;
	while (d > cur_depth) {
		memset(&ctxs[d], 0, sizeof(ctxs[d]));
		d--;
	}
}

listener_return_t
check_listeners(void *data, dtb_listener_t *listeners, size_t listener_cnt,
		void *fdt, int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	char path[MAX_PATH_LEN];
	int  path_ret = fdt_get_path(fdt, node_ofs, path, MAX_PATH_LEN);
	if (path_ret != 0) {
		ret = RET_ERROR;
		goto out_get_path_failure;
	}

	for (index_t i = 0; i < listener_cnt; ++i) {
		dtb_listener_t *cur_listener = listeners + i;
		if (cur_listener->type == BY_PATH) {
			ret = check_path_listener(data, cur_listener, fdt,
						  node_ofs, path, ctx);
		} else if (cur_listener->type == BY_STRING_PROP) {
			ret = check_strings_prop_listener(data, cur_listener,
							  fdt, node_ofs, ctx);
		}
	}

out_get_path_failure:
	return ret;
}

listener_return_t
check_path_listener(void *data, dtb_listener_t *listener, void *fdt,
		    int node_ofs, char path[], ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	regex_t regex;

	int reg_ret = regcomp(&regex, listener->expected_path, REG_NOSUB);
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
	return ret;
}

listener_return_t
check_strings_prop_listener(void *data, dtb_listener_t *listener, void *fdt,
			    int node_ofs, ctx_t *ctx)
{
	listener_return_t ret = RET_CONTINUE;

	int lenp = 0;

	const void *val = fdt_getprop_namelen(
		fdt, node_ofs, listener->string_prop_name,
		(int)strlen(listener->string_prop_name), &lenp);
	if (val == NULL) {
		goto out;
	}

	bool found = fdt_match_strings(val, lenp, listener->expected_string);
	if (found) {
		// match
		ret = listener->action(data, fdt, node_ofs, ctx);
	} else {
		ret = RET_CONTINUE;
	}
out:
	return ret;
}

bool
fdt_match_strings(const char *strings, int lenp, const char *expect)
{
	bool ret = false;

	const char *cur_s = strings;

	int rest_len = lenp;

	while (rest_len > 0) {
		size_t cur_len = strlen(cur_s);

		bool with_version = false;

		// check if contains version, if so, set flag to ignore version
		size_t api_len = strlen(gunyah_api_version);

		if ((cur_len > api_len) && (strcmp(cur_s + (cur_len - api_len),
						   gunyah_api_version) == 0)) {
			with_version = true;
		}

		if (with_version) {
			// remove '-' also
			size_t len = cur_len - api_len - 1;
			ret	   = strncmp(cur_s, expect, len) == 0;
		} else {
			ret = strcmp(cur_s, expect) == 0;
		}

		rest_len -= cur_len + 1;
		assert(rest_len >= 0);

		if (ret || (rest_len == 0)) {
			break;
		} else {
			cur_s += cur_len + 1;
		}
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
