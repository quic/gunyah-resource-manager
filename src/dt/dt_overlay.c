// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dt_overlay.h>
#include <util.h>
#include <utils/list.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#pragma clang diagnostic ignored "-Wbad-function-cast"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wdocumentation-unknown-command"
#pragma clang diagnostic ignored "-Wextra-semi"
#pragma clang diagnostic ignored "-Wpadded"
#include <libfdt.h>
#pragma clang diagnostic pop

#define MAX_PATH  (512)
#define MAX_LEVEL (15)
#define MAX_RETRY (3)

#define DTB_START_SZ	 (PAGE_SIZE)
#define DTB_EXPAND_SZ	 (PAGE_SIZE)
#define DTB_ALIGNMENT	 (PAGE_SIZE)
#define PWD_SZ		 (MAX_PATH)
#define FRAGMENT_NAME_SZ (64)

#define ASSERT_RUN(fdt_func, err)                                              \
	do {                                                                   \
		int count = 0;                                                 \
		int ret	  = (fdt_func);                                        \
		assert((ret == -FDT_ERR_NOSPACE) || (ret == 0));               \
		if (ret == -FDT_ERR_NOSPACE) {                                 \
			err = expand(dto);                                     \
		} else {                                                       \
			break;                                                 \
		}                                                              \
		count++;                                                       \
		if (count > MAX_RETRY) {                                       \
			break;                                                 \
		}                                                              \
	} while (1)

typedef struct local_fixup_leaf {
	struct local_fixup_leaf *local_fixup_leaf_prev;
	struct local_fixup_leaf *local_fixup_leaf_next;

	char *label;

} local_fixup_leaf_t;

typedef struct local_fixup_node {
	struct local_fixup_node *local_fixup_node_prev;
	struct local_fixup_node *local_fixup_node_next;

	struct local_fixup_node *sub_nodes;

	local_fixup_leaf_t *leaves;

	char *name;

} local_fixup_node_t;

typedef struct fixup {
	struct fixup *fixup_prev;
	struct fixup *fixup_next;
	// referred label
	char *label;
	// who refer this label: [full_path:property_name:offset]
	char *who;
} fixup_t;

struct dto {
	// root pointer to device tree, may be update after resize.
	void *fdt;

	size_t fdt_sz;

	local_fixup_node_t *local_fixup_list;

	fixup_t *fixup_list;
	char	 pwd[PWD_SZ];

	bool	use_external_memory;
	uint8_t use_external_memory_pdding[3];

	// fragment count
	index_t fragment_count;
};

static const char *overlay_node_name	  = "__overlay__";
static const char *fixups_node_name	  = "__fixups__";
static const char *local_fixups_node_name = "__local_fixups__";

#ifdef DTBO_DEBUG
static bool debug = false;

static void
write_to_file(dto_t *dto, const char *file_name);
#endif

// Utility to help manager pwd
static void
enter_node(dto_t *dto, const char *node_name);

// Utility to help manager pwd
static void
leave_node(dto_t *dto);

static error_t
gen_fixups_node(dto_t *dto);

static error_t
add_local_fixup(dto_t *dto, const char *label);

static error_t
gen_local_fixups_node(dto_t *dto);

static void
free_local_fixups(dto_t *dto);

static error_t
expand(dto_t *dto)
{
	error_t e = OK;

	size_t expanded_sz = dto->fdt_sz + DTB_EXPAND_SZ;

	if (!dto->use_external_memory) {
		void *expanded_fdt = aligned_alloc(DTB_ALIGNMENT, expanded_sz);
		if (expanded_fdt == NULL) {
			e = ERROR_NOMEM;
			goto out;
		}

		memcpy(expanded_fdt, dto->fdt, dto->fdt_sz);

		free(dto->fdt);

		dto->fdt    = expanded_fdt;
		dto->fdt_sz = expanded_sz;
	} else {
		// cannot expand for external memory
		e = ERROR_NOMEM;
		goto out;
	}

	int error = fdt_resize(dto->fdt, dto->fdt, (int)dto->fdt_sz);
	(void)error;
	assert(error == 0);
out:
	return e;
}

dto_t *
dto_init(void *external_memory, size_t memory_size)
{
	error_t e = OK;

	dto_t *dto = calloc(1, sizeof(*dto));
	if (dto == NULL) {
		e = ERROR_NOMEM;
		goto err;
	}

	if (external_memory == NULL) {
		dto->fdt = malloc(DTB_START_SZ);
		if (dto->fdt == NULL) {
			e = ERROR_NOMEM;
			goto err1;
		}

		dto->fdt_sz = DTB_START_SZ;

		dto->use_external_memory = false;
	} else {
		dto->fdt = external_memory;

		if (memory_size > DTBO_MAX_SIZE) {
			e = ERROR_ARGUMENT_SIZE;
			goto err1;
		}

		if (util_add_overflows((uintptr_t)external_memory,
				       memory_size)) {
			e = ERROR_ADDR_OVERFLOW;
			goto err1;
		}
		dto->fdt_sz = memory_size;

		dto->use_external_memory = true;
	}

	dto->local_fixup_list = NULL;
	dto->fixup_list	      = NULL;

	(void)snprintf(dto->pwd, PWD_SZ, "/");

	dto->fragment_count = 0;

	// create the root node
	ASSERT_RUN(fdt_create(dto->fdt, (int)dto->fdt_sz), e);
	if (e != OK) {
		goto err1;
	}

	ASSERT_RUN(fdt_finish_reservemap(dto->fdt), e);
	if (e != OK) {
		goto err1;
	}

	ASSERT_RUN(fdt_begin_node(dto->fdt, ""), e);
	if (e != OK) {
		goto err1;
	}

	goto out;
err1:
	if (external_memory == NULL) {
		free(dto->fdt);
	}
	free(dto);
err:
	dto = NULL;
out:
	return dto;
}

error_t
dto_modify_begin(dto_t *dto, const char *target)
{
	// generate fragment name
	char fragment_name[FRAGMENT_NAME_SZ];

	int sz_ret = snprintf(fragment_name, FRAGMENT_NAME_SZ, "fragment@%u",
			      dto->fragment_count);

	(void)sz_ret;
	assert(sz_ret <= FRAGMENT_NAME_SZ);

	error_t e = OK;

	// create fragment node
	ASSERT_RUN(fdt_begin_node(dto->fdt, fragment_name), e);
	if (e != OK) {
		goto out;
	}
	enter_node(dto, fragment_name);

	// add external ref
	dto_property_ref_external(dto, "target", target);

	// create __overlay__ node
	ASSERT_RUN(fdt_begin_node(dto->fdt, overlay_node_name), e);
	if (e != OK) {
		leave_node(dto);
		goto out;
	}

	enter_node(dto, overlay_node_name);

	dto->fragment_count++;
out:
	return e;
}

error_t
dto_modify_end(dto_t *dto, const char *target)
{
	error_t e = OK;

	(void)target;

	// finish overlay_node
	ASSERT_RUN(fdt_end_node(dto->fdt), e);
	if (e != OK) {
		goto out;
	}

	leave_node(dto);

	// finish fragment node
	ASSERT_RUN(fdt_end_node(dto->fdt), e);
	if (e != OK) {
		goto out;
	}
	leave_node(dto);

out:
	return e;
}

error_t
dto_modify_begin_by_path(dto_t *dto, const char *target)
{
	error_t e = OK;

	// generate fragment name
	char fragment_name[FRAGMENT_NAME_SZ];

	int sz_ret = snprintf(fragment_name, FRAGMENT_NAME_SZ, "fragment@%u",
			      dto->fragment_count);

	(void)sz_ret;
	assert(sz_ret <= FRAGMENT_NAME_SZ);

	// create fragment node
	ASSERT_RUN(fdt_begin_node(dto->fdt, fragment_name), e);
	if (e != OK) {
		goto out;
	}

	enter_node(dto, fragment_name);

	// add external ref
	dto_property_add_string(dto, "target-path", target);

	// create __overlay__ node
	ASSERT_RUN(fdt_begin_node(dto->fdt, overlay_node_name), e);
	if (e != OK) {
		leave_node(dto);
		goto out;
	}

	enter_node(dto, overlay_node_name);

	dto->fragment_count++;
out:
	return e;
}

error_t
dto_modify_end_by_path(dto_t *dto, const char *target)
{
	(void)target;

	error_t e = OK;

	// finish overlay_node
	ASSERT_RUN(fdt_end_node(dto->fdt), e);
	if (e != OK) {
		goto err;
	}

	leave_node(dto);

	// finish fragment node
	ASSERT_RUN(fdt_end_node(dto->fdt), e);
	if (e != OK) {
		goto err;
	}

	leave_node(dto);

err:
	return e;
}

error_t
dto_node_begin(dto_t *dto, const char *node_name)
{
	error_t e = OK;

	ASSERT_RUN(fdt_begin_node(dto->fdt, node_name), e);
	if (e != OK) {
		goto err;
	}

	enter_node(dto, node_name);
err:
	return e;
}

error_t
dto_node_end(dto_t *dto, const char *name)
{
	error_t e = OK;

	(void)name;
	ASSERT_RUN(fdt_end_node(dto->fdt), e);
	if (e != OK) {
		goto err;
	}

	leave_node(dto);
err:
	return e;
}

error_t
dto_property_add_u32(dto_t *dto, const char *name, uint32_t val)
{
	error_t e = OK;
	ASSERT_RUN(fdt_property_u32(dto->fdt, name, val), e);
	return e;
}

error_t
dto_property_add_u64(dto_t *dto, const char *name, uint64_t val)
{
	error_t e = OK;
	ASSERT_RUN(fdt_property_u64(dto->fdt, name, val), e);
	return e;
}

error_t
dto_property_add_u32array(dto_t *dto, const char *name, uint32_t vals[],
			  count_t cnt)
{
	error_t	  e    = OK;
	size_t	  len  = sizeof(vals[0]) * cnt;
	uint32_t *conv = malloc(len);

	if (conv == NULL) {
		e = ERROR_NOMEM;
		goto err;
	}

	for (index_t i = 0; i < cnt; ++i) {
		conv[i] = cpu_to_fdt32(vals[i]);
	}

	ASSERT_RUN(fdt_property(dto->fdt, name, conv, (int)len), e);

	free(conv);
err:
	return e;
}

error_t
dto_property_add_u64array(dto_t *dto, const char *name, uint64_t vals[],
			  count_t cnt)
{
	error_t	  e    = OK;
	size_t	  len  = sizeof(vals[0]) * cnt;
	uint64_t *conv = malloc(len);

	if (conv == NULL) {
		e = ERROR_NOMEM;
		goto err;
	}

	for (index_t i = 0; i < cnt; ++i) {
		conv[i] = cpu_to_fdt64(vals[i]);
	}

	ASSERT_RUN(fdt_property(dto->fdt, name, conv, (int)len), e);

	free(conv);
err:
	return e;
}

error_t
dto_property_add_blob(dto_t *dto, const char *name, uint8_t vals[], count_t cnt)
{
	error_t e = OK;
	ASSERT_RUN(fdt_property(dto->fdt, name, vals, (int)cnt), e);
	return e;
}

error_t
dto_property_add_string(dto_t *dto, const char *name, const char *val)
{
	error_t e = OK;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
	ASSERT_RUN(fdt_property_string(dto->fdt, name, val), e);
#pragma clang diagnostic pop
	return e;
}

error_t
dto_property_add_stringlist(dto_t *dto, const char *name, const char *vals[],
			    count_t cnt)
{
	error_t e = OK;

	size_t	total_sz = 0;
	size_t *vals_sz	 = malloc(sizeof(*vals_sz) * cnt);

	if (vals_sz == NULL) {
		e = ERROR_NOMEM;
		goto err;
	}

	for (index_t i = 0; i < cnt; ++i) {
		vals_sz[i] = strlen(vals[i]) + 1;
		total_sz += vals_sz[i];
	}

	char *val = malloc(total_sz);
	if (val == NULL) {
		e = ERROR_NOMEM;
		goto err1;
	}

	char *cur = val;
	for (index_t i = 0; i < cnt; ++i) {
		memcpy(cur, vals[i], vals_sz[i]);
		cur += vals_sz[i];
	}

	ASSERT_RUN(fdt_property(dto->fdt, name, val, (int)total_sz), e);
	free(val);
err1:
	free(vals_sz);
err:
	return e;
}

error_t
dto_property_add_phandle(dto_t *dto, uint32_t *pphandle)
{
	// get a handle from libfdt
	uint32_t phandle = 0;

	error_t e = OK;
	ASSERT_RUN(fdt_generate_phandle(dto->fdt, &phandle), e);
	if (e != OK) {
		goto err;
	}
	dto_property_add_u32(dto, "phandle", phandle);

	*pphandle = phandle;
err:
	return e;
}

error_t
dto_property_add_addrrange(dto_t *dto, const char *name, size_t addr_cells,
			   uint64_t addr, size_t size_cells, uint64_t size)
{
	error_t	 e = OK;
	uint8_t *data;

	if ((addr_cells > 2) || (size_cells > 2)) {
		e = ERROR_ARGUMENT_INVALID;
		goto err;
	}

	ASSERT_RUN(fdt_property_placeholder(
			   dto->fdt, name,
			   (int)(sizeof(uint32_t) * (addr_cells + size_cells)),
			   (void **)&data),
		   e);
	if (e != OK) {
		goto err;
	}

	if (addr_cells == 2) {
		fdt64_st(data, addr);
	} else if (addr_cells == 1) {
		fdt32_st(data, (uint32_t)addr);
	}
	data += addr_cells * (sizeof(uint32_t) / sizeof(*data));

	if (size_cells == 2) {
		fdt64_st(data, size);
	} else if (size_cells == 1) {
		fdt32_st(data, (uint32_t)size);
	}
err:
	return e;
}

error_t
dto_property_ref_internal(dto_t *dto, const char *name, uint32_t phandle)
{
	error_t e = dto_property_add_u32(dto, name, phandle);
	if (e != OK) {
		goto out;
	}

	e = add_local_fixup(dto, name);
out:
	return e;
}

error_t
dto_property_ref_external(dto_t *dto, const char *property_name,
			  const char *target_label)
{
	error_t e = OK;

	// set target property
	ASSERT_RUN(fdt_property_u32(dto->fdt, property_name, 0xFFFFFFFF), e);
	if (e != OK) {
		goto out;
	}

	// add entry to fixup
	fixup_t *fixup = calloc(1, sizeof(*fixup));
	if (fixup == NULL) {
		e = ERROR_NOMEM;
		goto out;
	}

	fixup->label = strdup(target_label);
	if (fixup->label == NULL) {
		e = ERROR_NOMEM;
		goto err1;
	}

	const int who_sz = 256;
	char *	  who	 = malloc((size_t)who_sz);
	if (who == NULL) {
		e = ERROR_NOMEM;
		goto err2;
	}

	char path[MAX_PATH];

	// remove the last '/'
	size_t len = strlen(dto->pwd) - 1;
	memcpy(path, dto->pwd, len);
	path[len] = '\0';

	int fmt_ret = snprintf(who, who_sz, "%s:%s:0", path, property_name);
	(void)fmt_ret;
	assert(fmt_ret < who_sz);
	fixup->who = who;

	list_append(fixup_t, &dto->fixup_list, fixup, fixup_);

	goto out;
err2:
	free(fixup->label);
err1:
	free(fixup);
out:
	return e;
}

#ifdef DTBO_DEBUG
void
write_to_file(dto_t *dto, const char *file_name)
{
	size_t size = fdt_totalsize(dto->fdt);

	FILE *fp = fopen(file_name, "w");
	assert(fp != NULL);

	// simple write, might cause some issue for valgrind
	size_t ret_sz = fwrite(dto->fdt, size, 1, fp);
	assert(ret_sz == 1);

	fclose(fp);
}
#endif

error_t
dto_finalise(dto_t *dto)
{
	error_t e = OK;

	// add fixup node group
	e = gen_fixups_node(dto);
	if (e != OK) {
		goto err;
	}

	// add local fixups
	e = gen_local_fixups_node(dto);
	if (e != OK) {
		goto err;
	}

	// close the root node
	ASSERT_RUN(fdt_end_node(dto->fdt), e);
	if (e != OK) {
		goto err;
	}

	// end sequential writing
	ASSERT_RUN(fdt_finish(dto->fdt), e);
	if (e != OK) {
		goto err;
	}

#ifdef DTBO_DEBUG
	if (debug) {
		write_to_file(dto, "debug.dtbo");
	}
#endif
err:
	return e;
}

void
dto_deinit(dto_t *dto)
{
	// free fixup list
	fixup_t *fnext, *fcur;
	loop_list_safe(fcur, fnext, &dto->fixup_list, fixup_)
	{
		list_remove(fixup_t, &dto->fixup_list, fcur, fixup_);
		if (fcur->label != NULL) {
			free(fcur->label);
		}

		if (fcur->who != NULL) {
			free(fcur->who);
		}

		free(fcur);
	}

	// free all local fixups
	free_local_fixups(dto);

	if (dto->fdt != NULL) {
		free(dto->fdt);
		dto->fdt = NULL;
	}

	free(dto);
}

void
enter_node(dto_t *dto, const char *node_name)
{
	size_t pwd_len = strlen(dto->pwd);
	// need one more space for '/'
	size_t node_len = strlen(node_name) + 1;
	(void)pwd_len;
	(void)node_len;
	assert((pwd_len + node_len) < PWD_SZ);

	int fmt_ret = snprintf(dto->pwd + strlen(dto->pwd), node_len + 1, "%s/",
			       node_name);
	(void)fmt_ret;
	assert((size_t)fmt_ret == node_len);
}

void
leave_node(dto_t *dto)
{
	// might be done by double strrchr or strlen
	char *first = strrchr(dto->pwd, '/');
	assert(first != NULL);

	if (dto->pwd == first) {
		// top node done
		*dto->pwd = '\0';
		goto out;
	}

	// remove the first '/'
	*first = '\0';

	char *second = strrchr(dto->pwd, '/');
	assert(second != NULL);
	*(second + 1) = '\0';
out:
	return;
}

error_t
gen_fixups_node(dto_t *dto)
{
	error_t e = OK;

	ASSERT_RUN(fdt_begin_node(dto->fdt, fixups_node_name), e);
	if (e != OK) {
		goto out;
	}

	enter_node(dto, fixups_node_name);

	fixup_t *cur_fixup = NULL;
	loop_list(cur_fixup, &dto->fixup_list, fixup_)
	{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
		ASSERT_RUN(fdt_property_string(dto->fdt, cur_fixup->label,
					       cur_fixup->who),
			   e);

		if (e != OK) {
			goto err1;
		}
#pragma clang diagnostic pop
	}

err1:
	ASSERT_RUN(fdt_end_node(dto->fdt), e);

	leave_node(dto);
out:
	return e;
}

error_t
add_local_fixup(dto_t *dto, const char *label)
{
	error_t e	  = OK;
	char *	saved_ptr = NULL;

	char *cur_pwd = strdup(dto->pwd);
	if (cur_pwd == NULL) {
		e = ERROR_NOMEM;
		goto out;
	}

	// for each node in pwd
	const char *delim	  = "/";
	char *	    cur_node_name = strtok_r(cur_pwd, delim, &saved_ptr);
	if (cur_node_name == NULL) {
		e = ERROR_NOMEM;
		goto err1;
	}

	local_fixup_node_t * cur_node	   = NULL;
	local_fixup_node_t **cur_node_list = &dto->local_fixup_list;
	while (cur_node_name != NULL) {
		// allocate local fixup node if needed
		bool found = false;
		loop_list(cur_node, cur_node_list, local_fixup_node_)
		{
			if (strcmp(cur_node->name, cur_node_name) == 0) {
				found = true;
				break;
			}
		}

		if (found) {
			cur_node_list = &cur_node->sub_nodes;
		} else {
			cur_node = calloc(1, sizeof(*cur_node));
			if (cur_node == NULL) {
				e = ERROR_NOMEM;
				goto err1;
			}

			cur_node->name = strdup(cur_node_name);
			if (cur_node->name == NULL) {
				free(cur_node);
				e = ERROR_NOMEM;
				goto err1;
			}

			list_append(local_fixup_node_t, cur_node_list, cur_node,
				    local_fixup_node_);
			cur_node_list = &cur_node->sub_nodes;
		}

		// goto next node
		cur_node_name = strtok_r(NULL, delim, &saved_ptr);
	}

	// check if there's already a leaf with the same label in the same node
	local_fixup_leaf_t *cur_leaf = NULL;
	loop_list(cur_leaf, &cur_node->leaves, local_fixup_leaf_)
	{
		// it's invalid to use same label for nodes
		assert(strcmp(cur_leaf->label, label) != 0);
	}

	// allocate leaf and record label
	local_fixup_leaf_t *leaf = calloc(1, sizeof(*leaf));
	if (leaf == NULL) {
		e = ERROR_NOMEM;
		goto err1;
	}

	leaf->label = strdup(label);
	if (leaf->label == NULL) {
		e = ERROR_NOMEM;
		goto err2;
	}
	list_append(local_fixup_leaf_t, &cur_node->leaves, leaf,
		    local_fixup_leaf_);

	goto out;
err2:
	free(leaf);
err1:
out:
	free(cur_pwd);
	return e;
}

error_t
gen_local_fixups_node(dto_t *dto)
{
	index_t		    cur_level = 0;
	local_fixup_node_t *stack[MAX_LEVEL + 1], *cur_node;

	error_t e = OK;

	ASSERT_RUN(fdt_begin_node(dto->fdt, local_fixups_node_name), e);
	if (e != OK) {
		goto err;
	}

	// NOTE: dodgy code to remove recursive call
	// loop for nodes, create node
	cur_node = dto->local_fixup_list;
	while (cur_node != NULL) {
		// create fdt node for curr node
		ASSERT_RUN(fdt_begin_node(dto->fdt, cur_node->name), e);
		if (e != OK) {
			goto err;
		}

		// create property for curr node
		local_fixup_leaf_t *cur_leaf = NULL;
		loop_list(cur_leaf, &cur_node->leaves, local_fixup_leaf_)
		{
			ASSERT_RUN(fdt_property_u32(dto->fdt, cur_leaf->label,
						    0),
				   e);

			if (e != OK) {
				goto err;
			}
		}

		// if has sub node, push cur node to stack, change cur node to
		// cur_node, start loop sub nodes
		if (!is_empty(cur_node->sub_nodes)) {
			stack[cur_level] = cur_node;
			assert(cur_level < MAX_LEVEL);
			cur_level++;

			cur_node = cur_node->sub_nodes;
			continue;
		}

		// pop up to node which has next node to handle
		while (is_last(cur_node, local_fixup_node_) &&
		       (cur_level != 0)) {
			// close current node
			ASSERT_RUN(fdt_end_node(dto->fdt), e);
			if (e != OK) {
				goto err;
			}

			assert(cur_level != 0);
			cur_level--;
			cur_node = stack[cur_level];
		}

		ASSERT_RUN(fdt_end_node(dto->fdt), e);
		if (e != OK) {
			goto err;
		}

		cur_node = cur_node->local_fixup_node_next;
	}

	ASSERT_RUN(fdt_end_node(dto->fdt), e);
	if (e != OK) {
		goto err;
	}

err:
	return e;
}

void
free_local_fixups(dto_t *dto)
{
	index_t		    cur_level = 0;
	local_fixup_node_t *cur, *next;

	struct {
		local_fixup_node_t *cur;
		local_fixup_node_t *next;
	} stack[MAX_LEVEL + 1];

	// NOTE: dodgy code to remove recursive call
	cur  = dto->local_fixup_list;
	next = (cur != NULL) ? cur->local_fixup_node_next : NULL;
	while (cur != NULL) {
		if (cur->name) {
			free(cur->name);
		}

		// free leaves
		local_fixup_leaf_t *cur_leaf, *next_leaf;
		loop_list_safe(cur_leaf, next_leaf, &cur->leaves,
			       local_fixup_leaf_)
		{
			if (cur_leaf->label != NULL) {
				free(cur_leaf->label);
			}
			free(cur_leaf);
		}

		if (!is_empty(cur->sub_nodes)) {
			stack[cur_level].cur  = cur;
			stack[cur_level].next = next;

			assert(cur_level < MAX_LEVEL);
			cur_level++;

			cur  = cur->sub_nodes;
			next = (cur != NULL) ? cur->local_fixup_node_next
					     : NULL;
			continue;
		}

		// pop to an upper node which still has next node to free
		while (is_last(cur, local_fixup_node_) && cur_level != 0) {
			free(cur);

			assert(cur_level != 0);
			cur_level--;
			cur  = stack[cur_level].cur;
			next = stack[cur_level].next;
		}

		free(cur);

		cur  = next;
		next = (cur != NULL) ? cur->local_fixup_node_next : NULL;
	}
}

error_t
dto_property_add_empty(dto_t *dto, const char *name)
{
	error_t e = OK;

	ASSERT_RUN(fdt_property(dto->fdt, name, name, 0), e);
	return e;
}

void *
dto_get_dtbo(dto_t *dto)
{
	return dto->fdt;
}

size_t
dto_get_size(dto_t *dto)
{
	return dto->fdt_sz;
}
