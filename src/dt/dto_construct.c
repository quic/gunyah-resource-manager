// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>

#include <dt_overlay.h>

error_t
dto_construct_begin_path(dto_t *dto, const char *path)
{
	error_t ret = OK;

	char *target = strdup(path);
	if (target == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	const char separator = '/';

	assert(target[0] == separator);

	char *name_start = target + 1;

	assert(*name_start != '\0');

	CHECK_DTO(ret, dto_modify_begin_by_path(dto, "/"));

	char *name_end = NULL;
	do {
		name_end = strchr(name_start, (int32_t)separator);
		if (name_end == NULL) {
			break;
		}

		*name_end = '\0';

		ret = dto_node_begin(dto, name_start);
		if (ret != OK) {
			goto out;
		}

		name_start = name_end + 1;
	} while (name_end != NULL);

	// the generate should specify a node name
	// we can change it to return error latter
	assert(*name_start != '\0');

	// create the last node
	ret = dto_node_begin(dto, name_start);

out:
	free(target);
	return ret;
}

error_t
dto_construct_end_path(dto_t *dto, const char *path)
{
	error_t ret = OK;

	size_t sz = strlen(path);

	char *target = strdup(path);
	if (target == NULL) {
		ret = ERROR_NOMEM;
		goto out;
	}

	const char separator = '/';

	assert(target[0] == separator);

	// should have a node name
	assert(target[sz - 1] != '/');

	// remove the node name
	char *name_start = NULL;

	do {
		name_start = strrchr(target, (int32_t)separator);
		if (name_start == NULL) {
			break;
		}

		*name_start = '\0';

		ret = dto_node_end(dto, &name_start[1]);
		if (ret != OK) {
			goto out;
		}
	} while (name_start != NULL);

	CHECK_DTO(ret, dto_modify_end_by_path(dto, "/"));
out:
	free(target);
	return ret;
}
