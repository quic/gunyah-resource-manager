// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause
#include <guest_types.h>

#include <assert.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>
#include <utils/guid_parser.h>

#include <errno.h>

#define GUID_STR_LEN_MIN (VM_GUID_LEN * 2U)

error_t
parse_guid_string(const char *guid_string, uint8_t (*guid)[VM_GUID_LEN])
{
	error_t ret;
	char	temp_guid[GUID_STR_LEN_MIN]; // Not NUL terminated
	index_t i;

	// Support up to 4 hyphens max
	size_t len = strnlen(guid_string, GUID_STR_LEN_MIN + 5U);

	if ((len < GUID_STR_LEN_MIN) || (len == (GUID_STR_LEN_MIN + 5U))) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	// Initialization below is too complex for static analysis, do it here.
	(void)memset(temp_guid, 0, sizeof(temp_guid));

	// Strip the hyphens and validate
	// No support for curly braces enclosed GUID currently.
	index_t guid_len = 0U;
	for (i = 0U; i < (index_t)len; i++) {
		if (guid_string[i] != '-') {
			if (guid_len == GUID_STR_LEN_MIN) { // overflow check
				ret = ERROR_ARGUMENT_INVALID;
				goto out;
			}
			// Validate only hex characters
			bool valid;
			switch (guid_string[i]) {
			case '0' ... '9':
			case 'a' ... 'f':
			case 'A' ... 'F':
				valid = true;
				break;
			default:
				valid = false;
				break;
			}
			if (!valid) {
				ret = ERROR_ARGUMENT_INVALID;
				goto out;
			}
			temp_guid[guid_len] = guid_string[i];
			guid_len++;
		}
	}
	if (guid_len != GUID_STR_LEN_MIN) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	// Convert to guid byte array
	for (i = 0U; i < (index_t)VM_GUID_LEN; i++) {
		uint8_t tmp;
		char	buf[3];

		buf[0] = temp_guid[i * 2U];
		buf[1] = temp_guid[(i * 2U) + 1U];
		buf[2] = '\0';

		errno = 0;
		tmp   = (uint8_t)strtoul(buf, NULL, 16);
		assert(errno == 0);

		(*guid)[i] = tmp;
	}
	ret = OK;

out:
	if (ret != OK) {
		(void)printf("parse: invalid GUID\n");
	}
	return ret;
}
