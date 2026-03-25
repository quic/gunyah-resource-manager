// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_DTB_PARSER_LISTNER_H_
#define INCLUDE_DTB_PARSER_LISTNER_H_

RM_PADDED(typedef struct dtb_listener_s {
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
	bool	 safe;

	regex_t *ctxt;
} dtb_listener_t)

#else

#error multiple include of dtb_parser_listener.h

#endif
