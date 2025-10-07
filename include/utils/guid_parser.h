// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef UTILS_GUID_PARSER_H_
#define UTILS_GUID_PARSER_H_

error_t
parse_guid_string(const char *guid_string, uint8_t (*guid)[VM_GUID_LEN]);

#else

#error multiple include of utils/guid_parser.h

#endif
