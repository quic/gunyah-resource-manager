// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define LOG(fmt, ...) printf(fmt, __VA_ARGS__)

typedef uint32_t rm_error_t;

rm_error_t
log_reconfigure(uintptr_t *log_buf, size_t size);

rm_error_t
log_expose_to_hlos(uintptr_t log_buf, size_t size);
