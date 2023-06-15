// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define LOG(fmt, ...) (void)printf(fmt, __VA_ARGS__)

#define LOG_LOC(msg) (void)printf("%s %d: %s\n", __FILE__, __LINE__, msg)
#define LOG_ERR(err) (void)printf("Error: %s %d: %d\n", __FILE__, __LINE__, err)

typedef uint32_t rm_error_t;

rm_error_t
log_reconfigure(uintptr_t *log_buf, size_t size);

rm_error_t
log_expose_to_hlos(uintptr_t log_buf, size_t size);
