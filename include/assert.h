// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef int line_number_t;

#if defined(CONFIG_DEBUG)
// Lightweight assert message without the function name
#define assert(x) ((void)((x) || (rm_assert_fail((#x), __FILE__, __LINE__), 0)))

_Noreturn void
rm_assert_fail(const char *cond_fail, const char *file, line_number_t line);
#else
// Lightweight assert message without the condition and function name
#define assert(x) ((void)((x) || (rm_assert_fail(__FILE__, __LINE__), 0)))

_Noreturn void
rm_assert_fail(const char *file, line_number_t line);
#endif

#define static_assert _Static_assert
