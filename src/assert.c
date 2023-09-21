// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

// These debug/production variants are defined differently to optimize calling
// argument setup in the production builds.
#if defined(CONFIG_DEBUG)
_Noreturn void
rm_assert_fail(const char *cond_fail, const char *file, line_number_t line)
{
	(void)printf("assert(%s) failed: %s:%d\n", cond_fail, file, line);

	exit(1);
}
#else
_Noreturn void
rm_assert_fail(const char *file, line_number_t line)
{
	(void)printf("assert failed: %s:%d\n", file, line);

	exit(1);
}
#endif
