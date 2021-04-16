// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>

#include <asm/arm_smccc.h>

// ARM SMCCC Call version 1.1
uint64_t
arm_smccc11_call(uint64_t func_id, uint64_t param[7], uint64_t result[4])
{
	assert(param != NULL);
	assert(result != NULL);

	register uint64_t x0 __asm__("x0") = func_id;
	register uint64_t x1 __asm__("x1") = param[0];
	register uint64_t x2 __asm__("x2") = param[1];
	register uint64_t x3 __asm__("x3") = param[2];
	register uint64_t x4 __asm__("x4") = param[3];
	register uint64_t x5 __asm__("x5") = param[4];
	register uint64_t x6 __asm__("x6") = param[5];
	register uint64_t x7 __asm__("x7") = param[6];

	__asm__ volatile(
#if defined(SMCCC_USE_SMC)
		"smc    #0\n"
#elif defined(SMCCC_USE_HVC)
		"hvc    #0\n"
#endif
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
		: "r"(x4), "r"(x5), "r"(x6), "r"(x7)
		: "memory");

	result[0] = x0;
	result[1] = x1;
	result[2] = x2;
	result[3] = x3;

	return result[0];
}

#if 0
// ARM SMCCC Call version 1.2
uint64_t
arm_smccc12_call(uint64_t func_id, uint64_t param[17], uint64_t result[18])
{
#error unimplemented
}
#endif
