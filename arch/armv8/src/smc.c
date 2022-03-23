// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>

#include <asm/arm_smccc.h>

// ARM SMCCC Call version 1.1
uint64_t
arm_smccc11_call(uint64_t func_id, uint64_t (*param)[7], uint64_t (*result)[4])
{
	assert(param != NULL);
	assert(result != NULL);

	register uint64_t x0 __asm__("x0") = func_id;
	register uint64_t x1 __asm__("x1") = (*param)[0];
	register uint64_t x2 __asm__("x2") = (*param)[1];
	register uint64_t x3 __asm__("x3") = (*param)[2];
	register uint64_t x4 __asm__("x4") = (*param)[3];
	register uint64_t x5 __asm__("x5") = (*param)[4];
	register uint64_t x6 __asm__("x6") = (*param)[5];
	register uint64_t x7 __asm__("x7") = (*param)[6];

	__asm__ volatile(
#if defined(SMCCC_USE_SMC)
		"smc    #0\n"
#elif defined(SMCCC_USE_HVC)
		"hvc    #0\n"
#endif
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
		: "r"(x4), "r"(x5), "r"(x6), "r"(x7)
		: "memory");

	(*result)[0] = x0;
	(*result)[1] = x1;
	(*result)[2] = x2;
	(*result)[3] = x3;

	return x0;
}

// ARM SMCCC Call version 1.2
uint64_t
arm_smccc12_call(uint64_t func_id, uint64_t (*param)[17],
		 uint64_t (*result)[18])
{
	assert(param != NULL);
	assert(result != NULL);

	register uint64_t x0 __asm__("x0")   = func_id;
	register uint64_t x1 __asm__("x1")   = (*param)[0];
	register uint64_t x2 __asm__("x2")   = (*param)[1];
	register uint64_t x3 __asm__("x3")   = (*param)[2];
	register uint64_t x4 __asm__("x4")   = (*param)[3];
	register uint64_t x5 __asm__("x5")   = (*param)[4];
	register uint64_t x6 __asm__("x6")   = (*param)[5];
	register uint64_t x7 __asm__("x7")   = (*param)[6];
	register uint64_t x8 __asm__("x8")   = (*param)[7];
	register uint64_t x9 __asm__("x9")   = (*param)[8];
	register uint64_t x10 __asm__("x10") = (*param)[9];
	register uint64_t x11 __asm__("x11") = (*param)[10];
	register uint64_t x12 __asm__("x12") = (*param)[11];
	register uint64_t x13 __asm__("x13") = (*param)[12];
	register uint64_t x14 __asm__("x14") = (*param)[13];
	register uint64_t x15 __asm__("x15") = (*param)[14];
	register uint64_t x16 __asm__("x16") = (*param)[15];
	register uint64_t x17 __asm__("x17") = (*param)[16];

	__asm__ volatile(
#if defined(SMCCC_USE_SMC)
		"smc    #0\n"
#elif defined(SMCCC_USE_HVC)
		"hvc    #0\n"
#endif
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5),
		  "+r"(x6), "+r"(x7), "+r"(x8), "+r"(x9), "+r"(x10), "+r"(x11),
		  "+r"(x12), "+r"(x13), "+r"(x14), "+r"(x15), "+r"(x16),
		  "+r"(x17)::"memory");

	(*result)[0]  = x0;
	(*result)[1]  = x1;
	(*result)[2]  = x2;
	(*result)[3]  = x3;
	(*result)[4]  = x4;
	(*result)[5]  = x5;
	(*result)[6]  = x6;
	(*result)[7]  = x7;
	(*result)[8]  = x8;
	(*result)[9]  = x9;
	(*result)[10] = x10;
	(*result)[11] = x11;
	(*result)[12] = x12;
	(*result)[13] = x13;
	(*result)[14] = x14;
	(*result)[15] = x15;
	(*result)[16] = x16;
	(*result)[17] = x17;

	return x0;
}
