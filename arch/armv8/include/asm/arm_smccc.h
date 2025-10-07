// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef ARCH_ARMV8_SMCCC_H_
#define ARCH_ARMV8_SMCCC_H_

#define SMCCC_USE_SMC
// #define SMCCC_USE_HVC

#define SMCCC_FAST_CALL_SHIFT  31U
#define SMCCC_64BIT_CALL_SHIFT 30U
#define SMCCC_SERVICE_BITS     6U
#define SMCCC_SERVICE_SHIFT    24U
#define SMCCC_FUNCTION_BITS    16U
#define SMCCC_FUNCTION_SHIFT   0U

#define SMCCC_SERVICE_MASK                                                     \
	(((1U << SMCCC_SERVICE_BITS) - 1U) << SMCCC_SERVICE_SHIFT)
#define SMCCC_FUNCTION_MASK ((1U << SMCCC_FUNCTION_BITS) - 1U)

#define SMCCC_SERVICE_ARM	      0U
#define SMCCC_SERVICE_CPU	      1U
#define SMCCC_SERVICE_SIP	      2U
#define SMCCC_SERVICE_OEM	      3U
#define SMCCC_SERVICE_STANDARD_SECURE 4U
#define SMCCC_SERVICE_STANDARD_HYP    5U
#define SMCCC_SERVICE_VENDOR_HYP      6U

#define SMCCC_FUNCTION_ID(fast, call64, service_call, function)                \
	(((uint64_t)((fast) ? 1U : 0U) << SMCCC_FAST_CALL_SHIFT) |             \
	 ((uint64_t)((call64) ? 1U : 0U) << SMCCC_64BIT_CALL_SHIFT) |          \
	 ((service_call) << SMCCC_SERVICE_SHIFT) |                             \
	 ((function) << SMCCC_FUNCTION_SHIFT))

#define SMCCC_FUNCTION_ID_IS_FAST(func_id)                                     \
	((bool)(((func_id) >> SMCCC_FAST_CALL_SHIFT) & 1))
#define SMCCC_FUNCTION_ID_IS_64BIT(func_id)                                    \
	((bool)(((func_id) >> SMCCC_64BIT_CALL_SHIFT) & 1))
#define SMCCC_FUNCTION_ID_GET_SERVICE(func_id)                                 \
	((uint32_t)((SMCCC_SERVICE_MASK & (func_id)) >> SMCCC_SERVICE_SHIFT))
#define SMCCC_FUNCTION_ID_GET_FUNCTION(func_id)                                \
	((uint32_t)((SMCCC_FUNCTION_MASK & (func_id)) >> SMCCC_FUNCTION_SHIFT))

uint64_t
arm_smccc11_call(uint64_t func_id, uint64_t (*param)[7], uint64_t (*result)[4]);

uint64_t
arm_smccc12_call(uint64_t func_id, uint64_t (*param)[17],
		 uint64_t (*result)[18]);

#else

#error arch/armv8/include/asm/arm_smccc.h multiple include

#endif
