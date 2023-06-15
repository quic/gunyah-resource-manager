// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define IPA_RESERVE   0x560000B0
#define IPA_UNRESERVE 0x560000B1

typedef enum ipa_reserve_req_type_e {
	IPA_RESERVE_REQ_FIXED_LIST = 0,
	IPA_RESERVE_REQ_ALLOC_LIST = 1,
} ipa_reserve_req_type_t;

#define IPA_GENERIC_CONSTRAINT_NONE		      0x0U
#define IPA_GENERIC_CONSTRAINT_ECC		      0x1U
#define IPA_GENERIC_CONSTRAINT_TAGGED		      0x2U
#define IPA_GENERIC_CONSTRAINT_NORMAL		      0x4U
#define IPA_GENERIC_CONSTRAINT_IO		      0x8U
#define IPA_GENERIC_CONSTRAINT_OWNER_VM_VISIBLE	      0x10U
#define IPA_GENERIC_CONSTRAINT_EXTERNAL_BUS_VISIBLE   0x20U
#define IPA_GENERIC_CONSTRAINT_BASE_MEMORY_COMPATIBLE 0x40U

#define IPA_PLATFORM_CONSTRAINT_NONE 0x0U

typedef struct {
	uint8_t	 alloc_type;
	uint8_t	 res0_0;
	uint16_t res0_1;
	uint32_t generic_constraints;
	uint32_t platform_constraints;
	uint32_t entries;
} ipa_reserve_req_t;

typedef struct {
	uint64_t base;
	uint64_t size;
} ipa_reserve_req_fixed_list_t;

typedef struct {
	uint64_t region_base;
	uint64_t region_size;
	uint64_t size;
	uint64_t alignment;
} ipa_reserve_req_alloc_list_t;

typedef struct {
	uint32_t reserved_entires;
} ipa_reserve_alloc_resp_t;
