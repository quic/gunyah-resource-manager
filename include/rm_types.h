// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_RM_TYPES_H_
#define INCLUDE_RM_TYPES_H_

#define VMID_HYP	  0x0U
#define VMID_HLOS	  0x3U
#define VMID_DYNAMIC_BASE 0x80U
#define VMID_DYNAMIC_END  0xBFU
#define VMID_RM		  0xFFU

// Special VMIDs
#define VMID_LAST	  0xFFU	  // Last usable VMID
#define VMID_ANY	  0xFFFEU // For resources without specific owner
#define VMID_PEER_DEFAULT 0xFFFFU

#define INVALID_ADDRESS (~(paddr_t)0U)

#define VM_MAX_NAME_LEN 80
#define VM_GUID_LEN	16U
#define VM_MAX_URI_LEN	80

// Macros to instruct the compiler not to warn about padding. These should only
// be used on structures that are either internal to the RM or else have been
// unmarshalled from a packed on-the-wire representation.
#define RM_PADDED_BEGIN                                                        \
	_Pragma("clang diagnostic push")                                       \
	_Pragma("clang diagnostic ignored \"-Wpadded\"")
#define RM_PADDED_END _Pragma("clang diagnostic pop")

#define RM_PADDED(struct_body)                                                 \
	RM_PADDED_BEGIN                                                        \
	struct_body;                                                           \
	RM_PADDED_END

struct rm_env_data_s;
typedef struct rm_env_data_s rm_env_data_t;

struct platform_env_data_s;
typedef struct platform_env_data_s platform_env_data_t;

struct vm_s;
typedef struct vm_s vm_t;

struct vm_config_s;
typedef struct vm_config_s vm_config_t;

struct vm_device_descriptor_s;
typedef struct vm_device_descriptor_s vm_device_descriptor_t;

struct vm_device_assignments_s;
typedef struct vm_device_assignments_s vm_device_assignments_t;

struct dtb_parser_data_s;
typedef struct dtb_parser_data_s dtb_parser_data_t;

struct dtb_parser_ops_s;
typedef struct dtb_parser_ops_s dtb_parser_ops_t;

struct dto_s;
typedef struct dto_s dto_t;

struct address_range_allocator_s;
typedef struct address_range_allocator_s address_range_allocator_t;

struct vector_s;
typedef struct vector_s vector_t;

struct memparcel_s;
typedef struct memparcel_s memparcel_t;

struct acl_entry_s;
typedef struct acl_entry_s acl_entry_t;

struct sgl_entry_s;
typedef struct sgl_entry_s sgl_entry_t;

struct vdevice_node;
typedef struct vdevice_node vdevice_node_t;

typedef uint32_t label_t;

typedef enum {
	VM_ID_TYPE_GUID	     = 0,
	VM_ID_TYPE_URI	     = 1,
	VM_ID_TYPE_NAME	     = 2,
	VM_ID_TYPE_SIGN_AUTH = 3,
} vm_id_type_t;

typedef enum {
	VM_AUTH_TYPE_NONE     = 0,
	VM_AUTH_TYPE_PLATFORM = 1,
	VM_AUTH_TYPE_ANDROID  = 2, // Android pVM
} vm_auth_type_t;

RM_PADDED(typedef struct interrupt_data {
	virq_t irq;
	bool   is_cpu_local;
	bool   is_edge_triggering;
} interrupt_data_t)

typedef uint32_t address_range_tag_t;

#define ADDRESS_RANGE_NO_TAG (address_range_tag_t)0UL

typedef uint32_t rm_error_t;

#define RM_OK			  ((rm_error_t)0x0U)
#define RM_ERROR_UNIMPLEMENTED	  ((rm_error_t)0xffffffffU)
#define RM_ERROR_NOMEM		  ((rm_error_t)0x1U)
#define RM_ERROR_NORESOURCE	  ((rm_error_t)0x2U)
#define RM_ERROR_DENIED		  ((rm_error_t)0x3U)
#define RM_ERROR_MSG_INVALID	  ((rm_error_t)0x4U)
#define RM_ERROR_BUSY		  ((rm_error_t)0x5U)
#define RM_ERROR_ARGUMENT_INVALID ((rm_error_t)0x6U)
#define RM_ERROR_HANDLE_INVALID	  ((rm_error_t)0x7U)
#define RM_ERROR_VALIDATE_FAILED  ((rm_error_t)0x8U)
#define RM_ERROR_MAP_FAILED	  ((rm_error_t)0x9U)
#define RM_ERROR_MEM_INVALID	  ((rm_error_t)0xaU)
#define RM_ERROR_MEM_INUSE	  ((rm_error_t)0xbU)
#define RM_ERROR_MEM_RELEASED	  ((rm_error_t)0xcU)
#define RM_ERROR_VMID_INVALID	  ((rm_error_t)0xdU)
#define RM_ERROR_LOOKUP_FAILED	  ((rm_error_t)0xeU)
#define RM_ERROR_IRQ_INVALID	  ((rm_error_t)0xfU)
#define RM_ERROR_IRQ_INUSE	  ((rm_error_t)0x10U)
#define RM_ERROR_IRQ_RELEASED	  ((rm_error_t)0x11U)
#define RM_ERROR_VM_STATE	  ((rm_error_t)0x14U)

#else

#error multiple include of rm_types.h

#endif
