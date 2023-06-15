// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define MEM_DONATE	    0x51000010U
#define MEM_ACCEPT	    0x51000011U
#define MEM_LEND	    0x51000012U
#define MEM_SHARE	    0x51000013U
#define MEM_RELEASE	    0x51000014U
#define MEM_RECLAIM	    0x51000015U
#define MEM_NOTIFY	    0x51000017U
#define MEM_APPEND	    0x51000018U
#define MEM_QCOM_LOOKUP_SGL 0x5100001AU

#define MEM_SHARED   0x51100011U
#define MEM_RELEASED 0x51100012U
#define MEM_ACCEPTED 0x51100013U
#define MEM_RECALL   0x51100014U

#define MEM_TYPE_NORMAL 0U
#define MEM_TYPE_IO	1U

#define MEM_RIGHTS_X   0x1U
#define MEM_RIGHTS_W   0x2U
#define MEM_RIGHTS_R   0x4U
#define MEM_RIGHTS_RX  0x5U
#define MEM_RIGHTS_RW  0x6U
#define MEM_RIGHTS_RWX 0x7U

#define MEM_CREATE_FLAG_SANITIZE 1U
#define MEM_CREATE_FLAG_APPEND	 2U

#define MEM_APPEND_FLAG_DONE 1U

#define MEM_ACCEPT_FLAG_VALIDATE_SANITIZED 1U
#define MEM_ACCEPT_FLAG_VALIDATE_ACL_ATTR  2U
#define MEM_ACCEPT_FLAG_VALIDATE_LABEL	   4U
#define MEM_ACCEPT_FLAG_MAP_OTHER	   8U
#define MEM_ACCEPT_FLAG_MAP_CONTIGUOUS	   16U
#define MEM_ACCEPT_FLAG_SANITIZE	   32U
#define MEM_ACCEPT_FLAG_DONE		   128U

#define MEM_RELEASE_FLAG_SANITIZE 1U

#define MEM_RECLAIM_FLAG_SANITIZE 1U

#define MEM_NOTIFY_FLAG_SHARED	 1U
#define MEM_NOTIFY_FLAG_RELEASED 2U
#define MEM_NOTIFY_FLAG_ACCEPTED 4U
#define MEM_NOTIFY_FLAG_RECALL	 8U

#define TRANS_TYPE_DONATE 0U
#define TRANS_TYPE_LEND	  1U
#define TRANS_TYPE_SHARE  2U

#define MEM_ATTR_NORMAL	  0U
#define MEM_ATTR_DEVICE	  1U
#define MEM_ATTR_UNCACHED 2U
#define MEM_ATTR_CACHED	  3U

typedef struct acl_entry {
	vmid_t	vmid;
	uint8_t rights;
	uint8_t res0;
} acl_entry_t;

typedef struct sgl_entry_s {
	uint64_t ipa;
	uint64_t size;
} sgl_entry_t;

typedef struct {
	uint16_t attr;
	vmid_t	 vmid;
} attr_entry_t;

typedef struct {
	vmid_t	 vmid;
	uint16_t res0;
} vmid_entry_t;

static_assert(sizeof(acl_entry_t) == 4U, "ACL entry not sized correctly");
static_assert(sizeof(sgl_entry_t) == 16U, "SGL entry not sized correctly");
static_assert(sizeof(attr_entry_t) == 4U, "ACL entry not sized correctly");
static_assert(sizeof(vmid_entry_t) == 4U, "VMID entry not sized correctly");

// Request structures contain the required fields of the request
typedef struct {
	uint8_t	 mem_type;
	uint8_t	 res0_0;
	uint8_t	 flags;
	uint8_t	 res0_1;
	uint32_t label;
	uint16_t acl_entries;
	uint16_t res0_acl_entries;
	// array of acl_entry_t
	uint16_t sgl_entries;
	uint16_t res0_2;
	// array of sgl_entry_t
	uint16_t attr_entries;
	uint16_t res0_3;
	// array of attr_entry_t
} memparcel_create_req_t;

typedef struct {
	uint32_t handle;
	uint8_t	 flags;
	uint8_t	 res0_0[3];
	uint16_t sgl_entries;
	uint16_t res0_1;
	// array of sgl_entry_t
} memparcel_append_req_t;

typedef struct {
	uint32_t handle;
	uint8_t	 mem_type;
	uint8_t	 trans_type;
	uint8_t	 flags;
	uint8_t	 res0_0;
	uint32_t label;
	uint16_t acl_entries;
	uint16_t res0_acl_entries;
	// array of acl_entry_t
	uint16_t sgl_entries;
	vmid_t	 map_vmid;
	// array of sgl_entry_t
	uint16_t attr_entries;
	uint16_t res0_1;
	// array of attr_entry_t
} memparcel_accept_req_t;

typedef struct {
	uint32_t handle;
	uint8_t	 flags;
	uint8_t	 res0[3];
} memparcel_release_req_t;

typedef struct {
	uint32_t handle;
	uint8_t	 flags;
	uint8_t	 res0[3];
	uint32_t mem_info_tag;
} memparcel_notify_req_t;

typedef memparcel_release_req_t memparcel_reclaim_req_t;

typedef struct {
	uint8_t	 mem_type;
	uint8_t	 res0_0[3];
	uint32_t label;
	uint16_t acl_entries;
	uint16_t res0_acl_entries;
	// array of acl_entry_t
	uint16_t sgl_entries;
	uint16_t res0_1;
	// array of sgl_entry_t
	// optional attr list
} memparcel_lookup_req_t;

static_assert(sizeof(memparcel_create_req_t) == 20U,
	      "Memparcel create request not sized correctly");
static_assert(sizeof(memparcel_accept_req_t) == 24U,
	      "Memparcel accept request not sized correctly");
static_assert(sizeof(memparcel_release_req_t) == 8U,
	      "Memparcel release request not sized correctly");
static_assert(sizeof(memparcel_lookup_req_t) == 16U,
	      "Memparcel lookup request not sized correctly");

typedef struct {
	uint32_t handle;
} memparcel_handle_resp_t;

#define MEMPARCEL_INVALID_HANDLE ~(uint32_t)0U

#define MEM_ACCEPT_RESP_FLAG_INCOMPLETE 1U

typedef struct {
	rm_error_t err;
	uint16_t   sgl_entries;
	uint8_t	   flags;
	uint8_t	   res0;
	// array of sgl_entry_t
} memparcel_accept_sgl_resp_t;

typedef struct {
	uint32_t handle;
	uint8_t	 mem_type;
	uint8_t	 trans_type;
	uint8_t	 flags;
	uint8_t	 res0_0;
	vmid_t	 owner_vmid;
	uint8_t	 res0_1[2];
	uint32_t label;
	uint32_t mem_info_tag;
	uint16_t acl_entries;
	uint16_t res0_acl_entries;
	// array of acl_entry_t
	uint16_t sgl_entries;
	uint16_t res0_2;
	// array of sgl_entry_t
	uint16_t attr_entries;
	uint16_t res0_3;
	// array of attr_entry_t
} memparcel_shared_notif_t;

typedef struct {
	uint32_t handle;
	vmid_t	 vmid;
	uint8_t	 res0[2];
	uint32_t mem_info_tag;
} memparcel_owner_notif_t;

typedef struct {
	uint32_t handle;
	uint32_t mem_info_tag;
} memparcel_recall_notif_t;

typedef uint32_t mem_handle_t;

// FIXME: The following declarations don't necessarily belong here. There are here
// because some necessary type definitions are in this file. Move them out once
// the code has been refactored.

typedef struct memparcel_construct_ret {
	rm_error_t err;
	uint32_t   handle;
} memparcel_construct_ret_t;

memparcel_construct_ret_t
memparcel_construct(vmid_t owner_vmid, uint16_t acl_entries,
		    uint16_t sgl_entries, uint16_t attr_entries,
		    acl_entry_t *acl, sgl_entry_t *sgl, attr_entry_t *attr_list,
		    uint32_t label, bool label_valid, uint8_t mem_type,
		    uint8_t trans_type, bool vm_init, uint8_t flags);

rm_error_t
memparcel_accept(vmid_t vmid, uint16_t acl_entries, uint16_t sgl_entries,
		 uint16_t attr_entries, const acl_entry_t *acl,
		 const sgl_entry_t *sgl, const attr_entry_t *attr_list,
		 vmid_t map_vmid, mem_handle_t handle, uint32_t label,
		 uint8_t mem_type, uint8_t trans_type, uint8_t flags);

mem_handle_t
memparcel_sgl_do_lookup(vmid_t vmid, uint16_t acl_entries, uint16_t sgl_entries,
			uint16_t attr_entries, acl_entry_t *acl,
			sgl_entry_t *sgl, attr_entry_t *attr_list,
			uint32_t label, uint8_t mem_type, bool hyp_unassign);

rm_error_t
memparcel_do_reclaim(vmid_t vmid, mem_handle_t handle, uint8_t flags);
