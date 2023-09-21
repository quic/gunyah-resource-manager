// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define MAX_LIST_ENTRIES 512U

typedef uint32_t	     mem_handle_t;
typedef struct vector_s	     vector_t;
typedef struct region_list_s region_list_t;

bool
memparcel_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		      void *buf, size_t len);

uintptr_result_t
memparcel_map_rm(mem_handle_t mp_handle, size_t offset, size_t size);

error_t
memparcel_unmap_rm(mem_handle_t handle);

error_t
memparcel_sanitize(mem_handle_t handle, size_t offset, size_t size);

error_t
memparcel_cache_clean(mem_handle_t handle, size_t offset, size_t size);

error_t
memparcel_cache_flush(mem_handle_t handle, size_t offset, size_t size);

RM_PADDED(typedef struct {
	void	  *ptr;
	size_t	   size;
	rm_error_t err;
} memparcel_accept_rm_donation_ret_t)

memparcel_accept_rm_donation_ret_t
memparcel_accept_rm_donation(mem_handle_t handle, uint8_t rights,
			     uint8_t mem_type);

typedef struct memparcel  memparcel_t;
typedef struct mem_region mem_region_t;
typedef uint32_t	  label_t;

mem_handle_t
memparcel_get_handle(const memparcel_t *mp);

vmid_t
memparcel_get_owner(const memparcel_t *mp);

label_t
memparcel_get_label(const memparcel_t *mp);

uint8_t
memparcel_get_mem_type(const memparcel_t *mp);

uint8_t
memparcel_get_trans_type(const memparcel_t *mp);

count_t
memparcel_get_num_regions(const memparcel_t *mp);

count_result_t
memparcel_get_num_mappings(const memparcel_t *mp, vmid_t vmid);

paddr_result_t
memparcel_get_phys(const memparcel_t *mp, index_t region_idx);

vmaddr_result_t
memparcel_get_mapped_ipa(const memparcel_t *mp, vmid_t vmid,
			 index_t mapping_idx);

bool
memparcel_is_shared(const memparcel_t *mp, vmid_t vmid);

bool
memparcel_is_exclusive(const memparcel_t *mp, vmid_t vmid);

bool
memparcel_is_private(const memparcel_t *mp, vmid_t vmid);

error_t
memparcel_get_shared_vmids(const memparcel_t *mp, vector_t *vmids);

size_t
memparcel_get_size(const memparcel_t *mp);

size_result_t
memparcel_get_region_size(const memparcel_t *mp, index_t region_idx);

region_list_t *
memparcel_get_regions_list(const memparcel_t *mp);

size_result_t
memparcel_get_mapped_size(const memparcel_t *mp, vmid_t vmid,
			  index_t mapping_idx);

memparcel_t *
memparcel_iter_by_target_vmid(memparcel_t *after, vmid_t vmid);

error_t
memparcel_get_shared_vmids(const memparcel_t *mp, vector_t *vmids);

void
memparcel_set_phandle(memparcel_t *mp, vmid_t vmid, uint32_t phandle,
		      bool is_external);

uint8_result_t
memparcel_get_vm_rights(const memparcel_t *mp, vmid_t vmid);

uint16_result_t
memparcel_get_vm_attrs(memparcel_t *mp, vmid_t vmid);

uint32_t
memparcel_get_phandle(memparcel_t *mp, vmid_t vmid, bool *is_external);

cap_id_result_t
memparcel_get_me_cap(const memparcel_t *mp);

void
memparcel_set_mem_info_tag(memparcel_t *mp, label_t tag);

bool
vm_reset_handle_release_memparcels(vmid_t vmid);

#define foreach_memparcel_by_target_vmid(mp, vmid)                             \
	for ((mp) = memparcel_iter_by_target_vmid(NULL, (vmid)); (mp) != NULL; \
	     (mp) = memparcel_iter_by_target_vmid((mp), (vmid)))

static inline memparcel_t *
memparcel_lookup_by_target_vmid(vmid_t vmid, mem_handle_t handle)
{
	memparcel_t *mp;

	foreach_memparcel_by_target_vmid (mp, vmid) {
		if (memparcel_get_handle(mp) == handle) {
			break;
		}
	}

	return mp;
}

rm_error_t
platform_memparcel_accept(memparcel_t *mp, vm_t *vm);

rm_error_t
platform_memparcel_release(memparcel_t *mp, vm_t *vm);

bool
memparcel_get_sanitize_reclaim(const memparcel_t *mp);

void
memparcel_set_lock(memparcel_t *mp, bool lock);

bool
memparcel_is_locked(const memparcel_t *mp);

uint32_t
memparcel_get_mpd_sanitise_refcount(const memparcel_t *mp, index_t region_idx);

void
memparcel_increment_mpd_sanitise_refcount(const memparcel_t *mp,
					  index_t	     region_idx);

void
memparcel_decrement_mpd_sanitise_refcount(const memparcel_t *mp,
					  index_t	     region_idx);
