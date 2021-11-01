// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define MAX_LIST_ENTRIES 512

typedef uint32_t      mem_handle_t;
typedef struct vector vector_t;

bool
memparcel_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		      void *buf, size_t len);

error_t
memparcel_map_rm(mem_handle_t handle, size_t offset, uintptr_t addr,
		 size_t size);

error_t
memparcel_unmap_rm(mem_handle_t handle);

typedef struct memparcel memparcel_t;
typedef uint32_t	 label_t;

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

paddr_result_t
memparcel_get_phys(const memparcel_t *mp, count_t region_index);

vmaddr_result_t
memparcel_get_mapped_ipa(const memparcel_t *mp, vmid_t vmid,
			 count_t region_index);

bool
memparcel_is_shared(const memparcel_t *mp, vmid_t vmid);

error_t
memparcel_get_shared_vmids(const memparcel_t *mp, vector_t *vmids);

size_result_t
memparcel_get_size(const memparcel_t *mp, count_t region_index);

memparcel_t *
memparcel_iter_by_target_vmid(memparcel_t *after, vmid_t vmid);

error_t
memparcel_get_shared_vmids(const memparcel_t *mp, vector_t *vmids);

void
memparcel_set_phandle(memparcel_t *mp, vmid_t vmid, uint32_t phandle,
		      bool is_external);

uint32_t
memparcel_get_phandle(memparcel_t *mp, vmid_t vmid, bool *is_external);

#define foreach_memparcel_by_target_vmid(mp, vmid)                             \
	for ((mp) = memparcel_iter_by_target_vmid(NULL, (vmid)); (mp) != NULL; \
	     (mp) = memparcel_iter_by_target_vmid((mp), (vmid)))
