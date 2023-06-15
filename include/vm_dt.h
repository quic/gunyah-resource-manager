// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define HLOS_MAX_NUM_DTBOS 2

RM_PADDED(struct boot_dtbo_info_s {
	void  *base;
	size_t size;
})

typedef struct boot_dtbo_info_s boot_dtbo_info_t;

RM_PADDED(typedef struct {
	error_t		 err;
	count_t		 num_dtbos;
	boot_dtbo_info_t dtbos[HLOS_MAX_NUM_DTBOS];
} vm_dt_create_hlos_ret_t)

vm_dt_create_hlos_ret_t
vm_dt_create_hlos(void *base, size_t size, vmaddr_t log_ipa, size_t log_size);

error_t
vm_dt_apply_hlos_overlay(vm_t *hlos_vm, paddr_t hlos_dtb, size_t dtb_size);
