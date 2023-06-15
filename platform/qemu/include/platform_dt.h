// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Apply generic platform transformations to the VM DT.
// This applies to HLOS and secondary VMs.
error_t
platform_dto_finalise(dto_t *dto, vm_t *vm, const void *base_dtb);

error_t
platform_dto_add_platform_props(dto_t *dto, vm_t *cur_vm);

error_t
platform_dto_create(struct vdevice_node *node, dto_t *dto, vmid_t self);
