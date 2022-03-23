// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

struct vm;
typedef struct vm vm_t;
struct dto;
typedef struct dto dto_t;

// Apply generic platform transformations to the VM DT.
// This applies to HLOS and secondary VMs.
error_t
platform_dto_finalise(dto_t *dto, vm_t *vm);
