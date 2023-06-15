// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

error_t
vgic_init(const rm_env_data_t *env_data);

error_t
vgic_vm_config_add(vm_config_t *vmcfg, const vm_config_parser_data_t *data);

error_t
vgic_dto_finalise(dto_t *dto, const vm_t *vm);

static const size_t vgic_gicd_size = (size_t)1U << 16;
static const size_t vgic_gicr_size = (size_t)2U << 16;
static const size_t vgic_alignment = (size_t)1U << 16;
