// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

static const virq_t VIRQ_NUM_INVALID = ~(virq_t)0U;

#define VIRQ_INVALID ((interrupt_data_t){ .irq = VIRQ_NUM_INVALID })

bool
virq_is_valid(interrupt_data_t virq);

interrupt_data_t
virq_edge(virq_t virq_num);

interrupt_data_t
virq_level(virq_t virq_num);

virq_t
virq_get_number(interrupt_data_t virq);
