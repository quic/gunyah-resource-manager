// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_VIRQ_H_
#define INCLUDE_VIRQ_H_

#define VIRQ_DATA_INVALID ((interrupt_data_t){ .irq = VIRQ_INVALID })

bool
virq_is_valid(interrupt_data_t virq);

interrupt_data_t
virq_edge(virq_t virq_num);

interrupt_data_t
virq_level(virq_t virq_num);

virq_t
virq_get_number(interrupt_data_t virq);

#else

#error multiple include of virq.h

#endif
