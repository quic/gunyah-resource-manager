// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <rm_types.h>

#include <virq.h>

bool
virq_is_valid(interrupt_data_t virq)
{
	return virq.irq != VIRQ_NUM_INVALID;
}

interrupt_data_t
virq_edge(virq_t virq_num)
{
	return (interrupt_data_t){
		.irq		    = virq_num,
		.is_edge_triggering = true,
	};
}

interrupt_data_t
virq_level(virq_t virq_num)
{
	return (interrupt_data_t){
		.irq		    = virq_num,
		.is_edge_triggering = false,
	};
}

virq_t
virq_get_number(interrupt_data_t virq)
{
	return virq.irq;
}
