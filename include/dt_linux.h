// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define DT_GIC_IRQ_TYPE_NONE	     0
#define DT_GIC_IRQ_TYPE_EDGE_RISING  1
#define DT_GIC_IRQ_TYPE_EDGE_FALLING 2
#define DT_GIC_IRQ_TYPE_EDGE_BOTH                                              \
	(DT_GIC_IRQ_TYPE_EDGE_FALLING | DT_GIC_IRQ_TYPE_EDGE_RISING)
#define DT_GIC_IRQ_TYPE_LEVEL_HIGH 4
#define DT_GIC_IRQ_TYPE_LEVEL_LOW  8
