// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_PCIE_INTERNAL_H_
#define INCLUDE_PCIE_INTERNAL_H_

#define PCIE_BDF_BUS_SHIFT  8U
#define PCIE_BDF_BUS_MASK   0xFFU
#define PCIE_BDF_DEV_SHIFT  3U
#define PCIE_BDF_DEV_MASK   0x1FU
#define PCIE_BDF_FUNC_SHIFT 0U
#define PCIE_BDF_FUNC_MASK  0x7U
#define PCIE_BDF_MASK	    0xFFFFU
#define PCIE_BDF_BUS(bdf)   (((bdf) >> PCIE_BDF_BUS_SHIFT) & PCIE_BDF_BUS_MASK)
#define PCIE_BDF_DEV(bdf)   (((bdf) >> PCIE_BDF_DEV_SHIFT) & PCIE_BDF_DEV_MASK)
#define PCIE_BDF_FUNC(bdf)  (((bdf) >> PCIE_BDF_FUNC_SHIFT) & PCIE_BDF_FUNC_MASK)

RM_PADDED(typedef struct {
	uint16_t bdf; // bus[15:8], device[7:3], function[2:0]
} pci_function_t)

rm_error_t
pcie_scan_bus(uintptr_t base, vector_t **pcie_functions);

#else

#error "Multiple includes of pcie-internal.h"

#endif
