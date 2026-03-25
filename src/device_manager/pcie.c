// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <rm_types.h>
#include <util.h>
#include <utils/vector.h>

#include <log.h>

#include "pcie-internal.h"

#if defined(CONFIG_DEVICE_MANAGER) && CONFIG_DEVICE_MANAGER

// PCIe Utility defines
// NOTE:
// Since PCIe Config Space is 1MB, therefore,
// it spawns until 1 Bus only.
#define MAX_PCIE_BUS_SUPPORTED 2
#define MAX_PCIE_DEV	       32U
#define MAX_PCIE_FUNC	       8U

// PCIe ECAM based shifts
#define PCIE_BUS_SHIFT	20
#define PCIE_DEV_SHIFT	15
#define PCIE_FUNC_SHIFT 12

// PCI Header Word Offset 0
// 31              23             15               7                0
// +---------------+---------------+---------------+----------------+
// | Device ID                     | Vendor ID                      |
// +---------------+---------------+---------------+----------------+
#define PCIE_INVALID_ID		     0xFFFFFFFFU
#define PCIE_DEVICE_VENDOR_ID_OFFSET 0U

// PCI Header Word Offset 1
// Bits within COMMAND register
// 31              23             15               7                0
// +---------------+---------------+---------------+----------------+
// | Status                        | Command                        |
// +---------------+---------------+---------------+----------------+

#define PCIE_GET_STATUS(x)		  (((x) >> 16) & 0x0000FFFFU)
#define PCIE_STATUS_CAPABILITIES_LIST_BIT (1U << 4)

#define PCIE_CMD_STATUS_OFFSET 1U

// PCI Header Word Offset 3
// 31              23             15               7                0
// +---------------+---------------+---------------+----------------+
// | BIST          | Header  Type  | Latency Timer | Cache Line Size|
// +---------------+---------------+---------------+----------------+
#define PCIE_GET_HEADER_TYPE(x)		 (((x) >> 16) & 0x0000007FU)
#define PCIE_HEADER_TYPE0		 0U
#define PCIE_HEADER_TYPE1		 1U
#define PCIE_GET_HEADER_MULTIFUNCTION(x) (((x) >> 23) & 1U)
#define PCIE_DEVICE_MULTIFUNCTION	 1U
#define PCIE_HEADER_TYPE_OFFSET		 3U

// PCI Header Word Offset 6 (Type-1 only)
// 31              23             15               7                0
// +---------------+---------------+---------------+----------------+
// | Sec Lat Timer | Subord Bus #  | Secndry Bus # | Primary Bus #  |
// +---------------+---------------+---------------+----------------+
#define PCIE_PRI_SEC_SUB_BUS_OFFSET 6U
#define PCIE_GET_SEC_BUS_NUM(x)	    (((x) >> 8) & 0xFFU)
#define PCIE_GET_SUB_BUS_NUM(x)	    (((x) >> 16) & 0xFFU)

// PCI Header Word Offset 0xD
#define PCIE_CAP_POINTER_OFFSET 0xDU
// NOTE: The bottom two bits of Capabilities offset must be masked as per the
// specs.
#define PCIE_GET_CAP_OFFSET(x) (((x) & 0xFCU) / 4U)

// Standard PCI Capability Header
#define PCIE_GET_STANDARD_CAPID(x) ((x) & 0xFFFFU)
// NOTE: The bottom two bits of Capabilities offset must be masked as per the
// specs.
#define PCIE_GET_STANDARD_NEXT_CAP_OFFSET(x) ((((x) >> 8) & 0xFCU) / 4U)

// Extended PCIe Capability Header
#define PCIE_EXTENDED_CAP_POINTER_OFFSET (0x100U / 4U)
#define PCIE_GET_EXTENDED_CAPID(x)	 ((x) & 0xFFFFU)
#define PCIE_GET_EXTENDED_CAPVER(x)	 (((x) >> 16) & 0xFU)
#define PCIE_GET_EXTENDED_CAP_OFFSET(x)	 ((((x) >> 20) & 0xFFCU) / 4U)

#define PCIE_BDF_FORMAT_BUS_SHIFT  8U
#define PCIE_BDF_FORMAT_DEV_SHIFT  5U
#define PCIE_BDF_FORMAT_FUNC_SHIFT 0U
#define PCIE_BDF_FORMAT_MASK	   0xFFFFU

// NOTE: The following function returns the BDF pair as per
// structure bdf bus[15:8], device[7:3], function[2:0] in pcie-internal.h.
static uint16_t
get_bdf_pair(uintptr_t addr)
{
	uint16_t bus	  = (uint16_t)PCIE_BDF_BUS(addr);
	uint16_t device	  = (uint16_t)PCIE_BDF_DEV(addr);
	uint16_t function = (uint16_t)PCIE_BDF_FUNC(addr);

	return ((uint16_t)((bus << PCIE_BDF_FORMAT_BUS_SHIFT) |
			   (device << PCIE_BDF_FORMAT_DEV_SHIFT) |
			   (function << PCIE_BDF_FORMAT_FUNC_SHIFT)) &
		PCIE_BDF_FORMAT_MASK);
}

static uintptr_t
get_bdf_addr_offset(uint32_t bus_idx, uint32_t dev_idx, uint32_t func_idx)
{
	return ((((uintptr_t)bus_idx & PCIE_BDF_BUS_MASK) << PCIE_BUS_SHIFT) |
		(((uintptr_t)dev_idx & PCIE_BDF_DEV_MASK) << PCIE_DEV_SHIFT) |
		(((uintptr_t)func_idx & PCIE_BDF_FUNC_MASK)
		 << PCIE_FUNC_SHIFT));
}

static uint32_t
read_pcie_config(uintptr_t bdf_base, uint32_t reg_offset)
{
	volatile uint32_t *cfg = (volatile uint32_t *)bdf_base;

	return cfg[reg_offset];
}

static void
parse_pcie_standard_capabilities(uintptr_t function_base)
{
	uint32_t reg = read_pcie_config(function_base, PCIE_CAP_POINTER_OFFSET);
	uint32_t cap_offset = PCIE_GET_CAP_OFFSET(reg);

	assert(cap_offset != 0U);

	do {
		reg = read_pcie_config(function_base, cap_offset);

		// NOTE: PCI Code and ID Assignment Specification
		// Revision 1.12 - 9 Jan 2020

		switch (PCIE_GET_STANDARD_CAPID(reg)) {
		case 0x00U: // NULL Capability // TODO: Special Handling
		case 0x01U: // Power Management
		case 0x02U: // Accelerated Graphics Port
		case 0x03U: // Vital Product Data
		case 0x04U: // Slot Identification
		case 0x05U: // MSI Capabilitiy
		case 0x06U: // CompactPCI Hot Swap
		case 0x07U: // PCI-X
		case 0x08U: // HyperTransport
		case 0x09U: // Vendor Specific
		case 0x0AU: // Debug Port
		case 0x0BU: // CompactPCI Central Resource Control
		case 0x0CU: // PCI Hot-Plug
		case 0x0DU: // PCI Bridge Subsystem Vendor ID
		case 0x0EU: // AGP 8x
		case 0x0FU: // Secure Device
		case 0x10U: // PCIe Express Capability
		case 0x11U: // MSI-X Capability
		case 0x12U: // Serial ATA Data/Index Config
		case 0x13U: // Advanced Features
		case 0x14U: // Enhanced Allocation
		case 0x15U: // Flattening Portal Bridge
			break;
		default: // Other IDs are reserved
			break;
		}

		cap_offset = PCIE_GET_STANDARD_NEXT_CAP_OFFSET(reg);
	} while (cap_offset != 0U);
}

static void
parse_pcie_extended_capabilities(uintptr_t function_base)
{
	// As per specs, extend. capabilities start at 0x100 offset.
	uint32_t reg;
	uint32_t ext_cap_offset = PCIE_EXTENDED_CAP_POINTER_OFFSET;
	uint32_t ext_cap_id;
	uint32_t ext_cap_version;

	do {
		reg = read_pcie_config(function_base, ext_cap_offset);
		ext_cap_offset	= PCIE_GET_EXTENDED_CAP_OFFSET(reg);
		ext_cap_id	= PCIE_GET_EXTENDED_CAPID(reg);
		ext_cap_version = PCIE_GET_EXTENDED_CAPVER(reg);

		(void)ext_cap_version;

		// NOTE: PCI Code and ID Assignment Specification
		// Revision 1.12 - 9 Jan 2020

		switch (ext_cap_id) {
		case 0x00U: // NULL Capability // TODO: Special Handling
		case 0x01U: // Advanced Error Reporting
		case 0x02U: // Virtual Channel (VC) used if an MFVC Extended
			    // Cap structure is not present in the device
		case 0x03U: // Device Serial Number
		case 0x04U: // Power Budgeting
		case 0x05U: // Root Complex Link Declaration
		case 0x06U: // Root Complex Internal Link Control
		case 0x07U: // Root Complex Event Collector Endpoint Association
		case 0x08U: // Multi-Function Virtual Channel (MFVC)
		case 0x09U: // Virtual Channel (VC) used if an MFVC Extended
			    // Cap structure is present in the device
		case 0x0AU: // Root Complex Register Block (RCRB) Header
		case 0x0BU: // Vendor-Specific Extended Capability (VSEC)
		case 0x0CU: // Configuration Access Correlation (CAC) – defined
			    // by the Trusted Configuration Space (TCS) for PCI
			    // Express ECN, which is no longer supported
		case 0x0DU: // Access Control Services (ACS)
		case 0x0EU: // Alternative Routing-ID Interpretation (ARI)
		case 0x0FU: // Address Translation Services (ATS)
		case 0x10U: // Single Root I/O Virtualization (SR-IOV)
		case 0x11U: // Deprecated; formerly Multi-Root I/O
			    // Virtualization (MR-IOV)
		case 0x12U: // Multicast
		case 0x13U: // Page Request Interface (PRI)
		case 0x14U: // Reserved for AMD
		case 0x15U: // Resizable BAR
		case 0x16U: // Dynamic Power Allocation (DPA)
		case 0x17U: // TPH Requester
		case 0x18U: // Latency Tolerance Reporting (LTR)
		case 0x19U: // Secondary PCI Express
		case 0x1AU: // Protocol Multiplexing (PMUX)
		case 0x1BU: // Process Address Space ID (PASID)
		case 0x1CU: // LN Requester (LNR)
		case 0x1DU: // Downstream Port Containment (DPC)
		case 0x1EU: // L1 PM Substates
		case 0x1FU: // Precision Time Measurement (PTM)
		case 0x20U: // PCI Express over M-PHY (M-PCIe)
		case 0x21U: // FRS Queueing
		case 0x22U: // Readiness Time Reporting
		case 0x23U: // Designated Vendor-Specific Extended Capability
		case 0x24U: // VF Resizable BAR
		case 0x25U: // Data Link Feature
		case 0x26U: // Physical Layer 16.0 GT/s
		case 0x27U: // Lane Margining at the Receiver
		case 0x28U: // Hierarchy ID
		case 0x29U: // Native PCIe Enclosure Management (NPEM)
		case 0x2AU: // Physical Layer 32.0 GT/s
		case 0x2BU: // Alternate Protocol
		case 0x2CU: // System Firmware Intermediary (SFI)
		case 0x2DU: // Shadow Functions
		case 0x2EU: // Data Object Exchange
			break;
		default: // Other IDs are reserved
			break;
		}

	} while (ext_cap_offset != 0U);
}

static void
pcie_scan_function(uintptr_t function_base, vector_t **pcie_functions)
{
	uint32_t       reg;
	error_t	       err;
	pci_function_t function;

	reg = read_pcie_config(function_base, PCIE_DEVICE_VENDOR_ID_OFFSET);
	if (reg == PCIE_INVALID_ID) {
		// Function is not implemented, simply return
		goto out;
	}

	// For now, we only handle Type 0 device functions
	reg	     = read_pcie_config(function_base, PCIE_CMD_STATUS_OFFSET);
	function.bdf = get_bdf_pair(function_base);

	// NOTE: All PCIe compatible devices must implement capabilities
	if ((PCIE_GET_STATUS(reg) & PCIE_STATUS_CAPABILITIES_LIST_BIT) != 0U) {
		parse_pcie_standard_capabilities(function_base);
		parse_pcie_extended_capabilities(function_base);
	} else {
		LOG("%s: No capabilites found for 0x%x\n", __func__,
		    function.bdf);
	}

	err = vector_push_back(*pcie_functions, function);
	assert(err == OK);
out:

	return;
}

static void
pcie_scan_device(uintptr_t base, uint32_t bus_idx, uint32_t dev_idx,
		 vector_t **pcie_functions)
{
	uint32_t  func_idx = 0U;
	uintptr_t bdf_base = get_bdf_addr_offset(bus_idx, dev_idx, func_idx);
	uint32_t  reg;
	bool	  multi_func = false;

	// TODO: 0xFFFF ignores VFs.
	reg = read_pcie_config(base + bdf_base, PCIE_DEVICE_VENDOR_ID_OFFSET);
	if (reg == PCIE_INVALID_ID) {
		// No device is present in this slot, simply return
		goto out;
	}

	reg = read_pcie_config(base + bdf_base, PCIE_HEADER_TYPE_OFFSET);

	// check if it is a P2P bridge, then simply return
	if (PCIE_GET_HEADER_TYPE(reg) == PCIE_HEADER_TYPE1) {
		goto out;
	}

	// check if the device is multifunction
	if (PCIE_GET_HEADER_MULTIFUNCTION(reg) == PCIE_DEVICE_MULTIFUNCTION) {
		multi_func = true;
	}

	do {
		bdf_base = get_bdf_addr_offset(bus_idx, dev_idx, func_idx);
		pcie_scan_function(base + bdf_base, pcie_functions);
		func_idx++;
	} while (multi_func && (func_idx < MAX_PCIE_FUNC));

out:

	return;
}

static void
pcie_scan_host_bridge(uintptr_t base, uint32_t *start_bus_idx,
		      uint32_t *end_bus_idx)
{
	uint32_t reg;

	reg = read_pcie_config(base, PCIE_DEVICE_VENDOR_ID_OFFSET);
	if (reg == PCIE_INVALID_ID) {
		*start_bus_idx = 0;
		*end_bus_idx   = 0;
		goto out;
	}

	reg = read_pcie_config(base, PCIE_HEADER_TYPE_OFFSET);

	if (PCIE_GET_HEADER_TYPE(reg) == PCIE_HEADER_TYPE1) {
		// it is a P2P bridge
		// Note: Assuming only one P2P Virtual Bridge is present
		// on bus 0.
		reg = read_pcie_config(base, PCIE_PRI_SEC_SUB_BUS_OFFSET);
		*start_bus_idx = PCIE_GET_SEC_BUS_NUM(reg);
		*end_bus_idx   = PCIE_GET_SUB_BUS_NUM(reg);
	} else if (PCIE_GET_HEADER_TYPE(reg) == PCIE_HEADER_TYPE0) {
		// it is an RCiEP
		*start_bus_idx = 0;
		*end_bus_idx   = 1;
	} else {
		// Other header layout encodings are reserved.
		*start_bus_idx = 0;
		*end_bus_idx   = 0;
	}

out:
	return;
}

rm_error_t
pcie_scan_bus(uintptr_t base, vector_t **pcie_functions)
{
	rm_error_t err;
	uint32_t   bus_idx;
	uint32_t   dev_idx;
	uint32_t   max_bus_idx = MAX_PCIE_BUS_SUPPORTED;

	*pcie_functions = vector_init(pci_function_t, 0U, 0U);
	if (*pcie_functions == NULL) {
		err = RM_ERROR_NOMEM;
		goto out;
	}

	// NOTE:
	// Start at BDF 00:00.0 directly from the Host Bridge assuming
	// there is single host controller preconfigured in ECAM mode
	// or RCiEPs on bus 0.
	// The following scanning assumes that the Host Bridge's link
	// is up and the downstream devices present are already
	// initialized.
	// The scanning continues until the sub-ordinate bus number
	// configured in the Host Bridge. If there are RCiEPs, then
	// no further scanning of buses is done.
	// Only type-0 devices are scanned for functions
	// as these are the only ones of our interest and are going to be
	// lent,donated ... to other VMs. Each function of a PCIe device
	// is considered a sole device in our terminology.

	pcie_scan_host_bridge(base, &bus_idx, &max_bus_idx);
	for (; bus_idx < max_bus_idx; bus_idx++) {
		for (dev_idx = 0; dev_idx < MAX_PCIE_DEV; dev_idx++) {
			pcie_scan_device(base, bus_idx, dev_idx,
					 pcie_functions);
		}
	}

	err = RM_OK;
out:
	return err;
}

#endif
