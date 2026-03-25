// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_DEV_MGR_INTERNAL_H_
#define INCLUDE_DEV_MGR_INTERNAL_H_

// Message IDs

#define DEVICE_ACCEPT	     0x56000060
#define DEVICE_LEND	     0x56000061
#define DEVICE_RELEASE	     0x56000062
#define DEVICE_RECLAIM	     0x56000063
#define DEVICE_NOTIFY	     0x56000064
#define DEVICE_FIND_HANDLE   0x56000065
#define DEVICE_GET_RESOURCES 0x56000066
#define DEVICE_BUS_LOCKDOWN  0x56000067
#define DEVICE_BUS_UNLOCK    0x56000068
#define DEVICE_DONATE	     0x56000069

// Notification IDs

#define NOTIFY_DEVICE_DONATED  0x56100060
#define NOTIFY_DEVICE_LENT     0x56100061
#define NOTIFY_DEVICE_RELEASED 0x56100062
#define NOTIFY_DEVICE_ACCEPTED 0x56100063
#define NOTIFY_DEVICE_RECALL   0x56100064

// Command flags

#define DEVICE_ACCEPT_FLAG_RESET (1U << 0)
#define DEVICE_ACCEPT_FLAG_BIND	 (1U << 1)
#define DEVICE_ACCEPT_FLAG_MASK                                                \
	(DEVICE_ACCEPT_FLAG_RESET | DEVICE_ACCEPT_FLAG_BIND)

#define DEVICE_LEND_FLAG_RESET (1U << 0)
#define DEVICE_LEND_FLAG_MASK  (DEVICE_LEND_FLAG_RESET)

#define DEVICE_RELEASE_FLAG_RESET (1U << 0)
#define DEVICE_RELEASE_FLAG_MASK  (DEVICE_RELEASE_FLAG_RESET)

#define DEVICE_RECLAIM_FLAG_RESET (1U << 0)
#define DEVICE_RECLAIM_FLAG_MASK  (DEVICE_RECLAIM_FLAG_RESET)

#define DEVICE_NOTIFY_FLAG_DONATED  (1U << 0)
#define DEVICE_NOTIFY_FLAG_LENT	    (1U << 1)
#define DEVICE_NOTIFY_FLAG_RELEASED (1U << 2)
#define DEVICE_NOTIFY_FLAG_ACCEPTED (1U << 3)
#define DEVICE_NOTIFY_FLAG_RECALL   (1U << 4)
#define DEVICE_NOTIFY_FLAG_MASK                                                \
	(DEVICE_NOTIFY_FLAG_DONATED | DEVICE_NOTIFY_FLAG_LENT |                \
	 DEVICE_NOTIFY_FLAG_RELEASED | DEVICE_NOTIFY_FLAG_ACCEPTED |           \
	 DEVICE_NOTIFY_FLAG_RECALL)

#define DEVICE_GET_RESOURCES_FLAG_PHYSICAL (1U << 0)
#define DEVICE_GET_RESOURCES_FLAG_MASK	   (DEVICE_GET_RESOURCES_FLAG_PHYSICAL)

#define DEVICE_DONATE_FLAG_RESET (1U << 0)
#define DEVICE_DONATE_FLAG_MASK	 (DEVICE_DONATE_FLAG_RESET)

// Misc

#define DEVICE_MGR_INVALID_HANDLE ~(uint32_t)0U
// Each device in our nomenclature represents a PCIe function. Given a maximum
// of 32 devices per bus and 8 functions per devices, there can be up to 256
// devices per bus.
#define DEVICES_PER_BUS_MAX 256U
// Maximum distance between segments to support up to 128K buses.
#define DEVICE_HANDLE_MAX_SEGMENT_OFFS ((uint32_t)1U << 15)
// Start of platform physical device memory. This is used to intialize the
// mmio_ranges list which tracks memory ranges across all devices. To avoid
// specifying this per platform, we simply use the use the entire addressable
// memory range.
#define DEVICE_MGR_DEVMEM_START 0U
// Size of the physical memory range.
#define DEVICE_MGR_DEVMEM_SIZE (util_balign_down((~(uint64_t)0), PAGE_SIZE))

// Devices & buses

typedef uint32_t device_handle_t;

typedef enum {
	DEVICE_LEND_STATE_NONE,
	DEVICE_LEND_STATE_OFFERED_LEND,
	DEVICE_LEND_STATE_OFFERED_DONATE,
	DEVICE_LEND_STATE_OFFERED_RECLAIM,
	DEVICE_LEND_STATE_ACCEPTED
} device_lend_state_t;

typedef struct {
	cap_id_t	      capid;
	resource_descriptor_t resource;
} device_resource_t;

RM_PADDED(typedef struct {
	vmid_t		    owner;
	vmid_t		    borrower;
	device_handle_t	    handle;
	device_lend_state_t lend_state;
	cap_id_t	    me_cap;
	vector_t	   *mmio_regs;	     // items: device_resource_t
	vector_t	   *irqs;	     // items: device_resource_t
	vector_t	   *iommu_endpoints; // items: device_resource_t
	vector_t	   *msi_endpoints;   // items: device_resource_t
	vector_t	   *pcie_functions;  // items: device_resource_t
} device_t)

RM_PADDED(typedef struct {
	// Handles of devices attached to this bus. Devices may be either
	// virtual or physical, although purely virtual devices are not
	// supported yet.
	vector_t *device_handles; // items: device_handle_t
	// Virtual bus handle.
	uint32_t handle;
} bus_t)

RM_PADDED(typedef struct {
	// PCIe config space mmio
	uintptr_t cfg_space;
	size_t	  cfg_size;
	// Non-prefectchable memory range
	uintptr_t np_mem_base;
	size_t	  np_mem_size;
	// IO memory range
	uintptr_t io_mem_base;
	size_t	  io_mem_size;
	// Prefetchable memory range
	uintptr_t p_mem_base;
	size_t	  p_mem_size;
	// capID for pci_host
	cap_id_t pci_host_capid;
	// List of PCIe functions that contain BAR apertures
	// IPAs (programmed by HLOS) and their sizes
	vector_t *pci_functions; // items: pci_function_t
} pci_host_t)

RM_PADDED(typedef struct {
	// Devices attached to this bus.  For the time being, use the same
	// device type as virtual_bus_t. Once we get actual physical devices,
	// we will introduce a separate type.
	vector_t *devices; // items: device_t
	// Random base offset for this bus with device handle space. This offset
	// will be applied to the device index when generating a device handle.
	uint32_t rand_base;
	// Physical bu shandle. For now equivalent to rand_base, may change
	// in the future.
	uint32_t handle;
	// PCI Root Complex
	pci_host_t *pci_host; // presence dictates its a Root Complex
} host_bus_t)

RM_PADDED(typedef struct {
	device_t *device;
	index_t	  bus_index;
} device_lookup_result_t)

RM_PADDED(typedef struct {
	index_t	    index;
	host_bus_t *bus;
	error_t	    err;
} host_bus_lookup_result_t)

RM_PADDED(typedef struct {
	device_t *device;
	index_t	  index;
} device_find_result_t)

RM_PADDED(typedef struct {
	index_t index;
	error_t err;
} bus_add_result_t)

// Device requests and replies
//
typedef struct {
	device_handle_t handle;
	uint8_t		flags;
	uint8_t		res0[3];
	device_handle_t bus_handle;
} device_accept_req_t;

typedef struct {
	vmid_t		participant;
	uint8_t		flags;
	uint8_t		res0[1];
	device_handle_t handle;
} device_notify_accept_req_t;

typedef struct {
	vmid_t		vmid;
	uint8_t		flags;
	uint8_t		res0[1];
	device_handle_t handle;
} device_lend_req_t;

typedef device_lend_req_t device_donate_req_t;

typedef struct {
	vmid_t		owner;
	uint8_t		res0[2];
	device_handle_t handle;
} device_notify_lent_req_t;

typedef device_notify_lent_req_t device_notify_donate_req_t;

typedef struct {
	device_handle_t handle;
	uint8_t		flags;
	uint8_t		res0[3];
} device_release_req_t;

typedef struct {
	device_handle_t handle;
} device_notify_release_req_t;

typedef struct {
	device_handle_t handle;
	uint8_t		flags;
	uint8_t		res0[3];
} device_reclaim_req_t;

typedef struct {
	device_handle_t handle;
	uint8_t		flags;
	uint8_t		res0[1];
	vmid_t		req_vmid;
} device_notify_req_t;

typedef resource_descriptor_t device_find_handle_req_t;

typedef struct {
	device_handle_t handle;
} device_find_handle_reply_t;

typedef struct {
	device_handle_t handle;
	uint8_t		flags;
	uint8_t		res0[3];
} device_get_resources_req_t;

typedef struct {
	uint16_t num_entries;
	uint16_t res0[1];
} device_get_resources_rep_hdr_t;

typedef struct {
	vmid_t		owner;
	uint8_t		flags;
	uint8_t		res0[1];
	device_handle_t handle;
} device_notify_recall_req_t;

typedef device_handle_t device_bus_lockdown_req_t;
typedef device_handle_t device_bus_unlock_req_t;

#else

#error multiple include of device_manager-internal.h

#endif
