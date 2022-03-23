// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

struct vcpu {
	// Cap in RM's cspace
	cap_id_t master_cap;

	// Possibly turn this into a list of tuples (vmid, cap)
	cap_id_t owner_cap;
	cap_id_t vm_cap;

	uint32_t affinity_index;

	bool  boot_vcpu;
	char *patch;
};
typedef struct vcpu vcpu_t;

#pragma clang diagnostic pop
