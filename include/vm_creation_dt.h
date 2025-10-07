// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_VM_CREATION_DT_H_
#define INCLUDE_VM_CREATION_DT_H_

error_t
vm_creation_add_compatibles(const struct vdevice_node *node,
			    const char *const	       compatibles[],
			    count_t compatible_cnt, dto_t *dto);

char *
vm_creation_node_name_capid(const char *generate, cap_id_t cap_id);

#else

#error multiple include of vm_creation_dt.h

#endif
