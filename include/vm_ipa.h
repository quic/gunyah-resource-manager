// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_VM_IPA_H_
#define INCLUDE_VM_IPA_H_

bool
vm_ipa_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		   void *buf, size_t len);

#else

#error multiple include of vm_ipa.h

#endif
