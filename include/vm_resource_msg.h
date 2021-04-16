// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef enum {
	RSC_DOORBELL_SRC   = 0,
	RSC_DOORBELL	   = 1,
	RSC_MSG_QUEUE_SEND = 2,
	RSC_MSG_QUEUE_RECV = 3,
	RSC_VIRTUAL_CPU	   = 4,
	RSC_VIRTUAL_PM	   = 5,
} resource_type_t;

typedef uint32_t resource_handle_t;
typedef uint32_t resource_label_t;

struct rm_hyp_resource_resp {
	uint8_t	 resource_type;
	uint8_t	 res0;
	uint16_t partner_vmid;

	resource_handle_t resource_handle;
	resource_label_t  resource_label;

	uint32_t resource_capid_low;
	uint32_t resource_capid_high;

	uint32_t resource_virq_handle;
	uint32_t resource_virq_number;
};

typedef struct rm_hyp_resource_resp rm_hyp_resource_resp_t;
