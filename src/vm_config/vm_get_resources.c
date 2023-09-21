// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <utils/vector.h>

#include <memparcel.h>
#include <resource-manager.h>
#include <rm-rpc-fifo.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <vm_config.h>
#include <vm_mgnt_message.h>
#include <vm_resources.h>
// after vm_resources.h
#include <vm_creation.h>
#include <vm_resource_msg.h>

static void
vm_get_hyp_resources(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
		     void *buf, size_t len)
{
	rm_error_t ret;
	vmid_t	   vmid;

	if (len != 4U) {
		ret = RM_ERROR_MSG_INVALID;
		goto out;
	}

	uint8_t *buf8 = (uint8_t *)buf;
	vmid	      = (vmid_t)(buf8[0] | (buf8[1] << 8));

	// Lookup resources
	uint32_t resource_entries = 0;

	vector_t *descs = vector_init(rm_hyp_resource_resp_t, 16, 16);
	if (descs == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out_deinit;
	}

	ret = vm_config_get_resource_descs(client_id, vmid, descs);
	if (ret != RM_OK) {
		goto out_deinit;
	}

	resource_entries = (uint32_t)vector_size(descs);

	size_t resp_size = (2U * sizeof(uint32_t)) +
			   (resource_entries * sizeof(rm_hyp_resource_resp_t));
	char *resp = calloc(1, resp_size);
	if (resp == NULL) {
		ret = RM_ERROR_NOMEM;
		goto out_deinit;
	}

	memcpy(resp, &ret, sizeof(ret));
	memcpy(resp + sizeof(uint32_t), &resource_entries,
	       sizeof(resource_entries));
	(void)memcpy((void *)(resp + (2U * sizeof(uint32_t))),
		     vector_raw_data(descs),
		     resource_entries * sizeof(rm_hyp_resource_resp_t));

	rm_error_t rpc_err =
		rm_rpc_fifo_reply(client_id, msg_id, seq_num, resp, resp_size);
	// We cannot recover from errors here
	if (rpc_err != RM_OK) {
		(void)printf("get_hyp_resources: err(%d)\n", rpc_err);
		exit(1);
	}

out_deinit:
	if (descs != NULL) {
		vector_deinit(descs);
	}

out:
	if (ret != RM_OK) {
		rm_standard_reply(client_id, msg_id, seq_num, ret);
	}
}

bool
vm_get_resources_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num,
			 void *buf, size_t len)
{
	bool handled = false;

	if (client_id == VMID_HYP) {
		goto out;
	}

	switch (msg_id) {
	case VM_GET_HYP_RESOURCES:
		vm_get_hyp_resources(client_id, msg_id, seq_num, buf, len);
		handled = true;
		break;
	case VM_GET_HYP_CAPIDS:
		// FIXME: implement in v2
		break;
	case VM_GET_HYP_IRQS:
		// FIXME: implement in v2
		break;
	default:
		// not a get-resources message
		break;
	}

out:
	return handled;
}
