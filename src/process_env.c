// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>

#include <qcbor/qcbor.h>

// Include after qcbor
#include <platform_env.h>
#include <rm_env_data.h>
#include <vm_passthrough_config.h>

static inline void
qcbor_item_conv_uint64(qcbor_item_t *qcbor_item_ptr)
{
	switch (qcbor_item_ptr->uDataType) {
	case QCBOR_TYPE_TRUE:
		qcbor_item_ptr->val.uint64 = 1;
		qcbor_item_ptr->uDataType  = QCBOR_TYPE_UINT64;
		break;

	case QCBOR_TYPE_FALSE:
		qcbor_item_ptr->val.uint64 = 0;
		qcbor_item_ptr->uDataType  = QCBOR_TYPE_UINT64;
		break;

	case QCBOR_TYPE_UINT64:
		break;

	case QCBOR_TYPE_INT64:
		if (qcbor_item_ptr->val.int64 >= 0) {
			uint64_t data_val;
			data_val = (uint64_t)qcbor_item_ptr->val.int64;
			qcbor_item_ptr->val.uint64 = data_val;
			qcbor_item_ptr->uDataType  = QCBOR_TYPE_UINT64;
		} else {
			qcbor_item_ptr->uDataType = QCBOR_TYPE_NONE;
		}
		break;

	default:
		// leave other data types alone, like strings
		break;
	}
}

void
process_and_get_env_data(rm_env_data_hdr_t *env_hdr, rm_env_data_t *rm_env);

DEFINE_QCBOR_ITEM_HANDLER(bool)
DEFINE_QCBOR_ITEM_HANDLER(uint8_t)
DEFINE_QCBOR_ITEM_HANDLER(uint16_t)
DEFINE_QCBOR_ITEM_HANDLER(uint32_t)
DEFINE_QCBOR_ITEM_HANDLER(uint64_t)

DEFINE_QCBOR_ARRAY_ITEM_HANDLER(uint32_t)
DEFINE_QCBOR_ARRAY_ITEM_HANDLER(uint64_t)

DEFINE_QCBOR_MD_ARRAY_ITEM_HANDLER(uint32_t)
DEFINE_QCBOR_MD_ARRAY_ITEM_HANDLER(uint64_t)

// 1D array of vm_device_descriptor_t type where data of type "uint32_t" is
// decoded into the respective member. Can be used to decode a 1D array of dtype
// as well.
DEFINE_QCBOR_DYNAMIC_STRUCT_ARRAY_ITEM_HANDLER(vmid_t, vm_device_descriptor_t)
DEFINE_QCBOR_DYNAMIC_STRUCT_ARRAY_ITEM_HANDLER(uint32_t, vm_device_descriptor_t)
// 1D array of vm_device_descriptor_t type where another 1D array of type
// "uint32_t" or "uint64_t" is decoded into the respective member. Can be used
// to decode a generic 2D array as well, where the outer 1D array is a structure
// whose members are "count_t in_dimension" and a "dtype *data_ptr". Here
// *data_ptr points to the inner array.
DEFINE_QCBOR_DYNAMIC_MD_STRUCT_ARRAY_ITEM_HANDLER(uint32_t,
						  vm_device_descriptor_t,
						  uint32_t)
DEFINE_QCBOR_DYNAMIC_MD_STRUCT_ARRAY_ITEM_HANDLER(uint64_t,
						  vm_device_descriptor_t,
						  uint32_t)

// This API decodes the passthrough device assignments which is encode as a map.
// Add any enhancement into passthrough device assignments data structure here
// for decoding.
static inline bool
process_qcbor_map_vm_device_assignment(
	const char *fname, qcbor_item_t *qcbor_item_ptr,
	qcbor_dec_ctxt_t	*qcbor_decode_ctxt,
	vm_device_assignments_t *device_assignments)
{
	bool ret = false;
	if (strncmp(qcbor_item_ptr->label.string.ptr, fname,
		    qcbor_item_ptr->label.string.len) == 0) {
		if (qcbor_item_ptr->uDataType != (uint8_t)QCBOR_TYPE_MAP) {
			goto out;
		}

		while (1) {
			if (QCBORDecode_GetNext(qcbor_decode_ctxt,
						qcbor_item_ptr) !=
			    QCBOR_SUCCESS) {
				break;
			}
			qcbor_item_conv_uint64(qcbor_item_ptr);

			if (qcbor_item_ptr->uLabelType ==
			    (uint8_t)QCBOR_TYPE_TEXT_STRING) {
				if (process_qcbor_item(num_devices,
						       qcbor_item_ptr,
						       device_assignments)) {
					continue;
				}
				if (device_assignments->num_devices != 0U) {
					if (process_qcbor_dynamic_struct_array_item(
						    vmid, qcbor_item_ptr,
						    qcbor_decode_ctxt, 1,
						    device_assignments->devices,
						    0,
						    offsetof(
							    vm_device_descriptor_t,
							    vmid),
						    vm_device_descriptor_t)) {
						continue;
					}
					if (process_qcbor_dynamic_md_struct_array_item(
						    irqs, qcbor_item_ptr,
						    qcbor_decode_ctxt, 1,
						    device_assignments->devices,
						    0,
						    offsetof(
							    vm_device_descriptor_t,
							    irqs),
						    offsetof(
							    vm_device_descriptor_t,
							    num_irqs),
						    vm_device_descriptor_t)) {
						continue;
					}
					if (process_qcbor_dynamic_md_struct_array_item(
						    mmio_ranges, qcbor_item_ptr,
						    qcbor_decode_ctxt, 2,
						    device_assignments->devices,
						    0,
						    offsetof(
							    vm_device_descriptor_t,
							    mmio_ranges),
						    offsetof(
							    vm_device_descriptor_t,
							    num_mmio_ranges),
						    vm_device_descriptor_t)) {
						continue;
					}
				}
			} else {
				// Handle integer label types
			}

			// Something we don't know about, so get to next node
			// past this node
			while (qcbor_item_ptr->uNextNestLevel > 1U) {
				if (QCBORDecode_GetNext(qcbor_decode_ctxt,
							qcbor_item_ptr) !=
				    QCBOR_SUCCESS) {
					break;
				}
			}
		}
		ret = true;
	}
out:
	return ret;
}

bool
check_qcbor_char_string_array(const char *fname, qcbor_item_t *qcbor_item_ptr,
			      qcbor_dec_ctxt_t *qcbor_decode_ctxt,
			      uint32_t max_dest_bytes, char *dstp,
			      uint32_t *copied_bytesp)
{
	(void)qcbor_decode_ctxt;

	if (strncmp(qcbor_item_ptr->label.string.ptr, fname,
		    qcbor_item_ptr->label.string.len) == 0) {
		if (qcbor_item_ptr->uDataType ==
		    (uint8_t)QCBOR_TYPE_TEXT_STRING) {
			uint32_t bytes_to_copy;

			bytes_to_copy =
				(uint32_t)qcbor_item_ptr->val.string.len;

			if (bytes_to_copy > max_dest_bytes) {
				bytes_to_copy = max_dest_bytes;
			}

			(void)memcpy(
				dstp,
				(const char *)qcbor_item_ptr->val.string.ptr,
				bytes_to_copy);

			if (copied_bytesp != NULL) {
				*copied_bytesp = bytes_to_copy;
			}
			return true;
		}
	}
	return false;
}

void
process_and_get_env_data(rm_env_data_hdr_t *env_hdr, rm_env_data_t *rm_env)
{
	uint32_t *cbor_data_ptr, cbor_data_size;

	if ((env_hdr == NULL) || (rm_env == NULL)) {
		goto exit;
	}

	if (env_hdr->signature != (uint32_t)RM_ENV_DATA_SIGNATURE) {
		goto exit;
	}

	rm_irq_env_data_t *irq_env = malloc(sizeof(*irq_env));
	assert(irq_env != NULL);

	rm_env->irq_env = irq_env;

	vm_device_assignments_t *device_assignments =
		calloc(1, sizeof(*device_assignments));
	assert(device_assignments != NULL);
	rm_env->device_assignments = device_assignments;

	// Set anything that needs all bits be set to 1's
	for (index_t i = 0; i < util_array_size(irq_env->vic_hwirq); i++) {
		irq_env->vic_hwirq[i] = CSPACE_CAP_INVALID;
	}
	for (index_t i = 0; i < util_array_size(irq_env->vic_msi_source); i++) {
		irq_env->vic_msi_source[i] = CSPACE_CAP_INVALID;
	}
	rm_env->addrspace_capid = CSPACE_CAP_INVALID;
	rm_env->vcpu_capid	= CSPACE_CAP_INVALID;
	rm_env->device_me_capid = CSPACE_CAP_INVALID;
	rm_env->partition_capid = CSPACE_CAP_INVALID;
	rm_env->cspace_capid	= CSPACE_CAP_INVALID;
	rm_env->me_capid	= CSPACE_CAP_INVALID;
	rm_env->smc_wqs[0]	= CSPACE_CAP_INVALID;
	rm_env->smc_wqs[1]	= CSPACE_CAP_INVALID;
	rm_env->vic		= CSPACE_CAP_INVALID;
	rm_env->uart_me_capid	= CSPACE_CAP_INVALID;

	cbor_data_ptr =
		(uint32_t *)(((uint32_t *)env_hdr) +
			     (env_hdr->data_payload_offset / sizeof(uint32_t)));
	cbor_data_size = env_hdr->data_payload_size;

	qcbor_dec_ctxt_t qcbor_decode_ctxt;
	qcbor_item_t	 qcbor_item;
	int32_t		 nReturn = -1;

	QCBORDecode_Init(&qcbor_decode_ctxt,
			 (const_useful_buff_t){ cbor_data_ptr, cbor_data_size },
			 QCBOR_DECODE_MODE_MAP_STRINGS_ONLY);

	// Make sure the top level entry is a map
	if (QCBORDecode_GetNext(&qcbor_decode_ctxt, &qcbor_item) !=
		    QCBOR_SUCCESS ||
	    qcbor_item.uDataType != (uint8_t)QCBOR_TYPE_MAP) {
		(void)nReturn;
		goto exit;
	}

	while (1) {
		if (QCBORDecode_GetNext(&qcbor_decode_ctxt, &qcbor_item) !=
		    QCBOR_SUCCESS) {
			break;
		}
		qcbor_item_conv_uint64(&qcbor_item);

		if (qcbor_item.uLabelType == (uint8_t)QCBOR_TYPE_TEXT_STRING) {
			// FIXME:
			// Consider using a hash table.

			if (process_qcbor_item(addrspace_capid, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(cspace_capid, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(device_me_base, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(vcpu_capid, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(device_me_capid, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(device_me_size, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(entry_hlos, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(hlos_dt_base, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(ipa_offset, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(me_capid, &qcbor_item, rm_env)) {
				continue;
			}
			if (process_qcbor_item(me_ipa_base, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(me_size, &qcbor_item, rm_env)) {
				continue;
			}
			if (process_qcbor_item(mpd_region_addr, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(mpd_region_size, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(partition_capid, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(uart_address, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(uart_me_capid, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(usable_cores, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(vic, &qcbor_item, rm_env)) {
				continue;
			}
			if (process_qcbor_item(wdt_address, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(boot_core, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(sve_supported, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(watchdog_supported, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(hlos_handles_ras, &qcbor_item,
					       rm_env)) {
				continue;
			}

			if (process_qcbor_item(hlos_vm_base, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(hlos_vm_size, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(hlos_ramfs_base, &qcbor_item,
					       rm_env)) {
				continue;
			}

			if (process_qcbor_array_item(
				    reserved_dev_irq, &qcbor_item,
				    &qcbor_decode_ctxt, rm_env,
				    &rm_env->num_reserved_dev_irqs)) {
				continue;
			}
			if (process_qcbor_array_item(smc_wqs, &qcbor_item,
						     &qcbor_decode_ctxt, rm_env,
						     0)) {
				continue;
			}
			if (process_qcbor_array_item(vic_hwirq, &qcbor_item,
						     &qcbor_decode_ctxt,
						     irq_env, 0)) {
				continue;
			}
			if (process_qcbor_array_item(
				    vic_msi_source, &qcbor_item,
				    &qcbor_decode_ctxt, irq_env, 0)) {
				continue;
			}
			if (process_qcbor_md_array_item(
				    free_ranges, &qcbor_item,
				    &qcbor_decode_ctxt, rm_env, 2,
				    &rm_env->free_ranges_count, 0, uint64_t)) {
				continue;
			}
			if (process_qcbor_map_vm_device_assignment(
				    "vm_device_assignments", &qcbor_item,
				    &qcbor_decode_ctxt, device_assignments)) {
				continue;
			}
			if (platform_process_qcbor_items(&qcbor_item,
							 &qcbor_decode_ctxt)) {
				continue;
			}

		} else {
			// Handle integer label types
		}

		// Something we don't know about, so get to next node past this
		// node
		while (qcbor_item.uNextNestLevel > 1U) {
			if (QCBORDecode_GetNext(&qcbor_decode_ctxt,
						&qcbor_item) != QCBOR_SUCCESS) {
				break;
			}
		}
	}
exit:
	return;
}
