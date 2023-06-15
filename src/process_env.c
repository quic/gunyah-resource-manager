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

#include <qcbor/qcbor.h>

// Include after qcbor
#include <platform_env.h>
#include <rm_env_data.h>

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

bool
check_qcbor_char_string_array(const char *fname, qcbor_item_t *qcbor_item_ptr,
			      qcbor_dec_ctxt_t *qcbor_decode_ctxt,
			      uint32_t max_dest_bytes, char *dstp,
			      uint32_t *copied_bytesp)
{
	(void)qcbor_decode_ctxt;

	if (strncmp(qcbor_item_ptr->label.string.ptr, fname,
		    qcbor_item_ptr->label.string.len) == 0) {
		if (qcbor_item_ptr->uDataType == QCBOR_TYPE_TEXT_STRING) {
			uint32_t bytes_to_copy;

			bytes_to_copy =
				(uint32_t)qcbor_item_ptr->val.string.len;

			if (bytes_to_copy > max_dest_bytes) {
				bytes_to_copy = max_dest_bytes;
			}

			memcpy(dstp, qcbor_item_ptr->val.string.ptr,
			       bytes_to_copy);

			if (copied_bytesp) {
				*copied_bytesp = bytes_to_copy;
			}
			return true;
		}
	}
	return false;
}

// For multi-dimensional array. For now implemented for 2D array
static inline bool
check_qcbor_uint64_t_md_array(const char *fname, qcbor_item_t *qcbor_item_ptr,
			      qcbor_dec_ctxt_t *qcbor_decode_ctxt,
			      uint32_t max_array_cnt, uint32_t array_stride,
			      uint64_t *dstp, uint32_t *items_foundp)
{
	if (strncmp(qcbor_item_ptr->label.string.ptr, fname,
		    qcbor_item_ptr->label.string.len) == 0) {
		if (qcbor_item_ptr->uDataType == QCBOR_TYPE_ARRAY) {
			uint32_t data_cnt, idx = 0, start_nesting, out_item_cnt,
					   i;

			data_cnt      = qcbor_item_ptr->val.uCount;
			start_nesting = qcbor_item_ptr->uNestingLevel;

			out_item_cnt = max_array_cnt;

			if (data_cnt < out_item_cnt) {
				out_item_cnt = data_cnt;
			}

			while (idx < data_cnt) {
				if (QCBORDecode_GetNext(qcbor_decode_ctxt,
							qcbor_item_ptr) != 0) {
					break;
				}

				if ((qcbor_item_ptr->uDataType !=
				     QCBOR_TYPE_ARRAY) ||
				    (qcbor_item_ptr->val.uCount !=
				     array_stride)) {
					break;
				}

				for (i = 0; i < array_stride; ++i) {
					if (QCBORDecode_GetNext(
						    qcbor_decode_ctxt,
						    qcbor_item_ptr) != 0) {
						goto done;
					}

					if (idx < max_array_cnt) {
						qcbor_item_conv_uint64(
							qcbor_item_ptr);
						dstp[(idx * array_stride) + i] =
							(uint64_t)qcbor_item_ptr
								->val.uint64;
					}
				}

				++idx;
			}
		done:
			if (items_foundp) {
				*items_foundp = idx;
			}

			while (qcbor_item_ptr->uNextNestLevel > start_nesting) {
				if (QCBORDecode_GetNext(qcbor_decode_ctxt,
							qcbor_item_ptr) != 0) {
					break;
				}
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
		goto Exit;
	}

	if (env_hdr->signature != RM_ENV_DATA_SIGNATURE) {
		goto Exit;
	}

	// Set anything that needs all bits be set to 1's
	memset(&rm_env->vic_hwirq, 0xFF, sizeof(rm_env->vic_hwirq));
	memset(&rm_env->vic_msi_source, 0xFF, sizeof(rm_env->vic_msi_source));
	memset(&rm_env->gic_xlate_me, 0xFF, sizeof(rm_env->gic_xlate_me));

	rm_env->uart_me_capid = CSPACE_CAP_INVALID;

	cbor_data_ptr =
		(uint32_t *)(((uint32_t *)env_hdr) +
			     (env_hdr->data_payload_offset / sizeof(uint32_t)));
	cbor_data_size = env_hdr->data_payload_size;

	qcbor_dec_ctxt_t qcbor_decode_ctxt;
	qcbor_item_t	 qcbor_item;
	int		 nReturn = -1;

	QCBORDecode_Init(&qcbor_decode_ctxt,
			 (const_useful_buff_t){ cbor_data_ptr, cbor_data_size },
			 QCBOR_DECODE_MODE_MAP_STRINGS_ONLY);

	// Make sure the top level entry is a map
	if (QCBORDecode_GetNext(&qcbor_decode_ctxt, &qcbor_item) !=
		    QCBOR_SUCCESS ||
	    qcbor_item.uDataType != QCBOR_TYPE_MAP) {
		(void)nReturn;
		goto Exit;
	}

	while (1) {
		if (QCBORDecode_GetNext(&qcbor_decode_ctxt, &qcbor_item) !=
		    QCBOR_SUCCESS) {
			break;
		}
		qcbor_item_conv_uint64(&qcbor_item);

		if (qcbor_item.uLabelType == QCBOR_TYPE_TEXT_STRING) {
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
			if (process_qcbor_array_item(gic_xlate_me, &qcbor_item,
						     &qcbor_decode_ctxt, rm_env,
						     0)) {
				continue;
			}
			if (process_qcbor_array_item(smc_wqs, &qcbor_item,
						     &qcbor_decode_ctxt, rm_env,
						     0)) {
				continue;
			}
			if (process_qcbor_array_item(vic_hwirq, &qcbor_item,
						     &qcbor_decode_ctxt, rm_env,
						     0)) {
				continue;
			}
			if (process_qcbor_array_item(
				    vic_msi_source, &qcbor_item,
				    &qcbor_decode_ctxt, rm_env, 0)) {
				continue;
			}
			if (process_qcbor_md_array_item(
				    free_ranges, &qcbor_item,
				    &qcbor_decode_ctxt, rm_env,
				    &rm_env->free_ranges_count)) {
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
		while (qcbor_item.uNextNestLevel > 1) {
			if (QCBORDecode_GetNext(&qcbor_decode_ctxt,
						&qcbor_item) != QCBOR_SUCCESS) {
				break;
			}
		}
	}
Exit:
	return;
}
