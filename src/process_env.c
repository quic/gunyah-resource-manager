// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
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

#include <compiler.h>
#include <guest_interface.h>
#include <irq_arch.h>
#include <panic.h>
#include <qcbor/qcbor.h>
#include <resource-manager.h>

// Include after qcbor
#include <platform_env.h>
#include <rm_env_data.h>
#include <vm_passthrough_config.h>

void
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

	case QCBOR_TYPE_INT64: {
		uint64_t data_val;
		// CBOR decode uses QCBOR_TYPE_INT64 for positive integers that
		// are less or equal to INT64_MAX, or negative values.
		// We simply cast to unsigned (including negative values which
		// are useful, for example ~0UL encoded as INT64 uses one byte,
		// vs 9-bytes for unsigned in CBOR).
		data_val = (uint64_t)qcbor_item_ptr->val.int64;
		qcbor_item_ptr->val.uint64 = data_val;
		qcbor_item_ptr->uDataType  = QCBOR_TYPE_UINT64;
		break;
	}

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

DEFINE_QCBOR_ARRAY_CREATE_DYNAMIC_ITEM_HANDLER(uint64_t)
DEFINE_QCBOR_ARRAY_CREATE_DYNAMIC_ITEM_HANDLER(uint32_t)

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

static inline bool
process_qcbor_map_smmu_v2_env(const char *fname, qcbor_item_t *qcbor_item_ptr,
			      qcbor_dec_ctxt_t *qcbor_decode_ctxt,
			      rm_env_data_t    *rm_env)
{
	bool		    ret	     = false;
	rm_smmu_env_data_t *smmu_env = NULL;

	if (qcbor_item_ptr->uDataType != (uint8_t)QCBOR_TYPE_ARRAY) {
		goto out;
	}

	if (strncmp(qcbor_item_ptr->label.string.ptr, fname,
		    qcbor_item_ptr->label.string.len) != 0) {
		goto out;
	}

	count_t start_nesting, data_cnt;
	start_nesting = qcbor_item_ptr->uNestingLevel;
	data_cnt      = qcbor_item_ptr->val.uCount;

	smmu_env = (rm_smmu_env_data_t *)calloc(data_cnt, sizeof(*smmu_env));
	assert(smmu_env != NULL);

	// The SMMUv2 environment is encoded as an array of tuples, containing
	// the cap ID and the SMMU address.
	for (count_t idx = 0; idx < data_cnt; idx++) {
		if (QCBORDecode_GetNext(qcbor_decode_ctxt, qcbor_item_ptr) !=
		    QCBOR_SUCCESS) {
			goto out;
		}

		if ((qcbor_item_ptr->uDataType != (uint8_t)QCBOR_TYPE_ARRAY) ||
		    (qcbor_item_ptr->val.uCount != 2U)) {
			goto out_skip;
		}

		if (QCBORDecode_GetNext(qcbor_decode_ctxt, qcbor_item_ptr) !=
		    QCBOR_SUCCESS) {
			goto out;
		}

		qcbor_item_conv_uint64(qcbor_item_ptr);

		if (qcbor_item_ptr->uDataType != (uint8_t)QCBOR_TYPE_UINT64) {
			goto out_skip;
		}
		smmu_env[idx].smmuv2_cap = qcbor_item_ptr->val.uint64;

		if (QCBORDecode_GetNext(qcbor_decode_ctxt, qcbor_item_ptr) !=
		    QCBOR_SUCCESS) {
			goto out;
		}
		qcbor_item_conv_uint64(qcbor_item_ptr);

		if (qcbor_item_ptr->uDataType != (uint8_t)QCBOR_TYPE_UINT64) {
			goto out_skip;
		}
		smmu_env[idx].smmu_addr = qcbor_item_ptr->val.uint64;
	}

	rm_env->num_v2_smmu = data_cnt;
	rm_env->smmuv2_env  = smmu_env;
	ret		    = true;

out_skip:
	while (qcbor_item_ptr->uNextNestLevel > start_nesting) {
		if (QCBORDecode_GetNext(qcbor_decode_ctxt, qcbor_item_ptr) !=
		    QCBOR_SUCCESS) {
			break;
		}
	}
out:
	if (!ret && (smmu_env != NULL)) {
		free(smmu_env);
	}

	return ret;
}

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

	if (qcbor_item_ptr->uDataType != (uint8_t)QCBOR_TYPE_MAP) {
		goto out;
	}
	if (strncmp(qcbor_item_ptr->label.string.ptr, fname,
		    qcbor_item_ptr->label.string.len) != 0) {
		goto out;
	}

	count_t start_nesting = qcbor_item_ptr->uNestingLevel;

	while (qcbor_item_ptr->uNextNestLevel > start_nesting) {
		if (QCBORDecode_GetNext(qcbor_decode_ctxt, qcbor_item_ptr) !=
		    QCBOR_SUCCESS) {
			goto out;
		}
		qcbor_item_conv_uint64(qcbor_item_ptr);

		if (qcbor_item_ptr->uLabelType !=
		    (uint8_t)QCBOR_TYPE_TEXT_STRING) {
			// Not a string-labelled map element; skip
			continue;
		}

		if (process_qcbor_item(num_devices, qcbor_item_ptr,
				       device_assignments)) {
			continue;
		}

		if (process_qcbor_dynamic_struct_array_item(
			    vmid, qcbor_item_ptr, qcbor_decode_ctxt, 1,
			    device_assignments->devices, 0,
			    offsetof(vm_device_descriptor_t, vmid),
			    vm_device_descriptor_t)) {
			continue;
		}

		if (process_qcbor_dynamic_md_struct_array_item(
			    irqs, qcbor_item_ptr, qcbor_decode_ctxt, 1,
			    device_assignments->devices, 0,
			    offsetof(vm_device_descriptor_t, irqs),
			    offsetof(vm_device_descriptor_t, num_irqs),
			    vm_device_descriptor_t)) {
			continue;
		}

		if (process_qcbor_dynamic_md_struct_array_item(
			    mmio_ranges, qcbor_item_ptr, qcbor_decode_ctxt, 2,
			    device_assignments->devices, 0,
			    offsetof(vm_device_descriptor_t, mmio_ranges),
			    offsetof(vm_device_descriptor_t, num_mmio_ranges),
			    vm_device_descriptor_t)) {
			continue;
		}

		// Unknown item; consume its child nodes, if any
		while (qcbor_item_ptr->uNextNestLevel > (start_nesting + 1U)) {
			if (QCBORDecode_GetNext(qcbor_decode_ctxt,
						qcbor_item_ptr) !=
			    QCBOR_SUCCESS) {
				goto out;
			}
		}
	}
	ret = true;

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

	bool res;

	if (qcbor_item_ptr->label.string.len == 0U) {
		res = false;
		goto out;
	}

	if (strncmp(qcbor_item_ptr->label.string.ptr, fname,
		    qcbor_item_ptr->label.string.len) == 0) {
		if (qcbor_item_ptr->uDataType ==
		    (uint8_t)QCBOR_TYPE_TEXT_STRING) {
			uint32_t bytes_to_copy;

			bytes_to_copy =
				(uint32_t)qcbor_item_ptr->val.string.len;

			(void)memscpy(
				dstp, max_dest_bytes,
				(const char *)qcbor_item_ptr->val.string.ptr,
				bytes_to_copy);

			if (copied_bytesp != NULL) {
				*copied_bytesp = bytes_to_copy;
			}
			res = true;
			goto out;
		}
	}
	res = false;

out:
	return res;
}

bool
check_qcbor_char_string_array_create_dynamic(
	const char *fname, const qcbor_item_t *qcbor_item_ptr,
	qcbor_dec_ctxt_t *qcbor_decode_ctxt, char **dstp,
	uint32_t *copied_bytesp)
{
	(void)qcbor_decode_ctxt;

	bool res;

	if (qcbor_item_ptr->label.string.len == 0U) {
		res = false;
		goto out;
	}

	if (strncmp(qcbor_item_ptr->label.string.ptr, fname,
		    qcbor_item_ptr->label.string.len) == 0) {
		if (qcbor_item_ptr->uDataType ==
		    (uint8_t)QCBOR_TYPE_TEXT_STRING) {
			size_t bytes_to_copy;

			bytes_to_copy = (size_t)qcbor_item_ptr->val.string.len;

			*dstp = (char *)calloc(bytes_to_copy + 1U,
					       sizeof(char));

			if (*dstp != NULL) {
				(void)memscpy(*dstp, bytes_to_copy,
					      (const char *)qcbor_item_ptr->val
						      .string.ptr,
					      bytes_to_copy);

				if (copied_bytesp != NULL) {
					*copied_bytesp =
						(uint32_t)bytes_to_copy;
				}
				res = true;
				goto out;
			} else {
				res = false;
				goto out;
			}
		}
	}
	res = false;

out:
	return res;
}

static void
validate_env_data(rm_env_data_t *rm_env)
{
	cpu_index_t max_core   = 0U;
	bool	    cpus_found = false;

	assert(rm_env->free_ranges_count <=
	       util_array_size(rm_env->free_ranges));
	assert(rm_env->device_ranges_count <=
	       util_array_size(rm_env->device_ranges));

	for (count_t i = 0; i < util_array_size(rm_env->usable_cores); i++) {
		if (rm_env->usable_cores[i] == 0UL) {
			continue;
		}
		cpus_found = true;

		count_t core_bits =
			(count_t)sizeof(rm_env->usable_cores[i]) * 8U;
		cpu_index_t core_i =
			((cpu_index_t)core_bits) -
			(cpu_index_t)compiler_clz(rm_env->usable_cores[i]);

		max_core = (cpu_index_t)(i * core_bits) + core_i;
	}
	if (!cpus_found) {
		panic("no cores found in rm_env");
	}

	if (rm_env->max_cores == 0U) {
		(void)printf("no max_cores found in rm_env\n");
		rm_env->max_cores = (count_t)max_core + 1U;
	}
	if (rm_env->boot_core == CPU_INDEX_INVALID) {
		(void)printf("no boot_core found in rm_env\n");
		rm_env->boot_core = 0U;
	}
	if (!rm_is_core_usable(rm_env->boot_core)) {
		panic("invalid boot_core");
	}

	if (rm_env->device_ranges_count == 0U) {
		panic("no io-memory found in rm_env\n");
	}

	platform_validate_env_data(rm_env->platform_env);
}

// Extended PPIs and SPIs can be encoded as sparse ranges:
//     "vic_hwirq_ranges": [ {
//                    "i": X,          # The starting IRQ number index
//                    "caps": [...]    # List of hwirq caps starting from 'i'
//                 }, {
//                     "i": Y
//                     "caps": [...]
//                 }, ...
//             ]
static bool
process_qcbor_vic_hwirq_ranges(qcbor_item_t	*qcbor_item_ptr,
			       qcbor_dec_ctxt_t *qcbor_decode_ctxt,
			       uint64_t *vic_hwirq, uint32_t max_array_cnt)
{
	bool ret = false;
	if ((strncmp(qcbor_item_ptr->label.string.ptr, "vic_hwirq_ranges",
		     qcbor_item_ptr->label.string.len) == 0) &&
	    (qcbor_item_ptr->uDataType == (uint8_t)QCBOR_TYPE_ARRAY)) {
		uint32_t data_cnt, idx = 0U, start_nesting;

		data_cnt      = qcbor_item_ptr->val.uCount;
		start_nesting = qcbor_item_ptr->uNestingLevel;

		index_t range_start = 0U;

		while (idx < data_cnt) {
			// Make sure there's a map
			if ((QCBORDecode_GetNext(qcbor_decode_ctxt,
						 qcbor_item_ptr) !=
			     QCBOR_SUCCESS) ||
			    (qcbor_item_ptr->uDataType !=
			     (uint8_t)QCBOR_TYPE_MAP)) {
				break;
			}

			// Get Range Start
			if (QCBORDecode_GetNext(qcbor_decode_ctxt,
						qcbor_item_ptr) !=
			    QCBOR_SUCCESS) {
				break;
			}
			if (!check_qcbor_uint32_t("i", qcbor_item_ptr,
						  &range_start)) {
				break;
			}

			if (range_start >= max_array_cnt) {
				(void)printf("irq out of range\n");
				break;
			}

			// Get Range Hwirqs Array
			if (QCBORDecode_GetNext(qcbor_decode_ctxt,
						qcbor_item_ptr) !=
			    QCBOR_SUCCESS) {
				break;
			}
			if (!check_qcbor_uint64_t_array(
				    "caps", qcbor_item_ptr, qcbor_decode_ctxt,
				    util_min(1024U,
					     max_array_cnt - range_start),
				    &vic_hwirq[range_start], NULL)) {
				break;
			}

			// De-Nest out of map
			while (qcbor_item_ptr->uNextNestLevel >
			       (start_nesting + 1U)) {
				if (QCBORDecode_GetNext(qcbor_decode_ctxt,
							qcbor_item_ptr) !=
				    QCBOR_SUCCESS) {
					break;
				}
			}

			idx++;
		}

		// De-Nest to Starting level
		while (qcbor_item_ptr->uNextNestLevel > start_nesting) {
			if (QCBORDecode_GetNext(qcbor_decode_ctxt,
						qcbor_item_ptr) !=
			    QCBOR_SUCCESS) {
				break;
			}
		}

		if (idx == data_cnt) {
			ret = true;
		} else {
			(void)printf("vic_hwirq_ranges parse error\n");
		}
	}

	return ret;
}

bool
process_qcbor_range64_array(const char *fname, qcbor_item_t *qcbor_item_ptr,
			    qcbor_dec_ctxt_t *qcbor_decode_ctxt,
			    count_t max_array_cnt, rm_range64_t *items,
			    count_t *items_foundp)
{
	bool ret = false;

	if (strncmp(qcbor_item_ptr->label.string.ptr, fname,
		    qcbor_item_ptr->label.string.len) != 0) {
		goto out;
	}

	if (qcbor_item_ptr->uDataType != (uint8_t)QCBOR_TYPE_ARRAY) {
		goto out;
	}

	ret = true;

	count_t data_cnt, start_nesting;

	data_cnt      = qcbor_item_ptr->val.uCount;
	start_nesting = qcbor_item_ptr->uNestingLevel;

	for (count_t idx = 0U; (idx < data_cnt) && (idx < max_array_cnt);
	     idx++) {
		if (QCBORDecode_GetNext(qcbor_decode_ctxt, qcbor_item_ptr) !=
		    QCBOR_SUCCESS) {
			goto out;
		}

		if ((qcbor_item_ptr->uDataType != (uint8_t)QCBOR_TYPE_ARRAY) ||
		    (qcbor_item_ptr->val.uCount != 2U)) {
			goto out_skip;
		}

		if (QCBORDecode_GetNext(qcbor_decode_ctxt, qcbor_item_ptr) !=
		    QCBOR_SUCCESS) {
			goto out;
		}

		if ((qcbor_item_ptr->uDataType != (uint8_t)QCBOR_TYPE_UINT64) &&
		    (qcbor_item_ptr->uDataType != (uint8_t)QCBOR_TYPE_INT64)) {
			goto out_skip;
		}
		items[idx].base = qcbor_item_ptr->val.uint64;

		if (QCBORDecode_GetNext(qcbor_decode_ctxt, qcbor_item_ptr) !=
		    QCBOR_SUCCESS) {
			goto out;
		}

		if (qcbor_item_ptr->uDataType != (uint8_t)QCBOR_TYPE_INT64) {
			goto out_skip;
		}
		items[idx].size = (uint32_t)qcbor_item_ptr->val.uint64;
	}

	if (items_foundp != NULL) {
		*items_foundp = data_cnt;
	}

out_skip:
	while (qcbor_item_ptr->uNextNestLevel > start_nesting) {
		if (QCBORDecode_GetNext(qcbor_decode_ctxt, qcbor_item_ptr) !=
		    QCBOR_SUCCESS) {
			break;
		}
	}

out:
	return ret;
}

void
process_and_get_env_data(rm_env_data_hdr_t *env_hdr, rm_env_data_t *rm_env)
{
	uint32_t *cbor_data_ptr, cbor_data_size;

	assert(env_hdr != NULL);
	assert(rm_env != NULL);

	if (env_hdr->signature != (uint32_t)RM_ENV_DATA_SIGNATURE) {
		panic("invalid env");
	}

	rm_irq_env_data_t *irq_env = malloc(sizeof(*irq_env));
	if (irq_env == NULL) {
		panic("no memory");
	}
	assert(irq_env != NULL);
	irq_env->vic_hwirq = malloc(sizeof(cap_id_t) * VIC_HWIRQ_SIZE);
	if (irq_env->vic_hwirq == NULL) {
		panic("no memory");
	}

	rm_env->irq_env = irq_env;

	vm_device_assignments_t *device_assignments =
		calloc(1, sizeof(*device_assignments));
	assert(device_assignments != NULL);
	rm_env->device_assignments = device_assignments;

	// Set anything that needs all bits be set to 1's
	for (index_t i = 0; i < VIC_HWIRQ_SIZE; i++) {
		irq_env->vic_hwirq[i] = CSPACE_CAP_INVALID;
	}
	for (index_t i = 0; i < util_array_size(rm_env->its_caps); i++) {
		rm_env->its_caps[i] = CSPACE_CAP_INVALID;
	}
	for (index_t i = 0U; i < util_array_size(rm_env->smmuv3_caps); i++) {
		rm_env->smmuv3_caps[i] = CSPACE_CAP_INVALID;
	}
	rm_env->addrspace_capid	   = CSPACE_CAP_INVALID;
	rm_env->vcpu_capid	   = CSPACE_CAP_INVALID;
	rm_env->device_me_capid	   = CSPACE_CAP_INVALID;
	rm_env->partition_capid	   = CSPACE_CAP_INVALID;
	rm_env->cspace_capid	   = CSPACE_CAP_INVALID;
	rm_env->me_capid	   = CSPACE_CAP_INVALID;
	rm_env->smc_wqs[0]	   = CSPACE_CAP_INVALID;
	rm_env->vic		   = CSPACE_CAP_INVALID;
	rm_env->vic_max_virqs	   = (count_t)GIC_SPI_NUM;
	rm_env->uart_me_capid	   = CSPACE_CAP_INVALID;
	rm_env->trace_dbl_capid	   = CSPACE_CAP_INVALID;
	rm_env->trace_me_capid	   = CSPACE_CAP_INVALID;
	rm_env->system_power_capid = CSPACE_CAP_INVALID;

	rm_env->boot_core = CPU_INDEX_INVALID;

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
	if ((QCBORDecode_GetNext(&qcbor_decode_ctxt, &qcbor_item) !=
	     QCBOR_SUCCESS) ||
	    (qcbor_item.uDataType != (uint8_t)QCBOR_TYPE_MAP)) {
		(void)nReturn;
		panic("env corrupt");
	}

	while (1) {
		if (QCBORDecode_GetNext(&qcbor_decode_ctxt, &qcbor_item) !=
		    QCBOR_SUCCESS) {
			break;
		}
		qcbor_item_conv_uint64(&qcbor_item);

		if (qcbor_item.uLabelType == (uint8_t)QCBOR_TYPE_TEXT_STRING) {
			// FIXME: QC RM issue #24
			// Consider using a hash table.

			if (process_qcbor_item(addrspace_capid, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(cspace_capid, &qcbor_item,
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
			if (process_qcbor_item(trace_dbl_capid, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(trace_me_capid, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(trace_phys, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(trace_size, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(system_power_capid, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(system_suspend, &qcbor_item,
					       rm_env)) {
				continue;
			}

			static_assert(
				sizeof(rm_env->usable_cores) >=
					(2U * sizeof(rm_env->usable_cores[0])),
				"rm_env->usable_cores array too small");

			struct {
				uint64_t usable_cores;
			} item1;

			if (process_qcbor_item(usable_cores, &qcbor_item,
					       &item1)) {
				rm_env->usable_cores[0] = item1.usable_cores;
				continue;
			}

			struct {
				uint64_t usable_cores_ext[1];
			} item2;

			uint32_t nwords = 0;
			if (process_qcbor_array_item(
				    usable_cores_ext, &qcbor_item,
				    &qcbor_decode_ctxt, &item2, &nwords)) {
				for (count_t i = 0; i < nwords; i++) {
					assert(i <
					       (ARRAY_SIZE(
							rm_env->usable_cores) -
						1U));
					rm_env->usable_cores[i + 1U] =
						item2.usable_cores_ext[i];
				}
				continue;
			}
			if (process_qcbor_item(max_cores, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(vic, &qcbor_item, rm_env)) {
				continue;
			}
			if (process_qcbor_item(vic_max_virqs, &qcbor_item,
					       rm_env)) {
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
			if (process_qcbor_item(sme_supported, &qcbor_item,
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
			if (process_qcbor_item(sdei_supported, &qcbor_item,
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
			if (process_qcbor_item(scheduler_default_timeslice,
					       &qcbor_item, rm_env)) {
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
						     &rm_env->smc_wqs_count)) {
				continue;
			}
			if (process_qcbor_array_item_explicit_size(
				    vic_hwirq, &qcbor_item, &qcbor_decode_ctxt,
				    irq_env, 0, VIC_HWIRQ_SIZE)) {
				continue;
			}
			if (process_qcbor_vic_hwirq_ranges(
				    &qcbor_item, &qcbor_decode_ctxt,
				    irq_env->vic_hwirq, VIC_HWIRQ_SIZE)) {
				continue;
			}
			if (process_qcbor_array_item(its_caps, &qcbor_item,
						     &qcbor_decode_ctxt, rm_env,
						     0)) {
				continue;
			}
			if (process_qcbor_array_item(smmuv3_caps, &qcbor_item,
						     &qcbor_decode_ctxt, rm_env,
						     0)) {
				continue;
			}
			if (process_qcbor_md_array_item(
				    free_ranges, &qcbor_item,
				    &qcbor_decode_ctxt, rm_env, 2,
				    &rm_env->free_ranges_count, 0, uint64_t)) {
				continue;
			}
			if (process_qcbor_md_array_item(
				    device_ranges, &qcbor_item,
				    &qcbor_decode_ctxt, rm_env, 2,
				    &rm_env->device_ranges_count, 0,
				    uint64_t)) {
				continue;
			}
			if (process_qcbor_map_vm_device_assignment(
				    "vm_device_assignments", &qcbor_item,
				    &qcbor_decode_ctxt, device_assignments)) {
				continue;
			}
			if (process_qcbor_map_smmu_v2_env(
				    "smmuv2_caps", &qcbor_item,
				    &qcbor_decode_ctxt, rm_env)) {
				continue;
			}
			if (process_qcbor_item(gicd_base, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_item(gicr_stride, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_range64_array(
				    "gicr_ranges", &qcbor_item,
				    &qcbor_decode_ctxt,
				    util_array_size(rm_env->gicr_ranges),
				    rm_env->gicr_ranges,
				    &rm_env->gicr_ranges_count)) {
				continue;
			}
			if (process_qcbor_item(gits_stride, &qcbor_item,
					       rm_env)) {
				continue;
			}
			if (process_qcbor_range64_array(
				    "gits_ranges", &qcbor_item,
				    &qcbor_decode_ctxt,
				    util_array_size(rm_env->gits_ranges),
				    rm_env->gits_ranges,
				    &rm_env->gits_ranges_count)) {
				continue;
			}
			if (process_qcbor_array_item(
				    gic_xlate_me, &qcbor_item,
				    &qcbor_decode_ctxt, rm_env,
				    &rm_env->gic_xlate_me_count)) {
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

	validate_env_data(rm_env);
}
