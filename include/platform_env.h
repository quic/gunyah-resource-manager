// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

// clang-format off

#define process_qcbor_md_array_item(n, ip, ctxp, ep, as, ocp, icp, dtype)  (_Generic((ep->n), \
	boot_env_phys_range_t *: check_qcbor_md_uint64_t_array                                \
)(#n, ip, ctxp, ARRAY_SIZE(ep->n), (dtype *)ep->n, as, ocp, icp))

// Handles decoding of 1D array or 1D structure array where the data is decoded
// into the member of structure.
#define process_qcbor_dynamic_struct_array_item(n, ip, ctxp, tm, ep, cp, mo, stype)  (_Generic((ep->n), \
	uint32_t: check_qcbor_dynamic_##stype##_uint32_t_array,                               \
	vmid_t: check_qcbor_dynamic_##stype##_vmid_t_array                                    \
)(#n, ip, ctxp, tm, &ep, cp, mo))

// Handles of 2D array
#define process_qcbor_dynamic_md_struct_array_item(n, ip, ctxp, tm, ep, cp, amo, cmo, stype)  (_Generic((ep->n), \
	uint32_t*: check_qcbor_dynamic_md_##stype##_uint32_t_array,                           \
	root_env_mmio_range_descriptor_t*: check_qcbor_dynamic_md_##stype##_uint64_t_array    \
)(#n, ip, ctxp, tm, &ep, cp, amo, cmo))

bool
check_qcbor_char_string_array(const char *fname, qcbor_item_t *qcbor_item_ptr,
			      qcbor_dec_ctxt_t *qcbor_decode_ctxt,
			      uint32_t max_dest_bytes, char *dstp,
			      uint32_t *copied_bytesp);

#define process_qcbor_array_item(n, ip, ctxp, ep, cp)  (_Generic((ep->n),    \
      char*: check_qcbor_char_string_array,                                  \
      uint32_t*: check_qcbor_uint32_t_array,                                 \
      uint64_t*: check_qcbor_uint64_t_array                                  \
   )(#n, ip, ctxp, ARRAY_SIZE(ep->n), ep->n, cp))

// signed integers are not supported, written only for unsigned integers
#define process_qcbor_item(n, ip, ep)  (_Generic((ep->n),                    \
      uint8_t: check_qcbor_uint8_t,                                          \
      uint16_t: check_qcbor_uint16_t,                                        \
      uint32_t: check_qcbor_uint32_t,                                        \
      uint64_t: check_qcbor_uint64_t,                                        \
      bool: check_qcbor_bool                                                 \
   )(#n, ip, &ep->n))
// clang-format on

#define DECLARE_QCBOR_ITEM_HANDLER(dtype)                                      \
	bool check_qcbor_##dtype(const char   *fname,                          \
				 qcbor_item_t *qcbor_item_ptr, dtype *dstp);

#define DEFINE_QCBOR_ITEM_HANDLER(dtype)                                       \
	bool check_qcbor_##dtype(const char   *fname,                          \
				 qcbor_item_t *qcbor_item_ptr, dtype *dstp)    \
	{                                                                      \
		if (strncmp(qcbor_item_ptr->label.string.ptr, fname,           \
			    qcbor_item_ptr->label.string.len) == 0) {          \
			qcbor_item_conv_uint64(qcbor_item_ptr);                \
			if (qcbor_item_ptr->uDataType == QCBOR_TYPE_UINT64) {  \
				*dstp = (dtype)qcbor_item_ptr->val.uint64;     \
				return true;                                   \
			}                                                      \
		}                                                              \
		return false;                                                  \
	}

#define DECLARE_QCBOR_ARRAY_ITEM_HANDLER(dtype)                                \
	bool check_qcbor_##dtype##_array(const char	  *fname,              \
					 qcbor_item_t	  *qcbor_item_ptr,     \
					 qcbor_dec_ctxt_t *qcbor_decode_ctxt,  \
					 uint32_t max_array_cnt, dtype *dstp,  \
					 uint32_t *items_foundp);

#define DEFINE_QCBOR_ARRAY_ITEM_HANDLER(dtype)                                        \
	bool check_qcbor_##dtype##_array(const char	  *fname,                     \
					 qcbor_item_t	  *qcbor_item_ptr,            \
					 qcbor_dec_ctxt_t *qcbor_decode_ctxt,         \
					 uint32_t max_array_cnt, dtype *dstp,         \
					 uint32_t *items_foundp)                      \
	{                                                                             \
		if (strncmp(qcbor_item_ptr->label.string.ptr, fname,                  \
			    qcbor_item_ptr->label.string.len) == 0) {                 \
			if (qcbor_item_ptr->uDataType == QCBOR_TYPE_ARRAY) {          \
				uint32_t data_cnt, idx = 0, start_nesting,            \
						   out_item_cnt;                      \
                                                                                      \
				start_nesting = qcbor_item_ptr->uNestingLevel;        \
				data_cnt      = qcbor_item_ptr->val.uCount;           \
				out_item_cnt  = max_array_cnt;                        \
                                                                                      \
				if (data_cnt < out_item_cnt) {                        \
					out_item_cnt = data_cnt;                      \
				}                                                     \
                                                                                      \
				while (idx < data_cnt) {                              \
					if (QCBORDecode_GetNext(                      \
						    qcbor_decode_ctxt,                \
						    qcbor_item_ptr) != 0) {           \
						break;                                \
					}                                             \
					qcbor_item_conv_uint64(                       \
						qcbor_item_ptr);                      \
                                                                                      \
					if (idx < max_array_cnt) {                    \
						if (qcbor_item_ptr->uDataType ==      \
						    QCBOR_TYPE_UINT64) {              \
							dstp[idx] =                   \
								(dtype)qcbor_item_ptr \
									->val         \
									.uint64;      \
						}                                     \
					}                                             \
					++idx;                                        \
				}                                                     \
                                                                                      \
				while (qcbor_item_ptr->uNextNestLevel >               \
				       start_nesting) {                               \
					if (QCBORDecode_GetNext(                      \
						    qcbor_decode_ctxt,                \
						    qcbor_item_ptr) != 0)             \
						break;                                \
				}                                                     \
				if (items_foundp) {                                   \
					*items_foundp = out_item_cnt;                 \
				}                                                     \
				return true;                                          \
			}                                                             \
		}                                                                     \
		return false;                                                         \
	}

#define DECLARE_QCBOR_MD_ARRAY_ITEM_HANDLER(dtype)                             \
	bool check_qcbor_md_##dtype##_array(                                   \
		const char *fname, qcbor_item_t *qcbor_item_ptr,               \
		qcbor_dec_ctxt_t *qcbor_decode_ctxt, uint32_t max_array_cnt,   \
		dtype *dstp, uint32_t array_stride,                            \
		uint32_t *out_items_foundp, uint32_t *in_items_foundp);

#define DEFINE_QCBOR_MD_ARRAY_ITEM_HANDLER(dtype)                                     \
	bool check_qcbor_md_##dtype##_array(                                          \
		const char *fname, qcbor_item_t *qcbor_item_ptr,                      \
		qcbor_dec_ctxt_t *qcbor_decode_ctxt, uint32_t max_array_cnt,          \
		dtype *dstp, uint32_t array_stride,                                   \
		uint32_t *out_items_foundp, uint32_t *in_items_foundp)                \
	{                                                                             \
		if (strncmp(qcbor_item_ptr->label.string.ptr, fname,                  \
			    qcbor_item_ptr->label.string.len) == 0) {                 \
			if (qcbor_item_ptr->uDataType == QCBOR_TYPE_ARRAY) {          \
				uint32_t out_data_cnt,                                \
					out_idx = 0, in_idx = 0,                      \
					start_nesting, in_data_count,                 \
					out_item_cnt, i;                              \
                                                                                      \
				out_data_cnt  = qcbor_item_ptr->val.uCount;           \
				start_nesting = qcbor_item_ptr->uNestingLevel;        \
                                                                                      \
				out_item_cnt = max_array_cnt;                         \
                                                                                      \
				if (out_data_cnt < out_item_cnt) {                    \
					out_item_cnt = out_data_cnt;                  \
				}                                                     \
                                                                                      \
				while (out_idx < out_data_cnt) {                      \
					if (QCBORDecode_GetNext(                      \
						    qcbor_decode_ctxt,                \
						    qcbor_item_ptr) != 0) {           \
						break;                                \
					}                                             \
                                                                                      \
					if (qcbor_item_ptr->uDataType !=              \
					    QCBOR_TYPE_ARRAY) {                       \
						break;                                \
					}                                             \
					in_data_count =                               \
						qcbor_item_ptr->val.uCount;           \
                                                                                      \
					for (i = 0; i < in_data_count; ++i) {         \
						if (QCBORDecode_GetNext(              \
							    qcbor_decode_ctxt,        \
							    qcbor_item_ptr) !=        \
						    0) {                              \
							goto done;                    \
						}                                     \
                                                                                      \
						if ((out_idx <                        \
						     out_item_cnt) &&                 \
						    (i < array_stride)) {             \
							qcbor_item_conv_uint64(       \
								qcbor_item_ptr);      \
							dstp[(out_idx *               \
							      array_stride) +         \
							     i] =                     \
								(dtype)qcbor_item_ptr \
									->val         \
									.uint64;      \
							++in_idx;                     \
						}                                     \
					}                                             \
					if ((out_idx < out_item_cnt) &&               \
					    (in_items_foundp)) {                      \
						*in_items_foundp = in_idx;            \
						in_idx		 = 0;                 \
						/* Count of inner array is            \
						 * taken in one dimensional           \
						 * array */                           \
						in_items_foundp++;                    \
					}                                             \
                                                                                      \
					++out_idx;                                    \
				}                                                     \
			done:                                                         \
				if (out_items_foundp) {                               \
					*out_items_foundp = out_idx;                  \
				}                                                     \
                                                                                      \
				while (qcbor_item_ptr->uNextNestLevel >               \
				       start_nesting) {                               \
					if (QCBORDecode_GetNext(                      \
						    qcbor_decode_ctxt,                \
						    qcbor_item_ptr) != 0) {           \
						break;                                \
					}                                             \
				}                                                     \
				return true;                                          \
			}                                                             \
		}                                                                     \
		return false;                                                         \
	}

// This decode function can be used to decode a single dimension array of
// standard type or a type of structure where the data will be decoded into one
// of the member of structure. If the data to be decoded is of standard type
// mention 'dtype' & 'stype' the same as the type of data to be decoded i.e.,
// e.g., uint32_t or uint64_t etc.. If the data to be decoded is a member of a
// structure array mention the type of structure in 'stype' and the type of
// member in 'dtype'. Decoding is done by creating a dynamic 1D array for either
// the structure type or the standard type and copying the data to the created
// memory.
//
// fname - String to match with the QCBOR data.
// qcbor_item_ptr - Pointer which will hold the decoded data.
// qcbor_decode_ctxt - Pointer which contains the decoded context.
// consecutive_elements - If the QCBOR array is encoded with multiple data items
//   for each source index, this field indicates how many such data items are
//   embedded for each source index. e.g., Source array has '7' as size and
//   for each iteration adds 3 elements, then actual elements in the
//   QCBOR array will be 21 and the actual size is 21/3 which 7
//   such data.
// dstp - Pointer to either the structure array or data array to be create.
// items_foundp - Number of elements decoded i.e.,
//   total_elements/consecutive_elements.
// member_offset - If the data to be decoded in a structure member, this gives
//   the offset of the structure. If the data to be decoded into a data_type
//   ptr this field will be zero.
#define DECLARE_QCBOR_DYNAMIC_STRUCT_ARRAY_ITEM_HANDLER(dtype, stype)          \
	bool check_qcbor_dynamic_##stype##_##dtype##_array(                    \
		const char *fname, qcbor_item_t *qcbor_item_ptr,               \
		qcbor_dec_ctxt_t *qcbor_decode_ctxt,                           \
		uint32_t consecutive_elements, stype **dstp,                   \
		uint32_t *items_foundp, size_t member_offset);

#define DEFINE_QCBOR_DYNAMIC_STRUCT_ARRAY_ITEM_HANDLER(dtype, stype)              \
	bool check_qcbor_dynamic_##stype##_##dtype##_array(                       \
		const char *fname, qcbor_item_t *qcbor_item_ptr,                  \
		qcbor_dec_ctxt_t *qcbor_decode_ctxt,                              \
		uint32_t consecutive_elements, stype **dstp,                      \
		uint32_t *items_foundp, size_t member_offset)                     \
	{                                                                         \
		if (strncmp(qcbor_item_ptr->label.string.ptr, fname,              \
			    qcbor_item_ptr->label.string.len) == 0) {             \
			if (qcbor_item_ptr->uDataType == QCBOR_TYPE_ARRAY) {      \
				uint32_t data_cnt, idx = 0, start_nesting;        \
				dtype	*data_ptr = NULL;                         \
                                                                                  \
				start_nesting = qcbor_item_ptr->uNestingLevel;    \
				data_cnt      = qcbor_item_ptr->val.uCount;       \
				if (*dstp == NULL) {                              \
					*dstp = (stype *)calloc(                  \
						data_cnt, sizeof(stype));         \
					assert(*dstp != NULL);                    \
				}                                                 \
                                                                                  \
				while (idx < data_cnt) {                          \
					if (QCBORDecode_GetNext(                  \
						    qcbor_decode_ctxt,            \
						    qcbor_item_ptr) != 0) {       \
						break;                            \
					}                                         \
					data_ptr =                                \
						(dtype *)((uintptr_t) &           \
							  (*dstp)[idx] +          \
								  member_offset); \
					qcbor_item_conv_uint64(                   \
						qcbor_item_ptr);                  \
					if (qcbor_item_ptr->uDataType ==          \
					    QCBOR_TYPE_UINT64) {                  \
						*data_ptr =                       \
							(dtype)qcbor_item_ptr     \
								->val.uint64;     \
					}                                         \
					++idx;                                    \
				}                                                 \
                                                                                  \
				while (qcbor_item_ptr->uNextNestLevel >           \
				       start_nesting) {                           \
					if (QCBORDecode_GetNext(                  \
						    qcbor_decode_ctxt,            \
						    qcbor_item_ptr) != 0)         \
						break;                            \
				}                                                 \
				if (items_foundp) {                               \
					/* Here consecutive_elements is just      \
					 * the number of homogeneous elements     \
					 * if a structure is encoded as an        \
					 * array. The size of this array of       \
					 * structure will be total array size     \
					 * divided by number of elements */       \
					*items_foundp =                           \
						idx / consecutive_elements;       \
				}                                                 \
				return true;                                      \
			}                                                         \
		}                                                                 \
		return false;                                                     \
	}

// This decode function can be used to decode a two dimension array. Here a one
// dimensional array of structure type will be allocated where, the typical
// members of the structure will be a total elements which has the number of
// elements of each 2nd dimensional array and a data pointer of desired data
// type for the total elements. An one dimensional array will be created for
// total elements with size of desired data type. The actual data of inner
// dimension will be copied to the data pointer.
//
// fname - String to match with the QCBOR data.
// qcbor_item_ptr - Pointer which will hold the decoded data.
// qcbor_decode_ctxt - Pointer which contains the decoded context.
// consecutive_elements - If the QCBOR array is encoded with multiple data items
//   for each source index, this field indicates how many such data items are
//   embedded for each source index. e.g., Source array has '7' as size and
//   for each iteration adds 3 elements, then actual elements in the
//   QCBOR array will be 21 and the actual size is 21/3 which 7
//   such data.
// dstp - Pointer to either the 1D structure array to be created.
// out_items_foundp - Outer dimension of the 2D array.
// array_member_offset - Offset of inner array member which is to be created.
//   This is the member of 1D structure array.
//   arr = &(*dstp)[i]+array_member_offset
// count_member_offset - Offset of inner dimension member of the 1D structure.
//   *Count = &(*dstp)[i]+count_member_offset
#define DECLARE_QCBOR_DYNAMIC_MD_STRUCT_ARRAY_ITEM_HANDLER(dtype, stype,       \
							   cnt_type)           \
	bool check_qcbor_dynamic_md_##stype##_##dtype##_array(                 \
		const char *fname, qcbor_item_t *qcbor_item_ptr,               \
		qcbor_dec_ctxt_t *qcbor_decode_ctxt,                           \
		uint8_t consecutive_elements, stype **dstp,                    \
		uint32_t *out_items_foundp, size_t array_member_offset,        \
		size_t count_member_offset);

#define DEFINE_QCBOR_DYNAMIC_MD_STRUCT_ARRAY_ITEM_HANDLER(dtype, stype,                   \
							  cnt_type)                       \
	bool check_qcbor_dynamic_md_##stype##_##dtype##_array(                            \
		const char *fname, qcbor_item_t *qcbor_item_ptr,                          \
		qcbor_dec_ctxt_t *qcbor_decode_ctxt,                                      \
		uint8_t consecutive_elements, stype **dstp,                               \
		uint32_t *out_items_foundp, size_t array_member_offset,                   \
		size_t count_member_offset)                                               \
	{                                                                                 \
		if (strncmp(qcbor_item_ptr->label.string.ptr, fname,                      \
			    qcbor_item_ptr->label.string.len) == 0) {                     \
			if (qcbor_item_ptr->uDataType == QCBOR_TYPE_ARRAY) {              \
				uint32_t out_data_cnt,                                    \
					out_idx = 0, in_idx = 0,                          \
					start_nesting, in_data_count, i;                  \
				dtype	**data_ptr;                                       \
				uint32_t *count_ptr;                                      \
                                                                                          \
				out_data_cnt  = qcbor_item_ptr->val.uCount;               \
				start_nesting = qcbor_item_ptr->uNestingLevel;            \
				if (*dstp == NULL) {                                      \
					*dstp = (stype *)calloc(                          \
						out_data_cnt, sizeof(stype));             \
					assert(*dstp != NULL);                            \
				}                                                         \
                                                                                          \
				while (out_idx < out_data_cnt) {                          \
					if (QCBORDecode_GetNext(                          \
						    qcbor_decode_ctxt,                    \
						    qcbor_item_ptr) != 0) {               \
						break;                                    \
					}                                                 \
                                                                                          \
					if (qcbor_item_ptr->uDataType !=                  \
					    QCBOR_TYPE_ARRAY) {                           \
						break;                                    \
					}                                                 \
					in_data_count =                                   \
						qcbor_item_ptr->val.uCount;               \
					data_ptr =                                        \
						(dtype **)((uintptr_t) &                  \
							   (*dstp)[out_idx] +             \
								   array_member_offset);  \
					count_ptr =                                       \
						(uint32_t                                 \
							 *)((uintptr_t) &                 \
							    (*dstp)[out_idx] +            \
								    count_member_offset); \
					*data_ptr = (dtype *)calloc(                      \
						in_data_count, sizeof(dtype));            \
					assert(*data_ptr != NULL);                        \
                                                                                          \
					for (i = 0; i < in_data_count; ++i) {             \
						if (QCBORDecode_GetNext(                  \
							    qcbor_decode_ctxt,            \
							    qcbor_item_ptr) !=            \
						    0) {                                  \
							goto done;                        \
						}                                         \
                                                                                          \
						qcbor_item_conv_uint64(                   \
							qcbor_item_ptr);                  \
						(*data_ptr)[i] =                          \
							(dtype)qcbor_item_ptr             \
								->val.uint64;             \
						++in_idx;                                 \
					}                                                 \
					/* Here consecutive_elements is just              \
					 * the number of homogeneous                      \
					 * elements if a structure is                     \
					 * encoded as an array. The                       \
					 * size of this array of                          \
					 * structure will be total                        \
					 * array size divided by                          \
					 * number of elements */                          \
					*count_ptr =                                      \
						in_idx / consecutive_elements;            \
					in_idx = 0;                                       \
                                                                                          \
					++out_idx;                                        \
				}                                                         \
			done:                                                             \
				if (out_items_foundp) {                                   \
					*out_items_foundp = out_idx;                      \
				}                                                         \
                                                                                          \
				while (qcbor_item_ptr->uNextNestLevel >                   \
				       start_nesting) {                                   \
					if (QCBORDecode_GetNext(                          \
						    qcbor_decode_ctxt,                    \
						    qcbor_item_ptr) != 0) {               \
						break;                                    \
					}                                                 \
				}                                                         \
				return true;                                              \
			}                                                                 \
		}                                                                         \
		return false;                                                             \
	}

DECLARE_QCBOR_ITEM_HANDLER(bool)
DECLARE_QCBOR_ITEM_HANDLER(uint8_t)
DECLARE_QCBOR_ITEM_HANDLER(uint16_t)
DECLARE_QCBOR_ITEM_HANDLER(uint32_t)
DECLARE_QCBOR_ITEM_HANDLER(uint64_t)

DECLARE_QCBOR_ARRAY_ITEM_HANDLER(uint32_t)
DECLARE_QCBOR_ARRAY_ITEM_HANDLER(uint64_t)

DECLARE_QCBOR_MD_ARRAY_ITEM_HANDLER(uint32_t)
DECLARE_QCBOR_MD_ARRAY_ITEM_HANDLER(uint64_t)

DECLARE_QCBOR_DYNAMIC_STRUCT_ARRAY_ITEM_HANDLER(vmid_t, vm_device_descriptor_t)
DECLARE_QCBOR_DYNAMIC_STRUCT_ARRAY_ITEM_HANDLER(uint32_t,
						vm_device_descriptor_t)
DECLARE_QCBOR_DYNAMIC_MD_STRUCT_ARRAY_ITEM_HANDLER(uint32_t,
						   vm_device_descriptor_t,
						   uint32_t)
DECLARE_QCBOR_DYNAMIC_MD_STRUCT_ARRAY_ITEM_HANDLER(uint64_t,
						   vm_device_descriptor_t,
						   uint32_t)

bool
platform_process_qcbor_items(qcbor_item_t     *item,
			     qcbor_dec_ctxt_t *qcbor_decode_ctxt);
