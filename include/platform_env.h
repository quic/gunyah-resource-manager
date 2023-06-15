// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

// clang-format off

#define process_qcbor_md_array_item(n, ip, ctxp, ep, cp)  (_Generic((ep->n), \
      boot_env_phys_range_t *: check_qcbor_uint64_t_md_array                 \
   )(#n, ip, ctxp, ARRAY_SIZE(ep->n), 2, (uint64_t*)ep->n, cp))


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

DECLARE_QCBOR_ITEM_HANDLER(bool)
DECLARE_QCBOR_ITEM_HANDLER(uint8_t)
DECLARE_QCBOR_ITEM_HANDLER(uint16_t)
DECLARE_QCBOR_ITEM_HANDLER(uint32_t)
DECLARE_QCBOR_ITEM_HANDLER(uint64_t)

DECLARE_QCBOR_ARRAY_ITEM_HANDLER(uint32_t)
DECLARE_QCBOR_ARRAY_ITEM_HANDLER(uint64_t)

bool
platform_process_qcbor_items(qcbor_item_t     *item,
			     qcbor_dec_ctxt_t *qcbor_decode_ctxt);
