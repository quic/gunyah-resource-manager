// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_LOG_H_
#define INCLUDE_LOG_H_

#define LOG(fmt, ...) (void)printf((fmt), __VA_ARGS__)

#define LOG_LOC(msg) (void)printf("%s %d: %s\n", __FILE__, __LINE__, (msg))
#define LOG_ERR(err)                                                           \
	(void)printf("Error: %s %d: %d\n", __FILE__, __LINE__, (err))

// Message IDs
#define GET_LOG 0x00000005U

typedef uint32_t rm_error_t;

typedef struct rm_get_log_req {
	uint16_t log_id;
	uint16_t padding;
} rm_get_log_req_t;

typedef struct rm_get_log_resp {
	uint64_t addr;
	uint64_t size;
} rm_get_log_resp_t;

bool
log_msg_handler(vmid_t client_id, uint32_t msg_id, uint16_t seq_num, void *buf,
		size_t len);

rm_error_t
log_reconfigure(uintptr_t *log_buf, size_t size);

rm_error_t
log_expose_to_hlos(uintptr_t log_buf, size_t size);

#else

#error multiple include of log.h

#endif
