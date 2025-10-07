// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef UAPI_EXIT_DEV_H_
#define UAPI_EXIT_DEV_H_

#define EXIT_MAGIC 0x44U

#define IOCTL_REGISTER_EXIT   _IOW(EXIT_MAGIC, 0U, struct register_exit_req)
#define IOCTL_DEREGISTER_EXIT _IOW(EXIT_MAGIC, 1U, int)

typedef void (*exit_t)(int exit_code);

struct register_exit_req {
	exit_t exit_func;
};

#else

#error multiple include of uapi/exit_dev.h

#endif
