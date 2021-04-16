// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define EXIT_MAGIC 0x44

#define IOCTL_REGISTER_EXIT   _IOW(EXIT_MAGIC, 0, struct register_exit_req)
#define IOCTL_DEREGISTER_EXIT _IOW(EXIT_MAGIC, 1, int)

typedef void (*exit_t)(int exit_code);

struct register_exit_req {
	exit_t exit_func;
};
