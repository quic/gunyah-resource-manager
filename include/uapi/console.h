// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define CONSOLE_MAGIC 0x43

#define IOCTL_REGISTER_CONSOLE                                                 \
	_IOW(CONSOLE_MAGIC, 0, struct register_console_req)
#define IOCTL_DEREGISTER_CONSOLE _IOW(CONSOLE_MAGIC, 1, int)
#define IOCTL_SET_PREFIX_CONSOLE _IOW(CONSOLE_MAGIC, 2, const char *)

typedef void (*console_t)(const char *out, size_t size);

struct register_console_req {
	console_t console;
};
