// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include <rm_types.h>

#include <exit_dev.h>
#include <fcntl.h>
#include <panic.h>
#include <platform.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <uapi/exit_dev.h>
#include <unistd.h>

rm_error_t
register_exit(void)
{
	const char *dev = "/dev/exit";

	rm_error_t error = RM_OK;

	int fd = open(dev, O_RDONLY);
	if (fd == -1) {
		error = RM_ERROR_DENIED;
		goto err;
	}

	struct register_exit_req req_register_exit = {
		.exit_func = platform_exit_handler,
	};
	int ret = ioctl(fd, (int)IOCTL_REGISTER_EXIT,
			(uint64_t)&req_register_exit);
	if (ret != 0) {
		error = RM_ERROR_DENIED;
	}

	(void)close(fd);

err:
	return error;
}

rm_error_t
deregister_exit(void)
{
	const char *dev = "/dev/exit";

	rm_error_t error = RM_OK;

	int fd = open(dev, O_RDWR);
	if (fd == -1) {
		error = RM_ERROR_DENIED;
		goto err;
	}

	int ret = ioctl(fd, (int)IOCTL_DEREGISTER_EXIT, 0);
	if (ret != 0) {
		error = RM_ERROR_DENIED;
	}

	(void)close(fd);

err:
	return error;
}

noreturn void
panic(const char *msg)
{
	(void)printf("panic: %s\n", msg);
	exit(1);
}
