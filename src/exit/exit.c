// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <stdio.h>
#include <sys/ioctl.h>

#include <asm/arm_smccc.h>
#include <rm-rpc.h>

#include <exit_dev.h>
#include <fcntl.h>
#include <platform.h>
#include <uapi/exit_dev.h>
#include <unistd.h>

static noreturn void
exit_handler(int exit_code)
{
	(void)exit_code;

	printf("exit: Abort in RM\n");

	while (1)
		;
}

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
		.exit_func = exit_handler,
	};
	int ret = ioctl(fd, IOCTL_REGISTER_EXIT,
			(unsigned long)&req_register_exit);
	if (ret != 0) {
		error = RM_ERROR_DENIED;
	}

	close(fd);

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

	int ret = ioctl(fd, IOCTL_DEREGISTER_EXIT, 0);
	if (ret != 0) {
		error = RM_ERROR_DENIED;
	}

	close(fd);

err:
	return error;
}
