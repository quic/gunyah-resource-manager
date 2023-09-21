// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <sys/ioctl.h>

#include <rm_types.h>

#include <fcntl.h>
#include <platform.h>
#include <rm-rpc.h>
#include <rm_env_data.h>
#include <uapi/console.h>
#include <uart.h>
#include <unistd.h>
#include <vm_console.h>

static bool uart_registered;

rm_error_t
register_uart(void)
{
	const char *dev	   = "/dev/console";
	const char *banner = "[RM]";

	rm_error_t e = RM_OK;

	if (uart_registered || platform_get_security_state()) {
		goto err;
	}

	// simple solution to open it multiple times
	int fd = open(dev, O_RDWR);
	if (fd == -1) {
		e = RM_ERROR_DENIED;
		goto err;
	}

	int ret = 0;

	struct register_console_req req_register_console = {
		.console = uart_write,
	};

	ret = ioctl(fd, (int)IOCTL_REGISTER_CONSOLE,
		    (uint64_t)&req_register_console);
	if (ret != 0) {
		e = RM_ERROR_DENIED;
		goto err1;
	}

	ret = ioctl(fd, (int)IOCTL_SET_PREFIX_CONSOLE, banner);
	if (ret != 0) {
		e = RM_ERROR_DENIED;
		goto err1;
	}

	uart_registered = true;

err1:
	(void)close(fd);
err:
	return e;
}

rm_error_t
deregister_uart(void)
{
	const char *dev = "/dev/console";

	rm_error_t e = RM_OK;

	if (!uart_registered) {
		goto err;
	}

	// simple solution to open it multiple times
	int fd = open(dev, O_RDWR);
	if (fd == -1) {
		e = RM_ERROR_DENIED;
		goto err;
	}

	int ret = ioctl(fd, (int)IOCTL_DEREGISTER_CONSOLE, 0);
	if (ret != 0) {
		e = RM_ERROR_DENIED;
	}

	uart_registered = false;

	(void)close(fd);
err:
	return e;
}
