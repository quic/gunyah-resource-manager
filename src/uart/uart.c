// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
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

static bool uart_registered;

rm_error_t
register_uart(void)
{
	const char *dev	   = "/dev/console";
	const char *banner = "[RM]";

	rm_error_t e = RM_OK;

	if (uart_registered || platform_is_in_secure_state()) {
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

#ifdef HYPVM_WITH_COVERAGE
#define TIOCGETCOV 0x548f

// Our non-standard buffer control message
struct tty_cov_buffer_req {
	uintptr_t buffer;
	uint32_t  size;
};

rm_error_t
uart_get_coverage_to_buf(char *data_buf, uint32_t size)
{
	struct tty_cov_buffer_req req = { (uintptr_t)data_buf, size };
	int result = ioctl(STDOUT_FILENO, TIOCGETCOV, (uint64_t)&req);
	if (result != 0) {
		goto err;
	}
	return req.size;
err:
	return RM_ERROR_NORESOURCE;
}

rm_error_t
uart_send_coverage(void)
{
	const char *dev = "/dev/console";

	rm_error_t e = RM_OK;

	// simple solution to open it multiple times
	int fd = open(dev, O_RDWR);
	if (fd == -1) {
		e = RM_ERROR_DENIED;
		goto err;
	}

	int ret = ioctl(fd, (int)IOCTL_SEND_COVERAGE_CONSOLE, 0);
	if (ret != 0) {
		e = RM_ERROR_DENIED;
	}

	uart_registered = false;

	(void)close(fd);
err:
	return e;
}
#endif
