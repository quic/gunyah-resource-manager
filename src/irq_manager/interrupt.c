// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <rm-rpc.h>

#include <event.h>
#include <fcntl.h>
#include <guest_interface.h>
#include <uapi/interrupt.h>
#include <unistd.h>
#include <utils/list.h>
#include <utils/vector.h>
#include <vm_config.h>

rm_error_t
register_isr(virq_t virq, int trigger, isr_t isr, void *data)
{
	const char *dev = "/dev/gicv3";

	rm_error_t e = RM_OK;
	// simple solution to open it multiple times
	int fd = open(dev, O_RDWR);
	if (fd == -1) {
		e = RM_ERROR_DENIED;
		goto err;
	}

	struct irq_set_trigger_req req_set_trigger = {
		.irq	 = (int)virq,
		.trigger = trigger,
	};

	int ret = 0;
	ret = ioctl(fd, IOCTL_SET_IRQ_TRIGGER, (unsigned long)&req_set_trigger);
	if (ret != 0) {
		e = RM_ERROR_DENIED;
		goto err1;
	}

	struct register_isr_req req_register_isr = {
		.isr  = isr,
		.irq  = (int)virq,
		.data = data,
	};

	ret = ioctl(fd, IOCTL_REGISTER_ISR, (unsigned long)&req_register_isr);
	if (ret != 0) {
		e = RM_ERROR_DENIED;
		goto err1;
	}

	ret = ioctl(fd, IOCTL_ENABLE_IRQ, (unsigned long)&virq);
	if (ret != 0) {
		e = RM_ERROR_DENIED;
	}

err1:
	close(fd);
err:
	return e;
}

static bool
isr_simple(int virq_num, void *data)
{
	bool ret = false;

	(void)virq_num;

	event_t *event = (event_t *)data;
	if (event == NULL) {
		goto out;
	}

	event_trigger(event);
	ret = true;

out:
	return ret;
}

rm_error_t
register_event_isr(virq_t virq, event_t *event)
{
	rm_error_t e = RM_OK;

	e = register_isr(virq, IRQ_TRIGGER_EDGE_RISING, isr_simple,
			 (void *)event);

	return e;
}

rm_error_t
deregister_isr(virq_t virq)
{
	const char *dev = "/dev/gicv3";

	rm_error_t e = RM_OK;

	// simple solution to open it multiple times
	int fd = open(dev, O_RDWR);
	if (fd == -1) {
		e = RM_ERROR_DENIED;
		goto err;
	}

	int ret = ioctl(fd, IOCTL_DISABLE_IRQ, (unsigned long)&virq);
	if (ret != 0) {
		e = RM_ERROR_DENIED;
	}

	ret = ioctl(fd, IOCTL_DEREGISTER_ISR, (unsigned long)&virq);
	if (ret != 0) {
		e = RM_ERROR_DENIED;
	}

	close(fd);
err:
	return e;
}
