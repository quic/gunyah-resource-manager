// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <utils/list.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_EVENTS 5

#define NS_PER_MS 1000000

struct event_data_s {
	event_t *head;
	int	 epoll_fd;
	bool	 exit_loop;
	bool	 initialised;
	uint8_t	 pad_to_end[2];
};

static struct event_data_s event_data;

error_t
event_init(void)
{
	if (!event_data.initialised) {
		int epoll_fd = epoll_create1(0);
		assert(epoll_fd >= 0);

		event_data.epoll_fd    = epoll_fd;
		event_data.exit_loop   = false;
		event_data.initialised = true;
	}

	return OK;
}

error_t
event_register(event_t *event, event_callback_t callback, void *data)
{
	assert(event != NULL);

	event->next	= NULL;
	event->prev	= NULL;
	event->callback = callback;
	event->data	= data;
	event->fd	= -1;
	event->pending	= false;

	return OK;
}

bool
event_deregister(event_t *event)
{
	bool was_pending = event->pending;

	if (was_pending) {
		list_remove(event_t, &event_data.head, event, );
		event->next    = NULL;
		event->prev    = NULL;
		event->pending = false;
	}

	if (event->fd != -1) {
		int ret = epoll_ctl(event_data.epoll_fd, EPOLL_CTL_DEL,
				    event->fd, NULL);
		assert(ret == 0);
		event->fd = -1;
	}

	return was_pending;
}

error_t
event_set_fd_trigger(event_t *event, int fd, int flags)
{
	assert(event != NULL);

	if (event->fd != -1) {
		return ERROR_BUSY;
	}

	struct epoll_event ee;

	ee.data.ptr = (void *)event;
	ee.events   = EPOLLET;
	if (flags & EVENT_FD_READ) {
		ee.events |= EPOLLIN;
	}
	if (flags & EVENT_FD_WRITE) {
		ee.events |= EPOLLOUT;
	}

	int ret = epoll_ctl(event_data.epoll_fd, EPOLL_CTL_ADD, fd, &ee);

	if (ret == 0) {
		event->fd = fd;
	}

	return (error_t)ret;
}

static bool
add_event_to_pending_list(event_t *event)
{
	bool was_pending = event->pending;

	if (!was_pending) {
		list_append(event_t, &event_data.head, event, );
		event->pending = true;
	}

	return was_pending;
}

static int
do_epoll_wait(int timeout)
{
	struct epoll_event ee[MAX_EVENTS];
	int		   ret, total = 0;

	do {
		ret = epoll_wait(event_data.epoll_fd, ee, MAX_EVENTS,
				 timeout / NS_PER_MS);
		if (ret < 0) {
			assert(errno == EINTR);
			continue;
		}

		for (int i = 0; i < ret; i++) {
			event_t *event = (event_t *)ee[i].data.ptr;
			// FIXME: ignore EPOLLHUP in Linux hosted test case
			if ((ee[i].events & ~(unsigned)EPOLLHUP) != 0U) {
				(void)add_event_to_pending_list(event);
			}
		}

		total += ret;
		timeout = 0;
	} while (ret == MAX_EVENTS);

	return total;
}

bool
event_is_pending(void)
{
	(void)do_epoll_wait(0);
	return (event_data.head != NULL);
}

bool
event_wait_pending(int timeout)
{
	int ret = do_epoll_wait(timeout);

	return (ret > 0);
}

static void
flush_pending_list(void)
{
	while (event_data.head != NULL) {
		event_t *ev = event_data.head;
		list_remove(event_t, &event_data.head, ev, );
		ev->pending = false;
		ev->callback(ev, ev->data);
	}
}

void
event_flush_pending(void)
{
	(void)do_epoll_wait(0);
	flush_pending_list();
}

static void
event_loop_common(int timeout)
{
	event_data.exit_loop = false;

	for (;;) {
		flush_pending_list();

		if (event_data.exit_loop) {
			break;
		}

		int ret = do_epoll_wait(timeout);
		if (ret == 0) {
			// FIXME: QC RM issue #1
			// Implement PSCI CPU suspend call
			(void)do_epoll_wait(-1);
		}
	}
}

void
event_loop_enter(void)
{
	event_loop_common(-1);
}

void
event_loop_enter_suspend(int timeout)
{
	event_loop_common(timeout);
}

void
event_loop_exit(void)
{
	event_data.exit_loop = true;
}

bool
event_trigger(event_t *event)
{
	return add_event_to_pending_list(event);
}
