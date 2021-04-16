// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <event.h>
#include <preempt.h>
#include <time.h>
#include <unistd.h>

#define NS_PER_S 1000000000

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

struct event_data {
	event_t *head;
	event_t *tail;
	bool	 exit_loop;
};

#pragma clang diagnostic pop

static struct event_data event_data;

error_t
event_init(void)
{
	return OK;
}

static void
flush_pending_list(void)
{
	assert_preempt_disabled();

	while (event_data.head != NULL) {
		event_t *ev   = event_data.head;
		event_t *next = ev->next;

		assert(ev->prev == NULL);

		event_data.head = next;

		if (next != NULL) {
			next->prev = NULL;
		} else {
			event_data.tail = NULL;
		}

		ev->next    = NULL;
		ev->pending = false;

		event_callback_t cb   = ev->callback;
		void *		 data = ev->data;

		preempt_enable();
		cb(ev, data);
		preempt_disable();
	}
}

static bool
do_event_wait(int timeout)
{
	assert_preempt_disabled();

	int ret;

	do {
		if (timeout > 0) {
			struct timespec ts = {
				.tv_sec	 = timeout / NS_PER_S,
				.tv_nsec = timeout % NS_PER_S,
			};
			ret = clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, NULL);
		} else if (timeout < 0) {
			ret = pause();
		} else {
			break;
		}

		// If we were interrupted but no event
		// was triggered, retry the wait.
	} while ((event_data.head == NULL) && (ret == -EINTR));

	return event_data.head != NULL;
}

static void
event_loop_common(int timeout)
{
	preempt_disable();

	event_data.exit_loop = false;

	for (;;) {
		flush_pending_list();

		if (event_data.exit_loop) {
			break;
		}

		if (!do_event_wait(timeout)) {
			(void)do_event_wait(-1);
		}
	}

	preempt_enable();
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
	preempt_disable();
	event_data.exit_loop = true;
	preempt_enable();
}

bool
event_is_pending(void)
{
	bool pending;

	preempt_disable();
	pending = event_data.head != NULL;
	preempt_enable();

	return pending;
}

void
event_flush_pending(void)
{
	preempt_disable();
	flush_pending_list();
	preempt_enable();
}

bool
event_wait_pending(int timeout)
{
	bool pending;

	preempt_disable();
	pending = (event_data.head != NULL) || do_event_wait(timeout);
	preempt_enable();

	return pending;
}

error_t
event_register(event_t *event, event_callback_t callback, void *data)
{
	assert(event != NULL);

	event->next	= NULL;
	event->prev	= NULL;
	event->callback = callback;
	event->data	= data;
	event->pending	= false;
	event->fd	= -1;

	return OK;
}

error_t
event_set_fd_trigger(event_t *event, int fd, int flags)
{
	(void)event;
	(void)fd;
	(void)flags;

	return ERROR_UNIMPLEMENTED;
}

bool
event_deregister(event_t *event)
{
	preempt_disable();

	bool was_pending = event->pending;

	if (was_pending) {
		event_t *next = event->next;
		event_t *prev = event->prev;

		if (next != NULL) {
			next->prev = prev;
		} else {
			event_data.tail = prev;
		}

		if (prev != NULL) {
			prev->next = next;
		} else {
			event_data.head = next;
		}

		event->next    = NULL;
		event->prev    = NULL;
		event->pending = false;
	}

	preempt_enable();

	return was_pending;
}

bool
event_trigger(event_t *event)
{
	preempt_disable();

	bool was_pending = event->pending;

	if (!was_pending) {
		event_t *tail = event_data.tail;

		if (tail != NULL) {
			tail->next = event;
		} else {
			event_data.head = event;
		}

		event->prev	= tail;
		event_data.tail = event;
		event->pending	= true;
	}

	preempt_enable();

	return was_pending;
}
