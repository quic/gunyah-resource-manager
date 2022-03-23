// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#define EVENT_FD_READ  (1 << 0)
#define EVENT_FD_WRITE (1 << 1)

typedef struct event event_t;
typedef void (*event_callback_t)(event_t *event, void *data);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

struct event {
	event_t		*next;
	event_t		*prev;
	event_callback_t callback;
	bool		 pending;
	void	     *data;
	int		 fd;
};

#pragma clang diagnostic pop

error_t
event_init(void);

void
event_loop_enter(void);

void
event_loop_enter_suspend(int timeout);

void
event_loop_exit(void);

bool
event_is_pending(void);

bool
event_is_registered(event_t *event);

void
event_flush_pending(void);

bool
event_wait_pending(int timeout);

error_t
event_register(event_t *event, event_callback_t callback, void *data);

error_t
event_set_fd_trigger(event_t *event, int fd, int flags);

bool
event_deregister(event_t *event);

bool
event_trigger(event_t *event);
