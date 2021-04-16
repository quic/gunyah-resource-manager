// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <memextent.h>
#include <platform.h>
#include <resource-manager.h>

#include "uart_qemu.h"

void
uart_putc(const char c)
{
	volatile uint32_t *tfr = (uint32_t *)(UART_BASE + UART_TFR);
	volatile uint32_t *dr  = (uint32_t *)(UART_BASE + UART_DR);

	while ((*tfr & ((uint32_t)1U << 5)) != 0U)
		;
	*dr = c;
}

void
uart_write(const char *out, size_t size)
{
	size_t	    remain = size;
	const char *pos	   = out;

	while (remain > 0) {
		char c;

		if (*pos == '\n') {
			c = '\r';
			uart_putc(c);
		}

		c = *pos;
		uart_putc(c);
		pos++;
		remain--;
	}
}

static cap_id_t uart_me = CSPACE_CAP_INVALID;

error_t
platform_uart_create_me(void)
{
	error_t ret = OK;

	if (uart_me == CSPACE_CAP_INVALID) {
		cap_id_result_t res = memextent_create(UART_BASE, UART_SIZE,
						       PGTABLE_ACCESS_RW,
						       MEMEXTENT_MEMTYPE_DEVICE,
						       rm_get_device_me());
		if (res.e != OK) {
			printf("UART memextent creation failed\n");
			ret = res.e;
		} else {
			uart_me = res.r;
		}
	}

	return ret;
}

error_t
platform_uart_map(cap_id_t addrspace_cap)
{
	error_t ret = OK;

	assert(uart_me != CSPACE_CAP_INVALID);

	ret = memextent_map(uart_me, addrspace_cap, UART_BASE,
			    PGTABLE_ACCESS_RW, MEMEXTENT_MEMTYPE_DEVICE);
	if (ret != OK) {
		printf("UART mapping failed\n");
		goto out;
	}

	ret = OK;
out:
	return ret;
}
