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

static vmaddr_t uart_address;

void
uart_putc(const char c)
{
	volatile uint32_t *tfr = (uint32_t *)(uart_address + UART_TFR);
	volatile uint32_t *dr  = (uint32_t *)(uart_address + UART_DR);

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

void
platform_uart_setup(boot_env_data_t *env_data)
{
	uart_address = env_data->uart_address;
}

error_t
platform_uart_map(cap_id_t addrspace_cap)
{
	error_t ret = OK;

	ret = memextent_map(rm_get_uart_me(), addrspace_cap, uart_address,
			    PGTABLE_ACCESS_RW, MEMEXTENT_MEMTYPE_DEVICE);
	if (ret != OK) {
		printf("UART mapping failed\n");
		goto out;
	}

	ret = OK;
out:
	return ret;
}
