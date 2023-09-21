// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <stdio.h>
#include <stdlib.h>

#include <rm_types.h>

#include <memextent.h>
#include <resource-manager.h>
#include <rm_env_data.h>
#include <uart.h>

#include "uart_qemu.h"

static bool	g_uart_log_en = false;
static vmaddr_t uart_address;

void
uart_putc(const char c)
{
	if (!g_uart_log_en) {
		goto out;
	}

	volatile uint32_t *tfr = (uint32_t *)(uart_address + UART_TFR);
	volatile uint32_t *dr  = (uint32_t *)(uart_address + UART_DR);

	while ((*tfr & ((uint32_t)1U << 5)) != 0U) {
	}
	*dr = c;

out:
	return;
}

void
uart_write(const char *out, size_t size)
{
	if (!g_uart_log_en) {
		goto out;
	}

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

out:
	return;
}

void
platform_uart_map(rm_env_data_t *env_data)
{
	error_t ret = OK;

	if (env_data->uart_address != 0U) {
		ret = memextent_map(rm_get_uart_me(), env_data->addrspace_capid,
				    env_data->uart_address, PGTABLE_ACCESS_RW,
				    PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
		if (ret != OK) {
			(void)printf("UART mapping failed\n");
			exit(1);
		}

		uart_address  = env_data->uart_address;
		g_uart_log_en = true;
	} else {
		(void)printf("No uart_address configured");
		g_uart_log_en = false;
	}
}
