// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <rm_types.h>

#include <guest_interface.h>
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

static cap_id_t uart_memextent = CSPACE_CAP_INVALID;

// For most cases, we just want to map UART to a IPA which is same with its
// physical address, no need to set destination IPA as an argument
error_t
platform_uart_map(cap_id_t addrspace_cap)
{
	error_t ret = OK;

	paddr_t uart_addr = rm_get_uart_address();
	if (uart_addr == 0U) {
		(void)printf("No uart_address configured\n");
		goto out;
	}

	assert(uart_memextent != CSPACE_CAP_INVALID);

	ret = memextent_map(uart_memextent, addrspace_cap, uart_addr,
			    PGTABLE_ACCESS_RW, PGTABLE_VM_MEMTYPE_DEVICE_NGNRE,
			    false);

out:
	return ret;
}

error_t
platform_uart_init(void)
{
	error_t ret = OK;

	paddr_t uart_addr = rm_get_uart_address();
	if (uart_addr == 0U) {
		(void)printf("No uart_address configured\n");
		goto out;
	}

	assert(uart_memextent == CSPACE_CAP_INVALID);

	uart_memextent = rm_get_uart_me();

	// Map UART to RM
	ret = platform_uart_map(rm_get_rm_addrspace());
	if (ret != OK) {
		(void)printf("Failed to map uart to RM\n");
		goto out;
	}

	g_uart_log_en = true;
	uart_address  = uart_addr;

out:
	return ret;
}
