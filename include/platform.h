// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

void
uart_putc(const char c);

void
uart_write(const char *out, size_t size);

error_t
platform_uart_create_me(void);

error_t
platform_uart_map(cap_id_t addrspace_cap);
