// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

void
platform_uart_map(rm_env_data_t *env_data);

rm_error_t
register_uart(void);

rm_error_t
deregister_uart(void);

void
uart_putc(const char c);

void
uart_write(const char *out, size_t size);
