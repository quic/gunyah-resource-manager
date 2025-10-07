// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_UART_H_
#define INCLUDE_UART_H_

error_t
platform_uart_map(cap_id_t addrspace_cap);

error_t
platform_uart_init(void);

rm_error_t
register_uart(void);

rm_error_t
deregister_uart(void);

#ifdef HYPVM_WITH_COVERAGE
rm_error_t
uart_send_coverage(void);
rm_error_t
uart_get_coverage_to_buf(char *data_buf, uint32_t max_size);
#endif

void
uart_putc(const char c);

void
uart_write(const char *out, size_t size);

#else

#error multiple include of uart.h

#endif
