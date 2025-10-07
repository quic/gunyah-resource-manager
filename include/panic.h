// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_PANIC_H_
#define INCLUDE_PANIC_H_

noreturn void
panic(const char *msg);

#else

#error multiple include of panic.h

#endif
