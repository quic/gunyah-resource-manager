// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_EXIT_DEV_H_
#define INCLUDE_EXIT_DEV_H_

rm_error_t
register_exit(void);

rm_error_t
deregister_exit(void);

#else

#error multiple include of exit_dev.h

#endif
