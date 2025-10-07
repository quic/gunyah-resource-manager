// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_RANDOM_H_
#define INCLUDE_RANDOM_H_

uint64_result_t
random_get_entropy64(void);

#else

#error multiple include of random.h

#endif
