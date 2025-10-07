// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_PREEMPT_H_
#define INCLUDE_PREEMPT_H_

void
preempt_disable(void);

void
preempt_enable(void);

void
assert_preempt_disabled(void);

void
assert_preempt_enabled(void);

#else

#error multiple include of preempt.h

#endif
