# coding: utf-8
#
# Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause

import SCons.Script
import configure
import os

env_vars = {
    'PATH': os.environ['PATH'],
    'LOCAL_SYSROOT': os.environ['LOCAL_SYSROOT'],
}

if 'QCOM_LLVM' in os.environ:
    env_vars['QCOM_LLVM'] = os.environ['QCOM_LLVM']

if 'QCOM_DTC' in os.environ:
    env_vars['QCOM_DTC'] = os.environ['QCOM_DTC']

if 'LLVM' in os.environ:
    env_vars['LLVM'] = os.environ['LLVM']

env = Environment(tools={}, SCANNERS=[], BUILDERS={}, ENV=env_vars)
configure.SConsBuild(env, Builder, Action, arguments=SCons.Script.ARGUMENTS)()
