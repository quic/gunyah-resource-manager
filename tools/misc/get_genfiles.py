#!/usr/bin/env python3
# coding: utf-8
#
# © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Simple script to parse the compile_commands to extract generated source and
header files, to pass to cscope or other source indexing tools.
"""

build_dir = 'build'
