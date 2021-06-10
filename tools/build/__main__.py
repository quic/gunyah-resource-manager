# coding: utf-8
#
# © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Gunyah general build system.

This module is invoked by configure.py with the global variable `graph` set to
an instance of AbstractBuildGraph, which can be used to add rules, targets and
variables to the build graph.
"""

import os
import sys
import logging
import inspect
import imp

fp, path, desc = imp.find_module("config_file")
cfg = imp.load_module('rm_cfg', fp, path, desc)

#
# Global variable & default settings
#
# Silence flake8 warnings about the externally-defined graph variable
graph = graph  # noqa: F821

logging.basicConfig()
logger = logging.getLogger(__name__)

build_dir = graph.build_dir
config_file_name = "build.conf"


# Extract command line parameter "platform" to select specific
# configuration file [platform_name].build.conf from directory "config"

platform_name = graph.get_argument('platform', 'qemu')

if os.path.isfile(config_file_name):
    os.remove(config_file_name)

platform_cfg_name = os.path.join( os.getcwd(), "config",
platform_name+".build.conf")

os.symlink(platform_cfg_name, config_file_name)


#
# Build rules
#


#
# General setup
#
def relpath(path):
    return os.path.relpath(path, start=graph.root_dir)


# parse configure file
config = cfg.Configuration(config_file_name, graph)
config.process()

#
# Python dependencies
#
for m in sys.modules.values():
    try:
        f = inspect.getsourcefile(m)
    except TypeError:
        continue
    if f is None:
        continue
    f = os.path.relpath(f)
    if f.startswith('../'):
        continue
    graph.add_gen_source(f)
