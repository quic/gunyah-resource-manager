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

from . import config_file as cfg

#
# Global variable & default settings
#
# Silence flake8 warnings about the externally-defined graph variable
graph = graph  # noqa: F821

logging.basicConfig()
logger = logging.getLogger(__name__)

build_dir = graph.build_dir
config_file_name = "build.conf"

#
# Build rules
#


#
# General setup
#
def relpath(path):
    return os.path.relpath(path, start=graph.root_dir)


#
# Variant setup
#
true_strings = ('true', 't', '1', 'yes', 'y')
false_strings = ('false', 'f', '0', 'no', 'n')
all_arg = graph.get_argument('all', 'false').lower()
if all_arg in true_strings:
    default_all_variants = True
elif all_arg in false_strings:
    default_all_variants = False
else:
    logger.error("Argument all= must have a boolean value, not '%s'", all_arg)
    sys.exit(1)

variant_config = {}
missing_variant = False
for variant_key in ('platform', 'quality'):
    try:
        variant_value = graph.get_env('VARIANT_' + variant_key)
    except KeyError:
        variant_arg = graph.get_argument(
            variant_key, 'all' if default_all_variants else None)

        import glob
        known_variants = frozenset(
            os.path.splitext(os.path.basename(f))[0]
            for f in glob.iglob(os.path.join('config', variant_key, '*.conf')))
        if not known_variants:
            logger.error('No variants known for key "%s"', variant_key)
            sys.exit(1)

        if variant_arg is None:
            logger.error('No variant specified for key %s; choices: %s',
                         variant_key, ', '.join(known_variants))
            missing_variant = True
            continue

        if variant_arg == 'all':
            selected_variants = known_variants
        else:
            selected_variants = frozenset(variant_arg.split(','))
            if not (selected_variants <= known_variants):
                logger.error("Unknown variants specified for key %s: %s; "
                             "choices: %s", variant_key,
                             ', '.join(selected_variants - known_variants),
                             ', '.join(known_variants))
                missing_variant = True
                continue

        for val in selected_variants:
            graph.add_variant(os.path.join(build_dir, val))(**{
                'VARIANT_' + variant_key: val
            })

        # Don't build anything until all variants are configured
        sys.exit()

    variant_config[variant_key] = variant_value

if missing_variant:
    sys.exit(1)

# parse configure file
config = cfg.Configuration(config_file_name, graph, **variant_config)
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
