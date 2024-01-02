#!/usr/bin/env python3
# coding: utf-8
#
# © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Run as a part of gitlab CI, after Parasoft reports have been generated.

This script converts the Parasoft XML-format report to a Code Climate
compatible json file, that gitlab code quality can interpret.
"""

import xml.etree.ElementTree as ET
import json
import argparse
import sys
import os
import re

argparser = argparse.ArgumentParser(
    description="Convert Parasoft XML to Code Climate JSON")
argparser.add_argument('input', type=argparse.FileType('r'), nargs='?',
                       default=sys.stdin, help="the Parasoft XML input")
argparser.add_argument('--output', '-o', type=argparse.FileType('w'),
                       default=sys.stdout, help="the Code Climate JSON output")
args = argparser.parse_args()

tree = ET.parse(args.input)

parasoft_viols = tree.findall(".//StdViol") + tree.findall(".//FlowViol")

cc_viols = []

severity_map = {
    1: "blocker",
    2: "critical",
    3: "major",
    4: "minor",
    5: "info",
}

deviation_map = {
    # Deviation because the behaviour proscribed by the rule is exactly the
    # intended behaviour of assert(): it prints the unexpanded expression.
    'MISRAC2012-RULE_20_12-a': [
        (None, re.compile(r"parameter of potential macro 'assert'")),
    ],
    'MISRAC2012-RULE_21_6-a': [
        (None, re.compile(r"Usage of 'printf' function")),
    ],
    # False positives due to __c11 builtins taking int memory order arguments
    # instead of enum in the Clang implementation.
    'MISRAC2012-RULE_10_3-b': [
        (None, re.compile(r"number '1'.*'essentially Enum'.*"
                          r"'__c11_atomic_(thread|signal)_fence'.*"
                          r"'essentially signed'")),
        (None, re.compile(r"number '2'.*'essentially Enum'.*"
                          r"'__c11_atomic_load'.*'essentially signed'")),
        (None, re.compile(r"number '3'.*'essentially Enum'.*"
                          r"'__c11_atomic_(store'|exchange'|fetch_).*"
                          r"'essentially signed'")),
        (None, re.compile(r"number '[45]'.*'essentially Enum'.*"
                          r"'__c11_atomic_compare_exchange_(strong|weak)'.*"
                          r"'essentially signed'")),
    ],
    'MISRAC2012-RULE_8_13-a': [
        # False positives due to the could-be-const check not understanding
        # that an inline assembly output constraint that dereferences a
        # pointer is a write to that pointer.
        (re.compile(r'^src/guest_accessors\.c$'),
         re.compile(r'parameter "b1"')),
    ],
    # False positive due to a builtin sizeof variant that does not evaluate its
    # argument, so there is no uninitialised use.
    'MISRAC2012-RULE_9_1-a': [
        (None, re.compile(r'passed to "__builtin_object_size"')),
    ],
    'MISRAC2012-RULE_1_3-b': [
        (None, re.compile(r'passed to "__builtin_object_size"')),
    ],
    # Compliance with rule 21.25 would have a significant performance impact.
    # All existing uses have been thoroughly analysed and tested, so we will
    # seek a project-wide deviation for this rule.
    'MISRAC2012-RULE_21_25-a': [
        (None, None),
    ],
}


def matches_deviation(v):
    rule = v.attrib['rule']
    if rule not in deviation_map:
        return False

    msg = v.attrib['msg']
    path = v.attrib['locFile'].split(os.sep, 2)[2]

    def check_constraint(constraint, value):
        if constraint is None:
            return True
        try:
            return constraint.search(value)
        except AttributeError:
            return constraint == value

    for d_path, d_msg in deviation_map[rule]:
        if check_constraint(d_path, path) and check_constraint(d_msg, msg):
            return True

    return False


cc_viols = [
    ({
        "type": "issue",
        "categories": ["Bug Risk"],
        "severity": ('info' if matches_deviation(v)
                     else severity_map[int(v.attrib['sev'])]),
        "check_name": v.attrib['rule'],
        "description": (v.attrib['msg'] + '. ' +
                        v.attrib['rule.header'] + '. (' +
                        v.attrib['rule'] + ')'),
        "fingerprint": v.attrib['unbViolId'],
        "location": {
            "path": v.attrib['locFile'].split(os.sep, 2)[2],
            "lines": {
                "begin": int(v.attrib['locStartln']),
                "end": int(v.attrib['locEndLn'])
            }
        }
    })
    for v in parasoft_viols]

args.output.write(json.dumps(cc_viols))
args.output.close()
