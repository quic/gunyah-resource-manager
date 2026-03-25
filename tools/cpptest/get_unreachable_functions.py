#!/usr/bin/env python3
# coding: utf-8
#
# Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import logging
import sys
import json
import gzip
import re

logger = logging.getLogger(__name__)


TOP_LEVEL = 'root'


graph_edges = {
    TOP_LEVEL: set(),
}


class ASTNode(object):
    def __init__(self, inner):
        self.inner = inner

    def find_calls(self, in_function=None):
        for i in self.inner:
            i.find_calls(in_function)


class FunctionDecl(ASTNode):
    def __init__(self, name, inner):
        super().__init__(inner)
        self.name = name

    def find_calls(self, in_function=None):
        if self.name not in graph_edges:
            graph_edges[self.name] = set()
        super().find_calls(self.name)


class FunctionCallExpr(ASTNode):
    def __init__(self, name, inner):
        self.name = name
        super().__init__(inner)

    def find_calls(self, in_function=None):
        graph_edges[in_function].add(self.name)
        super().find_calls(self.name)


def parse_node(json_dict):
    inner = json_dict['inner'] if 'inner' in json_dict else ()

    if 'kind' not in json_dict:
        return ASTNode(inner)
    elif json_dict['kind'] == 'FunctionDecl':
        return FunctionDecl(json_dict['name'], inner)
    elif (json_dict['kind'] == 'DeclRefExpr') and \
            (isinstance(json_dict['referencedDecl'], FunctionDecl)):
        return FunctionCallExpr(json_dict['referencedDecl'].name, inner)
    else:
        return ASTNode(inner)


def dump_calls():
    call_dump = []

    for fn in sorted(graph_edges.keys()):
        call_dump.append(
            f"Function: {fn} calls: {', '.join(sorted(graph_edges[fn]))}")

    return call_dump


def parse_calls(call_dump):
    call_graph = {}
    duplicates = {}

    function_pattern = re.compile(r'^Function:\s*([\w\d_]+)\s*calls:\s*(.*)$')

    for line in call_dump:
        match = function_pattern.match(line)
        if match:
            name = match.group(1)
            callees_str = match.group(2).strip()
            callees = callees_str.split(', ') if callees_str else []
            if name in call_graph:
                if name not in duplicates:
                    duplicates[name] = set(call_graph[name])
                duplicates[name].update(callees)
            else:
                call_graph[name] = callees

    # Handle duplicates
    for name, callees_set in duplicates.items():
        call_graph[name] = list(callees_set)

    return call_graph


def read_map_file(map_buffer):
    functions = set()
    # Pattern for valid function names
    function_pattern = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
    for line in map_buffer:
        parts = line.strip().split()
        if len(parts) > 4 and parts[3].isdigit() and \
                function_pattern.match(parts[4]):
            function_name = parts[4]
            functions.add(function_name)
    return functions


def find_reached_functions(functions, call_graph):
    used_functions = set(functions)
    stack = list(functions)

    while stack:
        function = stack.pop()
        if function in call_graph:
            for callee in call_graph[function]:
                if callee not in used_functions:
                    used_functions.add(callee)
                    stack.append(callee)

    return used_functions


def find_unreachable_functions(used_functions, call_graph):
    unreachable_functions = []

    for function in call_graph.keys():
        if function not in used_functions:
            unreachable_functions.append(function)

    return unreachable_functions


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )

    args = argparse.ArgumentParser()

    args.add_argument('-o', '--output',
                      help="Output file (default: stdout)",
                      type=argparse.FileType('w', encoding='utf-8'),
                      default=sys.stdout)
    args.add_argument('-m', '--map-file',
                      help="Load the map file",
                      type=argparse.FileType('r'))
    args.add_argument('inputs', help="Inputs (gzipped json AST files)",
                      nargs='*', type=argparse.FileType('rb'))

    options = args.parse_args()

    # Generate the function calls dump from the input ASTs
    for i in options.inputs:
        ast = json.load(gzip.open(i), object_hook=parse_node)
        ast.find_calls(TOP_LEVEL)
    call_dump = dump_calls()

    # Read the map file
    map_buffer = options.map_file.readlines()
    functions = read_map_file(map_buffer)

    # Parse the call dump to get callgraph
    call_graph = parse_calls(call_dump)

    # Identify all the reached functions
    reached_functions = find_reached_functions(functions, call_graph)

    # Find unreachable functions
    unreachable_functions = find_unreachable_functions(
        reached_functions, call_graph)

    # Add all the unreachable functions into the psrc for exclusion
    for func in sorted(unreachable_functions):
        to_write = "xharness.routineManager symbol_name={0} " \
            "command=setProperty property=ignored value=true".format(
                func)
        print(to_write, file=options.output)


if __name__ == "__main__":
    main()
