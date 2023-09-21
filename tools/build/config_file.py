# coding: utf-8
#
# © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Configure file parsing.

This script helps to parse configuration file.
"""
import logging
import sys
import os
from io import open

logger = logging.getLogger(__name__)

# Global generated headers depends
version_header = os.path.join('include', 'rmversion.h')
version_file = os.path.join('include', 'version.h')


class Configuration:
    """
    This module helps to parse the configuration file and setup build graph.

    It accepts the following syntax:
    * all global macro defines: configs PLATFORM_PHYS_ADDR_BITS=34
    there's no space around '='. the space can be used to separate multiple
    definitions.

    * arch_source: arch_source armv8 pgtable.c
    graph.add_target(xxx)

    * test_source: test_source testcase.c

    * source: source idle.c
    graph.add_target(xxx)

    * include: include dir
    set include directory to global cflags.

    * arch include: arch_include armv8 dir
    set include directory to global cflags if current architecture is armv8

    * local include: local_include dir
    set include directory in env dict with LOCAL_CPPFLAGS key. The dir should
    be a relative path based on where build.conf located.

    * local flags: local_flags -O -g
    set env dict with LOCAL_CPPFLAGS

    * arch flags: arch_flags aarch64 -O -g
    set env dict with LOCAL_CPPFLAGS

    * base target architecture: arch aarch64

    * target triple: target_triple aarch64-linux-gnu
    set target_triple

    * include sub directory: sub_directory path_to_subdirectory
    include build.conf in that sub directory (relative to source root)

    * link script: link_script armv8 file
    specify link specify file for a specific architecture

    * program: programe binary_name
    specify the binary name as current compilation target.
    It could trigger a new variant, and a new build graph to work on. And it's
    configuration file to link these two target together.

    * mark for end of program: end_program
    indicates that all the configurations for current program are collected.

    * static library: static_lib name
    specifiy the name of static library, the final name is "libname.a".

    * mark for end of lib: end_static_lib
    indicates that all the configurations for current static library are
    collected.

    * cflags: cflags -O -g
    set cflags for current program target

    * cppflags: cppflags -O -g
    set cppflags for current program target

    * ldflags: ldflags -O -g
    set ldflags for current program target

    It will parse the configuration file from the root, then load and parse
    sub directories by order of configuration file.
    """

    def __init__(self, file_name, graph, platform=None, quality=None):
        self.file_name = file_name
        self.graph = graph
        self.target_triple = None
        self.archs = set()
        if platform is None:
            raise Exception('Please specify platform=<name>')
        self.platform = platform
        if quality is None:
            raise Exception('Please specify quality=<name>')
        self.quality = quality
        self.linker_script = None
        # the name of current configuration target
        self.binary_name = None
        # collect all object for current configuration target
        self.objects = set()
        # env should be set before set any source
        self.local_env = {}
        self.compdb_file_name = "compile_commands.json"
        self.child_configs = []
        self._root_dir = os.path.dirname(self.file_name)
        self._config_dir = os.path.join(self._root_dir, 'config')
        self._quality_dir = os.path.join(self._config_dir, 'quality')
        self._platform_dir = os.path.join(self._config_dir, 'platform')
        self._arch_dir = os.path.join(self._config_dir, 'arch')

    def process(self):
        """
        Process configuration file line by line.
        """
        # read top level config file first, handle line by line.
        config_file = self.file_name

        self.set_default_rule()
        self._set_version()
        quality_config = os.path.join(self._quality_dir, self.quality +
                                      '.conf')
        self._parse_config(quality_config)
        self._add_arch(self.platform, self._platform_dir)
        self._parse_config(config_file)
        self._setup_toolchain()

        # Add the include directory for the auto-generated headers
        # FIXME: This should probably be done somewhere else
        self.graph.append_env(
            'CFLAGS',
            "-I " +
            self._relpath(
                os.path.join(
                    self.graph.build_dir,
                    "include")))

    def _add_arch(self, arch_name, cur_dir):
        self.archs.add(arch_name)
        arch_config = os.path.join(cur_dir, arch_name + '.conf')
        self._parse_config(arch_config)

    def _relpath(self, path):
        return os.path.relpath(path, start=self.graph.root_dir)

    def _parse_config(self, config_file):
        self.graph.add_gen_source(config_file)
        cur_dir = os.path.dirname(config_file)

        # clear all local configuration
        self.local_env.clear()

        with open(config_file, 'r', encoding='utf-8') as f:
            for s in f.readlines():
                words = s.split()
                if not words or words[0].startswith('#'):
                    # Skip comments or blank lines
                    pass
                elif words[0] == "base_arch":
                    self._add_arch(words[1], self._arch_dir)
                elif words[0] == "source":
                    for w in words[1:]:
                        # Add the version header file as a dependency
                        self._add_source(
                            cur_dir, w, self.version_header, self.local_env)
                elif words[0] == "include":
                    for w in words[1:]:
                        d = self._relpath(os.path.join(cur_dir, w))
                        self.graph.append_env("CFLAGS", "-I " + d)
                elif words[0] == "arch_include":
                    if words[1] in self.archs:
                        for w in words[2:]:
                            d = self._relpath(os.path.join(cur_dir, w))
                            self.graph.append_env("CFLAGS", "-I " + d)
                elif words[0] == "local_include":
                    for w in words[1:]:
                        d = self._relpath(os.path.join(cur_dir, w))
                        self._add_include(d, self.local_env)
                elif words[0] == "local_flags":
                    self._add_flags(words[1:], self.local_env)
                elif words[0] == "configs":
                    for w in words[1:]:
                        self._add_global_define(w)
                elif words[0] == "target_triple":
                    self.target_triple = words[1]
                    self.graph.add_env('TARGET_TRIPLE', self.target_triple)
                elif words[0] == "link_script":
                    if words[1] in self.archs:
                        self._set_link_script(cur_dir, words[2])
                elif words[0] == "arch_source":
                    if words[1] in self.archs:
                        for w in words[2:]:
                            self._add_source(cur_dir, w, None, self.local_env)
                elif words[0] == "program":
                    assert self.binary_name is None
                    self.binary_name = words[1]
                    # FIXME: the add_variant API is not work as expected, need
                    # double check if this program is helpful
                    #
                    # sub_graph_path = os.path.join(self.graph.build_dir,
                    #                               self.binary_name)
                    # sub_graph = self.graph.add_variant(sub_graph_path)
                    # sub_graph()
                    # self.graph.add_gen_source(self.file_name)
                    # self.graph = sub_graph
                elif words[0] == "end_program":
                    # only allowed one target, if need support multiple target,
                    # just need to implement a stack
                    assert self.binary_name is not None
                    self._set_program()
                elif words[0] == "static_lib":
                    self.binary_name = "lib" + words[0] + ".a"
                elif words[0] == "end_static_lib":
                    assert self.binary_name is not None
                    self._set_static_lib()
                elif words[0] == "cflags":
                    self.graph.append_env("CFLAGS", ' '.join(words[1:]))
                elif words[0] == "cppflags":
                    self.graph.append_env("CPPFLAGS", ' '.join(words[1:]))
                elif words[0] == "ldflags":
                    self.graph.append_env("LDFLAGS", ' '.join(words[1:]))
                elif words[0] == "sub_directory":
                    subdir = os.path.relpath(os.path.join(self._root_dir,
                                                          words[1]))
                    sub_config_file = os.path.join(subdir, self.file_name)
                    self._parse_config(sub_config_file)
                    self.graph.add_gen_source(sub_config_file)
                else:
                    logger.error("Unknown config directive: %s", words[0])

    def _setup_toolchain(self):
        try:
            llvm_root = self.graph.get_env('QCOM_LLVM')
        except KeyError:
            try:
                llvm_root = self.graph.get_env('LLVM')
            except KeyError:
                logger.error(
                    "Set $QCOM_LLVM or $LLVM to the root of LLVM toolchain")
                sys.exit(1)

        try:
            local_sysroot = self.graph.get_env('LOCAL_SYSROOT')
        except KeyError:
            logger.error("Missing environment: $LOCAL_SYSROOT")
            sys.exit(1)

        # Use a QC prebuilt LLVM
        self.graph.add_env('CLANG', os.path.join(llvm_root, 'bin', 'clang'))

        # On scons builds, the abs path may be put into the commandline,
        # strip it out of the __FILE__ macro.
        root = os.path.abspath(os.curdir) + os.sep
        self.graph.append_env('CFLAGS',
                              '-fmacro-prefix-map={:s}={:s}'.format(root, ''))

        # FIXME: manually add the toolchain header file. Remove it.
        self.graph.append_env('CFLAGS', "-isystem " + os.path.join(
            llvm_root,
            self.target_triple,
            "libc/include"))

        self.graph.append_env('CFLAGS', "-I " + os.path.join(
            local_sysroot,
            "include"))

        self.graph.append_env('LDFLAGS', "-L " + os.path.join(
            local_sysroot,
            "lib"))

        self.graph.add_env(
            'FORMATTER',
            os.path.join(
                llvm_root,
                'bin',
                'clang-format'))

        # Use Clang to compile.
        self.graph.add_env('TARGET_CC', '${CLANG} -target ${TARGET_TRIPLE}')
        self.graph.add_env('TEST_CC', '${CLANG} -target ${TARGET_TRIPLE}')
        self.graph.add_env('TARGET_AR',
                           os.path.join(llvm_root, 'bin', 'llvm-ar'))

        # Use Clang with LLD to link.
        self.graph.add_env('TARGET_LD', '${TARGET_CC} -fuse-ld=lld')
        self.graph.add_env('TEST_LD', '${TEST_CC} -fuse-ld=lld')

        # Use Clang to preprocess DSL files.
        self.graph.add_env('CPP', '${CLANG}-cpp -target ${TARGET_TRIPLE}')

        sysroot = llvm_root + '/' + self.target_triple + '/libc/'
        self.graph.append_env("LDFLAGS", '--sysroot=' + sysroot)

        logger.warn("Test programs are disabled by default")

    def _add_source_file(self, src, obj, requires, local_env):
        self.graph.add_target([obj], 'cc', [src], requires=requires,
                              **local_env)

    def _add_source(self, file_dir, src, requires, local_env):
        """
        file_dir must be relative path to root
        """
        out_dir = os.path.join(self.graph.build_dir, file_dir, 'obj')
        i = os.path.join(file_dir, src)
        o = os.path.join(out_dir, src + '.o')
        self._add_source_file(i, o, requires, local_env)
        self.objects.add(o)

    def _add_include_dir(self, d, local_env):
        if 'LOCAL_CPPFLAGS' in local_env:
            local_env['LOCAL_CPPFLAGS'] += ' '
        else:
            local_env['LOCAL_CPPFLAGS'] = ''
        local_env['LOCAL_CPPFLAGS'] += '-iquote ' + d

    def _add_include(self, include, local_env):
        """
        include is a relative path based on the scon's work dir
        """
        self._add_include_dir(include, local_env)

    def _add_flags(self, flags, local_env):
        if 'LOCAL_CFLAGS' in local_env:
            local_env['LOCAL_CFLAGS'] += ' '
        else:
            local_env['LOCAL_CFLAGS'] = ''
        local_env['LOCAL_CFLAGS'] += ' '.join(flags)

    def _add_global_define(self, d):
        self.graph.append_env('CPPFLAGS', "-D" + d)
        self.graph.append_env('CODEGEN_CONFIGS', "-D" + d)

    def _set_link_script(self, d, link_file):
        linker_script_in = os.path.join(d, link_file)
        linker_script = os.path.join(self.graph.build_dir, link_file + '.pp')
        self.graph.add_target([linker_script], 'cpp-dsl', [linker_script_in])
        self.graph.append_env('TARGET_LDFLAGS',
                              '-Wl,-T,{:s}'.format(linker_script))
        self.linker_script = linker_script

    def _set_program(self):
        bin_file = os.path.join(self.graph.build_dir, self.binary_name)
        deps = None
        if self.linker_script is not None:
            deps = [self.linker_script]
        assert len(self.objects) != 0
        self.graph.add_target([bin_file], 'ld', sorted(self.objects),
                              depends=deps)
        self.graph.add_default_target(bin_file)

    def _set_static_lib(self):
        bin_file = os.path.join(self.graph.build_dir, self.binary_name)
        deps = None
        assert len(self.objects) != 0
        self.graph.add_target([bin_file], 'ar', sorted(self.objects),
                              depends=deps)
        self.graph.add_default_target(bin_file)

    def _set_version(self):
        self.version_header = os.path.join(self.graph.build_dir,
                                           version_header)
        if os.path.exists(version_file):
            self.graph.add_rule('version_copy', 'cp ${in} ${out}')
            self.graph.add_target(
                [self.version_header],
                'version_copy',
                [version_file])
        else:
            script = "cd {:s} && tools/build/gen_ver.sh".format(
                self._relpath('.'))
            self.graph.add_rule('version_gen', script + ' > ${out}')
            import subprocess
            gitdir = subprocess.check_output(['git', 'rev-parse', '--git-dir'])
            gitdir = gitdir.decode('utf-8').strip()
            self.graph.add_target(
                [self.version_header], 'version_gen', [
                    '{:s}/logs/HEAD'.format(gitdir)], always=True)

    def set_default_rule(self):
        compdb_file = os.path.join(self.graph.build_dir, self.compdb_file_name)
        self.graph.add_compdb(compdb_file, form='clang')

        # Compile a target C file.
        self.graph.add_rule('cc',
                            '$TARGET_CC $CFLAGS $CPPFLAGS $TARGET_CFLAGS '
                            '$TARGET_CPPFLAGS $LOCAL_CFLAGS $LOCAL_CPPFLAGS '
                            ' -MD -MF ${out}.d -c -o ${out} ${in}',
                            depfile='${out}.d', compdbs=[compdb_file])
        # Preprocess a DSL file.
        self.graph.add_rule('cpp-dsl', '${CPP} $CPPFLAGS $TARGET_CPPFLAGS '
                            '$LOCAL_CPPFLAGS -undef $DSL_DEFINES -x c '
                            '-P -MD -MF ${out}.d -MT ${out} ${in} > ${out}',
                            depfile='${out}.d')
        # Link a target binary.
        self.graph.add_rule('ld', '$TARGET_LD $LDFLAGS $TARGET_LDFLAGS '
                            '$LOCAL_LDFLAGS ${in} -o ${out}')
        # Static library
        self.graph.add_rule('ar', '$TARGET_AR rc ${out} ${in}')
