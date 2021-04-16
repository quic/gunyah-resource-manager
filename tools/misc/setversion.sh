#!/bin/sh
# © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause

outputpath=../../include/version.h
echo "updating Resource Manager version #...."
echo "Remember to checkin version.h into P4"
echo chmod 777 ${outputpath}
echo $(source ../build/gen_ver.sh ./ > ${outputpath})
echo "Done! "${outputpath}" is updated!"
