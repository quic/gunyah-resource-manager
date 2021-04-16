#!/bin/sh

# Ensure this script aborts on errors
set -ex

# master should always contain correct lib & header files
GIT_SSL_CAINFO=.qcom-ca-bundle.crt git submodule add --depth 1 -b master ../gunyah-app-sysroot.git $LOCAL_SYSROOT

# Clear any stale builds
rm -rf build
