#!/bin/bash

hardened_malloc_dir="/usr/src/hardened_malloc"

## Install hardened_malloc.
# Download source.
git clone https://github.com/GrapheneOS/hardened_malloc ${hardened_malloc_dir}
cd ${hardened_malloc_dir}

# Import Daniel Micay's GPG key.
scurl https://github.com/thestinger.gpg | gpg --import

# Verify hardened_malloc.
if ! git tag --verify 1 &>/dev/null; then
  echo "ERROR: HARDENED_MALLOC CANNOT BE VERIFIED."
  exit 1
fi

# Compile hardened_malloc.
make

# Copy files.
install -m755 ${hardened_malloc_dir}/libhardened_malloc.so /usr/lib/libhardened_malloc.so
