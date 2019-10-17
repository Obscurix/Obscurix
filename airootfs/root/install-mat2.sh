#!/bin/bash

# Install the Metadata Anonymization Toolkit 2 (MAT2).
mat_dir="/usr/src/mat2"

# Download source.
git clone https://0xacab.org/jvoisin/mat2 ${mat_dir}

# Verify MAT2.
cd ${mat_dir}

## Disabled for now as gpg can't connect to the keyserver
## during build for some reason.
#
#gpg --recv-keys 9FCDEE9E1A381F311EA62A7404D041E8171901CC
#
#if ! git verify-tag $(git tag | tail -n 1) &>/dev/null; then
#  echo "ERROR: MAT2 CANNOT BE VERIFIED."
#  exit 1
#fi

# Install.
python setup.py install --optimize=1
find /usr/lib/python3.7/site-packages/mat2-*-py*.egg/ -type d -exec chmod 755 {} \;
find /usr/lib/python3.7/site-packages/mat2-*-py*.egg/ -type f -exec chmod 644 {} \;
chmod 755 /usr/bin/mat2

# Delete source files.
rm -rf ${mat_dir}
