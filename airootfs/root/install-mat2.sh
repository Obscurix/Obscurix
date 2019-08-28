#!/bin/bash

# Install the Metadata Anonymization Toolkit 2 (MAT2).
mat_dir="/usr/src/mat2"

# Download source.
git clone https://0xacab.org/jvoisin/mat2 ${mat_dir}

# Verify MAT2.
cd ${mat2_dir}

if ! git verify-tag $(git tag | tail -n 1) &>/dev/null; then
  echo "ERROR: MAT2 CANNOT BE VERIFIED."
  exit 1
fi

# Run tests.
python3 -m unittest discover -v

# Install.
python setup.py install --root="/" --optimize=1

