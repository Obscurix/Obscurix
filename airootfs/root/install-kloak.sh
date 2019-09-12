#!/bin/bash

kloak_dir="/usr/src/kloak-git"

# Get sources.
git clone https://github.com/vmonaco/kloak ${kloak_dir}

# Compile and install kloak.
cd ${kloak_dir}
make all
install -m744 ${kloak_dir}/kloak /usr/bin/kloak
install -m744 ${kloak_dir}/lib/systemd/system/kloak.service /lib/systemd/system/kloak.service

# We don't use /usr/sbin.
sed -i 's/\/usr\/sbin\/kloak/\/usr\/bin\/kloak/g' /lib/systemd/system/kloak.service

# Enable the systemd service.
systemctl enable kloak.service

# Delete source files.
rm -rf ${kloak_dir}
