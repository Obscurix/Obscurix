#!/bin/bash

# Get sources.
git clone https://github.com/vmonaco/kloak /usr/src/kloak-git

# Compile and install kloak.
cd /usr/src/kloak-git
make all
install -m644 /usr/src/kloak-git/kloak /usr/bin/kloak
install -m744 /usr/src/kloak-git/lib/systemd/system/kloak.service /lib/systemd/system/kloak.service

# We don't use /usr/sbin.
sed -i 's/\/usr\/sbin\/kloak/\/usr\/bin\/kloak/g' /lib/systemd/system/kloak.service

# Enable the systemd service.
systemctl enable kloak.service
