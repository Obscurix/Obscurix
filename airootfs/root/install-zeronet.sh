#!/bin/bash

# Install Zeronet.
zeronet_ver="0.7.1"
zeronet_dir="/usr/src/ZeroNet-${zeronet_ver}"
zeronet_archive="/usr/src/zeronet.tar.gz"

# Download and extract source.
scurl-download https://github.com/HelloZeroNet/ZeroNet/archive/v${zeronet_ver}.tar.gz -o ${zeronet_archive}
tar -xf ${zeronet_archive} -C /usr/src

# Create needed directory.
mkdir -pm 755 /opt/zeronet

# Copy needed files.
cp -a "${zeronet_dir}/." "/opt/zeronet/"

# Create Zeronet user.
useradd --system --user-group -m --home /var/lib/zeronet zeronet
usermod -a -G tor zeronet

# Create log directory.
mkdir -p /var/log/zeronet
chown zeronet:zeronet /var/log/zeronet

# Fix permissions.
chown zeronet:zeronet /etc/zeronet.conf
chmod 644 /etc/zeronet.conf
chown -R zeronet:zeronet /opt/zeronet

# Create Zeronet browser.
cp -r /home/user/tor-browser*_en-US /home/user/zeronet-browser

# Configure Zeronet browser.
cat <<EOF > /home/user/zeronet-browser/Browser/TorBrowser/Data/Browser/profile.default/user.js
// Proxy settings
user_pref("network.proxy.no_proxies_on", "127.0.0.1");

// Homepage
user_pref("browser.startup.homepage", "127.0.0.1:43110");
EOF

# Set permissions.
chown user -R /home/user/zeronet-browser

# Enable systemd service.
mv /etc/systemd/system/zeronet.service /usr/lib/systemd/system/zeronet.service
chmod 644 /usr/lib/systemd/system/zeronet.service
systemctl enable zeronet.service

# Delete source files.
rm -rf ${zeronet_dir} ${zeronet_archive}
