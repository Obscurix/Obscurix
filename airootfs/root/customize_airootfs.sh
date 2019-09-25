#!/bin/bash

set -e -u

sed -i 's/#\(en_US\.UTF-8\)/\1/' /etc/locale.gen
locale-gen

ln -sf /usr/share/zoneinfo/UTC /etc/localtime

usermod -s /bin/bash root
cp -aT /etc/skel/ /root/
chmod 700 /root

sed -i "s/#Server/Server/g" /etc/pacman.d/mirrorlist
sed -i 's/#\(Storage=\)auto/\1volatile/' /etc/systemd/journald.conf

sed -i 's/#\(HandleSuspendKey=\)suspend/\1ignore/' /etc/systemd/logind.conf
sed -i 's/#\(HandleHibernateKey=\)hibernate/\1ignore/' /etc/systemd/logind.conf
sed -i 's/#\(HandleLidSwitch=\)suspend/\1ignore/' /etc/systemd/logind.conf

systemctl enable pacman-init.service # choose-mirror.service
systemctl set-default graphical.target

# Configure Pacman mirrors.
scurl-download "https://www.archlinux.org/mirrorlist/?country=all&protocol=https&ip_version=4" -o /etc/pacman.d/mirrorlist
chmod 644 /etc/pacman.d/mirrorlist
sed -i 's/#Server/Server/g' /etc/pacman.d/mirrorlist

# Create new user.
useradd -m -s /bin/bash user
echo "user:password" | chpasswd

# Fix permissions.
chmod 755 /etc/ /etc/profile.d/ /etc/iptables/ /etc/apparmor.d/ /etc/apparmor.d/abstractions/ /home/user/.config/ /home/user/.config/xfce4/ /home/user/.config/xfce4/xfconf/ /usr/ /usr/bin/ /usr/bin/torbrowser /usr/lib /etc/NetworkManager /etc/NetworkManager/conf.d /etc/pam.d /usr/lib/obscurix/ /usr/share/ /usr/share/backgrounds/ /usr/share/backgrounds/xfce/ /usr/bin/i2pbrowser /usr/bin/freenet-browser /usr/bin/installi2p /usr/bin/installfreenet /usr/local/ /usr/local/bin/ /usr/local/bin/* /usr/bin/sandbox /lib/systemd /lib/systemd/system /usr/bin/zeronetbrowser /etc/onion-grater.d /usr/lib/thunderbird /usr/lib/thunderbird/defaults /usr/lib/thunderbird/defaults/pref
chmod 644 /etc/fstab /etc/bash.bashrc /etc/profile.d/umask.sh /etc/modprobe.d/*.conf /etc/iptables/iptables.rules /etc/apparmor.d/torbrowser.Browser.firefox /etc/apparmor.d/usr.bin.tor /etc/apparmor.d/tunables/torbrowser /etc/environment /home/user/.config/xfce4/xfconf/xfce-perchannel-xml/*.xml /etc/dnsmasq.conf /etc/NetworkManager/conf.d/dns.conf /etc/pam.d/* /usr/share/backgrounds/xfce/background.png /home/user/.bash_profile /etc/onion-grater.d/*.yml /usr/lib/thunderbird/defaults/pref/user.js
chmod 700 /home/user/.config/xfce4/xfconf/xfce-perchannel-xml/ /home/user/.config/autostart /home/user/.config/autostart/obscurix-startup.desktop /usr/lib/obscurix/* /home/user/.config/hexchat /home/user/.config/vlc /home/user/.config/xfce4/terminal /home/user/.bash_profile /home/user/.config/xfce4/desktop
chmod 600 /home/user/.config/hexchat/*.conf /home/user/.config/vlc/vlcrc /home/user/.config/xfce4/terminal/terminalrc /home/user/.config/xfce4/desktop/icons.screen.latest.rc
chmod 440 /etc/sudoers /etc/sudoers.d/*
chmod 750 /etc/sudoers.d

# Make /etc/resolv.conf immutable.
chattr +i /etc/resolv.conf

# Unpack Tor Browser and set permissions.
tar -xJf /home/user/tor-browser-linux64-*_en-US.tar.xz -C /home/user/
chown user -R /home/user/tor-browser*_en-US

# Create I2P and Freenet browsers.
cp -r /home/user/tor-browser*_en-US /home/user/i2p-browser
cp -r /home/user/tor-browser*_en-US /home/user/freenet-browser

# Configure I2P browser.
cat <<EOF > /home/user/i2p-browser/Browser/TorBrowser/Data/Browser/profile.default/user.js
// Disable Tor
user_pref("network.proxy.socks", "");
user_pref("network.proxy.socks_port", 0);
user_pref("network.proxy.socks_remote_dns", false);

// Proxy settings
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", 4444);
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", 4444);
user_pref("network.proxy.no_proxies_on", "127.0.0.1");

// Homepage
user_pref("browser.startup.homepage", "127.0.0.1:7657");
EOF

# Configure Freenet browser.
cat <<EOF > /home/user/freenet-browser/Browser/TorBrowser/Data/Browser/profile.default/user.js
// Disable Tor
user_pref("network.proxy.socks", "");
user_pref("network.proxy.socks_port", 0);
user_pref("network.proxy.socks_remote_dns", false);

// Proxy settings
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", 8888);
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", 8888);
user_pref("network.proxy.no_proxies_on", "127.0.0.1");

// Homepage
user_pref("browser.startup.homepage", "127.0.0.1:8888");
EOF

# Remove the TorButton extensions from Freenet and I2P browsers. This is needed to prevent the Tor proxy settings from reverting.
rm "/home/user/i2p-browser/Browser/TorBrowser/Data/Browser/profile.default/extensions/torbutton@torproject.org.xpi" "/home/user/freenet-browser/Browser/TorBrowser/Data/Browser/profile.default/extensions/torbutton@torproject.org.xpi"

# Set browser permissions.
chown user -R /home/user/i2p-browser /home/user/freenet-browser

# Delete Tor Browser archive.
rm /home/user/tor-browser-linux64-*_en-US.tar.xz

# Create I2P user.
useradd -m i2p

# Download I2P.
i2p_ver="0.9.41"
i2p_sha256="3faf1c24c776375694d5f70c53c795ef73e00b21cd4b931ee62b1299b7073fc4"

scurl-download https://download.i2p2.de/releases/${i2p_ver}/i2pinstall_${i2p_ver}.jar -o /home/i2p/i2pinstall.jar
scurl-download https://download.i2p2.de/releases/${i2p_ver}/i2pinstall_${i2p_ver}.jar.sig -o /home/i2p/i2pinstall.jar.sig
chown i2p /home/i2p/i2pinstall.jar /home/i2p/i2pinstall.jar.sig

# Import I2P signing key.
scurl https://geti2p.net/_static/zzz.key.asc | gpg --import

# Verify with GPG.
if ! gpg --status-fd 1 --verify "/home/i2p/i2pinstall.jar.sig" "/home/i2p/i2pinstall.jar" &>/dev/null; then
  echo "ERROR: I2P INSTALLER CANNOT BE VERIFIED WITH GPG."
  exit 1
else
  echo "I2P WAS SUCCESSFULLY VERIFIED WITH GPG."
fi

# Verify checksums.
if ! sha256sum /home/i2p/i2pinstall.jar | grep "${i2p_sha256}" >/dev/null; then
  echo "ERROR: I2P INSTALLER CANNOT BE VERIFIED WITH SHA256."
  exit 1
else
  echo "I2P WAS SUCCESSFULLY VERIFIED WITH SHA256."
fi


# Create Freenet user.
useradd -m freenet

# Download Freenet.
freenet_ver="1484"

scurl-download https://github.com/freenet/fred/releases/download/build0${freenet_ver}/new_installer_offline_${freenet_ver}.jar -o /home/freenet/new_installer_offline.jar
scurl-download https://github.com/freenet/fred/releases/download/build0${freenet_ver}/new_installer_offline_${freenet_ver}.jar.sig -o /home/freenet/new_installer_offline.jar.sig
chown user /home/freenet/new_installer_offline.jar /home/freenet/new_installer_offline.jar.sig

# Import Freenet signing key.
scurl https://freenetproject.org/assets/keyring.gpg | gpg --import

# Verify with GPG.
if ! gpg --status-fd 1 --verify "/home/freenet/new_installer_offline.jar.sig" "/home/freenet/new_installer_offline.jar" &>/dev/null; then
  echo "ERROR: FREENET INSTALLER CANNOT BE VERIFIED WITH GPG."
  exit 1
else
  echo "FREENET WAS SUCCESSFULLY VERIFIED WITH GPG."
fi

# Lock the root account.
passwd -l root

# Mask systemd-timesyncd.
systemctl mask systemd-timesyncd.service

# Disable coredumps.
echo "* hard core 0" | tee -a /etc/security/limits.conf >/dev/null

# Configure torrc.
echo "
# Transparent proxy.
TransPort 9040

# DNS.
DNSPort 5353
AutomapHostsOnResolve 1
AutomapHostsSuffixes .exit,.onion

# Tor Browser SocksPort.
SocksPort 9150 IsolateSOCKSAuth KeepAliveIsolateSOCKSAuth

# Pacman SocksPort.
SocksPort 9060

# ZeroNet SocksPort.
SocksPort 9070

# Generic SocksPort.
SocksPort 9050 IsolateDestAddr IsolateDestPort

# I2P installation.
SocksPort 9043

# Freenet installation.
SocksPort 9062

# Time sync.
SocksPort 9058

# Use less disk writes.
AvoidDiskWrites 1

# Tor Control Port.
ControlPort 9152

# onion-grater changes.
ControlSocket /run/tor/control
CookieAuthentication 1
CookieAuthFile /run/tor/control.authcookie" | tee -a /etc/tor/torrc >/dev/null

# Enable systemd services.
systemctl enable iptables.service block-wireless.service macspoof.service NetworkManager.service dnsmasq.service check-boot-parameters.service apparmor.service secure-time-sync.service onion-grater.service

# Disable tor.service so the Tor daemon does not start before the user has been asked for bridges.
systemctl mask tor.service

# Pacman stream isolation.
sed -i 's/#XferCommand = \/usr\/bin\/wget --passive-ftp -c -O %o %u/XferCommand = \/usr\/bin\/scurl --socks5-hostname localhost:9060 --continue-at - --fail --output %o %u/' /etc/pacman.conf

# Remove dhcpcd to reduce attack surface. NetworkManager has its own dhcp client.
pacman -Rn --noconfirm dhcpcd

# Remove swapon binary and replace it with a dummy.
rm /usr/bin/swapon
echo "#!/bin/sh
/bin/true" | tee /usr/bin/swapon >/dev/null
chmod 755 /usr/bin/swapon

# Make desktop files executable.
chmod +x /home/user/Desktop/*.desktop

# Make bubblewrap setuid.
# This is needed as unprivileged userns are disabled for security.
chmod u+s /usr/bin/bwrap

# Enable auditd service. Needed for creating AppArmor profiles.
# Will be later removed.
systemctl enable auditd.service

# Install Zeronet.
sh /root/install-zeronet.sh

# Install MAT2.
# sh /root/install-mat2.sh

# Install hardened_malloc.
sh /root/install-hardened-malloc.sh

# Install kloak.
sh /root/install-kloak.sh

# Disable zeronet.service as it has a dependency on tor.service.
# It will attempt to start at boot while tor.service is masked which breaks it.
# It is enabled in obscurix-startup after the user is prompted for bridges.
systemctl mask zeronet.service

# Disable evince thumbnailer and previewer.
sed -i 's/^Exec=/# &/' /usr/share/thumbnailers/evince.thumbnailer
chmod 000 /usr/bin/evince-thumbnailer
chmod 000 /usr/bin/evince-previewer

# Move ipfs.service so it can be masked.
mv /etc/systemd/system/ipfs.service /usr/lib/systemd/system/ipfs.service

# Make sure cjdns and IPFS are disabled.
systemctl mask cjdns.service ipfs.service

# Allow cjdns to run without root.
setcap "cap_net_admin+eip cap_net_raw+eip" /usr/bin/cjdroute

# Create cjdns user.
useradd --system --user-group cjdns
chown cjdns:cjdns /usr/bin/cjdroute /etc/cjdroute.conf

# Disable unnecessary services for improved boot speed.
systemctl disable lvm2-monitor.service

# Disable NetworkManager connectivity check.
echo "interval=0" | tee -a /usr/lib/NetworkManager/conf.d/20-connectivity.conf >/dev/null

# Remove the setuid/setgid bit of unneeded binaries.
for i in chage chsh chfn expiry ksu newgrp sg pkexec
do
  chmod u-s "/usr/bin/${i}"
done

for i in wall write
do
  chmod g-s "/usr/bin/${i}"
done

# Remove capabilities from unneeded binaries.
for i in ping rsh rlogin rcp
do
  setcap -r "/usr/bin/${i}"
done
