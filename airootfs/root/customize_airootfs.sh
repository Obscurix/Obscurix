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
chmod 755 /etc/ /etc/profile.d/ /etc/iptables/ /etc/apparmor.d/ /etc/apparmor.d/abstractions/ /home/user/.config/ /home/user/.config/xfce4/ /home/user/.config/xfce4/xfconf/ /usr/ /usr/bin/ /usr/bin/torbrowser /usr/lib /etc/NetworkManager /etc/NetworkManager/conf.d /etc/pam.d /usr/lib/obscurix/ /usr/share/ /usr/share/backgrounds/ /usr/share/backgrounds/xfce/ /usr/bin/i2pbrowser /usr/bin/freenet-browser /usr/local/ /usr/local/bin/ /usr/local/bin/* /usr/bin/sandbox /lib/systemd /lib/systemd/system /usr/bin/zeronetbrowser /etc/onion-grater.d /usr/local/share /usr/local/share/seccomp /usr/local/share/seccomp/* /usr/bin/start-xpra
chmod 644 /etc/fstab /etc/bash.bashrc /etc/profile.d/umask.sh /etc/modprobe.d/*.conf /etc/iptables/iptables.rules /etc/apparmor.d/torbrowser.Browser.firefox /etc/apparmor.d/usr.bin.tor /etc/apparmor.d/tunables/torbrowser /etc/environment /home/user/.config/xfce4/xfconf/xfce-perchannel-xml/*.xml /etc/dnsmasq.conf /etc/NetworkManager/conf.d/dns.conf /etc/pam.d/su /etc/pam.d/su-l /etc/pam.d/system-login /usr/share/backgrounds/xfce/background.png /home/user/.bash_profile /etc/onion-grater.d/*.yml /etc/systemd/system/NetworkManager.service.d/fail-closed.conf /etc/systemd/system/tor.service.d/sandbox.conf  /etc/systemd/system/haveged.service.d/apparmor.conf /etc/systemd/system/cjdns.service.d/sandbox.conf
chmod 700 /home/user/.config/xfce4/xfconf/xfce-perchannel-xml/ /home/user/.config/autostart /home/user/.config/autostart/obscurix-startup.desktop /usr/lib/obscurix/* /home/user/.config/hexchat /home/user/.config/vlc /home/user/.config/xfce4/terminal /home/user/.bash_profile /home/user/.config/xfce4/desktop /home/user/.thunderbird/ /home/user/.thunderbird/profile.default/ /home/user/.gnupg /lib/modules/
chmod 600 /home/user/.config/hexchat/*.conf /home/user/.config/vlc/vlcrc /home/user/.config/xfce4/terminal/terminalrc /home/user/.config/xfce4/desktop/icons.screen.latest.rc /home/user/.thunderbird/profile.default/user.js /home/user/.gnupg/gpg.conf
chmod 440 /etc/sudoers /etc/sudoers.d/*
chmod 750 /etc/sudoers.d

for i in i2p freenet block-wireless check-boot-parameters ipfs macspoof zeronet secure-time-sync onion-grater
do
  chmod 644 /etc/systemd/system/${i}.service
done

for i in systemd-logind tor haveged NetworkManager cjdns
do
  chmod 755 /etc/systemd/system/${i}.service.d
done

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

# Set browser permissions.
chown user -R /home/user/i2p-browser /home/user/freenet-browser

# Delete Tor Browser archive.
rm /home/user/tor-browser-linux64-*_en-US.tar.xz

# Create I2P user.
useradd -m i2p

# Download I2P.
i2p_ver="0.9.42"
i2p_sha256="cb192e48c5f06839c99b71861364f3a9117b6b24f78f7f7c25d6716507c81bdf"

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

# Install I2P.
sudo -u i2p java -jar /home/i2p/i2pinstall.jar -console <<EOF
0
1
1
/home/i2p/i2p
O
1
1
EOF

# Delete installer.
rm -f /home/i2p/i2pinstall.jar /home/i2p/i2pinstall.jar.sig

# Check if I2P has been installed correctly.
if [ -f /home/i2p/i2p/i2prouter ]; then
  echo "I2P HAS BEEN INSTALLED"
else
  echo "ERROR: I2P HAS NOT BEEN INSTALLED"
  exit 1
fi

# Create Freenet user.
useradd -m freenet

# Download Freenet.
freenet_ver="1484"

scurl-download https://github.com/freenet/fred/releases/download/build0${freenet_ver}/new_installer_offline_${freenet_ver}.jar -o /home/freenet/new_installer_offline.jar
scurl-download https://github.com/freenet/fred/releases/download/build0${freenet_ver}/new_installer_offline_${freenet_ver}.jar.sig -o /home/freenet/new_installer_offline.jar.sig
chown freenet /home/freenet/new_installer_offline.jar /home/freenet/new_installer_offline.jar.sig

# Import Freenet signing key.
scurl https://freenetproject.org/assets/keyring.gpg | gpg --import

# Verify with GPG.
if ! gpg --status-fd 1 --verify "/home/freenet/new_installer_offline.jar.sig" "/home/freenet/new_installer_offline.jar" &>/dev/null; then
  echo "ERROR: FREENET INSTALLER CANNOT BE VERIFIED WITH GPG."
  exit 1
else
  echo "FREENET WAS SUCCESSFULLY VERIFIED WITH GPG."
fi

# Freenet gives a few harmless errors that would
# kill the script as the script uses "set -e".
# Because of this, the freenet installation has
# to be exempted from "set -e".
set +e

# Install Freenet.
sudo -u freenet java -jar /home/freenet/new_installer_offline.jar -console <<EOF
/home/freenet/Freenet
1
EOF

set -e

# Freenet autostarts which we don't want at this stage.
sudo -u freenet /home/freenet/Freenet/run.sh stop

# Delete installer and signature.
rm -f /home/freenet/new_installer_offline.jar /home/freenet/new_installer_offline.jar.sig

# Check if Freenet has been installed correctly.
if [ -d /home/freenet/Freenet ]; then
  echo "FREENET HAS BEEN INSTALLED"
else
  echo "ERROR: FREENET HAS NOT BEEN INSTALLED"
  exit 1
fi

# Move I2P/Freenet systemd services.
mv /etc/systemd/system/i2p.service /lib/systemd/system/i2p.service
mv /etc/systemd/system/freenet.service /lib/systemd/system/freenet.service

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
SocksPort 9058 IsolateDestAddr IsolateDestPort

# GnuPG.
SocksPort 9042 IsolateDestAddr IsolateDestPort

# Use less disk writes.
AvoidDiskWrites 1

# Tor Control Port.
ControlPort 9152

# onion-grater changes.
ControlSocket /run/tor/control
CookieAuthentication 1
CookieAuthFile /run/tor/control.authcookie" | tee -a /etc/tor/torrc >/dev/null

# Enable systemd services.
systemctl enable iptables.service block-wireless.service macspoof.service NetworkManager.service dnsmasq.service check-boot-parameters.service apparmor.service secure-time-sync.service onion-grater.service i2p.service freenet.service

# Disable tor.service so the Tor daemon does not start before the user has been asked for bridges.
systemctl mask tor.service

# Pacman stream isolation.
sed -i 's/#XferCommand = \/usr\/bin\/wget --passive-ftp -c -O %o %u/XferCommand = \/usr\/bin\/scurl --socks5-hostname localhost:9060 --continue-at - --fail --output %o %u/' /etc/pacman.conf

# Remove swapon binary and replace it with a dummy.
rm /usr/bin/swapon
echo "#!/bin/sh
/bin/true" | tee /usr/bin/swapon >/dev/null
chmod 755 /usr/bin/swapon

# Make desktop files executable.
chmod +x /home/user/Desktop/*.desktop

# Install Zeronet.
sh /root/install-zeronet.sh

# Install MAT2.
sh /root/install-mat2.sh

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

# Disable NetworkManager connectivity check.
echo "interval=0" | tee -a /usr/lib/NetworkManager/conf.d/20-connectivity.conf >/dev/null

# Remove the setuid/setgid bit of unneeded binaries.
# If they need to be used, they can be run as root.
chmod u-s -R /usr/bin/ /usr/lib/
chmod g-s -R /usr/bin/ /usr/lib/
chmod u+s /usr/bin/bwrap /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/polkit-1/polkit-agent-helper-1 /usr/lib/xf86-video-intel-backlight-helper

# Remove capabilities from unneeded binaries.
for i in /usr/bin/*
do
  setcap -r "${i}"
done

setcap cap_setgid+ep /usr/bin/newgidmap
setcap cap_setuid+ep /usr/bin/newuidmap
setcap cap_net_bind_service,cap_net_admin+ep /usr/lib/gstreamer-1.0/gst-ptp-helper

# Starting VLC from the applications menu will make it run
# /usr/bin/vlc but we want it to run the first in $PATH
# (/usr/local/bin/vlc) instead for the sandboxing.
sed -i 's/\/usr\/bin\/vlc/vlc/g' /usr/share/applications/vlc.desktop

# Same as VLC except we want profile.default.
sed -i 's/\/usr\/lib\/thunderbird\/thunderbird/thunderbird/g' /usr/share/applications/thunderbird.desktop

# Required for evince sandbox.
mkdir -m 700 /home/user/i2p-browser/Browser/Downloads /home/user/freenet-browser/Browser/Downloads /home/user/zeronet-browser/Browser/Downloads /home/user/tor-browser_en-US/Browser/Downloads /home/user/Downloads
chown user:user /home/user/*-browser*/Browser/Downloads
chown user:user /home/user/Downloads

# Generate seccomp filters.
for i in default-seccomp tbb-seccomp evince-seccomp eog-seccomp
do
  gcc /usr/local/share/seccomp/${i}.c -o /usr/local/share/seccomp/${i} -lseccomp
  /usr/local/share/seccomp/${i}
  rm /usr/local/share/seccomp/${i}{,.c}
done

chmod 644 /usr/local/share/seccomp/*

# Files in /etc/skel don't need to be in every
# home directory.
for skel_file in $(find /etc/skel -maxdepth 1 -mindepth 1 | sed -e 's/\/etc\/skel\///g')
do
  for home_dir in /home/i2p /home/freenet /root /var/lib/zeronet
  do
    if [ -e "${home_dir}/${skel_file}" ]; then
      rm -rf "${home_dir}/{skel_file}"
    fi
  done
done
