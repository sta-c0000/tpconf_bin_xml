# tpconf_bin_xml.py

Simple command line utility to convert TP-Link modem/router backup config files from binary to XML and back:
- conf.bin ➡ decrypt, md5hash and uncompress ➡ conf.xml
- conf.xml ➡ compress, md5hash and encrypt ➡ conf.bin

*Should work for TP-Link models: TD-W8970, TD-W8980, TD-W9970, TD-W9980 (thanks d3dave), Archer VR900, C2, C20 and C60 / AC1350 (d3dave), TL-WR841N (thanks odolezal), WR841N V14 (thanks mcoops), XZ005-G6 (thanks tripleoxygen) and Archer AC3150 v2 (thanks borodean!).*<br>
*May or may not work with other TP-Link modem/routers, newer firmwares.*

## Getting Started

Single python file, [download](https://github.com/sta-c0000/tpconf_bin_xml/raw/master/tpconf_bin_xml.py), optionally chmod +x, and  run.

First, download a backup conf.bin file from your router using its web interface (System Tools → Backup & Restore → Backup).
```sh
python3 tpconf_bin_xml.py -h                # show help
python3 tpconf_bin_xml.py conf.bin conf.xml # convert bin to XML
```
*(optionally make changes to conf.xml)*
```sh
python3 tpconf_bin_xml.py conf.xml conf_new.bin # convert XML to bin
```
### Prerequisites

- Python 3.x
- pycryptodome
  - apt install python3-pycryptodome # for Debian type distro
  - *OR* (for other platforms)
  - pip install pycryptodomex

## Why?

To recover your router's account/password or simply make changes to your router's configuration using the XML file.

### Exploring inside the router (advanced users *at own risk*)
*Note: the following is for the TP-Link TD-W9970;  Other routers may differ (e.g. CPU architecture and/or endianness, LEDs), adapt as necessary.*

To explore inside your router you can start by adding the following line to the *\<DeviceInfo\>* section of your router's configuration XML:
```xml
<Description val="300Mbps Wireless N USB VDSL/ADSL Modem Router`telnetd -p 1023 -l login`" />
```
After converting to .bin and uploading this new configuration you can telnet to your router's port 1023 and login using: admin/1234. *(with admin/root access you could potentially brick your router; you should change the admin password; leaving this port open is a security risk!)*

The TD-W9970's configuration XML Description val is passed as a quoted parameter when launching upnpd (regarless if disabled in config) using sh -c around 20 seconds after boot (~ 35 seconds from power on).

A drive connected to the TD-W9970's USB port will be mounted around 4 seconds later.  So it is possible to directly execute a script located on the USB drive during boot using something like this (note that [XML special characters](https://stackoverflow.com/questions/1091945/what-characters-do-i-need-to-escape-in-xml-documents) must be escaped, and we redirect output to null otherwise upnpd launch would wait until our script finished):
```xml
<Description val="Modem Router`(sleep 10;/var/usbdisk/sda1/myscript)&gt;/dev/null &amp;`" />
```
Unfortunately TP-Link did not include ext4 filesystem support in their Linux kernel, only FAT and NTFS (fuse).  Using NTFS consumes a few more MB of RAM (running ntfs-3g) than FAT32, but offers the significant advantage of supporting symbolic links and large files.

You can download the latest **busybox-mips** *(if your router uses a big-endian MIPS32 CPU)* from the [busybox binaries](https://busybox.net/downloads/binaries/) repository and run it from your USB drive to have a more complete set of command line tools.  To get started very quickly, even using a FAT filesystem, you could source (.) something like this:

```sh
alias b='/var/usbdisk/sda1/busybox-mips'
for c in $(b --list); do alias $c="b $c"; done
```

SSH can be used instead of telnet to log in to your router.  You can download a recent compatible (MIPS32 version 1) [**dropbear_static** ssh server compiled by Martin Cracauer](https://github.com/cracauer/mFI-mPower-updated-sshd).  Follow the instructions in the README there to set up the needed host keys (on a real PC: `apt install dropbear-bin`).  The router's /etc is read-only, so you'll need to start *dropbear_static* with the *-r* option for each key, pointing to your USB drive, e.g.: `-r /var/usbdisk/sda1/ssh/dropbear_ecdsa_host_key`

Alternatively you can use the pre-compiled (big-endian MIPS) OpenSSH sshd daemon in this repository; read the **[sshd notes](sshd.md)** for more information.

Once you've made changes to the admin password / added new accounts, simply copy the passwd file to your usb; then your startup script can copy it over during each boot, e.g.: `cp -af /var/usbdisk/sda1/etc/passwd /var/passwd`

For debugging you can download a pre-compiled **gdbserver** that works on the TD-W9970 from the TL-WR940N V5's code repository at [TP-Link GPL Code Center](https://www.tp-link.com/en/support/gpl-code-center).

Your (latest busybox) scripts or cross-compiled programs can also control LED lights on the TD-W9970 modem router using:

```sh
printf "%02x%02x" lednum ledmode > /proc/tplink/led_ctrl
```

Where *lednum* is:
- 2 = Internet
- 3 = WPS (padlock)
- 17 = Power
- 18 = USB
- 20 to 23 = LAN1-4

And *ledmode* is:
- 0 = off
- 1 = on
- 3 = flash slow
- 4 = flash fast
- 5 = flash fast pause
- 7 = flash fast 5 times + slow pause

### How do I get my favourite tool running on the router?

Sadly due to lack of Broadcom xDSL support it is difficult at this time to run OpenWrt while using xDSL with this modem.  However, it is possible to cross-compile many console / server programs and run them directly on this device using a script on your USB drive (see above).
The TD-W9970 has a single core 600Mhz dual-CPU with ≈64MB of RAM.  If you know which built-in services you do not need, you can first disable them via the web interface, then kill remaining unused processes to free up the RAM they use in order to run many of your own tools and services.  For example:
```sh
sleep 15 # give router opportunity to finish setting up before we cleanup and setup our own services
killall -1 upnpd  # SIGHUP required to kill upnpd
killall telnetd dyndns noipdns cwmp ushare # etc. - make sure you do not depend on any of the services you kill
iptables -D INPUT -p udp -m udp --dport 161 -j ACCEPT # example to delete firewall's SNMP ACCEPT

# setup my services...
export TZ=EST+05:00EDT,M3.2.0/2,M11.1.0/2 # set timezone, e.g.: EST/EDT
export PATH='/var/usbdisk/sda1/bin:/sbin:/usr/sbin:/bin:/usr/bin' # insert USB drive's /bin into path
cp -af /var/usbdisk/sda1/etc/passwd /var/passwd # copy modified passwd file (accounts/passwords)
# can run your own binaries to background here
```
The easiest way to cross compile popular tools for this device is by using [Buildroot](https://buildroot.org/).  Compiling static binaries using uClibc will generate small efficient portable executables.
Some Buidroot settings to use for this device are: Target options: Architecture = *MIPS (big endian)*, Binary Format = *ELF*, Architecture Variant = *Generic MIPS32*, use soft-float; Build options: strip target binaries, libraries = static only; Toolchain: C library = *uClibc-ng*.

### Converting `/etc/default_config.xml` and `/etc/reduced_data_model.xml`

On the v1 firmware DES keys are stored in `libcmm.so`. The locations of the keys, the functions called, and the files targeted are (found using `radare2`):
```
478DA50FF9E3D2CB         > p8 8 @0xc0000-0x21a0
    dm_loadCfg (/etc/default_config.xml) > dm_decryptFile
    dm_init (/etc/reduced_data_model.xml) > dm_decryptFile
478DA50BF9E3D2CF         > p8 8 @0xf0000-0x5cf0
    rdp_backupCfg & rdp_restoreCfg (conf.bin) > cen_desMinDo, > cen_md5VerifyDigest, > cen_uncompressBuff
    rdp_saveModem3gFile > rsl_3g_saveModem3gFile
```
Therefore to decrypt `default_config.xml` and `reduced_data_model.xml` after copying the files to a PC:
```sh
openssl enc -d -des-ecb -nopad -K 478DA50FF9E3D2CB -in default_config.xml -out default_config_decrypted.xml
openssl enc -d -des-ecb -nopad -K 478DA50FF9E3D2CB -in reduced_data_model.xml -out reduced_data_model_decrypted.xml
```
Similarly, to encrypt:
```sh
openssl enc -e -des-ecb -nopad -K 478DA50FF9E3D2CB -in default_config_decrypted.xml -out default_config.xml
openssl enc -e -des-ecb -nopad -K 478DA50FF9E3D2CB -in reduced_data_model_decrypted.xml -out reduced_data_model.xml
```
Before encryption files must be *zero* padded to a file size multiple of eight.  A simple script like this could be used to do this:
```sh
#!/bin/sh
fsize=$(stat -c%s $1)
pad=$(($fsize%8))
if [ "$pad" != "0" ]; then
    dd if=/dev/zero bs=1 count=$((8-$pad)) | cat $1 - > $1.padded
fi
```
