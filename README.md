# tpconf_bin_xml.py

Simple command line utility to convert TP-Link TD-W9970 modem router backup config files from binary to XML and back:
- conf.bin ➡ decrypt, md5hash and uncompress ➡ conf.xml
- conf.xml ➡ compress, md5hash and encrypt ➡ conf.bin

*May or may not work with other TP-Link modem / routers (not tested)*

## Getting Started

Single python file, download, optionally chmod +x, and  run.

First, download a backup conf.bin file from your router using its web interface (System Tools → Backup & Restore → Backup).
```sh
[python3] tpconf_bin_xml.py -h
[python3] tpconf_bin_xml.py conf.bin conf.xml # decrypt, md5hash and uncompress
```
*optionally make changes to conf.xml*
```sh
[python3] tpconf_bin_xml.py conf.xml conf_new.bin # compress, md5hash and encrypt
```
### Prerequisites

- Python 3.x
- pycrypto
  - apt install python3-crypto
  - *OR* pip install pycrypto
  - *OR* pip install pycryptodome

## Why?

To recover your router's account/password or simply make changes to your router's configuration using the XML file.

### Exploring inside the router (advanced users)

To explore inside your router you can start by adding the following line to the *\<DeviceInfo\>* section of your router's configuration XML:
```xml
<Description val="300Mbps Wireless N USB VDSL/ADSL Modem Router`telnetd -p 1023 -l login`" />
```
After converting to .bin and uploading this new configuration you can telnet to your router's port 1023 and login using: admin/1234. *(Leaving this port open without changing the password is a security risk)*

The TD-W9970's configuration XML Description val is passed as a quoted parameter when launching upnpd (regarless if disabled in config) using sh -c around 20 seconds after boot (~ 35 seconds from power on).

A drive connected to the TD-W9970's USB port will be mounted around 4 seconds later.  So it is possible to directly execute a script located on the USB drive during boot using something like this (note that [XML special characters](https://stackoverflow.com/questions/1091945/what-characters-do-i-need-to-escape-in-xml-documents) must be escaped, and we redirect output to null otherwise upnpd launch would wait until our script finished):
```xml
<Description val="Modem Router`(sleep 10;/var/usbdisk/sda1/myscript)&gt;/dev/null &amp;`" />
```
Unfortunately TP-Link did not include ext4 filesystem support in their Linux kernel, only FAT and NTFS (fuse).  Using NTFS consumes a few more MB of RAM (running ntfs-3g) than FAT32, but offers the significant advantage of supporting symbolic links and large files.

You can download the latest **busybox-mips** from the [busybox binaries](https://busybox.net/downloads/binaries/) repository and run it from your USB drive to have a more complete set of command line tools.  To get started very quickly, even using a FAT filesystem, you could source (.) something like this:

```sh
alias b='/var/usbdisk/sda1/busybox-mips'
for c in $(b --list); do alias $c="b $c"; done
```

SSH can be used instead of telnet to log in to your router.  You can download a recent compatible (MIPS32 version 1) [**dropbear_static** ssh server compiled by Martin Cracauer](https://github.com/cracauer/mFI-mPower-updated-sshd).  Follow the instructions in the README there to set up the needed host keys (on a real PC: `apt install dropbear-bin`).  The router's /etc is read-only, so you'll need to start *dropbear_static* with the *-r* option for each key, pointing to your USB drive, e.g.: `-r /var/usbdisk/sda1/ssh/dropbear_ecdsa_host_key`

Alternatively you can use the pre-compiled OpenSSH sshd daemon in this repository; read the **[sshd notes](sshd.md)** for more information.

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
The TD-W9970 has a 600Mhz dual-core CPU with ≈64MB.  If you know which built-in services you do not need, you can first disable them via the web interface, then kill remaining unused processes to free up the RAM they use in order to run many of your own tools and services.  For example:
```sh
sleep 15 # give router opportunity to finish setting up before we cleanup and setup our own services
killall -1 upnpd  # SIGHUP required to kill upnpd
killall telnetd dyndns noipdns cwmp ushare # etc. - make sure you do not depend on any of the services you kill
# setup my services here
```
The easiest way to cross compile popular tools for this device is by using [Buildroot](https://buildroot.org/).  Compiling static binaries using uClibc will generate small efficient portable executables. 
Some Buidroot settings to use for this device are: Target options: Architecture = *MIPS (big endian)*, Binary Format = *ELF*, Architecture Variant = *Generic MIPS32*, use soft-float; Build options: strip target binaries, libraries = static only; Toolchain: C library = *uClibc-ng*.
