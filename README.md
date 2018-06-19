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
You can download the latest **busybox-mips** from the [busybox binaries](https://busybox.net/downloads/binaries/) repository and run it from your USB drive to have a more complete set of command line tools.  To get started very quickly, even with a non-ext2 USB drive, you could source (.) something like this:

```sh
alias b='/var/usbdisk/sda1/busybox-mips'
for c in $(b --list); do alias $c="b $c"; done
```

SSH can be used instead of telnet to log in to your router.  You can download a recent compatible (MIPS32 version 1) [**dropbear_static** ssh server compiled by Martin Cracauer](https://github.com/cracauer/mFI-mPower-updated-sshd).  Follow the instructions in the README there to set up the needed host keys (on a real PC: `apt install dropbear-bin`).  The router's /etc is read-only, so you'll need to start *dropbear_static* with the *-r* option for each key, pointing to your usb drive, e.g.: `-r /var/usbdisk/sda1/ssh/dropbear_ecdsa_host_key`

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
